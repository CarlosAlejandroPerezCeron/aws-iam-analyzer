from analyzer.base import AnalyzeConfig, IamEntity, PolicyDoc, Statement
from analyzer.rules import (
    check_destructive_s3_wildcard,
    check_full_iam_access,
    check_inline_policy_on_user,
    check_passrole_wildcard,
    check_wildcard_admin,
    run_all,
)

CFG = AnalyzeConfig()


def _entity(name="test-entity", entity_type="user", managed=None, inline=None):
    return IamEntity(
        name=name,
        entity_type=entity_type,
        managed_policies=managed or [],
        inline_policies=inline or [],
    )


def _policy(name="test-policy", statements=None, inline=False):
    return PolicyDoc(name=name, statements=statements or [], inline=inline)


def _stmt(effect="Allow", actions=None, resources=None, conditions=None):
    return Statement(
        effect=effect,
        actions=actions or [],
        resources=resources or ["*"],
        conditions=conditions or {},
    )


# --- IAM-001 Wildcard Admin ---


def test_wildcard_admin_flagged():
    entity = _entity(managed=[_policy(statements=[_stmt(actions=["*"], resources=["*"])])])
    findings = check_wildcard_admin(entity, CFG)
    assert any(f.rule_id == "IAM-001" and f.severity == "CRITICAL" for f in findings)


def test_wildcard_admin_deny_not_flagged():
    entity = _entity(
        managed=[_policy(statements=[_stmt(effect="Deny", actions=["*"], resources=["*"])])]
    )
    findings = check_wildcard_admin(entity, CFG)
    assert findings == []


def test_wildcard_admin_specific_resource_not_flagged():
    entity = _entity(
        managed=[
            _policy(statements=[_stmt(actions=["*"], resources=["arn:aws:s3:::my-bucket"])])
        ]
    )
    findings = check_wildcard_admin(entity, CFG)
    assert findings == []


def test_wildcard_admin_via_inline_policy():
    entity = _entity(
        entity_type="role",
        inline=[_policy(statements=[_stmt(actions=["*"], resources=["*"])])],
    )
    findings = check_wildcard_admin(entity, CFG)
    assert any(f.rule_id == "IAM-001" for f in findings)


# --- IAM-002 Full IAM Access ---


def test_full_iam_access_flagged():
    entity = _entity(managed=[_policy(statements=[_stmt(actions=["iam:*"], resources=["*"])])])
    findings = check_full_iam_access(entity, CFG)
    assert any(f.rule_id == "IAM-002" and f.severity == "HIGH" for f in findings)


def test_specific_iam_action_not_flagged():
    entity = _entity(
        managed=[_policy(statements=[_stmt(actions=["iam:GetUser"], resources=["*"])])]
    )
    findings = check_full_iam_access(entity, CFG)
    assert findings == []


def test_full_iam_deny_not_flagged():
    entity = _entity(
        managed=[_policy(statements=[_stmt(effect="Deny", actions=["iam:*"], resources=["*"])])]
    )
    findings = check_full_iam_access(entity, CFG)
    assert findings == []


# --- IAM-003 PassRole Wildcard ---


def test_passrole_wildcard_flagged():
    entity = _entity(
        managed=[_policy(statements=[_stmt(actions=["iam:PassRole"], resources=["*"])])]
    )
    findings = check_passrole_wildcard(entity, CFG)
    assert any(f.rule_id == "IAM-003" and f.severity == "HIGH" for f in findings)


def test_passrole_specific_resource_not_flagged():
    entity = _entity(
        managed=[
            _policy(
                statements=[
                    _stmt(
                        actions=["iam:PassRole"],
                        resources=["arn:aws:iam::123456789012:role/specific-role"],
                    )
                ]
            )
        ]
    )
    findings = check_passrole_wildcard(entity, CFG)
    assert findings == []


def test_passrole_deny_not_flagged():
    entity = _entity(
        managed=[
            _policy(statements=[_stmt(effect="Deny", actions=["iam:PassRole"], resources=["*"])])
        ]
    )
    findings = check_passrole_wildcard(entity, CFG)
    assert findings == []


# --- IAM-004 Inline Policy on User ---


def test_inline_policy_on_user_flagged():
    entity = _entity(entity_type="user", inline=[_policy(name="InlinePol")])
    findings = check_inline_policy_on_user(entity, CFG)
    assert any(f.rule_id == "IAM-004" and f.severity == "MEDIUM" for f in findings)


def test_inline_policy_on_role_not_flagged():
    entity = _entity(entity_type="role", inline=[_policy(name="InlinePol")])
    findings = check_inline_policy_on_user(entity, CFG)
    assert findings == []


def test_inline_policy_on_group_not_flagged():
    entity = _entity(entity_type="group", inline=[_policy(name="InlinePol")])
    findings = check_inline_policy_on_user(entity, CFG)
    assert findings == []


def test_user_with_only_managed_policy_not_flagged():
    entity = _entity(entity_type="user", managed=[_policy(name="ManagedPol")])
    findings = check_inline_policy_on_user(entity, CFG)
    assert findings == []


# --- IAM-005 Destructive S3 Wildcard ---


def test_s3_delete_object_wildcard_flagged():
    entity = _entity(
        managed=[_policy(statements=[_stmt(actions=["s3:DeleteObject"], resources=["*"])])]
    )
    findings = check_destructive_s3_wildcard(entity, CFG)
    assert any(f.rule_id == "IAM-005" and f.severity == "MEDIUM" for f in findings)


def test_s3_delete_bucket_wildcard_flagged():
    entity = _entity(
        managed=[_policy(statements=[_stmt(actions=["s3:DeleteBucket"], resources=["*"])])]
    )
    findings = check_destructive_s3_wildcard(entity, CFG)
    assert any(f.rule_id == "IAM-005" for f in findings)


def test_s3_delete_specific_bucket_not_flagged():
    entity = _entity(
        managed=[
            _policy(
                statements=[
                    _stmt(actions=["s3:DeleteObject"], resources=["arn:aws:s3:::my-bucket/*"])
                ]
            )
        ]
    )
    findings = check_destructive_s3_wildcard(entity, CFG)
    assert findings == []


def test_s3_get_object_not_flagged():
    entity = _entity(
        managed=[
            _policy(statements=[_stmt(actions=["s3:GetObject", "s3:PutObject"], resources=["*"])])
        ]
    )
    findings = check_destructive_s3_wildcard(entity, CFG)
    assert findings == []


# --- General ---


def test_clean_entity_no_findings():
    entity = _entity(
        managed=[
            _policy(
                statements=[
                    _stmt(actions=["s3:GetObject"], resources=["arn:aws:s3:::my-bucket/*"])
                ]
            )
        ]
    )
    assert run_all([entity], CFG) == []


def test_run_all_sorted_by_severity():
    entity = _entity(
        entity_type="user",
        managed=[
            _policy(
                statements=[
                    _stmt(actions=["*"], resources=["*"]),
                    _stmt(actions=["s3:DeleteObject"], resources=["*"]),
                ]
            )
        ],
        inline=[_policy(name="InlinePol")],
    )
    findings = run_all([entity], CFG)
    from analyzer.base import SEVERITY_ORDER

    sevs = [f.severity for f in findings]
    assert sevs == sorted(sevs, key=lambda s: SEVERITY_ORDER.get(s, 99))


def test_multiple_rules_can_trigger():
    entity = _entity(
        managed=[
            _policy(
                statements=[
                    _stmt(actions=["iam:*"], resources=["*"]),
                    _stmt(actions=["iam:PassRole"], resources=["*"]),
                ]
            )
        ]
    )
    findings = run_all([entity], CFG)
    rule_ids = {f.rule_id for f in findings}
    assert "IAM-002" in rule_ids
    assert "IAM-003" in rule_ids
