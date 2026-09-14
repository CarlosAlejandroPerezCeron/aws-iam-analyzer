from __future__ import annotations

from .base import SEVERITY_ORDER, AnalyzeConfig, IamEntity, IamFinding


def _all_policies(entity: IamEntity):
    return entity.managed_policies + entity.inline_policies


def _has_wildcard_action(actions: list[str]) -> bool:
    return any(a == "*" for a in actions)


def _has_wildcard_resource(resources: list[str]) -> bool:
    return any(r == "*" for r in resources)


def check_wildcard_admin(entity: IamEntity, config: AnalyzeConfig) -> list[IamFinding]:
    findings: list[IamFinding] = []
    for policy in _all_policies(entity):
        for stmt in policy.statements:
            if (
                stmt.effect == "Allow"
                and _has_wildcard_action(stmt.actions)
                and _has_wildcard_resource(stmt.resources)
            ):
                findings.append(
                    IamFinding(
                        rule_id="IAM-001",
                        severity="CRITICAL",
                        entity=entity.name,
                        title="Wildcard admin policy attached",
                        detail=f"Policy '{policy.name}' grants Action:* on Resource:*",
                        remediation=(
                            "Replace with least-privilege policy. "
                            "Never grant Action:* on Resource:* outside break-glass roles."
                        ),
                    )
                )
                break
    return findings


def check_full_iam_access(entity: IamEntity, config: AnalyzeConfig) -> list[IamFinding]:
    findings: list[IamFinding] = []
    for policy in _all_policies(entity):
        for stmt in policy.statements:
            if stmt.effect == "Allow" and any(a.lower() == "iam:*" for a in stmt.actions):
                findings.append(
                    IamFinding(
                        rule_id="IAM-002",
                        severity="HIGH",
                        entity=entity.name,
                        title="Full IAM access granted",
                        detail=f"Policy '{policy.name}' allows iam:* — full IAM control",
                        remediation=(
                            "Restrict to specific IAM actions required. "
                            "iam:* enables privilege escalation."
                        ),
                    )
                )
                break
    return findings


def check_passrole_wildcard(entity: IamEntity, config: AnalyzeConfig) -> list[IamFinding]:
    findings: list[IamFinding] = []
    for policy in _all_policies(entity):
        for stmt in policy.statements:
            has_passrole = any(a.lower() == "iam:passrole" for a in stmt.actions)
            if stmt.effect == "Allow" and has_passrole and _has_wildcard_resource(stmt.resources):
                findings.append(
                    IamFinding(
                        rule_id="IAM-003",
                        severity="HIGH",
                        entity=entity.name,
                        title="iam:PassRole allowed on all resources",
                        detail=f"Policy '{policy.name}' allows iam:PassRole on Resource:*",
                        remediation=(
                            "Restrict iam:PassRole to specific role ARNs. "
                            "Wildcard enables privilege escalation via role chaining."
                        ),
                    )
                )
                break
    return findings


def check_inline_policy_on_user(entity: IamEntity, config: AnalyzeConfig) -> list[IamFinding]:
    findings: list[IamFinding] = []
    if entity.entity_type == "user":
        for policy in entity.inline_policies:
            findings.append(
                IamFinding(
                    rule_id="IAM-004",
                    severity="MEDIUM",
                    entity=entity.name,
                    title="Inline policy attached to IAM user",
                    detail=f"User '{entity.name}' has inline policy '{policy.name}'",
                    remediation=(
                        "Convert to managed policy. "
                        "Inline policies are hard to audit and reuse."
                    ),
                )
            )
    return findings


def check_destructive_s3_wildcard(entity: IamEntity, config: AnalyzeConfig) -> list[IamFinding]:
    destructive = {"s3:deleteobject", "s3:deletebucket", "s3:delete*", "s3:*"}
    findings: list[IamFinding] = []
    for policy in _all_policies(entity):
        for stmt in policy.statements:
            matched = any(a.lower() in destructive for a in stmt.actions)
            if stmt.effect == "Allow" and matched and _has_wildcard_resource(stmt.resources):
                findings.append(
                    IamFinding(
                        rule_id="IAM-005",
                        severity="MEDIUM",
                        entity=entity.name,
                        title="Destructive S3 action allowed on all buckets",
                        detail=f"Policy '{policy.name}' allows S3 delete on Resource:*",
                        remediation=(
                            "Restrict S3 delete actions to specific bucket ARNs. "
                            "Wildcard enables account-wide data destruction."
                        ),
                    )
                )
                break
    return findings


RULES = [
    check_wildcard_admin,
    check_full_iam_access,
    check_passrole_wildcard,
    check_inline_policy_on_user,
    check_destructive_s3_wildcard,
]


def run_all(entities: list[IamEntity], config: AnalyzeConfig | None = None) -> list[IamFinding]:
    if config is None:
        config = AnalyzeConfig()
    results: list[IamFinding] = []
    for entity in entities:
        for rule in RULES:
            results.extend(rule(entity, config))
    return sorted(results, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.entity))
