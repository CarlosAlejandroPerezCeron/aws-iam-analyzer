from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class IamFinding:
    rule_id: str
    severity: str
    entity: str
    title: str
    detail: str
    remediation: str


@dataclass
class AnalyzeConfig:
    min_severity: str = "LOW"


@dataclass
class Statement:
    effect: str
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    conditions: dict = field(default_factory=dict)


@dataclass
class PolicyDoc:
    name: str
    statements: list[Statement] = field(default_factory=list)
    inline: bool = False


@dataclass
class IamEntity:
    name: str
    entity_type: str  # "user", "role", "group"
    managed_policies: list[PolicyDoc] = field(default_factory=list)
    inline_policies: list[PolicyDoc] = field(default_factory=list)
