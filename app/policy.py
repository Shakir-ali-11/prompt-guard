from dataclasses import dataclass

from app.detector import Finding, scan

# Higher number = stricter
ACTION_RANK = {"allow": 0, "warn": 1, "redact": 2, "block": 3}

DEFAULT_POLICY = {
    "aws_access_key": "block",
    "github_token": "block",
    "openai_key": "block",
    "private_key": "block",
    "credit_card": "redact",
    "email": "warn",
    "phone": "warn",
    "high_entropy_string": "warn",
}


@dataclass
class Decision:
    action: str
    findings: list[Finding]
    text: str | None  # text that is safe to forward; None when blocked


def validate_policy(policy: dict[str, str]) -> None:
    for rule, action in policy.items():
        if action not in ACTION_RANK:
            raise ValueError(f"Invalid action '{action}' for rule '{rule}'")


def redact(text: str, findings: list[Finding]) -> str:
    # Work from the end so earlier positions stay valid after each replacement
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        text = text[: f.start] + f"[REDACTED:{f.type}]" + text[f.end :]
    return text


def evaluate(text: str, policy: dict[str, str] | None = None) -> Decision:
    merged = {**DEFAULT_POLICY, **(policy or {})}
    validate_policy(merged)

    findings = scan(text)
    action = "allow"
    to_redact: list[Finding] = []

    for f in findings:
        rule_action = merged.get(f.type, "warn")
        if ACTION_RANK[rule_action] > ACTION_RANK[action]:
            action = rule_action
        if rule_action == "redact":
            to_redact.append(f)

    if action == "block":
        return Decision(action, findings, None)
    return Decision(action, findings, redact(text, to_redact))