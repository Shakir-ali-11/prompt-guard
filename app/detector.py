import re
from dataclasses import dataclass


@dataclass
class Finding:
    type: str
    start: int
    end: int
    severity: str


# Each rule: (name, compiled regex, severity)
PATTERN_RULES = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), "high"),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "high"),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "high",
    ),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "medium"),
]

# 13-19 digits, optionally separated by single spaces or dashes
CARD_REGEX = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def luhn_valid(number: str) -> bool:
    """Luhn checksum: used by real credit card numbers to catch typos."""
    total = 0
    for i, ch in enumerate(reversed(number)):
        digit = int(ch)
        if i % 2 == 1:          # double every second digit from the right
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for name, regex, severity in PATTERN_RULES:
        for match in regex.finditer(text):
            findings.append(Finding(name, match.start(), match.end(), severity))

    for match in CARD_REGEX.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            findings.append(Finding("credit_card", match.start(), match.end(), "high"))

    return sorted(findings, key=lambda f: f.start)