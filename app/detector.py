import math
import re
from collections import Counter
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
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "high"),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "high"),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        "high",
    ),
    (
        "email",
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b(?!:[A-Za-z~/])"
        ),
        "medium",
    ),
    # JWT: header and payload are base64url JSON, so both start with "eyJ"
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), "high"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "high"),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{24,}"), "high"),
    # Phone: international (+92 300 1234567)
    (
        "phone",
        re.compile(
            r"(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?!\d)"
        ),
        "medium",
    ),
    # Phone: Pakistani local (0300-1234567)
    ("phone", re.compile(r"(?<!\d)0\d{3}[\s-]?\d{7}(?!\d)"), "medium"),
    # Phone: US ((415) 555-2671 or 415-555-2671)
    (
        "phone",
        re.compile(r"(?<!\d)(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?!\d)"),
        "medium",
    ),
]

# 13-19 digits, optionally separated by single spaces or dashes
CARD_REGEX = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")

# Candidate tokens for the entropy check: 24+ "key-like" characters in a row
TOKEN_REGEX = re.compile(r"[A-Za-z0-9+/_\-]{24,}")
ENTROPY_THRESHOLD = 4.0
# Snake/kebab-case identifiers such as calculate_monthly_revenue_2024_v2
IDENTIFIER_REGEX = re.compile(r"[a-z0-9]+(?:[_-][a-z0-9]+){2,}")

# Context rules: a keyword, then a separator, then the value
CONTEXT_KEYWORDS = r"(?:password|passwd|pwd|secret|api_?key|token)\w*"
CONTEXT_VALUE = r"""["']?([^\s"'()\[\]{},;]{6,})"""

KEYWORD_ASSIGN_REGEX = re.compile(
    CONTEXT_KEYWORDS + r"\s*[:=]\s*" + CONTEXT_VALUE, re.IGNORECASE
)

PASSWORD_PHRASE_REGEX = re.compile(
    r"\b(?:password|passwd)(?:\s+is)?\s+" + CONTEXT_VALUE, re.IGNORECASE
)

# When two findings overlap, the lower number wins.
PRIORITY = {
    "credit_card": 0,
    "aws_access_key": 1,
    "github_token": 1,
    "openai_key": 1,
    "private_key": 1,
    "email": 2,
    "phone": 3,
    "high_entropy_string": 4,
    "generic_secret": 5,
    "jwt": 1,
    "slack_token": 1,
    "stripe_key": 1,
}


def luhn_valid(number: str) -> bool:
    """Luhn checksum: used by real credit card numbers to catch typos."""
    total = 0
    for i, ch in enumerate(reversed(number)):
        digit = int(ch)
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def shannon_entropy(s: str) -> float:
    """Bits of randomness per character. 0 = all identical, higher = more random."""
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _remove_overlaps(findings: list[Finding]) -> list[Finding]:
    """Keep the most specific finding when several cover the same text."""
    kept: list[Finding] = []
    for f in sorted(findings, key=lambda f: (PRIORITY[f.type], f.start)):
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def _looks_like_secret_value(value: str) -> bool:
    """Require a letter plus a digit or selected symbol."""
    has_letter = any(c.isalpha() for c in value)
    has_digit_or_symbol = any(c.isdigit() or c in "!@#$%^&*" for c in value)
    return has_letter and has_digit_or_symbol


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for name, regex, severity in PATTERN_RULES:
        for match in regex.finditer(text):
            findings.append(Finding(name, match.start(), match.end(), severity))

    for match in CARD_REGEX.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            findings.append(Finding("credit_card", match.start(), match.end(), "high"))

    for regex in (KEYWORD_ASSIGN_REGEX, PASSWORD_PHRASE_REGEX):
        for match in regex.finditer(text):
            if _looks_like_secret_value(match.group(1)):
                findings.append(
                    Finding("generic_secret", match.start(1), match.end(1), "high")
                )

    for match in TOKEN_REGEX.finditer(text):
        token = match.group()
        has_digit = any(c.isdigit() for c in token)
        has_letter = any(c.isalpha() for c in token)
        if (
            has_digit
            and has_letter
            and not IDENTIFIER_REGEX.fullmatch(token)
            and shannon_entropy(token) > ENTROPY_THRESHOLD
        ):
            findings.append(
                Finding("high_entropy_string", match.start(), match.end(), "medium")
            )

    return _remove_overlaps(findings)
