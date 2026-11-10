import pytest

from app.detector import PRIORITY, Finding
from app.policy import DEFAULT_POLICY, evaluate, redact

AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"


def test_high_entropy_string_warns_by_default():
    d = evaluate("secret=" + AWS_SECRET)
    assert d.action == "warn"


def test_clean_text_is_allowed():
    text = "How do I reverse a list in Python?"
    d = evaluate(text)
    assert d.action == "allow"
    assert d.findings == []
    assert d.text == text


def test_secret_is_blocked():
    d = evaluate("key=AKIAIOSFODNN7EXAMPLE")
    assert d.action == "block"
    assert d.text is None


def test_email_only_warns_and_text_unchanged():
    text = "mail shakir@example.com"
    d = evaluate(text)
    assert d.action == "warn"
    assert d.text == text


def test_credit_card_is_redacted():
    d = evaluate("card 4111 1111 1111 1111 thanks")
    assert d.action == "redact"
    assert d.text == "card [REDACTED:credit_card] thanks"


def test_two_cards_are_both_redacted():
    d = evaluate("4111 1111 1111 1111 and 5555 5555 5555 4444")
    assert d.text == "[REDACTED:credit_card] and [REDACTED:credit_card]"


def test_strictest_action_wins():
    d = evaluate("mail shakir@example.com key=AKIAIOSFODNN7EXAMPLE")
    assert d.action == "block"
    assert d.text is None


def test_redact_keeps_warned_content():
    d = evaluate("card 4111 1111 1111 1111 mail shakir@example.com")
    assert d.action == "redact"
    assert d.text == "card [REDACTED:credit_card] mail shakir@example.com"


def test_custom_policy_can_block_email():
    d = evaluate("mail shakir@example.com", {"email": "block"})
    assert d.action == "block"


def test_custom_policy_can_allow_email():
    d = evaluate("mail shakir@example.com", {"email": "allow"})
    assert d.action == "allow"
    assert len(d.findings) == 1  # still detected, just permitted


def test_invalid_action_raises():
    with pytest.raises(ValueError):
        evaluate("hello", {"email": "delete"})


def test_redact_helper_directly():
    f = Finding("x", 4, 10, "high")
    assert redact("abc secret def", [f]) == "abc [REDACTED:x] def"


def test_custom_policy_can_redact_phone():
    d = evaluate("call me at +92 300 1234567", {"phone": "redact"})
    assert d.action == "redact"
    assert "[REDACTED:phone]" in d.text
    assert "+92 300 1234567" not in d.text


def test_policy_overrides_do_not_change_detection():
    d = evaluate(
        "mail shakir@example.com key=AKIAIOSFODNN7EXAMPLE",
        {"email": "allow"},
    )
    assert d.action == "block"
    assert d.text is None
    assert len(d.findings) == 2


def test_short_secret_with_context_is_redacted():
    d = evaluate("secret=JBSWY3DPEHPK3PXP")
    assert d.action == "redact"
    assert d.text == "secret=[REDACTED:generic_secret]"


def test_github_token_and_card_blocks_prompt():
    token = (
        "github_pat_" + "11ABCDEFG0123456789_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    )
    d = evaluate(f"{token} card 4111 1111 1111 1111")
    assert d.action == "block"
    assert d.text is None

def test_every_rule_has_a_priority_and_a_default_action():
    assert set(PRIORITY) == set(DEFAULT_POLICY)