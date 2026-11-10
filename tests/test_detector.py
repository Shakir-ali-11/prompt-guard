from app.detector import luhn_valid, scan, shannon_entropy

# Fake secrets are built by concatenation so GitHub's secret scanner
# doesn't block your push.
FAKE_GITHUB = "ghp_" + "a" * 36
FAKE_OPENAI = "sk-" + "b" * 40


def types(text):
    return [f.type for f in scan(text)]


def test_aws_key():
    assert types("key=AKIAIOSFODNN7EXAMPLE") == ["aws_access_key"]


def test_aws_key_wrong_length_not_flagged():
    assert types("AKIA123") == []


def test_github_token():
    assert types(f"token {FAKE_GITHUB}") == ["github_token"]


def test_openai_key():
    assert types(f"OPENAI_API_KEY={FAKE_OPENAI}") == ["openai_key"]


def test_private_key_header():
    assert types("-----BEGIN RSA PRIVATE KEY-----") == ["private_key"]


def test_email():
    assert types("contact me at shakir@example.com") == ["email"]


def test_valid_credit_card():
    assert types("card 4111 1111 1111 1111") == ["credit_card"]


def test_invalid_credit_card_not_flagged():
    assert types("card 4111 1111 1111 1112") == []


def test_clean_text():
    assert scan("How do I reverse a list in Python?") == []


def test_positions_are_correct():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    f = scan(text)[0]
    assert text[f.start : f.end] == "AKIAIOSFODNN7EXAMPLE"


def test_luhn():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_two_secrets_in_one_string():
    text = f"github={FAKE_GITHUB} openai={FAKE_OPENAI}"
    assert types(text) == ["github_token", "openai_key"]


def test_email_at_start_of_sentence():
    text = "shakir@example.com is my contact email."
    assert types(text) == ["email"]


def test_credit_card_with_dashes():
    assert types("card 4111-1111-1111-1111") == ["credit_card"]


def test_github_gho_token():
    token = "gho_" + "c" * 36
    assert types(f"token={token}") == ["github_token"]


def test_empty_text():
    assert scan("") == []


def test_temporary_aws_access_key():
    key = "ASIA" + "A" * 16
    assert types(f"key={key}") == ["aws_access_key"]


def test_short_github_token_not_flagged():
    token = "ghp_" + "a" * 35
    assert scan(f"token={token}") == []


def test_email_has_medium_severity():
    findings = scan("shakir@example.com")
    assert len(findings) == 1
    assert findings[0].type == "email"
    assert findings[0].severity == "medium"


def test_findings_follow_text_order():
    text = f"shakir@example.com token={FAKE_GITHUB}"
    findings = scan(text)

    assert [finding.type for finding in findings] == [
        "email",
        "github_token",
    ]
    assert findings[0].start < findings[1].start


# AWS's documented example secret, split so secret scanners don't complain
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"


def test_entropy_of_repeated_chars_is_zero():
    assert shannon_entropy("aaaa") == 0


def test_entropy_of_four_distinct_chars_is_two():
    assert shannon_entropy("abcd") == 2.0


def test_high_entropy_secret_is_flagged():
    text = "secret=" + AWS_SECRET
    assert types(text) == ["high_entropy_string"]
    f = scan(text)[0]
    assert text[f.start : f.end] == AWS_SECRET


def test_git_hash_not_flagged():
    assert types("commit a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0") == []


def test_long_plain_word_not_flagged():
    assert types("internationalization-and-localization-guidelines") == []


def test_phone_international_pakistan():
    assert types("call +92 300 1234567") == ["phone"]


def test_phone_local_pakistan():
    assert types("call 0300-1234567") == ["phone"]


def test_phone_us():
    assert types("call (415) 555-2671") == ["phone"]


def test_short_number_not_phone():
    assert types("order 12345 shipped") == []


def test_card_not_reported_as_phone():
    assert types("card 4111 1111 1111 1111") == ["credit_card"]


def test_phone_with_sentence_punctuation():
    text = "Call +92 300 1234567."
    findings = scan(text)

    assert len(findings) == 1
    assert findings[0].type == "phone"
    assert text[findings[0].start : findings[0].end] == "+92 300 1234567"


def test_phone_and_email_together():
    text = "Call 0300-1234567 or email shakir@example.com."
    findings = scan(text)

    assert [finding.type for finding in findings] == ["phone", "email"]

    matched_text = [text[finding.start : finding.end] for finding in findings]
    assert matched_text == ["0300-1234567", "shakir@example.com"]


def test_github_token_reported_only_once():
    token = "ghp_" + "a" * 36
    text = f"token={token}"
    findings = scan(text)

    assert len(findings) == 1
    assert findings[0].type == "github_token"
    assert text[findings[0].start : findings[0].end] == token


def test_invalid_luhn_number_is_not_flagged():
    number = "4111111111111112"

    assert not luhn_valid(number)
    assert scan(f"Reference number: {number}") == []


def test_harmless_hex_reference_is_not_flagged():
    reference = "0123456789abcdef" * 2
    text = f"The public reference ID is {reference}."

    assert scan(text) == []


def test_github_fine_grained_token():
    token = (
        "github_pat_" + "11ABCDEFG0123456789_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    )
    assert types(f"token {token}") == ["github_token"]
