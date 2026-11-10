import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def client(db_path):
    return TestClient(create_app(db_path))


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_clean_prompt_is_allowed(client):
    r = client.post("/check", json={"user": "shakir", "text": "How do I reverse a list?"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    assert body["findings"] == []
    assert body["text"] == "How do I reverse a list?"


def test_secret_is_blocked(client):
    r = client.post("/check", json={"text": f"key={FAKE_AWS}"})
    body = r.json()
    assert body["action"] == "block"
    assert body["text"] is None
    assert body["findings"][0]["type"] == "aws_access_key"


def test_card_is_redacted(client):
    r = client.post("/check", json={"text": "card 4111 1111 1111 1111 thanks"})
    body = r.json()
    assert body["action"] == "redact"
    assert body["text"] == "card [REDACTED:credit_card] thanks"


def test_missing_text_returns_422(client):
    assert client.post("/check", json={"user": "shakir"}).status_code == 422


def test_events_are_logged(client):
    client.post("/check", json={"user": "shakir", "text": "mail shakir@example.com"})
    events = client.get("/events").json()
    assert len(events) == 1
    assert events[0]["user"] == "shakir"
    assert events[0]["rule"] == "email"
    assert events[0]["action"] == "warn"


def test_secret_never_stored_in_database(client, db_path):
    client.post("/check", json={"text": f"key={FAKE_AWS}"})
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT * FROM events").fetchall()
    conn.close()
    assert rows  # the event was logged...
    assert FAKE_AWS not in str(rows)  # ...without the secret


def test_clean_prompt_is_not_logged(client):
    client.post("/check", json={"text": "hello there"})
    assert client.get("/events").json() == []


def test_events_are_newest_first(client):
    client.post("/check", json={"text": "mail shakir@example.com"})
    client.post("/check", json={"text": f"key={FAKE_AWS}"})
    events = client.get("/events").json()
    assert events[0]["rule"] == "aws_access_key"
    assert events[1]["rule"] == "email"


def test_server_policy_is_applied(db_path):
    client = TestClient(create_app(db_path, {"email": "block"}))
    r = client.post("/check", json={"text": "mail shakir@example.com"})
    assert r.json()["action"] == "block"


def test_invalid_server_policy_fails_at_startup(db_path):
    with pytest.raises(ValueError):
        create_app(db_path, {"email": "delete"})


def test_client_cannot_override_policy(client):
    r = client.post(
        "/check",
        json={"text": f"key={FAKE_AWS}", "policy": {"aws_access_key": "allow"}},
    )
    assert r.json()["action"] == "block"


def test_events_limit_returns_one_event(client):
    client.post("/check", json={"text": "mail shakir@example.com"})
    client.post("/check", json={"text": "call me at +92 300 1234567"})
    events = client.get("/events?limit=1").json()
    assert len(events) == 1


def test_events_limit_zero_returns_422(client):
    response = client.get("/events?limit=0")
    assert response.status_code == 422


def test_two_findings_create_two_rows(client):
    client.post(
        "/check",
        json={
            "text": "mail shakir@example.com call me at +92 300 1234567"
        },
    )
    events = client.get("/events").json()
    assert len(events) == 2
    rules = {event["rule"] for event in events}
    assert rules == {"email", "phone"}    