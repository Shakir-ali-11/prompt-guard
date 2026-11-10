import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime

from app.policy import Decision


@contextmanager
def _connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        with conn:  # commits on success, rolls back on error
            yield conn
    finally:
        conn.close()


def init_db(db_path: str) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                start_pos INTEGER NOT NULL,
                end_pos INTEGER NOT NULL
            )
            """
        )


def log_decision(db_path: str, user: str, decision: Decision) -> None:
    """One row per finding. Stores the rule and position, never the text itself."""
    if not decision.findings:
        return
    now = datetime.now(UTC).isoformat()
    rows = [
        (now, user, decision.action, f.type, f.severity, f.start, f.end)
        for f in decision.findings
    ]
    with _connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO events (created_at, user, action, rule, severity, start_pos, end_pos) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )


def list_events(db_path: str, limit: int = 50) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, created_at, user, action, rule, severity, start_pos, end_pos "
            "FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
