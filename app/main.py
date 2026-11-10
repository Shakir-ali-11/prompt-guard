import os

from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

from app import storage
from app.policy import DEFAULT_POLICY, evaluate, validate_policy


class CheckRequest(BaseModel):
    user: str = "anonymous"
    text: str = Field(max_length=100_000)


class FindingOut(BaseModel):
    type: str
    start: int
    end: int
    severity: str


class CheckResponse(BaseModel):
    action: str
    findings: list[FindingOut]
    text: str | None  # safe-to-forward text; null when blocked


def create_app(
    db_path: str | None = None,
    policy: dict[str, str] | None = None,
) -> FastAPI:
    db_path = db_path or os.environ.get("PROMPT_GUARD_DB", "prompt_guard.db")
    validate_policy({**DEFAULT_POLICY, **(policy or {})})  # fail fast on bad config
    storage.init_db(db_path)

    app = FastAPI(title="Prompt Guard")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def root():
        return {"service": "Prompt Guard", "docs": "/docs"}

    @app.post("/check", response_model=CheckResponse)
    def check(req: CheckRequest):
        decision = evaluate(req.text, policy)
        storage.log_decision(db_path, req.user, decision)
        return CheckResponse(
            action=decision.action,
            findings=[f.__dict__ for f in decision.findings],
            text=decision.text,
        )

    @app.get("/events")
    def events(limit: int = Query(50, ge=1, le=500)):
        return storage.list_events(db_path, limit)

    return app
