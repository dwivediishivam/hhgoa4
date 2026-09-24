"""Local API for the analyst UI and integration tests.

Graph evidence and model scores will be added by the investigation orchestrator;
this API already guarantees that visible action recommendations obey policy.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.cors import CORSMiddleware

from .llm import synthesize_case
from .policy import CaseFacts, CustomerResponse, evaluate_policy
from .settings import settings


class FactsRequest(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    fraud_probability: float = Field(ge=0, le=1)
    exposure_usd: float = Field(ge=0)
    trigger_type: str
    evidence_families: int = Field(ge=0)
    verdict: str = "uncertain"
    customer_response: CustomerResponse | None = None
    card_testing: bool = False
    large_testing_purchase_cleared: bool = False
    shared_origin: bool = False
    connected_fraud: bool = False
    recurring_legitimate_pattern: bool = False
    conflicting_evidence: bool = False
    undocumented_coordinated_abuse: bool = False
    confirmed_fraud_on_two_customer_cards: bool = False
    credentials_confirmed_compromised: bool = False
    pending_authorization: bool = False

    def to_case_facts(self) -> CaseFacts:
        return CaseFacts(**self.model_dump())


app = FastAPI(title="SentinelGraph API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
app.mount("/static", StaticFiles(directory=WEB), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(WEB / "index.html")


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "openai_configured": bool(settings.openai_api_key),
        "tigergraph_configured": settings.tigergraph_ready,
        "tigergraph_workspace": settings.tg_workspace,
    }


@app.post("/api/policy/evaluate")
def evaluate(request: FactsRequest) -> dict[str, object]:
    decision = evaluate_policy(request.to_case_facts())
    return {
        "actions": [
            {"action": item.action, "route": item.route, "reason": item.reason}
            for item in decision.actions
        ],
        "should_open_case": decision.should_open_case,
        "should_file_sar": decision.should_file_sar,
        "should_request_evidence": decision.should_request_evidence,
        "can_stop": decision.can_stop,
        "stop_reason": decision.stop_reason,
        "warnings": decision.warnings,
    }


@app.get("/api/cases")
def list_cases() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for path in sorted((ROOT / "cases").glob("HHG-*.json")):
        payload = json.loads(path.read_text())
        record = payload["case"]
        result.append(
            {
                "case_id": payload["case_id"],
                "status": record["status"],
                "verdict": record["verdict"],
                "fraud_probability": record["fraud_probability"],
                "pattern": record["pattern"],
                "exposure_usd": record["exposure_usd"],
            }
        )
    return result


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, object]:
    path = ROOT / "cases" / f"{case_id}.json"
    if not path.is_file():
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Case not found")
    return json.loads(path.read_text())


@app.post("/api/cases/{case_id}/explain")
def explain_case(case_id: str) -> dict[str, object]:
    path = ROOT / "cases" / f"{case_id}.json"
    if not path.is_file():
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Case not found")
    return synthesize_case(json.loads(path.read_text()))
