from fastapi.testclient import TestClient

from sentinelgraph.api import app


def test_health_does_not_expose_secrets() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert "api_key" not in response.text.lower()
    assert response.json()["status"] == "ok"


def test_policy_endpoint_enforces_r1() -> None:
    response = TestClient(app).post(
        "/api/policy/evaluate",
        json={
            "fraud_probability": 0.45,
            "exposure_usd": 120,
            "trigger_type": "risk_score",
            "evidence_families": 1,
        },
    )
    assert response.status_code == 200
    actions = {item["action"] for item in response.json()["actions"]}
    assert "VERIFY_WITH_CUSTOMER" in actions
    assert "BLOCK_CARD" not in actions
