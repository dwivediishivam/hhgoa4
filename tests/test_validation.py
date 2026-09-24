from sentinelgraph.validation import validate_answer


def valid_payload() -> dict:
    return {
        "case_id": "HHG-001",
        "case": {
            "status": "closed_fraud",
            "verdict": "fraud",
            "fraud_probability": 0.91,
            "pattern": "card_testing",
            "pattern_description": "",
            "affected_txn_ids": ["1"],
            "first_suspicious_txn_id": "1",
            "connected_card_ids": [],
            "connected_device_profiles": [],
            "exposure_usd": 120.50,
            "evidence": [
                {
                    "claim": "Sequence observed",
                    "source": "graph",
                    "ref": "q_testing_sequence",
                    "entity_ids": ["1"],
                }
            ],
            "similar_prior_cases": [],
            "summary": "Testing sequence and corroborating behavior support fraud.",
            "written_to_graph": True,
            "graph_case_id": "CASE-HHG-001",
        },
        "evidence_requests": [],
        "next_best_actions": {
            "initial": [{"action": "CREATE_CASE", "route": "auto", "reason": "Policy 3a"}],
            "final": [{"action": "CREATE_CASE", "route": "auto", "reason": "Policy 3a"}],
            "what_changed": "nothing",
        },
        "sar": {
            "file": False,
            "reason": "Below reporting threshold",
            "narrative": "",
            "subjects": [],
            "total_amount_usd": 0,
            "activity_dates": [],
        },
        "stop_reason": "Two independent evidence families support the conclusion.",
        "tool_calls": 5,
        "tokens": 1000,
        "latency_s": 3.2,
    }


def test_valid_minimal_case_passes() -> None:
    result = validate_answer(valid_payload(), transaction_amounts={"1": 120.50})
    assert result.valid, result.errors


def test_wrong_approval_route_fails() -> None:
    payload = valid_payload()
    payload["next_best_actions"]["initial"][0]["route"] = "L1"
    payload["next_best_actions"]["final"][0]["route"] = "L1"
    result = validate_answer(payload, transaction_amounts={"1": 120.50})
    assert not result.valid
    assert any("route" in error for error in result.errors)


def test_non_filed_sar_must_be_empty() -> None:
    payload = valid_payload()
    payload["sar"]["narrative"] = "This should not exist"
    result = validate_answer(payload, transaction_amounts={"1": 120.50})
    assert not result.valid
    assert any("non-filed SAR" in error for error in result.errors)
