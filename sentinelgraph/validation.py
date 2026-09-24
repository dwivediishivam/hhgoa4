"""Submission-contract validation for HHGOA case outputs.

This module intentionally validates the pieces the LLM is most likely to get
wrong: enum values, policy/action agreement, exposure arithmetic and SAR shape.
It is designed to run before a case is persisted or committed under ``cases/``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import Action, ApprovalRoute, approval_route

PATTERNS = {
    "card_testing",
    "card_not_present_fraud",
    "card_not_present_new_device",
    "out_of_region_use",
    "account_takeover",
    "undocumented",
    "none",
}
STATUSES = {"open", "closed_fraud", "closed_legitimate", "escalated"}
VERDICTS = {"fraud", "legitimate", "uncertain"}
EVIDENCE_SOURCES = {"graph", "document", "customer", "external"}
REQUEST_TYPES = {"customer_validation", "step_up_auth", "analyst_info"}
TOP_LEVEL_FIELDS = {
    "case_id",
    "case",
    "evidence_requests",
    "next_best_actions",
    "sar",
    "stop_reason",
    "tool_calls",
    "tokens",
    "latency_s",
}


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.errors


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _sentences(text: str) -> int:
    return len([part for part in re.split(r"[.!?]+", text) if part.strip()])


def _actions(value: object, label: str, exposure: float, errors: list[str]) -> set[str]:
    if not isinstance(value, list):
        errors.append(f"next_best_actions.{label} must be a list")
        return set()
    found: set[str] = set()
    for index, item in enumerate(value):
        prefix = f"next_best_actions.{label}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        action = item.get("action")
        route = item.get("route")
        reason = item.get("reason")
        if action not in {member.value for member in Action}:
            errors.append(f"{prefix}.action is not an exact policy action")
            continue
        found.add(action)
        if route not in {member.value for member in ApprovalRoute}:
            errors.append(f"{prefix}.route is invalid")
        else:
            expected = approval_route(Action(action), exposure).value
            if route != expected:
                errors.append(f"{prefix}.route must be {expected} for {action} at this exposure")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"{prefix}.reason is required")
    return found


def validate_answer(
    payload: dict[str, Any], *, transaction_amounts: dict[str, float] | None = None
) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    missing_top = TOP_LEVEL_FIELDS - payload.keys()
    if missing_top:
        errors.append(f"missing top-level fields: {', '.join(sorted(missing_top))}")
    if not isinstance(payload.get("case_id"), str) or not payload.get("case_id", "").startswith(
        "HHG-"
    ):
        errors.append("case_id must be an HHG case identifier")

    case = payload.get("case")
    if not isinstance(case, dict):
        return ValidationResult(tuple(errors + ["case must be an object"]), tuple(warnings))

    status = case.get("status")
    verdict = case.get("verdict")
    probability = case.get("fraud_probability")
    pattern = case.get("pattern")
    affected = case.get("affected_txn_ids")
    exposure = case.get("exposure_usd")
    evidence = case.get("evidence")

    if status not in STATUSES:
        errors.append("case.status is invalid")
    if verdict not in VERDICTS:
        errors.append("case.verdict is invalid")
    if not _is_number(probability) or not 0 <= float(probability) <= 1:
        errors.append("case.fraud_probability must be a number in [0, 1]")
    if pattern not in PATTERNS:
        errors.append("case.pattern is invalid")
    if pattern == "undocumented" and not isinstance(case.get("pattern_description"), str):
        errors.append("undocumented pattern requires pattern_description")
    if pattern != "undocumented" and case.get("pattern_description", "") not in {"", None}:
        errors.append("pattern_description must be empty unless pattern is undocumented")
    if not isinstance(affected, list) or not all(isinstance(txn, str) for txn in affected):
        errors.append("case.affected_txn_ids must be a list of strings")
        affected = []
    if not _is_number(exposure) or float(exposure) < 0:
        errors.append("case.exposure_usd must be a non-negative number")
        exposure = 0.0
    if verdict == "legitimate":
        if affected:
            errors.append("legitimate verdict must have no affected transactions")
        if float(exposure) != 0:
            errors.append("legitimate verdict must have zero exposure")
    if transaction_amounts is not None and affected:
        missing_transactions = [txn for txn in affected if txn not in transaction_amounts]
        if missing_transactions:
            errors.append(
                f"affected transaction IDs do not exist: {', '.join(missing_transactions[:5])}"
            )
        else:
            expected_exposure = round(sum(abs(transaction_amounts[txn]) for txn in affected), 2)
            if round(float(exposure), 2) != expected_exposure:
                errors.append(
                    f"exposure_usd is {exposure}; expected {expected_exposure} from affected transactions"
                )

    if not isinstance(evidence, list) or not evidence:
        errors.append("case.evidence must be a non-empty list")
    elif isinstance(evidence, list):
        for index, item in enumerate(evidence):
            prefix = f"case.evidence[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{prefix} must be an object")
                continue
            for field in ("claim", "ref", "entity_ids"):
                if field not in item:
                    errors.append(f"{prefix}.{field} is required")
            if item.get("source") not in EVIDENCE_SOURCES:
                errors.append(f"{prefix}.source is invalid")
            if not isinstance(item.get("entity_ids"), list):
                errors.append(f"{prefix}.entity_ids must be a list")

    requests = payload.get("evidence_requests")
    if not isinstance(requests, list):
        errors.append("evidence_requests must be a list")
        requests = []
    else:
        for index, request in enumerate(requests):
            prefix = f"evidence_requests[{index}]"
            if not isinstance(request, dict):
                errors.append(f"{prefix} must be an object")
                continue
            if request.get("type") not in REQUEST_TYPES:
                errors.append(f"{prefix}.type is invalid")
            if not isinstance(request.get("asked_after_step"), int):
                errors.append(f"{prefix}.asked_after_step must be an integer")
            if (
                not isinstance(request.get("assumed_response"), str)
                or not request.get("assumed_response").strip()
            ):
                errors.append(f"{prefix}.assumed_response must be explicit")

    nba = payload.get("next_best_actions")
    final_actions: set[str] = set()
    if not isinstance(nba, dict):
        errors.append("next_best_actions must be an object")
    else:
        _actions(nba.get("initial"), "initial", float(exposure), errors)
        final_actions = _actions(nba.get("final"), "final", float(exposure), errors)
        changed = nba.get("what_changed")
        if not isinstance(changed, str) or not changed.strip():
            errors.append("next_best_actions.what_changed is required")
        if not requests and nba.get("initial") != nba.get("final"):
            errors.append("initial and final actions must match when no evidence was requested")

    sar = payload.get("sar")
    if not isinstance(sar, dict):
        errors.append("sar must be an object")
    else:
        file_report = sar.get("file")
        if not isinstance(file_report, bool):
            errors.append("sar.file must be boolean")
        elif file_report != (Action.FILE_REPORT.value in final_actions):
            errors.append("sar.file must agree with final FILE_REPORT action")
        if file_report:
            narrative = sar.get("narrative")
            if not isinstance(narrative, str) or not 6 <= _sentences(narrative) <= 12:
                errors.append("filed SAR narrative must contain 6–12 sentences")
            if not isinstance(sar.get("subjects"), list) or not sar.get("subjects"):
                errors.append("filed SAR must name subjects")
            if not _is_number(sar.get("total_amount_usd")) or float(sar["total_amount_usd"]) <= 0:
                errors.append("filed SAR requires a positive total_amount_usd")
            dates = sar.get("activity_dates")
            if not isinstance(dates, list) or len(dates) != 2:
                errors.append("filed SAR requires first and last activity dates")
        else:
            for field, expected in (
                ("narrative", ""),
                ("subjects", []),
                ("total_amount_usd", 0),
                ("activity_dates", []),
            ):
                if sar.get(field) != expected:
                    errors.append(f"non-filed SAR field {field} must be {expected!r}")

    for metric in ("tool_calls", "tokens", "latency_s"):
        if not _is_number(payload.get(metric)) or float(payload[metric]) < 0:
            errors.append(f"{metric} must be a non-negative number")

    if not isinstance(payload.get("stop_reason"), str) or not payload.get("stop_reason").strip():
        errors.append("stop_reason is required")
    if case.get("written_to_graph") is not True:
        warnings.append(
            "case is not marked written_to_graph; submission requirement may not be met"
        )
    if case.get("written_to_graph") is True and not isinstance(case.get("graph_case_id"), str):
        errors.append("written case requires graph_case_id")

    return ValidationResult(tuple(errors), tuple(warnings))


def load_transaction_amounts(transactions_csv: Path) -> dict[str, float]:
    """Stream the supplied CSV and index only IDs and amounts for validation."""
    import csv

    amounts: dict[str, float] = {}
    with transactions_csv.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            amounts[str(row["TransactionID"])] = float(row["TransactionAmt"])
    return amounts


def validate_file(
    path: Path, *, transaction_amounts: dict[str, float] | None = None
) -> ValidationResult:
    with path.open(encoding="utf-8") as handle:
        return validate_answer(json.load(handle), transaction_amounts=transaction_amounts)
