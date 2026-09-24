"""LLM evidence synthesis with deterministic-policy boundaries."""

from __future__ import annotations

import json
from typing import Any

from openai import OpenAI

from .settings import settings

SYSTEM_PROMPT = """You are the explanation layer of a bank fraud investigation agent.
Use only the supplied case evidence, prior-case IDs, and policy-controlled actions.
Do not invent transactions, people, merchants, links, or outcomes. Do not change
the verdict, probability, action, or approval route. Explain the evidence chain,
remaining uncertainty, and why the final action is defensible in 120 words or less."""


def synthesize_case(payload: dict[str, Any]) -> dict[str, Any]:
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured")
    client = OpenAI(api_key=settings.openai_api_key)
    context = {
        "case_id": payload["case_id"],
        "case": payload["case"],
        "evidence_requests": payload["evidence_requests"],
        "final_actions": payload["next_best_actions"]["final"],
        "sar_decision": payload["sar"]["file"],
        "stop_reason": payload["stop_reason"],
    }
    response = client.responses.create(
        model=settings.openai_model,
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(context)},
        ],
    )
    usage = getattr(response, "usage", None)
    return {
        "model": settings.openai_model,
        "explanation": response.output_text,
        "tokens": getattr(usage, "total_tokens", 0) if usage else 0,
        "guardrail": "LLM explains; TigerGraph evidence and deterministic policy decide.",
    }
