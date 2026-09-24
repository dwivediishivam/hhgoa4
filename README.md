# SentinelGraph — Agentic Fraud Investigation

SentinelGraph is a TigerGraph-powered fraud investigation agent for the TigerGraph × Hacker House Goa 2026 challenge. It investigates uncertain alerts with graph evidence, retrieves prior case memory, requests controlled evidence, applies approval-aware policy actions, and writes a complete auditable case record.

## Live deployment

- Analyst console: https://hhgoa4.vercel.app
- Presentation: https://hhgoa4.vercel.app/presentation.html
- API and interactive documentation: https://hhgoa4.onrender.com/docs

## Capabilities

- Graph-native fraud episode and shared-origin discovery
- Calibrated fraud probability from closed historical cases—not copied risk scores
- Deterministic policy enforcement for actions, approvals, SARs, and stop conditions
- Prior-case retrieval using graph-connected evidence
- Evidence-to-action audit trail and case memory written back to TigerGraph
- GPT-5 Mini evidence synthesis through the OpenAI Responses API

## Submission contents

- `cases/HHG-001.json` … `cases/HHG-020.json` — validated answer files in the exact required format.
- `graph/schema.gsql` — isolated `FraudGraph` schema, deliberately prefixed `FG_` so it can share a Savanna workspace safely.
- `graph/queries/` — reusable graph retrieval queries for trigger context, timelines, device links, and region links.
- `sentinelgraph/investigation.py` — evidence extraction, pattern assessment, prior-case retrieval, controlled evidence simulation, policy progression, and output construction.
- `sentinelgraph/policy.py` — deterministic implementation of policy R1–R10 and approval routing.
- `sentinelgraph/validation.py` — strict pre-submission contract and policy validation.
- `web/index.html` — analyst-facing investigation console, served by FastAPI.

The supplied raw data is deliberately local-only and ignored by Git.

## Local setup

```bash
cp .env.example .env
# Add your local credentials and TigerGraph Savanna endpoint.
```

Never commit `.env` or the supplied raw dataset.

## Run end to end

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp .env.example .env
# Fill in your local OpenAI and TigerGraph values.

# Regenerate the required 20 answer files from the supplied dataset.
.venv/bin/python scripts/generate_cases.py

# Verify IDs, exposure arithmetic, action names, routes, SAR agreement, and shape.
.venv/bin/python scripts/validate_cases.py \
  --cases cases \
  --transactions 'ps TigerGraph Agentic Fraud Investigation HHGOA/raw_data/transactions.csv'

# Write the investigation records and evidence to the configured FraudGraph.
set -a; source .env; set +a
.venv/bin/python scripts/persist_cases.py

# Launch the analyst console at http://127.0.0.1:8000
.venv/bin/uvicorn sentinelgraph.api:app --reload
```

The deployed API also exposes `POST /api/cases/{case_id}/explain` for an
LLM-generated explanation grounded only in the stored case evidence and final
policy decision.

## Architecture and controls

The system separates probability assessment from action authority. Graph/timeline/device evidence produces case facts; the policy compiler then determines the only permitted action names and approval routes. Customer validation and step-up requests are recorded as controlled evidence requests, and the final action set is recomputed after the explicit simulated response. Every generated case carries evidence references, the policy-grounded action history, SAR decision, stop reason, and graph case ID.

`TG_SECRET` is the database secret used by TigerGraph MCP/data-plane authentication. `SAVANNA_API_KEY` is only for Savanna control-plane operations; they must not be substituted for one another.
