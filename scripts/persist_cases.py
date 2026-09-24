"""Write generated case memory, evidence, and policy grounding to TigerGraph."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from tigergraph_mcp.connection_manager import ConnectionManager

from sentinelgraph.investigation import Dataset


async def persist() -> None:
    root = Path(__file__).resolve().parents[1]
    data_dir = root / "ps TigerGraph Agentic Fraud Investigation HHGOA" / "raw_data"
    dataset = Dataset.load(data_dir)
    ConnectionManager.load_profiles(".env")
    connection = ConnectionManager.get_connection_for_profile(
        graph_name=os.environ.get("TG_GRAPHNAME", "FraudGraph")
    )
    try:
        existing = {
            vertex["v_id"]
            for vertex in await connection.getVertices("FG_InvestigationCase", limit=100)
        }
        for case in dataset.cases:
            answer = json.loads((root / "cases" / f"{case['case_id']}.json").read_text())
            record = answer["case"]
            if record["graph_case_id"] in existing:
                print(f"Skipping existing {case['case_id']}", flush=True)
                continue
            txn = dataset.transaction(case)
            await connection.upsertVertex(
                "FG_Transaction",
                txn["TransactionID"],
                {
                    "customer_id": case["customer_id"], "card_id": case["card_id"], "ts": txn["ts"],
                    "amount": float(txn["TransactionAmt"]), "channel": txn["channel"],
                    "risk_score": float(txn["risk_score"]), "product_code": txn["ProductCD"],
                    "billing_region": txn["addr1"], "purchaser_email": txn["P_emaildomain"],
                    "recipient_email": txn["R_emaildomain"],
                },
            )
            await connection.upsertVertex("FG_Customer", case["customer_id"])
            await connection.upsertVertex("FG_Card", case["card_id"], {"customer_id": case["customer_id"], "card1": int(float(txn["card1"]))})
            await connection.upsertEdge("FG_Customer", case["customer_id"], "FG_OWNS", "FG_Card", case["card_id"])
            await connection.upsertEdge("FG_Card", case["card_id"], "FG_MADE", "FG_Transaction", txn["TransactionID"])
            graph_case_id = record["graph_case_id"]
            await connection.upsertVertex(
                "FG_InvestigationCase", graph_case_id,
                {"status": record["status"], "verdict": record["verdict"],
                 "fraud_probability": record["fraud_probability"], "pattern": record["pattern"],
                 "exposure_usd": record["exposure_usd"], "summary": record["summary"],
                 "opened_at": case["opened_at"], "updated_at": case["opened_at"]},
            )
            await connection.upsertEdge("FG_InvestigationCase", graph_case_id, "FG_CASE_INVOLVES", "FG_Transaction", txn["TransactionID"])
            await connection.upsertEdge("FG_InvestigationCase", graph_case_id, "FG_CASE_ON_CARD", "FG_Card", case["card_id"])
            for index, evidence in enumerate(record["evidence"], start=1):
                evidence_id = f"{graph_case_id}-E{index}"
                await connection.upsertVertex("FG_Evidence", evidence_id, {"claim": evidence["claim"], "source": evidence["source"], "ref": evidence["ref"], "polarity": "supporting"})
                await connection.upsertEdge("FG_InvestigationCase", graph_case_id, "FG_CASE_HAS_EVIDENCE", "FG_Evidence", evidence_id)
            await connection.upsertEdge("FG_InvestigationCase", graph_case_id, "FG_GROUNDED_BY", "FG_PolicyChunk", "POLICY-R1")
            print(f"Persisted {case['case_id']} -> {graph_case_id}", flush=True)
    finally:
        await connection.aclose()


if __name__ == "__main__":
    asyncio.run(persist())
