# TigerGraph artifacts

Apply `schema.gsql` to a Savanna graph named `FraudGraph`, then install the
queries from `queries/`. The query outputs provide compact evidence packets for
trigger context, card timelines, shared-device relationships, and shared-region
relationships. Generated investigations and their evidence are persisted with
`scripts/persist_cases.py`.
