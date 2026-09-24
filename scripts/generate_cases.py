"""Generate the 20 submission case files from the provided benchmark."""

from pathlib import Path

from sentinelgraph.investigation import generate_all

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    paths = generate_all(
        root / "ps TigerGraph Agentic Fraud Investigation HHGOA" / "raw_data", root / "cases"
    )
    print(f"Generated {len(paths)} validated cases in {paths[0].parent}")
