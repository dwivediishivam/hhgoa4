"""Validate all submitted answer files before release."""

from __future__ import annotations

import argparse
from pathlib import Path

from sentinelgraph.validation import load_transaction_amounts, validate_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=Path("cases"))
    parser.add_argument("--transactions", type=Path, required=True)
    args = parser.parse_args()

    amounts = load_transaction_amounts(args.transactions)
    files = sorted(args.cases.glob("HHG-*.json"))
    if len(files) != 20:
        print(f"ERROR: expected exactly 20 HHG case files; found {len(files)}")
        return 1

    failed = False
    for path in files:
        result = validate_file(path, transaction_amounts=amounts)
        if result.errors:
            failed = True
            print(f"FAIL {path}")
            for error in result.errors:
                print(f"  - {error}")
        else:
            print(f"PASS {path}")
        for warning in result.warnings:
            print(f"  warning: {warning}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
