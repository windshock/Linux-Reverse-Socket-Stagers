#!/usr/bin/env python3
"""Aggregate recorded direct-vs-tool AI experiment runs.

The script deliberately does not invent model/token data. Feed it JSONL records
from the caller that ran the same task under both conditions.
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


REQUIRED = {
    "condition", "run_id", "input_tokens", "output_tokens", "tool_calls",
    "tool_time_seconds", "total_time_seconds", "success", "retries",
}


def load_records(path: Path) -> list[dict]:
    records = []
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        missing = REQUIRED - record.keys()
        if missing:
            raise ValueError(f"line {line_no}: missing fields {sorted(missing)}")
        records.append(record)
    return records


def summarize(records: list[dict]) -> dict:
    if not records:
        return {"status": "NOT_TESTED", "reason": "no experiment records"}
    groups = {}
    for record in records:
        groups.setdefault(record["condition"], []).append(record)
    result = {"status": "MEASURED", "conditions": {}}
    for condition, rows in sorted(groups.items()):
        result["conditions"][condition] = {
            "runs": len(rows),
            "success_rate": sum(bool(r["success"]) for r in rows) / len(rows),
            "mean_input_tokens": statistics.mean(r["input_tokens"] for r in rows),
            "mean_output_tokens": statistics.mean(r["output_tokens"] for r in rows),
            "mean_tool_calls": statistics.mean(r["tool_calls"] for r in rows),
            "mean_tool_time_seconds": statistics.mean(r["tool_time_seconds"] for r in rows),
            "mean_total_time_seconds": statistics.mean(r["total_time_seconds"] for r in rows),
            "mean_retries": statistics.mean(r["retries"] for r in rows),
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, help="JSONL run records")
    args = parser.parse_args()
    if args.input is None:
        print(json.dumps({"status": "NOT_TESTED", "reason": "no --input supplied"}, indent=2))
        return 0
    print(json.dumps(summarize(load_records(args.input)), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
