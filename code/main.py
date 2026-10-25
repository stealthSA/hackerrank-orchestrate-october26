#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent.

Usage:  python3 code/main.py [--requests deletion_requests.csv] [--out output.csv]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghostaudit.common import ROOT  # noqa: E402
from ghostaudit import vision  # noqa: E402
from ghostaudit.pipeline import run, write_output  # noqa: E402
from ghostaudit.selfcheck import audit_all  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", default="deletion_requests.csv", help="file under dataset/")
    ap.add_argument("--out", default=os.path.join(ROOT, "output.csv"))
    args = ap.parse_args()
    cases, results, store = run(args.requests)
    write_output(results, args.out)
    counts = {}
    for status, _ in results.values():
        counts[status] = counts.get(status, 0) + 1
    issues = audit_all(results)
    print(f"self-audit of completeness conditions: {len(issues)} issues", *issues[:10], sep="\n  " if issues else " ")
    print(f"OCR identifiers snapped to known values: {store.snapped}; VLM usage: {vision.USAGE}")
    import json
    with open(os.path.join(ROOT, "code", "evaluation", "run_usage.json"), "w") as fh:
        json.dump({"vlm": vision.USAGE, "requests": len(results), "snapped": store.snapped,
                   "selfcheck_issues": len(issues)}, fh, indent=1)
    print(f"links resolved by deterministic tie-break (no discriminating evidence): {store.link_ties}")
    print(f"wrote {len(results)} rows to {args.out}: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
