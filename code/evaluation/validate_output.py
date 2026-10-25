#!/usr/bin/env python3
"""Structural validation of output.csv against the contract in problem_statement.md."""
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from ghostaudit.common import ROOT, parse_ts, read_csv  # noqa: E402
from ghostaudit.engine import OP_META, OP_ORDER, PHASES  # noqa: E402
from ghostaudit.pipeline import case_key  # noqa: E402

FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}


def validate(path, requests="deletion_requests.csv"):
    errs = []
    reqs = {r["case_id"]: r for r in read_csv(requests)}
    ev = {r["file_id"]: r for r in read_csv("evidence_files.csv")}
    with open(path, newline="", encoding="utf-8") as fh:
        rdr = csv.DictReader(fh)
        if rdr.fieldnames != ["case_id", "deletion_status", "steps_json"]:
            errs.append(f"bad header {rdr.fieldnames}")
        rows = list(rdr)
    ids = [r["case_id"] for r in rows]
    if sorted(ids, key=case_key) != ids:
        errs.append("rows are not sorted by case_id")
    if set(ids) != set(reqs) or len(ids) != len(set(ids)):
        errs.append(f"case ids differ from the request file ({len(ids)} rows, {len(reqs)} requests)")
    for r in rows:
        cid, st = r["case_id"], r["deletion_status"]
        try:
            steps = json.loads(r["steps_json"])
        except ValueError:
            errs.append(f"{cid}: steps_json is not JSON"); continue
        if st not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            errs.append(f"{cid}: bad status {st}")
        if st == "NOT_APPLICABLE" and steps != []:
            errs.append(f"{cid}: NOT_APPLICABLE must have []")
        audit = parse_ts(reqs[cid]["audit_at"]) if cid in reqs else None
        last = (-1, -1)
        for i, s in enumerate(steps, 1):
            if set(s) != FIELDS:
                errs.append(f"{cid}: step {i} fields {sorted(s)}")
                continue
            if s["step_no"] != i:
                errs.append(f"{cid}: step_no {s['step_no']} != {i}")
            m = OP_META.get(s["operation"])
            if not m or m != (s["phase"], s["state"]):
                errs.append(f"{cid}: step {i} invalid op/phase/state")
                continue
            key = (PHASES.index(s["phase"]), OP_ORDER.index(s["operation"]))
            if key < last:
                errs.append(f"{cid}: step {i} out of phase/operation order")
            last = key
            e = s["evidence_id"]
            if e:
                if e not in ev:
                    errs.append(f"{cid}: unknown evidence {e}")
                elif audit and parse_ts(ev[e]["captured_at"]) > audit:
                    errs.append(f"{cid}: evidence {e} captured after audit_at")
            elif st == "COMPLETE":
                errs.append(f"{cid}: COMPLETE step {i} lacks evidence")
            if st == "INCOMPLETE" and s["phase"] != "FINDING" and e:
                errs.append(f"{cid}: INCOMPLETE {s['phase']} step cites evidence")
            if st == "INCOMPLETE" and s["phase"] == "FINDING" and not e:
                errs.append(f"{cid}: finding without evidence")
            if st == "COMPLETE" and s["phase"] != "VERIFICATION":
                errs.append(f"{cid}: COMPLETE contains {s['phase']}")
        if st == "INCOMPLETE" and not any(s["phase"] == "FINDING" for s in steps):
            errs.append(f"{cid}: INCOMPLETE without findings")
    return errs, len(rows)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "output.csv")
    errs, n = validate(path)
    print(f"{n} rows checked, {len(errs)} problems")
    for e in errs[:40]:
        print(" -", e)
    sys.exit(1 if errs else 0)
