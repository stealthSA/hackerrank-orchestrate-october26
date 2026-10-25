#!/usr/bin/env python3
"""Score predictions against a labelled file (default: the public sample answers).

Metrics
  status accuracy     - deletion_status equals the label
  step-level          - precision/recall/F1 of exact step tuples (phase, system, resource, op, state, evidence)
  field-level         - per-field accuracy over steps aligned by (phase, system, resource, operation)
  sequence accuracy   - the full ordered step list matches exactly (and a normalised LCS ratio)
"""
import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ghostaudit.common import ROOT, read_csv  # noqa: E402
from ghostaudit.pipeline import run  # noqa: E402

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def key(s):
    return tuple(s[f] for f in FIELDS)


def lcs(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            dp[i + 1][j + 1] = dp[i][j] + 1 if a[i] == b[j] else max(dp[i][j + 1], dp[i + 1][j])
    return dp[-1][-1]


def evaluate(requests, labels_path, verbose=False):
    cases, results, _ = run(requests)
    with open(labels_path, newline="", encoding="utf-8") as fh:
        gold = {r["case_id"]: r for r in csv.DictReader(fh)}
    n = st_ok = 0
    tp = fp = fn = 0
    field_hit = {f: 0 for f in FIELDS}
    field_n = 0
    seq_ok = 0
    lcs_sum = 0.0
    per_case = []
    for cid, g in gold.items():
        if cid not in results:
            continue
        n += 1
        pstatus, psteps = results[cid]
        gsteps = json.loads(g["steps_json"])
        ok_status = pstatus == g["deletion_status"]
        st_ok += ok_status
        pk = [key(s) for s in psteps]
        gk = [key(s) for s in gsteps]
        ps, gs = set(pk), set(gk)
        tp += len(ps & gs)
        fp += len(ps - gs)
        fn += len(gs - ps)
        # field level, aligned by (phase, system, resource, operation)
        pal = {k[:4]: k for k in pk}
        for k in gk:
            field_n += 1
            m = pal.get(k[:4])
            if m is None:
                continue
            for i, f in enumerate(FIELDS):
                field_hit[f] += (m[i] == k[i])
        seq = pk == gk and pstatus == g["deletion_status"]
        seq_ok += seq
        denom = max(len(pk), len(gk), 1)
        lcs_sum += lcs(pk, gk) / denom if (pk or gk) else 1.0
        per_case.append((cid, ok_status, seq, sorted(ps - gs), sorted(gs - ps), pstatus, g["deletion_status"]))
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    out = {
        "cases": n,
        "status_accuracy": st_ok / n if n else 0,
        "step_precision": prec, "step_recall": rec, "step_f1": f1,
        "field_accuracy": {f: field_hit[f] / field_n if field_n else 0 for f in FIELDS},
        "sequence_exact_accuracy": seq_ok / n if n else 0,
        "sequence_lcs_ratio": lcs_sum / n if n else 0,
    }
    return out, per_case


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", default="sample_deletion_requests.csv")
    ap.add_argument("--labels", default=os.path.join(ROOT, "dataset", "sample_output.csv"))
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    out, per_case = evaluate(a.requests, a.labels)
    print(json.dumps(out, indent=2))
    if a.verbose:
        for cid, ok, seq, extra, missing, ps, gs in per_case:
            if ok and seq:
                continue
            print(f"\n{cid}: pred={ps} gold={gs}")
            for e in extra:
                print("   + extra  ", e)
            for m in missing:
                print("   - missing", m)


if __name__ == "__main__":
    main()
