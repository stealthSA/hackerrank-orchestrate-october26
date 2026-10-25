"""End-to-end pipeline: requests -> cases -> linked resources -> decisions."""
from __future__ import annotations

import csv
import json
import os

from .common import ROOT, parse_ts, read_csv
from .engine import Engine
from .evidence import EvidenceStore
from .identity import IdentityBook
from .intent import authorises_deletion
from .linker import Case, Linker


def build_cases(rows: list[dict], book: IdentityBook) -> list[Case]:
    cases = []
    for r in rows:
        ident = book.resolve(r["email"])
        auth = authorises_deletion(r["request_text"]) and ident is not None
        cases.append(Case(row=r, identity=ident, authorised=auth,
                          t_req=parse_ts(r["requested_at"]), t_rep=parse_ts(r["reported_at"]),
                          t_audit=parse_ts(r["audit_at"])))
    return cases


def load_universe(request_file: str) -> tuple[list[dict], set]:
    """All known requests (public samples + evaluation set) so that resources claimed by one
    subject can be eliminated for the others and time windows can be calibrated on more pairs."""
    def load(fn):
        if os.path.isabs(fn) or os.path.exists(fn):
            with open(fn, newline="", encoding="utf-8") as fh:
                return list(csv.DictReader(fh))
        return read_csv(fn)

    wanted = [r["case_id"] for r in load(request_file)]
    seen, rows = set(), []
    for fn in dict.fromkeys(["sample_deletion_requests.csv", "deletion_requests.csv", request_file]):
        try:
            batch = load(fn)
        except FileNotFoundError:
            continue
        for r in batch:
            if r["case_id"] not in seen:
                seen.add(r["case_id"])
                rows.append(r)
    return rows, set(wanted)


def run(request_file: str = "deletion_requests.csv", store: EvidenceStore | None = None):
    store = store or EvidenceStore().load()
    book = IdentityBook()
    rows, wanted = load_universe(request_file)
    cases = build_cases(rows, book)
    linker = Linker(store, book)
    engine = Engine(store)
    auth = linker.link_explicit(cases)
    # cases whose explicitly linked evidence already shows a violation are INCOMPLETE; only the
    # others can be the "everything compliant" family that needs policy-action anchoring.
    eligible = {c.case_id for c in auth if engine.decide(c)[0] == "COMPLETE"}
    linker.link_anchors(auth, eligible)
    results = {}
    for c in cases:
        if c.case_id in wanted:
            results[c.case_id] = engine.decide(c)
    store.link_ties = dict(linker.ties)
    return [c for c in cases if c.case_id in wanted], results, store


def case_key(cid: str):
    head, _, tail = cid.rpartition("_")
    return (head, int(tail)) if tail.isdigit() else (cid, 0)


def write_output(results: dict, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for cid in sorted(results, key=case_key):
            status, steps = results[cid]
            ordered = [{"step_no": s["step_no"], "phase": s["phase"], "system_id": s["system_id"],
                        "resource_id": s["resource_id"], "operation": s["operation"], "state": s["state"],
                        "evidence_id": s["evidence_id"]} for s in steps]
            w.writerow([cid, status, json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)])
