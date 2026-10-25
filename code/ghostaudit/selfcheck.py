"""Self-audit of a produced answer against the completeness conditions of the task.

A deletion is COMPLETE only if (1) every relevant copy has the treatment required by deletion_rules.csv,
(2) no sync/import/restore path can recreate the data, (3) retained records hold only permitted identifiers
and (4) required retained records stay available.  The functions below test the *shape* of an answer
against those conditions, independent of how the answer was produced, so a regression in any stage of the
pipeline is caught before it reaches output.csv.
"""
from __future__ import annotations

from .common import read_csv, rtype

# finding operation -> (remediation operations allowed, verification operation)
CLOSURE = {
    "REPORT_REMAINING_RECORD": ({"DELETE_RECORD"}, "VERIFY_RECORD_ABSENT"),
    "REPORT_EXPOSED_PII": ({"REDACT_RECORD", "ANONYMIZE_RECORD"}, None),   # verification matches the remediation
    "REPORT_ACTIVE_DATA_FLOW": ({"DISABLE_DATA_FLOW"}, "VERIFY_DATA_FLOW_DISABLED"),
    "REPORT_RESTORE_RISK": ({"BLOCK_RESTORE"}, "VERIFY_RESTORE_BLOCKED"),
}
REMEDIATION_VERIFY = {
    "DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
}
# resource type -> data category (deletion_rules.csv)
CATEGORY = {"account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "cache": "CACHE_ENTRY",
            "analytics": "ANALYTICS_PROFILE", "export": "USER_EXPORT", "marketing": "MARKETING_PROFILE",
            "audit_record": "SECURITY_AUDIT_LOG", "legal_hold": "LEGAL_HOLD_RECORD",
            "backup": "BACKUP_ARCHIVE", "tombstone": "ACCOUNT_TOMBSTONE"}
ALLOWED_FOR_ACTION = {  # policy action -> operations that may touch a record of that category
    "DELETE": {"REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"},
    "REDACT": {"REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"},
    "ANONYMIZE": {"REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"},
    "RETAIN": {"VERIFY_RECORD_PRESENT", "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"},
}


def _rules() -> dict:
    return {r["data_category"]: r["required_action"] for r in read_csv("deletion_rules.csv")}


def audit(cid: str, status: str, steps: list[dict], rules: dict | None = None) -> list[str]:
    rules = rules or _rules()
    out: list[str] = []
    if status == "NOT_APPLICABLE":
        return [f"{cid}: NOT_APPLICABLE must have no steps"] if steps else []
    by = {}
    for s in steps:
        by.setdefault((s["system_id"], s["resource_id"]), []).append(s)
        action = rules.get(CATEGORY.get(rtype(s["resource_id"]), ""))
        if action and s["operation"] not in ALLOWED_FOR_ACTION[action]:
            out.append(f"{cid}: {s['operation']} on {s['resource_id']} contradicts policy action {action}")
    if status == "COMPLETE":
        for s in steps:
            if s["phase"] != "VERIFICATION":
                out.append(f"{cid}: COMPLETE contains a {s['phase']} step")
            elif not s["evidence_id"]:
                out.append(f"{cid}: COMPLETE verification of {s['resource_id']} is not evidence-backed")
        if not steps:
            out.append(f"{cid}: COMPLETE without any verification")
        return out
    # INCOMPLETE
    if not any(s["phase"] == "FINDING" for s in steps):
        out.append(f"{cid}: INCOMPLETE without a finding")
    for key, group in by.items():
        ops = {s["operation"] for s in group}
        for f in (o for o in ops if o in CLOSURE):
            fixes, ver = CLOSURE[f]
            done = ops & fixes
            if not done:
                out.append(f"{cid}: finding {f} on {key[1]} has no remediation")
                continue
            need = ver or REMEDIATION_VERIFY[next(iter(done))]
            if need not in ops:
                out.append(f"{cid}: {key[1]} remediated but {need} missing")
        for r in (o for o in ops if o in REMEDIATION_VERIFY):
            if REMEDIATION_VERIFY[r] not in ops:
                out.append(f"{cid}: remediation {r} on {key[1]} has no verification")
            if not any(CLOSURE_F in ops for CLOSURE_F, (fx, _) in CLOSURE.items() if r in fx):
                out.append(f"{cid}: remediation {r} on {key[1]} has no finding")
    return out


def audit_all(results: dict) -> list[str]:
    rules = _rules()
    issues = []
    for cid, (status, steps) in results.items():
        issues += audit(cid, status, steps, rules)
    return issues
