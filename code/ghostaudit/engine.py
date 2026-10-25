"""Policy engine: reconstruct each linked resource's state at audit_at, apply
deletion_rules.csv, decide the case status and emit ordered steps."""
from __future__ import annotations

import collections
from dataclasses import dataclass, field

from .common import EMAIL_RE, RTYPES, parse_ts, read_csv, rtype
from .evidence import EvidenceStore, Obs
from .linker import Case

PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
OP_ORDER = [
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
]
OP_META = {  # op -> (phase, state)
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"), "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"), "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"), "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"), "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"), "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}

# resource type -> data category in deletion_rules.csv
CATEGORY = {
    "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "cache": "CACHE_ENTRY",
    "analytics": "ANALYTICS_PROFILE", "export": "USER_EXPORT", "marketing": "MARKETING_PROFILE",
    "email_delivery": "EMAIL_DELIVERY_LOG", "audit_record": "SECURITY_AUDIT_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD", "backup": "BACKUP_ARCHIVE", "tombstone": "ACCOUNT_TOMBSTONE",
}
ACTION_OP = {"DELETE": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
             "REDACT": ("REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
             "ANONYMIZE": ("ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED")}


@dataclass
class Verdict:
    rid: str
    system: str
    kind: str                       # violation | compliant | retained | unknown
    finding: str | None = None      # finding operation for violations
    remediation: str | None = None
    verification: str | None = None
    evidence: str = ""
    note: str = ""


def _truthy(v) -> bool | None:
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().strip('"').lower()
    if s in ("true", "1", "yes", "y", "enabled", "allow", "eligible"):
        return True
    if s in ("false", "0", "no", "n", "disabled", "deny", "blocked"):
        return False
    return None


class Engine:
    def __init__(self, store: EvidenceStore) -> None:
        self.S = store
        self.rules = {r["data_category"]: r for r in read_csv("deletion_rules.csv")}
        self.files = store.files

    # ------------------------------------------------------------ helpers
    def _window_obs(self, rid: str, case: Case) -> list[Obs]:
        out = []
        for o in self.S.for_rid(rid):
            t = parse_ts(o.ts)
            if t is not None and case.t_req <= t <= case.t_audit and self.S.visible(o.fid, case.t_audit):
                out.append(o)
        return out

    @staticmethod
    def _latest(obs: list[Obs]) -> list[Obs]:
        if not obs:
            return []
        m = max(parse_ts(o.ts) for o in obs)
        return [o for o in obs if parse_ts(o.ts) == m]

    def _identifiers(self, o: Obs) -> bool:
        return bool(o.emails or o.hashes or o.phones or o.names or
                    any(u for u in o.users))

    def _coverage_evidence(self, system: str, case: Case) -> str:
        """Latest evidence in the window whose snapshot enumerates the system."""
        best = None
        for c in self.S.cov:
            if c.system != system:
                continue
            t = parse_ts(c.ts)
            if t is None or t < case.t_req or t > case.t_audit or not self.S.visible(c.fid, case.t_audit):
                continue
            if best is None or t > best[0]:
                best = (t, c.fid)
        return best[1] if best else ""

    # ------------------------------------------------------- per-type state
    def evaluate(self, case: Case) -> list[Verdict]:
        out: list[Verdict] = []
        for rid in sorted(case.linked):
            v = self._eval_resource(rid, case)
            if v is not None:
                out.append(v)
        return out

    def _action(self, category: str) -> str:
        r = self.rules.get(category)
        return r["required_action"] if r else "DELETE"

    def _eval_resource(self, rid: str, case: Case) -> Verdict | None:
        v = self._eval_resource_raw(rid, case)
        if v is not None:
            # the data catalog names the owning system of a record it linked
            self.S._catalog_aliases()
            v.system = self.S._catalog_system.get(rid, v.system)
        return v

    def _eval_resource_raw(self, rid: str, case: Case) -> Verdict | None:
        rt = rtype(rid)
        system = RTYPES.get(rt, "")
        obs = self._window_obs(rid, case)
        latest = self._latest(obs)
        if rt in ("audit_record", "legal_hold") and not latest and rid in case.retained_any:
            # known only from later evidence: still a policy-retained record, cited only if visible
            return Verdict(rid, system, "retained", None, None, "VERIFY_RECORD_PRESENT", "")
        if rt == "account":
            return self._account(rid, system, obs, latest, case)
        if not latest:
            return None
        ev_present = [o for o in latest if o.present is not False]
        if rt == "search":
            if ev_present:
                return self._deletion_violation(rid, system, ev_present)
            return None
        if rt in ("export",):
            live = [o for o in ev_present if _truthy(o.attrs.get("download_available",
                                                                 o.attrs.get("available", True))) is not False]
            if live:
                return self._deletion_violation(rid, system, live)
            return None
        if rt in ("marketing", "object"):   # marketing profile / attachment belonging only to the subject
            if ev_present:
                return self._deletion_violation(rid, system, ev_present)
            return None
        if rt == "support":
            return self._support(rid, system, latest)
        if rt == "analytics":
            return self._analytics(rid, system, latest)
        if rt == "tombstone":
            exposed = [o for o in latest if o.emails or o.hashes or o.phones or o.names]
            if exposed:
                return Verdict(rid, system, "violation", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                               "VERIFY_RECORD_REDACTED", exposed[0].fid)
            return Verdict(rid, system, "compliant", None, None, "VERIFY_RECORD_REDACTED", latest[0].fid)
        if rt == "data_flow":
            return self._data_flow(rid, system, latest)
        if rt == "backup":
            return self._backup(rid, system, latest)
        if rt in ("audit_record", "legal_hold"):
            return Verdict(rid, system, "retained", None, None, "VERIFY_RECORD_PRESENT", latest[0].fid)
        return None

    # ------------------------------------------------------------- account
    def _account(self, rid, system, obs, latest, case) -> Verdict:
        present = [o for o in latest if o.present]
        if present:
            return Verdict(rid, system, "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD",
                           "VERIFY_RECORD_ABSENT", present[0].fid)
        absent = [o for o in latest if o.present is False]
        if absent:
            return Verdict(rid, system, "compliant", None, None, "VERIFY_RECORD_ABSENT", absent[0].fid)
        # no observation of the record itself: absence is shown by a snapshot that enumerates the system
        fid = self._coverage_evidence(system, case)
        return Verdict(rid, system, "compliant" if fid else "unknown", None, None,
                       "VERIFY_RECORD_ABSENT", fid)

    def _deletion_violation(self, rid, system, obs) -> Verdict:
        o = obs[0]
        return Verdict(rid, system, "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD",
                       "VERIFY_RECORD_ABSENT", o.fid)

    # ------------------------------------------------------------- support
    def _is_attachment(self, o: Obs) -> bool:
        a = o.attrs
        if o.src in ("ticket_attachments",) or "file_name" in a or "attachment" in o.src:
            return True
        ev = a.get("event", "")
        if ev.startswith("attachment"):
            return True
        if o.src == "document":
            path = self.files.get(o.fid, {}).get("file_path", "").lower()
            return "attachment" in path
        if o.src == "log:contact_query_completed" or ev == "contact_query_completed":
            return False
        return False

    def _support(self, rid, system, latest) -> Verdict | None:
        live = [o for o in latest if o.present is not False]
        if not live:
            return None
        for o in live:
            rt_, res = o.attrs.get("record_type"), o.attrs.get("result")
            if rt_ == "SUPPORT_ATTACHMENT" and res == "FOUND":
                return Verdict(rid, system, "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD",
                               "VERIFY_RECORD_ABSENT", o.fid)
            if rt_ == "SUPPORT_MESSAGE":
                if res == "IDENTIFIABLE":
                    return Verdict(rid, system, "violation", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                                   "VERIFY_RECORD_REDACTED", o.fid)
                if res == "REDACTED":
                    return Verdict(rid, system, "compliant", None, None, "VERIFY_RECORD_REDACTED", o.fid)
        if any(self._is_attachment(o) for o in live):
            o = [x for x in live if self._is_attachment(x)][0]
            return Verdict(rid, system, "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD",
                           "VERIFY_RECORD_ABSENT", o.fid)
        exposed = [o for o in live if o.emails or o.hashes or o.phones or o.names]
        # a replica contact lookup row that still resolves means the record was not removed
        if any(o.attrs.get("event") in ("contact_query_completed", "contact_lookup_completed",
                                        "deletion_marker_check") for o in live):
            o = live[0]
            return Verdict(rid, system, "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD",
                           "VERIFY_RECORD_ABSENT", o.fid)
        if exposed:
            return Verdict(rid, system, "violation", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                           "VERIFY_RECORD_REDACTED", exposed[0].fid)
        return Verdict(rid, system, "compliant", None, None, "VERIFY_RECORD_REDACTED", live[0].fid)

    # ----------------------------------------------------------- analytics
    def _analytics(self, rid, system, latest) -> Verdict | None:
        live = [o for o in latest if o.present is not False]
        if not live:
            return None
        for o in live:
            res = o.attrs.get("result")
            if o.attrs.get("record_type") == "ANALYTICS_PROFILE":
                if res == "IDENTIFIABLE":
                    return Verdict(rid, system, "violation", "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD",
                                   "VERIFY_RECORD_ANONYMIZED", o.fid)
                if res == "ANONYMIZED":
                    return Verdict(rid, system, "compliant", None, None, "VERIFY_RECORD_ANONYMIZED", o.fid)
        if any(o.attrs.get("event") in ("contact_lookup_completed",) or "email_opt_in" in o.attrs
               for o in live):
            return Verdict(rid, system, "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD",
                           "VERIFY_RECORD_ABSENT", live[0].fid)
        exposed = [o for o in live if o.emails or o.hashes or o.phones or o.names or
                   o.attrs.get("direct_identifiers") not in (None, "0", 0)]
        if exposed:
            return Verdict(rid, system, "violation", "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD",
                           "VERIFY_RECORD_ANONYMIZED", exposed[0].fid)
        return Verdict(rid, system, "compliant", None, None, "VERIFY_RECORD_ANONYMIZED", live[0].fid)

    # ----------------------------------------------------------- data flow
    def _data_flow(self, rid, system, latest) -> Verdict | None:
        flags = []
        for o in latest:
            a = o.attrs
            if a.get("record_type") == "DATA_FLOW" and a.get("result") in ("ACTIVE", "DISABLED"):
                flags.append((a["result"] == "ACTIVE", o))
                continue
            en = _truthy(a.get("enabled"))
            sch = _truthy(a.get("scheduler_registered"))
            if en is None and sch is None and a.get("last_delivery_status") is None:
                continue
            active = bool(en) or bool(sch) or (en is None and a.get("last_delivery_status") == "delivered")
            flags.append((active, o))
        if not flags:
            doc = [o for o in latest if o.src == "document"]
            if doc:
                return Verdict(rid, system, "violation", "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW",
                               "VERIFY_DATA_FLOW_DISABLED", doc[0].fid)
            return None
        act = [o for ac, o in flags if ac]
        if act:
            return Verdict(rid, system, "violation", "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW",
                           "VERIFY_DATA_FLOW_DISABLED", act[0].fid)
        return Verdict(rid, system, "compliant", None, None, "VERIFY_DATA_FLOW_DISABLED", flags[0][1].fid)

    # -------------------------------------------------------------- backup
    def _backup(self, rid, system, latest) -> Verdict | None:
        risky = []
        safe = []
        for o in latest:
            a = o.attrs
            if a.get("record_type") == "BACKUP_ARCHIVE" and a.get("result") in ("ACTIVE", "BLOCKED"):
                (risky if a["result"] == "ACTIVE" else safe).append(o)
                continue
            ra = _truthy(a.get("restore_allowed"))
            el = _truthy(a.get("eligible"))
            blk = _truthy(a.get("deletion_block"))
            dec = a.get("decision")
            if ra is not None:
                (risky if ra else safe).append(o)
            elif el is not None:
                (risky if el and not blk else safe).append(o)
            elif dec is not None:
                (safe if str(dec).lower() == "deny" else risky).append(o)
        if not risky and not safe:
            doc = [o for o in latest if o.src == "document"]
            if doc:
                return Verdict(rid, system, "violation", "REPORT_RESTORE_RISK", "BLOCK_RESTORE",
                               "VERIFY_RESTORE_BLOCKED", doc[0].fid)
            return None
        if risky:
            return Verdict(rid, system, "violation", "REPORT_RESTORE_RISK", "BLOCK_RESTORE",
                           "VERIFY_RESTORE_BLOCKED", risky[0].fid)
        return Verdict(rid, system, "compliant", None, None, "VERIFY_RESTORE_BLOCKED", safe[0].fid)

    # ------------------------------------------------------------- decision
    def decide(self, case: Case) -> tuple[str, list[dict]]:
        if not case.authorised:
            return "NOT_APPLICABLE", []
        verdicts = self.evaluate(case)
        violations = [v for v in verdicts if v.kind == "violation"]
        status = "INCOMPLETE" if violations else "COMPLETE"
        steps = []

        def add(op, v, evidence):
            phase, state = OP_META[op]
            steps.append({"phase": phase, "system_id": v.system, "resource_id": v.rid, "operation": op,
                          "state": state, "evidence_id": evidence})

        for v in verdicts:
            if v.kind == "violation":
                add(v.finding, v, v.evidence)
                add(v.remediation, v, "")
                add(v.verification, v, "")
            elif status == "COMPLETE":
                if v.evidence:                      # a compliant state must be proven by cited evidence
                    add(v.verification, v, v.evidence)
            elif v.rid in {x.rid for x in verdicts if x.system == "account_service"} or v.kind == "retained":
                # incomplete case: the account check and policy-retained records are always verified
                add(v.verification, v, "")
        if status == "INCOMPLETE":
            for s in steps:
                if s["phase"] != "FINDING":
                    s["evidence_id"] = ""
        steps.sort(key=lambda s: (PHASES.index(s["phase"]), OP_ORDER.index(s["operation"]),
                                  s["system_id"], s["resource_id"]))
        for i, s in enumerate(steps, 1):
            s["step_no"] = i
        return status, steps
