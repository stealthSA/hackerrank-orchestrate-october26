"""Link each authorised case to the resources that belong to the data subject.

Three independent signals, strongest first:

1. explicit identifier match - an evidence observation (or catalog link event)
   that carries one of the subject's current/historical emails, hashes, phone
   numbers or the stable user reference, observed inside the case window
   [requested_at, audit_at];
2. activity anchoring - the deletion worker's account-deletion event is the
   anchor of a case; it is matched to a case through the case's reported_at
   time and reported status, with elimination of events already claimed by
   other subjects (a self-calibrating time window is learned from the
   cases that are linked explicitly);
3. policy-action anchoring - anonymise/redact/disable/block actions that have
   no identifier at all (their records are already de-identified) are matched
   the same way, restricted to records that evidence shows in the window.
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field

from .common import EMAIL_RE, USER_RE, parse_ts, read_csv, rtype
from .evidence import EvidenceStore, Obs
from .identity import Identity, IdentityBook

STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


@dataclass
class Case:
    row: dict
    identity: Identity
    authorised: bool
    t_req: object = None
    t_rep: object = None
    t_audit: object = None
    explicit: dict = field(default_factory=dict)   # rid -> set(reason)
    linked: dict = field(default_factory=dict)     # rid -> set(reason)  (final)
    retained_any: set = field(default_factory=set) # retained records linked from any evidence date

    @property
    def case_id(self) -> str:
        return self.row["case_id"]


class Linker:
    def __init__(self, store: EvidenceStore, book: IdentityBook) -> None:
        self.S = store
        self.B = book
        self.ties: dict = {}
        self.act = read_csv("system_activity.csv")
        self.by_res: dict[str, list] = collections.defaultdict(list)
        for a in self.act:
            self.by_res[a["resource_id"]].append(a)
        self.links = []
        for a in self.act:
            if a["event_type"] == "LINK_RESOURCE_IDENTITY":
                self.links.append((a["resource_id"], {e.lower() for e in EMAIL_RE.findall(a["details"])},
                                   set(USER_RE.findall(a["details"])), parse_ts(a["event_time"]),
                                   a["activity_id"]))
        self.account_events = [a for a in self.act if a["event_type"] == "DELETE_RECORD"
                               and a["target_system"] == "account_service"
                               and a["source_system"] == "deletion_worker"]
        self.policy_events = [a for a in self.act if a["source_system"] == "deletion_worker"
                              and a["event_type"] in ("ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW",
                                                     "BLOCK_RESTORE", "RETAIN_RECORD")
                              and a["reported_result"] == "SUCCESS"]

    # ----------------------------------------------------------------- step 1
    def explicit_links(self, case: Case) -> dict:
        I = case.identity
        res: dict[str, set] = collections.defaultdict(set)
        for o in self.S.obs:
            t = parse_ts(o.ts)
            if t is None or t < case.t_req or t > case.t_audit:
                continue
            if not self.S.visible(o.fid, case.t_audit):
                continue
            if I.matches(o.emails, o.users, o.hashes) or (
                    o.phones and any(len(p) >= 8 and p in I.phones for p in o.phones)):
                res[o.rid].add("evidence:" + o.fid)
        for rid, em, us, t, aid in self.links:
            if case.t_req <= t <= case.t_audit and I.matches(em, us, ()):
                res[rid].add("catalog:" + aid)
        return res

    # ------------------------------------------------------------ whole set
    def link_explicit(self, cases: list[Case]) -> list[Case]:
        auth = [c for c in cases if c.authorised]
        for c in auth:
            c.explicit = self.explicit_links(c)
            c.linked = {k: set(v) for k, v in c.explicit.items()}
            self._retained_links(c)
        self.owner = collections.defaultdict(set)      # resource -> data subjects that explicitly own it
        for c in auth:
            for rid in c.explicit:
                self.owner[rid].add(c.identity.user_id)
        return auth

    def link_anchors(self, auth: list[Case], eligible_policy: set) -> None:
        self._anchor_accounts(auth, self.owner)
        self._anchor_policy_actions([c for c in auth if c.case_id in eligible_policy], self.owner)

    def _retained_links(self, case: Case) -> None:
        """Retained records (security audit log, legal hold) are kept by policy, so their identity
        link does not depend on when the file was captured; only citing them does."""
        I = case.identity
        for o in self.S.obs:
            if o.rt not in ("audit_record", "legal_hold"):
                continue
            t = parse_ts(o.ts)
            if t is None or t < case.t_req:
                continue
            if I.matches(o.emails, o.users, o.hashes):
                case.linked.setdefault(o.rid, set()).add("evidence:" + o.fid)
                case.retained_any.add(o.rid)

    # ----------------------------------------------------------------- step 2
    def _calibrate(self, auth: list[Case]) -> tuple[float, float]:
        offs = []
        for c in auth:
            accs = [r for r in c.explicit if rtype(r) == "account"]
            if len(accs) != 1:
                continue
            ev = [a for a in self.by_res.get(accs[0], []) if a in self.account_events]
            if not ev:
                continue
            d = (parse_ts(ev[0]["event_time"]) - c.t_rep).total_seconds() / 60.0
            if -180 <= d <= 60:
                offs.append(d)
        if not offs:
            return (-90.0, 15.0)
        return (min(offs) - 2.0, max(offs) + 2.0)

    def _anchor_accounts(self, auth: list[Case], owner) -> None:
        lo, hi = self._calibrate(auth)
        self.account_window = (lo, hi)
        taken = {r for c in auth for r in c.linked if rtype(r) == "account"}
        pending = [c for c in auth if not any(rtype(r) == "account" for r in c.linked)]
        # repeated requests of one subject at the same reported time are one deletion: solve it once
        reps, twins = {}, collections.defaultdict(list)
        for c in pending:
            k = (c.identity.user_id, c.row["reported_at"], c.row["reported_status"])
            if k not in reps:
                reps[k] = c
            else:
                twins[k].append(c)
        todo = list(reps.values())
        cand: dict[str, list] = {}
        for c in todo:
            want = STATUS_RESULT[c.row["reported_status"]]
            inwin = [a for a in self.account_events
                     if lo <= (parse_ts(a["event_time"]) - c.t_rep).total_seconds() / 60.0 <= hi
                     and a["resource_id"] not in taken
                     and not (owner.get(a["resource_id"], set()) - {c.identity.user_id})]
            exact = [a["resource_id"] for a in inwin if a["reported_result"] == want]
            # the workflow's result normally mirrors its reported status; fall back to any result
            cand[c.case_id] = exact or [a["resource_id"] for a in inwin]
        self._eliminate(todo, cand, "activity:account")
        for k, rep in reps.items():
            for t in twins.get(k, []):
                for rid, why in rep.linked.items():
                    if rtype(rid) == "account":
                        t.linked.setdefault(rid, set()).update(why)

    def _eliminate(self, todo, cand, reason, rtype_name="account") -> None:
        assigned = {}
        changed = True
        while changed:
            changed = False
            used = set(assigned.values())
            for c in todo:
                if c.case_id in assigned:
                    continue
                opts = [r for r in cand[c.case_id] if r not in used]
                if len(opts) == 1:
                    assigned[c.case_id] = opts[0]
                    used.add(opts[0])
                    changed = True
            # a resource that is a candidate of exactly one case is that case's resource
            used = set(assigned.values())
            count = collections.defaultdict(list)
            for c in todo:
                if c.case_id in assigned:
                    continue
                for r in cand[c.case_id]:
                    if r not in used:
                        count[r].append(c.case_id)
            for r, cs in count.items():
                if len(cs) == 1 and cs[0] not in assigned:
                    assigned[cs[0]] = r
                    changed = True
                    break
        # remaining ties: deterministic - cases by id order take candidates by event time order
        used = set(assigned.values())
        rest = [c for c in todo if c.case_id not in assigned]
        rest.sort(key=lambda c: (c.row["reported_at"], c.case_id))
        for c in rest:
            opts = sorted([r for r in cand[c.case_id] if r not in used],
                          key=lambda r: min(a["event_time"] for a in self.by_res[r]))
            if opts:
                assigned[c.case_id] = opts[0]
                used.add(opts[0])
        self.ties[reason] = self.ties.get(reason, 0) + len(rest)   # assignments made by the deterministic tie-break
        by_id = {c.case_id: c for c in todo}
        for cid, r in assigned.items():
            by_id[cid].linked.setdefault(r, set()).add(reason)

    # ----------------------------------------------------------------- step 3
    def _anchor_policy_actions(self, auth: list[Case], owner) -> None:
        """Link de-identified analytics records anonymised by a policy action."""
        evidence_rids = {}
        for o in self.S.obs:
            evidence_rids.setdefault(o.rid, []).append(o)
        claimed = {r for c in auth for r in c.linked}
        for rt in ("analytics",):
            todo = []
            cand = {}
            for c in auth:
                if any(rtype(r) == rt for r in c.linked):
                    continue
                # the case must show the policy-action pattern: some explicit policy resource
                # (redacted support / disabled flow / blocked backup) or an anchored account
                # with a policy action in its reported_at window
                evs = []
                for a in self.policy_events:
                    if rtype(a["resource_id"]) != rt:
                        continue
                    d = (parse_ts(a["event_time"]) - c.t_rep).total_seconds() / 60.0
                    if not (-45.0 <= d <= 5.0):
                        continue
                    rid = a["resource_id"]
                    if rid in claimed:
                        continue
                    # evidence inside the case window must exist for the record
                    obs = [o for o in evidence_rids.get(rid, [])
                           if c.t_req <= parse_ts(o.ts) <= c.t_audit and self.S.visible(o.fid, c.t_audit)]
                    if not obs:
                        continue
                    evs.append(rid)
                if evs:
                    todo.append(c)
                    cand[c.case_id] = evs
            self._eliminate(todo, cand, "activity:policy")
