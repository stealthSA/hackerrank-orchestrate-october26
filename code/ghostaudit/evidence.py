"""Evidence ingestion: turns every supplied evidence file (SQL snapshots, JSON
exports, logs, text handovers, PDFs, screenshots) into a uniform list of
observations about resources, plus "coverage" statements (which systems a
snapshot fully enumerates, so that a missing resource can be proven absent).
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass, field

from . import vision

from .common import (DATASET, EMAIL_RE, HASH_RE, RID_RE, RTYPES, USER_RE,
                     parse_ts, read_csv, rtype)

NAME_KEYS = {"full_name", "display_name", "requester_name", "name"}
PHONE_KEYS = ("phone",)
USER_KEYS = {"customer_reference", "subject_reference", "user_id", "correlation_key",
             "subject_selector", "lookup_value", "subject_ref", "subject_key", "lookup_key",
             "match_key", "scan_key", "owner_key"}
SKIP_ID_KEYS = {"resource_id", "source_resource_id", "trace_id", "requestid", "ticket_id",
                "order_reference", "archive_key", "object_key", "archive_path", "file", "file_name"}


@dataclass
class Obs:
    fid: str
    ts: str                      # observation time (ISO)
    rid: str
    system: str
    present: bool | None         # explicit presence if known
    emails: set = field(default_factory=set)
    users: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    names: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    attrs: dict = field(default_factory=dict)
    src: str = ""                # origin detail (table/format)

    @property
    def rt(self) -> str:
        return rtype(self.rid)


@dataclass
class Coverage:
    fid: str
    ts: str
    system: str
    src: str = ""


def _clean(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = v.strip()
        if v.lower() in ("", "null", "none", "n/a", "-"):
            return None
    return v


def collect_ids(d, o: Obs, key: str = "") -> None:
    """Recursively harvest identifiers from a record into the observation."""
    if isinstance(d, dict):
        for k, v in d.items():
            collect_ids(v, o, k.lower())
        return
    if isinstance(d, list):
        for v in d:
            collect_ids(v, o, key)
        return
    v = _clean(d)
    if v is None or not isinstance(v, str):
        return
    if key in SKIP_ID_KEYS or key == "message_text":
        return
    if key == "email_hash":
        o.hashes.add(v.lower())
        return
    if any(p in key for p in PHONE_KEYS):
        o.phones.add(re.sub(r"\D", "", v))
        return
    if key in NAME_KEYS:
        o.names.add(v)
        return
    for m in EMAIL_RE.findall(v):
        o.emails.add(m.lower())
    for m in USER_RE.findall(v):
        o.users.add(m)
    for m in HASH_RE.findall(v):
        o.hashes.add(m)


def _boolish(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().strip('"').lower()
    if s in ("true", "1", "yes", "y"):
        return True
    if s in ("false", "0", "no", "n"):
        return False
    return None


STATE_KEYS = ("enabled", "restore_allowed", "retention_until", "retained_until", "event_code",
              "event_name", "direct_identifiers", "status_code", "http_status", "rows",
              "account_status", "available", "download_available", "result", "archive_present",
              "scheduler_registered", "last_run", "last_delivery_status", "marker_found",
              "eligible", "deletion_block", "decision", "policy", "access", "reason",
              "record_type", "detector", "matched_value", "message_text", "excerpt",
              "message_excerpt", "audience_cohort", "index_name", "index", "total",
              "last_write", "mode", "connector_name", "storage_class", "email_opt_in",
              "retention_reason", "source_resource_id")


def record_obs(fid: str, ts: str, system: str, rec: dict, src: str, rid: str | None = None,
               present: bool | None = None) -> Obs | None:
    rid = rid or rec.get("resource_id")
    if not rid or not RID_RE.fullmatch(str(rid)):
        return None
    o = Obs(fid=fid, ts=ts, rid=rid, system=system or RTYPES.get(rtype(rid), ""), present=present, src=src)
    collect_ids(rec, o)
    flat = {}

    def walk(d):
        for k, v in d.items():
            if isinstance(v, dict):
                walk(v)
            else:
                flat[k.lower()] = v

    walk(rec)
    for k in STATE_KEYS:
        if k in flat:
            o.attrs[k] = flat[k]
    if "excerpt" in o.attrs and "message_excerpt" not in o.attrs:
        o.attrs["message_excerpt"] = o.attrs["excerpt"]
    # SQL excerpt / message text can carry email addresses
    for k in ("message_text", "message_excerpt"):
        t = o.attrs.get(k)
        if isinstance(t, str):
            for m in EMAIL_RE.findall(t):
                o.emails.add(m.lower())
    return o


class EvidenceStore:
    def __init__(self) -> None:
        self.files: dict[str, dict] = {}
        self.obs: list[Obs] = []
        self.cov: list[Coverage] = []
        self.by_rid: dict[str, list[Obs]] = {}

    # ---------------------------------------------------------------- build
    def load(self) -> "EvidenceStore":
        deferred = []
        for row in read_csv("evidence_files.csv"):
            self.files[row["file_id"]] = row
            path = os.path.join(DATASET, row["file_path"])
            ext = os.path.splitext(path)[1].lower()
            try:
                if ext == ".sql":
                    self._sql(row, path)
                elif ext == ".json":
                    self._json(row, path)
                elif ext == ".log":
                    self._log(row, path)
                elif ext == ".txt":
                    self._txt(row, path)
                elif ext == ".pdf":
                    deferred.append((row, _pdf_text(path)))
                elif ext in (".png", ".jpg", ".jpeg"):
                    deferred.append((row, vision.read_image(path)))
            except Exception as exc:  # keep going; evidence is best-effort
                print(f"[evidence] {row['file_id']} {row['file_path']}: {exc}")
        # documents/screenshots are read last: their noisy identifiers are snapped to the vocabulary
        # known from the structured evidence and the dataset tables
        emails, rids = vision.known_vocabulary()
        rids |= {o.rid for o in self.obs}
        snapper = vision.Snapper(emails, rids)
        for row, text in deferred:
            try:
                self._doc(row, snapper.snap(text))
            except Exception as exc:
                print(f"[evidence] {row['file_id']} {row['file_path']}: {exc}")
        self.snapped = snapper.fixed
        for o in self.obs:
            self.by_rid.setdefault(o.rid, []).append(o)
        return self

    def _add(self, o: Obs | None) -> None:
        if o is not None:
            self.obs.append(o)

    # ------------------------------------------------------------------ SQL
    def _sql(self, row, path) -> None:
        fid, cap = row["file_id"], row["captured_at"]
        text = open(path, encoding="utf-8").read()
        con = sqlite3.connect(":memory:")
        con.executescript(text)
        con.row_factory = sqlite3.Row
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        for t in tables:
            cols = [r[1] for r in con.execute(f"pragma table_info({t})")]
            rows = [dict(r) for r in con.execute(f"select * from {t}")]
            if t == "snapshot_scope":
                for r in rows:
                    self.cov.append(Coverage(fid, r["captured_at"], r["origin_system"], "inventory"))
                continue
            if "record_json" in cols:
                for r in rows:
                    rec = json.loads(r["record_json"])
                    self._add(record_obs(fid, cap, r["origin_system"], rec, t,
                                         rid=r["resource_id"], present=True))
                    self.cov.append(Coverage(fid, cap, r["origin_system"], t))
                continue
            system = _table_system(t)
            for r in rows:
                self._add(record_obs(fid, cap, system, r, t, present=True))
            if system and not t.startswith("snapshot"):
                # a table snapshot enumerates its system only for the primary-style tables
                if not any(c.fid == fid and c.system == system and c.src == "table" for c in self.cov):
                    self.cov.append(Coverage(fid, cap, system, "table"))

    # ----------------------------------------------------------------- JSON
    def _json(self, row, path) -> None:
        fid, cap = row["file_id"], row["captured_at"]
        d = json.load(open(path, encoding="utf-8"))
        if "snapshots" in d:
            for s in d["snapshots"]:
                ts = s.get("captured_at") or cap
                recs = s["records"]
                store = s["data_store"]
                if s["collection"] == "operational_record_history":
                    for r in recs:
                        self._lookup_record(fid, r, "history")
                    continue
                for r in recs:
                    self._add(record_obs(fid, ts, store, r, s["collection"], present=True))
                self.cov.append(Coverage(fid, ts, store, s["collection"]))
        elif "service_exports" in d:
            for svc, groups in d["service_exports"].items():
                for gname, items in groups.items():
                    for it in items:
                        self._export_item(fid, svc, gname, it, d.get("exported_at") or cap)
        elif "records" in d and isinstance(d["records"], list):
            for r in d["records"]:
                if "record_type" in r:
                    self._lookup_record(fid, r, "ledger")
                else:
                    self._add(record_obs(fid, d.get("captured_at") or cap, d.get("source", ""), r,
                                         d.get("collection", ""), present=True))
            if d.get("collection") and d.get("source"):
                self.cov.append(Coverage(fid, d.get("captured_at") or cap, d["source"], d["collection"]))

    def _lookup_record(self, fid, r, src) -> None:
        res = str(r.get("result", "")).upper()
        present = None
        if res in ("NOT_FOUND", "ABSENT", "MISS"):
            present = False
        elif res in ("FOUND", "IDENTIFIABLE", "PRESENT", "ACTIVE", "ENABLED"):
            present = True
        o = record_obs(fid, r.get("recorded_at"), r.get("system", ""), r, src, present=present)
        if o is not None:
            o.attrs["result"] = res
            for k in ("subject_reference", "lookup_value"):
                v = _clean(r.get(k))
                if isinstance(v, str):
                    for m in EMAIL_RE.findall(v):
                        o.emails.add(m.lower())
                    for m in USER_RE.findall(v):
                        o.users.add(m)
                    o.attrs["subject_text"] = v
            self._add(o)

    def _export_item(self, fid, svc, gname, it, ts) -> None:
        rec = dict(it)
        ots = rec.get("observed_at") or ts
        present = None
        if gname == "profile_lookups":
            sc = rec.get("status_code")
            present = bool(sc == 200 or rec.get("profile"))
            if rec.get("profile"):
                rec = {**rec, **rec["profile"]}
        elif gname == "index_queries":
            hits = rec.get("hits") or {}
            present = bool(hits.get("total") or hits.get("documents"))
            for dct in hits.get("documents", []) or []:
                o = record_obs(fid, ots, svc, {**dct, "query": rec.get("query")}, gname,
                               rid=dct.get("resource_id") or rec.get("resource_id"), present=True)
                if o is not None:
                    q = rec.get("query")
                    if isinstance(q, str):
                        for m in EMAIL_RE.findall(q):
                            o.emails.add(m.lower())
                        for m in USER_RE.findall(q):
                            o.users.add(m)
                    self._add(o)
            if present:
                return
            o = record_obs(fid, ots, svc, rec, gname, present=False)
            if o is not None:
                q = rec.get("query")
                if isinstance(q, str):
                    for m in EMAIL_RE.findall(q):
                        o.emails.add(m.lower())
                    for m in USER_RE.findall(q):
                        o.users.add(m)
                self._add(o)
            return
        else:
            present = True
        o = record_obs(fid, ots, svc, rec, gname, present=present)
        self._add(o)

    # ----------------------------------------------------------------- TXT
    def _txt(self, row, path) -> None:
        fid = row["file_id"]
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if not ln.startswith("- "):
                continue
            parts = [p.strip() for p in ln[2:].split("|")]
            if len(parts) < 6:
                continue
            ts, system, rid, rtype_, result, subj = parts[:6]
            rec = {"resource_id": rid, "record_type": rtype_, "result": result, "system": system,
                   "recorded_at": ts, "subject_reference": subj}
            self._lookup_record(fid, rec, "handover")

    # ----------------------------------------------------------- documents
    def _catalog_aliases(self) -> dict:
        """display reference -> resource id, from the data catalog's own link events."""
        if getattr(self, "_aliases", None) is None:
            self._aliases, self._catalog_system = {}, {}
            for a in read_csv("system_activity.csv"):
                if a["event_type"] != "LINK_RESOURCE_IDENTITY":
                    continue
                self._catalog_system[a["resource_id"]] = a["target_system"]
                m = re.search(r"(?:linked|confirmed) (\S+) \(([^)]+)\)", a["details"])
                if m and m.group(2) != m.group(1):
                    self._aliases[m.group(2).lower()] = a["resource_id"]
        return self._aliases

    def _doc(self, row, text: str) -> None:
        fid, cap = row["file_id"], row["captured_at"]
        if not text.strip():
            return
        lines = text.splitlines()
        all_emails = {e.lower() for e in EMAIL_RE.findall(text)}
        all_users = set(USER_RE.findall(text))
        seen = set()
        n_rids = len({m.group(0) for m in RID_RE.finditer(text)})
        # (1) resource ids named in the document: identifiers are taken from the surrounding rows only,
        #     so that a list of many records does not attach every identifier to every record.
        for i, ln in enumerate(lines):
            for m in RID_RE.finditer(ln):
                rid = m.group(0)
                lo, hi = max(0, i - 1), min(len(lines), i + 4)
                win = "\n".join(lines[lo:hi])
                o = Obs(fid=fid, ts=cap, rid=rid, system=RTYPES.get(rtype(rid), ""), present=True,
                        emails={e.lower() for e in EMAIL_RE.findall(win)}, users=set(USER_RE.findall(win)),
                        src="document")
                o.attrs["doc_text"] = win
                if n_rids == 1 and not (o.emails or o.users):
                    # a single-record document (invoice, attachment, ticket): its identifiers describe that record
                    o.emails, o.users = set(all_emails), set(all_users)
                self.obs.append(o)
                seen.add(rid)
        # (2) catalog display references (statement numbers, file names, user keys) that identify a resource
        def norm(x: str) -> str:
            x = re.sub(r"\.(pdf|pdt|png|jpg|zip)$", "", x.lower().strip())
            return re.sub(r"[^a-z0-9]", "", x)

        low = norm(text)          # OCR turns "_" into spaces and "pdf" into "pdt"; compare alphanumerics only
        for alias, rid in self._catalog_aliases().items():
            if rid in seen or len(norm(alias)) < 6 or norm(alias) not in low:
                continue
            o = Obs(fid=fid, ts=cap, rid=rid, system=RTYPES.get(rtype(rid), ""), present=True,
                    emails=set(all_emails), users=set(all_users), src="document")
            o.attrs["doc_text"] = text
            self.obs.append(o)
            seen.add(rid)

    # ----------------------------------------------------------------- LOG
    def _log(self, row, path) -> None:
        fid, cap = row["file_id"], row["captured_at"]
        events = []
        for ln in open(path, encoding="utf-8", errors="ignore"):
            ln = ln.rstrip("\n")
            if not ln.strip():
                continue
            ev = parse_log_line(ln)
            if ev:
                events.append(ev)
        # group by trace to join identity keys from the "started" line
        keys_by_trace: dict[str, dict] = {}
        for ev in events:
            a = ev["attrs"]
            tr = ev["trace"]
            for k in ("lookup_key", "match_key", "subject_key", "scan_key", "owner_key", "subject_ref"):
                if k in a and tr:
                    keys_by_trace.setdefault(tr, {})[k] = a[k]
        for ev in events:
            a = ev["attrs"]
            if ev["event"] == "record_lookup":
                rec = {"resource_id": a.get("resource_id"), "record_type": a.get("record_type"),
                       "result": a.get("result"), "system": a.get("system"),
                       "recorded_at": ev["ts"], "subject_reference": a.get("subject_reference")}
                self._lookup_record(fid, rec, "log")
                continue
            rid = a.get("resource_id")
            if not rid or not RID_RE.fullmatch(rid):
                continue
            if ev["event"].endswith("_started"):
                continue
            rec = dict(a)
            present = None
            if "rows" in a:
                present = _int(a["rows"]) > 0
            if "http_status" in a:
                present = str(a["http_status"]) == "200"
            if "result" in a and ev["event"] == "index_query_completed":
                present = str(a["result"]).lower() == "hit"
            if "marker_found" in a:
                present = None
            if ev["event"] in ("export_download_check_completed",):
                present = _boolish(a.get("available"))
            if ev["event"] in ("restore_policy_read_completed",):
                present = _boolish(a.get("archive_present"))
            if present is None and a.get("rows") is None and a.get("http_status") is None:
                if ev["event"].endswith(("_completed", "_read", "_loaded", "_scan", "_evaluated",
                                         "_heartbeat", "_authorization_completed", "_check")):
                    present = True
            o = record_obs(fid, ev["ts"], RTYPES.get(rtype(rid), ""), rec, "log:" + ev["event"], present=present)
            if o is None:
                continue
            o.attrs["event"] = ev["event"]
            for k, v in keys_by_trace.get(ev["trace"], {}).items():
                for m in EMAIL_RE.findall(str(v)):
                    o.emails.add(m.lower())
                for m in USER_RE.findall(str(v)):
                    o.users.add(m)
            self._add(o)

    # -------------------------------------------------------------- queries
    def visible(self, fid: str, audit_at) -> bool:
        """An evidence item captured after audit_at must never influence (or be cited by) the case."""
        cap = parse_ts(self.files[fid]["captured_at"]) if fid in self.files else None
        return cap is not None and cap <= audit_at

    def for_rid(self, rid: str) -> list[Obs]:
        return self.by_rid.get(rid, [])


# ---------------------------------------------------------------- helpers
def _int(v) -> int:
    try:
        return int(str(v).strip('"'))
    except ValueError:
        return 0


def _table_system(t: str) -> str:
    t = t.lower()
    if t.startswith("customer_profiles"):
        return "account_service"
    if t.startswith("search_documents"):
        return "search_service"
    m = {
        "customer_search_documents": "search_service",
        "customer_analytics_profiles": "analytics_platform",
        "support_records": "support_platform",
        "customer_exports": "export_service",
        "connector_subscriptions": "integration_service",
        "backup_restore_entries": "backup_service",
        "security_audit_records": "security_service",
    }
    return m.get(t, "")


_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def _kv(text: str) -> dict:
    out = {}
    for k, v in _KV_RE.findall(text):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        v = v.replace('\\"', '"')
        out[k] = None if v.lower() in ("null", "none") else v
    return out


def parse_log_line(ln: str) -> dict | None:
    m = re.match(r"(\d{4}-\d\d-\d\dT[\d:]+Z)\s+(.*)$", ln)
    if not m:
        return None
    ts, rest = m.group(1), m.group(2)
    attrs: dict = {}
    trace = ""
    if rest.startswith("{"):
        try:
            d = json.loads(rest)
        except ValueError:
            return None
        attrs = {k: (None if v in ("null", None) else v) for k, v in d.items()}
        trace = attrs.get("trace_id", "")
    elif rest.startswith("|") or " | " in rest:
        parts = [p.strip() for p in rest.lstrip("| ").split(" | ")]
        if len(parts) < 5:
            return None
        trace = parts[2]
        attrs = _kv(parts[-1])
        attrs["event"] = parts[3]
        attrs["level"] = parts[0]
    elif rest.startswith("["):
        bm = re.match(r"\[(\w+)\] \[(\S+)\] \[(\S+)\] (\w+):\s*(.*)$", rest)
        if not bm:
            return None
        trace = bm.group(3)
        attrs = _kv(bm.group(5))
        attrs["event"] = bm.group(4)
        attrs["level"] = bm.group(1)
    else:
        # "<12>1 node-3 service trace_id - - level=..." (syslog) or plain kv
        attrs = _kv(rest)
        trace = attrs.get("trace_id") or attrs.get("requestId") or ""
        if "message" in attrs and attrs["message"]:
            inner = _kv(attrs["message"])
            attrs.update(inner)
        sm = re.match(r"<\d+>1 \S+ (\S+) (\S+) - - ", rest)
        if sm:
            trace = sm.group(2)
    if "event" not in attrs or not attrs.get("event"):
        return None
    return {"ts": ts, "event": attrs["event"], "attrs": attrs, "trace": trace}


def _pdf_text(path: str) -> str:
    try:
        return subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True, text=True,
                              timeout=60).stdout
    except Exception:
        return ""


def _ocr_text_legacy(path: str) -> str:
    try:
        return subprocess.run(["tesseract", path, "-"], capture_output=True, text=True,
                              timeout=120).stdout
    except Exception:
        return ""
