"""Shared helpers: paths, time handling, identifier patterns."""
from __future__ import annotations

import csv
import os
import re
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATASET = os.path.join(ROOT, "dataset")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
RID_RE = re.compile(
    r"\b(account|search|analytics|support|email_delivery|cache|audit_record|export|"
    r"data_flow|backup|tombstone|legal_hold|object|marketing)_(\d+)\b"
)

# resource id prefix -> (type, owning system)
RTYPES = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "email_delivery": "email_delivery_service",
    "cache": "cache_service",
    "audit_record": "security_service",
    "export": "export_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "tombstone": "identity_service",
    "legal_hold": "legal_service",
    "object": "object_store",
    "marketing": "marketing_platform",
}


def rtype(rid: str) -> str:
    m = re.match(r"([a-z_]+?)_\d+$", rid)
    return m.group(1) if m else ""


def parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            d = datetime.strptime(s, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d
        except ValueError:
            continue
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except ValueError:
        return None


def read_csv(name: str) -> list[dict]:
    with open(os.path.join(DATASET, name), newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def norm_email(e: str | None) -> str | None:
    return e.strip().lower() if e else None
