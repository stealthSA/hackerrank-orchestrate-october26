"""Identity resolution: current + historical identifiers for each user."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .common import norm_email, read_csv


@dataclass
class Identity:
    user_id: str
    name: str = ""
    emails: set = field(default_factory=set)      # current + historical (lower-cased)
    current_email: str = ""
    hashes: set = field(default_factory=set)
    phones: set = field(default_factory=set)      # digits only
    names: set = field(default_factory=set)

    def matches(self, emails=(), users=(), hashes=()) -> bool:
        return bool(
            (self.emails & set(emails)) or (self.user_id in set(users)) or (self.hashes & set(hashes))
        )


def _digits(p: str) -> str:
    return "".join(c for c in (p or "") if c.isdigit())


class IdentityBook:
    def __init__(self) -> None:
        self.users: dict[str, Identity] = {}
        self.by_email: dict[str, set] = {}
        rows = read_csv("user_identities.csv")
        for r in rows:
            u = Identity(user_id=r["user_id"], name=r["name"], current_email=norm_email(r["email"]))
            u.emails.add(u.current_email)
            u.hashes.add(r["email_hash"].lower())
            u.phones.add(_digits(r["phone"]))
            u.names.add(r["name"])
            self.users[u.user_id] = u
        self.history: dict[str, list] = {}
        for a in read_csv("user_audit_log.csv"):
            u = self.users.get(a["user_id"])
            if not u:
                continue
            self.history.setdefault(u.user_id, []).append(a)
            f = a["field_name"]
            for v in (a["old_value"], a["new_value"]):
                if f == "email" and v:
                    u.emails.add(norm_email(v))
                    u.hashes.add(hashlib.sha256(norm_email(v).encode()).hexdigest())
                elif f == "email_hash" and v:
                    u.hashes.add(v.lower())
                elif f == "phone" and v:
                    u.phones.add(_digits(v))
        for u in self.users.values():
            for e in u.emails:
                self.by_email.setdefault(e, set()).add(u.user_id)

    def resolve(self, email: str) -> Identity | None:
        ids = self.by_email.get(norm_email(email), set())
        if not ids:
            return None
        # prefer the user whose *current* email matches
        for uid in sorted(ids):
            if self.users[uid].current_email == norm_email(email):
                return self.users[uid]
        return self.users[sorted(ids)[0]]
