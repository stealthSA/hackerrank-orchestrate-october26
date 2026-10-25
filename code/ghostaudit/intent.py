"""Request intent classification: does the message actually authorise deletion?

Rule-based and multilingual (EN/ES/FR/PT/KO/JA).  A request is NOT_APPLICABLE
when it declines deletion explicitly, or when it asks only for access,
correction, export, a marketing opt-out or a login/email change and carries no
deletion context.  Follow-ups about a deletion that already happened ("my
account page is gone but my profile still appears") are deletion requests.
"""
from __future__ import annotations

import re

# words that put a message in a deletion context (any supported language)
_DELETION_CONTEXT = re.compile(
    r"(delet|eras|remov|clos(e|ing|ed)\b|\bgone\b|account (was|has been|is) (closed|removed)|"
    r"left behind|still (appears|exists|existed|recognized|works)|request failed|"
    r"eliminar|eliminaci|eliminen|borrar|borren|cerrar la cuenta|"
    r"suppress|supprim|effac|cl[oô]tur|"
    r"exclus|excluir|exclua|apagar|"
    r"삭제|탈퇴|削除|消去|退会)",
    re.I,
)

# explicit declines of deletion / account closure
_DECLINES = [re.compile(p, re.I) for p in (
    r"\bnot (asking|requesting|looking)\b[^.]*\b(delet|eras|clos|remov)",
    r"\bnot (a )?request (to|for) (erase|delete|deletion|erasure)",
    r"\b(do not|don'?t|please do not|please don'?t|never) (delete|close|erase|remove)\b",
    r"\bwithout (removing|deleting|erasing)\b",
    r"\b(keep|leave) (the |my |this )?(account|profile)\b[^.]*\b(as it is|in place|active|open)\b",
    r"\bleave my profile\b",
    r"\bcontinue using the service\b",
    r"\bstill (need|want|use)\b[^.]*\b(account|receipts|service|history)",
    r"\bno (quiero|deseo) (eliminar|borrar|cerrar)",
    r"\bne (souhaite|veux) pas (supprimer|fermer)",
    r"\bn[aã]o (quero|desejo) (excluir|apagar)",
)]

# intents that are not deletion
_OTHER_INTENTS = [re.compile(p, re.I) for p in (
    r"\b(download|portable format|copy of|information (we|you) hold|what personal information|information held)\b",
    r"\b(out of date|misspelled|replace it|change the email|correct it|correction)\b",
    r"\b(reset|resetting|can'?t access)\b",
    r"\bmarketing lists only\b",
    r"\bstop the promotional\b",
    r"\bunsubscribe\b",
)]


def authorises_deletion(text: str) -> bool:
    """True when the message is (or follows up on) a genuine deletion request."""
    if not text or not text.strip():
        return False
    if any(p.search(text) for p in _DECLINES):
        return False
    has_context = bool(_DELETION_CONTEXT.search(text))
    if any(p.search(text) for p in _OTHER_INTENTS):
        # an "other" intent only wins if there is no deletion context at all
        return has_context and bool(re.search(
            r"(delet|eras|clos(e|ing)\b|account (deletion|closure)|permanent|삭제|削除)", text, re.I))
    return has_context
