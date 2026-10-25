"""Hybrid reading of screenshots and PDFs.

Layer 1 (always, local, free): a multi-pass OCR ensemble (original + upscaled, two page-segmentation modes)
Layer 2 (optional): a vision-language model transcribes the screenshot.  Enabled only when
    ANTHROPIC_API_KEY is set; results are cached on disk by content hash and token usage is recorded.
Layer 3 (always): identifier snapping.  OCR/VLM text is noisy ("areedi433@gmail.com", "support_9638"), so every
    e-mail address / resource id that is *not* known to the dataset is mapped to the single closest known value
    when it is within a tiny edit distance.  Only participant-facing data is used as the vocabulary.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request

from .common import RID_RE, RTYPES, ROOT, read_csv

CACHE_DIR = os.path.join(ROOT, "code", ".vision_cache")
USAGE = {"calls": 0, "cache_hits": 0, "input_tokens": 0, "output_tokens": 0, "models": {}}

VLM_PROMPT = (
    "Transcribe every piece of text visible in this application screenshot exactly as written, one row or "
    "field per line. Keep e-mail addresses, resource ids (such as account_123, support_45, export_9), "
    "file names and timestamps character-exact. Do not interpret or summarise."
)


# ------------------------------------------------------------------ local OCR ensemble
def _tesseract(path: str, psm: str | None) -> str:
    cmd = ["tesseract", path, "-"] + (["--psm", psm] if psm else [])
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return ""


def ocr_ensemble(path: str) -> str:
    texts = [_tesseract(path, None)]
    try:
        from PIL import Image, ImageOps  # optional
        with Image.open(path) as im:
            g = ImageOps.autocontrast(im.convert("L"))
            big = g.resize((g.width * 2, g.height * 2), Image.LANCZOS)
            with tempfile.TemporaryDirectory() as td:
                p = os.path.join(td, "x2.png")
                big.save(p)
                texts += [_tesseract(p, "6"), _tesseract(p, "11")]
    except Exception:
        pass
    return "\n".join(texts)


# ------------------------------------------------------------------ optional VLM pass
def vlm_enabled() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY")) and os.environ.get("GHOST_VLM", "1") != "0"


def vlm_transcribe(path: str) -> str:
    """Transcribe an image with a vision model (Anthropic Messages API). '' when disabled or on failure."""
    if not vlm_enabled():
        return ""
    model = os.environ.get("GHOST_VLM_MODEL", "claude-sonnet-5-5")
    data = open(path, "rb").read()
    key = hashlib.sha256(data + model.encode()).hexdigest()
    os.makedirs(CACHE_DIR, exist_ok=True)
    cpath = os.path.join(CACHE_DIR, key + ".json")
    if os.path.exists(cpath):
        USAGE["cache_hits"] += 1
        return json.load(open(cpath))["text"]
    body = {"model": model, "max_tokens": 2000, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                     "data": base64.b64encode(data).decode()}},
        {"type": "text", "text": VLM_PROMPT}]}]}
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
        headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    try:
        resp = json.load(urllib.request.urlopen(req, timeout=120))
    except Exception as exc:  # never let the optional layer break the run
        print(f"[vision] VLM unavailable for {os.path.basename(path)}: {exc}")
        return ""
    text = "".join(b.get("text", "") for b in resp.get("content", []))
    u = resp.get("usage", {})
    USAGE["calls"] += 1
    USAGE["input_tokens"] += u.get("input_tokens", 0)
    USAGE["output_tokens"] += u.get("output_tokens", 0)
    m = USAGE["models"].setdefault(model, {"calls": 0, "input_tokens": 0, "output_tokens": 0})
    m["calls"] += 1
    m["input_tokens"] += u.get("input_tokens", 0)
    m["output_tokens"] += u.get("output_tokens", 0)
    json.dump({"text": text, "usage": u}, open(cpath, "w"))
    return text


def read_image(path: str) -> str:
    return ocr_ensemble(path) + "\n" + vlm_transcribe(path)


# ------------------------------------------------------------------ identifier snapping
def edit_distance(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _nearest(token: str, vocab, cap: int):
    best, best_d, tie = None, cap + 1, False
    for v in vocab:
        d = edit_distance(token, v, cap)
        if d < best_d:
            best, best_d, tie = v, d, False
        elif d == best_d and v != best:
            tie = True
    return best if best_d <= cap and not tie else None


_EMAILISH = re.compile(r"[A-Za-z0-9._+\-]+(?: [A-Za-z0-9._+\-]+)?@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_RIDISH = re.compile(r"\b(" + "|".join(sorted(set(re.escape(p) for p in {
    "account", "search", "export", "support", "analytics", "marketing", "object", "backup", "data_flow",
    "audit_record", "legal_hold", "tombstone"}), key=len, reverse=True)) + r")[_ ](\d+)\b")


class Snapper:
    def __init__(self, emails: set, rids: set) -> None:
        self.emails = {e.lower() for e in emails}
        self.by_prefix: dict[str, set] = {}
        for r in rids:
            m = RID_RE.fullmatch(r)
            if m:
                self.by_prefix.setdefault(r.rsplit("_", 1)[0], set()).add(r)
        self.rids = set(rids)
        self.fixed = 0

    def _fix_email(self, tok: str) -> str:
        t = tok.lower()
        cands = [t] + ([t.replace(" ", sep) for sep in (".", "", "_", "-")] if " " in t else [])
        for c in cands:
            if c in self.emails:
                return c
        for c in cands:
            if len(c) >= 10:
                hit = _nearest(c, self.emails, 2)
                if hit:
                    return hit
        return tok

    def _fix_rid(self, m: re.Match) -> str:
        prefix, num = m.group(1), m.group(2)
        cand = f"{prefix}_{num}"
        pool = self.by_prefix.get(prefix, set())
        if cand in pool or not pool:
            return cand
        hit = _nearest(cand, pool, 1)
        return hit or cand

    def snap(self, text: str) -> str:
        def e(m):
            new = self._fix_email(m.group(0))
            self.fixed += new != m.group(0)
            return new

        def r(m):
            new = self._fix_rid(m)
            self.fixed += new != m.group(0)
            return new

        return _RIDISH.sub(r, _EMAILISH.sub(e, text))


def known_vocabulary() -> tuple[set, set]:
    emails, rids = set(), set()
    for r in read_csv("user_identities.csv"):
        emails.add(r["email"].lower())
    for r in read_csv("user_audit_log.csv"):
        for k in ("old_value", "new_value"):
            if "@" in (r.get(k) or ""):
                emails.add(r[k].lower())
    for r in read_csv("deletion_requests.csv") + read_csv("sample_deletion_requests.csv"):
        emails.add(r["email"].lower())
    for a in read_csv("system_activity.csv"):
        rids.add(a["resource_id"])
    return emails, rids
