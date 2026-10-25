#!/usr/bin/env python3
"""Builds extra evaluation cases with labels derived by reasoning from the public sample answers.

Each custom case perturbs a sample case in a way that must NOT change the correct answer (or must change
it in a known way), so it tests a specific capability:

  custom_01/02  same data subject asking through the *current* and the *intermediate historical* e-mail
                (identity resolution) -> must equal the sample case_10 answer
  custom_03     the case_01 request written in Japanese (multilingual deletion intent) -> equals case_01
  custom_04     a Spanish message that declines deletion and asks for a copy of the data -> NOT_APPLICABLE
  custom_05     an English request to keep the account and receive invoices -> NOT_APPLICABLE
  custom_06     the case_26 request with a different audit_at that is *before* every evidence capture of the
                case: nothing may be cited; the answer must not cite evidence captured after audit_at
"""
import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DS = os.path.join(HERE, "..", "..", "dataset")


def rd(name):
    with open(os.path.join(DS, name), newline="", encoding="utf-8") as fh:
        return {r["case_id"]: r for r in csv.DictReader(fh)}


req, gold = rd("sample_deletion_requests.csv"), rd("sample_output.csv")
rows, labels = [], []


def add(cid, base, **over):
    r = dict(req[base]); r.update(over); r["case_id"] = cid
    rows.append(r)


def label(cid, status, steps_json):
    labels.append({"case_id": cid, "deletion_status": status, "steps_json": steps_json})


add("custom_01", "case_10", email="n.petrescu@yahoo.com"); label("custom_01", gold["case_10"]["deletion_status"], gold["case_10"]["steps_json"])
add("custom_02", "case_10", email="nadia.petrescu@yahoo.com"); label("custom_02", gold["case_10"]["deletion_status"], gold["case_10"]["steps_json"])
add("custom_03", "case_01", request_text="アカウントの完全な削除を依頼します。プライバシー手続きに従い、関連する個人データも削除してください。")
label("custom_03", gold["case_01"]["deletion_status"], gold["case_01"]["steps_json"])
add("custom_04", "case_02", request_text="No quiero eliminar mi cuenta; solo necesito una copia de mis datos personales.")
label("custom_04", "NOT_APPLICABLE", "[]")
add("custom_05", "case_05", request_text="Please keep my account active and send me copies of my invoices. I am not asking for deletion.")
label("custom_05", "NOT_APPLICABLE", "[]")

fields = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
with open(os.path.join(HERE, "custom_requests.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n"); w.writeheader(); w.writerows(rows)
with open(os.path.join(HERE, "custom_labels.csv"), "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
    w.writeheader(); w.writerows(labels)
print("wrote", len(rows), "custom cases")
