import os
import sys
import time

os.environ.setdefault("OBLVN_REQUIRE_EMAIL_VERIFICATION", "false")

import pyotp
from pymongo.errors import WriteError

from backend.accounts import service
from backend.accounts.service import AuthError
from backend.auth import validate_token
from backend.db import AppendOnly, DuplicateKey, ServiceClient, UserClient, get_database
from backend.db.schema import COLLECTIONS

TAG = f"livecheck-{int(time.time())}"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  ' + detail) if detail else ''}", flush=True)


def main() -> int:
    t0 = time.monotonic()
    db = get_database()
    connect_ms = (time.monotonic() - t0) * 1000
    info = db.client.server_info()
    check("connect and ensure_schema", True, f"MongoDB {info['version']}, {connect_ms:.0f} ms including schema setup")
    t = time.monotonic()
    db.command("ping")
    check("round trip", True, f"ping {(time.monotonic() - t) * 1000:.0f} ms")

    names = set(db.list_collection_names())
    check("all collections exist", set(COLLECTIONS) <= names, f"{len(set(COLLECTIONS) & names)}/{len(COLLECTIONS)}")
    opts = db["wipe_jobs"].options()
    check("server-side validator installed", "$jsonSchema" in (opts.get("validator") or {}),
          f"validationLevel {opts.get('validationLevel')}")
    idx = db["anomalies"].index_information()
    partial = [i for i in idx.values() if i.get("partialFilterExpression")]
    check("partial unique dedupe index on server", bool(partial) and partial[0].get("unique"), str(partial[0].get("partialFilterExpression") if partial else None))
    ttl = [i for i in db["sessions"].index_information().values() if "expireAfterSeconds" in i]
    check("TTL index on sessions", bool(ttl))

    svc = ServiceClient(db)
    created = {"wipe_jobs": [], "anomalies": [], "audit_log": [], "users": [], "org_memberships": []}
    try:
        try:
            db["wipe_jobs"].insert_one({"_id": f"{TAG}-bad", "user_id": TAG, "method": "crypto_erase", "standard": "x",
                                        "device_serial": "S", "device_model": "M", "device_capacity_bytes": 1,
                                        "device_type": "nvme", "status": "exploded"})
            created["wipe_jobs"].append(f"{TAG}-bad")
            check("server rejects invalid enum (bypassing Python checks)", False)
        except WriteError as exc:
            check("server rejects invalid enum (bypassing Python checks)", exc.code == 121, f"code {exc.code}")

        job = svc.table("wipe_jobs").insert({"user_id": TAG, "method": "crypto_erase", "standard": "nist_800_88",
                                             "device_serial": TAG, "device_model": "M", "device_capacity_bytes": 10,
                                             "device_type": "nvme"}).execute().data[0]
        created["wipe_jobs"].append(job["id"])
        moved = svc.table("wipe_jobs").update({"status": "running"}).eq("id", job["id"]).eq("status", "queued").execute().data
        again = svc.table("wipe_jobs").update({"status": "running"}).eq("id", job["id"]).eq("status", "queued").execute().data
        check("atomic queued to running claim", len(moved) == 1 and again == [])

        a = svc.table("anomalies").insert({"anomaly_type": "livecheck", "severity": "low", "dedupe_key": TAG,
                                           "user_id": TAG}).execute().data[0]
        created["anomalies"].append(a["id"])
        try:
            dup = svc.table("anomalies").insert({"anomaly_type": "livecheck", "severity": "low", "dedupe_key": TAG,
                                                 "user_id": TAG}).execute().data[0]
            created["anomalies"].append(dup["id"])
            check("dedupe blocks a second open anomaly", False)
        except DuplicateKey:
            check("dedupe blocks a second open anomaly", True)
        svc.table("anomalies").update({"status": "resolved"}).eq("id", a["id"]).execute()
        b = svc.table("anomalies").insert({"anomaly_type": "livecheck", "severity": "low", "dedupe_key": TAG,
                                           "user_id": TAG}).execute().data[0]
        created["anomalies"].append(b["id"])
        n = svc.table("anomalies").insert({"anomaly_type": "livecheck", "severity": "low", "user_id": TAG}).execute().data[0]
        m = svc.table("anomalies").insert({"anomaly_type": "livecheck", "severity": "low", "user_id": TAG}).execute().data[0]
        created["anomalies"] += [n["id"], m["id"]]
        check("resolved frees the key; keyless anomalies never collide", True)

        first = svc.table("audit_log").insert({"event_type": TAG, "event_payload": "{}", "prev_entry_hash": TAG + "-0",
                                               "entry_hash": TAG + "-1", "org_id": TAG}).execute().data[0]
        created["audit_log"].append(first["id"])
        try:
            fork = svc.table("audit_log").insert({"event_type": TAG, "event_payload": "{}", "prev_entry_hash": TAG + "-0",
                                                  "entry_hash": TAG + "-2", "org_id": TAG}).execute().data[0]
            created["audit_log"].append(fork["id"])
            check("audit chain fork rejected by unique index", False)
        except DuplicateKey:
            check("audit chain fork rejected by unique index", True)
        try:
            svc.table("audit_log").update({"event_type": "x"}).eq("id", first["id"]).execute()
            check("audit log append-only", False)
        except AppendOnly:
            check("audit log append-only", True)

        svc.table("org_memberships").insert({"user_id": TAG, "org_id": TAG + "-org", "role": "operator"}).execute()
        created["org_memberships"].append(TAG)
        other = svc.table("wipe_jobs").insert({"user_id": TAG + "-other", "method": "crypto_erase", "standard": "nist_800_88",
                                               "device_serial": TAG, "device_model": "M", "device_capacity_bytes": 10,
                                               "device_type": "nvme"}).execute().data[0]
        created["wipe_jobs"].append(other["id"])
        seen = [j["id"] for j in UserClient(db, TAG).table("wipe_jobs").select("*").eq("device_serial", TAG).execute().data]
        check("policy layer hides other users' rows", job["id"] in seen and other["id"] not in seen, f"saw {len(seen)} of 2")

        email = f"{TAG}@example.com"
        pw = "Live-Check-Pass-9!"
        service.sign_up(email, pw)
        uid = service.get_user_by_email(email)["id"]
        created["users"].append(uid)
        stored = db["users"].find_one({"_id": uid})["password_hash"]
        check("argon2id hash stored", stored.startswith("$argon2id$v=19$m=65536,t=3,p=4$"))
        t = time.monotonic()
        s = service.sign_in(email, pw)
        check("password sign in", bool(s.get("access_token")), f"{(time.monotonic() - t) * 1000:.0f} ms including Argon2id")
        check("access token validates", validate_token(s["access_token"])["sub"] == uid)
        r = service.refresh(s["refresh_token"])
        try:
            service.refresh(s["refresh_token"])
            check("refresh reuse detected", False)
        except AuthError as exc:
            check("refresh reuse detected", exc.code == "refresh_reuse")
        check("reuse revokes the newer token too", validate_token(r["access_token"]) is None)
        s2 = service.sign_in(email, pw)
        secret = service.mfa_setup(uid)["secret"]
        codes = service.mfa_enable(uid, pyotp.TOTP(secret).now())
        step = service.sign_in(email, pw)
        session = service.sign_in_mfa(step["mfa_token"], codes[0])
        check("two-factor sign in with recovery code", bool(session.get("access_token")) and step.get("mfa_required"))
        service.sign_out(validate_token(s2["access_token"])["sid"])
        check("sign out revokes immediately", validate_token(s2["access_token"]) is None)
    finally:
        db["wipe_jobs"].delete_many({"$or": [{"_id": {"$in": created["wipe_jobs"]}}, {"user_id": {"$regex": f"^{TAG}"}}]})
        db["anomalies"].delete_many({"user_id": TAG})
        db["audit_log"].delete_many({"$or": [{"org_id": TAG}, {"event_type": TAG}]})
        db["org_memberships"].delete_many({"user_id": TAG})
        for uid in created["users"]:
            db["users"].delete_one({"_id": uid})
            db["sessions"].delete_many({"user_id": uid})
            db["auth_tokens"].delete_many({"user_id": uid})
        if db["audit_log"].count_documents({}) == 0:
            db["counters"].delete_one({"_id": "audit_log"})
        leftover = sum(db[c].count_documents(q) for c, q in [
            ("wipe_jobs", {"device_serial": TAG}), ("anomalies", {"user_id": TAG}), ("audit_log", {"org_id": TAG}),
            ("users", {"email": {"$regex": f"^{TAG}"}})])
        check("cleanup left no test records", leftover == 0)
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed in {time.monotonic() - t0:.1f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
