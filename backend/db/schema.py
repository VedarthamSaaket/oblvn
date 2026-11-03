import uuid
from datetime import datetime, timezone

from pymongo import ASCENDING, DESCENDING, IndexModel


class ValidationError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


ROLES = ["org_admin", "team_lead", "operator"]
JOB_STATUSES = ["pending_approval", "queued", "running", "completed", "failed", "cancelled"]
METHODS = ["binary_overwrite", "crypto_erase", "full_sanitization"]
DEVICE_TYPES = ["hdd", "ssd", "nvme", "usb_flash", "file"]
NIST = ["purge", "clear", "none", "not_applicable"]
SEVERITIES = ["low", "medium", "high", "critical"]
ANOMALY_STATUSES = ["open", "acknowledged", "resolved"]
FEEDBACK = ["true_positive", "false_positive"]
SENSITIVITIES = ["low", "medium", "high"]

COLLECTIONS: dict[str, dict] = {
    "organisations": {
        "key": "id",
        "required": ["name"],
        "defaults": {"approval_gate_enabled": False, "audit_retention_days": 2555, "anomaly_sensitivity": "medium",
                     "data_minimisation_config": None, "timezone": "UTC", "work_start_hour": 7, "work_end_hour": 20,
                     "created_at": _now},
        "enums": {"anomaly_sensitivity": SENSITIVITIES},
        "ranges": {"work_start_hour": (0, 23), "work_end_hour": (1, 24)},
        "indexes": [],
    },
    "org_memberships": {
        "key": "id",
        "required": ["user_id", "org_id", "role"],
        "defaults": {"team_id": None, "invited_at": _now, "joined_at": None},
        "enums": {"role": ROLES},
        "indexes": [IndexModel([("user_id", ASCENDING), ("org_id", ASCENDING)], unique=True),
                    IndexModel([("org_id", ASCENDING)])],
    },
    "wipe_jobs": {
        "key": "id",
        "required": ["user_id", "method", "standard", "device_serial", "device_model", "device_capacity_bytes",
                     "device_type"],
        "defaults": {"status": "queued", "passes_completed": 0, "options": dict, "cancel_requested": False,
                     "created_at": _now},
        "enums": {"status": JOB_STATUSES, "method": METHODS, "device_type": DEVICE_TYPES, "nist_category": NIST},
        "indexes": [IndexModel([("status", ASCENDING)]), IndexModel([("user_id", ASCENDING), ("created_at", DESCENDING)]),
                    IndexModel([("org_id", ASCENDING), ("completed_at", ASCENDING)]),
                    IndexModel([("agent_id", ASCENDING), ("status", ASCENDING), ("created_at", ASCENDING)]),
                    IndexModel([("device_serial", ASCENDING)])],
    },
    "audit_log": {
        "key": "id",
        "serial": True,
        "append_only": True,
        "required": ["event_type", "event_payload", "prev_entry_hash", "entry_hash"],
        "defaults": {"org_id": None, "user_id": None, "is_anomaly": False, "anomaly_severity": None,
                     "anomaly_type": None, "created_at": _now},
        "computed": {"chain_key": lambda d: d.get("org_id") or "global"},
        "indexes": [IndexModel([("chain_key", ASCENDING), ("prev_entry_hash", ASCENDING)], unique=True),
                    IndexModel([("chain_key", ASCENDING), ("_id", ASCENDING)]),
                    IndexModel([("user_id", ASCENDING)]), IndexModel([("org_id", ASCENDING)]),
                    IndexModel([("event_type", ASCENDING), ("created_at", ASCENDING)])],
    },
    "anomalies": {
        "key": "id",
        "required": ["anomaly_type", "severity"],
        "defaults": {"status": "open", "detector": "rule", "model_score": None, "feedback": None,
                     "detected_at": _now},
        "enums": {"severity": SEVERITIES, "status": ANOMALY_STATUSES, "feedback": FEEDBACK},
        "computed": {"active_dedupe_key": lambda d: d.get("dedupe_key") if d.get("dedupe_key") and
                     d.get("status", "open") in ("open", "acknowledged") else None},
        "indexes": [IndexModel([("active_dedupe_key", ASCENDING)], unique=True,
                               partialFilterExpression={"active_dedupe_key": {"$type": "string"}}),
                    IndexModel([("org_id", ASCENDING), ("detected_at", DESCENDING)]),
                    IndexModel([("user_id", ASCENDING), ("detected_at", DESCENDING)]),
                    IndexModel([("status", ASCENDING)]),
                    IndexModel([("org_id", ASCENDING), ("anomaly_type", ASCENDING), ("feedback", ASCENDING)])],
    },
    "agents": {
        "key": "id",
        "required": ["user_id", "name", "token_hash"],
        "defaults": {"org_id": None, "revoked_at": None, "created_at": _now},
        "indexes": [IndexModel([("token_hash", ASCENDING)], unique=True), IndexModel([("user_id", ASCENDING)]),
                    IndexModel([("org_id", ASCENDING)])],
    },
    "agent_pairing_codes": {
        "key": "code_hash",
        "required": ["code_hash", "user_id", "name", "expires_at"],
        "defaults": {"org_id": None, "used_at": None, "created_at": _now},
        "indexes": [],
    },
    "agent_devices": {
        "key": None,
        "required": ["agent_id", "serial", "device"],
        "defaults": {"reported_at": _now},
        "indexes": [IndexModel([("agent_id", ASCENDING), ("serial", ASCENDING)], unique=True)],
    },
    "smart_history": {
        "key": None,
        "required": ["serial", "captured_on", "snapshot"],
        "defaults": {"captured_at": _now, "org_id": None},
        "indexes": [IndexModel([("serial", ASCENDING), ("captured_on", ASCENDING)], unique=True),
                    IndexModel([("serial", ASCENDING), ("captured_at", DESCENDING)])],
    },
    "users": {
        "key": "id",
        "required": ["email", "password_hash"],
        "defaults": {"email_confirmed_at": None, "mfa_enabled": False, "mfa_secret": None, "recovery_codes": list,
                     "failed_logins": 0, "locked_until": None, "created_at": _now, "last_sign_in_at": None,
                     "providers": list},
        "indexes": [IndexModel([("email", ASCENDING)], unique=True),
                    IndexModel([("firebase_uid", ASCENDING)], unique=True,
                               partialFilterExpression={"firebase_uid": {"$type": "string"}})],
    },
    "sessions": {
        "key": "id",
        "required": ["user_id", "refresh_hash", "family", "expires_at"],
        "defaults": {"revoked_at": None, "replaced_by": None, "created_at": _now},
        "indexes": [IndexModel([("refresh_hash", ASCENDING)], unique=True), IndexModel([("user_id", ASCENDING)]),
                    IndexModel([("family", ASCENDING)]),
                    IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0)],
    },
    "auth_tokens": {
        "key": "id",
        "required": ["user_id", "purpose", "token_hash", "expires_at"],
        "defaults": {"used_at": None, "created_at": _now},
        "enums": {"purpose": ["verify_email", "reset_password", "invite", "mfa_login"]},
        "indexes": [IndexModel([("token_hash", ASCENDING)], unique=True),
                    IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0)],
    },
    "counters": {"key": None, "required": [], "defaults": {}, "indexes": []},
}


def spec(name: str) -> dict:
    if name not in COLLECTIONS:
        raise ValidationError(f"unknown collection {name}")
    return COLLECTIONS[name]


def apply_defaults(name: str, doc: dict) -> dict:
    s = spec(name)
    out = dict(doc)
    for k, v in s.get("defaults", {}).items():
        if k not in out:
            out[k] = v() if callable(v) else v
    if s.get("key") == "id" and not s.get("serial") and not out.get("id"):
        out["id"] = _uuid()
    return out


def apply_computed(name: str, doc: dict) -> dict:
    for k, fn in spec(name).get("computed", {}).items():
        value = fn(doc)
        if value is None:
            doc.pop(k, None)
        else:
            doc[k] = value
    return doc


def validate(name: str, doc: dict, partial: bool = False) -> None:
    s = spec(name)
    if not partial:
        missing = [k for k in s.get("required", []) if doc.get(k) in (None, "")]
        if missing:
            raise ValidationError(f"{name}: missing required fields {missing}")
    for k, allowed in s.get("enums", {}).items():
        if k in doc and doc[k] is not None and doc[k] not in allowed:
            raise ValidationError(f"{name}.{k}: {doc[k]!r} is not one of {allowed}")
    for k, (lo, hi) in s.get("ranges", {}).items():
        if k in doc and doc[k] is not None and not lo <= doc[k] <= hi:
            raise ValidationError(f"{name}.{k}: {doc[k]} is outside {lo}..{hi}")


def json_schema(name: str) -> dict:
    s = spec(name)
    props = {k: {"enum": allowed + [None]} for k, allowed in s.get("enums", {}).items()}
    for k, (lo, hi) in s.get("ranges", {}).items():
        props[k] = {"bsonType": ["int", "long", "null"], "minimum": lo, "maximum": hi}
    schema = {"bsonType": "object", "properties": props}
    key = s.get("key")
    required = ["_id" if field == key else field for field in s.get("required", [])]
    if required:
        schema["required"] = required
    return {"$jsonSchema": schema}


def ensure_schema(db) -> None:
    existing = set(db.list_collection_names())
    for name, s in COLLECTIONS.items():
        validator = json_schema(name) if name != "counters" else None
        if name not in existing:
            try:
                db.create_collection(name, **({"validator": validator, "validationLevel": "strict"} if validator else {}))
            except Exception:
                db.create_collection(name)
        elif validator:
            current = (db[name].options() or {}).get("validator")
            if current != validator:
                try:
                    db.command("collMod", name, validator=validator, validationLevel="strict")
                except Exception as exc:
                    print(f"[DB] could not update the {name} validator ({exc.__class__.__name__}); the database user "
                          "needs the collMod privilege (dbAdmin) or the collection must be recreated")
        for index in s.get("indexes", []):
            options = {k: v for k, v in index.document.items() if k != "key"}
            db[name].create_index(list(index.document["key"].items()), **options)
