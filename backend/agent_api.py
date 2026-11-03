import hashlib
import json
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from backend import jobs, realtime
from backend.anomaly import check_smart_anomalies
from backend.audit import log_event
from backend.auth import current_user
from backend.security import assert_org_membership, validate_uuid
from backend.db import get_service_client

router = APIRouter(prefix="/api/agents")
PAIR_TTL_SECONDS = 600
DEVICE_KEYS = {
    "serial", "model", "manufacturer", "capacity_bytes", "capacity_human", "device_type", "interface",
    "filesystem", "node", "health", "smart_available", "smart_snapshot", "detected_at", "is_system",
    "system_reason", "serial_reliable", "transport", "mountpoints",
}
_last_seen: dict[str, float] = {}


class PairingBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    org_id: Optional[str] = None


class RegisterBody(BaseModel):
    code: str = Field(min_length=6, max_length=16)
    hostname: str = Field(default="", max_length=255)
    platform: str = Field(default="", max_length=64)
    version: str = Field(default="", max_length=32)


class HeartbeatBody(BaseModel):
    devices: list[dict] = Field(default_factory=list, max_length=64)
    version: str = Field(default="", max_length=32)


class ResultBody(BaseModel):
    ok: bool
    cancelled: bool = False
    error: Optional[str] = None
    record: Optional[dict] = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _normalize_code(code: str) -> str:
    return code.replace("-", "").replace(" ", "").upper()


def _user(request: Request) -> dict:
    return current_user(request)


def current_agent(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Agent "):
        raise HTTPException(status_code=401, detail="Missing agent token")
    svc = get_service_client()
    r = (svc.table("agents").select("*").eq("token_hash", _hash(auth[6:].strip()))
         .is_("revoked_at", "null").maybe_single().execute())
    if not r or not r.data:
        raise HTTPException(status_code=401, detail="Unknown or revoked agent")
    agent = r.data
    if time.monotonic() - _last_seen.get(agent["id"], 0) > 30:
        _last_seen[agent["id"]] = time.monotonic()
        svc.table("agents").update({"last_seen_at": _now().isoformat()}).eq("id", agent["id"]).execute()
    return agent


def visible_agents(user_id: str, org_id: str | None) -> list[dict]:
    svc = get_service_client()
    q = svc.table("agents").select("id,name,hostname,platform,version,user_id,org_id,last_seen_at,created_at") \
        .is_("revoked_at", "null")
    q = q.eq("org_id", org_id) if org_id else q.eq("user_id", user_id)
    return q.execute().data or []


def agent_devices(user_id: str, org_id: str | None) -> list[dict]:
    agents = {a["id"]: a for a in visible_agents(user_id, org_id)}
    if not agents:
        return []
    rows = (get_service_client().table("agent_devices").select("*")
            .in_("agent_id", list(agents)).execute().data or [])
    out = []
    for row in rows:
        device = row["device"] if isinstance(row["device"], dict) else json.loads(row["device"])
        agent = agents[row["agent_id"]]
        out.append({**device, "agent_id": agent["id"], "agent_name": agent["name"],
                    "agent_last_seen": agent.get("last_seen_at"), "reported_at": row.get("reported_at")})
    return out


def find_agent_device(serial: str, user_id: str, org_id: str | None, agent_id: str | None = None) -> dict | None:
    for d in agent_devices(user_id, org_id):
        if d.get("serial") == serial and (agent_id is None or d["agent_id"] == agent_id):
            return d
    return None


@router.post("/pairing-code", status_code=201)
async def create_pairing_code(request: Request, body: PairingBody):
    user = _user(request)
    svc = get_service_client()
    if body.org_id:
        validate_uuid(body.org_id, "org_id")
        assert_org_membership(body.org_id, user["user_id"], svc, min_role="team_lead")
    raw = secrets.token_hex(4).upper()
    expires = _now() + timedelta(seconds=PAIR_TTL_SECONDS)
    svc.table("agent_pairing_codes").insert({
        "code_hash": _hash(raw),
        "user_id": user["user_id"],
        "org_id": body.org_id,
        "name": body.name,
        "expires_at": expires.isoformat(),
    }).execute()
    log_event("agent_pairing_code_created", {"name": body.name}, user_id=user["user_id"], org_id=body.org_id)
    return {"code": f"{raw[:4]}-{raw[4:]}", "expires_at": expires.isoformat()}


@router.post("/register", status_code=201)
async def register_agent(body: RegisterBody):
    svc = get_service_client()
    code_hash = _hash(_normalize_code(body.code))
    r = svc.table("agent_pairing_codes").select("*").eq("code_hash", code_hash).maybe_single().execute()
    pairing = r.data if r else None
    if not pairing or pairing.get("used_at") or datetime.fromisoformat(
            pairing["expires_at"].replace("Z", "+00:00")) < _now():
        raise HTTPException(status_code=400, detail="Pairing code is invalid or expired")
    claimed = (svc.table("agent_pairing_codes").update({"used_at": _now().isoformat()})
               .eq("code_hash", code_hash).is_("used_at", "null").execute())
    if not claimed.data:
        raise HTTPException(status_code=400, detail="Pairing code already used")
    token = secrets.token_urlsafe(32)
    agent = svc.table("agents").insert({
        "user_id": pairing["user_id"],
        "org_id": pairing.get("org_id"),
        "name": pairing["name"],
        "hostname": body.hostname,
        "platform": body.platform,
        "version": body.version,
        "token_hash": _hash(token),
        "last_seen_at": _now().isoformat(),
    }).execute().data[0]
    log_event("agent_registered", {"agent_id": agent["id"], "hostname": body.hostname},
              user_id=pairing["user_id"], org_id=pairing.get("org_id"))
    return {"agent_id": agent["id"], "name": agent["name"], "token": token}


@router.post("/heartbeat")
async def heartbeat(request: Request, body: HeartbeatBody):
    agent = current_agent(request)
    svc = get_service_client()
    devices = [{k: v for k, v in d.items() if k in DEVICE_KEYS} for d in body.devices if d.get("serial")]
    svc.table("agent_devices").delete().eq("agent_id", agent["id"]).execute()
    if devices:
        svc.table("agent_devices").insert([
            {"agent_id": agent["id"], "serial": d["serial"][:128], "device": d, "reported_at": _now().isoformat()}
            for d in devices
        ]).execute()
    if body.version:
        svc.table("agents").update({"version": body.version}).eq("id", agent["id"]).execute()
    for d in devices:
        try:
            check_smart_anomalies(d["serial"], d.get("smart_snapshot") or {}, agent.get("org_id"), agent["user_id"])
        except Exception as exc:
            print(f"[AGENT] smart check failed for {d['serial']}: {exc}")
    return {"ok": True, "devices": len(devices)}


@router.get("/jobs/next")
async def next_job(request: Request):
    agent = current_agent(request)
    svc = get_service_client()
    r = (svc.table("wipe_jobs").select("*").eq("agent_id", agent["id"]).eq("status", "queued")
         .order("created_at").limit(1).execute())
    if not r.data:
        return {"job": None}
    job = r.data[0]
    claimed = (svc.table("wipe_jobs")
               .update({"status": "running", "started_at": _now().isoformat(), "claimed_at": _now().isoformat()})
               .eq("id", job["id"]).eq("status", "queued").execute())
    if not claimed.data:
        return {"job": None}
    device = find_agent_device(job["device_serial"], agent["user_id"], agent.get("org_id"), agent["id"]) or {}
    log_event("agent_job_claimed", {"job_id": job["id"], "agent_id": agent["id"]},
              user_id=job["user_id"], org_id=job.get("org_id"))
    return {"job": {
        "id": job["id"],
        "method": job["method"],
        "standard": job["standard"],
        "device_serial": job["device_serial"],
        "device": device,
        "options": job.get("options") or {},
    }}


def _agent_job(agent: dict, job_id: str) -> dict:
    validate_uuid(job_id, "job_id")
    r = get_service_client().table("wipe_jobs").select("*").eq("id", job_id).maybe_single().execute()
    if not r or not r.data or r.data.get("agent_id") != agent["id"]:
        raise HTTPException(status_code=404, detail="Job not found")
    return r.data


@router.post("/jobs/{job_id}/progress")
async def job_progress(job_id: str, request: Request):
    agent = current_agent(request)
    job = _agent_job(agent, job_id)
    event = await request.json()
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Progress event must be an object")
    event["type"] = event.get("type") if event.get("type") in ("progress", "warning") else "progress"
    realtime.broadcast(job_id, event)
    return {"cancel": bool(job.get("cancel_requested")) or job.get("status") == "cancelled"}


@router.post("/jobs/{job_id}/result")
async def job_result(job_id: str, request: Request, body: ResultBody):
    agent = current_agent(request)
    job = _agent_job(agent, job_id)
    if job["status"] != "running":
        raise HTTPException(status_code=409, detail=f"Job is {job['status']}")
    record = body.record or {}
    record["agent_id"] = agent["id"]
    record["agent_name"] = agent["name"]
    if body.cancelled:
        get_service_client().table("wipe_jobs").update({"status": "cancelled", "completed_at": _now().isoformat()}) \
            .eq("id", job_id).execute()
        realtime.broadcast(job_id, {"type": "cancelled", "job_id": job_id})
        return {"ok": True}
    target = jobs.complete if body.ok else (lambda j, r: jobs.fail(j, body.error or "agent reported failure", r))
    threading.Thread(target=target, args=(job, record), daemon=True).start()
    return {"ok": True}


@router.get("")
async def list_agents(request: Request, org_id: Optional[str] = None):
    user = _user(request)
    if org_id in ("undefined", "null", ""):
        org_id = None
    if org_id:
        validate_uuid(org_id, "org_id")
        assert_org_membership(org_id, user["user_id"], get_service_client(), min_role="operator")
    return {"agents": visible_agents(user["user_id"], org_id)}


@router.delete("/{agent_id}")
async def revoke_agent(agent_id: str, request: Request):
    validate_uuid(agent_id, "agent_id")
    user = _user(request)
    svc = get_service_client()
    r = svc.table("agents").select("id,user_id,org_id").eq("id", agent_id).maybe_single().execute()
    if not r or not r.data:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = r.data
    if agent["user_id"] != user["user_id"]:
        if not agent.get("org_id"):
            raise HTTPException(status_code=403, detail="Forbidden")
        assert_org_membership(agent["org_id"], user["user_id"], svc, min_role="org_admin")
    svc.table("agents").update({"revoked_at": _now().isoformat()}).eq("id", agent_id).execute()
    log_event("agent_revoked", {"agent_id": agent_id}, user_id=user["user_id"], org_id=agent.get("org_id"))
    return {"ok": True}
