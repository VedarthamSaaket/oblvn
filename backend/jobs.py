import json
import platform
import threading
import time
from datetime import datetime, timezone

from backend import realtime
from backend.accounts import get_user
from backend.anomaly import check_repeat_wipe, check_verification_failure, score_completed_job
from backend.audit import log_event
from backend.config import config
from backend.detector import get_device_by_serial
from backend.file_wipe import PathRejected, run_file_job
from backend.hw import pipeline
from backend.hw.inventory import from_device
from backend.hw.model import Cancelled, WipeError
from backend.reporter import generate_certificate
from backend.db import get_service_client

SYSTEM = platform.system()
_cancel_flags: dict[str, threading.Event] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _loads(value, default):
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value


def update_with_retry(svc, update: dict, job_id: str, retries: int = 5, base_delay: float = 3.0) -> None:
    last = None
    for attempt in range(retries):
        try:
            svc.table("wipe_jobs").update(update).eq("id", job_id).execute()
            return
        except Exception as exc:
            last = exc
            if attempt < retries - 1:
                print(f"[JOBS] update attempt {attempt + 1}/{retries} failed ({exc}), retrying")
                time.sleep(base_delay * (attempt + 1))
    raise last


def start(job_id: str) -> None:
    threading.Thread(target=execute, args=(job_id,), name=f"job-{job_id[:8]}", daemon=True).start()


def request_cancel(job_id: str) -> bool:
    ev = _cancel_flags.get(job_id)
    if ev:
        ev.set()
        return True
    return False


def _cancel_check(event: threading.Event):
    def check() -> None:
        if event.is_set():
            raise Cancelled("cancelled by operator")
    return check


def _claim(svc, job_id: str) -> dict | None:
    r = (svc.table("wipe_jobs")
         .update({"status": "running", "started_at": _now()})
         .eq("id", job_id)
         .eq("status", "queued")
         .is_("agent_id", "null")
         .execute())
    return r.data[0] if r.data else None


def _hardware(job: dict, emit, check) -> dict:
    device = get_device_by_serial(job["device_serial"])
    if not device:
        raise WipeError("device is no longer attached")
    if device.get("is_system"):
        raise WipeError(f"refusing to wipe {device['node']}: it {device.get('system_reason')}")
    options = _loads(job.get("options"), {})
    if SYSTEM == "Windows" and not config.DRY_RUN:
        from backend.hw import windows
        if not windows.is_admin():
            if job["method"] == "crypto_erase":
                raise WipeError("crypto erase needs firmware commands; run on the OBLVN Linux agent")
            from backend.wiper import run_free_space_fill
            gen = run_free_space_fill(device["node"], job["standard"])
            return _drain(gen, emit)
    gen = pipeline.run(from_device(device), job["method"], job["standard"], options, check, dry_run=config.DRY_RUN)
    return _drain(gen, emit)


def _drain(gen, emit) -> dict:
    for ev in gen:
        if ev.get("type") == "complete":
            record = dict(ev.get("record") or {})
            record.setdefault("technique", ev.get("technique"))
            record.setdefault("nist_category", ev.get("nist_category"))
            record.setdefault("passes_completed", ev.get("passes_completed", 0))
            record.setdefault("verification", {"passed": ev.get("verification_passed")})
            return record
        emit(ev)
    raise WipeError("wipe ended without a completion event")


def execute(job_id: str) -> None:
    svc = get_service_client()
    job = _claim(svc, job_id)
    if not job:
        return
    event = threading.Event()
    _cancel_flags[job_id] = event
    check = _cancel_check(event)

    def emit(ev: dict) -> None:
        realtime.broadcast(job_id, ev)

    try:
        if job.get("device_type") == "file":
            paths = _loads(job.get("file_paths"), [])
            if not paths:
                raise WipeError("no file paths recorded for this file wipe job")
            record = run_file_job(paths, job["method"], job["standard"], emit, check, config.DRY_RUN)
        else:
            record = _hardware(job, emit, check)
        complete(job, record)
    except Cancelled:
        update_with_retry(svc, {"status": "cancelled", "completed_at": _now()}, job_id)
        log_event("wipe_job_cancelled", {"job_id": job_id, "during": "execution"},
                  user_id=job["user_id"], org_id=job.get("org_id"))
        emit({"type": "cancelled", "job_id": job_id})
    except (WipeError, PathRejected) as exc:
        fail(job, str(exc), getattr(exc, "record", None))
    except Exception as exc:
        fail(job, f"{type(exc).__name__}: {exc}", None)
    finally:
        _cancel_flags.pop(job_id, None)


def fail(job: dict, message: str, record: dict | None) -> None:
    svc = get_service_client()
    job_id = job["id"]
    update = {"status": "failed", "error_message": message[:2000], "completed_at": _now()}
    if record:
        update["wipe_record"] = json.dumps(record, default=str)
        update["technique"] = record.get("technique")
        update["nist_category"] = record.get("nist_category")
    try:
        update_with_retry(svc, update, job_id)
    except Exception as exc:
        print(f"[JOBS] could not mark {job_id} failed: {exc}")
    log_event("wipe_job_failed", {"job_id": job_id, "error": message[:500]},
              user_id=job["user_id"], org_id=job.get("org_id"))
    if "verification" in message:
        check_verification_failure(job_id, job.get("org_id"), job["user_id"])
    realtime.broadcast(job_id, {"type": "error", "error": message})


def complete(job: dict, record: dict) -> None:
    svc = get_service_client()
    job_id = job["id"]
    verification = record.get("verification") or {}
    if verification.get("passed") is False:
        fail(job, "read-back verification failed", record)
        return
    telemetry = record.get("telemetry") or {}
    update = {
        "status": "completed",
        "completed_at": _now(),
        "passes_completed": record.get("passes_completed", 0),
        "verification_passed": verification.get("passed"),
        "technique": record.get("technique"),
        "nist_category": record.get("nist_category"),
        "bytes_written": telemetry.get("bytes_written"),
        "duration_seconds": telemetry.get("total_seconds"),
        "throughput_mbps": telemetry.get("throughput_mbps"),
        "wipe_record": json.dumps(record, default=str),
    }
    update_with_retry(svc, update, job_id)
    _finalize_with_retry(job_id, job, record)


def _finalize_with_retry(job_id: str, job: dict, record: dict, retries: int = 5) -> None:
    last = None
    for attempt in range(retries):
        try:
            _finalize(job_id, job, record)
            return
        except Exception as exc:
            last = exc
            print(f"[JOBS] finalize attempt {attempt + 1}/{retries} failed ({exc})")
            time.sleep(3.0 * (attempt + 1))
    realtime.broadcast(job_id, {"type": "error", "error": f"wipe finished but the certificate failed: {last}"})


def _finalize(job_id: str, job: dict, record: dict) -> None:
    svc = get_service_client()
    updated = svc.table("wipe_jobs").select("*").eq("id", job_id).maybe_single().execute().data or job
    found = get_user(job["user_id"]) or {}
    user = {"id": job["user_id"], "email": found.get("email", "")}
    org = None
    if job.get("org_id"):
        org = svc.table("organisations").select("name").eq("id", job["org_id"]).maybe_single().execute().data
    approver = None
    if updated.get("approved_by"):
        ap = get_user(updated["approved_by"])
        if ap:
            approver = {"email": ap["email"]}

    cert = generate_certificate(updated, user, org, approver, record)
    svc.table("wipe_jobs").update({
        "sha256_hash": cert["fields"]["sha256_hash"],
        "ots_proof_path": cert.get("ots_path"),
        "pdf_path": cert["pdf_path"],
    }).eq("id", job_id).execute()
    log_event("wipe_job_completed", {
        "job_id": job_id,
        "sha256_hash": cert["fields"]["sha256_hash"],
        "cert_id": cert["certificate_id"],
        "technique": record.get("technique"),
        "nist_category": record.get("nist_category"),
    }, user_id=job["user_id"], org_id=job.get("org_id"))

    for fn in (lambda: check_repeat_wipe(job["device_serial"], job.get("org_id"), job["user_id"]),
               lambda: score_completed_job(updated, record)):
        try:
            fn()
        except Exception as exc:
            print(f"[JOBS] post-wipe anomaly check failed: {exc}")

    realtime.broadcast(job_id, {
        "type": "complete",
        "job_id": job_id,
        "certificate_id": cert["certificate_id"],
        "sha256_hash": cert["fields"]["sha256_hash"],
        "verify_url": cert["fields"]["verify_url"],
        "technique": record.get("technique"),
        "nist_category": record.get("nist_category"),
        "verification_passed": verification_passed(record),
        "crypto_key": None,
    })


def verification_passed(record: dict):
    return (record.get("verification") or {}).get("passed")
