"""
backend/server.py — OBLVN API Server (Security-Hardened)

Security changes applied (nothing stripped, no core functionality altered):
  ✔ SecurityHeadersMiddleware      — CSP, HSTS, X-Frame-Options, etc.
  ✔ RequestSizeLimitMiddleware     — 10 MiB body cap, DoS protection
  ✔ TrafficMonitorMiddleware       — per-IP rate + error-rate blocking
  ✔ HostValidationMiddleware       — phishing / DNS-rebind protection
  ✔ CORS locked to env-configured origins
  ✔ Rate limiting on register, devices, job creation, org creation
  ✔ Email & password-strength validation on register
  ✔ Email format validation on login / password-reset
  ✔ UUID validation on all path params (job_id, anomaly_id, org_id, cert_id, user_id)
  ✔ Enum allowlist validation on method, standard, role, sensitivity, format
  ✔ IDOR fixed on get_certificate / download_certificate (ownership check)
  ✔ IDOR fixed on list_anomalies (scoped to user when no org_id)
  ✔ IDOR fixed on ack_anomaly (ownership assertion before update)
  ✔ IDOR fixed on list_audit (scoped to user when no org_id)
  ✔ IDOR fixed on audit_export (org membership check)
  ✔ IDOR fixed on audit_verify (org membership check)
  ✔ IDOR fixed on risk_score (org membership check when org_id given)
  ✔ IDOR fixed on list_members (org membership check)
  ✔ IDOR fixed on list_jobs / list_devices (org membership check)
  ✔ IDOR fixed on create_job (org membership check)
  ✔ IDOR fixed on approve_job (job must belong to the supplied org)
  ✔ Internal error messages sanitised in production
"""

import io
import json
import os
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from apscheduler.schedulers.background import BackgroundScheduler

from backend import jobs, realtime
from backend.accounts import service as accounts_service
from backend.accounts.service import AuthError
from backend.db import DuplicateKey, get_user_client
from backend.agent_api import agent_devices, find_agent_device, router as agent_router
from backend.anomaly import (
    acknowledge_anomaly, check_failed_logins, check_new_ip,
    check_impossible_travel, check_new_operator, check_off_hours_wipe,
    check_smart_anomalies, check_unusual_login_hour,
    compute_risk_score, run_statistical_batch, check_role_escalation,
    primary_org, score_login,
)
from backend.audit import export_csv, export_json, export_pdf, log_event, verify_chain
from backend.auth import current_user, get_user_role, validate_token
from backend.config import config
from backend.detector import DeviceDetectionError, detect_devices, get_device_by_serial
from backend.file_wipe import PathRejected, check_path
from backend.db import get_service_client

# Security module — all helpers live here
from backend.security import (
    SecurityHeadersMiddleware,
    RequestSizeLimitMiddleware,
    TrafficMonitorMiddleware,
    HostValidationMiddleware,
    validate_uuid,
    validate_email,
    validate_password_strength,
    validate_enum,
    assert_job_access,
    assert_org_membership,
    assert_anomaly_access,
    assert_certificate_access,
    safe_error_detail,
    ALLOWED_WIPE_METHODS,
    ALLOWED_STANDARDS,
    ALLOWED_ROLES,
    ALLOWED_SENSITIVITIES,
    ALLOWED_AUDIT_FORMATS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────

class AuthBody(BaseModel):
    email: str
    password: str

class RefreshBody(BaseModel):
    refresh_token: str

class ResetBody(BaseModel):
    email: str

class AnomalyAckBody(BaseModel):
    note: Optional[str] = None
    resolved: bool = False
    feedback: Optional[str] = None

class OrgBody(BaseModel):
    name: str
    approval_gate_enabled: bool = False
    audit_retention_days: int = 2555
    anomaly_sensitivity: str = "medium"

class InviteBody(BaseModel):
    email: str
    role: str = "operator"

class RoleBody(BaseModel):
    role: str

class ApproveBody(BaseModel):
    org_id: Optional[str] = None

class FirebaseBody(BaseModel):
    id_token: str

class MfaLoginBody(BaseModel):
    mfa_token: str
    code: str

class CodeBody(BaseModel):
    code: str

class PasswordUpdateBody(BaseModel):
    token: str
    password: str
    invite: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="OBLVN")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Security middlewares (order matters — outermost runs first) ───────────────

# Host validation — protects against DNS rebinding / phishing Host headers
app.add_middleware(HostValidationMiddleware)

# Security response headers
app.add_middleware(SecurityHeadersMiddleware)

# Request body size cap (10 MiB)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=10 * 1024 * 1024)

# Per-IP traffic / abuse monitor
app.add_middleware(TrafficMonitorMiddleware)

# ── CORS — read allowed origins from env so production is locked down ─────────
_raw_origins = os.environ.get(
    "OBLVN_ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:3000",
)
_ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    expose_headers=["Content-Disposition"],
    max_age=600,
)

# ── Scheduled statistical anomaly batch ───────────────────────────────────────

def _scheduled_batch():
    try:
        from ml.train import run_nightly
        run_nightly()
    except Exception as exc:
        log_event("ml_training_failed", {"error": str(exc)[:500]}, user_id=None)
    try:
        run_statistical_batch(None)
    except Exception as exc:
        log_event("scheduled_batch_failed", {"error": str(exc)[:500]}, user_id=None)
    if datetime.now(timezone.utc).day == 1:
        try:
            from ml.report import run_monthly
            run_monthly()
        except Exception as exc:
            log_event("ml_report_failed", {"error": str(exc)[:500]}, user_id=None)

scheduler = BackgroundScheduler()
scheduler.add_job(func=_scheduled_batch, trigger="cron", hour=2, minute=0)
scheduler.start()

app.include_router(agent_router)


@app.on_event("startup")
async def _bind_realtime_loop():
    realtime.bind_loop(asyncio.get_running_loop())



# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

FRONTEND_DIST   = Path(__file__).parent.parent / "frontend" / "dist"
FRONTEND_PUBLIC = Path(__file__).parent.parent / "frontend" / "public"


# ─────────────────────────────────────────────────────────────────────────────
# File / folder picker utilities (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def _collect_folder_files(folder: str) -> list[str]:
    """Recursively collect all file paths inside a folder."""
    paths = []
    for root_dir, _dirs, files in os.walk(folder):
        for fname in files:
            paths.append(os.path.join(root_dir, fname))
    return paths


# ─────────────────────────────────────────────────────────────────────────────
# Routes — public
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
async def landing():
    landing_file = FRONTEND_PUBLIC / "landing.html"
    if landing_file.exists():
        return FileResponse(str(landing_file))
    raise HTTPException(status_code=404, detail="Landing page not found")


@app.get("/verify/{cert_id}")
async def verify_certificate(cert_id: str):
    validate_uuid(cert_id, "cert_id")
    svc = get_service_client()
    r = (
        svc.table("wipe_jobs")
        .select("id,status,sha256_hash,completed_at,device_model,device_serial,method,standard,"
                "technique,nist_category,verification_passed")
        .eq("id", cert_id)
        .maybe_single()
        .execute()
    )
    if not r.data or r.data.get("status") != "completed" or not r.data.get("sha256_hash"):
        raise HTTPException(status_code=404, detail="Certificate not found")
    job = r.data
    return {
        "verified":       True,
        "technique":      job.get("technique"),
        "nist_category":  job.get("nist_category"),
        "verification_passed": job.get("verification_passed"),
        "certificate_id": cert_id,
        "sha256_hash":    job.get("sha256_hash"),
        "completed_at":   job.get("completed_at"),
        "device_model":   job.get("device_model"),
        "device_serial":  job.get("device_serial"),
        "method":         job.get("method"),
        "standard":       job.get("standard"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Auth routes
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/auth/register", status_code=201)
@limiter.limit("10 per minute")
async def register(request: Request, body: AuthBody):
    validated_email = validate_email(body.email)
    validate_password_strength(body.password)
    result = accounts_service.sign_up(validated_email, body.password)
    if result.get("user_id"):
        log_event("user_registered", {"email": validated_email}, user_id=result["user_id"])
    return {"user_id": (result.get("user") or {}).get("id") or "pending_confirmation",
            "confirm_email": result["confirm_email"]}


def _login_success(session: dict, ip: str) -> dict:
    user_id = session["user"]["id"]
    org_id = primary_org(user_id)
    log_event("login_success", {"email": session["user"]["email"], "ip_address": ip}, user_id=user_id, org_id=org_id)
    now = datetime.now(timezone.utc)
    for check in (lambda: check_new_ip(user_id, org_id, ip),
                  lambda: check_unusual_login_hour(user_id, org_id, now),
                  lambda: check_impossible_travel(user_id, org_id, ip, now),
                  lambda: score_login(user_id, org_id, ip, now)):
        try:
            check()
        except Exception as exc:
            print(f"[ANOMALY] login check failed: {exc}")
    return {k: session[k] for k in ("access_token", "refresh_token", "expires_in", "token_type", "user")}


def _login_failed(email: str, ip: str, exc: AuthError) -> None:
    log_event("login_failed", {"email": email, "ip_address": ip, "reason": exc.code}, user_id=None)
    try:
        check_failed_logins(email, None, ip)
    except Exception:
        pass


@app.post("/api/auth/login")
@limiter.limit(config.AUTH_RATE_LIMIT)
async def login(request: Request, body: AuthBody):
    validated_email = validate_email(body.email)
    ip = request.client.host if request.client else "unknown"
    try:
        result = accounts_service.sign_in(validated_email, body.password)
    except AuthError as exc:
        _login_failed(validated_email, ip, exc)
        raise HTTPException(status_code=exc.status, detail=str(exc))
    if result.get("mfa_required"):
        return {"mfa_required": True, "mfa_token": result["mfa_token"]}
    return _login_success(result, ip)


@app.post("/api/auth/firebase")
@limiter.limit(config.AUTH_RATE_LIMIT)
async def login_firebase(request: Request, body: FirebaseBody):
    ip = request.client.host if request.client else "unknown"
    try:
        result = await asyncio.to_thread(accounts_service.sign_in_firebase, body.id_token)
    except AuthError as exc:
        log_event("login_failed", {"ip_address": ip, "reason": exc.code, "provider": "google"}, user_id=None)
        raise HTTPException(status_code=exc.status, detail=str(exc))
    if result.get("is_new"):
        log_event("user_registered", {"email": result["user"]["email"], "provider": "google"},
                  user_id=result["user"]["id"])
    if result.get("mfa_required"):
        return {"mfa_required": True, "mfa_token": result["mfa_token"]}
    return {**_login_success(result, ip), "is_new": result.get("is_new", False)}


@app.post("/api/auth/2fa/login")
@limiter.limit(config.AUTH_RATE_LIMIT)
async def login_second_factor(request: Request, body: MfaLoginBody):
    ip = request.client.host if request.client else "unknown"
    try:
        session = accounts_service.sign_in_mfa(body.mfa_token, body.code)
    except AuthError as exc:
        log_event("login_failed", {"ip_address": ip, "reason": exc.code}, user_id=None)
        raise HTTPException(status_code=exc.status, detail=str(exc))
    return _login_success(session, ip)


@app.post("/api/auth/logout")
async def logout(request: Request):
    user = current_user(request)
    accounts_service.sign_out(user["session_id"])
    log_event("logout", {}, user_id=user["user_id"])
    return {"ok": True}


@app.post("/api/auth/refresh")
@limiter.limit("30 per minute")
async def refresh(request: Request, body: RefreshBody):
    try:
        session = accounts_service.refresh(body.refresh_token)
    except AuthError as exc:
        if exc.code == "refresh_reuse":
            log_event("refresh_token_reuse", {"ip_address": request.client.host if request.client else "unknown"},
                      user_id=None)
        raise HTTPException(status_code=401, detail="Token refresh failed")
    return {"access_token": session["access_token"], "refresh_token": session["refresh_token"],
            "expires_in": session["expires_in"]}


@app.get("/api/auth/me")
async def me(request: Request):
    user = current_user(request)
    return accounts_service.get_user(user["user_id"])


@app.post("/api/auth/2fa/setup")
async def setup_2fa(request: Request):
    user = current_user(request)
    return accounts_service.mfa_setup(user["user_id"])


@app.post("/api/auth/2fa/enable")
async def enable_2fa(request: Request, body: CodeBody):
    user = current_user(request)
    try:
        codes = accounts_service.mfa_enable(user["user_id"], body.code)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    log_event("mfa_enabled", {}, user_id=user["user_id"])
    return {"ok": True, "recovery_codes": codes}


@app.post("/api/auth/2fa/disable")
async def disable_2fa(request: Request, body: CodeBody):
    user = current_user(request)
    try:
        accounts_service.mfa_disable(user["user_id"], body.code)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    log_event("mfa_disabled", {}, user_id=user["user_id"])
    return {"ok": True}


@app.post("/api/auth/password/reset")
@limiter.limit(config.AUTH_RATE_LIMIT)
async def password_reset(request: Request, body: ResetBody):
    validated_email = validate_email(body.email)
    try:
        accounts_service.request_password_reset(validated_email)
    except Exception as exc:
        print(f"[AUTH] reset email failed: {exc}")
    return {"ok": True}


@app.post("/api/auth/password/update")
@limiter.limit(config.AUTH_RATE_LIMIT)
async def password_update(request: Request, body: PasswordUpdateBody):
    validate_password_strength(body.password)
    try:
        user = accounts_service.reset_password(body.token, body.password, "invite" if body.invite else "reset_password")
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    if body.invite:
        get_service_client().table("org_memberships").update({"joined_at": datetime.now(timezone.utc).isoformat()}) \
            .eq("user_id", user["id"]).is_("joined_at", "null").execute()
    log_event("password_changed", {"via": "invite" if body.invite else "reset"}, user_id=user["id"])
    return {"ok": True, "email": user["email"]}


@app.get("/api/auth/verify-email")
async def verify_email(token: str = Query(...)):
    try:
        user = accounts_service.verify_email(token)
        log_event("email_verified", {}, user_id=user["id"])
        return RedirectResponse(f"{config.PUBLIC_URL.rstrip('/')}/app/login?verified=1", status_code=303)
    except AuthError:
        return RedirectResponse(f"{config.PUBLIC_URL.rstrip('/')}/app/login?verified=0", status_code=303)


@app.post("/api/auth/verify-email/resend")
@limiter.limit("5 per minute")
async def resend_verification(request: Request, body: ResetBody):
    found = accounts_service.get_user_by_email(validate_email(body.email))
    if found and not found["email_confirmed_at"]:
        accounts_service.send_verification(found["id"])
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# Device routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/devices")
@limiter.limit("60 per minute")
async def list_devices(request: Request, org_id: Optional[str] = Query(None)):
    user = current_user(request)

    # IDOR: if an org_id is provided, verify the caller belongs to it
    if org_id and org_id not in ("undefined", "null", ""):
        validate_uuid(org_id, "org_id")
        svc = get_service_client()
        assert_org_membership(org_id, user["user_id"], svc, min_role="operator")
    else:
        org_id = None

    remote = agent_devices(user["user_id"], org_id)
    try:
        devices = detect_devices()
    except DeviceDetectionError as exc:
        if remote:
            return {"devices": remote}
        return {"error": str(exc), "devices": []}
    for d in devices:
        try:
            d["anomalies"] = check_smart_anomalies(
                d["serial"], d.get("smart_snapshot", {}), org_id, user["user_id"]
            )
        except Exception as exc:
            print(f"[ANOMALY] smart check failed: {exc}")
            d["anomalies"] = []
    return {"devices": devices + remote}


@app.get("/api/devices/refresh")
@limiter.limit("30 per minute")
async def refresh_devices_get(request: Request):
    current_user(request)
    try:
        return {"devices": detect_devices()}
    except DeviceDetectionError as exc:
        return {"error": str(exc), "devices": []}


@app.post("/api/devices/refresh")
@limiter.limit("30 per minute")
async def refresh_devices(request: Request):
    current_user(request)
    try:
        return {"devices": detect_devices()}
    except DeviceDetectionError as exc:
        return {"error": str(exc), "devices": []}


@app.get("/api/devices/{serial}")
@limiter.limit("60 per minute")
async def get_device(serial: str, request: Request):
    user = current_user(request)
    try:
        d = get_device_by_serial(serial) or find_agent_device(serial, user["user_id"], None)
        if not d:
            raise HTTPException(status_code=404, detail="Device not found")
        return d
    except DeviceDetectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# File / folder picker endpoints (unchanged, security gated by current_user)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/utils/select-files")
async def select_local_files(request: Request):
    """Open a native multi-file dialog. Returns selected files as sources."""
    current_user(request)

    def _pick(root, result: dict):
        import tkinter as tk
        from tkinter import filedialog
        root.deiconify()
        root.update()
        root.attributes("-topmost", True)
        root.focus_force()
        paths = filedialog.askopenfilenames(
            parent=root,
            title="OBLVN — Select files to wipe",
        )
        root.attributes("-topmost", False)
        root.withdraw()
        root.update()
        result["paths"] = list(paths)

    try:
        from backend import tk_worker
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: tk_worker.run_job(_pick)
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=safe_error_detail(exc))

    if not result.get("paths"):
        raise HTTPException(status_code=400, detail="No files selected")

    abs_paths = [os.path.abspath(p) for p in result["paths"]]
    return {
        "paths":   abs_paths,
        "sources": [{"type": "file", "path": p} for p in abs_paths],
    }


@app.post("/api/utils/select-folder")
async def select_local_folder(request: Request):
    """
    Opens folder dialogs in a loop so the user can pick multiple folders
    one at a time. Each dialog shows an instruction label telling them
    how many they've picked so far and that cancelling finishes the selection.
    All files from all chosen folders are returned as sources.
    """
    current_user(request)

    def _pick(root, result: dict):
        import tkinter as tk
        from tkinter import filedialog, messagebox

        chosen_folders: list[str] = []
        seen_folders:   set[str]  = set()

        while True:
            root.deiconify()
            root.update()
            root.attributes("-topmost", True)
            root.focus_force()

            if not chosen_folders:
                title = "OBLVN — Select a folder to wipe (cancel when done)"
            else:
                title = (
                    f"OBLVN — {len(chosen_folders)} folder"
                    f"{'s' if len(chosen_folders) != 1 else ''} selected"
                    f" — pick another or cancel to finish"
                )

            folder = filedialog.askdirectory(
                parent=root,
                title=title,
                mustexist=True,
            )

            root.attributes("-topmost", False)
            root.withdraw()
            root.update()

            if not folder:
                break

            folder = os.path.abspath(folder)
            if folder not in seen_folders:
                seen_folders.add(folder)
                chosen_folders.append(folder)
                print(f"[select-folder] added: {folder} (total: {len(chosen_folders)})", flush=True)
            else:
                print(f"[select-folder] skipped duplicate: {folder}", flush=True)

        result["folders"] = chosen_folders

    try:
        from backend import tk_worker
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: tk_worker.run_job(_pick)
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=safe_error_detail(exc))

    folders = result.get("folders") or []
    if not folders:
        raise HTTPException(status_code=400, detail="No folder selected")

    all_paths: list[str] = []
    sources:   list[dict] = []
    seen_paths: set[str]  = set()

    for folder in folders:
        files = _collect_folder_files(folder)
        added = 0
        for fp in files:
            if fp not in seen_paths:
                seen_paths.add(fp)
                all_paths.append(fp)
                added += 1
        sources.append({"type": "folder", "path": folder, "file_count": added})

    if not all_paths:
        raise HTTPException(status_code=400, detail="Selected folders contain no files")

    return {"paths": all_paths, "sources": sources}


@app.post("/api/utils/select-items")
async def select_items(request: Request):
    """
    Opens a tkinter tree-browser. Kept for backwards compatibility.
    The frontend now uses select-files / select-folder instead.
    """
    current_user(request)

    def _picker(root, result: dict):
        import tkinter as tk
        from tkinter import ttk, filedialog

        print("[picker] starting askdirectory...", flush=True)

        root.deiconify()
        root.update()
        root.attributes("-topmost", True)
        root.focus_force()

        start_dir = filedialog.askdirectory(
            parent=root,
            title="OBLVN — Choose root folder to browse",
            mustexist=True,
        )

        root.attributes("-topmost", False)
        root.withdraw()
        root.update()

        print(f"[picker] askdirectory returned: {repr(start_dir)}", flush=True)

        if not start_dir:
            result["cancelled"] = True
            return

        start_dir = os.path.abspath(start_dir)

        win = tk.Toplevel(root)
        win.title("OBLVN — Select files and folders to wipe")
        win.geometry("760x560")
        win.configure(bg="#1a2218")
        win.resizable(True, True)
        win.attributes("-topmost", True)
        win.lift()
        win.focus_force()
        win.update()

        check_vars: dict[str, tk.BooleanVar] = {}
        iid_to_path: dict[str, str] = {}

        hdr = tk.Frame(win, bg="#1a2218")
        hdr.pack(fill="x", padx=20, pady=(16, 0))
        tk.Label(hdr, text="SELECT ITEMS TO WIPE",
                 font=("Courier New", 9), fg="#c4b48a", bg="#1a2218").pack(side="left")
        tk.Label(hdr, text=start_dir,
                 font=("Courier New", 8), fg="#4a5442", bg="#1a2218").pack(side="left", padx=(12, 0))

        tk.Label(win,
                 text="Check individual files or folders. Checking a folder selects all files inside it.",
                 font=("Courier New", 8), fg="#4a5442", bg="#1a2218").pack(anchor="w", padx=20, pady=(6, 0))

        tree_frame = tk.Frame(win, bg="#1a2218")
        tree_frame.pack(fill="both", expand=True, padx=20, pady=12)

        style = ttk.Style(win)
        style.theme_use("default")
        style.configure("oblvn.Treeview",
            background="#111a10", foreground="#e8dfc8",
            fieldbackground="#111a10", font=("Courier New", 9), rowheight=22)
        style.configure("oblvn.Treeview.Heading",
            background="#1a2218", foreground="#c4b48a", font=("Courier New", 8))
        style.map("oblvn.Treeview",
            background=[("selected", "#2a3828")],
            foreground=[("selected", "#e8dfc8")])

        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        tree = ttk.Treeview(
            tree_frame, style="oblvn.Treeview",
            columns=("check", "type", "size"),
            displaycolumns=("check", "type", "size"),
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
            selectmode="browse",
        )
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)

        tree.heading("#0",    text="Name",  anchor="w")
        tree.heading("check", text="",      anchor="center")
        tree.heading("type",  text="Type",  anchor="w")
        tree.heading("size",  text="Size",  anchor="e")
        tree.column("#0",    width=300, stretch=True)
        tree.column("check", width=36,  stretch=False, anchor="center")
        tree.column("type",  width=70,  stretch=False)
        tree.column("size",  width=80,  stretch=False, anchor="e")

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)

        def _fmt_size(b: int) -> str:
            for u in ("B", "KB", "MB", "GB"):
                if b < 1024:
                    return f"{b:.0f} {u}"
                b //= 1024
            return f"{b:.0f} GB"

        def _sym(var: tk.BooleanVar) -> str:
            return "[x]" if var.get() else "[ ]"

        def _insert_dir(parent_iid: str, dirpath: str, depth: int = 0):
            if depth > 8:
                return
            try:
                entries = sorted(os.scandir(dirpath),
                                 key=lambda e: (not e.is_dir(), e.name.lower()))
            except PermissionError:
                return
            for entry in entries:
                ap = os.path.abspath(entry.path)
                var = tk.BooleanVar(master=win, value=False)
                check_vars[ap] = var
                if entry.is_dir(follow_symlinks=False):
                    iid = tree.insert(parent_iid, "end",
                                      text=f"  {entry.name}",
                                      values=(_sym(var), "folder", ""),
                                      open=False)
                    iid_to_path[iid] = ap
                    _insert_dir(iid, ap, depth + 1)
                else:
                    try:
                        sz = _fmt_size(entry.stat().st_size)
                    except OSError:
                        sz = ""
                    ext = os.path.splitext(entry.name)[1].lstrip(".").upper() or "FILE"
                    iid = tree.insert(parent_iid, "end",
                                      text=f"  {entry.name}",
                                      values=(_sym(var), ext, sz))
                    iid_to_path[iid] = ap

        _insert_dir("", start_dir)
        win.update()

        def _set_subtree(iid: str, val: bool):
            path = iid_to_path.get(iid)
            if path and path in check_vars:
                check_vars[path].set(val)
                tree.set(iid, "check", _sym(check_vars[path]))
            for child in tree.get_children(iid):
                _set_subtree(child, val)

        def _on_click(event):
            iid = tree.identify_row(event.y)
            if not iid:
                return
            path = iid_to_path.get(iid)
            if not path or path not in check_vars:
                return
            _set_subtree(iid, not check_vars[path].get())

        tree.bind("<Button-1>", _on_click)

        btn_frame = tk.Frame(win, bg="#1a2218")
        btn_frame.pack(fill="x", padx=20, pady=(0, 8))

        def _mk_btn(parent, label, cmd, primary=False):
            return tk.Button(
                parent, text=label, command=cmd,
                font=("Courier New", 8),
                bg="#c4b48a" if primary else "#1a2218",
                fg="#1a2218" if primary else "#c4b48a",
                relief="flat", padx=14, pady=6, cursor="crosshair",
                activebackground="#d4c49a" if primary else "#2a3828",
                activeforeground="#1a2218" if primary else "#e8dfc8",
            )

        _mk_btn(btn_frame, "Select All",
                lambda: [_set_subtree(i, True)  for i in tree.get_children("")]).pack(side="left", padx=(0, 8))
        _mk_btn(btn_frame, "Select None",
                lambda: [_set_subtree(i, False) for i in tree.get_children("")]).pack(side="left")

        confirmed = {"ok": False}

        def _confirm():
            confirmed["ok"] = True
            win.destroy()

        def _cancel():
            win.destroy()

        bottom = tk.Frame(win, bg="#111a10", pady=10)
        bottom.pack(fill="x", side="bottom")
        _mk_btn(bottom, "Cancel",            _cancel).pack(side="left",  padx=(20, 8))
        _mk_btn(bottom, "Confirm Selection", _confirm, primary=True).pack(side="right", padx=(8, 20))

        win.protocol("WM_DELETE_WINDOW", _cancel)

        while True:
            try:
                if not win.winfo_exists():
                    break
                root.update()
            except tk.TclError:
                break

        if not confirmed["ok"]:
            result["cancelled"] = True
            return

        all_paths_local: list[str] = []
        sources_local:   list[dict] = []
        seen_local:      set[str]   = set()

        def _collect(iid: str):
            path = iid_to_path.get(iid)
            if not path:
                return
            is_dir  = os.path.isdir(path)
            var     = check_vars.get(path)
            checked = var.get() if var else False

            if is_dir and checked:
                files_in = _collect_folder_files(path)
                added = 0
                for fp in files_in:
                    if fp not in seen_local:
                        seen_local.add(fp)
                        all_paths_local.append(fp)
                        added += 1
                sources_local.append({"type": "folder", "path": path, "file_count": added})
            elif is_dir and not checked:
                for child in tree.get_children(iid):
                    _collect(child)
            elif not is_dir and checked:
                if path not in seen_local:
                    seen_local.add(path)
                    all_paths_local.append(path)
                    sources_local.append({"type": "file", "path": path})

        for top_iid in tree.get_children(""):
            _collect(top_iid)

        result["paths"]   = all_paths_local
        result["sources"] = sources_local

    try:
        from backend import tk_worker
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: tk_worker.run_job(_picker)
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=safe_error_detail(exc))

    if result.get("cancelled"):
        raise HTTPException(status_code=400, detail="Selection cancelled")
    if not result.get("paths"):
        raise HTTPException(status_code=400, detail="No items selected")

    return {"paths": result["paths"], "sources": result["sources"]}


# ─────────────────────────────────────────────────────────────────────────────
# Job routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/jobs")
@limiter.limit("60 per minute")
async def list_jobs(request: Request, org_id: Optional[str] = Query(None)):
    user = current_user(request)

    if org_id in ("undefined", "null", ""):
        org_id = None

    svc = get_service_client()
    scoped = get_user_client(user["user_id"])

    if org_id:
        # IDOR: verify caller is a member of the org before listing its jobs
        validate_uuid(org_id, "org_id")
        assert_org_membership(org_id, user["user_id"], svc, min_role="operator")
        q = scoped.table("wipe_jobs").select("*").order("created_at", desc=True).eq("org_id", org_id)
    else:
        # No org_id → return only the authenticated user's own jobs
        q = scoped.table("wipe_jobs").select("*").order("created_at", desc=True).eq("user_id", user["user_id"])

    r = q.execute()
    return {"jobs": r.data or []}


@app.post("/api/jobs", status_code=201)
@limiter.limit("30 per minute")
async def create_job(request: Request):
    user = current_user(request)
    data = await request.json()
    svc  = get_service_client()
    org_id = data.get("org_id")

    # IDOR: validate org membership before creating a job under that org
    if org_id and org_id not in ("undefined", "null", ""):
        validate_uuid(org_id, "org_id")
        assert_org_membership(org_id, user["user_id"], svc, min_role="operator")
    else:
        org_id = None

    # Validate wipe method and standard against allowlists
    method   = validate_enum(data.get("method", ""), ALLOWED_WIPE_METHODS, "method")
    standard = validate_enum(data.get("standard", ""), ALLOWED_STANDARDS, "standard")

    target_serial = data.get("device_serial", "")
    options = _job_options(data.get("options"))
    agent_id = None

    if target_serial.startswith("file:"):
        raw_paths = data.get("file_paths") or [target_serial.replace("file:", "", 1)]
        try:
            file_paths = [str(check_path(p)) for p in raw_paths]
        except PathRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        total_bytes = 0
        for p in file_paths:
            if os.path.isfile(p):
                total_bytes += os.path.getsize(p)
            else:
                for root_dir, _dirs, names in os.walk(p):
                    total_bytes += sum(os.path.getsize(os.path.join(root_dir, n)) for n in names
                                       if os.path.isfile(os.path.join(root_dir, n)))
        device = {
            "serial":         _file_serial_label(data, file_paths),
            "model":          _file_model_label(data, file_paths),
            "capacity_bytes": total_bytes,
            "device_type":    "file",
            "node":           file_paths[0],
            "smart_snapshot": {},
        }
    else:
        file_paths = []
        try:
            device = get_device_by_serial(target_serial)
        except DeviceDetectionError:
            device = None
        if not device:
            device = find_agent_device(target_serial, user["user_id"], org_id, data.get("agent_id"))
            if device:
                agent_id = device["agent_id"]
        if device and device.get("is_system"):
            raise HTTPException(
                status_code=400,
                detail=f"Refusing to wipe {device.get('node')}: it {device.get('system_reason')}",
            )

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    needs_approval = False
    if org_id:
        org_r = (
            svc.table("organisations")
            .select("approval_gate_enabled")
            .eq("id", org_id)
            .maybe_single()
            .execute()
        )
        if org_r.data:
            role = get_user_role(user["user_id"], org_id)
            needs_approval = org_r.data.get("approval_gate_enabled") and role == "operator"

    status = "pending_approval" if needs_approval else "queued"

    job = {
        "user_id":               user["user_id"],
        "org_id":                org_id,
        "status":                status,
        "method":                method,
        "standard":              standard,
        "device_serial":         device["serial"],
        "device_model":          device["model"],
        "device_capacity_bytes": device["capacity_bytes"],
        "device_type":           device["device_type"],
        "smart_snapshot":        json.dumps(device.get("smart_snapshot")),
        "passes_completed":      0,
        "created_at":            datetime.now(timezone.utc).isoformat(),
        "file_paths":            file_paths or None,
        "options":               options,
        "agent_id":              agent_id,
    }

    r = svc.table("wipe_jobs").insert(job).execute()
    created = r.data[0]
    log_event(
        "wipe_job_created",
        {"job_id": created["id"], "device": device["serial"], "agent_id": agent_id},
        user_id=user["user_id"],
        org_id=org_id,
    )
    for check in (lambda: check_new_operator(user["user_id"], org_id, created["id"]),
                  lambda: check_off_hours_wipe(created["id"], org_id, user["user_id"], datetime.now(timezone.utc))):
        try:
            check()
        except Exception as exc:
            print(f"[ANOMALY] job check failed: {exc}")

    if status == "queued" and not agent_id:
        jobs.start(created["id"])

    return JSONResponse(content=created, status_code=201)


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, request: Request):
    validate_uuid(job_id, "job_id")
    user = current_user(request)
    svc  = get_service_client()

    r = get_user_client(user["user_id"]).table("wipe_jobs").select("*").eq("id", job_id).maybe_single().execute()
    if not r.data:
        raise HTTPException(status_code=404, detail="Job not found")
    job = r.data

    # IDOR: assert the requester owns this job or is an org member
    assert_job_access(job, user["user_id"], svc)
    return job


@app.post("/api/jobs/{job_id}/approve")
async def approve_job(job_id: str, request: Request, body: ApproveBody):
    validate_uuid(job_id, "job_id")
    user = current_user(request)

    if body.org_id:
        validate_uuid(body.org_id, "org_id")

    role = get_user_role(user["user_id"], body.org_id)
    if role not in ("org_admin", "team_lead"):
        raise HTTPException(status_code=403, detail="Requires team_lead or org_admin")

    svc = get_service_client()

    # IDOR: verify the job actually belongs to the supplied org
    job_r = svc.table("wipe_jobs").select("org_id,status,agent_id").eq("id", job_id).maybe_single().execute()
    if not job_r.data:
        raise HTTPException(status_code=404, detail="Job not found")
    if not body.org_id or job_r.data.get("org_id") != body.org_id:
        raise HTTPException(status_code=403, detail="Forbidden: job does not belong to this organisation")
    if job_r.data.get("status") != "pending_approval":
        raise HTTPException(status_code=409, detail=f"Job is {job_r.data.get('status')}, not pending approval")

    updated = (svc.table("wipe_jobs").update({"status": "queued", "approved_by": user["user_id"]})
               .eq("id", job_id).eq("status", "pending_approval").execute())
    if not updated.data:
        raise HTTPException(status_code=409, detail="Job was already approved or cancelled")
    log_event("wipe_job_approved", {"job_id": job_id}, user_id=user["user_id"], org_id=body.org_id)
    if not job_r.data.get("agent_id"):
        jobs.start(job_id)
    return {"ok": True}


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, request: Request):
    validate_uuid(job_id, "job_id")
    user = current_user(request)
    svc  = get_service_client()

    r = svc.table("wipe_jobs").select("status,user_id,org_id").eq("id", job_id).maybe_single().execute()
    if not r.data:
        raise HTTPException(status_code=404, detail="Job not found")
    job = r.data

    if job["user_id"] != user["user_id"]:
        role = get_user_role(user["user_id"], job.get("org_id"))
        if role not in ("org_admin", "team_lead"):
            raise HTTPException(status_code=403, detail="Forbidden")

    current_status = job["status"]
    if current_status in {"completed", "cancelled", "failed"}:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel a job with status '{current_status}'. Only active jobs can be cancelled.",
        )

    log_event("wipe_job_cancel_requested", {"job_id": job_id, "status": current_status},
              user_id=user["user_id"], org_id=job.get("org_id"))
    if current_status == "running":
        svc.table("wipe_jobs").update({"cancel_requested": True}).eq("id", job_id).execute()
        jobs.request_cancel(job_id)
        return {"ok": True, "pending": True,
                "detail": "Cancellation requested; firmware sanitize commands cannot be interrupted once issued"}

    svc.table("wipe_jobs").update({"status": "cancelled", "cancel_requested": True}).eq("id", job_id) \
        .in_("status", ["queued", "pending_approval"]).execute()
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# Certificate routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/certificates/{job_id}")
async def get_certificate(job_id: str, request: Request):
    validate_uuid(job_id, "job_id")
    user = current_user(request)
    svc  = get_service_client()

    # IDOR: assert_certificate_access fetches + checks ownership
    job = assert_certificate_access(job_id, user["user_id"], svc)
    return job


@app.get("/api/certificates/{job_id}/download")
async def download_certificate(job_id: str, request: Request):
    validate_uuid(job_id, "job_id")
    user = current_user(request)
    svc  = get_service_client()

    # IDOR: verify ownership before serving the PDF from disk
    assert_certificate_access(job_id, user["user_id"], svc)

    pdf_path = config.DATA_DIR / "certs" / f"{job_id}.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF not found")
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=OBLVN-{job_id}.pdf"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Audit routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/audit")
async def list_audit(
    request: Request,
    org_id: Optional[str] = Query(None),
    start:  Optional[str] = Query(None),
    end:    Optional[str] = Query(None),
):
    user = current_user(request)

    if org_id and org_id not in ("undefined", "null", ""):
        validate_uuid(org_id, "org_id")
        # IDOR: only org_admin may view the organisation's full audit log
        role = get_user_role(user["user_id"], org_id)
        if role != "org_admin":
            raise HTTPException(status_code=403, detail="Requires org_admin")
        entries = export_json(org_id, start, end)
    else:
        # Account isolation: no org_id → return only this user's own entries
        svc = get_service_client()
        q   = svc.table("audit_log").select("*").order("id", desc=False).eq("user_id", user["user_id"])
        if start:
            q = q.gte("created_at", start)
        if end:
            q = q.lte("created_at", end)
        r = q.execute()
        entries = r.data or []

    return {"entries": entries, "count": len(entries)}


@app.get("/api/audit/export")
@limiter.limit("10 per minute")          # prevent bulk data exfiltration
async def audit_export(
    request: Request,
    org_id:  Optional[str] = Query(None),
    format:  str            = Query("json"),
    start:   Optional[str] = Query(None),
    end:     Optional[str] = Query(None),
):
    user = current_user(request)
    validate_enum(format, ALLOWED_AUDIT_FORMATS, "format")

    if org_id and org_id not in ("undefined", "null", ""):
        validate_uuid(org_id, "org_id")
        # IDOR: only org_admin may export the org's audit log
        svc  = get_service_client()
        assert_org_membership(org_id, user["user_id"], svc, min_role="org_admin")
    else:
        org_id = None

    scope_user = None if org_id else user["user_id"]
    if format == "csv":
        content = export_csv(org_id, start, end, scope_user)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=oblvn-audit.csv"},
        )
    if format == "pdf":
        pdf_bytes = export_pdf(org_id, start, end, scope_user)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=oblvn-audit.pdf"},
        )
    return {"entries": export_json(org_id, start, end, scope_user)}


@app.get("/api/audit/verify")
async def audit_verify(request: Request, org_id: Optional[str] = Query(None)):
    user = current_user(request)

    if org_id and org_id not in ("undefined", "null", ""):
        validate_uuid(org_id, "org_id")
        # IDOR: only org members may verify the org's chain
        svc = get_service_client()
        assert_org_membership(org_id, user["user_id"], svc, min_role="operator")
    else:
        org_id = None

    return verify_chain(org_id)


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/anomalies/risk-score")
async def risk_score(request: Request, org_id: Optional[str] = Query(None)):
    user = current_user(request)

    if org_id in ("undefined", "null", ""):
        org_id = None

    if org_id:
        validate_uuid(org_id, "org_id")
        # IDOR: verify membership before returning org-wide risk score
        svc = get_service_client()
        assert_org_membership(org_id, user["user_id"], svc, min_role="operator")

    return compute_risk_score(org_id, user["user_id"])


@app.get("/api/anomalies")
async def list_anomalies(
    request: Request,
    org_id:  Optional[str] = Query(None),
    status:  Optional[str] = Query(None),
):
    user = current_user(request)
    svc  = get_service_client()

    if org_id and org_id not in ("undefined", "null", ""):
        validate_uuid(org_id, "org_id")
        # IDOR: verify org membership before listing org anomalies
        assert_org_membership(org_id, user["user_id"], svc, min_role="operator")
        q = get_user_client(user["user_id"]).table("anomalies").select("*").order("detected_at", desc=True).eq("org_id", org_id)
    else:
        # Account isolation: no org → return only anomalies linked to this user
        q = get_user_client(user["user_id"]).table("anomalies").select("*").order("detected_at", desc=True).eq("user_id", user["user_id"])

    if status:
        q = q.eq("status", status)

    r = q.execute()
    return {"anomalies": r.data or []}


@app.get("/api/ml/report")
async def ml_report(request: Request, org_id: Optional[str] = Query(None), month: Optional[str] = Query(None)):
    user = current_user(request)
    if org_id in ("undefined", "null", ""):
        org_id = None
    if org_id:
        validate_uuid(org_id, "org_id")
        assert_org_membership(org_id, user["user_id"], get_service_client(), min_role="org_admin")
    if month is not None and not (len(month) == 7 and month[4] == "-" and month.replace("-", "").isdigit()):
        raise HTTPException(status_code=400, detail="month must be YYYY-MM")
    from ml import report
    month = month or report._previous_month(datetime.now(timezone.utc).date())
    return report.build(org_id, month, None if org_id else user["user_id"])


@app.post("/api/anomalies/{anomaly_id}/acknowledge")
async def ack_anomaly(anomaly_id: str, request: Request, body: AnomalyAckBody):
    validate_uuid(anomaly_id, "anomaly_id")
    user = current_user(request)
    svc  = get_service_client()

    # IDOR: verify user can access this anomaly before acknowledging it
    assert_anomaly_access(anomaly_id, user["user_id"], svc)

    if body.feedback is not None and body.feedback not in ("true_positive", "false_positive"):
        raise HTTPException(status_code=400, detail="feedback must be true_positive or false_positive")
    result = acknowledge_anomaly(
        anomaly_id, user["user_id"],
        note=body.note,
        resolved=body.resolved,
        feedback=body.feedback,
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Organisation routes
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/orgs", status_code=201)
@limiter.limit("10 per minute")
async def create_org(request: Request, body: OrgBody):
    user = current_user(request)

    # Validate sensitivity value against allowlist
    validate_enum(body.anomaly_sensitivity, ALLOWED_SENSITIVITIES, "anomaly_sensitivity")

    svc = get_service_client()
    org = {
        "name":                  body.name,
        "approval_gate_enabled": body.approval_gate_enabled,
        "audit_retention_days":  body.audit_retention_days,
        "anomaly_sensitivity":   body.anomaly_sensitivity,
        "created_at":            datetime.now(timezone.utc).isoformat(),
    }
    r = svc.table("organisations").insert(org).execute()
    created = r.data[0]
    svc.table("org_memberships").insert({
        "user_id":    user["user_id"],
        "org_id":     created["id"],
        "role":       "org_admin",
        "invited_at": datetime.now(timezone.utc).isoformat(),
        "joined_at":  datetime.now(timezone.utc).isoformat(),
    }).execute()
    return JSONResponse(content=created, status_code=201)


@app.patch("/api/orgs/{org_id}")
async def update_org(org_id: str, request: Request):
    validate_uuid(org_id, "org_id")
    user = current_user(request)
    role = get_user_role(user["user_id"], org_id)
    if role != "org_admin":
        raise HTTPException(status_code=403, detail="Requires org_admin")

    data    = await request.json()
    allowed = {"approval_gate_enabled", "audit_retention_days",
               "anomaly_sensitivity", "data_minimisation_config", "name"}
    update  = {k: v for k, v in data.items() if k in allowed}

    # Validate sensitivity if it's being updated
    if "anomaly_sensitivity" in update:
        validate_enum(update["anomaly_sensitivity"], ALLOWED_SENSITIVITIES, "anomaly_sensitivity")

    svc = get_service_client()
    r   = svc.table("organisations").update(update).eq("id", org_id).execute()
    return r.data[0] if r.data else {}


@app.get("/api/orgs/{org_id}/members")
async def list_members(org_id: str, request: Request):
    validate_uuid(org_id, "org_id")
    user = current_user(request)
    svc  = get_service_client()

    # IDOR: only org members may list other members
    assert_org_membership(org_id, user["user_id"], svc, min_role="operator")

    r = svc.table("org_memberships").select("*").eq("org_id", org_id).execute()
    return {"members": r.data or []}


@app.post("/api/orgs/{org_id}/invite")
async def invite_member(org_id: str, request: Request, body: InviteBody):
    validate_uuid(org_id, "org_id")
    user = current_user(request)
    role = get_user_role(user["user_id"], org_id)
    if role != "org_admin":
        raise HTTPException(status_code=403, detail="Requires org_admin")

    # Validate inputs
    validated_email = validate_email(body.email)
    validate_enum(body.role, ALLOWED_ROLES, "role")

    svc = get_service_client()
    org = svc.table("organisations").select("name").eq("id", org_id).maybe_single().execute().data or {}
    try:
        invited = accounts_service.invite(validated_email, org.get("name", "an organisation"), body.role)
        svc.table("org_memberships").insert({
            "user_id":    invited["user"]["id"],
            "org_id":     org_id,
            "role":       body.role,
            "invited_at": datetime.now(timezone.utc).isoformat(),
            "joined_at":  None if invited["created"] or not invited["user"]["email_confirmed_at"]
                          else datetime.now(timezone.utc).isoformat(),
        }).execute()
    except DuplicateKey:
        raise HTTPException(status_code=409, detail="That person is already a member of this organisation")
    log_event("member_invited", {"email": validated_email, "role": body.role, "new_account": invited["created"]},
              user_id=user["user_id"], org_id=org_id)
    return {"ok": True}


@app.delete("/api/orgs/{org_id}/members/{user_id}")
async def revoke_member(org_id: str, user_id: str, request: Request):
    validate_uuid(org_id, "org_id")
    validate_uuid(user_id, "user_id")
    user = current_user(request)
    role = get_user_role(user["user_id"], org_id)
    if role != "org_admin":
        raise HTTPException(status_code=403, detail="Requires org_admin")

    svc = get_service_client()
    svc.table("org_memberships").delete().eq("org_id", org_id).eq("user_id", user_id).execute()
    log_event("member_revoked", {"user_id": user_id}, user_id=user["user_id"], org_id=org_id)
    return {"ok": True}


@app.patch("/api/orgs/{org_id}/members/{user_id}/role")
async def change_role(org_id: str, user_id: str, request: Request, body: RoleBody):
    validate_uuid(org_id, "org_id")
    validate_uuid(user_id, "user_id")
    user = current_user(request)

    admin_role = get_user_role(user["user_id"], org_id)
    if admin_role != "org_admin":
        raise HTTPException(status_code=403, detail="Requires org_admin")

    validate_enum(body.role, ALLOWED_ROLES, "role")

    svc = get_service_client()
    old_r = (
        svc.table("org_memberships")
        .select("role")
        .eq("org_id", org_id)
        .eq("user_id", user_id)
        .maybe_single()
        .execute()
    )
    old_role = old_r.data["role"] if old_r.data else "operator"
    new_role = body.role
    svc.table("org_memberships").update({"role": new_role}).eq("org_id", org_id).eq("user_id", user_id).execute()
    check_role_escalation(user_id, org_id, old_role, new_role)
    log_event(
        "role_changed",
        {"user_id": user_id, "old_role": old_role, "new_role": new_role},
        user_id=user["user_id"],
        org_id=org_id,
    )
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket — job progress
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/jobs/{job_id}")
async def job_websocket(websocket: WebSocket, job_id: str, token: str = Query(...)):
    # Validate UUID before touching DB
    try:
        validate_uuid(job_id, "job_id")
    except HTTPException:
        await websocket.close(code=4000, reason="Invalid job_id format")
        return

    payload = validate_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    user_id = payload.get("sub")
    svc     = get_service_client()

    job_r = svc.table("wipe_jobs").select("user_id,org_id").eq("id", job_id).maybe_single().execute()
    if not job_r.data:
        await websocket.close(code=4004, reason="Job not found")
        return

    job_owner = job_r.data["user_id"]
    org_id    = job_r.data.get("org_id")

    if job_owner != user_id:
        member_r = (
            svc.table("org_memberships")
            .select("role")
            .eq("org_id", org_id or "")
            .eq("user_id", user_id)
            .maybe_single()
            .execute()
        )
        if not member_r.data:
            await websocket.close(code=4003, reason="Forbidden")
            return

    await websocket.accept()
    room = realtime.room(job_id)
    realtime.connected.setdefault(room, []).append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in realtime.connected.get(room, []):
            realtime.connected[room].remove(websocket)


def _job_options(raw) -> dict:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="options must be an object")
    out = {}
    if raw.get("verify") is not None:
        if raw["verify"] not in ("sample", "full"):
            raise HTTPException(status_code=400, detail="options.verify must be sample or full")
        out["verify"] = raw["verify"]
    if raw.get("psid") is not None:
        psid = str(raw["psid"]).strip()
        if not psid.isalnum() or len(psid) > 64:
            raise HTTPException(status_code=400, detail="options.psid must be alphanumeric")
        out["psid"] = psid
    return out


def _file_serial_label(data: dict, file_paths: list[str]) -> str:
    sources = data.get("sources") or []
    folders = [s for s in sources if s.get("type") == "folder"]
    if folders and len(folders) == 1 and len(folders) == len(sources):
        return folders[0]["path"].replace("\\", "/")
    if data.get("folder"):
        return data["folder"].replace("\\", "/")
    count = len(file_paths)
    return f"{count} item{'s' if count != 1 else ''}"


def _file_model_label(data: dict, file_paths: list[str]) -> str:
    if data.get("device_model"):
        return data["device_model"]
    sources = data.get("sources") or []
    folders = [s for s in sources if s.get("type") == "folder"]
    files = [s for s in sources if s.get("type") == "file"]
    count = len(file_paths)
    if folders and not files:
        if len(folders) == 1:
            name = folders[0]["path"].replace("\\", "/").rstrip("/").split("/")[-1]
            return f"Folder Wipe — {name}"
        return f"Folder Wipe — {len(folders)} folders"
    if folders and files:
        return f"Mixed Wipe — {len(files)} files + {len(folders)} folders"
    return f"File Wipe ({count} file{'s' if count != 1 else ''})"


# ─────────────────────────────────────────────────────────────────────────────
# SPA + static asset serving
# ─────────────────────────────────────────────────────────────────────────────

if FRONTEND_DIST.exists():
    app.mount("/app/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")


@app.get("/app")
@app.get("/app/{full_path:path}")
async def serve_spa(full_path: str = ""):
    if full_path.startswith("assets/"):
        raise HTTPException(status_code=404, detail="Asset not found")
    index = FRONTEND_DIST / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text(encoding="utf-8"))
    raise HTTPException(
        status_code=404,
        detail="Frontend not built. Run: cd frontend && npm run build",
    )


def create_app():
    return app