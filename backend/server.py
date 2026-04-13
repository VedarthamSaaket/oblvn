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
import threading
import os
import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from apscheduler.schedulers.background import BackgroundScheduler

from backend.anomaly import (
    acknowledge_anomaly, check_failed_logins, check_new_ip,
    check_new_operator, check_off_hours_wipe, check_repeat_wipe,
    check_smart_anomalies, check_unusual_login_hour, check_verification_failure,
    compute_risk_score, run_statistical_batch, check_role_escalation,
)
from backend.audit import export_csv, export_json, export_pdf, log_event, verify_chain
from backend.auth import get_user_role, validate_token
from backend.config import config
from backend.detector import DeviceDetectionError, detect_devices, get_device_by_serial
from backend.reporter import generate_certificate
from backend.supabase_client import get_service_client

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
        run_statistical_batch(None)
    except Exception as exc:
        log_event("scheduled_batch_failed", {"error": str(exc)}, user_id=None)

scheduler = BackgroundScheduler()
scheduler.add_job(func=_scheduled_batch, trigger="cron", hour=2, minute=0)
scheduler.start()

connected_websockets: dict[str, list[WebSocket]] = {}
_cancel_flags: dict[str, threading.Event] = {}


async def _ws_broadcast(job_id: str, data: dict):
    room = f"job_{job_id}"
    for ws in connected_websockets.get(room, []):
        try:
            await ws.send_json(data)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization token")
    token = auth[7:]
    payload = validate_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"user_id": payload.get("sub"), "token": token, "payload": payload}


def current_user(request: Request) -> dict:
    return _get_current_user(request)


FRONTEND_DIST   = Path(__file__).parent.parent / "frontend" / "dist"
FRONTEND_PUBLIC = Path(__file__).parent.parent / "frontend" / "public"


# ─────────────────────────────────────────────────────────────────────────────
# Supabase retry helpers (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def _supabase_update_with_retry(
    svc,
    table: str,
    update_data: dict,
    job_id: str,
    retries: int = 5,
    base_delay: float = 3.0,
) -> None:
    last_exc = None
    for attempt in range(retries):
        try:
            svc.table(table).update(update_data).eq("id", job_id).execute()
            return
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                wait = base_delay * (attempt + 1)
                print(
                    f"[SUPABASE RETRY] attempt {attempt + 1}/{retries} failed "
                    f"({type(exc).__name__}: {exc}). Retrying in {wait:.0f}s ..."
                )
                time.sleep(wait)
    raise last_exc


def _finalize_job_with_retry(
    job_id: str,
    job: dict,
    crypto_key: str | None,
    broadcast,
    retries: int = 5,
    base_delay: float = 3.0,
) -> None:
    last_exc = None
    for attempt in range(retries):
        try:
            _finalize_job(job_id, job, crypto_key, broadcast)
            return
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                wait = base_delay * (attempt + 1)
                print(
                    f"[FINALIZE RETRY] attempt {attempt + 1}/{retries} failed "
                    f"({type(exc).__name__}: {exc}). Retrying in {wait:.0f}s ..."
                )
                time.sleep(wait)
    raise last_exc


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
        .select("id,sha256_hash,completed_at,device_model,device_serial,method,standard")
        .eq("id", cert_id)
        .maybe_single()
        .execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Certificate not found")
    job = r.data
    return {
        "verified":       True,
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
@limiter.limit("10 per minute")          # prevent automated account creation
async def register(request: Request, body: AuthBody):
    # Validate email format and password strength before touching Supabase
    validated_email = validate_email(body.email)
    validate_password_strength(body.password)

    client = get_service_client()
    try:
        result = client.auth.sign_up({"email": validated_email, "password": body.password})
        if result.user is None:
            return {"user_id": "pending_confirmation", "confirm_email": True}
        user_id = result.user.id
        log_event("user_registered", {"email": validated_email}, user_id=user_id)
        return {"user_id": user_id, "confirm_email": False}
    except HTTPException:
        raise
    except Exception as exc:
        print(f"[REGISTER ERROR] {type(exc).__name__}: {exc}")
        # Do not leak provider error details; return a generic message
        raise HTTPException(
            status_code=400,
            detail=safe_error_detail(exc, "Registration failed. Please try again."),
        )


@app.post("/api/auth/login")
@limiter.limit(config.AUTH_RATE_LIMIT)
async def login(request: Request, body: AuthBody):
    # Validate email format to reject obviously malformed inputs early
    validated_email = validate_email(body.email)

    client = get_service_client()
    ip = request.client.host if request.client else "unknown"
    try:
        result = client.auth.sign_in_with_password(
            {"email": validated_email, "password": body.password}
        )
        user_id = result.user.id
        log_event("login_success", {"email": validated_email, "ip_address": ip}, user_id=user_id)
        check_new_ip(user_id, None, ip)
        check_unusual_login_hour(user_id, None, datetime.now(timezone.utc))
        return {
            "access_token":  result.session.access_token,
            "refresh_token": result.session.refresh_token,
            "user":          {"id": user_id, "email": validated_email},
        }
    except HTTPException:
        raise
    except Exception:
        log_event("login_failed", {"email": validated_email, "ip_address": ip}, user_id=None)
        try:
            check_failed_logins(validated_email, None)
        except Exception:
            pass
        # Always return the same generic message to prevent user enumeration
        raise HTTPException(status_code=401, detail="Invalid login credentials")


@app.post("/api/auth/logout")
async def logout(request: Request):
    user = current_user(request)
    try:
        get_service_client().auth.admin.sign_out(user["token"])
    except Exception:
        pass
    log_event("logout", {}, user_id=user["user_id"])
    return {"ok": True}


@app.post("/api/auth/refresh")
@limiter.limit("30 per minute")
async def refresh(request: Request, body: RefreshBody):
    try:
        result = get_service_client().auth.refresh_session(body.refresh_token)
        return {
            "access_token":  result.session.access_token,
            "refresh_token": result.session.refresh_token,
        }
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Token refresh failed")


@app.post("/api/auth/2fa/setup")
async def setup_2fa(request: Request):
    current_user(request)
    return {
        "message":  "TOTP enrollment is handled via Supabase MFA API",
        "endpoint": f"{config.SUPABASE_URL}/auth/v1/factors",
        "docs":     "https://supabase.com/docs/guides/auth/auth-mfa",
    }


@app.post("/api/auth/password/reset")
@limiter.limit(config.AUTH_RATE_LIMIT)
async def password_reset(request: Request, body: ResetBody):
    validated_email = validate_email(body.email)
    try:
        get_service_client().auth.reset_password_email(validated_email)
        # Always return success — never reveal whether the email exists
        return {"ok": True}
    except Exception:
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

    try:
        devices = detect_devices()
        for d in devices:
            d["anomalies"] = check_smart_anomalies(
                d["serial"], d.get("smart_snapshot", {}), org_id, user["user_id"]
            )
        return {"devices": devices}
    except DeviceDetectionError as exc:
        return {"error": str(exc), "devices": []}


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
    current_user(request)
    try:
        d = get_device_by_serial(serial)
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

    if org_id:
        # IDOR: verify caller is a member of the org before listing its jobs
        validate_uuid(org_id, "org_id")
        assert_org_membership(org_id, user["user_id"], svc, min_role="operator")
        q = svc.table("wipe_jobs").select("*").order("created_at", desc=True).eq("org_id", org_id)
    else:
        # No org_id → return only the authenticated user's own jobs
        q = svc.table("wipe_jobs").select("*").order("created_at", desc=True).eq("user_id", user["user_id"])

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

    if target_serial.startswith("file:"):
        file_paths = data.get("file_paths") or []
        if not file_paths:
            file_paths = [target_serial.replace("file:", "", 1)]

        missing = [p for p in file_paths if not os.path.exists(p)]
        if missing:
            raise HTTPException(
                status_code=404,
                detail=f"File(s) not found: {', '.join(missing[:5])}{'...' if len(missing) > 5 else ''}",
            )

        total_bytes = sum(os.path.getsize(p) for p in file_paths if os.path.isfile(p))

        sources = data.get("sources") or []
        count   = len(file_paths)

        if sources:
            folder_sources = [s for s in sources if s.get("type") == "folder"]
            file_sources   = [s for s in sources if s.get("type") == "file"]

            if folder_sources and not file_sources:
                if len(folder_sources) == 1:
                    fname        = folder_sources[0]["path"].replace("\\", "/").rstrip("/").split("/")[-1]
                    model_label  = f"Folder Wipe — {fname} ({count} files)"
                    serial_label = folder_sources[0]["path"].replace("\\", "/")
                else:
                    model_label  = f"Folder Wipe — {len(folder_sources)} folders ({count} files)"
                    serial_label = f"{len(folder_sources)} folders"
            elif file_sources and not folder_sources:
                model_label  = data.get("device_model") or f"File Wipe ({count} file{'s' if count != 1 else ''})"
                serial_label = f"{count} file{'s' if count != 1 else ''}"
            else:
                model_label  = (
                    f"Mixed Wipe — {len(file_sources)} file{'s' if len(file_sources) != 1 else ''} "
                    f"+ {len(folder_sources)} folder{'s' if len(folder_sources) != 1 else ''} ({count} total)"
                )
                serial_label = f"{count} items"
        else:
            folder = data.get("folder")
            if folder:
                fname        = folder.replace("\\", "/").rstrip("/").split("/")[-1]
                model_label  = data.get("device_model") or f"Folder Wipe — {fname} ({count} files)"
                serial_label = folder.replace("\\", "/")
            else:
                model_label  = data.get("device_model") or f"File Wipe ({count} file{'s' if count != 1 else ''})"
                serial_label = f"{count} file{'s' if count != 1 else ''}"

        device = {
            "serial":         serial_label,
            "model":          model_label,
            "capacity_bytes": total_bytes,
            "device_type":    "file",
            "node":           file_paths[0],
            "smart_snapshot": {},
        }

    else:
        file_paths = []
        try:
            device = get_device_by_serial(target_serial)
        except DeviceDetectionError as exc:
            raise HTTPException(status_code=503, detail=str(exc))

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

    check_new_operator(user["user_id"], org_id, "pending")
    check_off_hours_wipe("pending", org_id, user["user_id"], datetime.now(timezone.utc))

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
        "file_paths":            json.dumps(file_paths) if file_paths else None,
    }

    r = svc.table("wipe_jobs").insert(job).execute()
    created = r.data[0]
    log_event(
        "wipe_job_created",
        {"job_id": created["id"], "device": device["serial"]},
        user_id=user["user_id"],
        org_id=org_id,
    )

    if status == "queued":
        threading.Thread(target=_execute_job, args=(created["id"],), daemon=True).start()

    return JSONResponse(content=created, status_code=201)


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, request: Request):
    validate_uuid(job_id, "job_id")
    user = current_user(request)
    svc  = get_service_client()

    r = svc.table("wipe_jobs").select("*").eq("id", job_id).maybe_single().execute()
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
    job_r = svc.table("wipe_jobs").select("org_id,status").eq("id", job_id).maybe_single().execute()
    if not job_r.data:
        raise HTTPException(status_code=404, detail="Job not found")
    if body.org_id and job_r.data.get("org_id") != body.org_id:
        raise HTTPException(status_code=403, detail="Forbidden: job does not belong to this organisation")

    svc.table("wipe_jobs").update({"status": "queued", "approved_by": user["user_id"]}).eq("id", job_id).execute()
    log_event("wipe_job_approved", {"job_id": job_id}, user_id=user["user_id"], org_id=body.org_id)
    threading.Thread(target=_execute_job, args=(job_id,), daemon=True).start()
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

    cancel_event = _cancel_flags.get(job_id)
    if cancel_event:
        cancel_event.set()

    svc.table("wipe_jobs").update({"status": "cancelled"}).eq("id", job_id).execute()
    log_event("wipe_job_cancelled", {"job_id": job_id}, user_id=user["user_id"])
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

    if format == "csv":
        content = export_csv(org_id, start, end)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=oblvn-audit.csv"},
        )
    if format == "pdf":
        pdf_bytes = export_pdf(org_id, start, end)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=oblvn-audit.pdf"},
        )
    return {"entries": export_json(org_id, start, end)}


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

    return compute_risk_score(org_id)


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
        q = svc.table("anomalies").select("*").order("detected_at", desc=True).eq("org_id", org_id)
    else:
        # Account isolation: no org → return only anomalies linked to this user
        q = svc.table("anomalies").select("*").order("detected_at", desc=True).eq("user_id", user["user_id"])

    if status:
        q = q.eq("status", status)

    r = q.execute()
    return {"anomalies": r.data or []}


@app.post("/api/anomalies/{anomaly_id}/acknowledge")
async def ack_anomaly(anomaly_id: str, request: Request, body: AnomalyAckBody):
    validate_uuid(anomaly_id, "anomaly_id")
    user = current_user(request)
    svc  = get_service_client()

    # IDOR: verify user can access this anomaly before acknowledging it
    assert_anomaly_access(anomaly_id, user["user_id"], svc)

    result = acknowledge_anomaly(
        anomaly_id, user["user_id"],
        note=body.note,
        resolved=body.resolved,
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
    try:
        user_result = svc.auth.admin.invite_user_by_email(validated_email)
        svc.table("org_memberships").insert({
            "user_id":    user_result.user.id,
            "org_id":     org_id,
            "role":       body.role,
            "invited_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
        log_event(
            "member_invited",
            {"email": validated_email, "role": body.role},
            user_id=user["user_id"],
            org_id=org_id,
        )
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=safe_error_detail(exc, "Invite failed"))


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
    room = f"job_{job_id}"
    connected_websockets.setdefault(room, []).append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_websockets.get(room, []):
            connected_websockets[room].remove(websocket)


# ─────────────────────────────────────────────────────────────────────────────
# Background job execution (unchanged core logic)
# ─────────────────────────────────────────────────────────────────────────────

class _CancelledError(Exception):
    pass


def _check_cancel(job_id: str):
    ev = _cancel_flags.get(job_id)
    if ev and ev.is_set():
        raise _CancelledError(f"Job {job_id} was cancelled")


def _wipe_single_file(
    file_path: str,
    method: str,
    standard: str,
    broadcast,
    file_index: int,
    file_total: int,
    job_id: str,
):
    file_size  = os.path.getsize(file_path)
    chunk_size = 1024 * 1024

    if method == "crypto_erase":
        from backend.crypto_erase import run_crypto_erase

        def cb(pct, label):
            _check_cancel(job_id)
            broadcast({
                "type":        "progress",
                "phase":       "crypto",
                "file_index":  file_index,
                "file_total":  file_total,
                "file_path":   file_path,
                "pass_pct":    pct,
                "overall_pct": round(((file_index - 1) / file_total + pct / 100 / file_total) * 100, 2),
                "label":       f"[{file_index}/{file_total}] {label}",
            })

        run_crypto_erase(file_path, progress_cb=cb)

    else:
        from backend.wiper import STANDARDS as WIPER_STANDARDS, NIST_PASSES
        passes     = WIPER_STANDARDS.get(standard, NIST_PASSES)
        num_passes = len(passes)

        for pass_num, p in enumerate(passes, 1):
            _check_cancel(job_id)
            pattern = p["pattern"]
            if pattern == "zero":
                chunk = bytearray(chunk_size)
            elif pattern == "ones":
                chunk = bytearray(b"\xFF" * chunk_size)
            elif pattern == "random":
                chunk = bytearray(os.urandom(chunk_size))
            else:
                raw   = p.get("data", b"\x00")
                chunk = bytearray((raw * (chunk_size // len(raw) + 1))[:chunk_size])

            with open(file_path, "r+b") as f:
                written = 0
                while written < file_size:
                    _check_cancel(job_id)
                    to_write = min(chunk_size, file_size - written)
                    f.write(chunk[:to_write])
                    written += to_write
                    pass_pct    = (written / file_size) * 100
                    file_pct    = ((pass_num - 1) / num_passes + pass_pct / 100 / num_passes) * 100
                    overall_pct = round(((file_index - 1) / file_total + file_pct / 100 / file_total) * 100, 2)
                    broadcast({
                        "type":         "progress",
                        "file_index":   file_index,
                        "file_total":   file_total,
                        "file_path":    file_path,
                        "pass_num":     pass_num,
                        "total_passes": num_passes,
                        "pass_pct":     round(pass_pct, 2),
                        "overall_pct":  overall_pct,
                        "label":        f"[{file_index}/{file_total}] {p['label']}",
                    })

    os.remove(file_path)


def _execute_job(job_id: str):
    cancel_event = threading.Event()
    _cancel_flags[job_id] = cancel_event

    svc = get_service_client()
    r   = svc.table("wipe_jobs").select("*").eq("id", job_id).maybe_single().execute()
    if not r.data:
        _cancel_flags.pop(job_id, None)
        return
    job = r.data

    if job["status"] == "cancelled":
        _cancel_flags.pop(job_id, None)
        return

    _supabase_update_with_retry(svc, "wipe_jobs", {
        "status":     "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }, job_id)

    loop = asyncio.new_event_loop()

    def broadcast(data):
        if not loop.is_closed():
            asyncio.run_coroutine_threadsafe(_ws_broadcast(job_id, data), loop)

    loop_thread = threading.Thread(target=loop.run_forever, daemon=True)
    loop_thread.start()

    try:
        target_serial = job["device_serial"]
        passes_done   = 0
        verification  = None

        if job.get("device_type") == "file":
            # ── FILE / FOLDER PATH ─────────────────────────────────────────
            raw_paths = job.get("file_paths")
            if raw_paths:
                try:
                    file_paths = json.loads(raw_paths) if isinstance(raw_paths, str) else raw_paths
                except Exception:
                    file_paths = []
            else:
                file_paths = []

            if not file_paths:
                raise RuntimeError("No file paths recorded for this file wipe job")

            file_total = len(file_paths)
            method     = job["method"]
            standard   = job["standard"]

            for file_index, file_path in enumerate(file_paths, 1):
                _check_cancel(job_id)
                if not os.path.exists(file_path):
                    broadcast({
                        "type":       "warning",
                        "message":    f"Skipped (not found): {file_path}",
                        "file_index": file_index,
                        "file_total": file_total,
                    })
                    continue
                _wipe_single_file(file_path, method, standard, broadcast, file_index, file_total, job_id)

            passes_done  = 1
            verification = True

        else:
            # ── HARDWARE PATH ──────────────────────────────────────────────
            device = get_device_by_serial(target_serial)
            if not device:
                raise RuntimeError("Device not found during execution")

            node     = device["node"]
            method   = job["method"]
            standard = job["standard"]

            if method == "binary_overwrite":
                from backend.wiper import run_wipe
                gen = run_wipe(node, standard, job["device_type"])

                for event in gen:
                    _check_cancel(job_id)
                    if event.get("type") == "complete":
                        passes_done  = event.get("passes_completed", passes_done)
                        verification = event.get("verification_passed")
                        break
                    event["type"] = "progress"
                    broadcast(event)
                    if event.get("pass_num"):
                        passes_done = event["pass_num"]

            elif method == "crypto_erase":
                from backend.crypto_erase import run_crypto_erase

                def cb(pct, label):
                    _check_cancel(job_id)
                    broadcast({"type": "progress", "phase": "crypto", "pass_pct": pct,
                               "overall_pct": pct, "label": label,
                               "pass_num": 1, "total_passes": 1})

                result = run_crypto_erase(node, progress_cb=cb)

                _supabase_update_with_retry(svc, "wipe_jobs", {
                    "status":              "completed",
                    "completed_at":        datetime.now(timezone.utc).isoformat(),
                    "passes_completed":    1,
                    "verification_passed": None,
                }, job_id)

                _finalize_job_with_retry(job_id, job, result.get("key_displayed_once"), broadcast)
                return

            else:
                # full_sanitization hardware path
                from backend.sanitizer import run_full_sanitization
                gen = run_full_sanitization(node, standard, job["device_type"])
                crypto_key = None

                for event in gen:
                    _check_cancel(job_id)
                    if event.get("type") == "complete":
                        passes_done  = event.get("passes_completed", 1)
                        verification = event.get("verification_passed")
                        crypto_key   = (event.get("crypto_result") or {}).get("key_displayed_once")
                        break
                    event["type"] = "progress"
                    broadcast(event)
                    if event.get("pass_num"):
                        passes_done = event["pass_num"]

                _supabase_update_with_retry(svc, "wipe_jobs", {
                    "status":              "completed",
                    "completed_at":        datetime.now(timezone.utc).isoformat(),
                    "passes_completed":    passes_done,
                    "verification_passed": verification,
                }, job_id)

                _finalize_job_with_retry(job_id, job, crypto_key, broadcast)
                return

        # Shared finalization for file/folder and binary_overwrite paths
        if verification is False:
            check_verification_failure(job_id, job.get("org_id"), job["user_id"])

        _supabase_update_with_retry(svc, "wipe_jobs", {
            "status":              "completed",
            "completed_at":        datetime.now(timezone.utc).isoformat(),
            "passes_completed":    passes_done,
            "verification_passed": verification,
        }, job_id)

        _finalize_job_with_retry(job_id, job, None, broadcast)

    except _CancelledError:
        broadcast({"type": "cancelled", "job_id": job_id})

    except Exception as exc:
        try:
            current_r = svc.table("wipe_jobs").select("status").eq("id", job_id).maybe_single().execute()
            if current_r.data and current_r.data["status"] != "cancelled":
                _supabase_update_with_retry(svc, "wipe_jobs", {
                    "status":        "failed",
                    "error_message": str(exc),
                }, job_id)
                log_event(
                    "wipe_job_failed",
                    {"job_id": job_id, "error": str(exc)},
                    user_id=job["user_id"],
                    org_id=job.get("org_id"),
                )
                broadcast({"type": "error", "error": str(exc)})
        except Exception:
            pass

    finally:
        _cancel_flags.pop(job_id, None)
        time.sleep(0.5)
        try:
            loop.call_soon_threadsafe(loop.stop)
        except Exception:
            pass
        loop_thread.join(timeout=5)
        try:
            loop.close()
        except Exception:
            pass


def _finalize_job(job_id: str, job: dict, crypto_key: str | None, broadcast):
    svc = get_service_client()

    r           = svc.table("wipe_jobs").select("*").eq("id", job_id).maybe_single().execute()
    updated_job = r.data or job

    user_r = get_service_client().auth.admin.get_user_by_id(job["user_id"])
    user   = (
        {"id": job["user_id"], "email": getattr(user_r.user, "email", "")}
        if user_r.user else {"id": job["user_id"], "email": ""}
    )

    org = None
    if job.get("org_id"):
        org_r = (
            svc.table("organisations")
            .select("name")
            .eq("id", job["org_id"])
            .maybe_single()
            .execute()
        )
        org = org_r.data

    approver = None
    if updated_job.get("approved_by"):
        ap_r = get_service_client().auth.admin.get_user_by_id(updated_job["approved_by"])
        if ap_r.user:
            approver = {"email": ap_r.user.email}

    cert_result = generate_certificate(updated_job, user, org, approver)

    _supabase_update_with_retry(svc, "wipe_jobs", {
        "sha256_hash":    cert_result["fields"]["sha256_hash"],
        "ots_proof_path": cert_result.get("ots_path"),
        "pdf_path":       cert_result["pdf_path"],
    }, job_id)

    log_event(
        "wipe_job_completed",
        {
            "job_id":     job_id,
            "sha256_hash": cert_result["fields"]["sha256_hash"],
            "cert_id":    cert_result["certificate_id"],
        },
        user_id=job["user_id"],
        org_id=job.get("org_id"),
    )

    check_repeat_wipe(job["device_serial"], job.get("org_id"), job["user_id"])

    broadcast({
        "type":           "complete",
        "job_id":         job_id,
        "certificate_id": cert_result["certificate_id"],
        "sha256_hash":    cert_result["fields"]["sha256_hash"],
        "verify_url":     cert_result["fields"]["verify_url"],
        "crypto_key":     crypto_key,
    })


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