import base64
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import qrcode
from jinja2 import Environment, FileSystemLoader, select_autoescape
from backend.config import config
from backend.platform_env import FONT_DIR, weasy_html
from backend.timestamps import stamp_certificate


def _compute_hash(fields: dict) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _get_qr_base64(url: str) -> str:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#f5e6c8", back_color="#1a2218")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def _human_bytes(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _verification_method(v: dict | None) -> str | None:
    if not v:
        return None
    if v.get("simulated"):
        return "simulated (dry run)"
    check = v.get("check")
    if check == "pattern":
        return f"{v.get('mode', 'sample')} keyed pattern read-back, {v.get('samples', 0)} blocks, {v.get('mismatches', 0)} mismatches"
    if check == "changed":
        return (f"pre/post sector hash, {v.get('changed', 0)} changed, "
                f"{v.get('unchanged', 0)} unchanged, {v.get('indeterminate', 0)} indeterminate")
    return v.get("reason") or check


FAMILIES = {
    "PlayfairDisplay": "Playfair Display",
    "CormorantGaramond": "Cormorant Garamond",
    "DMSans": "DM Sans",
    "IBMPlexMono": "IBM Plex Mono",
}
TEMPLATES = Path(__file__).resolve().parent / "templates"
ARTWORK = Path(__file__).resolve().parent / "assets" / "artwork_panel.png"
NIST_LABELS = {
    "purge": "Purge",
    "clear": "Clear",
    "none": "None (not a NIST sanitize)",
    "not_applicable": "File level",
}


def _font_faces() -> str:
    rules = []
    for path in sorted(FONT_DIR.glob("*.ttf")):
        parts = path.stem.split("-")
        if len(parts) != 3 or parts[0] not in FAMILIES:
            continue
        family, weight, style = FAMILIES[parts[0]], parts[1], parts[2]
        rules.append(
            f"@font-face {{ font-family: '{family}'; src: url('{path.as_uri()}'); "
            f"font-weight: {weight}; font-style: {style}; }}"
        )
    return "\n".join(rules)


def _issued_display(issued_at: str) -> str:
    try:
        return datetime.fromisoformat(issued_at).strftime("%d %b %Y %H:%M UTC")
    except (TypeError, ValueError):
        return issued_at or ""


def _clip(text: str, limit: int = 64) -> str:
    if len(text) <= limit:
        return text
    head = (limit - 1) // 2
    return f"{text[:head]}\u2026{text[-(limit - 1 - head):]}"


def _ots_status(ots: dict) -> str:
    if ots.get("error"):
        return f"Anchor unavailable: {ots['error']}"
    if ots.get("pending"):
        return "Submitted, pending Bitcoin block confirmation (about 1 hour)"
    return "Immutable blockchain proof anchored"


def _generate_html(cert: dict, qr_b64: str) -> str:
    verified = cert.get("verification_passed")
    dash = "\u2014"
    fields = [
        {"label": "Device", "value": _clip(cert.get("device_model") or dash), "span": 2},
        {"label": "Serial", "value": _clip(cert.get("device_serial") or dash), "span": 2},
        {"label": "Type", "value": (cert.get("device_type") or dash).replace("_", " ").upper()},
        {"label": "Capacity", "value": cert.get("device_capacity_human") or _human_bytes(cert.get("device_capacity_bytes", 0))},
        {"label": "Method", "value": (cert.get("wipe_method") or dash).replace("_", " ")},
        {"label": "Standard", "value": (cert.get("wipe_standard") or dash).replace("_", " ").upper()},
        {"label": "Technique", "value": (cert.get("sanitize_technique") or dash).replace("_", " ").replace("+", " + "), "span": 2},
        {"label": "NIST 800-88", "value": NIST_LABELS.get(cert.get("nist_800_88_category"), dash), "accent": True},
        {"label": "Passes", "value": str(cert.get("passes_completed", 0))},
        {"label": "Verification", "value": "Passed" if verified else "Failed" if verified is False else "Not verifiable",
         "accent": True},
        {"label": "Read-back", "value": cert.get("verification_method") or dash, "span": 2},
        {"label": "Issued", "value": _issued_display(cert.get("issued_at", ""))},
        {"label": "Operator", "value": cert.get("operator_name") or dash, "span": 2},
        {"label": "Organisation", "value": cert.get("organisation_name") or dash},
        {"label": "Approver", "value": cert.get("approver_name") or dash},
    ]
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html"]))
    issued = cert.get("issued_at", "")
    return env.get_template("certificate.html").render(
        font_faces=_font_faces(),
        artwork_uri=ARTWORK.as_uri(),
        cert_id=cert.get("certificate_id", ""),
        badge="Dry run · no data destroyed" if cert.get("dry_run") else
              "Obliteration verified" if verified else "Unverified read-back",
        verified=bool(verified) and not cert.get("dry_run"),
        fields=fields,
        sha256=cert.get("sha256_hash", ""),
        verify_url=cert.get("verify_url", ""),
        ots_status=_ots_status(cert.get("ots_result") or {}),
        qr_b64=qr_b64,
        year=(issued or "")[:4] or datetime.now(timezone.utc).year,
    )


def generate_certificate(
    job: dict,
    user: dict,
    org: dict | None = None,
    approver: dict | None = None,
    record: dict | None = None,
) -> dict:
    cert_id   = job.get("id", str(uuid.uuid4()))
    issued_at = datetime.now(timezone.utc).isoformat()

    cert_fields = {
        "certificate_id":        cert_id,
        "issued_at":             issued_at,
        "device_serial":         job["device_serial"],
        "device_model":          job["device_model"],
        "device_capacity_bytes": job.get("device_capacity_bytes", 0),
        "device_capacity_human": job.get("device_capacity_human") or
                                 _human_bytes(job.get("device_capacity_bytes", 0)),
        "device_type":           job.get("device_type", ""),
        "wipe_method":           job["method"],
        "wipe_standard":         job["standard"],
        "passes_completed":      job.get("passes_completed", 0),
        "verification_passed":   job.get("verification_passed"),
        "operator_id":           user.get("id", ""),
        "operator_name":         user.get("email", ""),
        "organisation_name":     org.get("name") if org else None,
        "approver_name":         approver.get("email") if approver else None,
        "smart_snapshot":        job.get("smart_snapshot"),
        "sanitize_technique":    (record or {}).get("technique") or job.get("technique"),
        "nist_800_88_category":  (record or {}).get("nist_category") or job.get("nist_category"),
        "verification_method":   _verification_method((record or {}).get("verification")),
        "wipe_host":             (record or {}).get("hostname"),
        "wipe_platform":         (record or {}).get("platform"),
        "dry_run":               bool((record or {}).get("dry_run")),
    }

    sha256     = _compute_hash(cert_fields)
    verify_url = f"{config.VERIFY_BASE_URL}/verify/{cert_id}"
    ots_result = stamp_certificate(sha256, cert_id)

    cert_fields["sha256_hash"] = sha256
    cert_fields["verify_url"]  = verify_url
    cert_fields["ots_result"]  = ots_result

    qr_b64       = _get_qr_base64(verify_url)
    html_content = _generate_html(cert_fields, qr_b64)

    pdf_dir = config.DATA_DIR / "certs"
    pdf_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = pdf_dir / f"{cert_id}.pdf"

    weasy_html()(string=html_content).write_pdf(target=str(pdf_path))

    ots_path = config.DATA_DIR / "ots" / f"{cert_id}.ots"

    return {
        "certificate_id": cert_id,
        "pdf_path":        str(pdf_path),
        "ots_path":        str(ots_path) if ots_path.exists() else None,
        "ots_result":      ots_result,
        "issued_at":       issued_at,
        "fields":          cert_fields,
    }