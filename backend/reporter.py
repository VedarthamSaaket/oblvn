import base64
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import qrcode
from weasyprint import HTML, CSS

from backend.config import config
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
    img = qr.make_image(fill_color="#c4b48a", back_color="#1a2218")
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


def _generate_html(cert: dict, qr_b64: str) -> str:
    cert_id       = cert.get("certificate_id", "")
    issued_at     = cert.get("issued_at", "")
    device_model  = cert.get("device_model", "—")
    device_serial = cert.get("device_serial", "—")
    device_type   = (cert.get("device_type") or "").upper() or "—"
    capacity      = cert.get("device_capacity_human") or _human_bytes(cert.get("device_capacity_bytes", 0))
    wipe_method   = (cert.get("wipe_method") or "").replace("_", " ").title()
    wipe_standard = (cert.get("wipe_standard") or "").upper().replace("_", " ")
    passes        = str(cert.get("passes_completed", 0))
    verify_status = "Passed" if cert.get("verification_passed") else "N/A"
    operator      = cert.get("operator_name", "—")
    org           = cert.get("organisation_name") or "—"
    sha256        = cert.get("sha256_hash", "")
    verify_url    = cert.get("verify_url", "")
    ots           = cert.get("ots_result") or {}

    if ots.get("pending"):
        ots_status = "Pending block confirmation (~1 hr)"
    elif ots.get("error"):
        ots_status = ots.get("error")
    else:
        ots_status = "Immutable blockchain proof anchored"

    # Font URIs — Windows absolute paths; adjust for your deployment
    playfair_uri  = Path(r"C:\Users\Saaket Vedarth\PlayfairDisplay-Bold.ttf").as_uri()
    mono_reg_uri  = Path(r"C:\Users\Saaket Vedarth\IBMPlexMono-Regular.ttf").as_uri()
    mono_bold_uri = Path(r"C:\Users\Saaket Vedarth\IBMPlexMono-Bold.ttf").as_uri()

    ots_block = ""
    if ots:
        ots_block = f"""
        <div class="ots-block">
            <span class="ots-icon">&#x20BF;</span>
            <div>
                <div class="ots-label">Bitcoin Anchored via OpenTimestamps</div>
                <div class="ots-status">{ots_status}</div>
            </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  /* ── Fonts ───────────────────────────────────────────── */
  @font-face {{
    font-family: 'Playfair Display';
    src: url('{playfair_uri}');
    font-weight: 700;
  }}
  @font-face {{
    font-family: 'IBM Plex Mono';
    src: url('{mono_reg_uri}');
    font-weight: 400;
  }}
  @font-face {{
    font-family: 'IBM Plex Mono';
    src: url('{mono_bold_uri}');
    font-weight: 700;
  }}

  /* ── Page ────────────────────────────────────────────── */
  @page {{
    size: A4;
    margin: 48pt 44pt;
    background: #1a2218;

    @bottom-left {{
      content: "Obliteration verified.";
      font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
      font-style: italic;
      font-size: 9pt;
      color: #c4b48a;
    }}
    @bottom-right {{
      content: "GDPR Art.\00a017\2002\2022\2002HIPAA \00a7164.310\2002\2022\2002NIST 800-88\2002\2022\2002ISO 27001\2002\2022\2002DoD 5220.22-M";
      font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
      font-size: 5.5pt;
      letter-spacing: 0.06em;
      color: rgba(240,235,224,0.14);
    }}
  }}

  /* ── Reset ───────────────────────────────────────────── */
  *, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}

  /* ── Design tokens ───────────────────────────────────── */
  :root {{
    --ink:       #1a2218;
    --ink-mid:   #1f2a1d;
    --moss:      #2e3a2b;
    --sage:      #4a5442;
    --cream:     #f5e6c8;
    --parchment: #c4b48a;
    --serif:     'Playfair Display', Georgia, 'Times New Roman', serif;
    --mono:      'IBM Plex Mono', 'Courier New', monospace;
    --sans:      'Helvetica Neue', Helvetica, Arial, sans-serif;
  }}

  body {{
    font-family: var(--mono);
    background: var(--ink);
    color: var(--cream);
    font-size: 9pt;
    line-height: 1.5;
  }}

  /* ── Top accent stripe ───────────────────────────────── */
  .stripe {{
    display: flex;
    height: 4pt;
    margin-bottom: 36pt;
    margin-left:  -44pt;
    margin-right: -44pt;
  }}
  .stripe-1 {{ flex: 2; background: rgba(74,84,66,0.90); }}
  .stripe-2 {{ flex: 1; background: rgba(240,235,224,0.18); }}
  .stripe-3 {{ flex: 3; background: rgba(74,84,66,0.55); }}
  .stripe-4 {{ flex: 1; background: rgba(196,180,138,0.45); }}

  /* ── Brand ───────────────────────────────────────────── */
  .brand {{
    margin-bottom: 28pt;
  }}
  .brand-name {{
    font-family: var(--serif);
    font-size: 38pt;
    font-weight: 700;
    color: var(--cream);
    letter-spacing: -0.01em;
    line-height: 1;
    margin-bottom: 6pt;
  }}
  .brand-tagline {{
    font-family: var(--sans);
    font-size: 5.5pt;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: rgba(240,235,224,0.22);
    margin-bottom: 18pt;
  }}
  .doc-title {{
    font-family: var(--sans);
    font-style: italic;
    font-size: 17pt;
    font-weight: 300;
    color: rgba(240,235,224,0.48);
  }}

  /* ── ID rule ─────────────────────────────────────────── */
  .id-rule {{
    display: flex;
    justify-content: flex-end;
    align-items: center;
    border-bottom: 0.5pt solid rgba(240,235,224,0.08);
    padding-bottom: 5pt;
    margin-bottom: 26pt;
  }}
  .cert-id-label {{
    font-size: 6pt;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: rgba(240,235,224,0.16);
  }}

  /* ── Two-column data grid ────────────────────────────── */
  .grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    column-gap: 36pt;
    row-gap: 18pt;
    margin-bottom: 32pt;
  }}
  .field-label {{
    font-family: var(--sans);
    font-size: 5.5pt;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: rgba(240,235,224,0.20);
    margin-bottom: 3pt;
  }}
  .field-value {{
    font-family: var(--mono);
    font-size: 9pt;
    color: var(--cream);
    line-height: 1.35;
  }}

  /* ── Section divider ─────────────────────────────────── */
  .section-rule {{
    border: none;
    border-top: 0.5pt solid rgba(240,235,224,0.06);
    margin: 22pt 0;
  }}

  /* ── Hash block ──────────────────────────────────────── */
  .hash-block {{
    background: rgba(74,84,66,0.18);
    border-left: 2.5pt solid rgba(74,84,66,0.60);
    padding: 12pt 14pt;
    margin-bottom: 14pt;
  }}
  .hash-label {{
    font-family: var(--sans);
    font-size: 5.5pt;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: rgba(240,235,224,0.20);
    margin-bottom: 7pt;
  }}
  .hash-value {{
    font-family: var(--mono);
    font-size: 7pt;
    color: rgba(240,235,224,0.40);
    word-break: break-all;
    line-height: 1.6;
  }}

  /* ── OTS block ───────────────────────────────────────── */
  .ots-block {{
    display: flex;
    align-items: flex-start;
    gap: 12pt;
    background: rgba(46,58,43,0.38);
    border-left: 2.5pt solid rgba(196,180,138,0.48);
    padding: 10pt 14pt;
    margin-bottom: 14pt;
  }}
  .ots-icon {{
    font-size: 13pt;
    color: var(--parchment);
    flex-shrink: 0;
    line-height: 1;
    margin-top: 1pt;
  }}
  .ots-label {{
    font-family: var(--sans);
    font-size: 6pt;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: rgba(196,180,138,0.75);
    margin-bottom: 3pt;
  }}
  .ots-status {{
    font-family: var(--mono);
    font-size: 8pt;
    color: rgba(196,180,138,0.55);
  }}

  /* ── QR / verify block ───────────────────────────────── */
  .qr-block {{
    display: flex;
    align-items: center;
    gap: 18pt;
    border: 0.5pt solid rgba(240,235,224,0.07);
    background: rgba(240,235,224,0.02);
    padding: 14pt;
    margin-bottom: 24pt;
  }}
  .qr-img {{
    width: 72pt;
    height: 72pt;
    flex-shrink: 0;
  }}
  .qr-title {{
    font-family: var(--sans);
    font-size: 5.5pt;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: rgba(240,235,224,0.20);
    margin-bottom: 5pt;
  }}
  .qr-url {{
    font-family: var(--mono);
    font-size: 7.5pt;
    color: var(--parchment);
    margin-bottom: 5pt;
    word-break: break-all;
  }}
  .qr-desc {{
    font-family: var(--sans);
    font-size: 6.5pt;
    color: rgba(240,235,224,0.18);
    line-height: 1.7;
  }}
</style>
</head>
<body>

  <!-- Accent stripe -->
  <div class="stripe">
    <div class="stripe-1"></div>
    <div class="stripe-2"></div>
    <div class="stripe-3"></div>
    <div class="stripe-4"></div>
  </div>

  <!-- Brand -->
  <div class="brand">
    <div class="brand-name">OBLVN</div>
    <div class="brand-tagline">Secure Data Obliteration Platform</div>
    <div class="doc-title">Certificate of Destruction</div>
  </div>

  <!-- ID rule -->
  <div class="id-rule">
    <span class="cert-id-label">{cert_id}</span>
  </div>

  <!-- Data grid -->
  <div class="grid">
    <div>
      <div class="field-label">Certificate ID</div>
      <div class="field-value">{cert_id}</div>
    </div>
    <div>
      <div class="field-label">Issued At (UTC)</div>
      <div class="field-value">{issued_at}</div>
    </div>
    <div>
      <div class="field-label">Device Model</div>
      <div class="field-value">{device_model}</div>
    </div>
    <div>
      <div class="field-label">Device Serial</div>
      <div class="field-value">{device_serial}</div>
    </div>
    <div>
      <div class="field-label">Device Type</div>
      <div class="field-value">{device_type}</div>
    </div>
    <div>
      <div class="field-label">Capacity</div>
      <div class="field-value">{capacity}</div>
    </div>
    <div>
      <div class="field-label">Wipe Method</div>
      <div class="field-value">{wipe_method}</div>
    </div>
    <div>
      <div class="field-label">Standard Applied</div>
      <div class="field-value">{wipe_standard}</div>
    </div>
    <div>
      <div class="field-label">Passes Completed</div>
      <div class="field-value">{passes}</div>
    </div>
    <div>
      <div class="field-label">Verification Read-back</div>
      <div class="field-value">{verify_status}</div>
    </div>
    <div>
      <div class="field-label">Operator</div>
      <div class="field-value">{operator}</div>
    </div>
    <div>
      <div class="field-label">Organisation</div>
      <div class="field-value">{org}</div>
    </div>
  </div>

  <hr class="section-rule" />

  <!-- SHA-256 hash -->
  <div class="hash-block">
    <div class="hash-label">SHA-256 &middot; Wipe Fingerprint</div>
    <div class="hash-value">{sha256[:32]}<br />{sha256[32:]}</div>
  </div>

  <!-- OTS (conditional) -->
  {ots_block}

  <!-- QR verify -->
  <div class="qr-block">
    <img class="qr-img" src="data:image/png;base64,{qr_b64}" alt="Verify QR" />
    <div>
      <div class="qr-title">Verify this certificate independently</div>
      <div class="qr-url">{verify_url}</div>
      <div class="qr-desc">
        Scan QR or visit the URL above to verify the wipe fingerprint.<br />
        This proof persists on the Bitcoin blockchain even if OBLVN goes offline.
      </div>
    </div>
  </div>

</body>
</html>"""


def generate_certificate(
    job: dict,
    user: dict,
    org: dict | None = None,
    approver: dict | None = None,
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

    HTML(string=html_content).write_pdf(target=str(pdf_path))

    ots_path = config.DATA_DIR / "ots" / f"{cert_id}.ots"

    return {
        "certificate_id": cert_id,
        "pdf_path":        str(pdf_path),
        "ots_path":        str(ots_path) if ots_path.exists() else None,
        "ots_result":      ots_result,
        "issued_at":       issued_at,
        "fields":          cert_fields,
    }