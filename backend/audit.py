import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone

from weasyprint import HTML
from backend.supabase_client import get_service_client
import os
import os
import sys

# --- FORCED FONTCONFIG INJECTION ---
gtk_fonts_dir = r"C:\Program Files\GTK3-Runtime Win64\etc\fonts"
fonts_conf_file = rf"{gtk_fonts_dir}\fonts.conf"

# Verify the file actually exists on your hard drive
if not os.path.exists(fonts_conf_file):
    print(f"\n[CRITICAL ERROR] Fontconfig file is literally missing: {fonts_conf_file}")
    print("GTK might be installed in a different folder, or the installation is broken.\n")
else:
    # Force both variables into the OS environment before WeasyPrint loads
    os.environ["FONTCONFIG_PATH"] = gtk_fonts_dir
    os.environ["FONTCONFIG_FILE"] = fonts_conf_file

# NOW we can safely import WeasyPrint
from weasyprint import HTML

def _hash_entry(payload: dict, prev_hash: str) -> str:
    content = json.dumps(payload, sort_keys=True, separators=(",", ":")) + prev_hash
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _get_last_hash(org_id: str | None) -> str:
    svc = get_service_client()
    q = svc.table("audit_log").select("entry_hash").order("id", desc=True).limit(1)
    if org_id:
        q = q.eq("org_id", org_id)
    r = q.execute()
    if r.data:
        return r.data[0]["entry_hash"]
    return "0" * 64


def _safe_uuid(value: str | None) -> str | None:
    """Return value only if it's a valid UUID, otherwise None."""
    if value is None:
        return None
    try:
        uuid.UUID(str(value))
        return str(value)
    except (ValueError, AttributeError):
        return None


def log_event(event_type: str, payload: dict, user_id: str,
              org_id: str | None = None, is_anomaly: bool = False,
              anomaly_severity: str | None = None,
              anomaly_type: str | None = None) -> dict:
    svc = get_service_client()
    prev_hash = _get_last_hash(org_id)

    safe_user_id = _safe_uuid(user_id) or None
    safe_org_id = _safe_uuid(org_id)

    entry_payload = {"event_type": event_type, "payload": payload,
                     "user_id": safe_user_id, "org_id": safe_org_id}
    entry_hash = _hash_entry(entry_payload, prev_hash)

    row = {
        "org_id": safe_org_id,
        "user_id": safe_user_id,
        "event_type": event_type,
        "event_payload": json.dumps(payload),
        "prev_entry_hash": prev_hash,
        "entry_hash": entry_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_anomaly": is_anomaly,
        "anomaly_severity": anomaly_severity,
        "anomaly_type": anomaly_type,
    }

    try:
        result = svc.table("audit_log").insert(row).execute()
        return result.data[0] if result.data else row
    except Exception as exc:
        print(f"[AUDIT] Failed to log event '{event_type}': {exc}")
        return row


def verify_chain(org_id: str | None = None) -> dict:
    svc = get_service_client()
    q = svc.table("audit_log").select("*").order("id", desc=False)
    if org_id:
        q = q.eq("org_id", org_id)
    r = q.execute()
    entries = r.data or []

    prev_hash = "0" * 64
    broken_at = None

    for i, entry in enumerate(entries):
        payload = {
            "event_type": entry["event_type"],
            "payload": json.loads(entry["event_payload"]) if isinstance(entry["event_payload"], str) else entry["event_payload"],
            "user_id": entry["user_id"],
            "org_id": entry["org_id"],
        }
        expected_hash = _hash_entry(payload, prev_hash)
        if expected_hash != entry["entry_hash"]:
            broken_at = i
            break
        prev_hash = entry["entry_hash"]

    return {
        "intact": broken_at is None,
        "total_entries": len(entries),
        "broken_at_entry": broken_at,
    }


def export_csv(org_id: str | None = None, start: str | None = None,
               end: str | None = None) -> str:
    svc = get_service_client()
    q = svc.table("audit_log").select("*").order("id", desc=False)
    if org_id:
        q = q.eq("org_id", org_id)
    if start:
        q = q.gte("created_at", start)
    if end:
        q = q.lte("created_at", end)
    r = q.execute()
    entries = r.data or []

    buf = io.StringIO()
    if not entries:
        return buf.getvalue()

    writer = csv.DictWriter(buf, fieldnames=list(entries[0].keys()))
    writer.writeheader()
    writer.writerows(entries)
    return buf.getvalue()


def export_json(org_id: str | None = None, start: str | None = None,
                end: str | None = None) -> list[dict]:
    svc = get_service_client()
    q = svc.table("audit_log").select("*").order("id", desc=False)
    if org_id:
        q = q.eq("org_id", org_id)
    if start:
        q = q.gte("created_at", start)
    if end:
        q = q.lte("created_at", end)
    r = q.execute()
    return r.data or []


# --- WeasyPrint PDF Export ---
def export_pdf(org_id: str | None = None, start: str | None = None,
               end: str | None = None) -> bytes:
    entries = export_json(org_id, start, end)
    chain = verify_chain(org_id)

    # Prepare Chain Integrity Status
    if chain["intact"]:
        chain_status_html = '<span class="status-intact">INTACT</span>'
    else:
        chain_status_html = f'<span class="status-broken">BROKEN AT ENTRY {chain["broken_at_entry"]}</span>'

    # Build Table Rows
    rows_html = ""
    for e in entries:
        # Format columns
        id_str = str(e.get("id", ""))
        event_str = str(e.get("event_type", ""))[:25]
        user_str = str(e.get("user_id", ""))[:32]
        time_str = str(e.get("created_at", ""))[:19].replace("T", " ")
        anomaly_str = str(e.get("anomaly_severity") or "")
        hash_str = str(e.get("entry_hash", ""))[:32] + "..."

        # Apply alert class to the row if it's an anomaly
        row_class = "row-anomaly" if e.get("anomaly_severity") else "row-normal"

        rows_html += f"""
        <tr class="{row_class}">
            <td>{id_str}</td>
            <td>{event_str}</td>
            <td>{user_str}</td>
            <td>{time_str}</td>
            <td>{anomaly_str}</td>
            <td class="hash-cell">{hash_str}</td>
        </tr>
        """

    # HTML Template (Matching the exact OBLVN style)
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            @page {{
                size: A4 landscape;
                margin: 40pt;
                background-color: #1a2218;
                @bottom-left {{
                    content: "OBLVN Platform Audit";
                    font-family: 'Helvetica', sans-serif;
                    color: rgba(240, 235, 224, 0.18);
                    font-size: 8pt;
                    letter-spacing: 1px;
                }}
                @bottom-right {{
                    content: "Page " counter(page) " of " counter(pages);
                    font-family: 'Helvetica', sans-serif;
                    color: rgba(240, 235, 224, 0.18);
                    font-size: 8pt;
                }}
            }}

            body {{
                font-family: 'Courier', monospace;
                color: #f0ebe0;
                margin: 0;
                padding: 0;
            }}

            /* TOP DECORATION STRIPE */
            .top-stripe {{
                position: absolute;
                top: -40pt; left: -40pt; right: -40pt;
                height: 5pt;
                display: flex;
            }}
            .seg-1 {{ flex: 2; background-color: rgba(74,84,66,0.9); }}
            .seg-2 {{ flex: 1; background-color: rgba(240,235,224,0.18); }}
            .seg-3 {{ flex: 3; background-color: rgba(74,84,66,0.55); }}
            .seg-4 {{ flex: 1; background-color: rgba(196,180,138,0.45); }}

            /* BRANDING */
            .brand-block {{
                margin-top: 10pt;
                margin-bottom: 25pt;
            }}
            .brand-name {{
                font-family: 'Playfair Display', serif;
                font-size: 28pt;
                font-weight: bold;
                color: #f0ebe0;
                margin: 0 0 4pt 0;
            }}
            .brand-sub {{
                font-family: 'Helvetica', sans-serif;
                font-size: 7pt;
                color: rgba(118, 128, 101, 1); /* SAGE */
                letter-spacing: 1.5px;
            }}

            /* CHAIN INTEGRITY BLOCK */
            .integrity-block {{
                background-color: #242b21;
                border-left: 2.5pt solid rgba(196, 180, 138, 0.5); /* PARCHMENT */
                padding: 10pt 12pt;
                border-radius: 3pt;
                margin-bottom: 20pt;
                font-size: 8pt;
                color: #768065;
            }}
            .status-intact {{ color: #c4b48a; font-weight: bold; }} /* PARCHMENT */
            .status-broken {{ color: #c44a42; font-weight: bold; }} /* RED ALERT */

            /* TABLE STYLES */
            table {{
                width: 100%;
                border-collapse: collapse;
                table-layout: fixed;
            }}
            thead {{
                display: table-header-group; /* Repeats header on new pages */
            }}
            th {{
                font-family: 'Courier', monospace;
                font-weight: bold;
                font-size: 7.5pt;
                color: #768065;
                text-align: left;
                padding-bottom: 8pt;
                border-bottom: 1px solid #768065;
            }}
            td {{
                font-size: 7.5pt;
                padding: 8pt 0;
                border-bottom: 0.5px solid rgba(240, 235, 224, 0.09);
                vertical-align: top;
            }}
            
            /* ROW HIGHLIGHTS */
            .row-normal td {{
                color: #f0ebe0;
            }}
            .row-anomaly td {{
                color: #c44a42; /* Red-ish alert color */
            }}
            .hash-cell {{
                color: rgba(240, 235, 224, 0.42); /* Dimmer hash */
            }}

            /* COLUMN WIDTHS */
            th:nth-child(1), td:nth-child(1) {{ width: 5%; }}
            th:nth-child(2), td:nth-child(2) {{ width: 20%; }}
            th:nth-child(3), td:nth-child(3) {{ width: 25%; }}
            th:nth-child(4), td:nth-child(4) {{ width: 15%; }}
            th:nth-child(5), td:nth-child(5) {{ width: 10%; }}
            th:nth-child(6), td:nth-child(6) {{ width: 25%; }}

        </style>
    </head>
    <body>
        <div class="top-stripe">
            <div class="seg-1"></div><div class="seg-2"></div><div class="seg-3"></div><div class="seg-4"></div>
        </div>

        <div class="brand-block">
            <h1 class="brand-name">OBLVN</h1>
            <div class="brand-sub">SECURE DATA OBLITERATION PLATFORM &bull; AUDIT LOG EXPORT</div>
        </div>

        <div class="integrity-block">
            Chain Integrity: {chain_status_html} &nbsp;&nbsp;|&nbsp;&nbsp; Total entries: {chain["total_entries"]}
        </div>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>EVENT</th>
                    <th>USER</th>
                    <th>TIMESTAMP (UTC)</th>
                    <th>ANOMALY</th>
                    <th>HASH</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </body>
    </html>
    """

    # WeasyPrint directly returns bytes when `target` is not specified
    return HTML(string=html_content).write_pdf()