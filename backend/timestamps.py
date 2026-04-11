import hashlib
import os
from pathlib import Path
from backend.config import config


def _ots_stamp(digest_hex: str, ots_path: Path) -> dict:
    import opentimestamps.calendar
    import opentimestamps.core.timestamp as ots_timestamp
    import opentimestamps.core.op as ots_op
    import opentimestamps.core.serialize as ots_ser
    import binascii

    digest_bytes = binascii.unhexlify(digest_hex)

    file_timestamp = ots_timestamp.DetachedTimestampFile(
        ots_op.OpSHA256(),
        ots_timestamp.Timestamp(digest_bytes),
    )

    calendar_urls = [
        config.OTS_CALENDAR_URL,
        "https://bob.btc.calendar.opentimestamps.org",
        "https://finney.calendar.eternitywall.com",
    ]

    attestations = []
    for url in calendar_urls:
        try:
            calendar = opentimestamps.calendar.RemoteCalendar(url)
            result = calendar.submit(file_timestamp.timestamp)
            attestations.append({"calendar": url, "submitted": True})
        except Exception as exc:
            attestations.append({"calendar": url, "submitted": False, "error": str(exc)})

    with open(ots_path, "wb") as f:
        ctx = ots_ser.StreamSerializationContext(f)
        file_timestamp.serialize(ctx)

    return {
        "ots_file": str(ots_path),
        "attestations": attestations,
        "pending": True,
        "note": (
            "OTS proof is pending Bitcoin block confirmation. "
            "Run 'ots upgrade' on the .ots file after ~1 hour to get the confirmed proof."
        ),
    }


def stamp_certificate(cert_hash_hex: str, cert_id: str) -> dict:
    ots_dir = config.DATA_DIR / "ots"
    ots_dir.mkdir(parents=True, exist_ok=True)
    ots_path = ots_dir / f"{cert_id}.ots"

    try:
        result = _ots_stamp(cert_hash_hex, ots_path)
        result["cert_id"] = cert_id
        result["cert_hash"] = cert_hash_hex
        return result
    except Exception as exc:
        return {
            "cert_id": cert_id,
            "cert_hash": cert_hash_hex,
            "ots_file": None,
            "error": str(exc),
            "pending": False,
        }


def verify_timestamp(ots_path: Path) -> dict:
    try:
        import subprocess
        result = subprocess.run(
            ["ots", "verify", str(ots_path)],
            capture_output=True, text=True, timeout=30,
        )
        return {
            "verified": result.returncode == 0,
            "output": result.stdout + result.stderr,
        }
    except FileNotFoundError:
        return {
            "verified": False,
            "error": "ots command not found. Install with: pip install opentimestamps-client",
        }
    except Exception as exc:
        return {"verified": False, "error": str(exc)}
