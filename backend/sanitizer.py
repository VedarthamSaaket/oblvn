from collections.abc import Generator
from backend.wiper import run_wipe
from backend.crypto_erase import run_crypto_erase
import os


def run_full_sanitization(node: str, standard: str, device_type: str) -> Generator[dict, None, None]:
    """
    For file/folder targets: preserve existing overwrite + crypto_seal logic.
    For hardware devices: skip raw device wipe, use crypto_erase only.
    """

    if device_type == "file":
        # ── FILE / FOLDER PATH ── preserve original logic exactly ──────────
        for event in run_wipe(node, standard, device_type):
            event["phase"] = "overwrite"
            yield event

        crypto_events = []

        def crypto_progress(pct: float, label: str):
            crypto_events.append({
                "phase":        "crypto_seal",
                "pass_num":     1,
                "total_passes": 1,
                "pass_pct":     pct,
                "overall_pct":  pct,
                "label":        label,
            })

        crypto_result = run_crypto_erase(node, progress_cb=crypto_progress)

        for ev in crypto_events:
            yield ev

        yield {
            "type":         "complete",
            "phase":        "full_sanitization",
            "crypto_result": crypto_result,
            "standard":     standard,
            "method":       "full_sanitization",
        }

    else:
        # ── HARDWARE PATH ── crypto-erase only (no raw device access needed) ──
        crypto_events = []

        def crypto_progress(pct: float, label: str):
            crypto_events.append({
                "phase":        "crypto_erase",
                "pass_num":     1,
                "total_passes": 1,
                "pass_pct":     pct,
                "overall_pct":  pct,
                "label":        label,
            })

        crypto_result = run_crypto_erase(node, progress_cb=crypto_progress)

        for ev in crypto_events:
            yield ev

        yield {
            "type":          "complete",
            "phase":         "hardware_sanitization",
            "crypto_result": crypto_result,
            "standard":      standard,
            "method":        "crypto_erase",
        }