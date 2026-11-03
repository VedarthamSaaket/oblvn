import threading
import time
import traceback

from agent.client import AgentClient
from backend.detector import DeviceDetectionError, detect_devices
from backend.hw import pipeline
from backend.hw.inventory import from_device
from backend.hw.model import Cancelled, WipeError

HEARTBEAT_SECONDS = 30
POLL_SECONDS = 5
PROGRESS_SECONDS = 1.0


def inventory() -> list[dict]:
    try:
        return detect_devices()
    except DeviceDetectionError as exc:
        print(f"[agent] {exc}")
        return []


def execute(client: AgentClient, job: dict, dry_run: bool = False) -> None:
    job_id = job["id"]
    device = job.get("device") or {}
    if not device.get("node"):
        client.result(job_id, {"ok": False, "error": "device is not attached to this agent anymore"})
        return
    cancel = threading.Event()

    def check() -> None:
        if cancel.is_set():
            raise Cancelled("cancelled by operator")

    last = 0.0
    print(f"[agent] job {job_id}: {job['method']} {job['standard']} on {device['node']}")
    try:
        for ev in pipeline.run(from_device(device), job["method"], job["standard"],
                               job.get("options") or {}, check, dry_run=dry_run):
            if ev.get("type") == "complete":
                client.result(job_id, {"ok": True, "record": ev["record"]})
                print(f"[agent] job {job_id} complete")
                return
            now = time.monotonic()
            if now - last >= PROGRESS_SECONDS or ev.get("pass_pct", 0) >= 100:
                last = now
                if client.progress(job_id, ev):
                    cancel.set()
    except Cancelled:
        client.result(job_id, {"ok": False, "cancelled": True})
        print(f"[agent] job {job_id} cancelled")
    except WipeError as exc:
        client.result(job_id, {"ok": False, "error": str(exc), "record": exc.record})
        print(f"[agent] job {job_id} failed: {exc}")
    except Exception as exc:
        traceback.print_exc()
        client.result(job_id, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def run(client: AgentClient, dry_run: bool = False, once: bool = False) -> None:
    last_beat = 0.0
    while True:
        try:
            client.flush_spool()
            if time.monotonic() - last_beat >= HEARTBEAT_SECONDS:
                client.heartbeat(inventory())
                last_beat = time.monotonic()
            job = client.next_job()
            if job:
                execute(client, job, dry_run)
                last_beat = 0.0
        except Exception as exc:
            print(f"[agent] loop error: {exc}")
        if once:
            return
        time.sleep(POLL_SECONDS)
