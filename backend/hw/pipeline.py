import platform
import queue
import socket
import threading
import time
from collections.abc import Callable, Generator
from datetime import datetime, timezone

from backend.hw import capabilities, executors, inventory, preflight, smart, verify
from backend.hw.keystream import Keystream, source_for
from backend.hw.model import Cancelled, Capabilities, Disk, Plan, PlanError, Step, WipeError
from backend.hw.overwrite import overwrite_pass
from backend.hw.patterns import passes_for
from backend.hw.planner import plan as make_plan
from backend.hw.runner import tool_version

SYSTEM = platform.system()
_DONE = object()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulated_caps(disk: Disk) -> Capabilities:
    caps = Capabilities(notes=["simulated capabilities (dry run)"])
    if disk.device_type == "nvme":
        caps.nvme_sanitize = ["crypto", "block"]
        caps.nvme_format = caps.nvme_format_crypto = True
    elif disk.device_type == "ssd":
        caps.ata_security = caps.ata_enhanced_erase = True
        caps.ata_sanitize = ["crypto", "block"]
    elif disk.device_type == "hdd":
        caps.ata_security = caps.ata_enhanced_erase = True
        caps.ata_sanitize = ["overwrite"]
    return caps


def tool_versions() -> dict:
    return {
        "nvme": tool_version("nvme", "version"),
        "hdparm": tool_version("hdparm", "-V"),
        "smartctl": tool_version("smartctl", "--version"),
        "sg_sanitize": tool_version("sg_sanitize", "--version"),
        "sedutil-cli": tool_version("sedutil-cli", "--version"),
    }


class _Progress:
    def __init__(self, emit: Callable[[dict], None], steps: list[Step]):
        self.emit = emit
        self.steps = steps
        self.total = sum(s.weight for s in steps) or 1.0
        self.done = 0.0
        self.index = 0
        self.last = 0.0

    def start(self, index: int) -> None:
        self.index = index
        self.done = sum(s.weight for s in self.steps[:index])

    def update(self, pct: float, label: str, force: bool = False) -> None:
        now = time.monotonic()
        if not force and pct < 100 and now - self.last < 0.5:
            return
        self.last = now
        step = self.steps[self.index]
        overall = (self.done + step.weight * min(pct, 100) / 100) / self.total * 100
        self.emit({
            "type": "progress",
            "phase": step.kind,
            "pass_num": self.index + 1,
            "total_passes": len(self.steps),
            "pass_pct": round(pct, 2),
            "overall_pct": round(min(overall, 99.9), 2),
            "label": label,
        })


class _Runner:
    def __init__(self, disk: Disk, method: str, standard: str, options: dict,
                 cancel_check: Callable[[], None], emit: Callable[[dict], None], dry_run: bool):
        self.disk = disk
        self.method = method
        self.standard = standard
        self.options = options
        self.cancel_check = cancel_check
        self.emit = emit
        self.dry_run = dry_run
        self.record: dict = {
            "platform": SYSTEM,
            "hostname": socket.gethostname(),
            "dry_run": dry_run,
            "method": method,
            "standard": standard,
            "started_at": _now(),
            "steps": [],
        }
        self.last_source = None
        self.keystreams: list[Keystream] = []

    def _plan(self, caps: Capabilities) -> Plan:
        return make_plan(self.disk, caps, self.method, self.standard, self.options,
                         firmware_allowed=self.dry_run or SYSTEM == "Linux")

    def execute(self) -> dict:
        started = time.monotonic()
        if self.dry_run:
            caps = simulated_caps(self.disk)
            node = self.disk.node
            size = self.disk.size_bytes
        elif SYSTEM == "Windows":
            from backend.hw import windows
            self.disk, cleared = windows.prepare(self.disk)
            self.record["unmount"] = cleared
            caps = Capabilities(notes=["firmware sanitize is not driven from Windows; use the OBLVN Linux agent"])
            node = self.disk.node
            size = self.disk.size_bytes
            self.record["smart_before"] = smart.snapshot(self.disk.node)
        else:
            self.disk, unmounts = preflight.check(self.disk.node)
            self.record["unmount"] = unmounts
            caps = capabilities.probe(self.disk)
            node = inventory.raw_node(self.disk)
            size = inventory.exact_size(self.disk)
            self.record["smart_before"] = smart.snapshot(self.disk.node)
            self.record["tool_versions"] = tool_versions()
        self.record["device"] = self.disk.to_dict()
        self.record["capabilities"] = caps.to_dict()
        plan = self._plan(caps)
        self.record["plan"] = plan.to_dict()
        self.record["technique"] = plan.technique
        self.record["nist_category"] = plan.nist_category
        offsets = verify.sample_offsets(size)
        before = None if self.dry_run else verify.snapshot(node, size, offsets)
        progress = _Progress(self.emit, plan.steps)
        bytes_written = 0
        overwrite_seconds = 0.0
        firmware_seconds = 0.0
        passes_done = 0
        verification = None
        try:
            for i, step in enumerate(plan.steps):
                self.cancel_check()
                progress.start(i)
                progress.update(0.0, step.name, force=True)
                t0 = time.monotonic()
                entry = {"name": step.name, "kind": step.kind, "started_at": _now(), "params": step.params}
                ctx = executors.Context(lambda pct, label: progress.update(pct, label))
                if self.dry_run:
                    result = self._simulate(step, progress)
                elif step.kind == "overwrite":
                    result = self._overwrite(node, size, step, progress)
                    bytes_written += result["bytes"]
                    overwrite_seconds += result["seconds"]
                elif step.kind == "verify":
                    result = self._verify(node, size, step, offsets, before)
                elif step.kind == "sed_psid_revert":
                    executors.sed_psid_revert(self.disk, caps, step, ctx, self.options["psid"])
                    result = {}
                else:
                    executors.FIRMWARE_EXECUTORS[step.kind](self.disk, caps, step, ctx)
                    result = {}
                    if step.kind in ("remove_hpa", "restore_dco") and SYSTEM == "Linux":
                        size = inventory.exact_size(self.disk)
                if step.kind == "verify":
                    verification = result
                elapsed = time.monotonic() - t0
                if step.kind not in ("overwrite", "verify"):
                    firmware_seconds += elapsed
                if step.kind != "verify":
                    passes_done += 1
                entry.update({"seconds": round(elapsed, 3), "ok": True, "commands": ctx.commands, "result": result})
                self.record["steps"].append(entry)
                progress.update(100.0, step.name, force=True)
                if step.kind == "verify" and result.get("passed") is False:
                    raise WipeError("read-back verification failed", self.record)
        except Cancelled:
            self._fail_step("cancelled")
            raise
        except WipeError as exc:
            self._fail_step(str(exc))
            exc.record = self.record
            raise
        except Exception as exc:
            self._fail_step(str(exc))
            raise WipeError(str(exc), self.record)
        finally:
            for ks in self.keystreams:
                ks.destroy()
        total = time.monotonic() - started
        if not self.dry_run and SYSTEM != "Windows":
            self.record["smart_after"] = smart.snapshot(self.disk.node)
        self.record["verification"] = verification
        self.record["passes_completed"] = passes_done
        self.record["telemetry"] = {
            "size_bytes": size,
            "bytes_written": bytes_written,
            "overwrite_seconds": round(overwrite_seconds, 3),
            "firmware_seconds": round(firmware_seconds, 3),
            "total_seconds": round(total, 3),
            "throughput_mbps": round(bytes_written / 1e6 / overwrite_seconds, 2) if overwrite_seconds > 0 else None,
            "overwrite_passes": sum(1 for s in plan.steps if s.kind == "overwrite"),
        }
        self.record["keys_destroyed"] = all(ks.destroyed for ks in self.keystreams)
        self.record["finished_at"] = _now()
        return self.record

    def _fail_step(self, message: str) -> None:
        self.record["error"] = message
        self.record["finished_at"] = _now()

    def _overwrite(self, node: str, size: int, step: Step, progress: _Progress) -> dict:
        p = passes_for(step.params["standard"])[step.params["index"]]
        source, ks = source_for(p)
        if ks:
            self.keystreams.append(ks)
        self.last_source = source
        result = overwrite_pass(node, size, source, lambda pct, _w: progress.update(pct, step.name), self.cancel_check)
        result["pattern"] = p["pattern"]
        return result

    def _verify(self, node: str, size: int, step: Step, offsets: list[int], before: dict | None) -> dict:
        if step.params["check"] == "pattern":
            if self.last_source is None:
                raise WipeError("pattern verification requested without an overwrite pass")
            return verify.check_pattern(node, size, None if step.params["mode"] == "full" else offsets, self.last_source)
        return verify.check_changed(node, size, before or {})

    def _simulate(self, step: Step, progress: _Progress) -> dict:
        for pct in range(0, 101, 10):
            self.cancel_check()
            time.sleep(0.03)
            progress.update(float(pct), f"[DRY RUN] {step.name}", force=True)
        if step.kind == "verify":
            return {"check": step.params["check"], "mode": step.params["mode"], "simulated": True, "passed": True}
        return {"simulated": True}


def run(disk: Disk, method: str, standard: str, options: dict | None = None,
        cancel_check: Callable[[], None] | None = None, dry_run: bool = False) -> Generator[dict, None, None]:
    events: queue.Queue = queue.Queue()
    outcome: dict = {}
    runner = _Runner(disk, method, standard, options or {}, cancel_check or (lambda: None), events.put, dry_run)

    def work():
        try:
            outcome["record"] = runner.execute()
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            events.put(_DONE)

    threading.Thread(target=work, name="oblvn-wipe", daemon=True).start()
    while True:
        ev = events.get()
        if ev is _DONE:
            break
        yield ev
    if "error" in outcome:
        raise outcome["error"]
    record = outcome["record"]
    yield {
        "type": "complete",
        "ok": True,
        "record": record,
        "technique": record["technique"],
        "nist_category": record["nist_category"],
        "passes_completed": record["passes_completed"],
        "verification_passed": (record.get("verification") or {}).get("passed"),
        "standard": standard,
    }


__all__ = ["run", "Cancelled", "PlanError", "WipeError"]
