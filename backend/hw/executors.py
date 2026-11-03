import os
import re
import secrets
import tempfile
import time
from collections.abc import Callable

from backend.hw.capabilities import nvme_controller, parse_hdparm_identify
from backend.hw.model import Capabilities, Disk, Step, WipeError
from backend.hw.runner import Result, ToolError, run

HOUR = 3600


class Context:
    def __init__(self, progress: Callable[[float, str], None], poll_seconds: float = 5.0):
        self.progress = progress
        self.poll_seconds = poll_seconds
        self.commands: list[dict] = []

    def exec(self, cmd: list[str], timeout: float = 120, check: bool = True, secret: str | None = None) -> Result:
        try:
            r = run(cmd, timeout=timeout, check=False)
        except ToolError as exc:
            self.commands.append({"cmd": self._mask(" ".join(cmd), secret), "error": str(exc)})
            raise WipeError(str(exc))
        rec = r.record()
        rec["cmd"] = self._mask(rec["cmd"], secret)
        self.commands.append(rec)
        if check and r.code != 0:
            detail = (r.err or r.out).strip()[:400]
            raise WipeError(f"{self._mask(' '.join(cmd), secret)} failed ({r.code}): {detail}")
        return r

    @staticmethod
    def _mask(text: str, secret: str | None) -> str:
        return text.replace(secret, "****") if secret else text

    def poll(self, status: Callable[[], tuple[str, float]], label: str, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state, pct = status()
            self.progress(pct, label)
            if state == "done":
                return
            if state == "failed":
                raise WipeError(f"{label} reported failure by the drive firmware")
            time.sleep(self.poll_seconds)
        raise WipeError(f"{label} did not finish within {int(timeout / HOUR)}h")


def parse_nvme_sanitize_log(data: dict) -> tuple[str, float]:
    if len(data) == 1:
        inner = next(iter(data.values()))
        if isinstance(inner, dict):
            data = inner
    sstat = int(data.get("sstat", 0) or 0)
    sprog = int(data.get("sprog", 0) or 0)
    state = sstat & 0x7
    if state == 2:
        return "running", round(sprog / 65535 * 100, 2)
    if state in (1, 4):
        return "done", 100.0
    if state == 3:
        return "failed", 0.0
    return "idle", 0.0


def parse_ata_sanitize_status(text: str) -> tuple[str, float]:
    low = text.lower()
    m = re.search(r"\((\d+)%\)", text)
    pct = float(m.group(1)) if m else 0.0
    if "in progress" in low:
        return "running", pct
    if "completed without error" in low:
        return "done", 100.0
    if "failed" in low:
        return "failed", pct
    return "idle", pct


def _idle_guard(status: Callable[[], tuple[str, float]], limit: int = 12):
    seen = {"idle": 0}

    def wrapped() -> tuple[str, float]:
        state, pct = status()
        if state == "idle":
            seen["idle"] += 1
            if seen["idle"] >= limit:
                return "failed", pct
            return "running", pct
        return state, pct
    return wrapped


def nvme_sanitize(disk: Disk, caps: Capabilities, step: Step, ctx: Context) -> None:
    ctrl = nvme_controller(disk.node)
    sanact = {"block": 2, "overwrite": 3, "crypto": 4}[step.params["action"]]
    cmd = ["nvme", "sanitize", ctrl, f"--sanact={sanact}"]
    if sanact == 3:
        cmd += ["--owpass=1", "--ovrpat=0"]
    ctx.exec(cmd, timeout=300)

    def status():
        return parse_nvme_sanitize_log(ctx.exec(["nvme", "sanitize-log", ctrl, "-o", "json"], timeout=60).json())
    ctx.poll(_idle_guard(status), step.name, timeout=48 * HOUR)


def nvme_format(disk: Disk, caps: Capabilities, step: Step, ctx: Context) -> None:
    cmd = ["nvme", "format", disk.node, f"--ses={step.params['ses']}", "--force"]
    r = ctx.exec(cmd, timeout=6 * HOUR, check=False)
    if r.code != 0 and "unrecognized option" in (r.err + r.out):
        r = ctx.exec(cmd[:-1], timeout=6 * HOUR, check=False)
    if r.code != 0:
        raise WipeError(f"nvme format failed ({r.code}): {(r.err or r.out).strip()[:400]}")
    ctx.progress(100.0, step.name)


def ata_sanitize(disk: Disk, caps: Capabilities, step: Step, ctx: Context) -> None:
    flag = {
        "crypto": ["--sanitize-crypto-scramble"],
        "block": ["--sanitize-block-erase"],
        "overwrite": ["--sanitize-overwrite", "hex:00000000"],
    }[step.params["action"]]
    ctx.exec(["hdparm", "--yes-i-know-what-i-am-doing", *flag, disk.node], timeout=300)

    def status():
        return parse_ata_sanitize_status(ctx.exec(["hdparm", "--sanitize-status", disk.node], timeout=60).out)
    ctx.poll(_idle_guard(status), step.name, timeout=72 * HOUR)


def ata_secure_erase(disk: Disk, caps: Capabilities, step: Step, ctx: Context) -> None:
    enhanced = step.params.get("enhanced", False)
    minutes = (caps.ata_enhanced_erase_minutes if enhanced else caps.ata_erase_minutes) or 600
    password = secrets.token_hex(8)
    ctx.exec(["hdparm", "--user-master", "u", "--security-set-pass", password, disk.node],
             timeout=120, secret=password)
    flag = "--security-erase-enhanced" if enhanced else "--security-erase"
    ctx.progress(1.0, f"{step.name} running, drive estimate {minutes} min")
    try:
        ctx.exec(["hdparm", "--user-master", "u", flag, password, disk.node],
                 timeout=minutes * 60 * 2 + HOUR, secret=password)
    except WipeError:
        ctx.exec(["hdparm", "--user-master", "u", "--security-disable", password, disk.node],
                 timeout=120, check=False, secret=password)
        raise
    after = Capabilities()
    parse_hdparm_identify(ctx.exec(["hdparm", "-I", disk.node], timeout=60).out, after)
    if after.ata_security_enabled:
        ctx.exec(["hdparm", "--user-master", "u", "--security-disable", password, disk.node],
                 timeout=120, check=False, secret=password)
        raise WipeError("drive still reports ATA security enabled after erase")
    ctx.progress(100.0, step.name)


def scsi_sanitize(disk: Disk, caps: Capabilities, step: Step, ctx: Context) -> None:
    action = step.params["action"]
    if action == "overwrite":
        fd, pattern = tempfile.mkstemp(prefix="oblvn_pattern_")
        try:
            os.write(fd, bytes(disk.logical_sector))
            os.close(fd)
            ctx.exec(["sg_sanitize", "--quick", "--overwrite", f"--pattern={pattern}", disk.node], timeout=72 * HOUR)
        finally:
            os.unlink(pattern)
    else:
        ctx.exec(["sg_sanitize", "--quick", f"--{action}", disk.node], timeout=72 * HOUR)
    ctx.progress(100.0, step.name)


def sed_psid_revert(disk: Disk, caps: Capabilities, step: Step, ctx: Context, psid: str) -> None:
    ctx.exec(["sedutil-cli", "--yesIreallywanttoERASEALLmydatausingthePSID", psid, disk.node],
             timeout=1800, secret=psid)
    ctx.progress(100.0, step.name)


def remove_hpa(disk: Disk, caps: Capabilities, step: Step, ctx: Context) -> None:
    native = step.params["native_sectors"]
    ctx.exec(["hdparm", "--yes-i-know-what-i-am-doing", "-N", f"p{native}", disk.node], timeout=120)
    ctx.exec(["blockdev", "--rereadpt", disk.node], timeout=60, check=False)
    ctx.progress(100.0, step.name)


def restore_dco(disk: Disk, caps: Capabilities, step: Step, ctx: Context) -> None:
    ctx.exec(["hdparm", "--yes-i-know-what-i-am-doing", "--dco-restore", disk.node], timeout=120)
    ctx.progress(100.0, step.name)


FIRMWARE_EXECUTORS = {
    "nvme_sanitize": nvme_sanitize,
    "nvme_format": nvme_format,
    "ata_sanitize": ata_sanitize,
    "ata_secure_erase": ata_secure_erase,
    "scsi_sanitize": scsi_sanitize,
    "remove_hpa": remove_hpa,
    "restore_dco": restore_dco,
}
