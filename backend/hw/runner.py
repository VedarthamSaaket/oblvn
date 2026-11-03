import json
import shutil
import subprocess
from dataclasses import dataclass


class ToolError(RuntimeError):
    pass


@dataclass
class Result:
    cmd: list[str]
    code: int
    out: str
    err: str

    def json(self) -> dict:
        text = self.out.strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}

    def record(self) -> dict:
        return {
            "cmd": " ".join(self.cmd),
            "exit_code": self.code,
            "stdout": self.out[-4000:],
            "stderr": self.err[-2000:],
        }


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run(cmd: list[str], timeout: float = 60, check: bool = False) -> Result:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise ToolError(f"{cmd[0]} is not installed")
    except subprocess.TimeoutExpired:
        raise ToolError(f"{' '.join(cmd)} timed out after {int(timeout)}s")
    result = Result(cmd, proc.returncode, proc.stdout or "", proc.stderr or "")
    if check and result.code != 0:
        detail = (result.err or result.out).strip()[:500]
        raise ToolError(f"{' '.join(cmd)} failed with exit code {result.code}: {detail}")
    return result


def tool_version(tool: str, flag: str = "--version") -> str | None:
    if not have(tool):
        return None
    try:
        r = run([tool, flag], timeout=10)
    except ToolError:
        return None
    line = (r.out or r.err).strip().splitlines()
    return line[0][:120] if line else None
