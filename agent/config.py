import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_PATH = Path(os.environ.get("OBLVN_AGENT_CONFIG", "/etc/oblvn-agent/agent.json"))
SPOOL_DIR = Path(os.environ.get("OBLVN_AGENT_SPOOL", "/var/lib/oblvn-agent/pending"))


@dataclass
class AgentConfig:
    server: str
    agent_id: str
    token: str
    name: str = ""
    ca_bundle: str | None = None

    def save(self, path: Path = DEFAULT_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(asdict(self), f, indent=2)
        os.replace(tmp, path)


def load(path: Path = DEFAULT_PATH) -> AgentConfig | None:
    if not path.exists():
        return None
    return AgentConfig(**json.loads(path.read_text()))
