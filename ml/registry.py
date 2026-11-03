import json
import shutil
from datetime import datetime, timezone

import joblib

from ml.paths import MODELS_DIR

_cache: dict[tuple[str, str], tuple[float, dict]] = {}


def _path(scope: str, name: str):
    return MODELS_DIR / scope / f"{name}.joblib"


def save(scope: str, name: str, model, meta: dict) -> dict:
    folder = MODELS_DIR / scope
    folder.mkdir(parents=True, exist_ok=True)
    meta = {**meta, "name": name, "scope": scope, "trained_at": datetime.now(timezone.utc).isoformat()}
    joblib.dump({"model": model, "meta": meta}, _path(scope, name))
    (folder / f"{name}.meta.json").write_text(json.dumps(meta, indent=2, default=str))
    _cache.pop((scope, name), None)
    return meta


def load(scope: str, name: str) -> dict | None:
    path = _path(scope, name)
    if not path.exists():
        return None
    mtime = path.stat().st_mtime
    cached = _cache.get((scope, name))
    if cached and cached[0] == mtime:
        return cached[1]
    bundle = joblib.load(path)
    _cache[(scope, name)] = (mtime, bundle)
    return bundle


def load_scoped(scope: str, name: str) -> dict | None:
    from ml.paths import GLOBAL
    return load(scope, name) or load(GLOBAL, name)


def _archive(scope: str, name: str, tag: str) -> str | None:
    src = _path(scope, name)
    if not src.exists():
        return None
    history = MODELS_DIR / scope / "history"
    history.mkdir(parents=True, exist_ok=True)
    dst = history / f"{name}-{tag}.joblib"
    shutil.move(str(src), dst)
    meta = MODELS_DIR / scope / f"{name}.meta.json"
    if meta.exists():
        shutil.move(str(meta), history / f"{name}-{tag}.meta.json")
    return str(dst)


def _log(scope: str, entry: dict) -> None:
    folder = MODELS_DIR / scope
    folder.mkdir(parents=True, exist_ok=True)
    with open(folder / "promotions.jsonl", "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def promote(scope: str, name: str, model, meta: dict, candidate: float | None, incumbent: float | None,
            metric: str, higher_is_better: bool = True, tolerance: float = 0.01) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if incumbent is None or candidate is None:
        better = True
    elif higher_is_better:
        better = candidate >= incumbent - tolerance
    else:
        better = candidate <= incumbent + tolerance
    decision = {
        "at": stamp, "model": name, "metric": metric, "candidate": candidate, "incumbent": incumbent,
        "tolerance": tolerance, "higher_is_better": higher_is_better,
        "decision": "promoted" if better else "rejected",
    }
    if better:
        decision["archived"] = _archive(scope, name, stamp)
        saved = save(scope, name, model, {**meta, "promotion": decision})
        _log(scope, decision)
        return saved
    history = MODELS_DIR / scope / "history"
    history.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "meta": {**meta, "promotion": decision}}, history / f"{name}-{stamp}-rejected.joblib")
    _log(scope, decision)
    current = load(scope, name)
    return {**(current or {}).get("meta", {}), "promotion": decision}
