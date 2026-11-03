import json
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
