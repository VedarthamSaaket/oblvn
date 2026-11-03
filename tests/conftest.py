import os
import tempfile

os.environ["OBLVN_DRY_RUN"] = "1"
os.environ.setdefault("MONGODB_URI", "mongodb://unused-in-tests")
os.environ.setdefault("OBLVN_JWT_SECRET", "test-jwt-secret-that-is-long-enough-1234567890")
os.environ.setdefault("OBLVN_SECRET_KEY", "test-encryption-key-that-is-long-enough-123456")
os.environ.setdefault("FLASK_ENV", "testing")
os.environ.setdefault("OBLVN_LOCAL_OPS", "any")
os.environ.setdefault("OBLVN_DATA_DIR", tempfile.mkdtemp(prefix="oblvn_data_"))
os.environ.setdefault("OBLVN_ML_MODELS", tempfile.mkdtemp(prefix="oblvn_models_"))

import mongomock
import pytest

from backend.db import ServiceClient, set_database
from backend.db.schema import apply_computed, spec


class Tables:
    def __init__(self, db):
        self.db = db

    def _raw(self, name, row):
        doc = apply_computed(name, dict(row))
        key = spec(name).get("key")
        if key and key in doc:
            doc["_id"] = doc.pop(key)
        return doc

    def __setitem__(self, name, rows):
        self.db[name].delete_many({})
        if rows:
            self.db[name].insert_many([self._raw(name, r) for r in rows])

    def __getitem__(self, name):
        key = spec(name).get("key")
        out = []
        for d in self.db[name].find().sort("_id", 1):
            d = dict(d)
            _id = d.pop("_id")
            if key:
                d[key] = _id
            out.append(d)
        return out

    def append(self, name, row):
        self.db[name].insert_one(self._raw(name, row))


class MongoFixture:
    def __init__(self):
        self.db = mongomock.MongoClient(tz_aware=True).oblvn
        set_database(self.db)
        self.tables = Tables(self.db)
        self.svc = ServiceClient(self.db)

    def add_user(self, user_id, email, confirmed=True, password_hash="!unusable:test"):
        self.db.users.insert_one({"_id": user_id, "email": email, "password_hash": password_hash,
                                  "email_confirmed_at": "2026-01-01T00:00:00+00:00" if confirmed else None,
                                  "mfa_enabled": False, "recovery_codes": [], "failed_logins": 0})


@pytest.fixture
def fake_db(monkeypatch):
    from backend import anomaly
    fixture = MongoFixture()
    anomaly._settings_cache.clear()
    yield fixture
    set_database(None, ensure=False)


@pytest.fixture
def models_dir(tmp_path, monkeypatch):
    import ml.feedback
    import ml.paths
    import ml.registry
    import ml.train
    monkeypatch.setattr(ml.paths, "MODELS_DIR", tmp_path)
    monkeypatch.setattr(ml.registry, "MODELS_DIR", tmp_path)
    monkeypatch.setattr(ml.feedback, "MODELS_DIR", tmp_path)
    monkeypatch.setattr(ml.train, "MODELS_DIR", tmp_path)
    ml.registry._cache.clear()
    ml.feedback._cache.clear()
    return tmp_path


@pytest.fixture
def api(fake_db, monkeypatch):
    import backend.auth
    from fastapi.testclient import TestClient

    def validate(token):
        return {"sub": token.split(":", 1)[1], "sid": "test"} if token.startswith("user:") else None
    monkeypatch.setattr(backend.auth, "validate_token", validate)
    from backend.server import app
    with TestClient(app) as client:
        yield client


def bearer(user_id: str) -> dict:
    return {"Authorization": f"Bearer user:{user_id}"}
