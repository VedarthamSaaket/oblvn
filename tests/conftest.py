import os
import tempfile

os.environ["OBLVN_DRY_RUN"] = "1"
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_ANON_KEY", "test-anon-key")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-service-key")
os.environ.setdefault("SUPABASE_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FLASK_ENV", "testing")
os.environ.setdefault("OBLVN_DATA_DIR", tempfile.mkdtemp(prefix="oblvn_data_"))
os.environ.setdefault("OBLVN_ML_MODELS", tempfile.mkdtemp(prefix="oblvn_models_"))

import pytest

from tests.fakes import FakeSupabase


@pytest.fixture
def fake_db(monkeypatch):
    import backend.supabase_client as sc
    from backend import anomaly
    db = FakeSupabase()
    monkeypatch.setattr(sc, "_service", db)
    monkeypatch.setattr(sc, "_anon", db)
    anomaly._settings_cache.clear()
    return db


@pytest.fixture
def models_dir(tmp_path, monkeypatch):
    import ml.feedback
    import ml.paths
    import ml.registry
    import ml.train
    monkeypatch.setattr(ml.paths, "MODELS_DIR", tmp_path)
    monkeypatch.setattr(ml.train, "MODELS_DIR", tmp_path)
    monkeypatch.setattr(ml.registry, "MODELS_DIR", tmp_path)
    monkeypatch.setattr(ml.feedback, "MODELS_DIR", tmp_path)
    ml.registry._cache.clear()
    ml.feedback._cache.clear()
    return tmp_path


@pytest.fixture
def api(fake_db, monkeypatch):
    import backend.auth
    from fastapi.testclient import TestClient

    def validate(token):
        return {"sub": token.split(":", 1)[1]} if token.startswith("user:") else None
    monkeypatch.setattr(backend.auth, "validate_token", validate)
    from backend.server import app
    with TestClient(app) as client:
        yield client


def bearer(user_id: str) -> dict:
    return {"Authorization": f"Bearer user:{user_id}"}
