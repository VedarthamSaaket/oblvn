import re
from pathlib import Path

import mongomock
import pytest

from backend.db import DuplicateKey, ServiceClient
from backend.db.schema import ensure_schema

ROOT = Path(__file__).resolve().parents[2]


def test_security_headers_middleware_does_not_crash_responses(api):
    assert api.get("/api/health").status_code == 200


def test_dry_run_records_verification():
    from backend.hw import pipeline
    from backend.hw.model import Disk
    disk = Disk(node="/dev/sim", name="sim", serial="S", model="M", size_bytes=10 ** 9, logical_sector=512,
                transport="nvme", rotational=False, removable=False, device_type="nvme", is_system=False,
                system_reason=None)
    done = list(pipeline.run(disk, "crypto_erase", "nist_800_88", dry_run=True))[-1]
    assert done["verification_passed"] is True and done["record"]["verification"]["passed"] is True


def test_insert_many_duplicates_map_to_duplicate_key():
    db = mongomock.MongoClient().r
    ensure_schema(db)
    svc = ServiceClient(db)
    svc.table("users").insert({"email": "a@b.io", "password_hash": "x"}).execute()
    with pytest.raises(DuplicateKey):
        svc.table("users").insert([{"email": "a@b.io", "password_hash": "y"}]).execute()


def test_partial_indexes_survive_index_creation():
    db = mongomock.MongoClient().r
    ensure_schema(db)
    partial = [i for i in db.anomalies.index_information().values() if i.get("partialFilterExpression")]
    assert partial and partial[0]["unique"]


def test_connection_reads_uri_through_config(monkeypatch):
    from backend.db import connection
    import backend.config as cfg
    seen = {}

    class FakeClient:
        def __init__(self, uri, **kw):
            seen["uri"] = uri

        def __getitem__(self, name):
            seen["db"] = name
            return mongomock.MongoClient().x
    monkeypatch.delenv("MONGODB_URI", raising=False)
    monkeypatch.setattr(cfg.config, "MONGODB_URI", "mongodb+srv://u:p@example.mongodb.net/")
    monkeypatch.setattr(cfg.config, "MONGODB_DB", "oblvn_reg")
    monkeypatch.setattr("pymongo.MongoClient", FakeClient)
    connection._open()
    assert seen == {"uri": "mongodb+srv://u:p@example.mongodb.net/", "db": "oblvn_reg"}


def test_requirements_have_one_pinned_package_per_line():
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        if line.strip():
            assert re.fullmatch(r"[A-Za-z0-9_.\-]+(\[[a-z,]+\])?==[0-9][A-Za-z0-9.\-]*", line.strip()), line


def test_select_columns_do_not_return_other_fields():
    db = mongomock.MongoClient().r
    ensure_schema(db)
    svc = ServiceClient(db)
    svc.table("agents").insert({"user_id": "u", "name": "a", "token_hash": "secret"}).execute()
    assert "token_hash" not in svc.table("agents").select("id,name").execute().data[0]


def test_broadcast_without_bound_loop_is_safe():
    from backend import realtime
    realtime.bind_loop(None)
    realtime.broadcast("job", {"type": "progress"})


def test_production_build_uses_the_app_base_path():
    config = (ROOT / "frontend" / "vite.config.js").read_text()
    assert "command === 'build' ? '/app/' : '/'" in config


def test_websocket_url_is_derived_not_hardcoded():
    api_js = (ROOT / "frontend" / "src" / "lib" / "api.js").read_text()
    job = (ROOT / "frontend" / "src" / "pages" / "JobDetail.jsx").read_text()
    assert "ws://localhost:8000" not in job and "WS_BASE" in job and "new URL(BASE, window.location.origin)" in api_js


def test_docker_does_not_publish_the_app_port_or_copy_secrets():
    compose = (ROOT / "docker" / "docker-compose.yml").read_text()
    ignore = (ROOT / ".dockerignore").read_text().splitlines()
    assert '"5173:5173"' not in compose and "expose:" in compose
    assert ".env" in ignore and "ml/data" in ignore


def test_approve_requires_pending_status(api, fake_db):
    from tests.conftest import bearer
    user, org, job = "99999999-0000-0000-0000-000000000001", "99999999-0000-0000-0000-000000000002", "99999999-0000-0000-0000-000000000003"
    fake_db.tables["org_memberships"] = [{"id": "m", "user_id": user, "org_id": org, "role": "team_lead"}]
    fake_db.tables["wipe_jobs"] = [{"id": job, "org_id": org, "status": "completed", "agent_id": None}]
    assert api.post(f"/api/jobs/{job}/approve", headers=bearer(user), json={"org_id": org}).status_code == 409


def test_server_validators_never_require_a_field_that_becomes_the_id():
    from backend.db.schema import COLLECTIONS, json_schema
    for name, spec in COLLECTIONS.items():
        if name == "counters":
            continue
        required = json_schema(name)["$jsonSchema"].get("required", [])
        if spec.get("key"):
            assert spec["key"] not in required or spec["key"] == "_id", name
