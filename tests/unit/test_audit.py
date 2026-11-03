from backend import audit


def test_chain_appends_and_verifies(fake_db):
    for i in range(5):
        audit.log_event("evt", {"i": i}, user_id=None)
    audit.log_event("org_evt", {"i": 1}, user_id=None, org_id="11111111-1111-1111-1111-111111111111")
    assert audit.verify_chain(None) == {"intact": True, "total_entries": 5, "broken_at_entry": None}
    assert audit.verify_chain("11111111-1111-1111-1111-111111111111")["intact"]


def test_chain_detects_tampering(fake_db):
    for i in range(3):
        audit.log_event("evt", {"i": i}, user_id=None)
    fake_db.tables["audit_log"][1]["event_payload"] = '{"i": 99}'
    result = audit.verify_chain(None)
    assert not result["intact"] and result["broken_at_entry"] == 1


def test_fork_is_retried_on_unique_violation(fake_db, monkeypatch):
    audit.log_event("first", {}, user_id=None)
    real = audit._get_last_hash
    calls = {"n": 0}

    def stale(org_id):
        calls["n"] += 1
        return audit.GENESIS_HASH if calls["n"] == 1 else real(org_id)
    monkeypatch.setattr(audit, "_get_last_hash", stale)
    audit.log_event("second", {}, user_id=None)
    assert len(fake_db.tables["audit_log"]) == 2
    assert audit.verify_chain(None)["intact"]


def test_verify_pages_past_one_thousand(fake_db, monkeypatch):
    monkeypatch.setattr(audit, "PAGE_SIZE", 7)
    for i in range(20):
        audit.log_event("evt", {"i": i}, user_id=None)
    assert audit.verify_chain(None)["total_entries"] == 20


def test_exports_are_scoped(fake_db):
    audit.log_event("mine", {}, user_id="22222222-2222-2222-2222-222222222222")
    audit.log_event("theirs", {}, user_id="33333333-3333-3333-3333-333333333333")
    rows = audit.export_json(None, None, None, user_id="22222222-2222-2222-2222-222222222222")
    assert [r["event_type"] for r in rows] == ["mine"]
