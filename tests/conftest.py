import os
import pytest

os.environ.setdefault("OBLVN_DRY_RUN", "1")
os.environ.setdefault("SUPABASE_URL", "http://localhost:54321")
os.environ.setdefault("SUPABASE_ANON_KEY", "test-anon-key")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-service-key")
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key")
os.environ.setdefault("FLASK_ENV", "testing")


@pytest.fixture
def app():
    from unittest.mock import patch, MagicMock
    mock_supa = MagicMock()
    mock_supa.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value.data = []
    mock_supa.table.return_value.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
    mock_supa.table.return_value.insert.return_value.execute.return_value.data = [{"id": "test-id"}]
    mock_supa.auth.sign_in_with_password.return_value.user.id = "test-user-id"
    mock_supa.auth.sign_in_with_password.return_value.session.access_token = "test-token"
    mock_supa.auth.sign_in_with_password.return_value.session.refresh_token = "test-refresh"

    with patch("backend.supabase_client.get_service_client", return_value=mock_supa), \
         patch("backend.supabase_client.get_anon_client", return_value=mock_supa):
        from backend.server import create_app
        flask_app, _ = create_app()
        flask_app.config["TESTING"] = True
        yield flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-token"}
