import pytest
from unittest.mock import patch, MagicMock
from backend.auth import validate_token, get_user_role, ROLES


def test_roles_hierarchy():
    assert ROLES["org_admin"] > ROLES["team_lead"]
    assert ROLES["team_lead"] > ROLES["operator"]
    assert ROLES["operator"] > ROLES["individual"]


def test_validate_token_invalid_returns_none():
    result = validate_token("not-a-real-token")
    assert result is None


def test_validate_token_expired_returns_none():
    expired = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJ1c2VyLTEyMyIsImV4cCI6MX0."
        "invalid-sig"
    )
    result = validate_token(expired)
    assert result is None


def test_get_user_role_no_org_returns_individual():
    result = get_user_role("user-123", None)
    assert result == "individual"


def test_get_user_role_with_org():
    mock_svc = MagicMock()
    mock_svc.table.return_value.select.return_value.eq.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = {"role": "team_lead"}
    with patch("backend.auth.get_service_client", return_value=mock_svc):
        result = get_user_role("user-123", "org-456")
    assert result == "team_lead"


def test_get_user_role_not_member_returns_individual():
    mock_svc = MagicMock()
    mock_svc.table.return_value.select.return_value.eq.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
    with patch("backend.auth.get_service_client", return_value=mock_svc):
        result = get_user_role("user-123", "org-456")
    assert result == "individual"
