from supabase import Client, create_client
from backend.config import config

_anon: Client | None = None
_service: Client | None = None


def get_anon_client() -> Client:
    global _anon
    if _anon is None:
        _anon = create_client(config.SUPABASE_URL, config.SUPABASE_ANON_KEY)
    return _anon


def get_service_client() -> Client:
    global _service
    if _service is None:
        _service = create_client(
            config.SUPABASE_URL,
            config.SUPABASE_SERVICE_ROLE_KEY,
        )
    return _service


def get_authed_client(access_token: str) -> Client:
    client = create_client(config.SUPABASE_URL, config.SUPABASE_ANON_KEY)
    client.postgrest.auth(access_token)  # ✅ FIXED
    return client