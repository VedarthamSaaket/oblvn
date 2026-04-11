import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")


class Config:
    SUPABASE_URL: str = os.environ.get("SUPABASE_URL", "")
    SUPABASE_ANON_KEY: str = os.environ.get("SUPABASE_ANON_KEY", "")
    SUPABASE_SERVICE_ROLE_KEY: str = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    SUPABASE_JWT_SECRET: str = os.environ.get("SUPABASE_JWT_SECRET", "")
    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", "dev-key-change-me")
    ENV: str = os.environ.get("FLASK_ENV", "development")
    DEBUG: bool = os.environ.get("FLASK_ENV", "development") == "development"
    DRY_RUN: bool = os.environ.get("OBLVN_DRY_RUN", "0") == "1"
    VERIFY_BASE_URL: str = os.environ.get("OBLVN_VERIFY_BASE_URL", "http://localhost:5173")
    DATA_DIR: Path = Path(os.path.expanduser(os.environ.get("OBLVN_DATA_DIR", "~/.oblvn")))
    OTS_CALENDAR_URL: str = os.environ.get("OTS_CALENDAR_URL", "https://alice.btc.calendar.opentimestamps.org")
    AUTH_RATE_LIMIT: str = os.environ.get("AUTH_RATE_LIMIT", "20") + " per minute"
    ANOMALY_BASELINE_MIN_EVENTS: int = 30

    @classmethod
    def validate(cls) -> list[str]:
        missing = []
        for k in ("SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_JWT_SECRET"):
            if not getattr(cls, k):
                missing.append(k)
        return missing


config = Config()