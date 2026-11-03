import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw in (None, "") else raw.strip().lower() in ("1", "true", "yes", "on")


class Config:
    MONGODB_URI: str = os.environ.get("MONGODB_URI", "")
    MONGODB_DB: str = os.environ.get("MONGODB_DB", "oblvn")
    JWT_SECRET: str = os.environ.get("OBLVN_JWT_SECRET", "")
    SECRET_KEY: str = os.environ.get("OBLVN_SECRET_KEY", "")
    ACCESS_TOKEN_TTL: int = int(os.environ.get("OBLVN_ACCESS_TOKEN_TTL", "900"))
    REFRESH_TOKEN_TTL: int = int(os.environ.get("OBLVN_REFRESH_TOKEN_TTL", str(30 * 24 * 3600)))
    LOCKOUT_THRESHOLD: int = int(os.environ.get("OBLVN_LOCKOUT_THRESHOLD", "10"))
    LOCKOUT_MINUTES: int = int(os.environ.get("OBLVN_LOCKOUT_MINUTES", "15"))
    SMTP_HOST: str = os.environ.get("SMTP_HOST", "")
    SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER: str = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM: str = os.environ.get("SMTP_FROM", "")
    SMTP_FROM_NAME: str = os.environ.get("SMTP_FROM_NAME", "OBLVN")
    SMTP_STARTTLS: bool = _bool("SMTP_STARTTLS", True)
    SMTP_SSL: bool = _bool("SMTP_SSL", False)
    REQUIRE_EMAIL_VERIFICATION: bool = _bool("OBLVN_REQUIRE_EMAIL_VERIFICATION", bool(os.environ.get("SMTP_HOST")))
    FIREBASE_PROJECT_ID: str = os.environ.get("FIREBASE_PROJECT_ID", "")
    COOKIE_SECURE: bool = _bool("OBLVN_COOKIE_SECURE", (os.environ.get("FLASK_ENV") or "production").strip().lower() == "production")
    LOCAL_OPS: str = os.environ.get("OBLVN_LOCAL_OPS", "loopback").strip().lower()
    ENV: str = (os.environ.get("FLASK_ENV") or "production").strip().lower()
    DEBUG: bool = (os.environ.get("FLASK_ENV") or "production").strip().lower() == "development"
    DRY_RUN: bool = os.environ.get("OBLVN_DRY_RUN", "0") == "1"
    VERIFY_BASE_URL: str = os.environ.get("OBLVN_VERIFY_BASE_URL", "http://localhost:5173")
    PUBLIC_URL: str = os.environ.get("OBLVN_PUBLIC_URL", os.environ.get("OBLVN_VERIFY_BASE_URL", "http://localhost:5173"))
    DATA_DIR: Path = Path(os.path.expanduser(os.environ.get("OBLVN_DATA_DIR", "~/.oblvn")))
    OTS_CALENDAR_URL: str = os.environ.get("OTS_CALENDAR_URL", "https://alice.btc.calendar.opentimestamps.org")
    AUTH_RATE_LIMIT: str = os.environ.get("AUTH_RATE_LIMIT", "20") + " per minute"
    ANOMALY_BASELINE_MIN_EVENTS: int = 30

    @classmethod
    def validate(cls) -> list[str]:
        problems = []
        if not cls.MONGODB_URI:
            problems.append("MONGODB_URI (MongoDB Atlas connection string)")
        if len(cls.JWT_SECRET) < 32:
            problems.append("OBLVN_JWT_SECRET (at least 32 random characters)")
        if len(cls.SECRET_KEY) < 32:
            problems.append("OBLVN_SECRET_KEY (at least 32 random characters)")
        if cls.SMTP_HOST and not cls.SMTP_FROM:
            problems.append("SMTP_FROM (sender address, needed when SMTP_HOST is set)")
        return problems


config = Config()
