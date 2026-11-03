import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODELS_DIR = Path(os.environ.get("OBLVN_ML_MODELS", str(ROOT / "models")))
DATA_DIR = Path(os.environ.get("OBLVN_ML_DATA", str(ROOT / "data")))
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
GLOBAL = "global"


def scope_name(org_id: str | None) -> str:
    return org_id or "individual"
