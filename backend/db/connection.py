import os
import threading

_lock = threading.Lock()
_db = None


def _open():
    from pymongo import MongoClient
    from backend.config import config
    uri = config.MONGODB_URI or os.environ.get("MONGODB_URI", "")
    if not uri:
        raise RuntimeError("MONGODB_URI is not set; add your MongoDB Atlas connection string to .env")
    from backend.config import mongo_uri_problem
    problem = mongo_uri_problem(uri)
    if problem:
        raise RuntimeError(problem)
    client = MongoClient(uri, tz_aware=True, appname="oblvn", serverSelectionTimeoutMS=10000,
                         retryWrites=True, w="majority")
    return client[config.MONGODB_DB or "oblvn"]


def get_database():
    global _db
    with _lock:
        if _db is None:
            _db = _open()
            from backend.db.schema import ensure_schema
            ensure_schema(_db)
        return _db


def set_database(db, ensure: bool = True) -> None:
    global _db
    with _lock:
        _db = db
    if ensure and db is not None:
        from backend.db.schema import ensure_schema
        ensure_schema(db)
