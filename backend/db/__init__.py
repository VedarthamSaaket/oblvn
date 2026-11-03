from backend.db.connection import get_database, set_database
from backend.db.policies import DENY_ALL, policy
from backend.db.query import AppendOnly, DuplicateKey, Query, Response, UnsafeValue
from backend.db.schema import ValidationError


class ServiceClient:
    def __init__(self, db):
        self.db = db

    def table(self, name: str) -> Query:
        return Query(self.db, name)


class UserClient:
    def __init__(self, db, user_id: str):
        self.db = db
        self.user_id = user_id

    def table(self, name: str) -> Query:
        rule = policy(self.db, name, self.user_id)
        return Query(self.db, name, base_filter=rule if rule is not None else DENY_ALL, read_only=True)


def get_service_client() -> ServiceClient:
    return ServiceClient(get_database())


def get_user_client(user_id: str) -> UserClient:
    return UserClient(get_database(), user_id)


__all__ = [
    "AppendOnly", "DuplicateKey", "UnsafeValue", "Query", "Response", "ServiceClient", "UserClient", "ValidationError",
    "get_database", "get_service_client", "get_user_client", "set_database",
]
