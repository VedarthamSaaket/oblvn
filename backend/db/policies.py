RANKS = {"operator": 1, "team_lead": 2, "org_admin": 3}


def org_ids(db, user_id: str, min_rank: int = 1) -> list[str]:
    rows = db["org_memberships"].find({"user_id": user_id}, {"org_id": 1, "role": 1})
    return [r["org_id"] for r in rows if RANKS.get(r.get("role"), 0) >= min_rank]


def _own_or_org(user_id: str, orgs: list[str]) -> dict:
    return {"$or": [{"user_id": user_id}, {"org_id": {"$in": orgs}}]}


def policy(db, name: str, user_id: str) -> dict | None:
    if name == "audit_log":
        return _own_or_org(user_id, org_ids(db, user_id, RANKS["org_admin"]))
    if name in ("wipe_jobs", "anomalies", "org_memberships"):
        return _own_or_org(user_id, org_ids(db, user_id))
    if name == "organisations":
        return {"_id": {"$in": org_ids(db, user_id)}}
    if name == "users":
        return {"_id": user_id}
    return None


DENY_ALL = {"_id": {"$exists": False}}
