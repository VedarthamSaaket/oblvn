import copy

from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import BulkWriteError, DuplicateKeyError

from backend.db.schema import apply_computed, apply_defaults, spec, validate


class DuplicateKey(Exception):
    def __init__(self, message: str):
        super().__init__(f"duplicate key value violates unique constraint (23505): {message}")


class AppendOnly(PermissionError):
    pass


class Response:
    def __init__(self, data, count=None):
        self.data = data
        self.count = count


class _Not:
    def __init__(self, query: "Query"):
        self.query = query

    def is_(self, col: str, value):
        return self.query._add(self.query._field(col), {"$ne": None} if value == "null" else {"$ne": value})


def _public(doc: dict | None, key: str | None) -> dict | None:
    if doc is None:
        return None
    out = {k: v for k, v in doc.items() if k != "_id"}
    if key:
        out[key] = doc["_id"]
    return out


class Query:
    def __init__(self, db, name: str, base_filter: dict | None = None, read_only: bool = False):
        self.db = db
        self.name = name
        self.coll = db[name]
        self.spec = spec(name)
        self.key = self.spec.get("key")
        self.filters: list[dict] = [base_filter] if base_filter else []
        self.read_only = read_only
        self.op = "select"
        self.payload = None
        self.count_mode = None
        self.single = False
        self.sort: list[tuple] = []
        self.limit_n = None
        self.skip_n = 0
        self.not_ = _Not(self)

    def _field(self, col: str) -> str:
        return "_id" if self.key and col == self.key else col

    def _add(self, field: str, cond) -> "Query":
        self.filters.append({field: cond})
        return self

    def select(self, *_columns, count=None):
        self.count_mode = count
        return self

    def insert(self, payload):
        self.op, self.payload = "insert", payload
        return self

    def update(self, payload: dict):
        self.op, self.payload = "update", payload
        return self

    def delete(self):
        self.op = "delete"
        return self

    def eq(self, col, value):
        return self._add(self._field(col), value)

    def neq(self, col, value):
        return self._add(self._field(col), {"$ne": value})

    def is_(self, col, value):
        return self._add(self._field(col), None if value == "null" else value)

    def in_(self, col, values):
        return self._add(self._field(col), {"$in": list(values)})

    def gt(self, col, value):
        return self._add(self._field(col), {"$gt": value})

    def gte(self, col, value):
        return self._add(self._field(col), {"$gte": value})

    def lt(self, col, value):
        return self._add(self._field(col), {"$lt": value})

    def lte(self, col, value):
        return self._add(self._field(col), {"$lte": value})

    def order(self, col, desc: bool = False):
        self.sort.append((self._field(col), DESCENDING if desc else ASCENDING))
        return self

    def limit(self, n: int):
        self.limit_n = n
        return self

    def range(self, start: int, end: int):
        self.skip_n, self.limit_n = start, end - start + 1
        return self

    def maybe_single(self):
        self.single = True
        self.limit_n = 1
        return self

    def _query(self) -> dict:
        if not self.filters:
            return {}
        return self.filters[0] if len(self.filters) == 1 else {"$and": self.filters}

    def _next_id(self) -> int:
        doc = self.db["counters"].find_one_and_update({"_id": self.name}, {"$inc": {"seq": 1}},
                                                       upsert=True, return_document=ReturnDocument.AFTER)
        return int(doc["seq"])

    def _prepare(self, item: dict) -> dict:
        doc = apply_computed(self.name, apply_defaults(self.name, copy.deepcopy(item)))
        validate(self.name, doc)
        if self.spec.get("serial"):
            doc["_id"] = self._next_id()
            doc.pop("id", None)
        elif self.key:
            doc["_id"] = doc.pop(self.key)
        return doc

    def _guard_write(self) -> None:
        if self.read_only:
            raise PermissionError(f"{self.name}: this client is read only")
        if self.spec.get("append_only") and self.op in ("update", "delete"):
            raise AppendOnly(f"{self.name} is append-only; updates and deletes are forbidden")

    def execute(self) -> Response:
        if self.op != "select":
            self._guard_write()
        try:
            return getattr(self, f"_{self.op}")()
        except DuplicateKeyError as exc:
            raise DuplicateKey(str(exc.details or exc)) from exc
        except BulkWriteError as exc:
            errors = (exc.details or {}).get("writeErrors", [])
            if errors and all(e.get("code") == 11000 for e in errors):
                raise DuplicateKey(errors[0].get("errmsg", "E11000")) from exc
            raise

    def _select(self) -> Response:
        cursor = self.coll.find(self._query())
        if self.sort:
            cursor = cursor.sort(self.sort)
        if self.skip_n:
            cursor = cursor.skip(self.skip_n)
        if self.limit_n is not None:
            cursor = cursor.limit(self.limit_n)
        rows = [_public(d, self.key) for d in cursor]
        count = self.coll.count_documents(self._query()) if self.count_mode else None
        if self.single:
            return Response(rows[0] if rows else None, count)
        return Response(rows, count)

    def _insert(self) -> Response:
        items = self.payload if isinstance(self.payload, list) else [self.payload]
        docs = [self._prepare(i) for i in items]
        if docs:
            self.coll.insert_many(docs, ordered=True)
        return Response([_public(d, self.key) for d in docs])

    def _update(self) -> Response:
        changes = copy.deepcopy(self.payload)
        changes.pop(self.key, None) if self.key else None
        validate(self.name, changes, partial=True)
        ids = [d["_id"] for d in self.coll.find(self._query(), {"_id": 1})]
        computed = self.spec.get("computed")
        out = []
        for _id in ids:
            if computed:
                current = self.coll.find_one({"_id": _id}) or {}
                merged = apply_computed(self.name, {**current, **changes})
                sets = {k: merged[k] for k in list(changes) + list(computed) if k in merged}
                unsets = {k: "" for k in computed if k not in merged}
                update = {"$set": sets}
                if unsets:
                    update["$unset"] = unsets
            else:
                update = {"$set": changes}
            doc = self.coll.find_one_and_update({"_id": _id}, update, return_document=ReturnDocument.AFTER)
            if doc:
                out.append(_public(doc, self.key))
        return Response(out)

    def _delete(self) -> Response:
        q = self._query()
        docs = list(self.coll.find(q))
        if docs:
            self.coll.delete_many({"_id": {"$in": [d["_id"] for d in docs]}})
        return Response([_public(d, self.key) for d in docs])
