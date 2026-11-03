import copy
import itertools
import uuid
from types import SimpleNamespace


class Response:
    def __init__(self, data, count=None):
        self.data = data
        self.count = count


class _Not:
    def __init__(self, query):
        self.query = query

    def is_(self, col, value):
        self.query.filters.append(lambda r: not _is(r.get(col), value))
        return self.query


def _is(v, value):
    return v is None if value == "null" else v == value


def _sort_key(value):
    if value is None:
        return (2, 0, "")
    if isinstance(value, (int, float)):
        return (0, value, "")
    return (1, 0, str(value))


class Query:
    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.filters = []
        self.op = "select"
        self.payload = None
        self.count = None
        self.single = False
        self.order_by = []
        self.limit_n = None
        self.range_ = None
        self.not_ = _Not(self)

    def select(self, *_cols, count=None):
        self.count = count
        return self

    def insert(self, payload):
        self.op, self.payload = "insert", payload
        return self

    def update(self, payload):
        self.op, self.payload = "update", payload
        return self

    def delete(self):
        self.op = "delete"
        return self

    def eq(self, col, v):
        self.filters.append(lambda r: r.get(col) == v)
        return self

    def neq(self, col, v):
        self.filters.append(lambda r: r.get(col) != v)
        return self

    def is_(self, col, v):
        self.filters.append(lambda r: _is(r.get(col), v))
        return self

    def in_(self, col, values):
        values = list(values)
        self.filters.append(lambda r: r.get(col) in values)
        return self

    def gte(self, col, v):
        self.filters.append(lambda r: r.get(col) is not None and str(r.get(col)) >= str(v))
        return self

    def lte(self, col, v):
        self.filters.append(lambda r: r.get(col) is not None and str(r.get(col)) <= str(v))
        return self

    def lt(self, col, v):
        self.filters.append(lambda r: r.get(col) is not None and str(r.get(col)) < str(v))
        return self

    def order(self, col, desc=False):
        self.order_by.append((col, desc))
        return self

    def limit(self, n):
        self.limit_n = n
        return self

    def range(self, start, end):
        self.range_ = (start, end)
        return self

    def maybe_single(self):
        self.single = True
        return self

    def _rows(self):
        return self.db.tables.setdefault(self.name, [])

    def _match(self):
        return [r for r in self._rows() if all(f(r) for f in self.filters)]

    def execute(self):
        if self.op == "insert":
            items = self.payload if isinstance(self.payload, list) else [self.payload]
            out = []
            for item in items:
                row = copy.deepcopy(item)
                self.db.before_insert(self.name, row)
                self._rows().append(row)
                out.append(copy.deepcopy(row))
            return Response(out)
        if self.op == "update":
            rows = self._match()
            for r in rows:
                r.update(copy.deepcopy(self.payload))
            return Response([copy.deepcopy(r) for r in rows])
        if self.op == "delete":
            rows = self._match()
            self.db.tables[self.name] = [r for r in self._rows() if r not in rows]
            return Response(rows)
        rows = [copy.deepcopy(r) for r in self._match()]
        for col, desc in reversed(self.order_by):
            rows.sort(key=lambda r: _sort_key(r.get(col)), reverse=desc)
        total = len(rows)
        if self.range_:
            rows = rows[self.range_[0]:self.range_[1] + 1]
        if self.limit_n is not None:
            rows = rows[:self.limit_n]
        if self.single:
            return Response(rows[0] if rows else None)
        return Response(rows, count=total if self.count else None)


class FakeSupabase:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {}
        self._ids = itertools.count(1)
        self.users: dict[str, str] = {}
        self.auth = SimpleNamespace(admin=SimpleNamespace(get_user_by_id=self._get_user))

    def _get_user(self, user_id):
        email = self.users.get(user_id)
        return SimpleNamespace(user=SimpleNamespace(id=user_id, email=email) if email else None)

    def before_insert(self, name, row):
        if name == "audit_log":
            row.setdefault("id", next(self._ids))
            row["chain_key"] = row.get("org_id") or "global"
            for other in self.tables.get(name, []):
                if other.get("chain_key") == row["chain_key"] and other.get("prev_entry_hash") == row["prev_entry_hash"]:
                    raise Exception("duplicate key value violates unique constraint (23505)")
        elif name == "anomalies":
            row.setdefault("id", str(uuid.uuid4()))
            if row.get("dedupe_key"):
                for other in self.tables.get(name, []):
                    if other.get("dedupe_key") == row["dedupe_key"] and other.get("status") in ("open", "acknowledged"):
                        raise Exception("duplicate key value violates unique constraint (23505)")
        else:
            row.setdefault("id", str(uuid.uuid4()))

    def table(self, name):
        return Query(self, name)
