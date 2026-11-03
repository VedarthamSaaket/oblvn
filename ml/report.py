import argparse
import json
from collections import Counter, defaultdict
from datetime import date, datetime, timezone

from ml import datasource, registry
from ml.paths import GLOBAL, MODELS_DIR, scope_name

REPORTS_DIR = MODELS_DIR / "reports"
MODEL_NAMES = ("wipe_duration", "behaviour_jobs", "behaviour_logins", "drive_health")


def _previous_month(today: date) -> str:
    first = today.replace(day=1)
    prev = first.replace(year=first.year - 1, month=12) if first.month == 1 else first.replace(month=first.month - 1)
    return prev.strftime("%Y-%m")


def _anomalies(org_id: str | None, month: str, user_id: str | None = None) -> list[dict]:
    from backend.audit import fetch_all
    from backend.supabase_client import get_service_client
    svc = get_service_client()
    start = f"{month}-01T00:00:00+00:00"
    year, mon = map(int, month.split("-"))
    end = f"{year + (mon == 12)}-{(mon % 12) + 1:02d}-01T00:00:00+00:00"

    def build():
        q = (svc.table("anomalies").select("anomaly_type,severity,status,detector,feedback,detected_at")
             .gte("detected_at", start).lt("detected_at", end).order("detected_at"))
        if org_id:
            return q.eq("org_id", org_id)
        q = q.is_("org_id", "null")
        return q.eq("user_id", user_id) if user_id else q
    return fetch_all(build)


def _models(scope: str) -> dict:
    out = {}
    for name in MODEL_NAMES:
        bundle = registry.load(scope, name) or (registry.load(GLOBAL, name) if scope != GLOBAL else None)
        if not bundle:
            out[name] = None
            continue
        meta = bundle["meta"]
        out[name] = {
            "scope": meta.get("scope"),
            "trained_at": meta.get("trained_at"),
            "samples": meta.get("samples") or meta.get("rows"),
            "holdout": meta.get("holdout"),
            "calibration": meta.get("calibration"),
            "promotion": meta.get("promotion"),
        }
    return out


def summarise(rows: list[dict]) -> dict:
    by_type: dict[str, dict] = defaultdict(lambda: {"count": 0, "true_positive": 0, "false_positive": 0})
    for r in rows:
        t = by_type[r["anomaly_type"]]
        t["count"] += 1
        if r.get("feedback") in ("true_positive", "false_positive"):
            t[r["feedback"]] += 1
    for t in by_type.values():
        labelled = t["true_positive"] + t["false_positive"]
        t["labelled"] = labelled
        t["false_positive_share"] = round(t["false_positive"] / labelled, 3) if labelled else None
    return {
        "total": len(rows),
        "by_severity": dict(Counter(r["severity"] for r in rows)),
        "by_status": dict(Counter(r.get("status") for r in rows)),
        "by_detector": dict(Counter(r.get("detector") or "rule" for r in rows)),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1]["count"])),
    }


def build(org_id: str | None, month: str, user_id: str | None = None) -> dict:
    scope = scope_name(org_id)
    return {
        "scope": scope,
        "month": month,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts": summarise(_anomalies(org_id, month, user_id)),
        "models": _models(scope),
    }


def markdown(report: dict) -> str:
    a = report["alerts"]
    lines = [f"# OBLVN ML report {report['month']} ({report['scope']})", "",
             f"Alerts: {a['total']}.",
             f"By severity: {', '.join(f'{k} {v}' for k, v in a['by_severity'].items()) or 'none'}.",
             f"By detector: {', '.join(f'{k} {v}' for k, v in a['by_detector'].items()) or 'none'}.", "",
             "## Alert types", ""]
    for name, t in a["by_type"].items():
        fp = "no labels" if t["false_positive_share"] is None else f"{t['false_positive_share'] * 100:.0f} percent false positive of {t['labelled']} labelled"
        lines.append(f"- {name}: {t['count']} ({fp}).")
    lines += ["", "## Models", ""]
    for name, m in report["models"].items():
        if not m:
            lines.append(f"- {name}: not trained.")
            continue
        decision = (m.get("promotion") or {}).get("decision", "n/a")
        lines.append(f"- {name}: scope {m['scope']}, trained {m['trained_at']}, samples {m['samples']}, last promotion {decision}.")
    return "\n".join(lines) + "\n"


def write(org_id: str | None, month: str) -> dict:
    report = build(org_id, month)
    folder = REPORTS_DIR / month
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{report['scope']}.json").write_text(json.dumps(report, indent=2, default=str))
    (folder / f"{report['scope']}.md").write_text(markdown(report))
    return report


def run_monthly(today: date | None = None) -> list[dict]:
    month = _previous_month(today or date.today())
    return [write(org, month) for org in [None] + datasource.org_ids()]


def main() -> None:
    ap = argparse.ArgumentParser(description="Write monthly alert and model reports to ml/models/reports")
    ap.add_argument("--month", help="YYYY-MM, default is last month")
    ap.add_argument("--scope", action="append", help="org uuid or individual; default every scope")
    args = ap.parse_args()
    month = args.month or _previous_month(date.today())
    scopes = [None if s == "individual" else s for s in args.scope] if args.scope else [None] + datasource.org_ids()
    for org in scopes:
        r = write(org, month)
        print(f"{r['scope']}: {r['alerts']['total']} alerts -> {REPORTS_DIR / month}")


if __name__ == "__main__":
    main()
