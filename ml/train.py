import argparse
import json

from ml import behaviour, datasource, drive_health, feedback, wipe_duration
from ml.paths import GLOBAL, MODELS_DIR, scope_name

WHAT = ("duration", "behaviour", "drive_health", "feedback")


def train_scope(org_id: str | None, what: set[str]) -> dict:
    scope = scope_name(org_id)
    report: dict = {"scope": scope}
    jobs = datasource.jobs(org_id) if what & {"duration", "behaviour"} else []
    if "duration" in what:
        report["duration"] = wipe_duration.train(jobs, scope) or "not enough completed jobs"
    if "behaviour" in what:
        logins = datasource.logins(org_id)
        result = behaviour.train(jobs, logins, scope, datasource.org_timezone(org_id))
        report["behaviour"] = {k: v or "not enough samples" for k, v in result.items()}
    if "feedback" in what:
        report["feedback"] = feedback.calibrate(org_id, datasource.labelled_anomalies(org_id))
    return report


def train_global(what: set[str]) -> dict:
    report: dict = {"scope": GLOBAL}
    jobs = datasource.jobs(None, all_scopes=True) if what & {"duration", "behaviour"} else []
    if "duration" in what:
        report["duration"] = wipe_duration.train(jobs, GLOBAL) or "not enough completed jobs"
    if "behaviour" in what:
        result = behaviour.train(jobs, datasource.logins(None, all_scopes=True), GLOBAL, "UTC")
        report["behaviour"] = {k: v or "not enough samples" for k, v in result.items()}
    if "drive_health" in what:
        if drive_health.DATASET.exists():
            report["drive_health"] = drive_health.train()
        else:
            report["drive_health"] = f"skipped, {drive_health.DATASET} not built yet"
    return report


def run(scopes: list[str | None] | None = None, what: set[str] | None = None, include_global: bool = True) -> list[dict]:
    what = what or set(WHAT) - {"drive_health"}
    scopes = scopes if scopes is not None else [None] + datasource.org_ids()
    reports = [train_global(what)] if include_global else []
    for org_id in scopes:
        try:
            reports.append(train_scope(org_id, what))
        except Exception as exc:
            reports.append({"scope": scope_name(org_id), "error": str(exc)})
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    (MODELS_DIR / "last_training_report.json").write_text(json.dumps(reports, indent=2, default=str))
    return reports


def run_nightly() -> list[dict]:
    return run()


def main() -> None:
    ap = argparse.ArgumentParser(description="Train OBLVN anomaly models")
    ap.add_argument("--what", default="duration,behaviour,feedback",
                    help=f"comma list from {','.join(WHAT)}")
    ap.add_argument("--scope", action="append",
                    help="org uuid or 'individual'; repeatable; default every scope")
    ap.add_argument("--no-global", action="store_true")
    args = ap.parse_args()
    what = {w.strip() for w in args.what.split(",") if w.strip()}
    unknown = what - set(WHAT)
    if unknown:
        raise SystemExit(f"unknown model names: {', '.join(sorted(unknown))}")
    scopes = None
    if args.scope:
        scopes = [None if s == "individual" else s for s in args.scope]
    print(json.dumps(run(scopes, what, not args.no_global), indent=2, default=str))


if __name__ == "__main__":
    main()
