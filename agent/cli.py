import argparse
import json
import os
import sys
from pathlib import Path

from agent import VERSION
from agent.client import AgentClient, pair
from agent.config import DEFAULT_PATH, load
from agent.worker import inventory, run


def _prompt_pair(path: Path, ca_bundle: str | None) -> None:
    print("OBLVN agent is not paired yet.")
    print("Create a pairing code in OBLVN with POST /api/agents/pairing-code, then enter it here.")
    server = input("OBLVN server URL: ").strip()
    code = input("Pairing code: ").strip()
    pair(server, code, ca_bundle).save(path)
    print(f"Paired. Config saved to {path}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="oblvn-agent", description=f"OBLVN wipe agent {VERSION}")
    ap.add_argument("--config", type=Path, default=DEFAULT_PATH)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("pair")
    p.add_argument("--server", required=True)
    p.add_argument("--code", required=True)
    p.add_argument("--ca-bundle")
    p.add_argument("--allow-insecure-http", action="store_true")
    r = sub.add_parser("run")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--once", action="store_true")
    r.add_argument("--interactive-pair", action="store_true")
    r.add_argument("--ca-bundle")
    sub.add_parser("inventory")
    args = ap.parse_args(argv)

    if args.command == "inventory":
        print(json.dumps(inventory(), indent=2, default=str))
        return
    if args.command == "pair":
        pair(args.server, args.code, args.ca_bundle, args.allow_insecure_http).save(args.config)
        print(f"Paired. Config saved to {args.config}")
        return
    if hasattr(os, "geteuid") and os.geteuid() != 0 and not args.dry_run:
        sys.exit("oblvn-agent run needs root to reach raw block devices")
    cfg = load(args.config)
    if cfg is None:
        if not args.interactive_pair:
            sys.exit(f"not paired: run 'oblvn-agent pair' first (config {args.config} missing)")
        _prompt_pair(args.config, args.ca_bundle)
        cfg = load(args.config)
    run(AgentClient(cfg), dry_run=args.dry_run, once=args.once)
