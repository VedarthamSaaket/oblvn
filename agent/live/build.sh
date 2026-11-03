#!/bin/sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
STAGE="$HERE/config/includes.chroot"

if [ "$(id -u)" -ne 0 ]; then
  echo "run build.sh as root on a Debian or Ubuntu host with live-build installed" >&2
  exit 1
fi
command -v lb >/dev/null || { echo "live-build is not installed: apt install live-build" >&2; exit 1; }

rm -rf "$STAGE"
mkdir -p "$STAGE/opt/oblvn/backend/hw" "$STAGE/etc/systemd/system"
cp -r "$ROOT/agent" "$STAGE/opt/oblvn/agent"
rm -rf "$STAGE/opt/oblvn/agent/live"
cp "$ROOT/backend/__init__.py" "$ROOT/backend/detector.py" "$STAGE/opt/oblvn/backend/"
cp "$ROOT"/backend/hw/*.py "$STAGE/opt/oblvn/backend/hw/"
cp "$ROOT/agent/oblvn-agent.service" "$STAGE/etc/systemd/system/oblvn-agent.service"
chmod +x "$HERE/auto/config" "$HERE"/config/hooks/normal/*.hook.chroot

cd "$HERE"
lb clean --purge
lb config
lb build
ls -lh "$HERE"/*.iso
