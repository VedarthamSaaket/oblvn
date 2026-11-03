import subprocess
import sys
import time

from backend.hw import verify
from backend.hw.keystream import source_for
from backend.hw.overwrite import overwrite_pass
from backend.hw.patterns import passes_for

SECTORS = 131072


def attach() -> str:
    out = subprocess.run(["hdiutil", "attach", "-nomount", f"ram://{SECTORS}"],
                         capture_output=True, text=True, check=True).stdout
    return out.split()[0]


def main() -> int:
    if sys.platform != "darwin":
        print("macOS only")
        return 2
    node = attach()
    raw = node.replace("/dev/disk", "/dev/rdisk")
    size = SECTORS * 512
    ok = True
    try:
        print(f"ram disk {node} ({raw}), {size} bytes")
        offsets = verify.sample_offsets(size, 512, seed=7)
        before = verify.snapshot(raw, size, offsets)
        for p in passes_for("dod_5220_22m"):
            source, ks = source_for(p)
            t = time.monotonic()
            res = overwrite_pass(raw, size, source, lambda pct, w: None, lambda: None)
            print(f"{p['label']}: {res['bytes']} bytes in {res['seconds']}s, {res['throughput_mbps']} MB/s")
        sample = verify.check_pattern(raw, size, offsets, source)
        full = verify.check_pattern(raw, size, None, source)
        changed = verify.check_changed(raw, size, before)
        print("sample verify:", sample)
        print("full verify:", full)
        print("changed check:", changed)
        ok &= sample["passed"] and full["passed"] and changed["passed"] is not False
        with open(raw, "r+b", buffering=0) as f:
            f.seek(512 * 1000)
            f.write(bytes(512))
        tampered = verify.check_pattern(raw, size, None, source)
        print("after tampering one sector:", tampered)
        ok &= tampered["passed"] is False and tampered["mismatches"] == 1
        ks.destroy()
        ok &= ks.destroyed
    finally:
        subprocess.run(["hdiutil", "detach", node], capture_output=True)
        print(f"detached {node}")
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
