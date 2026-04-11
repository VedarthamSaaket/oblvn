"""
Dedicated tkinter worker thread for OBLVN.
All tkinter calls MUST happen on this single thread.
"""

import queue
import threading
import traceback

_job_queue: queue.Queue = queue.Queue()
_ready = threading.Event()
_started = False
_lock = threading.Lock()


def start():
    global _started
    with _lock:
        if _started:
            return
        _started = True
    t = threading.Thread(target=_worker, name="tk-worker", daemon=True)
    t.start()
    if not _ready.wait(timeout=10):
        raise RuntimeError("[tk_worker] tkinter failed to initialise within 10s")
    print("[tk_worker] ready", flush=True)


def run_job(fn) -> dict:
    if not _ready.is_set():
        raise RuntimeError("[tk_worker] not started — call tk_worker.start() first")
    result: dict = {}
    done = threading.Event()
    _job_queue.put((fn, result, done))
    done.wait()
    if "error" in result:
        raise RuntimeError(result["error"])
    return result


def _worker():
    import tkinter as tk

    try:
        root = tk.Tk()
        root.withdraw()
        root.update()
        print("[tk_worker] tk root created OK", flush=True)
    except Exception as e:
        print(f"[tk_worker] FATAL: could not create Tk root: {e}", flush=True)
        return

    _ready.set()

    while True:
        try:
            fn, result, done = _job_queue.get(timeout=0.05)
            print("[tk_worker] got job, executing...", flush=True)
            try:
                fn(root, result)
                print("[tk_worker] job done", flush=True)
            except Exception as exc:
                traceback.print_exc()
                result["error"] = str(exc)
            finally:
                done.set()
        except queue.Empty:
            try:
                root.update()
            except tk.TclError:
                print("[tk_worker] root destroyed, exiting", flush=True)
                break