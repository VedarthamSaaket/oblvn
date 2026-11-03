import asyncio
import secrets
import threading
import time

from fastapi import WebSocket

connected: dict[str, list[WebSocket]] = {}
_loop: asyncio.AbstractEventLoop | None = None


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


TICKET_TTL = 30
_tickets: dict[str, tuple[str, str, float]] = {}
_ticket_lock = threading.Lock()


def issue_ticket(user_id: str, job_id: str) -> str:
    ticket = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _ticket_lock:
        for k in [k for k, (_, _, exp) in _tickets.items() if exp < now]:
            _tickets.pop(k, None)
        _tickets[ticket] = (user_id, job_id, now + TICKET_TTL)
    return ticket


def redeem_ticket(ticket: str, job_id: str) -> str | None:
    with _ticket_lock:
        entry = _tickets.pop(ticket or "", None)
    if not entry:
        return None
    user_id, bound_job, expires = entry
    if bound_job != job_id or expires < time.monotonic():
        return None
    return user_id


def room(job_id: str) -> str:
    return f"job_{job_id}"


async def _send(job_id: str, data: dict) -> None:
    for ws in list(connected.get(room(job_id), [])):
        try:
            await ws.send_json(data)
        except Exception:
            pass


def broadcast(job_id: str, data: dict) -> None:
    if _loop is None or _loop.is_closed():
        return
    asyncio.run_coroutine_threadsafe(_send(job_id, data), _loop)
