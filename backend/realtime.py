import asyncio

from fastapi import WebSocket

connected: dict[str, list[WebSocket]] = {}
_loop: asyncio.AbstractEventLoop | None = None


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


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
