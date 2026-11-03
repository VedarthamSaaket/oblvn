import ipaddress

from fastapi import HTTPException, Request

from backend.config import config

LOOPBACK_NAMES = {"localhost"}


def is_loopback(request: Request) -> bool:
    host = request.client.host if request.client else ""
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def allowed(request: Request) -> bool:
    mode = config.LOCAL_OPS
    if mode == "any":
        return True
    if mode == "off":
        return False
    return is_loopback(request)


def require(request: Request) -> None:
    if not allowed(request):
        raise HTTPException(
            status_code=403,
            detail="Operations on this server's own disks and files are only allowed from the server itself; "
                   "use an OBLVN agent for remote machines",
        )
