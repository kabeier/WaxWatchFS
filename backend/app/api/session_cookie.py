from __future__ import annotations

from typing import Literal, cast

from fastapi import Request, Response

from app.core.config import settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SameSite = Literal["lax", "strict", "none"]


def set_session_cookie(response: Response, *, access_token: str, max_age_seconds: int) -> None:
    """Attach the web session cookie (httpOnly, Secure by default, SameSite=Lax by default)."""
    response.set_cookie(
        key=settings.auth_session_cookie_name,
        value=access_token,
        max_age=max_age_seconds,
        path="/",
        domain=settings.auth_session_cookie_domain,
        secure=settings.auth_session_cookie_secure,
        httponly=True,
        samesite=cast(SameSite, settings.auth_session_cookie_samesite),
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.auth_session_cookie_name,
        path="/",
        domain=settings.auth_session_cookie_domain,
        secure=settings.auth_session_cookie_secure,
        httponly=True,
        samesite=cast(SameSite, settings.auth_session_cookie_samesite),
    )


def read_session_cookie(request: Request) -> str | None:
    value = request.cookies.get(settings.auth_session_cookie_name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def cookie_request_origin_allowed(request: Request) -> bool:
    """CSRF guard for cookie-authenticated, state-changing requests.

    Browsers send `Origin` on cross-origin fetches and form posts. When present on an unsafe
    method, it must be this API's own origin or an explicitly allowed CORS origin. Requests
    without `Origin` (same-origin navigations, non-browser clients) are allowed; SameSite on the
    cookie is the first line of defense.
    """
    if request.method.upper() in SAFE_METHODS:
        return True

    origin = request.headers.get("origin")
    if origin is None:
        return True

    normalized = origin.strip().rstrip("/").lower()
    allowed = {o.rstrip("/").lower() for o in settings.cors_allowed_origins if o != "*"}
    if normalized in allowed:
        return True
    return _matches_request_origin(request, normalized)


def _first_header_value(request: Request, name: str) -> str | None:
    raw = request.headers.get(name)
    if raw is None:
        return None
    first = raw.split(",", maxsplit=1)[0].strip().lower()
    return first or None


def _split_origin(origin: str) -> tuple[str, str] | None:
    scheme, sep, host = origin.partition("://")
    if not sep or not scheme or not host or "/" in host:
        return None
    return scheme, host


def _strip_default_port(scheme: str, host: str) -> str:
    default_port = {"http": ":80", "https": ":443"}.get(scheme)
    if default_port and host.endswith(default_port):
        return host[: -len(default_port)]
    return host


def _matches_request_origin(request: Request, origin: str) -> bool:
    """Is `origin` this API's own *external* origin?

    Uvicorn runs without `--proxy-headers`, so behind a TLS-terminating proxy/LB `request.url` is
    `http://<host>` while browsers send `Origin: https://<host>`. Derive the external origin from
    `X-Forwarded-Host` / `X-Forwarded-Proto` (first value) when present, falling back to the Host
    header / `request.url`. When no `X-Forwarded-Proto` is sent, compare host only (scheme-
    insensitive): http/https on the same host is the same site for SameSite purposes, and a
    cross-site attacker cannot add forwarding headers to a credentialed browser request without a
    CORS preflight, which fails for disallowed origins.
    """
    parsed = _split_origin(origin)
    if parsed is None:
        return False
    origin_scheme, origin_host = parsed

    forwarded_proto = _first_header_value(request, "x-forwarded-proto")
    forwarded_host = _first_header_value(request, "x-forwarded-host")
    request_host = forwarded_host or (request.headers.get("host") or request.url.netloc).strip().lower()
    if not request_host:
        return False

    if forwarded_proto is None:
        # Scheme unknown: ignore either default port on the internal Host.
        internal_host = _strip_default_port("https", _strip_default_port("http", request_host))
        return _strip_default_port(origin_scheme, origin_host) == internal_host

    return origin_scheme == forwarded_proto and _strip_default_port(
        origin_scheme, origin_host
    ) == _strip_default_port(forwarded_proto, request_host)
