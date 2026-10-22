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
    own_origin = f"{request.url.scheme}://{request.url.netloc}".lower()
    allowed = {o.rstrip("/").lower() for o in settings.cors_allowed_origins if o != "*"}
    return normalized == own_origin or normalized in allowed
