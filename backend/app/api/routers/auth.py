from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import _get_auth_verifier, get_db, rate_limit_scope
from app.api.errors import CodedHTTPException
from app.api.session_cookie import cookie_request_origin_allowed, set_session_cookie
from app.core.auth import PasswordGrantError, exchange_password_for_session
from app.core.logging import get_logger
from app.core.rate_limit import RateLimitExceededError
from app.db import models
from app.schemas.auth import ErrorEnvelope, LoginRequest, LoginResponse

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorEnvelope, "description": "Unauthorized"},
    403: {"model": ErrorEnvelope, "description": "Forbidden"},
    422: {"model": ErrorEnvelope, "description": "Validation Error"},
    429: {"model": ErrorEnvelope, "description": "Too Many Requests"},
    503: {"model": ErrorEnvelope, "description": "Authentication Provider Unavailable"},
}


def _sanitize_return_to(return_to: str | None) -> str:
    """Only same-origin relative paths are echoed back; anything else falls back to `/`."""
    if not return_to:
        return "/"
    candidate = return_to.strip()
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or any(ord(ch) < 0x20 for ch in candidate)
    ):
        return "/"
    return candidate


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Web Login",
    responses=_ERROR_RESPONSES,
    dependencies=[Depends(rate_limit_scope("auth_endpoints", require_authenticated_principal=True))],
)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    request_id = getattr(request.state, "request_id", "-")
    log_extra = {"request_id": request_id, "handoff": bool(payload.handoff)}
    logger.info("auth.login.call", extra=log_extra)

    if not cookie_request_origin_allowed(request):
        logger.warning(
            "auth.login.origin_denied", extra={**log_extra, "origin": request.headers.get("origin")}
        )
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            code="origin_not_allowed",
            message="cross-origin login not allowed",
        )

    try:
        session = exchange_password_for_session(email=str(payload.email), password=payload.password)
    except PasswordGrantError as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            raise RateLimitExceededError(
                scope="auth_endpoints", retry_after_seconds=exc.retry_after_seconds or 60
            ) from exc
        raise CodedHTTPException(status_code=exc.status_code, code=exc.code, message=exc.message) from exc

    # Re-verify the issued token with the same verifier protected routes use, so a misconfigured
    # issuer/audience/JWKS surfaces at login instead of as a cookie every later request rejects.
    try:
        verified = _get_auth_verifier().verify(session.access_token)
    except Exception as exc:
        logger.error("auth.login.issued_token_rejected", extra={**log_extra, "error": exc.__class__.__name__})
        raise CodedHTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="auth_provider_error",
            message="authentication provider returned an unverifiable token",
        ) from exc

    user = db.query(models.User).filter(models.User.id == verified.user_id).first()
    if user is not None and not user.is_active:
        logger.warning("auth.login.inactive_denied", extra={**log_extra, "user_id": str(verified.user_id)})
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            code="account_inactive",
            message="User account is inactive",
        )

    set_session_cookie(response, access_token=session.access_token, max_age_seconds=session.expires_in)
    request.state.user_id = str(verified.user_id)
    logger.info("auth.login.success", extra={**log_extra, "user_id": str(verified.user_id)})
    return LoginResponse(success=True, redirect_to=_sanitize_return_to(payload.return_to))
