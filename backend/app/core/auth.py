from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx
import jwt
from fastapi import HTTPException, status
from jwt import InvalidTokenError, PyJWK

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("app.auth")


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: UUID
    claims: dict[str, Any]


class SupabaseJWTVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        algorithms: tuple[str, ...],
        jwks_cache_ttl_seconds: int,
        clock_skew_seconds: int,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self.algorithms = algorithms
        self.jwks_cache_ttl_seconds = jwks_cache_ttl_seconds
        self.clock_skew_seconds = clock_skew_seconds

        self._jwks: dict[str, Any] | None = None
        self._jwks_loaded_at: float = 0.0

    def _fetch_jwks(self) -> dict[str, Any]:
        now = time.time()
        if self._jwks and (now - self._jwks_loaded_at) < self.jwks_cache_ttl_seconds:
            return self._jwks

        logger.info("auth.jwks.fetch", extra={"jwks_url": self.jwks_url})
        response = httpx.get(self.jwks_url, timeout=5.0)
        response.raise_for_status()
        try:
            jwks = response.json()
        except ValueError as exc:
            logger.info("auth.jwks.invalid_json")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="invalid jwks response",
            ) from exc
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="invalid jwks response"
            )

        self._jwks = jwks
        self._jwks_loaded_at = now
        logger.info("auth.jwks.fetch.success", extra={"keys_count": len(jwks.get("keys", []))})
        return jwks

    def _get_signing_key(self, token: str) -> Any:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg")

        if alg not in self.algorithms:
            logger.warning(
                "auth.token.invalid_algorithm", extra={"alg": alg, "allowed": list(self.algorithms)}
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token algorithm")

        jwks = self._fetch_jwks()

        for key in jwks["keys"]:
            if key.get("kid") == kid:
                return PyJWK.from_dict(key).key

        self._jwks = None
        logger.warning("auth.jwks.kid_unknown", extra={"kid": kid})
        logger.info("auth.jwks.kid_miss.refresh", extra={"kid": kid})
        jwks = self._fetch_jwks()
        for key in jwks["keys"]:
            if key.get("kid") == kid:
                return PyJWK.from_dict(key).key

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unknown token key id")

    def verify(self, token: str) -> AuthenticatedUser:
        try:
            signing_key = self._get_signing_key(token)
            claims = jwt.decode(
                token,
                key=signing_key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.clock_skew_seconds,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except HTTPException:
            raise
        except httpx.HTTPError as exc:
            logger.exception("auth.jwks.fetch.error")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="unable to fetch jwks",
            ) from exc
        except InvalidTokenError as exc:
            logger.warning("auth.token.invalid", extra={"error": exc.__class__.__name__})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token"
            ) from exc

        subject = claims.get("sub")
        try:
            user_id = UUID(str(subject))
        except (TypeError, ValueError) as exc:
            logger.warning("auth.token.invalid_subject")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token subject"
            ) from exc

        logger.debug("auth.token.verified", extra={"user_id": str(user_id), "issuer": self.issuer})
        return AuthenticatedUser(user_id=user_id, claims=claims)


def build_verifier() -> SupabaseJWTVerifier:
    issuer = settings.auth_issuer
    jwks_url = settings.auth_jwks_url

    if not issuer and settings.supabase_url:
        issuer = f"{settings.supabase_url.rstrip('/')}/auth/v1"
    if not jwks_url and issuer:
        jwks_url = f"{issuer.rstrip('/')}/.well-known/jwks.json"

    if not issuer or not jwks_url:
        raise RuntimeError("AUTH_ISSUER/AUTH_JWKS_URL or SUPABASE_URL must be configured")

    logger.info(
        "auth.verifier.configured",
        extra={
            "issuer": issuer,
            "audience": settings.auth_audience,
            "jwks_url": jwks_url,
            "algorithms": settings.auth_jwt_algorithms,
            "jwks_cache_ttl_seconds": settings.auth_jwks_cache_ttl_seconds,
            "clock_skew_seconds": settings.auth_clock_skew_seconds,
        },
    )

    return SupabaseJWTVerifier(
        issuer=issuer,
        audience=settings.auth_audience,
        jwks_url=jwks_url,
        algorithms=tuple(settings.auth_jwt_algorithms),
        jwks_cache_ttl_seconds=settings.auth_jwks_cache_ttl_seconds,
        clock_skew_seconds=settings.auth_clock_skew_seconds,
    )


@dataclass(frozen=True)
class PasswordGrantSession:
    access_token: str
    expires_in: int


class PasswordGrantError(Exception):
    """Login failure mapped to an API status + stable error code."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retry_after_seconds = retry_after_seconds


DEFAULT_SESSION_TTL_SECONDS = 3600
_INVALID_CREDENTIAL_ERROR_CODES = {"invalid_credentials", "invalid_grant"}
_UNCONFIRMED_ERROR_CODES = {"email_not_confirmed"}


def resolve_auth_api_base_url() -> str | None:
    """Base URL of the Supabase Auth (GoTrue) API, e.g. `https://<ref>.supabase.co/auth/v1`."""
    if settings.supabase_url:
        return f"{settings.supabase_url.rstrip('/')}/auth/v1"
    if settings.auth_issuer:
        return settings.auth_issuer.rstrip("/")
    return None


def _provider_error_code(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("error_code", "error"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None


def _parse_retry_after(value: str | None) -> int:
    try:
        parsed = int(value) if value is not None else 60
    except ValueError:
        parsed = 60
    return max(parsed, 1)


def exchange_password_for_session(*, email: str, password: str) -> PasswordGrantSession:
    """Exchange email/password for a Supabase access token via the password grant.

    Never logs the password or token material.
    """
    base_url = resolve_auth_api_base_url()
    anon_key = settings.supabase_anon_key
    if not base_url or not anon_key:
        logger.error(
            "auth.login.not_configured",
            extra={"auth_api_configured": bool(base_url), "anon_key_configured": bool(anon_key)},
        )
        raise PasswordGrantError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="auth_login_unavailable",
            message="login is not configured",
        )

    try:
        response = httpx.post(
            f"{base_url}/token",
            params={"grant_type": "password"},
            json={"email": email, "password": password},
            headers={"apikey": anon_key, "Accept": "application/json"},
            timeout=settings.auth_login_timeout_seconds,
        )
    except httpx.HTTPError as exc:
        logger.warning("auth.login.provider_transport_error", extra={"error": exc.__class__.__name__})
        raise PasswordGrantError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="auth_provider_unavailable",
            message="authentication provider unavailable",
        ) from exc

    try:
        payload: Any = response.json()
    except ValueError:
        payload = None

    if response.status_code == status.HTTP_200_OK:
        access_token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(access_token, str) or not access_token:
            logger.error("auth.login.provider_missing_access_token")
            raise PasswordGrantError(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                code="auth_provider_error",
                message="authentication provider returned an invalid response",
            )
        raw_expires_in = payload.get("expires_in")
        expires_in = (
            raw_expires_in
            if isinstance(raw_expires_in, int) and not isinstance(raw_expires_in, bool) and raw_expires_in > 0
            else DEFAULT_SESSION_TTL_SECONDS
        )
        return PasswordGrantSession(access_token=access_token, expires_in=expires_in)

    provider_code = _provider_error_code(payload)
    log_extra = {"provider_status": response.status_code, "provider_error_code": provider_code}

    if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
        logger.warning("auth.login.provider_rate_limited", extra=log_extra)
        raise PasswordGrantError(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="rate_limited",
            message="rate limit exceeded",
            retry_after_seconds=_parse_retry_after(response.headers.get("retry-after")),
        )

    if provider_code in _UNCONFIRMED_ERROR_CODES:
        logger.info("auth.login.email_not_confirmed", extra=log_extra)
        raise PasswordGrantError(
            status_code=status.HTTP_403_FORBIDDEN,
            code="email_not_confirmed",
            message="email address not confirmed",
        )

    if (
        response.status_code == status.HTTP_400_BAD_REQUEST
        or provider_code in _INVALID_CREDENTIAL_ERROR_CODES
    ):
        logger.info("auth.login.invalid_credentials", extra=log_extra)
        raise PasswordGrantError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="invalid_credentials",
            message="invalid email or password",
        )

    # A provider 401/403 here means our API key/config is wrong and 5xx is an outage:
    # report a provider failure instead of blaming the user's credentials.
    logger.error("auth.login.provider_error", extra=log_extra)
    raise PasswordGrantError(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        code="auth_provider_error",
        message="authentication provider error",
    )
