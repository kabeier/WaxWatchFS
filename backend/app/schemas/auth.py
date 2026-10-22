from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    """Web login form payload (`POST /api/auth/login`).

    `return_to`, `handoff`, `state`, `nonce`, and `expires_at` are echoed by the web client for
    redirect/handoff bookkeeping. The backend only uses `return_to` (sanitized to a same-origin
    relative path) to compute `redirect_to`; handoff fields are accepted for contract compatibility
    and are not used to mint tokens.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "listener@example.com",
                "password": "<redacted>",
                "return_to": "/",
            }
        }
    )

    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)
    return_to: str | None = Field(default=None, max_length=2048)
    handoff: str | None = Field(default=None, max_length=2048)
    state: str | None = Field(default=None, max_length=512)
    nonce: str | None = Field(default=None, max_length=512)
    expires_at: str | None = Field(default=None, max_length=64)


class LoginResponse(BaseModel):
    success: bool = True
    redirect_to: str | None = None


class ErrorEnvelopeError(BaseModel):
    message: str
    code: str | None = None
    type: str | None = None
    status: int | None = None
    details: Any = None


class ErrorEnvelope(BaseModel):
    error: ErrorEnvelopeError
