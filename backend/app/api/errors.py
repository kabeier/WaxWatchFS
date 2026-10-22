from __future__ import annotations

from fastapi import HTTPException


class CodedHTTPException(HTTPException):
    """HTTPException that carries a stable machine-readable `error.code` for the error envelope.

    The global HTTPException handler in `app.main` emits `code` instead of the generic
    `http_error` when raised with this subclass.
    """

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.code = code
