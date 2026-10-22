from __future__ import annotations

from http.cookies import SimpleCookie
from uuid import uuid4

import httpx
import pytest

from app.core.config import settings
from app.core.rate_limit import reset_rate_limiter_state

LOGIN_URL = "/api/auth/login"
COOKIE_NAME = "waxwatch_session"
CREDENTIALS = {"email": "listener@example.com", "password": "correct horse battery staple"}


class _FakeProviderResponse:
    def __init__(self, status_code: int, payload=None, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self._payload = payload
        self.headers = httpx.Headers(headers or {})

    def json(self):
        if self._payload is None:
            raise ValueError("no json body")
        return self._payload


@pytest.fixture(autouse=True)
def _login_settings(monkeypatch):
    monkeypatch.setattr(settings, "supabase_anon_key", "test-anon-key")
    monkeypatch.setattr(settings, "supabase_url", None)
    monkeypatch.setattr(settings, "auth_session_cookie_name", COOKIE_NAME)
    monkeypatch.setattr(settings, "auth_session_cookie_secure", True)
    monkeypatch.setattr(settings, "auth_session_cookie_samesite", "lax")
    monkeypatch.setattr(settings, "auth_session_cookie_domain", None)
    reset_rate_limiter_state()
    yield
    reset_rate_limiter_state()


@pytest.fixture()
def provider(monkeypatch):
    """Replace the Supabase password-grant HTTP call; records each outbound request."""
    calls: list[dict] = []
    state: dict = {"response": None, "exc": None}

    def _fake_post(url, *, params=None, json=None, headers=None, timeout=None):
        calls.append({"url": url, "params": params, "json": json, "headers": headers, "timeout": timeout})
        if state["exc"] is not None:
            raise state["exc"]
        return state["response"]

    monkeypatch.setattr("app.core.auth.httpx.post", _fake_post)

    def _respond(status_code: int, payload=None, headers=None):
        state["response"] = _FakeProviderResponse(status_code, payload, headers)

    def _raise(exc: Exception):
        state["exc"] = exc

    return type(
        "Provider", (), {"calls": calls, "respond": staticmethod(_respond), "raise_": staticmethod(_raise)}
    )


def _session_cookie(response) -> SimpleCookie:
    raw = [value for key, value in response.headers.multi_items() if key.lower() == "set-cookie"]
    assert raw, "expected a Set-Cookie header"
    jar: SimpleCookie = SimpleCookie()
    for item in raw:
        jar.load(item)
    return jar


def test_login_success_sets_httponly_session_cookie(client, user, sign_jwt, provider):
    token = sign_jwt(sub=str(user.id))
    provider.respond(200, {"access_token": token, "token_type": "bearer", "expires_in": 1800})

    response = client.post(LOGIN_URL, json={**CREDENTIALS, "return_to": "/alerts?tab=new"})

    assert response.status_code == 200
    assert response.json() == {"success": True, "redirect_to": "/alerts?tab=new"}
    # The access token must never be exposed to JS via the response body.
    assert token not in response.text

    call = provider.calls[0]
    assert call["url"] == "http://127.0.0.1:8765/auth/v1/token"
    assert call["params"] == {"grant_type": "password"}
    assert call["json"] == CREDENTIALS
    assert call["headers"]["apikey"] == "test-anon-key"

    raw_cookie = response.headers["set-cookie"]
    morsel = _session_cookie(response)[COOKIE_NAME]
    assert morsel.value == token
    assert morsel["httponly"] is True
    assert morsel["secure"] is True
    assert morsel["samesite"].lower() == "lax"
    assert morsel["path"] == "/"
    assert morsel["max-age"] == "1800"
    assert "Domain=" not in raw_cookie


def test_login_uses_supabase_url_when_configured(client, user, sign_jwt, provider, monkeypatch):
    monkeypatch.setattr(settings, "supabase_url", "https://project.supabase.co/")
    provider.respond(200, {"access_token": sign_jwt(sub=str(user.id)), "expires_in": 3600})

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 200
    assert provider.calls[0]["url"] == "https://project.supabase.co/auth/v1/token"


def test_login_cookie_honors_configured_attributes(client, user, sign_jwt, provider, monkeypatch):
    monkeypatch.setattr(settings, "auth_session_cookie_samesite", "strict")
    monkeypatch.setattr(settings, "auth_session_cookie_domain", "waxwatch.example")
    provider.respond(200, {"access_token": sign_jwt(sub=str(user.id))})

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    morsel = _session_cookie(response)[COOKIE_NAME]
    assert morsel["samesite"].lower() == "strict"
    assert morsel["domain"] == "waxwatch.example"
    # Missing expires_in falls back to the default session TTL.
    assert morsel["max-age"] == "3600"


@pytest.mark.parametrize(
    "return_to",
    [None, "https://evil.example/phish", "//evil.example", "/\\evil.example", "relative/path"],
)
def test_login_redirect_to_only_echoes_relative_paths(client, user, sign_jwt, provider, return_to):
    provider.respond(200, {"access_token": sign_jwt(sub=str(user.id))})

    response = client.post(LOGIN_URL, json={**CREDENTIALS, "return_to": return_to})

    assert response.status_code == 200
    assert response.json()["redirect_to"] == "/"


def test_login_accepts_handoff_fields(client, user, sign_jwt, provider):
    provider.respond(200, {"access_token": sign_jwt(sub=str(user.id))})

    response = client.post(
        LOGIN_URL,
        json={
            **CREDENTIALS,
            "return_to": "/",
            "handoff": "waxwatch://auth/callback",
            "state": "state-123",
            "nonce": "nonce-123",
            "expires_at": "2026-01-02T00:00:01.000Z",
        },
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {"error_code": "invalid_credentials", "msg": "Invalid login credentials", "code": 400},
        {"error": "invalid_grant", "error_description": "Invalid login credentials"},
        None,
    ],
)
def test_login_invalid_credentials_returns_401_envelope(client, provider, payload):
    provider.respond(400, payload)

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 401
    assert response.json() == {
        "error": {"message": "invalid email or password", "code": "invalid_credentials", "status": 401}
    }
    assert "set-cookie" not in response.headers


def test_login_unconfirmed_email_returns_403(client, provider):
    provider.respond(400, {"error_code": "email_not_confirmed", "msg": "Email not confirmed"})

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "email_not_confirmed"


@pytest.mark.parametrize("status_code", [401, 403, 500, 502])
def test_login_provider_errors_map_to_503(client, provider, status_code):
    provider.respond(status_code, {"message": "Invalid API key"})

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "auth_provider_error"
    assert "set-cookie" not in response.headers


def test_login_provider_transport_error_maps_to_503(client, provider):
    provider.raise_(httpx.ConnectTimeout("timed out"))

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "auth_provider_unavailable"


def test_login_provider_success_without_token_maps_to_503(client, provider):
    provider.respond(200, {"token_type": "bearer"})

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "auth_provider_error"


def test_login_rejects_unverifiable_provider_token(client, provider, sign_jwt):
    provider.respond(200, {"access_token": sign_jwt(sub=str(uuid4()), aud="someone-else")})

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "auth_provider_error"
    assert "set-cookie" not in response.headers


def test_login_provider_rate_limit_maps_to_429(client, provider):
    provider.respond(429, {"error_code": "over_request_rate_limit"}, headers={"Retry-After": "42"})

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "42"
    body = response.json()["error"]
    assert body["code"] == "rate_limited"
    assert body["details"] == {"scope": "auth_endpoints", "retry_after_seconds": 42}


def test_login_not_configured_returns_503(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "supabase_anon_key", None)

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "auth_login_unavailable"
    assert provider.calls == []


def test_login_inactive_account_returns_403_without_cookie(client, user, db_session, sign_jwt, provider):
    user.is_active = False
    db_session.flush()
    provider.respond(200, {"access_token": sign_jwt(sub=str(user.id))})

    response = client.post(LOGIN_URL, json=CREDENTIALS)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "account_inactive"
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize(
    "body",
    [
        {"email": "not-an-email", "password": "x"},
        {"email": "listener@example.com", "password": ""},
        {"email": "listener@example.com"},
    ],
)
def test_login_validation_errors_use_envelope(client, provider, body):
    response = client.post(LOGIN_URL, json=body)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert provider.calls == []


def test_login_rejects_disallowed_cross_origin(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "cors_allowed_origins", ["https://app.waxwatch.example"])

    response = client.post(LOGIN_URL, json=CREDENTIALS, headers={"Origin": "https://evil.example"})

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "origin_not_allowed"
    assert provider.calls == []


def test_login_allows_configured_cors_origin(client, user, sign_jwt, provider, monkeypatch):
    monkeypatch.setattr(settings, "cors_allowed_origins", ["https://app.waxwatch.example"])
    provider.respond(200, {"access_token": sign_jwt(sub=str(user.id))})

    response = client.post(LOGIN_URL, json=CREDENTIALS, headers={"Origin": "https://app.waxwatch.example"})

    assert response.status_code == 200


def test_login_scope_rate_limit_is_keyed_per_client(client, provider, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_auth_endpoint_rpm", 1)
    monkeypatch.setattr(settings, "rate_limit_auth_endpoint_burst", 0)
    monkeypatch.setattr(settings, "rate_limit_global_anonymous_rpm", 100)
    monkeypatch.setattr(settings, "rate_limit_global_authenticated_rpm", 100)
    provider.respond(400, {"error_code": "invalid_credentials"})

    first = client.post(LOGIN_URL, json=CREDENTIALS)
    second = client.post(LOGIN_URL, json=CREDENTIALS)
    # Rotating bogus session cookies must not mint fresh login budgets (shared anon:<client>:bearer key).
    third = client.post(LOGIN_URL, json=CREDENTIALS, headers={"Cookie": f"{COOKIE_NAME}=bogus-1"})
    fourth = client.post(LOGIN_URL, json=CREDENTIALS, headers={"Cookie": f"{COOKIE_NAME}=bogus-2"})

    assert first.status_code == 401
    assert second.status_code == 429
    assert second.json()["error"]["details"]["scope"] == "auth_endpoints"
    assert "Retry-After" in second.headers
    assert third.status_code == 401
    assert fourth.status_code == 429
    assert len(provider.calls) == 2


def test_session_cookie_authenticates_protected_route(client, user, sign_jwt):
    token = sign_jwt(sub=str(user.id))

    response = client.get("/api/me", headers={"Cookie": f"{COOKIE_NAME}={token}"})

    assert response.status_code == 200
    assert response.json()["id"] == str(user.id)


def test_login_then_cookie_session_round_trip(client, user, sign_jwt, provider):
    token = sign_jwt(sub=str(user.id))
    provider.respond(200, {"access_token": token, "expires_in": 600})

    login = client.post(LOGIN_URL, json=CREDENTIALS)
    cookie_value = _session_cookie(login)[COOKIE_NAME].value

    # TestClient talks plain http, so replay the Secure cookie explicitly like a browser over https would.
    me = client.get("/api/me", headers={"Cookie": f"{COOKIE_NAME}={cookie_value}"})

    assert me.status_code == 200
    assert me.json()["id"] == str(user.id)


def test_bearer_header_takes_precedence_over_cookie(client, user, user2, sign_jwt):
    bearer = sign_jwt(sub=str(user.id))
    cookie = sign_jwt(sub=str(user2.id))

    response = client.get(
        "/api/me",
        headers={"Authorization": f"Bearer {bearer}", "Cookie": f"{COOKIE_NAME}={cookie}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == str(user.id)


def test_invalid_session_cookie_is_rejected(client):
    response = client.get("/api/me", headers={"Cookie": f"{COOKIE_NAME}=not-a-jwt"})

    assert response.status_code == 401


def test_expired_session_cookie_is_rejected(client, user, sign_jwt):
    token = sign_jwt(sub=str(user.id), exp_delta_seconds=-10)

    response = client.get("/api/me", headers={"Cookie": f"{COOKIE_NAME}={token}"})

    assert response.status_code == 401


def test_cookie_session_blocks_cross_origin_unsafe_requests(client, user, sign_jwt, monkeypatch):
    monkeypatch.setattr(settings, "cors_allowed_origins", ["https://app.waxwatch.example"])
    token = sign_jwt(sub=str(user.id))
    cookie_header = {"Cookie": f"{COOKIE_NAME}={token}"}

    denied = client.post("/api/me/logout", headers={**cookie_header, "Origin": "https://evil.example"})
    allowed = client.post(
        "/api/me/logout", headers={**cookie_header, "Origin": "https://app.waxwatch.example"}
    )
    same_origin = client.post("/api/me/logout", headers={**cookie_header, "Origin": "http://testserver"})
    safe_method = client.get("/api/me", headers={**cookie_header, "Origin": "https://evil.example"})

    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "origin_not_allowed"
    assert allowed.status_code == 200
    assert same_origin.status_code == 200
    assert safe_method.status_code == 200


def test_bearer_requests_skip_cookie_origin_check(client, user, headers, monkeypatch):
    monkeypatch.setattr(settings, "cors_allowed_origins", [])

    response = client.post(
        "/api/me/logout", headers={**headers(user.id), "Origin": "https://native-shell.example"}
    )

    assert response.status_code == 200


def test_logout_clears_session_cookie(client, user, sign_jwt):
    token = sign_jwt(sub=str(user.id))

    response = client.post("/api/me/logout", headers={"Cookie": f"{COOKIE_NAME}={token}"})

    assert response.status_code == 200
    morsel = _session_cookie(response)[COOKIE_NAME]
    assert morsel.value == ""
    assert morsel["max-age"] == "0"
    assert morsel["httponly"] is True
    assert morsel["path"] == "/"


def test_deactivate_clears_session_cookie(client, user, sign_jwt):
    token = sign_jwt(sub=str(user.id))

    response = client.delete("/api/me", headers={"Cookie": f"{COOKIE_NAME}={token}"})

    assert response.status_code == 200
    assert _session_cookie(response)[COOKIE_NAME]["max-age"] == "0"
