from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

# --- Test auth material (must be defined before app import/settings init) ---
TEST_KID = "test-signing-key"
AUTH_ISSUER = "http://127.0.0.1:8765/auth/v1"
AUTH_AUDIENCE = "authenticated"
AUTH_JWKS_URL = f"{AUTH_ISSUER}/.well-known/jwks.json"

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_KEY_PEM = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
PUBLIC_JWK = json.loads(RSAAlgorithm.to_jwk(_private_key.public_key()))
PUBLIC_JWK["kid"] = TEST_KID
PUBLIC_JWK["alg"] = "RS256"
PUBLIC_JWK["use"] = "sig"
JWKS_PAYLOAD = {"keys": [PUBLIC_JWK]}

# --- Force test settings early (before app import) ---
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault("JSON_LOGS", "false")
os.environ.setdefault("PROVIDER_FORCE_MOCK", "1")

os.environ.setdefault("DISCOGS_USER_AGENT", "test-agent")
os.environ.setdefault("DISCOGS_TOKEN", "test-token")
os.environ.setdefault("TOKEN_CRYPTO_LOCAL_KEY", "5pq6kEUS_UIk1_4qatN-Lx42s3e362VNq5CgyI4LAZU=")

os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "true")
os.environ.setdefault("CELERY_TASK_EAGER_PROPAGATES", "true")
os.environ.setdefault("DB_POOL", "queue")
os.environ.setdefault("DB_POOL_SIZE", "5")
os.environ.setdefault("DB_MAX_OVERFLOW", "10")

os.environ.setdefault("AUTH_ISSUER", AUTH_ISSUER)
os.environ.setdefault("AUTH_AUDIENCE", AUTH_AUDIENCE)
os.environ.setdefault("AUTH_JWKS_URL", AUTH_JWKS_URL)
os.environ.setdefault("AUTH_JWT_ALGORITHMS", '["RS256"]')
# Keep auth-expiry tests deterministic: avoid leeway masking short-expired tokens.
os.environ["AUTH_CLOCK_SKEW_SECONDS"] = "0"

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL must be set for tests (point it to a Postgres DB).")

from app.api.deps import get_db  # noqa: E402
from app.db.models import User  # noqa: E402
from app.main import create_app  # noqa: E402

SHARD_INDEX_ENV = "PYTEST_SHARD_INDEX"
SHARD_TOTAL_ENV = "PYTEST_SHARD_TOTAL"


def shard_settings_from_env(environ: Mapping[str, str] = os.environ) -> tuple[int, int] | None:
    """Return the (1-based index, total) CI shard selection, or None when sharding is off.

    Both variables unset/empty (or a total of 1) means "run everything", which keeps
    `make ci-db-tests` / `make ci-local` unsharded by default.
    """
    raw_index = (environ.get(SHARD_INDEX_ENV) or "").strip()
    raw_total = (environ.get(SHARD_TOTAL_ENV) or "").strip()
    if not raw_index and not raw_total:
        return None
    try:
        index = int(raw_index)
        total = int(raw_total)
    except ValueError as exc:
        raise pytest.UsageError(
            f"{SHARD_INDEX_ENV} and {SHARD_TOTAL_ENV} must both be integers (got {raw_index!r}/{raw_total!r})"
        ) from exc
    if total < 1 or not 1 <= index <= total:
        raise pytest.UsageError(
            f"{SHARD_INDEX_ENV} must be within 1..{SHARD_TOTAL_ENV} (got {index}/{total})"
        )
    if total == 1:
        return None
    return index, total


def assign_files_to_shards(file_weights: dict[str, int], total: int) -> dict[str, int]:
    """Deterministically map test files to 1-based shards, balancing by weight.

    Greedy longest-processing-time: heaviest files first (ties broken by path), each placed on
    the currently lightest shard (ties broken by lowest shard index). Whole files stay together so
    module-level fixtures and intra-file ordering behave exactly as in an unsharded run.
    """
    loads = [0] * total
    assignment: dict[str, int] = {}
    for path, weight in sorted(file_weights.items(), key=lambda kv: (-kv[1], kv[0])):
        shard = min(range(total), key=lambda i: (loads[i], i))
        loads[shard] += weight
        assignment[path] = shard + 1
    return assignment


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    # trylast: run after marker (-m) / keyword (-k) deselection so weights reflect the selected tests.
    settings = shard_settings_from_env()
    if settings is None:
        return
    index, total = settings

    file_weights: dict[str, int] = {}
    for item in items:
        path = item.nodeid.split("::", 1)[0]
        file_weights[path] = file_weights.get(path, 0) + 1
    assignment = assign_files_to_shards(file_weights, total)

    selected = [item for item in items if assignment[item.nodeid.split("::", 1)[0]] == index]
    deselected = [item for item in items if assignment[item.nodeid.split("::", 1)[0]] != index]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected


def pytest_report_header(config: pytest.Config) -> str | None:
    settings = shard_settings_from_env()
    if settings is None:
        return None
    return f"ci shard: {settings[0]}/{settings[1]} (files balanced by test count)"


engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)
SessionTesting = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class _JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/auth/v1/.well-known/jwks.json":
            body = json.dumps(JWKS_PAYLOAD).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):
        return


@pytest.fixture(scope="session", autouse=True)
def jwks_server() -> Iterator[None]:
    server = HTTPServer(("127.0.0.1", 8765), _JWKSHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    time.sleep(0.05)

    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture(scope="session", autouse=True)
def _smoke_db_connection(jwks_server) -> None:
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))


@pytest.fixture()
def db_session() -> Iterator[Session]:
    connection = engine.connect()
    trans = connection.begin()

    session = SessionTesting(bind=connection)
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def restart_savepoint(sess: Session, txn) -> None:
        if txn.nested and not txn._parent.nested:
            sess.begin_nested()

    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


@pytest.fixture()
def client(db_session: Session) -> Iterator[TestClient]:
    app = create_app()

    def _override_get_db() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def user(db_session: Session) -> User:
    u = User(
        id=uuid.uuid4(),
        email=f"test-{uuid.uuid4()}@example.com",
        hashed_password="not-a-real-hash",
        display_name="Test User",
        is_active=True,
    )
    db_session.add(u)
    db_session.flush()
    return u


@pytest.fixture()
def user2(db_session: Session) -> User:
    u = User(
        id=uuid.uuid4(),
        email=f"test-{uuid.uuid4()}@example.com",
        hashed_password="not-a-real-hash",
        display_name="Other User",
        is_active=True,
    )
    db_session.add(u)
    db_session.flush()
    return u


@pytest.fixture()
def sign_jwt():
    def _sign_jwt(
        *,
        sub: str,
        iss: str = AUTH_ISSUER,
        aud: str = AUTH_AUDIENCE,
        exp_delta_seconds: int = 3600,
        kid: str = TEST_KID,
        extra_claims: dict | None = None,
    ) -> str:
        now = datetime.now(tz=timezone.utc)
        payload = {
            "sub": sub,
            "iss": iss,
            "aud": aud,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=exp_delta_seconds)).timestamp()),
        }
        if extra_claims:
            payload.update(extra_claims)
        return jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256", headers={"kid": kid})

    return _sign_jwt


@pytest.fixture()
def headers():
    def _headers(user_id: uuid.UUID) -> dict[str, str]:
        now = datetime.now(tz=timezone.utc)
        payload = {
            "sub": str(user_id),
            "iss": AUTH_ISSUER,
            "aud": AUTH_AUDIENCE,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "role": "authenticated",
        }
        token = jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256", headers={"kid": TEST_KID})
        return {"Authorization": f"Bearer {token}"}

    return _headers
