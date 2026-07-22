"""Pytest fixtures for black-box HTTP integration tests. Boots the real
FastAPI app via uvicorn as a subprocess on a test port (4397, distinct from
the dev port 4301) against the live shared Postgres DB, then yields an
httpx.Client with cookie persistence. Test rows are marked with an
`@integration.local` email domain and cleaned up at session end."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import asyncpg
import httpx
import pytest

TEST_PORT = 4397
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"
TEST_DOMAIN = "@integration.local"

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _database_url() -> str:
    from app.core.config import settings

    return settings.database_url


async def _cleanup() -> None:
    conn = await asyncpg.connect(_database_url())
    try:
        await conn.execute("DELETE FROM user_verifications WHERE identifier LIKE '%integration.local%'")
        await conn.execute("DELETE FROM users WHERE email LIKE '%' || $1", TEST_DOMAIN)
    finally:
        await conn.close()


def _wait_for_server(timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{BASE_URL}/api/health", timeout=1.0)
            if resp.status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    return False


@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture(scope="session")
def test_domain() -> str:
    return TEST_DOMAIN


@pytest.fixture(scope="session", autouse=True)
def server():
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(TEST_PORT)],
        cwd=str(PROJECT_ROOT),
    )
    try:
        if not _wait_for_server():
            proc.kill()
            proc.wait()
            pytest.exit("server did not become healthy in time")
        yield proc
    finally:
        proc.kill()
        proc.wait()
        import asyncio

        asyncio.run(_cleanup())


@pytest.fixture
def client():
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as c:
        yield c


async def _insert_verified_user_async(password: str, email: str, role: str) -> str:
    from app.core.security import hash_password

    conn = await asyncpg.connect(_database_url())
    try:
        user_id = await conn.fetchval(
            """
            INSERT INTO users (email, email_verified, first_name, last_name, phone, status, role)
            VALUES ($1, true, 'Py', 'Admin', '9000000098', 'active', $2)
            RETURNING id
            """,
            email,
            role,
        )
        password_hash = hash_password(password)
        await conn.execute(
            """
            INSERT INTO user_accounts (account_id, provider_id, user_id, password, updated_at)
            VALUES ($1, 'credential', $1, $2, now())
            """,
            user_id,
            password_hash,
        )
        return user_id
    finally:
        await conn.close()


def insert_verified_admin(password: str, email: str, role: str = "ADMIN") -> str:
    """Directly inserts a fully-verified, active admin-role user + credential
    account (bypassing register/OTP) so authenticated-flow tests don't depend
    on reading real email OTPs. Returns the user id."""
    import asyncio

    return asyncio.run(_insert_verified_user_async(password, email, role))


def unique_email(prefix: str) -> str:
    return f"{prefix}-{int(time.time() * 1_000_000)}{TEST_DOMAIN}"
