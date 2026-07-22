"""Google OIDC (PKCE) — ports Go internal/lib/authlib/google.go / oauth.go.

Uses authlib's low-level AsyncOAuth2Client (not the Starlette/FastAPI
integration) so PKCE verifier + state + nonce travel in the signed
`next_oauth` cookie rather than a server-side session, matching Go/express.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from fastapi import Request
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import KeySet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import STATUS_ACTIVE, User, UserAccount
from app.services import session_service
from app.services.common import log_activity, to_safe_user
from app.utils.client_info import ClientInfo, get_client_ip
from app.utils.response import ApiResult, err, ok

_GOOGLE_ISSUER = "https://accounts.google.com"
_DISCOVERY_URL = f"{_GOOGLE_ISSUER}/.well-known/openid-configuration"

_discovery_cache: dict | None = None
_discovery_cached_at: float = 0.0
_jwks_cache: KeySet | None = None
_jwks_cached_at: float = 0.0
_CACHE_TTL = 3600


async def _discovery() -> dict:
    global _discovery_cache, _discovery_cached_at
    if _discovery_cache is not None and time.time() - _discovery_cached_at < _CACHE_TTL:
        return _discovery_cache
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(_DISCOVERY_URL)
        resp.raise_for_status()
        _discovery_cache = resp.json()
        _discovery_cached_at = time.time()
        return _discovery_cache


async def _jwks(jwks_uri: str) -> KeySet:
    global _jwks_cache, _jwks_cached_at
    if _jwks_cache is not None and time.time() - _jwks_cached_at < _CACHE_TTL:
        return _jwks_cache
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        _jwks_cache = KeySet.import_key_set(resp.json())
        _jwks_cached_at = time.time()
        return _jwks_cache


def _random_url_safe(n: int) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(n)).rstrip(b"=").decode()


def _redirect_uri() -> str:
    return f"{settings.api_url}/api/auth/google/callback"


@dataclass
class OAuthState:
    state: str
    nonce: str
    code_verifier: str


async def build_google_auth_url(client_id: str, client_secret: str) -> tuple[str, OAuthState]:
    if not client_id or not client_secret:
        raise ValueError("Google OAuth credentials not configured")

    discovery = await _discovery()
    state = _random_url_safe(32)
    nonce = _random_url_safe(32)
    code_verifier = _random_url_safe(48)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": _redirect_uri(),
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = f"{discovery['authorization_endpoint']}?{urllib.parse.urlencode(params)}"
    return url, OAuthState(state=state, nonce=nonce, code_verifier=code_verifier)


@dataclass
class GoogleUser:
    sub: str
    email: str
    email_verified: bool
    name: str
    given_name: str
    family_name: str
    picture: str


async def _exchange_code(discovery: dict, client_id: str, client_secret: str, code: str, code_verifier: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            discovery["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _redirect_uri(),
                "client_id": client_id,
                "client_secret": client_secret,
                "code_verifier": code_verifier,
            },
        )
        resp.raise_for_status()
        return resp.json()


async def handle_google_callback(client_id: str, client_secret: str, code: str, state: OAuthState) -> GoogleUser:
    discovery = await _discovery()
    token_response = await _exchange_code(discovery, client_id, client_secret, code, state.code_verifier)

    raw_id_token = token_response.get("id_token")
    if not raw_id_token:
        raise ValueError("no id_token in response")

    key_set = await _jwks(discovery["jwks_uri"])
    token = joserfc_jwt.decode(raw_id_token, key_set)
    claims = token.claims

    if claims.get("iss") not in (_GOOGLE_ISSUER, "accounts.google.com"):
        raise ValueError("invalid issuer")
    if claims.get("aud") != client_id:
        raise ValueError("invalid audience")
    if claims.get("exp", 0) < time.time():
        raise ValueError("id_token expired")
    if claims.get("nonce") != state.nonce:
        raise ValueError("nonce mismatch")

    return GoogleUser(
        sub=claims.get("sub", ""), email=claims.get("email", ""), email_verified=bool(claims.get("email_verified")),
        name=claims.get("name", ""), given_name=claims.get("given_name", ""),
        family_name=claims.get("family_name", ""), picture=claims.get("picture", ""),
    )


async def process_google_login(db: AsyncSession, request: Request, google_user: GoogleUser, ci: ClientInfo) -> ApiResult:
    if not google_user.email or not google_user.email_verified:
        return err(400, "Google account email is not verified")

    existing_account = (
        await db.execute(select(UserAccount).where(UserAccount.provider_id == "google", UserAccount.account_id == google_user.sub))
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if existing_account is not None:
        user_id = existing_account.user_id
    else:
        existing_user = (await db.execute(select(User).where(User.email == google_user.email))).scalar_one_or_none()
        if existing_user is not None:
            user_id = existing_user.id
        else:
            first_name = google_user.given_name or google_user.name or "User"
            user_id = str(uuid.uuid4())
            db.add(User(
                id=user_id, email=google_user.email, email_verified=True,
                first_name=first_name, last_name=google_user.family_name or "",
                image=google_user.picture or None, registered_ip=get_client_ip(request),
                created_at=now, updated_at=now, role="USER", status=STATUS_ACTIVE,
            ))
            await db.flush()
        db.add(UserAccount(
            id=str(uuid.uuid4()), account_id=google_user.sub, provider_id="google", user_id=user_id,
            created_at=now, updated_at=now,
        ))
        await db.commit()

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or user.status != STATUS_ACTIVE:
        return err(403, "Account is disabled")

    token, _ = await session_service.issue_session(db, request, user_id, True)
    await log_activity(db, "LOGIN_SUCCESS", user_id, ci)
    return ok("Login successful", {"token": token, "user": to_safe_user(user)})
