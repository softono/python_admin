"""WebAuthn (passkeys) — ports Go internal/lib/authlib/webauthn.go +
internal/modules/auth/passkey.go, using the `webauthn` (py_webauthn) library.

Column contract (must match Go/express so passkeys interop across ports):
`user_passkeys.credential_id` and `.public_key` are base64url (no padding) of
the RAW bytes — the credential ID bytes and the raw CBOR/COSE public key
bytes exactly as parsed from the attestation object — NOT any PEM/DER
re-encoding. `VerifiedRegistration.credential_id` / `.credential_public_key`
from py_webauthn are already these raw byte forms (same as go-webauthn's
`Credential.ID` / `.PublicKey`), so we only base64url-encode/decode at the
storage boundary, never re-derive or re-serialize the key material.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import settings
from app.models.models import STATUS_ACTIVE, User, UserPasskey
from app.services import session_service
from app.services.challenge_service import consume_webauthn_challenge, create_webauthn_challenge
from app.services.common import log_activity, to_safe_user
from app.utils.client_info import ClientInfo
from app.utils.response import ApiResult, err, ok


def _rp_id() -> str:
    return settings.webauthn_rp_id


def _origin() -> str:
    return settings.webauthn_origin


async def _existing_credentials(db: AsyncSession, user_id: str) -> list[PublicKeyCredentialDescriptor]:
    rows = (await db.execute(select(UserPasskey).where(UserPasskey.user_id == user_id))).scalars().all()
    return [PublicKeyCredentialDescriptor(id=base64url_to_bytes(pk.credential_id)) for pk in rows]


async def register_options(db: AsyncSession, user_id: str) -> ApiResult:
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        return err(404, "User not found")

    exclude = await _existing_credentials(db, user_id)
    options = generate_registration_options(
        rp_id=_rp_id(),
        rp_name=settings.app_name,
        user_name=user.email,
        # Registration userID = UTF-8 bytes of the user's UUID string — per
        # project convention, matching Go's WebAuthnUser.ID = []byte(u.ID).
        user_id=user.id.encode("utf-8"),
        user_display_name=f"{user.first_name} {user.last_name}".strip(),
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    handle = await create_webauthn_challenge(bytes_to_base64url(options.challenge))
    return ok("ok", {"options": json.loads(options_to_json(options)), "challengeHandle": handle})


async def register_verify(db: AsyncSession, user_id: str, response_raw: dict, challenge_handle: str, name: str, ci: ClientInfo) -> ApiResult:
    challenge_b64 = await consume_webauthn_challenge(challenge_handle)
    if not challenge_b64:
        return err(400, "No challenge found")

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        return err(404, "User not found")

    try:
        verified = verify_registration_response(
            credential=json.dumps(response_raw),
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
        )
    except (InvalidRegistrationResponse, Exception):
        return err(400, "Passkey verification failed")

    device_type = "multiDevice" if verified.credential_device_type == "multi_device" else "singleDevice"
    transports = response_raw.get("response", {}).get("transports") or []

    now = datetime.now(timezone.utc)
    db.add(UserPasskey(
        id=str(uuid.uuid4()),
        name=name or None,
        public_key=bytes_to_base64url(verified.credential_public_key),
        user_id=user_id,
        credential_id=bytes_to_base64url(verified.credential_id),
        counter=verified.sign_count,
        device_type=device_type,
        backed_up=bool(verified.credential_backed_up),
        transports=",".join(transports) if transports else None,
        created_at=now,
        aaguid=verified.aaguid,
    ))
    await db.commit()

    await log_activity(db, "PASSKEY_ADDED", user_id, ci)
    return ok("Passkey added")


async def list_passkeys(db: AsyncSession, user_id: str) -> ApiResult:
    rows = (await db.execute(select(UserPasskey).where(UserPasskey.user_id == user_id))).scalars().all()
    return ok("ok", [
        {"id": pk.id, "name": pk.name or "", "device_type": pk.device_type, "created_at": pk.created_at}
        for pk in rows
    ])


async def delete_passkey(db: AsyncSession, ci: ClientInfo, user_id: str, passkey_id: str) -> ApiResult:
    row = (
        await db.execute(select(UserPasskey).where(UserPasskey.id == passkey_id, UserPasskey.user_id == user_id))
    ).scalar_one_or_none()
    if row is None:
        return err(404, "Passkey not found")
    await db.delete(row)
    await db.commit()
    await log_activity(db, "PASSKEY_DELETED", user_id, ci)
    return ok("Passkey deleted")


# --- Login (discoverable / usernameless) ---

async def login_options() -> ApiResult:
    options = generate_authentication_options(
        rp_id=_rp_id(),
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    handle = await create_webauthn_challenge(bytes_to_base64url(options.challenge))
    return ok("ok", {"options": json.loads(options_to_json(options)), "challengeHandle": handle})


async def login_verify(db: AsyncSession, request: Request, response_raw: dict, challenge_handle: str, ci: ClientInfo) -> ApiResult:
    challenge_b64 = await consume_webauthn_challenge(challenge_handle)
    if not challenge_b64:
        return err(400, "No challenge found")

    raw_id = response_raw.get("rawId") or response_raw.get("id")
    if not raw_id:
        return err(400, "Invalid passkey response")
    # Normalize to canonical base64url (no padding) to match the storage
    # encoding regardless of the browser's exact base64url formatting.
    cred_id_b64url = bytes_to_base64url(base64url_to_bytes(raw_id))
    passkey = (
        await db.execute(select(UserPasskey).where(UserPasskey.credential_id == cred_id_b64url))
    ).scalar_one_or_none()
    if passkey is None:
        return err(401, "Passkey login failed")

    user = (await db.execute(select(User).where(User.id == passkey.user_id))).scalar_one_or_none()
    if user is None:
        return err(401, "Passkey login failed")

    try:
        verified = verify_authentication_response(
            credential=response_raw,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
            credential_public_key=base64url_to_bytes(passkey.public_key),
            credential_current_sign_count=passkey.counter,
        )
    except (InvalidAuthenticationResponse, Exception):
        return err(401, "Passkey login failed")

    passkey.counter = verified.new_sign_count
    await db.commit()

    if user.status != STATUS_ACTIVE:
        return err(403, "Account is disabled")

    token, _ = await session_service.issue_session(db, request, user.id, True)
    await log_activity(db, "LOGIN_WITH_SOCIAL", user.id, ci)
    return ok("Login successful", {"token": token, "user": to_safe_user(user)})
