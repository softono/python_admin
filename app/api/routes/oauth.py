"""Google OAuth redirect flow — mirrors Go oauth_routes.go."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.cookies import clear_oauth_state_cookie, get_oauth_state, set_oauth_state_cookie, set_session_cookie
from app.core.db import get_db
from app.services import google_oauth_service
from app.services.setting_service import get_all_settings
from app.utils.client_info import get_client_info

router = APIRouter()


@router.get("/google")
async def google_start(db: AsyncSession = Depends(get_db)):
    settings_map = await get_all_settings(db)
    try:
        url, state = await google_oauth_service.build_google_auth_url(
            settings_map.get("google_client_id", ""), settings_map.get("google_client_secret", "")
        )
    except Exception:
        return RedirectResponse(f"{settings.app_url}/login?error=oauth_unavailable", status_code=302)

    response = RedirectResponse(url, status_code=302)
    set_oauth_state_cookie(response, state.state, state.nonce, state.code_verifier)
    return response


@router.get("/google/callback")
async def google_callback(request: Request, db: AsyncSession = Depends(get_db)):
    oauth_state = get_oauth_state(request)
    if not oauth_state:
        return RedirectResponse(f"{settings.app_url}/login?error=invalid_state", status_code=302)

    code = request.query_params.get("code", "")
    settings_map = await get_all_settings(db)
    state = google_oauth_service.OAuthState(
        state=oauth_state["state"], nonce=oauth_state["nonce"], code_verifier=oauth_state["codeVerifier"]
    )

    try:
        google_user = await google_oauth_service.handle_google_callback(
            settings_map.get("google_client_id", ""), settings_map.get("google_client_secret", ""), code, state
        )
        result = await google_oauth_service.process_google_login(db, request, google_user, get_client_info(request))
    except Exception:
        result = None

    response = RedirectResponse(settings.app_url, status_code=302)
    clear_oauth_state_cookie(response)
    if result is not None and result.status == 1 and isinstance(result.data, dict):
        if token := result.data.get("token"):
            set_session_cookie(response, token, True)
        return response

    message = result.message if result is not None else "Google sign-in failed"
    return RedirectResponse(f"{settings.app_url}/login?error={message}", status_code=302)
