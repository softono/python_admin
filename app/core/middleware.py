"""ASGI middleware: device-uid cookie issuance + proxy.ts-parity rate limit."""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.cache import incr_cache
from app.core.config import settings
from app.core.security import COOKIE_DEVICE_UID, random_alnum
from app.utils.client_info import get_client_ip

_IS_PROD = settings.app_env == "production"

_LOGIN_PREFIXES = ("/api/auth/login", "/api/admin/auth/login")
_STRICT_PREFIXES = (
    "/api/auth/register", "/api/auth/otp", "/api/auth/login-otp", "/api/auth/tfa",
    "/api/auth/forgot-password", "/api/auth/reset-password", "/api/auth/verify-account",
)


class DeviceCookieMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        uid = request.cookies.get(COOKIE_DEVICE_UID)
        response: Response = await call_next(request)
        if not uid:
            new_uid = random_alnum(64)
            response.set_cookie(
                COOKIE_DEVICE_UID, new_uid, max_age=31536000, httponly=True,
                samesite="lax", secure=_IS_PROD, path="/",
            )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        limit = 0
        if any(path.startswith(p) for p in _LOGIN_PREFIXES):
            limit = 10
        elif any(path.startswith(p) for p in _STRICT_PREFIXES):
            limit = 5

        if limit == 0:
            return await call_next(request)

        key = f"{path}:{get_client_ip(request)}"
        count, ttl = await incr_cache(key, 15 * 60)
        if count > limit:
            return JSONResponse(
                status_code=429,
                content={"status": 0, "message": "Too many requests, please try again later.", "data": []},
                headers={
                    "Retry-After": str(ttl),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(ttl),
                },
            )
        return await call_next(request)
