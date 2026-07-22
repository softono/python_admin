"""FastAPI app assembly for the admin panel service: CORS, device-cookie +
rate-limit middleware, standard-envelope exception handling, route
registration. Mounts /api/admin (admin panel) plus the shared /api/auth
router (session, logout, 2FA/passkey/login-link/oauth management) that both
admin login and the admin account-security pages depend on."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException

from app.api.routes import admin, auth, login_link, oauth, passkey, tfa
from app.core.config import settings
from app.core.middleware import DeviceCookieMiddleware, RateLimitMiddleware
from app.utils.response import send_error

app = FastAPI(title="Next Admin API (Python)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(DeviceCookieMiddleware)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return send_error(exc.status_code, str(exc.detail))


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return send_error(500, "Something went wrong")


@app.get("/api/health")
async def health():
    return {"status": 1, "message": "Ok", "data": []}


# Shared /api/auth router — session lifecycle + 2FA/passkey/login-link/oauth,
# identical to the `python` project's, since admin and user share one
# session model with separate contexts on the frontend side only.
app.include_router(auth.router, prefix="/api/auth")
app.include_router(tfa.router, prefix="/api/auth")
app.include_router(login_link.router, prefix="/api/auth")
app.include_router(oauth.router, prefix="/api/auth")
app.include_router(passkey.router, prefix="/api/auth")

# Admin panel surface (includes its own POST /api/admin/auth/login).
app.include_router(admin.router, prefix="/api/admin")
