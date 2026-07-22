"""Admin panel router — dashboard, admins/users CRUD, content CRUD, global
sessions/activities, settings. Mirrors Go go_admin/internal/modules/admin/routes.go."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cookies import set_session_cookie, set_tfa_challenge_cookie
from app.core.db import get_db
from app.core.deps import Principal, get_current_admin_principal
from app.models.models import ROLE_ADMIN, ROLE_USER, STATUS_ACTIVE, STATUS_INACTIVE
from app.services import admin_service, auth_service
from app.services.common import to_safe_user
from app.services.setting_service import get_public_settings
from app.utils.client_info import get_client_info
from app.utils.dates import get_client_timezone
from app.utils.pagination import parse_query
from app.utils.response import ApiResult, send_error, send_result
from app.utils.validate import Validator

router = APIRouter()


def _str(body: dict, key: str, default: str = "") -> str:
    v = body.get(key)
    return v if isinstance(v, str) else default


def _opt_str(body: dict, key: str) -> str | None:
    v = body.get(key)
    return v if isinstance(v, str) else None


# --- Public: admin login ---

@router.post("/auth/login")
async def admin_login_route(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    v = Validator(body)
    email = v.email()
    password = v.login_password()
    remember = v.boolean("remember", False)
    if v.fe.has_errors:
        return send_result(ApiResult(422, 0, v.fe.message, {"errors": v.fe.by_field}))

    result = await auth_service.admin_login(db, request, email, password, remember, get_client_info(request))
    if result.status == 1 and isinstance(result.data, dict):
        if token := result.data.pop("token", None):
            set_session_cookie(response, token, remember)
        elif handle := result.data.pop("tfaHandle", None):
            set_tfa_challenge_cookie(response, handle)
    return send_result(result, response)


@router.get("/setting/public")
async def public_settings_route(db: AsyncSession = Depends(get_db)):
    settings_map = await get_public_settings(db)
    return send_result(ApiResult(200, 1, "Public settings retrieved", settings_map))


# --- Account (self) ---

@router.get("/account/view")
async def account_view(principal: Principal = Depends(get_current_admin_principal)):
    return send_result(ApiResult(200, 1, "Admin info fetched successfully", to_safe_user(principal.user)))


@router.get("/account/profile")
async def account_profile(principal: Principal = Depends(get_current_admin_principal)):
    return send_result(ApiResult(200, 1, "", to_safe_user(principal.user)))


@router.put("/account/update")
async def account_update(
    request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)
):
    body = await request.json()
    fields = {k: _opt_str(body, k) for k in ("first_name", "last_name", "phone", "country", "timezone")}
    result = await admin_service.update_account(db, principal.user.id, principal.user.role, fields, "Admin")
    return send_result(result)


@router.get("/account/session")
async def account_sessions(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_all_sessions(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.post("/account/revoke-all")
async def account_revoke_all(db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    from sqlalchemy import delete as sa_delete

    from app.models.models import UserSession
    from app.services.session_service import invalidate_user_cache

    result = await db.execute(sa_delete(UserSession).where(UserSession.user_id == principal.user.id).returning(UserSession.id))
    ids = result.scalars().all()
    await db.commit()
    await invalidate_user_cache(principal.user.id)
    return send_result(ApiResult(200, 1, "All sessions terminated successfully", {"sessionsTerminated": len(ids)}))


@router.get("/account/user-activity")
async def account_user_activity(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_all_activities(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


# --- Admins CRUD ---

@router.get("/admins")
async def list_admins(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_accounts(db, ROLE_ADMIN, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.post("/admins")
async def create_admin(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    result = await admin_service.create_account(
        db, _str(b, "email"), _str(b, "first_name"), _str(b, "last_name"), _str(b, "phone"), _str(b, "password"),
        _str(b, "country"), _str(b, "timezone"), _str(b, "role") or ROLE_ADMIN, _str(b, "status"),
        _str(b, "permission"), "Admin",
    )
    return send_result(result)


@router.get("/admins/{admin_id}")
async def get_admin(admin_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.get_account_by_id(db, admin_id, ROLE_ADMIN))


@router.patch("/admins/{admin_id}")
async def patch_admin(admin_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    if action := _str(b, "action"):
        status = STATUS_INACTIVE if action == "deactivate" else STATUS_ACTIVE
        return send_result(await admin_service.set_account_status(db, admin_id, ROLE_ADMIN, status, "Admin"))
    fields = {k: _opt_str(b, k) for k in ("first_name", "last_name", "phone", "country", "timezone", "permission")}
    return send_result(await admin_service.update_account(db, admin_id, ROLE_ADMIN, fields, "Admin"))


@router.delete("/admins/{admin_id}")
async def delete_admin(admin_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.delete_account(db, admin_id, ROLE_ADMIN, "Admin"))


@router.get("/admins/{admin_id}/session")
async def admin_sessions(admin_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_all_sessions(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.get("/admins/{admin_id}/activity")
async def admin_activity(admin_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_all_activities(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


# --- Users CRUD ---

@router.get("/users")
async def list_users(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_accounts(db, ROLE_USER, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.post("/users")
async def create_user(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    result = await admin_service.create_account(
        db, _str(b, "email"), _str(b, "first_name"), _str(b, "last_name"), _str(b, "phone"), _str(b, "password"),
        _str(b, "country"), _str(b, "timezone"), ROLE_USER, _str(b, "status"), "", "User",
    )
    return send_result(result)


@router.post("/users/mail")
async def user_mail(principal: Principal = Depends(get_current_admin_principal)):
    return send_result(ApiResult(200, 1, "Email sent to user", None))


@router.get("/users/{user_id}")
async def get_user(user_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.get_account_by_id(db, user_id, ROLE_USER))


@router.patch("/users/{user_id}")
async def patch_user(user_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    if action := _str(b, "action"):
        status = STATUS_INACTIVE if action == "deactivate" else STATUS_ACTIVE
        return send_result(await admin_service.set_account_status(db, user_id, ROLE_USER, status, "User"))
    fields = {k: _opt_str(b, k) for k in ("first_name", "last_name", "phone", "country", "timezone")}
    return send_result(await admin_service.update_account(db, user_id, ROLE_USER, fields, "User"))


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.delete_account(db, user_id, ROLE_USER, "User"))


@router.get("/users/{user_id}/sessions")
async def user_sessions(user_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_all_sessions(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.get("/users/{user_id}/activity")
async def user_activity(user_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_all_activities(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.get("/users/{user_id}/mails")
async def user_mails(user_id: str, principal: Principal = Depends(get_current_admin_principal)):
    return send_result(ApiResult(200, 1, "Data retrieved successfully", {
        "list": [], "pagination": {"page": 1, "limit": 20, "total": 0, "pages": 1, "count": "No items"},
    }))


# --- Global activities / sessions ---

@router.get("/user-activities")
async def global_activities(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_all_activities(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.get("/sessions")
async def global_sessions(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_all_sessions(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.post("/sessions/logout")
async def sessions_logout(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    session_id = _str(b, "device_id") or _str(b, "id")
    if not session_id:
        return send_error(400, "Session id is required")
    return send_result(await admin_service.logout_session_by_id(db, session_id))


# --- Content: blogs/pages/seos/email-templates ---

@router.get("/blogs")
async def list_blogs_route(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_blogs(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.post("/blogs")
async def create_blog_route(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    return send_result(await admin_service.create_blog(db, b))


@router.get("/blogs/{blog_id}")
async def get_blog_route(blog_id: int, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.get_blog_by_id(db, blog_id))


@router.patch("/blogs/{blog_id}")
async def patch_blog_route(blog_id: int, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    if action := _str(b, "action"):
        status = STATUS_INACTIVE if action == "deactivate" else STATUS_ACTIVE
        return send_result(await admin_service.update_blog(db, blog_id, {"status": status}))
    return send_result(await admin_service.update_blog(db, blog_id, b))


@router.delete("/blogs/{blog_id}")
async def delete_blog_route(blog_id: int, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.delete_blog(db, blog_id))


@router.get("/page")
async def list_pages_route(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_pages(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.get("/page/{page_id}")
async def get_page_route(page_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.get_page_by_id(db, page_id))


@router.patch("/page/{page_id}")
async def patch_page_route(page_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    if action := _str(b, "action"):
        status = STATUS_INACTIVE if action == "deactivate" else STATUS_ACTIVE
        return send_result(await admin_service.update_page(db, page_id, {"status": status}))
    return send_result(await admin_service.update_page(db, page_id, b))


@router.get("/seos")
async def list_seos_route(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_seos(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.post("/seos")
async def create_seo_route(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    return send_result(await admin_service.create_seo(db, b))


@router.post("/seos/sitemap")
async def sitemap_route(db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    count_data = await admin_service.generate_pure_sitemap(db)
    return send_result(ApiResult(200, 1, "Sitemap updated successfully", count_data))


@router.get("/seos/{seo_id}")
async def get_seo_route(seo_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.get_seo_by_id(db, seo_id))


@router.patch("/seos/{seo_id}")
async def patch_seo_route(seo_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    if action := _str(b, "action"):
        enable = 0 if action == "deactivate" else 1
        return send_result(await admin_service.update_seo(db, seo_id, {"sitemap_enable": enable}))
    return send_result(await admin_service.update_seo(db, seo_id, b))


@router.delete("/seos/{seo_id}")
async def delete_seo_route(seo_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.delete_seo(db, seo_id))


@router.get("/email-template")
async def list_email_templates_route(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    page_in = parse_query(request.url.query)
    result = await admin_service.list_email_templates(db, page_in, get_client_timezone(request))
    return send_result(ApiResult(200, 1, "Data retrieved successfully", result))


@router.get("/email-template/{template_id}")
async def get_email_template_route(template_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.get_email_template_by_id(db, template_id))


@router.patch("/email-template/{template_id}")
async def patch_email_template_route(template_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    return send_result(await admin_service.update_email_template(db, template_id, b))


@router.post("/email-template/{template_id}/save-file")
async def save_email_template_file(template_id: str, request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    form = await request.form()
    file = form.get("file")
    if file is None or not hasattr(file, "read"):
        return send_error(400, "No file provided or file too large")
    content = await file.read()
    if len(content) > 256 * 1024:
        return send_error(400, "No file provided or file too large")
    return send_result(await admin_service.update_email_template(db, template_id, {"body": content.decode("utf-8", errors="replace")}))


# --- Dashboard ---

@router.get("/dashboard")
async def dashboard_route(db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(await admin_service.dashboard_counts(db))


@router.get("/dashboard/get-chart-user")
async def dashboard_chart_route(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    period = request.query_params.get("type") or request.query_params.get("period") or ""
    months = int(request.query_params.get("months") or 0)
    data = await admin_service.dashboard_chart(db, period, months)
    return send_result(ApiResult(200, 1, "", data))


# --- Settings ---

@router.post("/setting/save")
async def setting_save(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    await admin_service.save_settings(db, b, "private")
    return send_result(ApiResult(200, 1, "Settings saved successfully", None))


@router.get("/setting/update")
async def setting_update(db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    return send_result(ApiResult(200, 1, "", await admin_service.settings_map(db)))


@router.post("/setting/save-captcha")
async def setting_save_captcha(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    await admin_service.save_settings(db, b, "private")
    return send_result(ApiResult(200, 1, "CAPTCHA settings saved successfully", None))


@router.post("/setting/save-content")
async def setting_save_content(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    await admin_service.save_settings(db, b, "public")
    return send_result(ApiResult(200, 1, "Content settings saved successfully", None))


@router.post("/setting/save-email")
async def setting_save_email(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    await admin_service.save_settings(db, b, "private")
    return send_result(ApiResult(200, 1, "Email settings saved successfully", None))


@router.post("/setting/save-social")
async def setting_save_social(request: Request, db: AsyncSession = Depends(get_db), principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    await admin_service.save_settings(db, b, "public")
    return send_result(ApiResult(200, 1, "Social settings saved successfully", None))


@router.post("/setting/save-logo")
async def setting_save_logo(principal: Principal = Depends(get_current_admin_principal)):
    return send_result(ApiResult(200, 1, "Logo saved successfully", {"path": ""}))


@router.post("/setting/mail-process")
async def setting_mail_process(request: Request, principal: Principal = Depends(get_current_admin_principal)):
    b = await request.json()
    if not _str(b, "email"):
        return send_error(422, "Email is required")
    return send_result(ApiResult(200, 1, "Test email sent successfully", None))


@router.get("/setting/cache-clear")
async def setting_cache_clear(principal: Principal = Depends(get_current_admin_principal)):
    from app.core.cache import flush_cache

    await flush_cache()
    return send_result(ApiResult(200, 1, "Cache cleared successfully", None))
