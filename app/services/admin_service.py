"""Ports Go go_admin/internal/modules/admin/{admin,content,settings}.go —
dashboard, admins/users CRUD, blogs/pages/seos/email-templates CRUD, global
sessions/activities, settings save/read."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.models import (
    ACTIVITY_LABELS,
    Blog,
    EmailTemplate,
    Page,
    STATUS_ACTIVE,
    STATUS_INACTIVE,
    Seo,
    User,
    UserAccount,
    UserSession,
)
from app.services.common import resolve_user_image, to_safe_user
from app.services.session_service import invalidate_session_cache, invalidate_user_cache
from app.services.setting_service import get_all_settings, update_setting
from app.utils.client_info import device_name
from app.utils.dates import date_time_format
from app.utils.pagination import PageInput, PageOptions, build_filter, paginate
from app.utils.response import ApiResult, err, ok

# --- Dashboard ---


async def dashboard_counts(db: AsyncSession) -> ApiResult:
    total = (await db.execute(select(func.count()).select_from(User).where(User.role == "USER"))).scalar_one()
    active = (
        await db.execute(select(func.count()).select_from(User).where(User.role == "USER", User.status == STATUS_ACTIVE))
    ).scalar_one()
    inactive = (
        await db.execute(select(func.count()).select_from(User).where(User.role == "USER", User.status == STATUS_INACTIVE))
    ).scalar_one()
    return ok("Admin dashboard data retrieved", {"total": total, "active": active, "inactive": inactive})


async def dashboard_chart(db: AsyncSession, period: str, months: int) -> list[dict]:
    period = "daily" if period in ("day", "daily") else "monthly"
    if months <= 0:
        months = 1 if period == "daily" else 12
    months = min(months, 24)

    label_expr = "to_char(created_at, 'YYYY-MM-DD')" if period == "daily" else "to_char(created_at, 'YYYY-MM')"
    rows = (
        await db.execute(
            text(
                f"SELECT {label_expr} AS label, count(*)::int AS count FROM users "
                f"WHERE role = 'USER' AND created_at >= now() - make_interval(months => :months) "
                f"GROUP BY label ORDER BY label"
            ),
            {"months": months},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


# --- Admins / Users CRUD (shared implementation, filtered by role) ---

_ACCOUNT_SORT_MAP = {"name": "first_name", "email": "email", "phone": "phone", "status": "status", "created_at": "created_at"}
_ACCOUNT_FILTER_MAP = {
    "name": ("first_name", "text"),
    "email": ("email", "text"),
    "phone": ("phone", "text"),
    "status": ("status", "multiSelect"),
    "created_at": ("created_at", "date"),
}


async def list_accounts(db: AsyncSession, role: str, page_in: PageInput, tz: str) -> dict:
    base_query = "SELECT id, first_name, last_name, email, phone, image, status, created_at FROM users WHERE role = :role"
    params: dict = {"role": role}
    if page_in.search:
        base_query += " AND (first_name ILIKE :search OR last_name ILIKE :search OR email ILIKE :search)"
        params["search"] = f"%{page_in.search}%"
    filter_sql, filter_params = build_filter(_ACCOUNT_FILTER_MAP, page_in.filter)
    if filter_sql:
        base_query += f" AND {filter_sql}"
        params.update(filter_params)

    def map_row(row: dict) -> dict:
        row["name"] = f"{row.get('first_name', '')} {row.get('last_name', '')}".strip()
        row["image"] = resolve_user_image(row.get("image"))
        row["created_at"] = date_time_format(row["created_at"], tz)
        return row

    return await paginate(db, base_query, params, page_in, PageOptions(
        default_sort_field="created_at", default_sort_dir="desc", sort_map=_ACCOUNT_SORT_MAP, map_row=map_row,
    ))


async def get_account_by_id(db: AsyncSession, account_id: str, role: str) -> ApiResult:
    user = (await db.execute(select(User).where(User.id == account_id))).scalar_one_or_none()
    if user is None or user.role != role:
        return err(404, "Not found")
    return ok("ok", to_safe_user(user))


async def create_account(
    db: AsyncSession, email: str, first_name: str, last_name: str, phone: str, password: str,
    country: str, tz_field: str, role: str, status: str, permission: str, entity_label: str,
) -> ApiResult:
    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing is not None:
        return err(409, "Email already in use")

    now = datetime.now(timezone.utc)
    user = User(
        id=str(uuid.uuid4()), email=email, email_verified=False, first_name=first_name, last_name=last_name,
        phone=phone or None, country=country or None, timezone=tz_field or "UTC", role=role,
        status=status or STATUS_ACTIVE, permission=permission or None, created_at=now, updated_at=now,
    )
    db.add(user)
    await db.flush()
    db.add(UserAccount(
        id=str(uuid.uuid4()), account_id=user.id, provider_id="credential", user_id=user.id,
        password=hash_password(password), created_at=now, updated_at=now,
    ))
    await db.commit()
    return ApiResult(201, 1, f"{entity_label} created successfully", to_safe_user(user))


async def update_account(
    db: AsyncSession, account_id: str, role: str, fields: dict, entity_label: str,
) -> ApiResult:
    user = (await db.execute(select(User).where(User.id == account_id))).scalar_one_or_none()
    if user is None or user.role != role:
        return err(404, f"{entity_label} not found")

    for key in ("first_name", "last_name", "phone", "country", "timezone", "permission"):
        if key in fields and fields[key] is not None:
            setattr(user, key, fields[key])
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await invalidate_user_cache(account_id)
    return ok(f"{entity_label} profile updated successfully", to_safe_user(user))


async def set_account_status(db: AsyncSession, account_id: str, role: str, status: str, entity_label: str) -> ApiResult:
    user = (await db.execute(select(User).where(User.id == account_id))).scalar_one_or_none()
    if user is None or user.role != role:
        return err(404, f"{entity_label} not found")
    user.status = status
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await invalidate_user_cache(account_id)
    action = "deactivated" if status == STATUS_INACTIVE else "activated"
    return ok(f"{entity_label} {action} successfully", to_safe_user(user))


async def delete_account(db: AsyncSession, account_id: str, role: str, entity_label: str) -> ApiResult:
    user = (await db.execute(select(User).where(User.id == account_id))).scalar_one_or_none()
    if user is None or user.role != role:
        return err(404, f"{entity_label} not found")
    await db.execute(delete(UserSession).where(UserSession.user_id == account_id))
    await db.execute(delete(User).where(User.id == account_id))
    await db.commit()
    await invalidate_user_cache(account_id)
    return ok(f"{entity_label} deleted successfully")


# --- Global sessions & activities ---

_GLOBAL_ACTIVITY_SORT_MAP = {"type": "a.type", "created_at": "a.created_at"}
_GLOBAL_SESSION_SORT_MAP = {"user_agent": "s.user_agent", "ip_address": "s.ip_address", "created_at": "s.created_at"}


async def list_all_activities(db: AsyncSession, page_in: PageInput, tz: str) -> dict:
    base_query = (
        "SELECT a.id, a.user_id, a.type, a.ip, a.client, a.created_at, "
        "u.first_name, u.last_name, u.email, u.role "
        "FROM user_activities a LEFT JOIN users u ON a.user_id = u.id"
    )

    def map_row(row: dict) -> dict:
        row["type"] = ACTIVITY_LABELS.get(row["type"], row["type"])
        row["client"] = device_name(row.get("client"))
        row["created_at"] = date_time_format(row["created_at"], tz)
        return row

    return await paginate(db, base_query, {}, page_in, PageOptions(
        default_sort_field="created_at", default_sort_dir="desc", sort_map=_GLOBAL_ACTIVITY_SORT_MAP, map_row=map_row,
    ))


async def list_all_sessions(db: AsyncSession, page_in: PageInput, tz: str) -> dict:
    base_query = (
        "SELECT s.id, s.user_id, s.device_uid, s.user_agent, s.ip_address, s.created_at, s.expires_at, "
        "u.first_name, u.last_name, u.email, u.role "
        "FROM user_sessions s LEFT JOIN users u ON s.user_id = u.id"
    )

    def map_row(row: dict) -> dict:
        row["user_agent"] = device_name(row.get("user_agent"))
        row["created_at"] = date_time_format(row["created_at"], tz)
        row["expires_at"] = date_time_format(row["expires_at"], tz)
        return row

    return await paginate(db, base_query, {}, page_in, PageOptions(
        default_sort_field="created_at", default_sort_dir="desc", sort_map=_GLOBAL_SESSION_SORT_MAP, map_row=map_row,
    ))


async def logout_session_by_id(db: AsyncSession, session_id: str) -> ApiResult:
    row = (await db.execute(select(UserSession).where(UserSession.id == session_id))).scalar_one_or_none()
    if row is None:
        return err(404, "Session not found")
    token = row.token
    await db.execute(delete(UserSession).where(UserSession.id == session_id))
    await db.commit()
    await invalidate_session_cache(token)
    return ok("Device logged out successfully")


# --- Settings ---


async def settings_map(db: AsyncSession) -> dict[str, str]:
    return await get_all_settings(db)


async def save_settings(db: AsyncSession, values: dict, type_: str = "private") -> None:
    for k, v in values.items():
        if isinstance(v, str):
            await update_setting(db, k, v, type_)


# --- Blogs ---

_BLOG_SORT_MAP = {"title": "title", "category": "category", "status": "status", "created_at": "created_at"}


async def list_blogs(db: AsyncSession, page_in: PageInput, tz: str) -> dict:
    base_query = "SELECT id, slug, title, category, image, status, created_at FROM blogs"
    params: dict = {}
    if page_in.search:
        base_query += " WHERE title ILIKE :search"
        params["search"] = f"%{page_in.search}%"

    def map_row(row: dict) -> dict:
        row["created_at"] = date_time_format(row["created_at"], tz)
        return row

    return await paginate(db, base_query, params, page_in, PageOptions(
        default_sort_field="created_at", default_sort_dir="desc", sort_map=_BLOG_SORT_MAP, map_row=map_row,
    ))


def _blog_to_dict(b: Blog) -> dict:
    return {
        "id": b.id, "slug": b.slug, "title": b.title, "excerpt": b.excerpt, "body": b.body,
        "category": b.category, "image": b.image, "meta_title": b.meta_title or "",
        "meta_description": b.meta_description or "", "status": b.status,
        "created_at": b.created_at, "updated_at": b.updated_at,
    }


async def get_blog_by_id(db: AsyncSession, blog_id: int) -> ApiResult:
    b = (await db.execute(select(Blog).where(Blog.id == blog_id))).scalar_one_or_none()
    if b is None:
        return err(404, "Blog not found")
    return ok("Blog fetched successfully", _blog_to_dict(b))


async def create_blog(db: AsyncSession, fields: dict) -> ApiResult:
    now = datetime.now(timezone.utc)
    blog = Blog(
        slug=fields.get("slug", ""), title=fields.get("title", ""), excerpt=fields.get("excerpt", ""),
        body=fields.get("body", ""), category=fields.get("category", ""), image=fields.get("image") or None,
        meta_title=fields.get("meta_title") or None, meta_description=fields.get("meta_description") or None,
        status=fields.get("status") or STATUS_ACTIVE, created_at=now, updated_at=now,
    )
    db.add(blog)
    await db.commit()
    await db.refresh(blog)
    return ApiResult(201, 1, "Blog created successfully", {"id": blog.id})


async def update_blog(db: AsyncSession, blog_id: int, fields: dict) -> ApiResult:
    if not fields:
        return await get_blog_by_id(db, blog_id)
    fields = dict(fields)
    fields.pop("action", None)
    if not fields:
        return await get_blog_by_id(db, blog_id)
    fields["updated_at"] = datetime.now(timezone.utc)
    result = await db.execute(update(Blog).where(Blog.id == blog_id).values(**fields))
    await db.commit()
    if result.rowcount == 0:
        return err(404, "Blog not found")
    return await get_blog_by_id(db, blog_id)


async def delete_blog(db: AsyncSession, blog_id: int) -> ApiResult:
    result = await db.execute(delete(Blog).where(Blog.id == blog_id))
    await db.commit()
    if result.rowcount == 0:
        return err(404, "Blog not found")
    return ok("Blog deleted successfully")


# --- Pages ---


async def list_pages(db: AsyncSession, page_in: PageInput, tz: str) -> dict:
    base_query = "SELECT id, slug, title, status, created_at FROM pages"

    def map_row(row: dict) -> dict:
        row["created_at"] = date_time_format(row["created_at"], tz)
        return row

    return await paginate(db, base_query, {}, page_in, PageOptions(
        default_sort_field="created_at", default_sort_dir="desc",
        sort_map={"title": "title", "status": "status", "created_at": "created_at"}, map_row=map_row,
    ))


async def get_page_by_id(db: AsyncSession, page_id: str) -> ApiResult:
    p = (await db.execute(select(Page).where(Page.id == int(page_id)))).scalar_one_or_none()
    if p is None:
        return err(404, "Page not found")
    return ok("ok", {"slug": p.slug, "title": p.title, "body": p.body, "status": p.status})


async def update_page(db: AsyncSession, page_id: str, fields: dict) -> ApiResult:
    if not fields:
        return await get_page_by_id(db, page_id)
    fields = dict(fields)
    fields.pop("action", None)
    if not fields:
        return await get_page_by_id(db, page_id)
    fields["updated_at"] = datetime.now(timezone.utc)
    result = await db.execute(update(Page).where(Page.id == int(page_id)).values(**fields))
    await db.commit()
    if result.rowcount == 0:
        return err(404, "Page not found")
    return await get_page_by_id(db, page_id)


# --- SEO ---


async def list_seos(db: AsyncSession, page_in: PageInput, tz: str) -> dict:
    base_query = "SELECT id, url, title, status, sitemap_enable, created_at FROM seos"

    def map_row(row: dict) -> dict:
        row["created_at"] = date_time_format(row["created_at"], tz)
        return row

    return await paginate(db, base_query, {}, page_in, PageOptions(
        default_sort_field="created_at", default_sort_dir="desc",
        sort_map={"url": "url", "created_at": "created_at"}, map_row=map_row,
    ))


async def get_seo_by_id(db: AsyncSession, seo_id: str) -> ApiResult:
    s = (await db.execute(select(Seo).where(Seo.id == int(seo_id)))).scalar_one_or_none()
    if s is None:
        return err(404, "Not found")
    return ok("ok", {"url": s.url, "title": s.title or "", "status": s.status})


async def create_seo(db: AsyncSession, fields: dict) -> ApiResult:
    now = datetime.now(timezone.utc)
    seo = Seo(
        type=fields.get("type", "STATIC"), url=fields.get("url", ""), title=fields.get("title"),
        meta_title=fields.get("meta_title"), keyword=fields.get("keyword"), meta_keyword=fields.get("meta_keyword"),
        description=fields.get("description"), meta_description=fields.get("meta_description"),
        image=fields.get("image"), canonical=fields.get("canonical"),
        status=fields.get("status", 1), sitemap_enable=fields.get("sitemap_enable", 1),
        created_at=now, updated_at=now,
    )
    db.add(seo)
    await db.commit()
    await db.refresh(seo)
    return ok("ok", {"id": seo.id})


async def update_seo(db: AsyncSession, seo_id: str, fields: dict) -> ApiResult:
    fields = dict(fields)
    fields.pop("action", None)
    if not fields:
        return await get_seo_by_id(db, seo_id)
    fields["updated_at"] = datetime.now(timezone.utc)
    result = await db.execute(update(Seo).where(Seo.id == int(seo_id)).values(**fields))
    await db.commit()
    if result.rowcount == 0:
        return err(404, "Not found")
    return await get_seo_by_id(db, seo_id)


async def delete_seo(db: AsyncSession, seo_id: str) -> ApiResult:
    result = await db.execute(delete(Seo).where(Seo.id == int(seo_id)))
    await db.commit()
    if result.rowcount == 0:
        return err(404, "Not found")
    return ok("Deleted successfully")


async def generate_pure_sitemap(db: AsyncSession) -> dict:
    count = (
        await db.execute(select(func.count()).select_from(Seo).where(Seo.sitemap_enable == 1))
    ).scalar_one()
    return {"count": count}


# --- Email templates ---


async def list_email_templates(db: AsyncSession, page_in: PageInput, tz: str) -> dict:
    base_query = "SELECT id, key, coalesce(title,'') as title, subject, created_at FROM email_templates"

    def map_row(row: dict) -> dict:
        row["created_at"] = date_time_format(row["created_at"], tz)
        return row

    return await paginate(db, base_query, {}, page_in, PageOptions(
        default_sort_field="created_at", default_sort_dir="desc",
        sort_map={"key": "key", "created_at": "created_at"}, map_row=map_row,
    ))


async def get_email_template_by_id(db: AsyncSession, template_id: str) -> ApiResult:
    t = (await db.execute(select(EmailTemplate).where(EmailTemplate.id == int(template_id)))).scalar_one_or_none()
    if t is None:
        return err(404, "Template not found")
    return ok("ok", {"key": t.key, "subject": t.subject, "body": t.body})


async def update_email_template(db: AsyncSession, template_id: str, fields: dict) -> ApiResult:
    if not fields:
        return await get_email_template_by_id(db, template_id)
    fields = dict(fields)
    fields["updated_at"] = datetime.now(timezone.utc)
    result = await db.execute(update(EmailTemplate).where(EmailTemplate.id == int(template_id)).values(**fields))
    await db.commit()
    if result.rowcount == 0:
        return err(404, "Template not found")
    return await get_email_template_by_id(db, template_id)
