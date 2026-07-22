"""SQLAlchemy declarative models mirroring the shared Postgres schema
(owned/migrated by the `express` project — this app runs no migrations)."""
from __future__ import annotations

import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, TypeDecorator
from sqlalchemy.dialects.postgresql import ENUM as PGEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

# Reference existing DB enum types (owned by express's migrations) —
# create_type=False so SQLAlchemy never tries to CREATE TYPE itself.
UserStatusEnum = PGEnum("active", "inactive", name="user_status", create_type=False)
StatusEnum = PGEnum("active", "inactive", name="status", create_type=False)


class UTCNaiveDateTime(TypeDecorator):
    """Stores tz-aware Python datetimes into a naive `timestamp` column (columns
    owned by express's schema that predate timezone-aware storage), assuming UTC
    both ways."""

    impl = DateTime(timezone=False)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is not None:
            value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=datetime.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    email: Mapped[str] = mapped_column(Text)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    image: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())
    updated_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())
    two_factor_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    role: Mapped[str | None] = mapped_column(Text, nullable=True)
    permission: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(UserStatusEnum, nullable=True)
    first_name: Mapped[str] = mapped_column(Text)
    last_name: Mapped[str] = mapped_column(Text)
    phone: Mapped[str | None] = mapped_column(Text, nullable=True)
    country: Mapped[str | None] = mapped_column(Text, nullable=True)
    timezone: Mapped[str | None] = mapped_column(Text, nullable=True)
    registered_ip: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    expires_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())
    token: Mapped[str] = mapped_column(Text, unique=True)
    created_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())
    updated_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id", ondelete="CASCADE"))
    device_uid: Mapped[str | None] = mapped_column(Text, nullable=True)
    remember: Mapped[bool] = mapped_column(Boolean, default=False)


class UserAccount(Base):
    __tablename__ = "user_accounts"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    account_id: Mapped[str] = mapped_column(Text)
    provider_id: Mapped[str] = mapped_column(Text)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id", ondelete="CASCADE"))
    access_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    id_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    password: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())
    updated_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())


class UserVerification(Base):
    __tablename__ = "user_verifications"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    identifier: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())
    updated_at: Mapped[datetime.datetime] = mapped_column(UTCNaiveDateTime())


class UserTwoFactor(Base):
    __tablename__ = "user_two_factors"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    secret: Mapped[str] = mapped_column(Text)
    backup_codes: Mapped[str] = mapped_column(Text)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id", ondelete="CASCADE"))
    verified: Mapped[bool | None] = mapped_column(Boolean, default=False)


class UserPasskey(Base):
    __tablename__ = "user_passkeys"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    public_key: Mapped[str] = mapped_column(Text)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id", ondelete="CASCADE"))
    credential_id: Mapped[str] = mapped_column(Text)
    counter: Mapped[int] = mapped_column(Integer)
    device_type: Mapped[str] = mapped_column(Text)
    backed_up: Mapped[bool] = mapped_column(Boolean)
    transports: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime | None] = mapped_column(UTCNaiveDateTime(), nullable=True)
    aaguid: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserDevice(Base):
    __tablename__ = "user_devices"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id", ondelete="CASCADE"))
    device_uid: Mapped[str] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    trusted_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class UserLoginLink(Base):
    __tablename__ = "user_login_links"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    purpose: Mapped[str] = mapped_column(Text)
    email: Mapped[str] = mapped_column(Text)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id", ondelete="CASCADE"))
    poll_token_hash: Mapped[str] = mapped_column(Text)
    link_token_hash: Mapped[str] = mapped_column(Text)
    code: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="pending")
    device_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    location: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    remember: Mapped[bool] = mapped_column(Boolean, default=False)
    tfa_handle: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class UserActivity(Base):
    __tablename__ = "user_activities"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id", ondelete="CASCADE"))
    device_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    type: Mapped[str | None] = mapped_column(Text, nullable=True)
    data: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    client: Mapped[str | None] = mapped_column(Text, nullable=True)
    location: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class Setting(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(Text, unique=True)
    value: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(Text, default="public")
    group: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class Blog(Base):
    __tablename__ = "blogs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(Text, unique=True)
    title: Mapped[str] = mapped_column(Text)
    excerpt: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    image: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(StatusEnum, default="active")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class Page(Base):
    __tablename__ = "pages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(Text, unique=True)
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    meta_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(UserStatusEnum, default="inactive")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class Seo(Base):
    __tablename__ = "seos"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(Text, default="STATIC")
    url: Mapped[str] = mapped_column(Text, unique=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    keyword: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta_keyword: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    image: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[int] = mapped_column(Integer, default=1)
    sitemap_enable: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class EmailTemplate(Base):
    __tablename__ = "email_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(Text, unique=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class ContactMessage(Base):
    __tablename__ = "contact_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_user: Mapped[str] = mapped_column(Text)
    subject: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))


# --- Shared constants ---

STATUS_ACTIVE = "active"
STATUS_INACTIVE = "inactive"

ROLE_SUPER_ADMIN = "SUPER_ADMIN"
ROLE_ADMIN = "ADMIN"
ROLE_USER = "USER"
ADMIN_ROLES = (ROLE_ADMIN, ROLE_SUPER_ADMIN)

ACTIVITY_LABELS = {
    "LOGIN_FAILED": "Login Fail", "LOGIN_SUCCESS": "Login Success", "REGISTER": "Register",
    "LOGIN_WITH_OTP": "Login With Otp", "LOGIN_WITH_SOCIAL": "Login With Social Media",
    "LOGIN_WITH_LINK": "Login With Magic Link", "LOGOUT": "Logout",
    "ACCOUNT_DEACTIVATE": "Account deactivate", "EMAIL_UPDATE": "Email update",
    "PASSWORD_CHANGED": "password changed", "ACCOUNT_UPDATE": "Account update",
    "DEVICE_LOGGED_OUT": "device logged out", "IMAGE_UPLOADED": "Image uploaded",
    "PASSWORD_SET": "Password set", "PASSKEY_ADDED": "Passkey added",
    "PASSKEY_DELETED": "Passkey deleted", "BACKUP_CODES_REGENERATED": "Backup codes regenerated",
    "TFA_ENABLED": "TFA enabled", "TFA_DISABLED": "TFA disabled",
    "TFA_AUTHENTICATOR_REMOVED": "Authenticator app removed",
    "SETTING_UPDATE": "Setting update", "ADMIN_UPDATE": "Admin update",
    "USER_UPDATE": "User update", "DATA_UPDATE": "Data update",
}


def activity_label(t: str | None) -> str | None:
    if t is None:
        return t
    return ACTIVITY_LABELS.get(t, t)
