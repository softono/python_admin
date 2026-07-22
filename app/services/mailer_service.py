"""Ports express src/lib/mailer — SMTP transport from decrypted settings,
HTML wrapped in the shared layout, templates from email_templates + {{param}}
substitution."""
from __future__ import annotations

import re
from datetime import datetime, timezone

import aiosmtplib
from email.message import EmailMessage
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import EmailTemplate
from app.services.setting_service import get_all_settings

_TAG_RE = re.compile(r"<[^>]*>")


async def send_mail(db: AsyncSession, to: str, subject: str, html: str) -> dict:
    s = await get_all_settings(db)
    host = s.get("smtp_host", "")
    port = int(s.get("smtp_port") or 587)
    user = s.get("smtp_username", "")
    password = s.get("smtp_password", "")
    encryption = (s.get("smtp_encryption") or "tls").lower()

    if not host or not user or not password:
        return {"status": 0, "message": "SMTP configuration missing"}

    mail_from = s.get("mail_from_address") or user
    mail_from_name = s.get("mail_from_name") or settings.app_name

    msg = EmailMessage()
    msg["From"] = f'"{mail_from_name}" <{mail_from}>'
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(_TAG_RE.sub("", html))
    msg.add_alternative(html, subtype="html")

    try:
        await aiosmtplib.send(
            msg, hostname=host, port=port, username=user, password=password,
            use_tls=encryption == "ssl", start_tls=encryption != "ssl",
        )
        return {"status": 1, "message": "Email sent successfully"}
    except Exception as e:
        return {"status": 0, "message": str(e)}


def _render_layout(body: str) -> str:
    year = datetime.now(timezone.utc).year
    return f"""
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><title>{settings.app_name}</title></head>
    <body style="margin:0;padding:0;background-color:#f5f5f5;">
      <table width="100%" cellpadding="0" cellspacing="0" border="0" style="padding:30px 0;">
        <tr><td align="center">
          <table width="600" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border-radius:8px;overflow:hidden;">
            <tr><td style="padding:20px 30px;font-size:24px;font-weight:bold;text-align:center;">
              <img src="{settings.app_logo}" alt="{settings.app_name}" style="max-width:100px;height:50px;" />
            </td></tr>
            <tr><td style="height:4px;background-color:#85b33a;"></td></tr>
            <tr><td style="padding:20px;font-family:Arial,sans-serif;font-size:16px;color:#333;">{body}</td></tr>
            <tr><td style="background:#f0f0f0;padding:20px 30px;text-align:center;color:#888;font-size:13px;">
              &copy; {year}. All rights reserved.
            </td></tr>
          </table>
        </td></tr>
      </table>
    </body></html>"""


async def send_email(db: AsyncSession, to: str, template: str, data: dict) -> dict:
    payload = {"app_name": settings.app_name, "email": to, **data}
    tpl = (await db.execute(select(EmailTemplate).where(EmailTemplate.key == template))).scalar_one_or_none()
    if not tpl:
        return {"status": 0, "message": "Email template not found"}

    subject, body = tpl.subject, tpl.body
    for k, v in payload.items():
        pattern = re.compile(r"\{\{\s*" + re.escape(k) + r"\s*\}\}")
        subject = pattern.sub(str(v), subject)
        body = pattern.sub(str(v), body)

    return await send_mail(db, to, subject or "Notification", _render_layout(body))
