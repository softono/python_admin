"""Hand-rolled field validator producing the express-compatible 422 payload:
message = all errors joined ", ", data.errors = first message per field."""
from __future__ import annotations

import re
from typing import Any

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PHONE_RE = re.compile(r"^[0-9]{10}$")
_OTP_RE = re.compile(r"^[0-9]+$")
_ALPHA_RE = re.compile(r"^[A-Za-z]+$")


class FieldErrors:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.by_field: dict[str, str] = {}

    def add(self, field: str, message: str) -> None:
        self.messages.append(message)
        self.by_field.setdefault(field, message)

    @property
    def has_errors(self) -> bool:
        return bool(self.messages)

    @property
    def message(self) -> str:
        return ", ".join(self.messages)


class Validator:
    def __init__(self, body: dict[str, Any] | None):
        self.body = body or {}
        self.fe = FieldErrors()

    def _str(self, field: str) -> str | None:
        v = self.body.get(field)
        return v if isinstance(v, str) else None

    def required_string(self, field: str, msg: str) -> str:
        v = self._str(field)
        if not v:
            self.fe.add(field, msg)
            return ""
        return v

    def optional_string(self, field: str, fallback: str = "") -> str:
        v = self._str(field)
        return v if v else fallback

    def boolean(self, field: str, fallback: bool = False) -> bool:
        v = self.body.get(field)
        return v if isinstance(v, bool) else fallback

    def email(self, field: str = "email") -> str:
        v = self._str(field)
        if not v:
            self.fe.add(field, "Email is required")
            return ""
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            self.fe.add(field, "Please provide a valid email address")
            return ""
        return v

    def password(self, field: str = "password") -> str:
        v = self._str(field)
        if not v:
            self.fe.add(field, "Password is required")
            return ""
        if len(v) < 6:
            self.fe.add(field, "Password must be at least 6 characters")
            return ""
        if len(v) > 100:
            self.fe.add(field, "Password cannot exceed 100 characters")
            return ""
        return v

    def login_password(self, field: str = "password") -> str:
        v = self._str(field)
        if not v:
            self.fe.add(field, "Password is required")
            return ""
        return v

    def phone(self, field: str = "phone") -> str:
        v = self._str(field)
        if not v:
            self.fe.add(field, "Phone number is required")
            return ""
        if not _PHONE_RE.match(v):
            self.fe.add(field, "Phone number must be 10 digits")
            return ""
        return v

    def person_name(self, field: str, label: str) -> str:
        v = self._str(field)
        if not v:
            self.fe.add(field, f"{label} is required")
            return ""
        v = v.strip()
        if not _ALPHA_RE.match(v):
            self.fe.add(field, f"{label} must contain only letters")
            return ""
        if len(v) < 3:
            self.fe.add(field, f"{label} must be at least 3 characters")
            return ""
        if len(v) > 50:
            self.fe.add(field, f"{label} cannot exceed 50 characters")
            return ""
        return v

    def otp(self, field: str = "otp") -> str:
        v = self._str(field)
        if not v:
            self.fe.add(field, "OTP is required")
            return ""
        if len(v) != 6:
            self.fe.add(field, "OTP must be exactly 6 digits")
            return ""
        if not _OTP_RE.match(v):
            self.fe.add(field, "OTP must contain only numeric digits")
            return ""
        return v
