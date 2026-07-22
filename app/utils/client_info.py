"""Client IP/UA extraction — ports express src/utils/clientInfo.ts exactly
(scan x-forwarded-for right-to-left for the first public IP)."""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from app.core.security import COOKIE_DEVICE_UID


@dataclass
class ClientInfo:
    ip: str
    client: str
    device_id: str


def _is_private_ip(ip: str) -> bool:
    v = ip.strip()
    if not v or v == "::1":
        return True
    lower = v.lower()
    if v.startswith(("127.", "10.", "192.168.")) or lower.startswith(("fe80:", "fc", "fd")):
        return True
    if v.startswith("172."):
        parts = v.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded.strip():
        ips = [p.strip() for p in forwarded.split(",") if p.strip()]
        for ip in reversed(ips):
            if not _is_private_ip(ip):
                return ip
        if ips:
            return ips[-1]
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    return request.client.host if request.client else ""


def get_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "").strip()


def get_device_uid(request: Request) -> str:
    return request.cookies.get(COOKIE_DEVICE_UID, "")


def get_client_info(request: Request) -> ClientInfo:
    return ClientInfo(ip=get_client_ip(request), client=get_user_agent(request), device_id=get_device_uid(request))


def device_name(user_agent: str | None) -> str:
    if not user_agent:
        return "Unknown Device"
    ua = user_agent.lower()
    if "mobile" in ua:
        return "Mobile Device"
    if "windows" in ua:
        return "Windows PC"
    if "macintosh" in ua or "mac os x" in ua:
        return "Mac"
    if "linux" in ua:
        return "Linux"
    parts = user_agent.split(" ")
    return parts[0] if parts else "Device"
