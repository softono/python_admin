"""Application configuration loaded from environment (.env)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Next"
    app_uid: str = "next"
    app_logo: str = ""
    app_url: str = "http://localhost:5174"  # admin frontend origin
    api_url: str = "http://localhost:4301"  # own origin
    port: int = 4301
    app_env: str = "development"
    app_debug: bool = False
    cors_origin: str = "http://localhost:5174"

    database_url: str = ""
    encryption_key: str = ""
    redis_url: str = ""
    cache_driver: str = "memory"

    filesystem_disk: str = "local"
    filesystem_path: str = "."
    filesystem_url: str = ""

    webauthn_rp_id: str = "localhost"
    webauthn_origin: str = "http://localhost:5174"

    app_timezone: str = "UTC"

    otp_expire_sec: int = 600
    login_link_expire_sec: int = 300

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origin.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
