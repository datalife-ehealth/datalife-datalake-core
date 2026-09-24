"""Process settings for the data lake core."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed settings. Secrets stay outside the repository."""

    model_config = SettingsConfigDict(env_prefix="DATALIFE_", extra="ignore")

    database_url: str = "postgresql+psycopg://datalife:datalife@localhost:5432/datalife"
    object_storage_path: str = "./var/objects"
    audit_secret: str = "replace-me"
    otp_ttl_seconds: int = 900
    master_physician_ids: str = "PHY-0001"

    def physician_ids(self) -> set[str]:
        return {item.strip() for item in self.master_physician_ids.split(",") if item.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
