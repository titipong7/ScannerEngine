"""Application configuration, loaded once from the environment."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Supabase
    supabase_url: str = ""
    supabase_key: str = ""
    supabase_table: str = "scan_results"
    persist_results: bool = True

    # DNS
    dns_resolvers: str = "1.1.1.1,8.8.8.8"
    dns_timeout: float = 5.0
    dns_lifetime: float = 10.0
    # Warn this many days before a DNSSEC signature expires.
    dnssec_expiry_warning_days: int = 14

    # API
    log_level: str = "INFO"
    api_key: str = ""

    @property
    def resolver_list(self) -> list[str]:
        return [ip.strip() for ip in self.dns_resolvers.split(",") if ip.strip()]

    @property
    def supabase_enabled(self) -> bool:
        return self.persist_results and bool(self.supabase_url and self.supabase_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
