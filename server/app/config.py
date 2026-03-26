from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


SERVICE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = SERVICE_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECOS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SecOS Defender"
    api_v1_prefix: str = "/api/v1"
    database_url: str = Field(
        default="sqlite:///./secos_defender_v2.db",
        description="PostgreSQL in docker; SQLite fallback for local tests.",
    )
    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    rules_path: Path = ROOT_DIR / "rules" / "default"
    vulnerability_feed_path: Path = SERVICE_DIR / "app" / "data" / "vulnerability_feed.json"
    websocket_backlog: int = 50
    response_requires_approval: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
