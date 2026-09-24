"""Runtime configuration loaded from local environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    openai_api_key: str | None = None
    openai_model: str = "gpt-5-mini"
    savanna_api_key: str | None = None
    tg_workspace: str = "my-workspace"
    tg_organization: str | None = None
    tg_host: str | None = None
    tg_graphname: str = "FraudGraph"
    tg_secret: str | None = None

    @property
    def tigergraph_ready(self) -> bool:
        return bool(self.tg_host and self.tg_secret)


settings = Settings()
