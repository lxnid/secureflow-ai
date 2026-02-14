"""Centralized configuration via Pydantic BaseSettings.

All settings are loaded from environment variables.
In production, inject via Azure Container Apps secrets or Key Vault.
"""

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Azure OpenAI
    azure_openai_endpoint: str
    azure_openai_api_key: str
    azure_openai_deployment: str = "gpt-4o"

    # Cosmos DB
    cosmos_endpoint: str
    cosmos_key: str
    cosmos_database: str = "secureflow"

    # GitHub
    github_token: str
    github_webhook_secret: str

    # Application Insights (optional — telemetry degrades gracefully)
    appinsights_connection_string: str = ""

    # App
    log_level: str = "INFO"
    max_concurrent_analyses: int = 5
    agent_timeout_seconds: int = 45
    github_api_timeout: float = 15.0
    scanner_timeout: int = 30

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @field_validator("azure_openai_endpoint")
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("azure_openai_endpoint must be an HTTPS URL")
        return v.rstrip("/")

    @field_validator("cosmos_endpoint")
    @classmethod
    def validate_cosmos_endpoint(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("cosmos_endpoint must be an HTTPS URL")
        return v.rstrip("/")
