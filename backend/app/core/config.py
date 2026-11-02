"""SentinelX Core Configuration
Loads environment variables using Pydantic Settings with strict validation.
"""

from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Core Application Settings
    ENVIRONMENT: str = Field(default="development")
    DEBUG: bool = Field(default=False)
    APP_NAME: str = Field(default="CyberSentry Cyber Defense Platform")
    APP_VERSION: str = Field(default="1.0.0")
    API_PREFIX: str = Field(default="/api/v1")

    # Security & Authentication
    SENTINELX_API_KEY: str = Field(default="sentinelx-client-dev-key")
    SECRET_KEY: str = Field(default="sentinelx-insecure-dev-secret-key-change-in-prod-32bytes")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=1440)

    # Database Configuration (supports sqlite+aiosqlite and mysql+aiomysql)
    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./sentinelx.db")
    DB_POOL_SIZE: int = Field(default=10)
    DB_MAX_OVERFLOW: int = Field(default=20)
    DB_POOL_TIMEOUT: int = Field(default=30)

    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(default=["*"])

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=120)
    MAX_REQUEST_SIZE_BYTES: int = Field(default=1048576)  # 1MB limit

    # Retention
    TELEMETRY_RETENTION_DAYS: int = Field(default=90)
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=180)

    # Threat Intelligence Integrations
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None)
    ALIENVAULT_OTX_API_KEY: Optional[str] = Field(default=None)
    URLHAUS_AUTH_KEY: Optional[str] = Field(default=None)
    THREAT_INTEL_CACHE_TTL_SECONDS: int = Field(default=3600)
    THREAT_INTEL_TIMEOUT_SECONDS: float = Field(default=4.0)

    # Multi-Agent Investigation Configuration
    AGENT_TIMEOUT_SECONDS: float = Field(default=10.0)
    AGENT_MAX_STEPS: int = Field(default=8)
    AGENT_LLM_PROVIDER: str = Field(default="none")
    OPENAI_API_KEY: Optional[str] = Field(default=None)
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None)


settings = Settings()
