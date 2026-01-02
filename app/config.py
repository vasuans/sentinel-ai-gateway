"""
Sentinel Gateway Configuration Module.
Handles environment-based configuration with validation.
"""
from enum import Enum
from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class GatewayMode(str, Enum):
    """Operating mode for the gateway circuit breaker."""
    SHADOW = "SHADOW"      # Log but don't block unsafe actions
    ENFORCE = "ENFORCE"    # Block unsafe actions


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = "Sentinel AI Governance Gateway"
    app_version: str = "1.0.0"
    debug: bool = False
    gateway_mode: GatewayMode = GatewayMode.ENFORCE
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    
    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    redis_policy_prefix: str = "sentinel:policy:"
    redis_rate_limit_prefix: str = "sentinel:ratelimit:"
    policy_cache_ttl: int = 300  # 5 minutes
    
    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "sentinel"
    postgres_password: str = "sentinel_secure_password"
    postgres_db: str = "sentinel_audit"
    postgres_pool_size: int = 20
    postgres_max_overflow: int = 10
    
    # Security
    api_key_prefix: str = "agent_sk_"
    api_key_min_length: int = 32
    
    # Circuit Breaker
    risk_score_block_threshold: float = 1.0
    risk_score_approval_threshold: float = 0.8
    approval_webhook_url: str = "http://localhost:8001/approval"
    approval_webhook_timeout: float = 5.0
    
    # Rate Limiting
    rate_limit_requests: int = 1000
    rate_limit_window_seconds: int = 60
    
    # Observability
    log_level: str = "INFO"
    metrics_enabled: bool = True
    
    @property
    def redis_url(self) -> str:
        """Construct Redis URL from components."""
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"
    
    @property
    def postgres_url(self) -> str:
        """Construct PostgreSQL URL from components."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    @property
    def postgres_sync_url(self) -> str:
        """Construct synchronous PostgreSQL URL for migrations."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    @field_validator('gateway_mode', mode='before')
    @classmethod
    def validate_gateway_mode(cls, v: str) -> GatewayMode:
        if isinstance(v, str):
            return GatewayMode(v.upper())
        return v
    
    class Config:
        env_prefix = "SENTINEL_"
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
