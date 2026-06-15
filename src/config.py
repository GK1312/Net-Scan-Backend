from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class PhaseTimeouts(BaseModel):
    ping_timeout: float = 3.0
    retries_limit: int = 3
    retry_delay: float = 0.1
    ping_stub_delay_seconds: float = 4.0
    tcp_connect_timeout: float = 2.0


class DatabaseSettings(BaseModel):
    host: str = "89.167.16.30"
    port: int = 5432
    user: str = "GK1312"
    password: str = "Gauravsk@100"
    database: str = "postgres"
    dsn: str | None = None
    pool_size: int = 50
    batch_insert_size: int = 1000
    result_retention_time_day: int = 30
    notify_channel: str = "ping_results"


class QueueSettings(BaseModel):
    url: str = Field(default="amqp://guest:guest@localhost:5672/")
    queue_name: str = "scan_queue"
    durable: bool = True
    prefetch_count: int = 3


class WorkerSettings(BaseModel):
    batch_size: int = 2_000
    chunk_size: int = 1_000
    max_connections: int = 25
    rate_limit_per_pod: int = 1_000
    flush_interval_seconds: float = 1.0


class StreamSettings(BaseModel):
    heartbeat_seconds: float = 15.0
    page_size: int = 500


class SecuritySettings(BaseModel):
    encryption_key_env: str = "SCANNER_ENCRYPTION_KEY"
    jwt_secret_key_env: str = "SCANNER_JWT_SECRET_KEY"
    jwt_algorithm: str = "HS256"
    jwt_expiration_seconds: int = 3_600
    min_confidence: float = 0.55


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCANNER_", env_nested_delimiter="__", extra="ignore"
    )
    environment: str = "development"
    config_dir: Path = Path("config.py")

    timeouts: PhaseTimeouts = Field(default_factory=PhaseTimeouts)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    queue: QueueSettings = Field(default_factory=QueueSettings)
    worker: WorkerSettings = Field(default_factory=WorkerSettings)
    stream: StreamSettings = Field(default_factory=StreamSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)

    @classmethod
    def from_yaml(cls, path: Path) -> Settings:
        raise NotImplementedError


@lru_cache()
def get_settings() -> Settings:
    return Settings()
