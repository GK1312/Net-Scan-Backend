from __future__ import annotations

from functools import lru_cache

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class PhaseTimeouts(BaseModel):
    ping_timeout: float = 3.0
    tcp_connect_timeout: float = 2.0
    port_connect_timeout: float = 1.0
    smb_timeout: float = 4.0
    port_scan_timeout: float = 5.0


class DatabaseSettings(BaseModel):
    host: str = "localhost"
    port: int = 5432
    user: str = "postgres"
    password: str = ""
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
    max_concurrent_connections: int = 0
    rate_limit_per_pod: int = 1_000
    flush_interval_seconds: float = 1.0
    max_retries: int = 3
    thread_pool_size: int = 256
    shutdown_grace_seconds: float = 30.0
    enable_reverse_dns: bool = True


class StreamSettings(BaseModel):
    heartbeat_seconds: float = 15.0
    page_size: int = 500


class SecuritySettings(BaseModel):
    encryption_key_env: str = "SCANNER_ENCRYPTION_KEY"
    jwt_secret_key_env: str = "SCANNER_JWT_SECRET_KEY"
    jwt_algorithm: str = "HS256"
    jwt_expiration_seconds: int = 3_600
    min_confidence: float = 0.55
    short_circuit_confidence: float = 90.0
    api_key: str = ""
    rate_limit_per_minute: int = 120
    rate_limit_burst: int = 0


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCANNER_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
    environment: str = "development"

    timeouts: PhaseTimeouts = Field(default_factory=PhaseTimeouts)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    queue: QueueSettings = Field(default_factory=QueueSettings)
    worker: WorkerSettings = Field(default_factory=WorkerSettings)
    stream: StreamSettings = Field(default_factory=StreamSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)


@lru_cache
def get_settings() -> Settings:
    return Settings()
