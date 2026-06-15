from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

Phase = Literal["ping", "test_connection", "extract_data"]


class BatchMessage(BaseModel):
    job_id: str
    batch_id: str
    ips: list[str]
    credentials_env: Optional[str] = None
    phase: list[Phase] = Field(default_factory=lambda: ["ping", "test_connection", "extract_data"])
    created_at: datetime
    worker_id: Optional[str] = None
    retry_count: int = 0
    priority: Literal["low", "medium", "high"] = "medium"
