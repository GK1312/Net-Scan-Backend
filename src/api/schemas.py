from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class PingRequest(BaseModel):
    targets: list[str]


class PingResponse(BaseModel):
    job_id: UUID
    status: str
    total_ips: int
    invalid_ips: int


class ResultsPageRequest(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=100, ge=1, le=1000)


class PingJobStatusResponse(BaseModel):
    job_id: UUID
    status: str
    total_ips: int
    processed_ips: int
    page: int
    page_size: int
    total_results: int
    total_pages: int
    results: list[dict[str, Any]] = Field(default_factory=list)