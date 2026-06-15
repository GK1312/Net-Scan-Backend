from __future__ import annotations

import asyncio
import json
import math
from datetime import datetime, timezone
from typing import AsyncIterator
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import StreamingResponse

from src.queue.schemas import BatchMessage
from src.exceptions import ValidationError
from src.config import get_settings
from src.api.schemas import (
    PingResponse,
    PingRequest,
    PingJobStatusResponse,
    ResultsPageRequest,
)
from src.database import repository
from src.utils.validators import expand_targets
from src.utils.helpers import chunk

router = APIRouter()


@router.post("/ping", response_model=PingResponse)
async def ping(request: PingRequest, http: Request) -> PingResponse:
    settings = get_settings()
    db = http.app.state.db
    producer = http.app.state.producer

    try:
        valid_ips, invalid_ips = expand_targets(request.targets, max_count=100_000)
    except ValidationError as exception:
        raise HTTPException(status_code=400, detail=str(exception)) from exception

    job_id = uuid4()
    now = datetime.now(timezone.utc)

    await repository.create_job(db.pool, job_id, len(valid_ips))

    batches = chunk(valid_ips, settings.worker.batch_size)
    messages = [
        BatchMessage(
            job_id=str(job_id),
            batch_id=str(i),
            ips=batch_ips,
            phase=["ping"],
            created_at=now,
        )
        for i, batch_ips in enumerate(batches)
    ]
    await producer.publish_job(messages)

    return PingResponse(
        job_id=job_id,
        status="pending",
        total_ips=len(valid_ips),
        invalid_ips=len(invalid_ips),
    )


@router.post("/ping/{job_id}", response_model=PingJobStatusResponse)
async def get_ping(
        job_id: UUID,
        http: Request,
        pagination: ResultsPageRequest = Body(default_factory=ResultsPageRequest),
) -> PingJobStatusResponse:
    db = http.app.state.db
    job = await repository.fetch_job(db.pool, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")

    total_results = job["processed_count"]
    offset = (pagination.page - 1) * pagination.page_size
    rows = await repository.fetch_results_page(
        db.pool, job_id, limit=pagination.page_size, offset=offset
    )
    return PingJobStatusResponse(
        job_id=job_id,
        status=job["status"],
        total_ips=job["total_ips"],
        processed_ips=job["processed_count"],
        page=pagination.page,
        page_size=pagination.page_size,
        total_results=total_results,
        total_pages=math.ceil(total_results / pagination.page_size) if total_results else 0,
        results=[repository.serialize_result(row) for row in rows],
    )


@router.get("/ping/{job_id}/stream")
async def stream_ping(job_id: UUID, http: Request) -> StreamingResponse:
    db = http.app.state.db
    job = await repository.fetch_job(db.pool, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")

    last_event_id = http.headers.get("last-event-id")
    generator = _result_event_stream(db, str(job_id), last_event_id)
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse(event: str, data: dict, event_id: int | None = None) -> str:
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(data)}")
    return "\n".join(lines) + "\n\n"


async def _result_event_stream(
        db, job_id: str, last_event_id: str | None
) -> AsyncIterator[str]:
    settings = get_settings()

    cursor = int(last_event_id) if last_event_id and last_event_id.isdigit() else 0

    wakeup = asyncio.Event()

    def on_notify(_conn, _pid, _channel, payload: str) -> None:
        if payload == job_id:
            wakeup.set()

    async with db.pool.acquire() as conn:
        await conn.add_listener(settings.database.notify_channel, on_notify)
        try:
            while True:
                wakeup.clear()

                while True:
                    rows = await repository.fetch_results_after(
                        conn, job_id, cursor, limit=settings.stream.page_size
                    )
                    if not rows:
                        break
                    cursor = rows[-1]["id"]
                    payload = {
                        "results": [repository.serialize_result(r) for r in rows]
                    }
                    yield _sse("results", payload, event_id=cursor)

                job = await repository.fetch_job(conn, job_id)
                yield _sse(
                    "progress",
                    {"processed": job["processed_count"], "total": job["total_ips"]},
                )

                if job["status"] == "completed":
                    yield _sse(
                        "done", {"status": "completed", "total_ips": job["total_ips"]}
                    )
                    return

                try:
                    await asyncio.wait_for(
                        wakeup.wait(), timeout=settings.stream.heartbeat_seconds
                    )
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            await conn.remove_listener(settings.database.notify_channel, on_notify)
