from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import asyncpg

from src.config import get_settings

Querier = Any


@dataclass(slots=True)
class ResultRow:
    ip: str
    status: str
    latency_ms: float | None
    error: str | None
    platform: str | None
    confidence: float | None
    hostname: str | None
    document: dict


async def create_job(db: Querier, job_id: UUID | str, total_ips: int) -> None:
    await db.execute(
        """
        INSERT INTO jobs (job_id, total_ips, status)
        VALUES ($1, $2, 'pending')
        """,
        str(job_id),
        total_ips,
    )


async def fetch_job(db: Querier, job_id: UUID | str) -> asyncpg.Record | None:
    return await db.fetchrow(
        """
        SELECT job_id, status, total_ips, processed_count, created_at, completed_at
        FROM jobs
        WHERE job_id = $1
        """,
        str(job_id),
    )


async def fetch_results_after(
    db: Querier, job_id: UUID | str, cursor: int, limit: int = 500
) -> list[asyncpg.Record]:
    """Results with id strictly greater than ``cursor`` (the streaming tail read)."""
    return await db.fetch(
        """
        SELECT id, document
        FROM ping_results
        WHERE job_id = $1 AND id > $2
        ORDER BY id
        LIMIT $3
        """,
        str(job_id),
        cursor,
        limit,
    )


async def fetch_results_page(
    db: Querier, job_id: UUID | str, limit: int, offset: int
) -> list[asyncpg.Record]:
    """Offset-paginated snapshot read for GET /ping/{job_id}."""
    return await db.fetch(
        """
        SELECT id, document
        FROM ping_results
        WHERE job_id = $1
        ORDER BY id
        LIMIT $2 OFFSET $3
        """,
        str(job_id),
        limit,
        offset,
    )


async def insert_results(
    conn: asyncpg.Connection, job_id: UUID | str, rows: Sequence[ResultRow]
) -> int:
    """Insert fingerprint rows for one job, skipping any (job_id, ip) that already
    exists. Returns the count of *newly* inserted rows so callers only advance
    processed_count for results that are genuinely new. Documents are passed as
    JSON text and cast to jsonb per row."""
    if not rows:
        return 0
    inserted = await conn.fetch(
        """
        INSERT INTO ping_results
            (job_id, ip, status, latency_ms, error, platform, confidence, hostname, document)
        SELECT $1, ip, status, latency_ms, error, platform, confidence, hostname, document::jsonb
        FROM unnest(
            $2::text[], $3::text[], $4::float8[], $5::text[],
            $6::text[], $7::float8[], $8::text[], $9::text[]
        ) AS t(ip, status, latency_ms, error, platform, confidence, hostname, document)
        ON CONFLICT (job_id, ip) DO NOTHING
        RETURNING id
        """,
        str(job_id),
        [r.ip for r in rows],
        [r.status for r in rows],
        [r.latency_ms for r in rows],
        [r.error for r in rows],
        [r.platform for r in rows],
        [r.confidence for r in rows],
        [r.hostname for r in rows],
        [json.dumps(r.document) for r in rows],
    )
    return len(inserted)


async def increment_processed(
    conn: asyncpg.Connection, job_id: UUID | str, count: int
) -> asyncpg.Record:
    """Atomically bump processed_count and flip status to completed when done."""
    return await conn.fetchrow(
        """
        UPDATE jobs
        SET processed_count = processed_count + $2,
            status = CASE
                WHEN processed_count + $2 >= total_ips THEN 'completed'
                ELSE 'running'
            END,
            completed_at = CASE
                WHEN processed_count + $2 >= total_ips THEN now()
                ELSE completed_at
            END
        WHERE job_id = $1
        RETURNING processed_count, total_ips, status
        """,
        str(job_id),
        count,
    )


async def notify_results(conn: asyncpg.Connection, job_id: UUID | str) -> None:
    """Ring the doorbell: tell listening stream endpoints new rows exist for this job."""
    channel = get_settings().database.notify_channel
    await conn.execute("SELECT pg_notify($1, $2)", channel, str(job_id))


def serialize_result(record: asyncpg.Record) -> dict[str, Any]:
    # The full scan_ip() document (jsonb decoded to a dict by the connection codec).
    return record["document"]


async def delete_expired_jobs(db: Querier, retention_days: int) -> int:
    return await db.fetchval(
        """
        WITH deleted AS (
            DELETE FROM jobs
            WHERE created_at < now() - make_interval(days => $1)
            RETURNING 1
        )
        SELECT count(*) FROM deleted
        """,
        retention_days,
    )
