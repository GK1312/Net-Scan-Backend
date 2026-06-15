from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
from aio_pika.abc import AbstractIncomingMessage
from pydantic import ValidationError as PydanticValidationError

from src.config import Settings
from src.database.connections import DatabaseConnection
from src.database import repository
from src.queue.connections import QueueConnection
from src.queue.schemas import BatchMessage
from src.core.scan.runner import scan_ip
from src.database.repository import ResultRow
from src.utils.ratelimit import RateLimiter


def _code_build_time() -> str:
    src_dir = Path(__file__).resolve().parents[1]
    newest = max((p.stat().st_mtime for p in src_dir.rglob("*.py")), default=0.0)
    return datetime.fromtimestamp(newest, timezone.utc).isoformat(timespec="seconds")


class Worker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = DatabaseConnection(settings.database)
        self.queue = QueueConnection(settings.queue)
        self._rate_limiter = RateLimiter(settings.worker.rate_limit_per_pod)

    async def run(self) -> None:
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        print(f"worker: code build {_code_build_time()} | started {started}")
        await self.db.connect()
        channel = await self.queue.channel(
            prefetch_count=self.settings.queue.prefetch_count
        )
        queue = await self.queue.declare_queue(channel)
        await queue.consume(self._on_message)
        print(
            f"worker: consuming from '{self.settings.queue.queue_name}' "
            f"(prefetch={self.settings.queue.prefetch_count}, "
            f"max_connections={self.settings.worker.max_connections})"
        )
        await asyncio.Future()

    async def _on_message(self, message: AbstractIncomingMessage) -> None:
        try:
            batch = BatchMessage.model_validate_json(message.body)
        except PydanticValidationError:
            print("worker: dropping unparseable message")
            await message.reject(requeue=False)
            return

        try:
            await self._process_batch(batch)
        except asyncpg.ForeignKeyViolationError:
            print(f"worker: dropping batch for unknown job_id={batch.job_id}")
            await message.reject(requeue=False)
            return
        except Exception as exc:
            print(f"worker: requeueing batch job_id={batch.job_id}: {exc!r}")
            await message.reject(requeue=True)
            return

        await message.ack()

    async def _process_batch(self, batch: BatchMessage) -> None:
        results: asyncio.Queue[dict | None] = asyncio.Queue()
        semaphore = asyncio.Semaphore(self.settings.worker.max_connections)

        async def run_one(ip: str) -> None:
            async with semaphore:
                await self._rate_limiter.acquire()
                document = await scan_ip(ip, self.settings)
                await results.put(document)

        flusher = asyncio.create_task(self._flush_loop(batch.job_id, results))
        try:
            await asyncio.gather(*(run_one(ip) for ip in batch.ips))
        finally:
            await results.put(None)
            await flusher

    async def _flush_loop(
        self, job_id: str, results: "asyncio.Queue[dict | None]"
    ) -> None:
        chunk_size = self.settings.worker.chunk_size
        flush_interval = self.settings.worker.flush_interval_seconds
        buffer: list[dict] = []
        done = False
        deadline: float | None = None
        while not done:
            timeout = (
                None if deadline is None else max(0.0, deadline - time.monotonic())
            )
            try:
                outcome = await asyncio.wait_for(results.get(), timeout=timeout)
                if outcome is None:  # sentinel: probing finished, flush remainder
                    done = True
                else:
                    buffer.append(outcome)
                    if deadline is None:
                        deadline = time.monotonic() + flush_interval
            except asyncio.TimeoutError:
                pass

            time_up = deadline is not None and time.monotonic() >= deadline
            if buffer and (done or len(buffer) >= chunk_size or time_up):
                await self._persist_chunk(job_id, buffer)
                buffer = []
                deadline = None

    async def _persist_chunk(self, job_id: str, documents: list[dict]) -> None:
        rows = [_row_from_document(doc) for doc in documents]
        async with self.db.pool.acquire() as conn:
            async with conn.transaction():
                inserted = await repository.insert_results(conn, job_id, rows)
                if inserted:
                    await repository.increment_processed(conn, job_id, inserted)
                    await repository.notify_results(conn, job_id)


def _row_from_document(doc: dict) -> ResultRow:
    """Flatten a scan_ip() document into the persisted row (derived scalar columns
    for SQL filtering + the full document as JSONB)."""
    classification = doc["classification"]
    return ResultRow(
        ip=classification["ip"],
        status="alive" if classification["reachable"] else "dead",
        latency_ms=doc["probes"]["icmp"]["rtt_ms"],
        error=classification["error"],
        platform=classification["platform"],
        confidence=classification["confidence"],
        hostname=classification["hostname"],
        document=doc,
    )
