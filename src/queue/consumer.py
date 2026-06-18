from __future__ import annotations

import asyncio
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
from aio_pika.abc import AbstractIncomingMessage
from pydantic import ValidationError as PydanticValidationError

from src.config import Settings
from src.core.scan import icmp_socket
from src.core.scan.runner import scan_ip
from src.database import repository
from src.database.connections import DatabaseConnection
from src.database.repository import ResultRow
from src.queue.connections import QueueConnection
from src.queue.producer import JobProducer
from src.queue.schemas import BatchMessage
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
        self.producer = JobProducer(self.queue)
        self._rate_limiter = RateLimiter(settings.worker.rate_limit_per_pod)
        self._queue = None  # the declared aio-pika queue
        self._consumer_tag: str | None = None
        self._stop = asyncio.Event()
        self._idle = asyncio.Event()
        self._idle.set()  # idle until a batch is in flight
        self._inflight = 0
        # Created in run() (must bind to the running loop): a process-wide ceiling
        # on concurrent outbound connects shared across every IP/batch in flight.
        self._conn_limit: asyncio.Semaphore | None = None

    async def run(self) -> None:
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        print(f"worker: code build {_code_build_time()} | started {started}")

        icmp_mode = icmp_socket.mode()
        if icmp_mode == "subprocess":
            print(
                "worker: ICMP via 'ping' subprocess (no raw/datagram socket available)"
            )
        else:
            print(f"worker: ICMP via {icmp_mode} socket")

        loop = asyncio.get_running_loop()
        loop.set_default_executor(
            ThreadPoolExecutor(
                max_workers=self.settings.worker.thread_pool_size,
                thread_name_prefix="probe",
            )
        )

        max_conns = self.settings.worker.max_concurrent_connections
        self._conn_limit = asyncio.Semaphore(max_conns) if max_conns > 0 else None
        if self._conn_limit is not None:
            print(f"worker: outbound connect limit = {max_conns}")

        await self.db.connect()
        channel = await self.queue.channel(
            prefetch_count=self.settings.queue.prefetch_count
        )
        self._queue = await self.queue.declare_queue(channel)
        self._consumer_tag = await self._queue.consume(self._on_message)
        print(
            f"worker: consuming from '{self.settings.queue.queue_name}' "
            f"(prefetch={self.settings.queue.prefetch_count}, "
            f"max_connections={self.settings.worker.max_connections})"
        )

        self._install_signal_handlers()
        await self._stop.wait()
        await self._shutdown()

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except (NotImplementedError, AttributeError, ValueError):
                # Windows / unsupported loop: fall back to KeyboardInterrupt.
                pass

    async def _shutdown(self) -> None:
        print(f"worker: shutdown signal received, draining {self._inflight} batch(es)")
        if self._queue is not None and self._consumer_tag is not None:
            try:
                await self._queue.cancel(self._consumer_tag)
            except Exception as exc:
                print(f"worker: error cancelling consumer: {exc!r}")

        grace = self.settings.worker.shutdown_grace_seconds
        try:
            await asyncio.wait_for(self._idle.wait(), timeout=grace)
            print("worker: drained cleanly")
        except asyncio.TimeoutError:
            print(
                f"worker: grace period ({grace}s) elapsed with {self._inflight} "
                f"batch(es) still running; they will be requeued"
            )

        await self.queue.close()
        await self.db.close()
        print("worker: stopped")

    async def _on_message(self, message: AbstractIncomingMessage) -> None:
        self._inflight += 1
        self._idle.clear()
        try:
            await self._dispatch(message)
        finally:
            self._inflight -= 1
            if self._inflight == 0:
                self._idle.set()

    async def _dispatch(self, message: AbstractIncomingMessage) -> None:
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
            await self._handle_failure(batch, exc)
            await message.ack()
            return

        await message.ack()

    async def _handle_failure(self, batch: BatchMessage, exc: Exception) -> None:
        if batch.retry_count < self.settings.worker.max_retries:
            batch.retry_count += 1
            print(
                f"worker: retry {batch.retry_count}/{self.settings.worker.max_retries} "
                f"for job_id={batch.job_id} batch={batch.batch_id}: {exc!r}"
            )
            await self.producer.publish_batch(batch)
            return

        print(
            f"worker: giving up on job_id={batch.job_id} batch={batch.batch_id} "
            f"after {batch.retry_count} retries: {exc!r}"
        )
        await self._reconcile_abandoned(batch)

    async def _reconcile_abandoned(self, batch: BatchMessage) -> None:
        try:
            async with self.db.pool.acquire() as conn, conn.transaction():
                await repository.increment_processed(conn, batch.job_id, len(batch.ips))
                await repository.notify_results(conn, batch.job_id)
        except Exception as exc:  # never let reconciliation failure requeue
            print(f"worker: reconcile failed for job_id={batch.job_id}: {exc!r}")

    async def _process_batch(self, batch: BatchMessage) -> None:
        results: asyncio.Queue[dict | None] = asyncio.Queue()
        semaphore = asyncio.Semaphore(self.settings.worker.max_connections)

        async def run_one(ip: str) -> None:
            async with semaphore:
                await self._rate_limiter.acquire()
                document = await scan_ip(ip, self.settings, self._conn_limit)
                await results.put(document)

        flusher = asyncio.create_task(self._flush_loop(batch.job_id, results))
        try:
            await asyncio.gather(*(run_one(ip) for ip in batch.ips))
        finally:
            await results.put(None)
            await flusher

    async def _flush_loop(
        self, job_id: str, results: asyncio.Queue[dict | None]
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
        async with self.db.pool.acquire() as conn, conn.transaction():
            inserted = await repository.insert_results(conn, job_id, rows)
            if inserted:
                await repository.increment_processed(conn, job_id, inserted)
                await repository.notify_results(conn, job_id)


def _row_from_document(doc: dict) -> ResultRow:
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
