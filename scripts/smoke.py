from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from uuid import uuid4

from src.api.routes import _result_event_stream
from src.config import get_settings
from src.database import repository
from src.database.connections import DatabaseConnection
from src.database.notify import NotifyDispatcher
from src.queue.connections import QueueConnection
from src.queue.consumer import Worker
from src.queue.producer import JobProducer
from src.queue.schemas import BatchMessage
from src.utils.helpers import chunk
from src.utils.validators import expand_targets

_DEADLINE_SECONDS = 90.0


async def _publish_job(producer, db, settings, targets: list[str]):
    valid, invalid = expand_targets(targets, max_count=100_000)
    job_id = uuid4()
    now = datetime.now(timezone.utc)
    await repository.create_job(db.pool, job_id, len(valid))
    messages = [
        BatchMessage(
            job_id=str(job_id),
            batch_id=str(i),
            ips=batch,
            phase=["ping"],
            created_at=now,
        )
        for i, batch in enumerate(chunk(valid, settings.worker.batch_size))
    ]
    await producer.publish_job(messages)
    print(f"smoke: published job {job_id} — {len(valid)} ip(s), {len(invalid)} invalid")
    return job_id, len(valid)


async def _wait_for_completion(db, job_id) -> dict:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _DEADLINE_SECONDS
    while loop.time() < deadline:
        job = await repository.fetch_job(db.pool, job_id)
        if job and job["status"] == "completed":
            return dict(job)
        await asyncio.sleep(0.5)
    raise TimeoutError(f"job {job_id} did not complete within {_DEADLINE_SECONDS}s")


async def _collect_stream(db, settings, job_id) -> list[str]:
    dispatcher = NotifyDispatcher(db.pool, settings.database.notify_channel)
    await dispatcher.start()
    events: list[str] = []
    try:
        async for chunk_text in _result_event_stream(db, dispatcher, str(job_id), None):
            events.append(chunk_text)
            if "event: done" in chunk_text:
                break
    finally:
        await dispatcher.stop()
    return events


async def main(targets: list[str]) -> int:
    settings = get_settings()
    db = DatabaseConnection(settings.database)
    queue = QueueConnection(settings.queue)
    await db.connect()
    await queue.connect()
    producer = JobProducer(queue)

    worker = Worker(settings)
    worker_task = asyncio.create_task(worker.run())
    try:
        job_id, total = await _publish_job(producer, db, settings, targets)

        job = await _wait_for_completion(db, job_id)
        print(
            f"smoke: job completed — processed {job['processed_count']}/{job['total_ips']}"
        )

        rows = await repository.fetch_results_page(
            db.pool, job_id, limit=10_000, offset=0
        )
        assert job["processed_count"] == total, "processed_count != total"
        assert len(rows) == total, f"expected {total} result rows, got {len(rows)}"

        events = await _collect_stream(db, settings, job_id)
        assert any("event: done" in e for e in events), "stream never emitted 'done'"
        print(f"smoke: stream emitted {len(events)} event(s), including 'done'")

        sample = repository.serialize_result(rows[0])["classification"]
        print(
            f"smoke: sample classification — {sample['ip']}: "
            f"{sample['platform']} ({sample['confidence']}%) reachable={sample['reachable']}"
        )
    finally:
        worker._stop.set()
        await worker_task
        await queue.close()
        await db.close()

    print("smoke: PASS")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:] or ["127.0.0.1", "8.8.8.8"]
    try:
        raise SystemExit(asyncio.run(main(args)))
    except (AssertionError, TimeoutError, OSError) as exc:
        print(f"smoke: FAIL — {exc!r}")
        raise SystemExit(1) from exc
