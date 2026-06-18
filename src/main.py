from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.api.routes import router
from src.config import get_settings
from src.database.connections import DatabaseConnection
from src.database.notify import NotifyDispatcher
from src.queue.connections import QueueConnection
from src.queue.producer import JobProducer
from src.utils.ratelimit import ClientRateLimiter


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()

    db = DatabaseConnection(settings.database)
    await db.connect()
    queue_connection = QueueConnection(settings.queue)
    await queue_connection.connect()

    dispatcher = NotifyDispatcher(db.pool, settings.database.notify_channel)
    await dispatcher.start()

    application.state.db = db
    application.state.queue_connection = queue_connection
    application.state.producer = JobProducer(queue_connection)
    application.state.notify = dispatcher
    application.state.rate_limiter = _build_rate_limiter(settings)
    try:
        yield
    finally:
        await dispatcher.stop()
        await queue_connection.close()
        await db.close()


def _build_rate_limiter(settings) -> ClientRateLimiter | None:
    per_minute = settings.security.rate_limit_per_minute
    if per_minute <= 0:
        return None
    burst = settings.security.rate_limit_burst or per_minute
    return ClientRateLimiter(rate_per_sec=per_minute / 60.0, burst=burst)


def create_app() -> FastAPI:
    application = FastAPI(title="Network Scanner", version="0.0.1", lifespan=lifespan)
    application.include_router(router)
    return application


app = create_app()
