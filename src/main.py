from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from src.api.routes import router
from src.config import get_settings
from src.database.connections import DatabaseConnection
from src.queue.connections import QueueConnection
from src.queue.producer import JobProducer


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()

    db = DatabaseConnection(settings.database)
    await db.connect()
    queue_connection = QueueConnection(settings.queue)
    await queue_connection.connect()

    application.state.db = db
    application.state.queue_connection = queue_connection
    application.state.producer = JobProducer(queue_connection)
    try:
        yield
    finally:
        await queue_connection.close()
        await db.close()


def create_app() -> FastAPI:
    application = FastAPI(title="Network Scanner", version="0.0.1", lifespan=lifespan)
    application.include_router(router)
    return application


app = create_app()
