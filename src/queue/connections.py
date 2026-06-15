from __future__ import annotations

import aio_pika
from aio_pika.abc import AbstractRobustConnection, AbstractChannel, AbstractQueue
from src.config import QueueSettings


class QueueConnection:
    def __init__(self, settings: QueueSettings) -> None:
        self.settings = settings
        self._connection: AbstractRobustConnection | None = None

    async def connect(self) -> AbstractRobustConnection:
        if self._connection is None or self._connection.is_closed:
            self._connection = await aio_pika.connect_robust(self.settings.url)

        assert self._connection is not None
        return self._connection

    async def channel(self, prefetch_count: int | None = None) -> AbstractChannel:
        connection = await self.connect()
        channel = await connection.channel()
        if prefetch_count is not None:
            await channel.set_qos(prefetch_count=prefetch_count)
        return channel

    async def declare_queue(self, channel: AbstractChannel) -> AbstractQueue:
        return await channel.declare_queue(self.settings.queue_name, durable=self.settings.durable)

    async def close(self) -> None:
        if self._connection is not None and not self._connection.is_closed:
            await self._connection.close()
        self._connection = None
