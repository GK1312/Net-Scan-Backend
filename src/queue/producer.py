from __future__ import annotations

import aio_pika
from aio_pika.abc import AbstractChannel

from src.queue.connections import QueueConnection
from src.queue.schemas import BatchMessage


class JobProducer:
    def __init__(self, connection: QueueConnection) -> None:
        self.connection = connection
        self._channel: AbstractChannel | None = None

    async def _get_channel(self) -> AbstractChannel:
        if self._channel is None or self._channel.is_closed:
            self._channel = await self.connection.channel()

            assert self._channel is not None
            await self.connection.declare_queue(self._channel)

        assert self._channel is not None
        return self._channel

    async def publish_batch(self, messages: BatchMessage) -> None:
        channel = await self._get_channel()
        body = messages.model_dump_json().encode()
        await channel.default_exchange.publish(
            aio_pika.Message(
                body=body,
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            ),
            routing_key=self.connection.settings.queue_name,
        )

    async def publish_job(self, messages: list[BatchMessage]) -> int:
        for message in messages:
            await self.publish_batch(message)
        return len(messages)
