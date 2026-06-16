from __future__ import annotations

import asyncio

from src.core.scan.constants import (
    MQTT,
    MQTT_CONNACK_BYTES,
    MQTT_CONNECT_PACKET,
    MQTT_CONNACK_BYTE0,
    MQTT_CONNACK_BYTE1,
)
from src.core.scan.context import ProbeContext
from src.core.scan.models import MqttResult


async def run(ctx: ProbeContext) -> MqttResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, MQTT), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return MqttResult()

    try:
        writer.write(MQTT_CONNECT_PACKET)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(MQTT_CONNACK_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return MqttResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    if len(reply) >= 2 and reply[0] == MQTT_CONNACK_BYTE0 and reply[1] == MQTT_CONNACK_BYTE1:
        return MqttResult(responded=True)
    return MqttResult()
