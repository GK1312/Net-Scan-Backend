from __future__ import annotations

import asyncio

from src.core.scan.context import ProbeContext
from src.core.scan.models import MqttResult

MQTT_PORT = 1883
_REPLY_BYTES = 64

_MQTT_CONNECT = bytes(
    [
        0x10,
        0x12,
        0x00,
        0x04,
        0x4D,
        0x51,
        0x54,
        0x54,
        0x04,
        0x00,
        0x00,
        0x3C,
        0x00,
        0x06,
        0x70,
        0x72,
        0x6F,
        0x62,
        0x65,
        0x31,
    ]
)


async def run(ctx: ProbeContext) -> MqttResult:
    timeout = ctx.timeouts.tcp_connect_timeout
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.ip, MQTT_PORT), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return MqttResult()

    try:
        writer.write(_MQTT_CONNECT)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(_REPLY_BYTES), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return MqttResult()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    if len(reply) >= 2 and reply[0] == 0x20 and reply[1] == 0x02:
        return MqttResult(responded=True)
    return MqttResult()
