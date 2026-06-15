from __future__ import annotations

import asyncio

from src.config import get_settings
from src.queue.consumer import Worker


async def main() -> None:
    worker = Worker(get_settings())
    await worker.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
