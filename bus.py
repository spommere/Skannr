import asyncio
from datetime import datetime


def local_now():
    """Return local timestamps for event payloads and UI display."""
    return datetime.now().replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")


def utc_now():
    """Compatibility wrapper for existing call sites; returns local time now."""
    return local_now()


class EventBus:
    """Small async event bus shared by all collectors.

    Collectors only know how to publish events. The main runtime consumes this
    queue and decides what to persist and what to forward to connected browsers.
    """

    def __init__(self):
        self.queue = asyncio.Queue()

    async def publish(self, event):
        """Normalize an event and enqueue it for the runtime fan-out task."""
        event.setdefault("timestamp", utc_now())
        event.setdefault("severity", "info")
        event.setdefault("data", {})
        await self.queue.put(event)

    async def next(self):
        """Wait for the next event from any collector."""
        return await self.queue.get()
