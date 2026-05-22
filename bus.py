"""Process-local event plumbing shared by collectors and the web runtime.

Collectors publish normalized dictionaries here instead of writing logs or
talking to the browser directly. That keeps each collector focused on one radio
or tool while main.py owns persistence, findings generation, and UI fan-out.
"""

import asyncio

from log_utils import format_epoch, now_epoch, timestamp_epoch


def local_now(epoch=None):
    """Return Skannr's local display timestamp for an epoch value."""
    return format_epoch(now_epoch() if epoch is None else epoch)


class EventBus:
    """Small async event bus shared by all collectors.

    Collectors only know how to publish events. The main runtime consumes this
    queue and decides what to persist and what to forward to connected browsers.
    """

    def __init__(self):
        self.queue = asyncio.Queue()

    async def publish(self, event):
        """Normalize an event and enqueue it for the runtime fan-out task."""
        # Every persisted/UI event should have these fields, even if a collector
        # only supplied the collector/type-specific data.
        data = event.setdefault("data", {})
        epoch = timestamp_epoch(event.get("timestamp_epoch"))
        if epoch is None:
            epoch = timestamp_epoch(data.get("timestamp_epoch"))
        if epoch is None:
            epoch = now_epoch()
        event["timestamp_epoch"] = epoch
        event.setdefault("timestamp", local_now(epoch))
        event.setdefault("severity", "info")
        await self.queue.put(event)

    async def next(self):
        """Wait for the next event from any collector."""
        return await self.queue.get()
