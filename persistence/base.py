"""Persistence interface used by the runtime fan-out path."""


class BasePersistence:
    """Interface implemented by persistence backends."""

    name = "base"

    def __init__(self, config):
        self.config = config

    def write(self, event):
        """Store one normalized event."""
        raise NotImplementedError

    def query(self, collector=None, since=None, until=None, limit=100):
        """Return recent events; backends may ignore filters they do not need."""
        return []

    def rotate(self):
        """Apply retention policy if the backend has one."""
        return None

    def stats(self):
        """Return small status data for diagnostics/system views."""
        return {
            "backend": self.name,
            "log_dir": None,
            "file_count": 0,
            "total_size": 0,
        }
