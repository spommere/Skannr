import json
import os
import time
from datetime import datetime

from log_utils import normalize_retention_days
from persistence.base import BasePersistence


class FilesystemPersistence(BasePersistence):
    """Append events as JSON Lines files grouped by collector and day."""

    name = "filesystem"

    def __init__(self, config):
        super().__init__(config)
        # log_dir is relative to the current working directory when Skannr is
        # launched. The install/run instructions start from /tmp/skannr, so
        # the default becomes /tmp/skannr/logs.
        self.log_dir = config.get("log_dir", "./logs")
        self.retention_days = normalize_retention_days(config.get("retention_days", 30))
        os.makedirs(self.log_dir, exist_ok=True)
        self.rotate()

    def write(self, event):
        """Append one event to logs/<collector>/<YYYY-MM-DD>.jsonl."""
        collector = event.get("collector", "system")
        date = datetime.now().strftime("%Y-%m-%d")
        directory = os.path.join(self.log_dir, collector)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "{}.jsonl".format(date))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

    def query(self, collector=None, since=None, until=None, limit=100):
        """Read recent JSONL events.

        since/until are placeholders for a future query API; today the dashboard
        only needs a simple tail, so this returns the last limit events found
        without reading every retained log file during startup.
        """
        if limit <= 0:
            return []
        events = []
        roots = [os.path.join(self.log_dir, collector)] if collector else [
            os.path.join(self.log_dir, name) for name in os.listdir(self.log_dir)
        ]
        for root in roots:
            if not os.path.isdir(root):
                continue
            for filename in sorted(os.listdir(root), reverse=True):
                if not filename.endswith(".jsonl"):
                    continue
                path = os.path.join(root, filename)
                for line in reversed(self.read_lines(path)):
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        # Ignore partial/corrupt lines so one bad write does
                        # not make the whole history unreadable.
                        continue
                    if len(events) >= limit:
                        break
                if len(events) >= limit:
                    break
        return list(reversed(events[-limit:]))

    def read_lines(self, path):
        """Read one JSONL file, returning an empty list when it disappears."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.readlines()
        except OSError:
            return []

    def rotate(self):
        """Delete old JSONL files based on retention_days."""
        cutoff = time.time() - (self.retention_days * 86400)
        for root, _dirs, files in os.walk(self.log_dir):
            for filename in files:
                path = os.path.join(root, filename)
                if filename.endswith(".jsonl") and os.path.getmtime(path) < cutoff:
                    os.remove(path)

    def stats(self):
        """Summarize persistence storage for diagnostics."""
        file_count = 0
        total_size = 0
        for root, _dirs, files in os.walk(self.log_dir):
            for filename in files:
                path = os.path.join(root, filename)
                file_count += 1
                total_size += os.path.getsize(path)
        return {
            "backend": self.name,
            "log_dir": self.log_dir,
            "file_count": file_count,
            "total_size": total_size,
        }
