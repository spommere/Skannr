"""Persistence backend loader.

Skannr currently ships filesystem JSONL persistence and a no-op backend. The
rest of the app calls the BasePersistence interface and does not know which one
was selected in config/skannr.yaml.
"""

from .filesystem import FilesystemPersistence
from .none import NonePersistence


def load_persistence(config):
    """Create the configured persistence backend."""
    persistence_config = config.get("persistence", {})
    backend = persistence_config.get("backend", "none")
    if backend == "filesystem":
        return FilesystemPersistence(persistence_config.get("filesystem", {}))
    # Unknown/disabled backends fall back to no-op persistence so collectors can
    # still run in a test or temporary session.
    return NonePersistence({})
