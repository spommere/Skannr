from persistence.filesystem import FilesystemPersistence
from persistence.none import NonePersistence


def load_persistence(config):
    """Create the configured persistence backend."""
    persistence_config = config.get("persistence", {})
    backend = persistence_config.get("backend", "none")
    if backend == "filesystem":
        return FilesystemPersistence(persistence_config.get("filesystem", {}))
    return NonePersistence({})
