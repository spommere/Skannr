from persistence.base import BasePersistence


class NonePersistence(BasePersistence):
    """No-op backend used when persistence is disabled."""

    name = "none"

    def write(self, event):
        """Accept events without writing them anywhere."""
        return None
