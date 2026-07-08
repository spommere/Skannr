"""Small shared connectivity checks for internet-fed integrations."""

import socket

DEFAULT_INTERNET_TARGETS = (
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
)


def internet_available(targets=None, timeout=2):
    """Return True when at least one generic internet target is reachable."""
    for host, port in targets or DEFAULT_INTERNET_TARGETS:
        try:
            with socket.create_connection((host, int(port)), timeout=float(timeout)):
                return True
        except OSError:
            continue
    return False
