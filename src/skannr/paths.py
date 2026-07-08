"""Filesystem layout constants for the standard Skannr tree."""

import os

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.dirname(PACKAGE_DIR)
PROJECT_ROOT = os.path.dirname(SRC_DIR)


def _user_config_dir():
    """Return ~/.config/skannr for the real user, even when running as root.

    When Skannr starts via ``sudo``, ``os.path.expanduser("~")`` resolves to
    ``/root`` because the process runs as root.  ``SUDO_USER`` tells us who
    invoked sudo so config lands in that user's home directory.
    When started by systemd (no ``SUDO_USER``), we fall back to the home of
    uid 1000 (the default Pi user).
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "skannr")
    user = os.environ.get("SUDO_USER")
    if user:
        return os.path.join("/home", user, ".config", "skannr")
    home = os.path.expanduser("~")
    if home != "/root":
        return os.path.join(home, ".config", "skannr")
    # Systemd or root login — resolve the Pi user's home.
    try:
        import pwd

        pi_home = pwd.getpwuid(1000).pw_dir
        return os.path.join(pi_home, ".config", "skannr")
    except (ImportError, KeyError):
        return os.path.join("/home/pi", ".config", "skannr")


CONFIG_DIR = _user_config_dir()
CONFIG_PATH = os.path.join(CONFIG_DIR, "skannr.yaml")
CONFIG_COLLECTORS_DIR = os.path.join(CONFIG_DIR, "collectors")

# Pre-0.3.5 location — used only for one-time migration on startup.
OLD_CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")

RUNTIME_DIR = os.path.join(PROJECT_ROOT, "runtime")
RUNTIME_LOG_DIR = os.path.join(RUNTIME_DIR, "logs")

DATA_DIR = os.path.join(PACKAGE_DIR, "data")
DATA_COLLECTORS_DIR = os.path.join(DATA_DIR, "collectors")
STATIC_DIR = os.path.join(PACKAGE_DIR, "static")
VERSION_PATH = os.path.join(PROJECT_ROOT, "VERSION")


def get_real_user_uid_gid():
    """Return ``(uid, gid)`` for the real user, even when running as root via sudo.

    Returns ``(0, 0)`` when we cannot determine the real user (e.g. running as
    real root, or pwd unavailable).
    """
    user = os.environ.get("SUDO_USER")
    if user:
        try:
            import pwd

            pw = pwd.getpwnam(user)
            return (pw.pw_uid, pw.pw_gid)
        except (ImportError, KeyError):
            pass
    # Fall back to uid 1000 (default Pi user) when started by systemd.
    try:
        import pwd

        pw = pwd.getpwuid(1000)
        return (pw.pw_uid, pw.pw_gid)
    except (ImportError, KeyError):
        pass
    return (0, 0)


def ensure_owner(path):
    """Chown *path* to the real user when running as root via sudo.

    No-op when the real user cannot be determined or is already root.
    Errors (e.g. read-only filesystem) are silently ignored.
    """
    uid, gid = get_real_user_uid_gid()
    if uid == 0 and gid == 0:
        return
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass
