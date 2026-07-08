"""Optional external alert notification delivery."""

import logging
import urllib.parse
import urllib.request

from .connectivity import internet_available

PUSHOVER_MESSAGES_URL = "https://api.pushover.net/1/messages.json"
PUSHOVER_MESSAGE_MAX = 1024


def pushover_enabled(config):
    """Return True when Pushover notification delivery is configured."""
    return bool((config or {}).get("enabled", False))


def pushover_ready(config):
    """Return True when Pushover has both required credentials."""
    config = config or {}
    return bool(
        pushover_enabled(config)
        and str(config.get("userkey") or "").strip()
        and str(config.get("appkey") or "").strip()
    )


def pushover_alert_message(alert):
    """Return a compact human-readable alert message for Pushover."""
    alert = alert or {}
    parts = []
    level = str(alert.get("level") or "").strip().upper()
    title = str(alert.get("title") or "").strip()
    subject = str(alert.get("subject") or "").strip()
    summary = str(alert.get("summary") or "").strip()
    source = str(alert.get("source") or "").strip()
    if level:
        parts.append(level)
    if title:
        parts.append(title)
    if subject:
        parts.append(subject)
    if summary and summary not in parts:
        parts.append(summary)
    if source:
        parts.append("source {}".format(source))
    message = " | ".join(parts) or "Skannr alert"
    if len(message) > PUSHOVER_MESSAGE_MAX:
        return message[: PUSHOVER_MESSAGE_MAX - 3] + "..."
    return message


def send_pushover_alert(alert, config):
    """Send one alert through the Pushover Messages API."""
    config = config or {}
    if not pushover_enabled(config):
        return False
    if not pushover_ready(config):
        logging.warning("Pushover alert delivery enabled but userkey/appkey is missing")
        return False
    timeout = float(config.get("timeout_sec") or 5)
    if not internet_available(timeout=min(timeout, 3)):
        logging.warning(
            "Pushover alert delivery skipped: internet connectivity unavailable"
        )
        return False
    payload = urllib.parse.urlencode(
        {
            "token": str(config.get("appkey") or "").strip(),
            "user": str(config.get("userkey") or "").strip(),
            "title": "Skannr Alert",
            "message": pushover_alert_message(alert),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        PUSHOVER_MESSAGES_URL,
        data=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Skannr",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = response.getcode()
        if status < 200 or status >= 300:
            logging.warning("Pushover alert delivery returned HTTP %s", status)
            return False
    logging.info(
        "Pushover alert delivered id=%s level=%s type=%s",
        (alert or {}).get("id") or "",
        (alert or {}).get("level") or "",
        (alert or {}).get("alert_type") or "",
    )
    return True
