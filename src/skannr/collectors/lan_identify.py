"""On-demand active LAN device identification.

The regular LAN collector stays passive or low-impact. This action runs only
when the operator requests identification for one observed IP address, then
uses bounded `nmap` and `curl` probes to extract compact service/HTTP clues.
"""

import asyncio
import html
import ipaddress
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET

from .base import BaseCollector, STATE_OFFLINE, STATE_STOPPED
from .lan import clean_lan_data, compact_lan_text


DEFAULT_NMAP_PORTS = "22,23,53,80,443,554,1900,5000,5353,8008,8080,8443,9100"
DEFAULT_HTTP_PORTS = (80, 443, 5000, 8008, 8080, 8443)
DEFAULT_HINT_PATTERNS = (
    "airplay",
    "amazon",
    "arlo",
    "brother",
    "canon",
    "chamberlain",
    "chromecast",
    "ecobee",
    "epson",
    "garage",
    "google",
    "homekit",
    "hue",
    "ipp",
    "liftmaster",
    "myq",
    "nest",
    "philips",
    "printer",
    "reolink",
    "ring",
    "roku",
    "samsung",
    "sonos",
    "tplink",
    "tp-link",
    "ubiquiti",
    "unifi",
    "wyze",
)


class LANIdentifyCollector(BaseCollector):
    """On-demand LAN service/HTTP clue collector."""

    config_key = "lan_identify"
    name = "LAN Identify"
    tab_label = "LAN Identify"
    required_hardware = "nmap/curl for active LAN identification"

    @classmethod
    def hardware_status(cls, config):
        """Return local command availability for LAN Identify."""
        return {
            "nmap": bool(shutil.which("nmap")),
            "curl": bool(shutil.which("curl")),
            "enabled": bool(config.get("enabled", True)),
        }

    async def start(self):
        """Do not run a background loop; identification is target-based."""
        self._running = False
        self.state = STATE_STOPPED if self.detect() else STATE_OFFLINE

    def detect(self):
        """LAN Identify needs at least nmap or curl available."""
        tools = []
        if shutil.which("nmap"):
            tools.append("nmap")
        if shutil.which("curl"):
            tools.append("curl")
        if not tools:
            self.state = STATE_OFFLINE
            self.warning = "Neither nmap nor curl is installed."
            return False
        self.active_hardware = ", ".join(tools)
        self.state = STATE_STOPPED
        self.warning = None
        return True

    async def identify(self, target, mac="", subject_key="", timeout=None):
        """Probe one IPv4/IPv6 target and emit compact identification clues."""
        target = self.normalize_target(target)
        mac = compact_lan_text(mac, 80)
        subject_key = compact_lan_text(subject_key, 160)
        if not target:
            await self.emit(
                "identify_failed",
                {"reason": "LAN Identify needs an IPv4 or IPv6 address."},
                "warning",
            )
            return
        if not self.detect():
            await self.emit(
                "collector_offline", {"reason": self.warning}, "warning"
            )
            return

        timeout = float(timeout or self.config.get("identify_timeout_sec", 30))
        await self.emit(
            "identify_started",
            {
                "target": target,
                "ip": target,
                "mac": mac,
                "subject_key": subject_key,
                "timeout_sec": timeout,
                "tools": self.active_hardware,
            },
        )
        started = time.time()
        result = await self.run_blocking(
            self.identify_sync, target, mac, subject_key, timeout
        )
        result["duration_sec"] = round(time.time() - started, 2)
        event_type = "identify_result" if result.get("identified") else "identify_failed"
        severity = "info" if result.get("identified") else "warning"
        await self.emit(event_type, clean_lan_data(result), severity)

    async def run_blocking(self, callback, *args):
        """Run blocking subprocess work without Python 3.9 to_thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, callback, *args)

    def identify_sync(self, target, mac, subject_key, timeout):
        """Run bounded nmap/curl probes for one target."""
        result = {
            "target": target,
            "ip": target,
            "mac": mac,
            "subject_key": subject_key or ("ip:{}".format(target)),
            "open_ports": [],
            "service_banners": [],
            "http_urls": [],
            "http_titles": [],
            "http_headers": [],
            "http_scripts": [],
            "http_hints": [],
            "identify_errors": [],
            "nmap_available": bool(shutil.which("nmap")),
            "curl_available": bool(shutil.which("curl")),
            "identified": False,
        }
        nmap_ports = []
        if shutil.which("nmap"):
            nmap_result = self.run_nmap(target, timeout)
            result["open_ports"] = nmap_result.get("open_ports") or []
            result["service_banners"] = nmap_result.get("service_banners") or []
            result["identify_errors"].extend(nmap_result.get("errors") or [])
            nmap_ports = nmap_result.get("http_ports") or []
        else:
            result["identify_errors"].append("nmap is not installed")

        if shutil.which("curl"):
            http_ports = nmap_ports or self.configured_http_probe_ports()
            for url in self.http_probe_urls(target, http_ports):
                http_info = self.run_curl(url, timeout)
                self.merge_http_info(result, http_info)
        else:
            result["identify_errors"].append("curl is not installed")

        result["identified"] = bool(
            result["open_ports"]
            or result["service_banners"]
            or result["http_titles"]
            or result["http_scripts"]
            or result["http_hints"]
        )
        return result

    def normalize_target(self, target):
        """Return a safe IPv4/IPv6 target string, or blank."""
        text = compact_lan_text(target, 120).strip("[]")
        if not text:
            return ""
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return ""

    def run_nmap(self, target, timeout):
        """Run a bounded nmap service scan and parse XML output."""
        nmap_timeout = int(float(self.config.get("nmap_timeout_sec", timeout)))
        nmap_timeout = max(3, nmap_timeout)
        command_timeout = nmap_timeout + 5
        ports = compact_lan_text(
            self.config.get("nmap_ports") or DEFAULT_NMAP_PORTS, 300
        )
        cmd = [
            "nmap",
            "-sV",
            "--version-light",
            "--max-retries",
            "1",
            "--host-timeout",
            "{}s".format(nmap_timeout),
            "-p",
            ports,
            "-oX",
            "-",
        ]
        try:
            if ipaddress.ip_address(target).version == 6:
                cmd.insert(1, "-6")
        except ValueError:
            pass
        cmd.append(target)
        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=command_timeout,
                universal_newlines=True,
            )
        except subprocess.TimeoutExpired:
            return {"errors": ["nmap timed out after {}s".format(command_timeout)]}
        except Exception as exc:
            return {"errors": ["nmap failed: {}".format(exc)]}

        parsed = self.parse_nmap_xml(completed.stdout)
        errors = parsed.get("errors") or []
        if completed.returncode not in (0, 1):
            detail = compact_lan_text(completed.stderr or completed.stdout, 240)
            errors.append("nmap exited {}{}".format(
                completed.returncode, ": {}".format(detail) if detail else ""
            ))
        parsed["errors"] = errors
        return parsed

    def parse_nmap_xml(self, text):
        """Extract compact open-port/service fields from nmap XML."""
        try:
            root = ET.fromstring(text or "")
        except Exception as exc:
            return {"errors": ["nmap XML parse failed: {}".format(exc)]}
        open_ports = []
        service_banners = []
        http_ports = []
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            proto = port.get("protocol") or "tcp"
            portid = port.get("portid") or ""
            service = port.find("service")
            name = service.get("name") if service is not None else ""
            product = service.get("product") if service is not None else ""
            version = service.get("version") if service is not None else ""
            extra = service.get("extrainfo") if service is not None else ""
            label = "/".join(part for part in (portid, proto) if part)
            detail = " ".join(
                part for part in (label, name, product, version, extra) if part
            )
            open_ports.append(compact_lan_text(detail, 160))
            if any(part for part in (product, version, extra)):
                service_banners.append(compact_lan_text(detail, 160))
            try:
                port_number = int(portid)
            except (TypeError, ValueError):
                port_number = None
            if port_number and self.port_looks_http(port_number, name):
                http_ports.append(port_number)
        return {
            "open_ports": unique(open_ports, 24),
            "service_banners": unique(service_banners, 16),
            "http_ports": unique(http_ports, 8),
            "errors": [],
        }

    def port_looks_http(self, port, service_name):
        """Return true for ports worth trying with curl."""
        name = str(service_name or "").lower()
        return port in self.configured_http_probe_ports() or "http" in name

    def configured_http_probe_ports(self):
        """Return configured HTTP probe ports as integers."""
        ports = self.config.get("http_probe_ports") or DEFAULT_HTTP_PORTS
        output = []
        for port in ports:
            try:
                output.append(int(port))
            except (TypeError, ValueError):
                continue
        return output or list(DEFAULT_HTTP_PORTS)

    def http_probe_urls(self, target, ports):
        """Return HTTP/HTTPS root URLs to probe for one IP target."""
        host = "[{}]".format(target) if ":" in target else target
        urls = []
        for port in ports:
            scheme = "https" if int(port) in (443, 8443) else "http"
            netloc = host if int(port) in (80, 443) else "{}:{}".format(host, int(port))
            urls.append("{}://{}/".format(scheme, netloc))
        return unique(urls, 8)

    def run_curl(self, url, timeout):
        """Fetch one HTTP root with curl and return compact clues."""
        curl_timeout = float(self.config.get("curl_timeout_sec", min(timeout, 10)))
        curl_timeout = max(2.0, curl_timeout)
        cmd = [
            "curl",
            "-k",
            "-L",
            "--max-redirs",
            "1",
            "--connect-timeout",
            str(int(min(3, curl_timeout))),
            "--max-time",
            str(int(curl_timeout)),
            "-i",
            "-sS",
            url,
        ]
        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=curl_timeout + 2,
                universal_newlines=True,
            )
        except subprocess.TimeoutExpired:
            return {"url": url, "errors": ["curl timed out for {}".format(url)]}
        except Exception as exc:
            return {"url": url, "errors": ["curl failed for {}: {}".format(url, exc)]}
        output = (completed.stdout or "")[: int(self.config.get("curl_output_max_bytes", 30000))]
        info = self.extract_http_info(url, output)
        if completed.returncode != 0:
            detail = compact_lan_text(completed.stderr or completed.stdout, 220)
            info.setdefault("errors", []).append(
                "curl exited {} for {}{}".format(
                    completed.returncode,
                    url,
                    ": {}".format(detail) if detail else "",
                )
            )
        return info

    def extract_http_info(self, url, output):
        """Extract title, selected headers, scripts, and brand-like hints."""
        headers, body = split_http_response(output)
        info = {
            "url": url,
            "headers": selected_http_headers(headers),
            "title": first_regex(body, r"<title[^>]*>(.*?)</title>"),
            "scripts": unique(
                re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", body or "", re.I),
                8,
            ),
            "hints": self.http_hints(body),
            "errors": [],
        }
        return info

    def http_hints(self, body):
        """Return compact text snippets that identify common local devices."""
        text = html.unescape(strip_tags(body or ""))
        lines = [compact_lan_text(line, 180) for line in text.splitlines()]
        patterns = [
            str(item or "").lower()
            for item in (self.config.get("http_hint_patterns") or DEFAULT_HINT_PATTERNS)
            if str(item or "").strip()
        ]
        hints = []
        for line in lines:
            lowered = line.lower()
            if "copyright" in lowered or "\u00a9" in lowered:
                hints.append(line)
                continue
            if any(pattern in lowered for pattern in patterns):
                hints.append(line)
        return unique([item for item in hints if item], 12)

    def merge_http_info(self, result, info):
        """Fold one HTTP probe result into the action result."""
        if not info:
            return
        url = compact_lan_text(info.get("url"), 160)
        if url:
            append_unique(result["http_urls"], url, 12)
        for source, dest, limit in (
            ("headers", "http_headers", 16),
            ("scripts", "http_scripts", 16),
            ("hints", "http_hints", 16),
        ):
            for item in info.get(source) or []:
                append_unique(result[dest], compact_lan_text(item, 180), limit)
        title = compact_lan_text(clean_html_text(info.get("title")), 160)
        if title:
            append_unique(result["http_titles"], title, 8)
        for error in info.get("errors") or []:
            append_unique(result["identify_errors"], compact_lan_text(error, 240), 12)


def split_http_response(output):
    """Split curl -i output into the last header block and body."""
    text = output or ""
    matches = list(re.finditer(r"(?m)^HTTP/\S+\s+\d+.*$", text))
    if not matches:
        return "", text
    response = text[matches[-1].start() :]
    parts = re.split(r"\r?\n\r?\n", response, maxsplit=1)
    if len(parts) < 2:
        return parts[0], ""
    return parts[-2], parts[-1]


def selected_http_headers(headers):
    """Return headers that often identify embedded devices."""
    output = []
    for line in (headers or "").splitlines():
        lowered = line.lower()
        if lowered.startswith(("server:", "content-type:", "www-authenticate:")):
            output.append(compact_lan_text(line, 160))
    return unique(output, 8)


def first_regex(text, pattern):
    """Return the first compact regex capture from text."""
    match = re.search(pattern, text or "", re.I | re.S)
    if not match:
        return ""
    return clean_html_text(match.group(1))


def strip_tags(text):
    """Remove HTML tags for rough snippet extraction."""
    return re.sub(r"<[^>]+>", " ", text or "")


def clean_html_text(text):
    """Return compact unescaped HTML text."""
    return compact_lan_text(html.unescape(strip_tags(text or "")), 180)


def append_unique(items, value, limit):
    """Append one non-empty unique value to a bounded list."""
    if value and value not in items:
        items.append(value)
        del items[limit:]


def unique(items, limit):
    """Return ordered unique values with a max length."""
    output = []
    for item in items or []:
        if item in output:
            continue
        output.append(item)
        if len(output) >= limit:
            break
    return output
