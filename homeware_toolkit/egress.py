"""Opt-in public egress-address lookup."""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.request


ENDPOINTS = {
    "ipv4": "https://api4.ipify.org?format=json",
    "ipv6": "https://api6.ipify.org?format=json",
}


def _fetch(url: str, timeout: float) -> str | None:
    request = urllib.request.Request(
        url, headers={"User-Agent": "homeware-toolkit egress-check"})
    try:
        with urllib.request.urlopen(
                request, timeout=timeout,
                context=ssl.create_default_context()) as response:
            value = json.loads(response.read(4096).decode("utf-8"))["ip"]
    except (urllib.error.URLError, TimeoutError, OSError, ValueError,
            KeyError, json.JSONDecodeError):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def query(timeout: float = 4.0) -> dict:
    """Contact two public endpoints only after explicit caller opt-in."""
    return {family: _fetch(url, timeout) for family, url in ENDPOINTS.items()}
