"""Generic OpenWrt driver.

This driver demonstrates the multi-device architecture on a device family that
already exposes SSH and uses the standard OpenWrt UCI firewall.  It is *not*
a fully supported target yet — the CLI's guided ``setup`` still assumes an
injection channel — but it validates that the toolkit can carry device-specific
capabilities for authentication, SSH service names, and WAN interfaces.

Future work: teach the CLI/setup path to skip injection when a device declares
``auth.method != "button_login"`` and ``injection`` is absent, so this driver
can be used end-to-end.
"""

from __future__ import annotations

from ..driver import Device
from .. import compat

DRIVER_NAME = "openwrt"

# Capability overrides for a generic OpenWrt router.  Everything else inherits
# the NeXXt One defaults, which happen to match OpenWrt for UCI/dropbear.
OPENWRT_CAPABILITIES = {
    "auth": {"method": "ssh_key", "service": "none"},
    "wan": {"wan4_interface": "eth1", "lan6_interface": "br-lan"},
    # Keep UCI firewall and dropbear SSH defaults.
}


def make_device(entry: dict | None = None) -> Device:
    """Return a Device configured for a generic OpenWrt router."""
    caps = compat.entry_capabilities(entry)
    caps = _merge_caps(caps, OPENWRT_CAPABILITIES)
    return Device(DRIVER_NAME, entry, caps)


def _merge_caps(base: dict, overlay: dict) -> dict:
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_caps(result[key], value)
        else:
            result[key] = value
    return result
