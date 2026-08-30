"""Vodafone UK Technicolor VCNT-I / VBNT-6 speculative driver.

This driver is based on public Homeware documentation and the
`benwaterson/technicolor-exploit` research for Vodafone UK gateways.  It has
**not been verified on real hardware**; it exists to exercise the driver
framework and to give VCNT-I owners a starting point for community testing.

Known differences from the NeXXt One (speculative):

- Board family ``VCNT-I`` / ``VBNT-6`` instead of ``GDNT-S``.
- WAN interfaces on Vodafone firmware are typically ``eth4`` (IPv4) and
  ``br-lan`` (IPv6 LAN).
- Authentication on Vodafone devices is SRP6 password-based (fixed legacy
  multiplier, SHA-256, RFC 5054 2048-bit group) rather than a physical
  button; implemented in ``srp6.py`` and reachable via
  ``homeware session login --username vodafone --password <ui-password>``.
  The simulator's ``generic_homeware`` profile speaks the same handshake, so
  the flow is integration-tested — but no real VCNT-I has confirmed it yet.
- The command-injection surface may be a different diagnostic endpoint or may
  not exist on newer firmware.  The capabilities inherit the NeXXt defaults so
  tests can at least exercise the same code paths.

Do **not** mark this driver as ``verified`` without a real-device end-to-end
run of probe → auth → injection → SSH bootstrap → firewall.
"""

from __future__ import annotations

from ..driver import Device
from .. import compat

DRIVER_NAME = "vcnt_i"

# Overrides from public Homeware references.  Everything else inherits NeXXt
# defaults, which is intentionally conservative.
VCNT_I_CAPABILITIES = {
    "auth": {"method": "srp6", "endpoint": "/authenticate",
             "default_username": "vodafone"},
    "injection": {"service": "pingstatus"},
    "wan": {"wan4_interface": "eth4", "lan6_interface": "br-lan"},
}


def _merge_caps(base: dict, overlay: dict) -> dict:
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_caps(result[key], value)
        else:
            result[key] = value
    return result


def make_device(entry: dict | None = None) -> Device:
    """Return a speculative Device for Vodafone UK Technicolor VCNT-I."""
    caps = compat.entry_capabilities(entry)
    caps = _merge_caps(caps, VCNT_I_CAPABILITIES)
    return Device(DRIVER_NAME, entry, caps)
