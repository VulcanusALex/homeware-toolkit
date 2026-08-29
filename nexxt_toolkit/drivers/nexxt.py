"""NeXXt One / Technicolor FGA221D driver.

This is the historical driver.  It currently only wraps the default NeXXt One
capabilities from ``compat.json``; over time it will grow to host the
device-specific implementations that are currently hard-coded in
``client.py``, ``inject.py``, ``ssh.py``, ``firewall.py`` and ``wanwatch.py``.
"""

from __future__ import annotations

from ..driver import Device
from .. import compat

DRIVER_NAME = "nexxt"


def make_device(entry: dict | None = None) -> Device:
    """Return a Device configured for the NeXXt One defaults."""
    return Device(
        DRIVER_NAME,
        entry,
        compat.entry_capabilities(entry),
    )
