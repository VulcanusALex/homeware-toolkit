"""Device driver registry.

Each supported device family implements a driver module and registers it here
by name.  The name must match the ``driver`` field declared in a
``compat.json`` fingerprint entry.

For now only the historical NeXXt One driver exists.  New drivers are added by:

1. creating ``drivers/<name>.py`` with a ``Driver`` class;
2. importing and registering it here with ``register("<name>", Driver)``.
"""

from __future__ import annotations

from typing import Callable, Optional

from ..driver import Device
from . import nexxt as _nexxt
from . import openwrt as _openwrt

_DriverFactory = Callable[[Optional[dict]], Device]

_REGISTRY: dict[str, _DriverFactory] = {
    "nexxt": _nexxt.make_device,
    "openwrt": _openwrt.make_device,
}


def register(name: str, factory: _DriverFactory) -> None:
    """Register a driver factory under ``name``."""
    if not isinstance(name, str) or not name:
        raise ValueError("driver name must be a non-empty string")
    _REGISTRY[name] = factory


def get(name: str) -> _DriverFactory:
    """Return the driver factory registered under ``name``.

    Falls back to the NeXXt driver if the name is unknown, so that a new
    ``compat.json`` entry can be shipped before its driver module lands.
    """
    return _REGISTRY.get(name, _REGISTRY["nexxt"])


def make_device(name: str, entry: dict | None = None) -> Device:
    """Instantiate the driver identified by ``name`` with ``entry``."""
    return get(name)(entry)
