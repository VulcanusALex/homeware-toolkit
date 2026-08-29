"""Device driver abstraction.

A :class:`Device` encapsulates the device-specific configuration discovered
from ``compat.json``.  The historical NeXXt One behaviour is the default, so
existing code paths keep working even when no device has been explicitly
detected.

The longer-term goal is a small plugin system: each fingerprint entry declares
a ``driver`` name, the CLI loads the matching driver module, and the driver
supplies the concrete implementations for authentication, command execution,
firewall management, etc.  For now the abstraction only carries capabilities
and constants, which is enough to remove hard-coded NeXXt One strings from the
rest of the toolkit one module at a time.
"""

from __future__ import annotations

from . import compat

DEFAULT_DEVICE_NAME = "nexxt"


class Device:
    """Runtime handle for a matched fingerprint entry.

    It surfaces the driver name and merged capabilities so that
    device-specific code can read settings instead of hard-coding NeXXt One
    constants.  Missing capabilities fall back to the NeXXt One defaults, so
    callers can safely read nested values.
    """

    def __init__(self, name: str, entry: dict | None,
                 capabilities: dict | None = None) -> None:
        self.name = name
        self.entry = entry
        self.capabilities = capabilities or dict(compat.DEFAULT_CAPABILITIES)

    def cap(self, *path: str, default=None):
        """Read a nested capability value.

        Returns ``default`` if any path segment is missing or the node is not
        a dict.  The empty path returns the whole capabilities object.
        """
        if not path:
            return self.capabilities
        node = self.capabilities
        for part in path[:-1]:
            if not isinstance(node, dict):
                return default
            node = node.get(part, {})
        if not isinstance(node, dict):
            return default
        last = path[-1]
        return node[last] if last in node else default

    def __repr__(self) -> str:
        return f"<Device {self.name}>"


def default_device() -> Device:
    """Return the NeXXt One default device (no fingerprint match needed)."""
    return Device(DEFAULT_DEVICE_NAME, None)


def detect_from_sysinfo(sysinfo: dict) -> Device:
    """Match sysinfo against compat.json and return the corresponding Device."""
    result = compat.match_fingerprint(
        board=str(sysinfo.get("hw_version", "")),
        model=str(sysinfo.get("model", "")),
        product=str(sysinfo.get("model", "")),
        firmware=str(sysinfo.get("fw_version", "")),
    )
    name = compat.entry_driver(result.entry)
    caps = compat.entry_capabilities(result.entry)
    return Device(name, result.entry, caps)


def detect_from_entry(entry: dict) -> Device:
    """Build a Device from an already-known fingerprint entry."""
    return Device(
        compat.entry_driver(entry),
        entry,
        compat.entry_capabilities(entry),
    )
