"""The homeware-toolkit Home Assistant integration."""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
from datetime import timedelta

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    CONF_BASE_URL,
    CONF_SSH_KEY,
    CONF_SSH_PORT,
    COORDINATOR,
    DOMAIN,
)

PLATFORMS = [Platform.SENSOR]

SERVICE_RUN_COMMAND = "run_command"
ATTR_COMMAND = "command"

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up homeware-toolkit from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    coordinator = HomewareDataUpdateCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {COORDINATOR: coordinator}
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    _register_services(hass, entry)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_RUN_COMMAND)
    return unload_ok


def _register_services(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Register integration services (idempotent)."""
    if hass.services.has_service(DOMAIN, SERVICE_RUN_COMMAND):
        return

    async def handle_run_command(call: ServiceCall) -> None:
        """Run a homeware CLI subcommand against the configured gateway."""
        command = str(call.data.get(ATTR_COMMAND, "")).strip()
        if not command:
            raise ValueError("command is required")
        argv = shlex.split(command)
        base_url = entry.data[CONF_BASE_URL]
        # --key/--port are per-subcommand options; if the caller did not
        # supply them, append the configured ones.  Subcommands that do not
        # accept them (probe, session, simulate) reject unknown arguments
        # with a clear argparse error.
        if "--key" not in argv:
            key = os.path.expanduser(entry.data.get(CONF_SSH_KEY, ""))
            if key and os.path.isfile(key):
                argv += ["--key", key]
        if "--port" not in argv:
            port = entry.data.get(CONF_SSH_PORT)
            if port:
                argv += ["--port", str(port)]
        args = ["homeware", "--base-url", base_url, "--json", *argv]

        def _run() -> subprocess.CompletedProcess:
            return subprocess.run(
                args, capture_output=True, text=True, timeout=300, check=False)

        proc = await hass.async_add_executor_job(_run)
        if proc.returncode != 0:
            _LOGGER.error("homeware %s failed (%s): %s",
                          command, proc.returncode, proc.stderr.strip())
            raise RuntimeError(
                f"homeware {command!r} exited {proc.returncode}: "
                f"{proc.stderr.strip()}")
        _LOGGER.debug("homeware %s: %s", command, proc.stdout.strip())

    hass.services.async_register(
        DOMAIN,
        SERVICE_RUN_COMMAND,
        handle_run_command,
        schema=vol.Schema({vol.Required(ATTR_COMMAND): str}),
    )


class HomewareDataUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator that polls the gateway via the homeware CLI.

    Runs `doctor` (health stages) and `wanwatch` (WAN provisioning snapshot)
    in the executor so the event loop never blocks.  Both are read-only.
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize."""
        self.entry = entry
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=5),
        )

    async def _async_update_data(self) -> dict:
        """Fetch data from the gateway."""
        return await self.hass.async_add_executor_job(self._poll)

    def _poll(self) -> dict:
        base_url = self.entry.data[CONF_BASE_URL]
        key = os.path.expanduser(self.entry.data.get(CONF_SSH_KEY, ""))
        port = int(self.entry.data.get(CONF_SSH_PORT, 2222))
        data: dict = {"gateway": "offline"}

        doctor = _run_json(["doctor", "--key", key, "--port", str(port)],
                           base_url)
        if doctor is not None:
            stages = {s["stage"]: s["status"]
                      for s in doctor.get("stages", [])}
            data["gateway"] = ("online" if stages.get("web-ui-compatibility")
                               == "PASS" else "offline")
            data["ssh_service"] = stages.get("ssh-service", "unknown")
            data["wan_ipv4_class"] = stages.get("wan-ipv4-assignment", "")
            data["doctor_stages"] = stages

        wan = _run_json(["wanwatch", "--key", key, "--port", str(port)],
                        base_url)
        if wan is not None and "mode" in wan:
            data["wan_ipv4"] = wan.get("wan_ipv4")
            data["wan_mode"] = wan.get("mode")
            data["wan6_up"] = wan.get("wan6_up")
        return data


def _run_json(argv: list, base_url: str) -> dict | None:
    """Run `python -m homeware_toolkit --json <argv>` and parse its JSON."""
    import json as _json
    import sys

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "homeware_toolkit", "--json",
             "--base-url", base_url, *argv],
            capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _LOGGER.warning("homeware %s failed to run: %s", argv[0], exc)
        return None
    try:
        return _json.loads(proc.stdout)
    except ValueError:
        _LOGGER.debug("homeware %s produced no JSON (rc=%s)",
                      argv[0], proc.returncode)
        return None
