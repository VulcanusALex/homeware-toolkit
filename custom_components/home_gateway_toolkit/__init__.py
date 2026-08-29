"""The home-gateway-toolkit Home Assistant integration."""

from __future__ import annotations

import logging
import os
import shlex
import subprocess

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
    """Set up home-gateway-toolkit from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    coordinator = HomeGatewayDataUpdateCoordinator(hass, entry)
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
        """Run a home-gateway CLI subcommand against the configured gateway."""
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
        args = ["home-gateway", "--base-url", base_url, "--json", *argv]

        def _run() -> subprocess.CompletedProcess:
            return subprocess.run(
                args, capture_output=True, text=True, timeout=300, check=False)

        proc = await hass.async_add_executor_job(_run)
        if proc.returncode != 0:
            _LOGGER.error("home-gateway %s failed (%s): %s",
                          command, proc.returncode, proc.stderr.strip())
            raise RuntimeError(
                f"home-gateway {command!r} exited {proc.returncode}: "
                f"{proc.stderr.strip()}")
        _LOGGER.debug("home-gateway %s: %s", command, proc.stdout.strip())

    hass.services.async_register(
        DOMAIN,
        SERVICE_RUN_COMMAND,
        handle_run_command,
        schema=vol.Schema({vol.Required(ATTR_COMMAND): str}),
    )


class HomeGatewayDataUpdateCoordinator(DataUpdateCoordinator):
    """Coordinator that polls the gateway over SSH."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize."""
        self.entry = entry
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=None,  # Manual / service-driven for now
        )

    async def _async_update_data(self) -> dict:
        """Fetch data from the gateway."""
        return {}
