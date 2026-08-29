"""Config flow for home-gateway-toolkit."""

from __future__ import annotations

import os
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_BASE_URL,
    CONF_SSH_KEY,
    CONF_SSH_PORT,
    DEFAULT_BASE_URL,
    DEFAULT_SSH_KEY,
    DEFAULT_SSH_PORT,
    DOMAIN,
)


class HomeGatewayConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for home-gateway-toolkit."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            key_path = os.path.expanduser(user_input[CONF_SSH_KEY])
            if not os.path.isfile(key_path):
                errors[CONF_SSH_KEY] = "file_not_found"
            else:
                await self.async_set_unique_id(
                    user_input[CONF_BASE_URL].rstrip("/")
                )
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_BASE_URL], data=user_input
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_BASE_URL, default=DEFAULT_BASE_URL): str,
                    vol.Required(CONF_SSH_KEY, default=DEFAULT_SSH_KEY): str,
                    vol.Required(CONF_SSH_PORT, default=DEFAULT_SSH_PORT): int,
                }
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> NexxtOptionsFlow:
        """Get the options flow for this handler."""
        return NexxtOptionsFlow(config_entry)


class NexxtOptionsFlow(config_entries.OptionsFlow):
    """Handle options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({}),
        )
