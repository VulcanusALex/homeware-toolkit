"""Sensors for home-gateway-toolkit."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import COORDINATOR, DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the sensor platform."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id][COORDINATOR]
    async_add_entities(
        [
            HomeGatewaySensor(coordinator, "gateway", "Gateway"),
            HomeGatewaySensor(coordinator, "wan_ipv4", "WAN IPv4"),
            HomeGatewaySensor(coordinator, "wan_mode", "WAN Mode"),
        ]
    )


class HomeGatewaySensor(CoordinatorEntity, SensorEntity):
    """Representation of a home-gateway sensor."""

    _attr_has_entity_name = True

    def __init__(self, coordinator, key: str, name: str) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._key = key
        self._attr_name = name
        self._attr_unique_id = f"{coordinator.entry.entry_id}_{key}"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        data = self.coordinator.data or {}
        return data.get(self._key)

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        return self.coordinator.data or {}
