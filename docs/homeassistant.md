# Home Assistant integration for home-gateway-toolkit

The repository root contains a HACS-compatible custom component under
`custom_components/home_gateway_toolkit/`.

## Installation (HACS)

1. Add this repository as a custom repository in HACS:
   **Settings → Devices & services → HACS → ⋮ → Custom repositories**
   - Repository: `https://github.com/VulcanusALex/home-gateway-toolkit`
   - Category: **Integration**
2. Install **home-gateway-toolkit** from HACS.
3. Restart Home Assistant.
4. Go to **Settings → Devices & services → Add integration** and search for
   **home-gateway-toolkit**.
5. Enter your gateway URL, SSH private key path, and SSH port.

## Manual installation

Copy `custom_components/home_gateway_toolkit/` into your Home Assistant
`config/custom_components/` directory and restart.

## Current scope

This is a skeleton that provides:

- Config flow with unique-id based on gateway URL.
- Sensor entities for gateway, WAN IPv4, and WAN mode (values populated once
  polling is wired up).
- A `home_gateway_toolkit.run_command` service that can invoke arbitrary
  home-gateway CLI commands.

Future versions will add real-time polling of `doctor`, `wanwatch`, and
`fw audit` outputs.
