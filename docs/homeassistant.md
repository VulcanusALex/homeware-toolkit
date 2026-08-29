# Home Assistant integration for homeware-toolkit

The repository root contains a HACS-compatible custom component under
`custom_components/homeware_toolkit/`.

## Installation (HACS)

1. Add this repository as a custom repository in HACS:
   **Settings → Devices & services → HACS → ⋮ → Custom repositories**
   - Repository: `https://github.com/VulcanusALex/homeware-toolkit`
   - Category: **Integration**
2. Install **homeware-toolkit** from HACS.
3. Restart Home Assistant.
4. Go to **Settings → Devices & services → Add integration** and search for
   **homeware-toolkit**.
5. Enter your gateway URL, SSH private key path, and SSH port.

## Manual installation

Copy `custom_components/homeware_toolkit/` into your Home Assistant
`config/custom_components/` directory and restart.

## Current scope

This is a skeleton that provides:

- Config flow with unique-id based on gateway URL.
- Sensor entities for gateway, WAN IPv4, and WAN mode (values populated once
  polling is wired up).
- A `homeware_toolkit.run_command` service that can invoke arbitrary
  homeware CLI commands.

Future versions will add real-time polling of `doctor`, `wanwatch`, and
`fw audit` outputs.
