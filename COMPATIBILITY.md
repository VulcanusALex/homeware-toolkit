# Compatibility matrix

The authoritative, machine-readable source is
[`home_gateway_toolkit/compat.json`](home_gateway_toolkit/compat.json) — the injection
guard and `home-gateway probe --report` both consume it. This page is the
human-readable summary.

| Device | Board | Firmware | Status | Source |
| --- | --- | --- | --- | --- |
| Fastweb NeXXt One (Technicolor/Vantiva FGA221D, `FGA221DFWB`) | GDNT-S | `22.2.0378_FW_058_FGA221D` | ✅ verified | maintainer's device (see README) |
| Fastweb NeXXt One (Technicolor/Vantiva FGA221D, `FGA221DFWB`) | GDNT-S | `22.2.0378_FW_056_FGA221D` | ✅ verified | community report (see README) |
| Vodafone UK Technicolor VCNT-I / VBNT-6 (Vantiva Homeware) | VCNT-I | — | 🧪 untested | speculative driver; see [docs/hardware-testing.md](docs/hardware-testing.md) |

## Status legend

- **verified** — the full flow (probe → session → injection → SSH bootstrap →
  firewall management) has been exercised on this exact firmware.
- **untested** — the board family matches a known fingerprint but the exact
  firmware is not listed. The toolkit proceeds (the guard warns), but verify
  each step with `home-gateway doctor` and consider sending a report.
- **unknown** — no fingerprint matches. Privileged operations are refused
  unless you pass `--force`.

## Reporting a new device or firmware

1. Run `home-gateway probe --report http://192.168.1.254` and save the Markdown
   output (it contains no credentials, keys, MACs or serials).
2. Open an issue using the *Compatibility report* template and paste the
   report: <https://github.com/VulcanusALex/home-gateway-toolkit/issues>
3. Once confirmed, the fingerprint is added to `compat.json` — for the
   NeXXt One family usually no code change is required.

## Schema

`compat.json` is versioned. Schema 2 adds per-fingerprint `driver` and
`capabilities` fields so the toolkit can select device-specific behaviour
without hard-coding NeXXt One constants.

```json
{
  "schema": 2,
  "fingerprints": [
    {
      "board": "GDNT-S",
      "model_prefix": "FGA221",
      "product_contains": "NeXXt",
      "known_firmware": ["22.2.0378_FW_058_FGA221D"],
      "status": "verified",
      "driver": "nexxt",
      "capabilities": {
        "api": {"base_path": "/status.cgi", "read_param": "nvget", "write_action": "nvset"},
        "auth": {"method": "button_login", "service": "login_confirm"},
        "injection": {"service": "pingstatus", "payload_prefix": ":::::::;", "space_substitute": "${IFS}", "oracle_sleep": 5},
        "firewall": {"backend": "uci"},
        "ssh": {"service": "dropbear", "instance": "nx", "shell": "/bin/ash", "original_shell": "/bin/restricted_shell", "key_algorithms": ["ssh-rsa"]},
        "wan": {"wan4_interface": "veip0_1", "lan6_interface": "br-lan"}
      }
    }
  ]
}
```

- `driver` selects the device-family implementation under `home_gateway_toolkit/drivers/`.
- `capabilities` are merged with the NeXXt One defaults, so a new entry only
  needs to override values that differ from the default.

## Adding a new device family

When a fingerprint matches a different board family, the workflow is:

1. Add the fingerprint to `compat.json` with `"driver": "<name>"`.
2. Create `home_gateway_toolkit/drivers/<name>.py` and register it in
   `home_gateway_toolkit/drivers/__init__.py`.
3. Start by overriding the capabilities that differ; the CLI and Injector will
  pick them up automatically.

Until a dedicated driver module lands, unknown driver names fall back to the
`nexxt` (NeXXt One) driver, so new `compat.json` entries can be shipped before code.
