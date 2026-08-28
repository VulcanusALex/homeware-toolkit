# Compatibility matrix

The authoritative, machine-readable source is
[`nexxt_toolkit/compat.json`](nexxt_toolkit/compat.json) — the injection
guard and `nexxt probe --report` both consume it. This page is the
human-readable summary.

| Device | Board | Firmware | Status | Source |
| --- | --- | --- | --- | --- |
| Fastweb NeXXt One (Technicolor/Vantiva FGA221D, `FGA221DFWB`) | GDNT-S | `22.2.0378_FW_058_FGA221D` | ✅ verified | maintainer's device (see README) |
| Fastweb NeXXt One (Technicolor/Vantiva FGA221D, `FGA221DFWB`) | GDNT-S | `22.2.0378_FW_056_FGA221D` | ✅ verified | community report (see README) |

## Status legend

- **verified** — the full flow (probe → session → injection → SSH bootstrap →
  firewall management) has been exercised on this exact firmware.
- **untested** — the board family matches a known fingerprint but the exact
  firmware is not listed. The toolkit proceeds (the guard warns), but verify
  each step with `nexxt doctor` and consider sending a report.
- **unknown** — no fingerprint matches. Privileged operations are refused
  unless you pass `--force`.

## Reporting a new device or firmware

1. Run `nexxt probe --report http://192.168.1.254` and save the Markdown
   output (it contains no credentials, keys, MACs or serials).
2. Open an issue using the *Compatibility report* template and paste the
   report: <https://github.com/VulcanusALex/nexxt-one-toolkit/issues>
3. Once confirmed, the fingerprint is added to `compat.json` — no code
   change required.
