# Community hardware testing program

The toolkit's driver framework makes it possible to support additional
Technicolor/Vantiva **Homeware** gateway families without rewriting the CLI.
However, every new device needs at least one owner willing to run the real
flow on real hardware before it can move from `untested` to `verified`.

## How to volunteer

If you own a device listed below (or a close relative), open a
**Hardware testing call** issue and fill in the template:

1. Run the read-only probe:
   ```bash
   homeware probe --report http://192.168.1.254
   ```
2. Try authentication (button login, or note the method your UI uses).
3. Run `homeware verify` to check whether the diagnostic injection channel is
   still present.
4. Optionally run the guided setup:
   ```bash
   homeware setup
   ```

## Currently speculative / untested targets

| Driver | Device family | Known differences from NeXXt One |
|---|---|---|
| `vcnt_i` | Vodafone UK Technicolor VCNT-I / VBNT-6 | Board `VCNT-I`; WAN interface `eth4`; SRP6 auth (not implemented yet) |

The generic `openwrt` driver is a framework demonstration: OpenWrt devices
already ship with SSH, so they are outside the project's focus and do not
need testing volunteers.

## What "verified" means

A driver can be marked `verified` for a given firmware once a volunteer has
successfully run:

- `homeware probe` → strong board match
- `homeware session login` or equivalent auth
- `homeware verify` → `CONFIRMED`
- `homeware setup` → SSH handshake OK
- `homeware fw ensure` + `homeware doctor` → no errors

## Safety

- Test only on a gateway **you own**.
- The toolkit does not flash firmware or change TR-069, but speculative
drivers may still behave differently on your firmware revision.
- `homeware ssh teardown` rolls back the toolkit's own changes if you reach the
  SSH bootstrap step.
