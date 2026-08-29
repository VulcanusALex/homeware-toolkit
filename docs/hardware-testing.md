# Community hardware testing program

The toolkit's driver framework makes it possible to support additional
gateway families without rewriting the CLI.  However, every new device needs
at least one owner willing to run the real flow on real hardware before it
can move from `untested` to `verified`.

## How to volunteer

If you own a device listed below (or a close relative), open a
**Hardware testing call** issue and fill in the template:

1. Run the read-only probe:
   ```bash
   home-gateway probe --report http://192.168.1.254
   ```
2. Try authentication (button login, or note the method your UI uses).
3. Run `home-gateway verify` to check whether the diagnostic injection channel is
   still present.
4. Optionally run the guided setup:
   ```bash
   home-gateway setup
   ```

## Currently speculative / untested targets

| Driver | Device family | Known differences from NeXXt One |
|---|---|---|
| `vcnt_i` | Vodafone UK Technicolor VCNT-I / VBNT-6 | Board `VCNT-I`; WAN interface `eth4`; SRP6 auth (not implemented yet) |
| `openwrt` | Generic OpenWrt router | Assumes existing SSH access; no injection channel |

## What "verified" means

A driver can be marked `verified` for a given firmware once a volunteer has
successfully run:

- `home-gateway probe` → strong board match
- `home-gateway session login` or equivalent auth
- `home-gateway verify` → `CONFIRMED`
- `home-gateway setup` → SSH handshake OK
- `home-gateway fw ensure` + `home-gateway doctor` → no errors

## Safety

- Test only on a gateway **you own**.
- The toolkit does not flash firmware or change TR-069, but speculative
drivers may still behave differently on your firmware revision.
- `home-gateway ssh teardown` rolls back the toolkit's own changes if you reach the
  SSH bootstrap step.
