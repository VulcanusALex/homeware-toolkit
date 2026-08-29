# Security Policy

## Scope and intended use

homeware-toolkit is an **owner-side** toolkit. It exists so that owners of
Technicolor/Vantiva Homeware gateways (Fastweb NeXXt One, Vodafone UK VCNT-I
and similar) can inspect and control hardware they own, on their
own LAN. Every privileged action requires an authenticated web session, which
in turn requires **physical access** (pressing the device buttons) or a
session created that way. It is not a remote exploit and provides no way to
bypass the physical-button login.

## What the toolkit does and does not do

It does:

- read public static web assets (unauthenticated);
- use the documented ping diagnostic API to run shell commands as root
  (this is the known command-injection issue on this platform);
- transfer locally generated files (your SSH public key) to the device;
- start a key-only, password-less, LAN-only SSH service.
- keep a root-only persistent ownership record so rollback removes only the
  key and account change made by this toolkit;
- observe named firewall counters and audit configuration/runtime state.

It does not:

- change any password (root password is never touched);
- flash firmware, change boot banks, or touch TR-069/cwmp;
- download or execute third-party code on the device;
- exfiltrate data anywhere — session cookies and keys stay in the local
  `.work/` directory (gitignored).
- upload support bundles automatically — the user reviews and attaches them.

## Vulnerability disclosure

The command-injection issue in the ping diagnostic of the
Technicolor/Vantiva Homeware platform (as shipped in Fastweb's FGA221D
firmware) has been publicly known in the hack-technicolor community since at
least the FW_056 release and remains present in FW_058. This repository
documents and automates owner-side use of that issue but is **not** the
original reporter. We encourage anyone discovering **new** vulnerabilities to
report them to the vendor (Vantiva/Technicolor) and the ISP (Fastweb) before
publication, following coordinated disclosure practices.

## Reporting issues in THIS toolkit

- For bugs in the toolkit itself: open a GitHub issue.
- For anything with security impact (e.g., a flaw that lets someone use the
  toolkit against devices they do not own): please report privately via
  GitHub's "Report a vulnerability" feature (Security tab) instead of a
  public issue.

## Hardening notes for users

- The SSH instance installed by `bootstrap` is key-only, on a LAN high port,
  with password and root-password auth disabled. The ISP's own
  `dropbear.wan` management instance is never modified.
- Bootstrap appends its recorded key and preserves unrelated authorized keys.
  State under `/etc/homeware-toolkit/` is mode 0700/0600 and survives reboot.
- `teardown` removes only toolkit-owned state and restores the exact original
  root account line. Unowned legacy changes are refused unless explicitly
  adopted.
- Browser HAR captures contain your `sessionID` and may contain VoIP
  credentials returned by the `deviceinfo` API — delete them after use.
- `support-bundle` uses a strict sysinfo allowlist and redacts credentials,
  sessions, MACs, serials and raw IP addresses; still review it before sharing.
- GitHub Releases publish `SHA256SUMS` beside the wheel, source archive and
  standalone `homeware.pyz`. Verify the selected artifact before running it; the
  README includes a command that checks only the downloaded zipapp entry.
- Since v1.6.0, SSH-based commands verify the dropbear host key
  trust-on-first-use against `~/.homeware-toolkit/known_hosts` (0700/0600).
  A changed key fails the connection; delete the stale line only when you
  reinstalled the device yourself.
- The gateway HTTPS certificate is self-signed, so CA validation is off.
  Pin it with `homeware session fingerprint` + `--tls-fingerprint <sha256>` to
  detect a different TLS endpoint answering on the LAN.
- `transfer` validates `--tag` and the target path against strict character
  allowlists before any command is sent; `vpn wireguard` writes keys with
  0600 permissions and never prints private keys.
