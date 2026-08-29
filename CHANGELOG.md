# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is semver.

## [Unreleased]

### Added
- Device-driver framework: `compat.json` schema 2 adds `driver` and
  `capabilities` per fingerprint; the CLI loads the matching driver from
  `home_gateway_toolkit/drivers/` and reads device-specific constants instead of
  hard-coding NeXXt One values.
- Second driver (`openwrt`) demonstrating multi-device support and capability
  inheritance from NeXXt defaults.
- Third speculative driver (`vcnt_i`) for Vodafone UK Technicolor VCNT-I /
  VBNT-6, plus a community hardware-testing program.
- Multi-profile simulator: `FakeGateway` accepts a `profile` parameter and the
  CLI grows `simulate --profile {nexxt,generic_homeware}` to exercise different
  board/firmware fingerprints without hardware.
- Local web setup wizard: `home-gateway setup --wizard` serves a browser-based guide
  on `127.0.0.1` for probe → login → verify → SSH bootstrap.
- Installer build script (`tools/build_installer.py`) producing `home_gateway.pyz`,
  a macOS `.app` zip, and a Windows PyInstaller spec.
- Home Assistant HACS custom component skeleton under `custom_components/`,
  including a `home_gateway_toolkit.run_command` service.

### Changed
- **Project renamed** from `nexxt-one-toolkit` to `home-gateway-toolkit`:
  Python package `home_gateway_toolkit`, CLI command `home-gateway`, Home
  Assistant domain `home_gateway_toolkit`.  `nexxt` survives only as the
  internal driver name for the NeXXt One device family.
- `client.py`, `inject.py`, `firewall.py`, `ssh.py`, and `wanwatch.py` now
  consume device capabilities for API paths, injection parameters, firewall
  backend, SSH service/instance/shell, and WAN interface names.
- `verify.py` and `doctor.py` now read the payload prefix, `${IFS}`
  substitute, injection service and WAN interface from the detected device
  instead of hard-coding the NeXXt One values.
- `compat.json` is now loaded via `importlib.resources` so the zipapp
  (`.pyz`) release artifact works without extracting package data.

### Fixed
- Release zipapp and PyInstaller builds now bundle `compat.json` and the
  `drivers/` subpackage (both were missing, crashing the artifacts at import
  time); the wheel now includes `drivers/` as well.
- Windows PyInstaller spec uses project-root-relative paths and includes the
  package data, so it can actually build on a Windows runner.
- Wizard API endpoints return proper HTTP status codes and JSON error
  payloads instead of `0`/`1`, and the setup step no longer blocks the
  single-threaded server on an invisible terminal `[y/N]` prompt.
- Fingerprint detection now uses the sysinfo `product_name` field (falling
  back to `model`), so devices matched only by `product_contains` are
  recognized correctly.
- Device detection routes through the driver registry, so driver-module
  capability overlays are actually applied at runtime.
- `compat.json`: corrected the Vodafone model prefix `VANT-6` → `VBNT-6`.
- `--adopt-legacy` also migrates the pre-rename on-device state directory
  `/etc/nexxt-toolkit` to `/etc/home-gateway-toolkit`.
- Wizard: the final SSH command display no longer shows a literal `\n`.
- Removed the dead `_M_SIXRD` marker constant in `wanwatch.py`.

### Fixed
- Simulator fidelity, checked against real FW_058 hardware: every `nvget`
  readout requires an authenticated session (nginx 403 otherwise, even with
  a fresh `/login` cookie); only the `login_confirm` handshake service is
  reachable pre-auth. The fake gateway now enforces this and an integration
  test locks the behaviour in.
- The dashboard curses event loop is fully unit-tested: rendering and key
  handling are driven through an injected curses interface (quit, manual
  refresh, periodic refresh, small windows, per-row `curses.error`), leaving
  no untestable glue code.

## [1.6.0] - 2026-08-29

### Security
- `transfer` now strictly validates `--tag` and `<target>` before any command
  is sent (character allowlists, absolute-path and length rules), closing the
  last unvalidated interpolation into the injection channel.
- SSH connections are now trust-on-first-use by default: host keys are
  recorded in `~/.home-gateway-toolkit/known_hosts` (0700/0600) with
  `StrictHostKeyChecking=accept-new`. `ssh run --no-verify-host-key`
  restores the old behaviour explicitly.
- Optional TLS certificate pinning: `home-gateway session fingerprint` prints the
  gateway certificate's SHA-256 fingerprint and `--tls-fingerprint` enforces
  it on every HTTPS request (CA verification remains off for the self-signed
  device certificate).

### Added
- `home-gateway simulate`: in-process fake gateway (sessions, button login, ping
  injection channel with an interpreted shell subset, timing behaviour) for
  hardware-free development and demos, plus 17 integration tests that run
  probe, login, verify and a full md5-verified transfer against it.
- `home-gateway apply` / `home-gateway diff`: declarative desired-state management from a
  JSON config (firewall pinholes, SSH policy assertions). Idempotent,
  transactional via the existing ensure/rollback machinery; optional
  `firewall.prune` removes only toolkit-shaped extra rules.
  See `examples/home_gateway.json`.
- `home-gateway vpn wireguard`: one-step WireGuard remote access — pure-Python
  RFC 7748 X25519 key generation, server/client configs (0600), unique
  per-client PSKs and an idempotent IPv6 UDP pinhole on the gateway.
- `home-gateway dashboard`: live read-only curses dashboard (WAN classification,
  6rd prefixes, SSH and firewall state) with graceful degradation on
  non-terminals.
- `home-gateway probe --report`: Markdown compatibility report for GitHub issues;
  firmware fingerprints are now data-driven via `home_gateway_toolkit/compat.json`
  and documented in `COMPATIBILITY.md` — new firmware reports no longer
  require code changes.

### Changed
- The injection fingerprint guard now accepts board-matched devices with
  not-yet-listed firmware as "untested" (warning, still requires no
  `--force`) instead of refusing outright; unknown boards remain refused.

## [1.5.0] - 2026-08-27

### Safety
- SSH bootstrap now keeps persistent, root-only ownership records before any
  mutation. It appends and tracks its own key instead of overwriting existing
  authorized keys; teardown removes only toolkit-owned state and restores the
  exact recorded root account line after reboot.
- Existing unowned `dropbear.nx` or root-shell changes are refused by default.
  Confirmed installs from v1.4.0 or older can be migrated explicitly with
  `--adopt-legacy`; destructive legacy cleanup requires `--legacy-force`.
- Guided setup is transactional and attempts exact rollback if the final SSH
  handshake fails.

### Added
- `home-gateway setup`: guided probe, physical-button login, non-persistent
  verification, local RSA key generation, confirmation, bootstrap and doctor.
- `home-gateway inbound observe`: proves arrival at the gateway from positive named
  firewall-rule counter deltas and treats zero as inconclusive.
- `home-gateway fw ensure`: idempotent named pinholes with UCI backup and rollback;
  `home-gateway fw audit`: duplicate, broad-WAN and UCI/runtime checks.
  The existing `fw allow` CLI is retained as an alias for the safe ensure path.
- `home-gateway audit-update`: firmware fingerprint change tracking plus SSH policy,
  rollback-state and firewall-runtime auditing after OTA updates.
- `home-gateway support-bundle`: reviewable ZIP/JSON with a strict sysinfo allowlist
  and automatic credential, session, MAC, serial and IPv4 redaction.
- Release workflow now builds wheel/sdist, a standalone `home_gateway.pyz`, SHA-256
  checksums, uploads GitHub Release assets and publishes via PyPI OIDC.

### Changed
- `doctor` reports WAN address assignment separately from inbound reachability.
  Private/RFC1918 WAN is informational, not proof of CGNAT blocking or failed
  inbound; upstream static 1:1 NAT is explicitly supported by the model.
- `doctor --check-egress` optionally contacts the IPv4/IPv6 ipify endpoints;
  external lookup is off by default and never substitutes for an inbound test.
- Fastweb notes now distinguish historical test evidence from current/dynamic
  operator provisioning instead of making permanent claims from WAN address.

## [1.4.0] - 2026-08-26

### Security
- **`fw allow` / `fw delete` command-injection hardening.** Free-form values
  (`--dest-ip`, `--dest-port`, `--src`, `--dest`, `--proto`) that get
  interpolated into UCI commands sent over SSH are now strictly validated:
  IPs via `ipaddress` (scope-ids rejected, address normalized before use),
  ports as single/range/list within 1–65535, zones/proto against a strict
  token regex. `delete` now validates the rule name (previously unchecked).

### Fixed
- **`probe` no longer crashes on non-matching firmware.** `inspect_assets`
  used an eagerly-evaluated `all((...))` tuple that raised `AttributeError`
  when the IPv6 validator regex was absent — the exact "firmware differs" case
  the probe exists to report. Now short-circuits to `incomplete-match`.
- **`transfer` verifies the assembled file end-to-end.** `assemble` takes an
  optional `expect_md5` and the `home-gateway transfer` command now checks the target
  md5 (defends against the backend's async/out-of-order segment writes) and
  cleans up its `/tmp` scratch files.
- User-Agent now derives from the package version (was pinned to `1.2`).
- `wanwatch --state-file` path expansion fixed (`~` was string-replaced
  everywhere); file handles wrapped in context managers; dead code removed;
  Injector baseline now uses a two-sample max like `verify`.

### Added
- **Richer `wanwatch`.** When the router exposes `ifstatus` it reports the
  connectivity mode (native DHCPv6 vs 6rd), delegated prefixes and dynamic
  flags, a human-readable change summary, atomic state writes, and an opt-in
  `--notify` desktop notification (macOS; no-op elsewhere). Falls back to
  plain `ip addr` parsing on devices without `ifstatus`.
- Regression test suites: `test_firewall.py`, `test_core_fixes.py`,
  `test_plumbing.py` (53 tests total).

## [1.3.0] - 2026-08-25

### Added
- **Scripted button login now works end-to-end** (`home-gateway session login`): the
  root cause of the old failure was found in the router sources
  (`sessionmgr.lua`/`login.wat`) — the confirm step only authenticates the
  most recently created session, so the client now mints a fresh session
  before arming the button window. The HAR export step is no longer required
  (kept as `import-cookie` fallback).
- `session check/dump/import-cookie` now print human-readable output in
  non-JSON mode.

## [1.2.0] - 2026-08-25

### Added
- **Unified CLI** `home-gateway` with subcommands: `probe`, `doctor`, `session`,
  `verify`, `transfer`, `ssh`, `fw`, `wanwatch`; global `--json`, `--quiet`,
  `--force`, `--version` flags. Legacy `tools/*.py` scripts remain as
  backward-compatible shims.
- **`home-gateway doctor`**: end-to-end health check (web UI compatibility, session,
  injection, SSH service, WAN public-IPv4) with per-stage hints.
- **Firmware fingerprint guard**: injection commands refuse to run on
  unrecognized device families unless `--force` is given.
- **`--dry-run`** for `ssh bootstrap` (prints intended commands only).
- **Unit test suite** (18 hardware-free tests using mocks) covering transfer
  encoding/bisect, oracle thresholds, fingerprint guard, pubkey validation,
  HAR cookie import, WAN classification, CLI parsing.
- `SECURITY.md`, `CONTRIBUTING.md`, issue/PR templates, CI badge.
- `pyproject.toml`: installable package with `home-gateway` console script.

### Changed
- Transfer segment verification is now a single `grep -qFx` oracle call
  (proves content+length at once, ~2x faster); oracle sleep 8s→5s.

## [1.1.0] - 2026-08-25

### Added
- `home_gateway_ssh.py run` subcommand (execute commands over the persistent SSH
  service), `bootstrap --test` handshake self-check.
- `home_gateway_firewall.py`: list/allow/delete precise pinhole rules over SSH.
- `home_gateway_wanwatch.py`: cron-friendly watcher for public IPv4 provisioning.
- GitHub Actions CI.

## [1.0.0] - 2026-08-25

### Added
- Initial release: read-only probe, session helper (button login + HAR cookie
  import), non-persistent injection verification, reliable file transfer
  (segment + bisect + oracle), persistent key-only LAN SSH bootstrap.
- Full guides in English and Chinese, Fastweb CGNAT/6rd findings.
