# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is semver.

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
  optional `expect_md5` and the `nexxt transfer` command now checks the target
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
- **Scripted button login now works end-to-end** (`nexxt session login`): the
  root cause of the old failure was found in the router sources
  (`sessionmgr.lua`/`login.wat`) — the confirm step only authenticates the
  most recently created session, so the client now mints a fresh session
  before arming the button window. The HAR export step is no longer required
  (kept as `import-cookie` fallback).
- `session check/dump/import-cookie` now print human-readable output in
  non-JSON mode.

## [1.2.0] - 2026-08-25

### Added
- **Unified CLI** `nexxt` with subcommands: `probe`, `doctor`, `session`,
  `verify`, `transfer`, `ssh`, `fw`, `wanwatch`; global `--json`, `--quiet`,
  `--force`, `--version` flags. Legacy `tools/*.py` scripts remain as
  backward-compatible shims.
- **`nexxt doctor`**: end-to-end health check (web UI compatibility, session,
  injection, SSH service, WAN public-IPv4) with per-stage hints.
- **Firmware fingerprint guard**: injection commands refuse to run on
  unrecognized device families unless `--force` is given.
- **`--dry-run`** for `ssh bootstrap` (prints intended commands only).
- **Unit test suite** (18 hardware-free tests using mocks) covering transfer
  encoding/bisect, oracle thresholds, fingerprint guard, pubkey validation,
  HAR cookie import, WAN classification, CLI parsing.
- `SECURITY.md`, `CONTRIBUTING.md`, issue/PR templates, CI badge.
- `pyproject.toml`: installable package with `nexxt` console script.

### Changed
- Transfer segment verification is now a single `grep -qFx` oracle call
  (proves content+length at once, ~2x faster); oracle sleep 8s→5s.

## [1.1.0] - 2026-08-25

### Added
- `nexxt_ssh.py run` subcommand (execute commands over the persistent SSH
  service), `bootstrap --test` handshake self-check.
- `nexxt_firewall.py`: list/allow/delete precise pinhole rules over SSH.
- `nexxt_wanwatch.py`: cron-friendly watcher for public IPv4 provisioning.
- GitHub Actions CI.

## [1.0.0] - 2026-08-25

### Added
- Initial release: read-only probe, session helper (button login + HAR cookie
  import), non-persistent injection verification, reliable file transfer
  (segment + bisect + oracle), persistent key-only LAN SSH bootstrap.
- Full guides in English and Chinese, Fastweb CGNAT/6rd findings.
