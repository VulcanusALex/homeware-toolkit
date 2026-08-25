# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/), versioning is semver.

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
