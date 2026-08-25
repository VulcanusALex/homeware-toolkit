# nexxt-one-toolkit

[![ci](https://github.com/VulcanusALex/nexxt-one-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/VulcanusALex/nexxt-one-toolkit/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)

Open-source toolkit for the **Fastweb NeXXt One** residential gateway
(Technicolor/Vantiva **FGA221D**, board **GDNT-S**, firmware branch `22.2.0378`),
covering compatibility probing, a non-destructive verification of the ping
diagnostic command-injection issue, reliable file transfer over that channel,
and bootstrapping a **persistent key-only SSH service** on a device **you own**.

Everything is pure **Python 3.9+ stdlib** — no dependencies to install.

> ⚠️ **Use only on your own device.** Every privileged step requires an
> authenticated web session, which requires pressing the physical buttons on
> the gateway. This is an owner-side toolkit, not a remote exploit — see
> [SECURITY.md](SECURITY.md).

## Quick start

```bash
git clone https://github.com/VulcanusALex/nexxt-one-toolkit.git
cd nexxt-one-toolkit

# 1. Read-only compatibility probe (no login, no changes)
./nexxt probe
#   compatibility: strong-front-end-match  stamps=['20260515082010']  ports={'22': 'refused', ...}

# 2. Session: scripted button login (press BOTH side buttons for 3s when asked)
./nexxt session login
#   [login] fresh session created (must stay the latest — do not open
#   [login] armed button wait (http 200)
#   [login] press BOTH side buttons for 3s within 60s
#   [login] button press detected
#   [login] authenticated=True
./nexxt session dump              # read-only device snapshot
#   (fallback: log in via browser, then `./nexxt session import-cookie <har|sessionID>`)

# 3. Verify the injection exists (no persistent changes)
./nexxt verify
#   [verify] baseline 2.3s
#   [verify] timing-sleep 12.4s
#   ...
#   backend command execution: CONFIRMED

# 4. Persistent key-only SSH on the LAN (RSA key required — dropbear is 2019.x)
ssh-keygen -t rsa -b 2048 -f ~/.ssh/nexxt_rsa
./nexxt ssh bootstrap --pubkey ~/.ssh/nexxt_rsa.pub --test
#   [ssh] root shell ready
#   [ssh] public key installed (md5 verified)
#   [ssh] handshake OK
ssh -i ~/.ssh/nexxt_rsa -p 2222 \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa \
  root@192.168.1.254

# 5. Health check at any time — tells you exactly what is missing
./nexxt doctor --key ~/.ssh/nexxt_rsa
#   [✓] web-ui-compatibility: PASS strong-front-end-match
#   [-] web-session: SKIP no valid session  → nexxt session login ...
#   [✓] ssh-service: PASS port 2222 reachable with key
#   [✗] wan-public-ipv4: FAIL private-RFC1918  → inbound blocked at ISP (CGNAT) ...

# 6. Everyday operations over the persistent SSH service
./nexxt ssh run "ip6tables -L zone_wan_forward -nv" --key ~/.ssh/nexxt_rsa
./nexxt fw list --key ~/.ssh/nexxt_rsa
./nexxt fw allow --key ~/.ssh/nexxt_rsa \
  --name Allow-AWG-v6 --proto udp --dest-ip 2001:db8::123 --dest-port 51820
./nexxt wanwatch --key ~/.ssh/nexxt_rsa   # exit 0 once the WAN IPv4 is public

# 7. Undo everything (also restores root's original shell)
./nexxt ssh teardown
```

Install as a package if you prefer (`pipx` recommended):

```bash
pipx install .
nexxt --help
```

## The toolkit

| Command | Purpose |
|---|---|
| `nexxt probe` | Unauthenticated, read-only compatibility check (safe first step) |
| `nexxt doctor` | End-to-end health check with per-stage hints |
| `nexxt session` | Button-assisted login, HAR cookie import, read-only dump |
| `nexxt verify` | Non-persistent proof of command injection (timing probe + short-lived `/tmp` marker, cleaned up) |
| `nexxt transfer` | Reliable file transfer through the injection channel (segmented, content-filter-tolerant, oracle-verified) |
| `nexxt ssh` | **bootstrap / status / run / teardown** of the persistent, key-only, LAN-only dropbear |
| `nexxt fw` | Precise firewall pinhole rules over SSH — firewall stays ON |
| `nexxt wanwatch` | Cron-friendly watcher: detects when the ISP finally assigns a public IPv4 / the 6rd prefix changes |

Legacy entry points (`tools/nexxt_probe.py`, `tools/nexxt_session.py`, …) still
work and forward to the unified CLI.

Global flags: `--json` (machine-readable), `--quiet`, `--force` (skip the
firmware fingerprint guard), `--version`.

Docs:

- [docs/root-guide.md](docs/root-guide.md) — full technical guide (EN)
- [docs/root-guide.zh-CN.md](docs/root-guide.zh-CN.md) — 完整中文指南
- [docs/fastweb-notes.md](docs/fastweb-notes.md) — Fastweb network findings
  (CGNAT IPv4, 6rd inbound filtering) and how to talk to support

## Verified on

- NeXXt One `FGA221DFWB` / `GDNT-S`, firmware `22.2.0378_FW_058_FGA221D`
  (community report covers FW_056; the issue persists on FW_058).
  Other firmware? Please open a
  [compatibility report](https://github.com/VulcanusALex/nexxt-one-toolkit/issues/new?template=compatibility_report.md).

## Safety model

- No third-party code is ever downloaded to the router; everything is
  generated locally and transferred as data.
- No password changes, no firmware flashing, no TR-069 changes, no boot-bank
  changes.
- The SSH instance is key-only, password auth disabled, LAN high port only.
- `teardown` removes the instance and restores `/bin/restricted_shell`.

## 中文摘要

本项目是 Fastweb NeXXt One 网关（FGA221D / GDNT-S）的开源工具箱：只读兼容性探测、
Ping 诊断命令注入的无持久化验证、经该通道的可靠文件传输、一键部署
**持久化、仅密钥、仅 LAN** 的 SSH 服务（可随时 teardown 完全还原）、
精确防火墙 pinhole 管理、以及 WAN 公网 IP 下发监控。
统一入口 `./nexxt`，`./nexxt doctor` 一键体检告诉你卡在哪一步。
**仅限用于你自己的设备**。完整中文文档见
[docs/root-guide.zh-CN.md](docs/root-guide.zh-CN.md)。

## License

MIT — see [LICENSE](LICENSE).
