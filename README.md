# nexxt-one-toolkit

Open-source toolkit for the **Fastweb NeXXt One** residential gateway
(Technicolor/Vantiva **FGA221D**, board **GDNT-S**, firmware branch `22.2.0378`),
covering compatibility probing, a non-destructive verification of the ping
diagnostic command-injection issue, reliable file transfer over that channel,
and bootstrapping a **persistent key-only SSH service** on a device **you own**.

Everything is pure **Python 3.9+ stdlib** — no dependencies to install.

> ⚠️ **Use only on your own device.** This toolkit exists so owners can
> inspect and control hardware they paid for (see
> [docs/root-guide.md](docs/root-guide.md) for the safety model). It is not a
> remote exploit: every privileged step requires an authenticated web session,
> which in turn requires pressing the physical buttons on the gateway.

## What you get

| Tool | Purpose |
|---|---|
| `tools/nexxt_probe.py` | Unauthenticated, read-only compatibility check of the web UI (safe first step) |
| `tools/nexxt_session.py` | Session handling: button-assisted login attempt, HAR session-cookie import, read-only info dump |
| `tools/nexxt_phaseb.py` | Non-persistent proof that the ping diagnostic executes injected commands (timing probe + short-lived `/tmp` marker, cleaned up) |
| `tools/nexxt_transfer.py` | Reliable file transfer through the injection channel (segmented, content-filter-tolerant, oracle-verified) |
| `tools/nexxt_ssh.py` | One-shot **bootstrap / status / run / teardown** of a persistent, key-only, LAN-only dropbear; `run` executes commands over SSH (no web session needed) |
| `tools/nexxt_firewall.py` | Manage precise pinhole rules over SSH (**list / allow / delete**) — firewall stays ON |
| `tools/nexxt_wanwatch.py` | Cron-friendly WAN watcher: detects when the ISP finally assigns a public IPv4 / when the 6rd prefix changes |

Docs:

- [docs/root-guide.md](docs/root-guide.md) — full technical guide (EN)
- [docs/root-guide.zh-CN.md](docs/root-guide.zh-CN.md) — 完整中文指南
- [docs/fastweb-notes.md](docs/fastweb-notes.md) — Fastweb network findings
  (CGNAT IPv4, 6rd inbound filtering) and how to talk to support

## Quick start

```bash
# 1. Read-only compatibility probe (no login, no changes)
python3 tools/nexxt_probe.py

# 2. Get a session: log in via browser (press the two side buttons),
#    export HAR from devtools, then import the sessionID
python3 tools/nexxt_session.py import-cookie /path/to/capture.har
python3 tools/nexxt_session.py dump            # read-only device snapshot

# 3. Verify the injection exists (no persistent changes)
python3 tools/nexxt_phaseb.py

# 4. Persistent key-only SSH on the LAN (RSA key required, dropbear is 2019.x)
ssh-keygen -t rsa -b 2048 -f ~/.ssh/nexxt_rsa
python3 tools/nexxt_ssh.py bootstrap --pubkey ~/.ssh/nexxt_rsa.pub
ssh -i ~/.ssh/nexxt_rsa -p 2222 \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa \
  root@192.168.1.254

# 5. Undo everything (also restores root's original shell)
python3 tools/nexxt_ssh.py teardown

# Everyday operations over the persistent SSH service:
python3 tools/nexxt_ssh.py run "ip6tables -L zone_wan_forward -nv" --key ~/.ssh/nexxt_rsa
python3 tools/nexxt_firewall.py list --key ~/.ssh/nexxt_rsa
python3 tools/nexxt_firewall.py allow --key ~/.ssh/nexxt_rsa \
  --name Allow-AWG-v6 --proto udp --dest-ip 2001:db8::123 --dest-port 51820
python3 tools/nexxt_wanwatch.py --key ~/.ssh/nexxt_rsa   # exit 0 once the WAN IPv4 is public
```

## Verified on

- NeXXt One `FGA221DFWB` / `GDNT-S`, firmware `22.2.0378_FW_058_FGA221D`
  (community report covers FW_056; the issue persists on FW_058).

## Safety model

- No third-party code is ever downloaded to the router; everything is
  generated locally and transferred as data.
- No password changes, no firmware flashing, no TR-069 changes, no boot-bank
  changes.
- The SSH instance is key-only, password auth disabled, LAN high port only.
- `teardown` removes the instance and restores `/bin/restricted_shell`.

## 中文摘要

本项目是 Fastweb NeXXt One 网关（FGA221D / GDNT-S）的开源工具箱：只读兼容性探测、
Ping 诊断命令注入的无持久化验证、经该通道的可靠文件传输，以及一键部署
**持久化、仅密钥、仅 LAN** 的 SSH 服务（可随时 teardown 完全还原）。
**仅限用于你自己的设备**。完整中文文档见
[docs/root-guide.zh-CN.md](docs/root-guide.zh-CN.md)。

## License

MIT — see [LICENSE](LICENSE).
