# Step-by-step quickstart: from zero to persistent SSH

> Target device: Fastweb **NeXXt One** (FGA221D / GDNT-S, firmware 22.2.0378
> series). About 10 minutes total. Except for one button press on the router,
> everything happens in your computer's terminal.
> **Use only on your own router.** 中文版: [quickstart.zh-CN.md](quickstart.zh-CN.md)

## Prerequisites

- A computer on the same LAN as the NeXXt (macOS / Linux / Windows WSL);
- Python 3.9+ (no third-party packages needed);
- Clone the repo:

```bash
git clone https://github.com/VulcanusALex/nexxt-one-toolkit.git
cd nexxt-one-toolkit
```

> Run every `./nexxt` command below from the repo root. On native Windows
> cmd, use `python nexxt_toolkit/cli.py` instead (or just use WSL).

## Step 1: read-only probe (30 seconds, zero risk)

No login, no changes — confirm your device is compatible:

![step 1](images/step1-probe.png)

`strong-front-end-match` means go ahead. `incomplete-match` means the
firmware differs — please open a
[compatibility issue](https://github.com/VulcanusALex/nexxt-one-toolkit/issues/new?template=compatibility_report.md)
instead of pushing forward blindly.

## Step 2: button login (1 minute)

The NeXXt has no password login; logging in means **pressing both side
buttons for 3 seconds**. Run one command and press when asked:

![step 2](images/step2-login.png)

> ⚠️ Two things to note:
> 1. Press within 60 seconds of the prompt appearing;
> 2. **Don't open the router page in a browser during login** (a browser
>    session would supersede the script's session — mechanism explained in
>    [root-guide.md §2](root-guide.md)).

`authenticated=True` means you're in; the session is saved locally under
`.work/` for subsequent commands.

> Fallback: if you prefer the browser — log in on the router page, then hand
> the `sessionID` cookie value (or a full HAR export) to the tool:
> `./nexxt session import-cookie <sessionID|capture.har>`

## Step 3: verify the injection (1 minute, nothing persistent)

Harmless probes only (a sleep timing probe + a `/tmp` marker that is created
and immediately deleted), confirming the command-execution channel:

![step 3](images/step3-verify.png)

`CONFIRMED` means continue; `NOT CONFIRMED` means the firmware has patched
the injection — SSH deployment won't work (read-only features still do).

## Step 4: deploy persistent SSH (~5 minutes)

Generate an **RSA** key first (the router's dropbear is from 2019 and
**does not support ed25519**), then bootstrap in one shot:

![step 4](images/step4-bootstrap.png)

The tool automatically: backs up and patches the root shell → transfers the
public key in verified segments → creates a key-only, LAN-only dropbear
instance → restarts the service → **verifies the handshake itself**.

`handshake OK` means you can connect:

```bash
ssh -i ~/.ssh/nexxt_rsa -p 2222 \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa \
  root@192.168.1.254
```

> Want to see what would run before deciding? Add `--dry-run`:
> `./nexxt ssh bootstrap --pubkey ... --dry-run`

## Step 5: health check anytime (5 seconds)

One command tells you exactly which stage is good/bad/missing:

![step 5](images/step5-doctor.png)

- All green: everything ready;
- Any FAIL: the trailing `→` tells you how to fix it;
- `wan-public-ipv4: FAIL` is an **ISP-side** issue (not your device) — see
  [fastweb-notes.md](fastweb-notes.md).

## Everyday usage

```bash
./nexxt ssh run "ip6tables -L zone_wan_forward -nv" --key ~/.ssh/nexxt_rsa   # run commands on the router
./nexxt fw list --key ~/.ssh/nexxt_rsa                                       # list pinhole rules
./nexxt fw allow --key ~/.ssh/nexxt_rsa --name Allow-AWG-v6 \
  --proto udp --dest-ip 2001:db8::123 --dest-port 51820                      # precise allow (firewall stays on)
./nexxt wanwatch --key ~/.ssh/nexxt_rsa                                      # watch for the public IPv4 provisioning
```

## Full rollback

```bash
./nexxt ssh teardown    # removes the SSH instance and keys, restores /bin/restricted_shell
```

## Error quick reference

| Symptom | Cause & fix |
|---|---|
| `authenticated=False` after pressing | Timed out, or a browser page was opened during login; rerun `./nexxt session login` |
| `not authenticated` (exit 3) | Session expired or superseded; run `./nexxt session login` again |
| `UnknownDeviceError` | Unknown firmware fingerprint; run `./nexxt probe` first, use `--force` only if sure |
| Handshake rejected after bootstrap | Key isn't RSA; must `ssh-keygen -t rsa` |
| `no matching host key type found` | Modern OpenSSH needs `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa` |
| `verify` shows NOT CONFIRMED | Injection patched on this firmware; read-only features only |

## Next steps

- Full mechanism & internals: [root-guide.md](root-guide.md)
- ISP-side network findings (CGNAT/6rd): [fastweb-notes.md](fastweb-notes.md)
- 中文图文版: [quickstart.zh-CN.md](quickstart.zh-CN.md)
