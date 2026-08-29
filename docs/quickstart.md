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
git clone https://github.com/VulcanusALex/homeware-toolkit.git
cd homeware-toolkit
```

> Run every `./homeware` command below from the repo root. On native Windows
> cmd, use `python homeware_toolkit/cli.py` instead (or just use WSL).

Alternatively, install the same CLI with `pipx install homeware-toolkit`, or
download the standalone `homeware.pyz` and `SHA256SUMS` from the latest GitHub
Release. The README contains the checksum-verification commands. When using an
installed command, replace `./homeware` below with `homeware`; for the zipapp, use
`./homeware.pyz`.

## Guided path (recommended)

One command performs the numbered steps below, generates a compatible RSA key
under `~/.homeware-toolkit/`, shows the persistent change, asks for consent,
and rolls back automatically if the final SSH handshake fails:

```bash
./homeware setup
```

Use the manual steps below when you want to inspect each stage separately.

## Step 1: read-only probe (30 seconds, zero risk)

No login, no changes — confirm your device is compatible:

![step 1](images/step1-probe.png)

`strong-front-end-match` means go ahead. `incomplete-match` means the
firmware differs — please open a
[compatibility issue](https://github.com/VulcanusALex/homeware-toolkit/issues/new?template=compatibility_report.md)
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
> `./homeware session import-cookie <sessionID|capture.har>`

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

The tool automatically: stores the original root account line in a persistent,
root-only ownership directory → patches the shell → appends (never overwrites)
its recorded public key → creates a key-only, LAN-only dropbear instance →
restarts the service → **verifies the handshake itself**.

If the device was bootstrapped by toolkit v1.4.0 or older, migrate it once:

```bash
./homeware ssh bootstrap --pubkey ~/.ssh/homeware_rsa.pub --test --adopt-legacy
```

Without that explicit flag, an unowned pre-existing `dropbear.nx` or patched
root shell is left untouched.

`handshake OK` means you can connect:

```bash
ssh -i ~/.ssh/homeware_rsa -p 2222 \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa \
  root@192.168.1.254
```

> Want to see what would run before deciding? Add `--dry-run`:
> `./homeware ssh bootstrap --pubkey ... --dry-run`

## Step 5: health check anytime (5 seconds)

One command tells you exactly which stage is good/bad/missing:

![step 5](images/step5-doctor.png)

- All green: everything ready;
- Any FAIL: the trailing `→` tells you how to fix it;
- `wan-ipv4-assignment: INFO private-RFC1918` describes address assignment;
  it does **not** claim inbound is blocked. An ISP may provide upstream 1:1
  NAT. Use the inbound observer for direct evidence.
- `doctor --check-egress` is an explicit opt-in to contact api4/api6.ipify.org
  and compare public egress with WAN assignment. It remains disabled by default.

## Everyday usage

```bash
./homeware ssh run "ip6tables -L zone_wan_forward -nv" --key ~/.ssh/homeware_rsa   # run commands on the router
./homeware fw list --key ~/.ssh/homeware_rsa                                       # list pinhole rules
./homeware fw ensure --key ~/.ssh/homeware_rsa --name Allow-AWG-v6 \
  --proto udp --dest-ip 2001:db8::123 --dest-port 51820                      # idempotent precise allow
./homeware fw audit --key ~/.ssh/homeware_rsa                                      # UCI/runtime safety audit
./homeware diff -f my-router.json --key ~/.ssh/homeware_rsa                        # preview drift vs a saved config
./homeware apply -f my-router.json --key ~/.ssh/homeware_rsa                       # converge to it, transactionally
./homeware vpn wireguard --key ~/.ssh/homeware_rsa --server-ipv6 2001:db8::123 \
  --client phone                                                             # WireGuard keys + configs + pinhole
./homeware dashboard --key ~/.ssh/homeware_rsa                                     # live WAN/SSH/firewall dashboard
./homeware inbound observe --key ~/.ssh/homeware_rsa --rule Allow-AWG-v6 --wait 30 # make a fresh external connection
./homeware audit-update --key ~/.ssh/homeware_rsa                                  # after OTA or configuration changes
./homeware support-bundle --key ~/.ssh/homeware_rsa                                # sanitized issue attachment
./homeware wanwatch --key ~/.ssh/homeware_rsa                                      # watch for the public IPv4 provisioning
```

Tip: pin the gateway certificate once and use it on every call —
`./homeware session fingerprint`, then `./homeware --tls-fingerprint <fp> ...`.

## No hardware? Develop or demo against the simulator

Every feature above except the real hardware handshake can be exercised
against a fake gateway running on your machine:

```bash
./homeware simulate --time-scale 0.1        # serves on http://127.0.0.1:<port>
./homeware --base-url http://127.0.0.1:<port> probe
./homeware --base-url http://127.0.0.1:<port> session login   # virtual button press
```

The simulator speaks the same web API, button-login handshake and injection
channel (backed by an in-memory filesystem). It is what the integration test
suite runs against, and the fastest way to contribute without owning the
device.

## Full rollback

```bash
./homeware ssh teardown    # removes only toolkit-owned state/key and restores the recorded root line
```

## Error quick reference

| Symptom | Cause & fix |
|---|---|
| `authenticated=False` after pressing | Timed out, or a browser page was opened during login; rerun `./homeware session login` |
| `not authenticated` (exit 3) | Session expired or superseded; run `./homeware session login` again |
| `UnknownDeviceError` | Unknown firmware fingerprint; run `./homeware probe` first, use `--force` only if sure |
| Handshake rejected after bootstrap | Key isn't RSA; must `ssh-keygen -t rsa` |
| `no matching host key type found` | Modern OpenSSH needs `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa` |
| Host key warning from `homeware ssh run` / `fw` | TOFU is on since v1.6.0; if you reinstalled the device, remove the stale line from `~/.homeware-toolkit/known_hosts` |
| `verify` shows NOT CONFIRMED | Injection patched on this firmware; read-only features only |
| Existing changes have no ownership record | A v1.4.0-or-older install is present; rerun bootstrap once with `--adopt-legacy` only if you created it with this toolkit |
| Inbound observer says `not-observed` | Inconclusive: create a fresh client connection; offload or upstream filtering may both produce zero delta |

## Next steps

- Full mechanism & internals: [root-guide.md](root-guide.md)
- ISP-side network findings (CGNAT/6rd): [fastweb-notes.md](fastweb-notes.md)
- 中文图文版: [quickstart.zh-CN.md](quickstart.zh-CN.md)
