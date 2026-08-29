"""One-shot WireGuard remote-access bootstrap (pure stdlib, hardware-free).

Fastweb hands out private/CGNAT IPv4 addresses; the owner typically gets
public reachability only through the 6rd-delegated IPv6 prefix. This module
builds a complete WireGuard setup around that reality:

- X25519 key generation in pure Python (RFC 7748), so neither the gateway
  nor the operator's machine needs the ``wg`` tools installed to bootstrap.
- wg-quick style [Interface]/[Peer] configs for a server running on an
  always-on LAN device (the gateway itself stays stock — see SECURITY.md)
  and one or more roaming clients.
- An idempotent IPv6 firewall pinhole (UDP 51820 -> the WG server's LAN
  address) created through :class:`homeware_toolkit.firewall.FW.ensure`.

Private keys are only ever written to a caller-chosen output directory
(files 0600, directory 0700) and are never printed in full — log lines show
only the first 6 characters followed by "...".
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
import secrets

from .firewall import NAME_RE

DEFAULT_WG_SUBNET = "10.66.66.0/24"
DEFAULT_LISTEN_PORT = 51820
DEFAULT_KEEPALIVE = 25
DEFAULT_RULE_NAME = "Allow-WG-v6"

ENDPOINT_PLACEHOLDER = "<SERVER_PUBLIC_IPV6>"

_CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# ---------------------------------------------------------------------------
# X25519 (RFC 7748) — Montgomery ladder over Curve25519, pure Python.
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_A24 = 121665  # (486662 - 2) / 4, per RFC 7748 section 5
_BASEPOINT = bytes([9]) + bytes(31)


def x25519(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    """RFC 7748 X25519 scalar multiplication. Both inputs are 32 bytes."""
    if len(scalar_bytes) != 32 or len(u_bytes) != 32:
        raise ValueError("X25519 inputs must be exactly 32 bytes")
    # decodeScalar25519: clamp per RFC 7748.
    k = bytearray(scalar_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    scalar = int.from_bytes(k, "little")
    # decodeUCoordinate: mask the most significant bit for X25519.
    x1 = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (scalar >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = x2 * pow(z2, _P - 2, _P) % _P
    return result.to_bytes(32, "little")


def _clamp(raw: bytes) -> bytes:
    """Apply X25519 clamping to 32 random bytes (WireGuard stores them so)."""
    if len(raw) != 32:
        raise ValueError("private key material must be 32 bytes")
    k = bytearray(raw)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(value: str, what: str = "key") -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise RuntimeError(f"invalid base64 WireGuard {what}: {value!r}") from exc
    if len(raw) != 32:
        raise RuntimeError(f"WireGuard {what} must decode to 32 bytes")
    return raw


def generate_private_key() -> str:
    """New clamped X25519 private key, base64-encoded (WireGuard format)."""
    return _b64encode(_clamp(secrets.token_bytes(32)))


def derive_public_key(private_key: str) -> str:
    """base64 public key = X25519(private, basepoint 9)."""
    raw = _b64decode(private_key, "private key")
    return _b64encode(x25519(raw, _BASEPOINT))


def generate_keypair() -> dict:
    """Return {"private": b64, "public": b64} for one WireGuard identity."""
    private = generate_private_key()
    return {"private": private, "public": derive_public_key(private)}


def generate_psk() -> str:
    """New WireGuard preshared key: base64 of 32 random bytes."""
    return _b64encode(secrets.token_bytes(32))


def mask_secret(value: str) -> str:
    """Redacted form for logs: first 6 characters then an ellipsis."""
    return value[:6] + "..." if value else "<empty>"


# ---------------------------------------------------------------------------
# Validation helpers.
# ---------------------------------------------------------------------------

def _validate_server_ipv6(addr: str) -> str:
    """Normalize a global-scope IPv6 address usable as pinhole destination."""
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        raise RuntimeError(f"server_ipv6 must be an IPv6 address: {addr!r}")
    if (ip.is_unspecified or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip in ipaddress.ip_network("fc00::/7")):
        raise RuntimeError(
            f"server_ipv6 must be a global (6rd-delegated) address: {addr!r}")
    return str(ip)


def _validate_network(value: str, what: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise RuntimeError(f"invalid {what}: {value!r}")
    if not isinstance(net, ipaddress.IPv4Network):
        raise RuntimeError(f"{what} must be IPv4 (wg-quick CIDR): {value!r}")
    return net


def _validate_listen_port(port: int) -> int:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise RuntimeError("listen_port must be between 1 and 65535")
    return port


def _validate_client_names(clients) -> list[str]:
    names = list(clients)
    if not names:
        raise RuntimeError("at least one client name is required")
    for name in names:
        if not _CLIENT_NAME_RE.fullmatch(name):
            raise RuntimeError(
                f"client name must be [A-Za-z0-9_-]{{1,32}}: {name!r}")
    if len(set(names)) != len(names):
        raise RuntimeError(f"duplicate client names: {names}")
    return names


# ---------------------------------------------------------------------------
# wg-quick configuration generation.
# ---------------------------------------------------------------------------

def generate_server_config(*, private_key: str, address: str,
                           listen_port: int, peers: list[dict]) -> str:
    """Render a wg-quick server config.

    ``peers`` is a list of dicts with keys ``name``, ``public_key``,
    ``preshared_key`` and ``allowed_ips`` (a sequence of CIDR strings).
    """
    _validate_listen_port(listen_port)
    _b64decode(private_key, "private key")
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
        f"ListenPort = {listen_port}",
    ]
    for peer in peers:
        _b64decode(peer["public_key"], "public key")
        _b64decode(peer["preshared_key"], "preshared key")
        allowed = ", ".join(str(ipaddress.ip_network(a, strict=False))
                            for a in peer["allowed_ips"])
        lines += [
            "",
            f"# client: {peer['name']}",
            "[Peer]",
            f"PublicKey = {peer['public_key']}",
            f"PresharedKey = {peer['preshared_key']}",
            f"AllowedIPs = {allowed}",
        ]
    return "\n".join(lines) + "\n"


def generate_client_config(*, private_key: str, address: str,
                           peer_public_key: str, preshared_key: str,
                           endpoint: str | None,
                           allowed_ips=("10.66.66.0/24",),
                           dns=(), persistent_keepalive: int = DEFAULT_KEEPALIVE,
                           listen_port: int = DEFAULT_LISTEN_PORT) -> str:
    """Render a wg-quick client config.

    ``endpoint=None`` emits the ``<SERVER_PUBLIC_IPV6>`` placeholder plus a
    comment telling the operator to fill in the WG server's public IPv6
    (an address inside the 6rd-delegated prefix).
    """
    _b64decode(private_key, "private key")
    _b64decode(peer_public_key, "public key")
    _b64decode(preshared_key, "preshared key")
    _validate_listen_port(listen_port)
    allowed = ", ".join(str(ipaddress.ip_network(a, strict=False))
                        for a in allowed_ips)
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
    ]
    for server in dns:
        lines.append(f"DNS = {ipaddress.ip_address(server)}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {peer_public_key}",
        f"PresharedKey = {preshared_key}",
        f"AllowedIPs = {allowed}",
    ]
    if endpoint:
        lines.append(f"Endpoint = [{endpoint}]:{listen_port}")
    else:
        lines += [
            f"# TODO: replace {ENDPOINT_PLACEHOLDER} with the WG server's",
            "# public IPv6 (inside the 6rd-delegated prefix, same address",
            "# used as the firewall pinhole destination).",
            f"Endpoint = {ENDPOINT_PLACEHOLDER}:{listen_port}",
        ]
    if persistent_keepalive:
        lines.append(f"PersistentKeepalive = {int(persistent_keepalive)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Secret file handling.
# ---------------------------------------------------------------------------

def _prepare_output_dir(path: str) -> str:
    path = os.path.expanduser(path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _write_secret_file(path: str, content: str, force: bool) -> None:
    """Write ``content`` with mode 0600; refuse to overwrite unless forced."""
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if force else os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(
            f"{path} already exists; pass force=True to overwrite it") from exc
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# Bootstrap orchestration.
# ---------------------------------------------------------------------------

def _snapshot_warnings(snapshot: dict, server_ipv6: str | None) -> list[str]:
    """Cross-check the WG server address against the wanwatch snapshot."""
    warnings: list[str] = []
    if snapshot.get("mode") == "none":
        warnings.append(
            "wanwatch snapshot shows no IPv6 connectivity; the WireGuard "
            "endpoint will not be reachable until 6rd/wan6 comes up")
    prefixes = (snapshot.get("sixrd_prefixes")
                or snapshot.get("wan6_prefixes") or [])
    if server_ipv6 and prefixes:
        ip = ipaddress.ip_address(server_ipv6)
        if not any(ip in ipaddress.ip_network(p, strict=False)
                   for p in prefixes):
            warnings.append(
                f"server_ipv6 {server_ipv6} is outside the delegated prefix(es) "
                f"{', '.join(prefixes)}; check the address or re-run wanwatch")
    return warnings


def bootstrap_wireguard(fw, output_dir: str, *,
                        server_ipv6: str | None = None,
                        clients=("client1",),
                        wg_subnet: str = DEFAULT_WG_SUBNET,
                        server_wg_address: str | None = None,
                        listen_port: int = DEFAULT_LISTEN_PORT,
                        allowed_ips=None,
                        dns=(),
                        persistent_keepalive: int = DEFAULT_KEEPALIVE,
                        rule_name: str = DEFAULT_RULE_NAME,
                        snapshot: dict | None = None,
                        force: bool = False,
                        log=print) -> dict:
    """One-shot WireGuard remote-access bootstrap.

    Generates a server keypair, one keypair + PSK per client, renders both
    configs into ``output_dir`` (0700, files 0600) and — when ``fw`` is not
    None — idempotently ensures the UDP pinhole ``listen_port`` ->
    ``server_ipv6`` on the gateway via ``fw.ensure`` (family ipv6).

    ``fw`` may be None to only render configs; the manual ``homeware fw ensure``
    command is then included in ``next_steps``. ``snapshot`` is an optional
    wanwatch report dict used to sanity-check ``server_ipv6`` against the
    delegated 6rd/native prefix. Returns a structured result; full private
    keys appear ONLY inside the returned/written config texts, never in log
    output.
    """
    if not NAME_RE.fullmatch(rule_name):
        raise RuntimeError("rule name must be [A-Za-z0-9_-]{1,32}")
    listen_port = _validate_listen_port(listen_port)
    names = _validate_client_names(clients)
    net = _validate_network(wg_subnet, "wg_subnet")
    if fw is not None and server_ipv6 is None:
        raise RuntimeError("server_ipv6 is required to create the pinhole "
                           "(or pass fw=None to only render configs)")
    if server_ipv6 is not None:
        server_ipv6 = _validate_server_ipv6(server_ipv6)
    allowed = list(allowed_ips) if allowed_ips else [str(net)]
    for a in allowed:
        ipaddress.ip_network(a, strict=False)  # raises on garbage
    dns = [str(ipaddress.ip_address(s)) for s in dns]

    if net.num_addresses < 2 + len(names):
        raise RuntimeError(f"wg_subnet {net} too small for {len(names)} clients")
    if server_wg_address is None:
        server_host = net.network_address + 1
    else:
        server_host = ipaddress.IPv4Address(server_wg_address)
        if server_host not in net:
            raise RuntimeError(
                f"server_wg_address {server_host} outside {net}")
    server_address = f"{server_host}/{net.prefixlen}"

    # Keys: one server identity, one identity + unique PSK per client.
    server_keys = generate_keypair()
    peers = []
    client_entries = []
    for index, name in enumerate(names):
        client_keys = generate_keypair()
        psk = generate_psk()
        client_host = net.network_address + 2 + index
        if client_host == server_host:
            client_host += 1
        client_address = f"{client_host}/32"
        peers.append({"name": name, "public_key": client_keys["public"],
                      "preshared_key": psk, "allowed_ips": [client_address]})
        client_entries.append({
            "name": name, "keys": client_keys, "psk": psk,
            "address": client_address,
        })
    log(f"[vpn] generated server keypair (public {server_keys['public'][:6]}...)"
        f" and {len(names)} client identit{'ies' if len(names) != 1 else 'y'}"
        f" with unique PSKs")

    server_config = generate_server_config(
        private_key=server_keys["private"], address=server_address,
        listen_port=listen_port, peers=peers)
    for entry in client_entries:
        entry["config"] = generate_client_config(
            private_key=entry["keys"]["private"], address=entry["address"],
            peer_public_key=server_keys["public"], preshared_key=entry["psk"],
            endpoint=server_ipv6, allowed_ips=allowed, dns=dns,
            persistent_keepalive=persistent_keepalive,
            listen_port=listen_port)

    # Firewall pinhole (idempotent, strict validation inside FW.ensure).
    rule_result = None
    if fw is not None:
        rule_result = fw.ensure(name=rule_name, proto="udp",
                                dest_ip=server_ipv6,
                                dest_port=str(listen_port), family="ipv6")
        log(f"[vpn] firewall rule {rule_name!r} "
            f"{'updated' if rule_result.get('changed') else 'already exact'}: "
            f"udp/{listen_port} -> [{server_ipv6}] (ipv6)")

    # Secret material only ever touches the output directory.
    out_dir = _prepare_output_dir(output_dir)
    server_path = os.path.join(out_dir, "wg-server.conf")
    _write_secret_file(server_path, server_config, force)
    for entry in client_entries:
        entry["config_path"] = os.path.join(out_dir,
                                            f"wg-client-{entry['name']}.conf")
        _write_secret_file(entry["config_path"], entry["config"], force)
    log(f"[vpn] wrote {server_path} and {len(names)} client config(s) to "
        f"{out_dir} (dir 0700, files 0600)")
    log(f"[vpn] server private key: {mask_secret(server_keys['private'])} "
        f"(full value only in {server_path})")

    endpoint = f"[{server_ipv6}]:{listen_port}" if server_ipv6 else None
    warnings = _snapshot_warnings(snapshot, server_ipv6) if snapshot else []
    for warning in warnings:
        log(f"[vpn] WARNING: {warning}")

    next_steps = [
        f"Install WireGuard on the always-on LAN device that will serve "
        f"(e.g. 'apt install wireguard' / your NAS package manager) and copy "
        f"{server_path} to /etc/wireguard/wg0.conf there.",
        "Start it with 'wg-quick up wg0' (enable ip forwarding: "
        "net.ipv4.ip_forward=1 if clients should reach the whole LAN).",
        f"Import each wg-client-<name>.conf from {out_dir} into the WireGuard "
        "app on the matching phone/laptop (file import or QR code).",
    ]
    if server_ipv6 is None:
        next_steps.append(
            f"Fill in {ENDPOINT_PLACEHOLDER} in every client config with the "
            "WG server's public IPv6 from the 6rd-delegated prefix (see "
            "'homeware wanwatch' for the current prefix).")
    if fw is None:
        next_steps.append(
            f"Open the pinhole manually once SSH is up: homeware fw ensure "
            f"--name {rule_name} --proto udp --dest-ip <server-ipv6> "
            f"--dest-port {listen_port} --family ipv6 --key <key>")
    if endpoint:
        next_steps.append(
            f"Clients connect to {endpoint}; verify with 'homeware inbound "
            f"observe --rule {rule_name}' while a client handshakes.")

    return {
        "rule_name": rule_name,
        "rule": rule_result,
        "endpoint": endpoint,
        "listen_port": listen_port,
        "wg_subnet": str(net),
        "output_dir": out_dir,
        "server": {
            "wg_address": server_address,
            "public_key": server_keys["public"],
            "config_path": server_path,
            "config": server_config,
        },
        "clients": [{
            "name": entry["name"],
            "wg_address": entry["address"],
            "public_key": entry["keys"]["public"],
            "config_path": entry["config_path"],
            "config": entry["config"],
        } for entry in client_entries],
        "warnings": warnings,
        "next_steps": next_steps,
    }
