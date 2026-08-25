"""Unified CLI for nexxt-one-toolkit.

Usage: nexxt [--base-url URL] [--json] [--quiet] [--version] <command> [options]

Commands:
  probe                         read-only compatibility probe (no login)
  doctor                        end-to-end health check
  session login|check|dump|import-cookie
  verify                        non-persistent injection proof
  transfer <file> <target>      push a file over the injection channel
  ssh bootstrap|status|run|teardown
  fw list|allow|delete
  wanwatch
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .client import DEFAULT_BASE_URL, NexxtClient, SessionExpired
from .inject import Injector
from .ssh import host_of


class Reporter:
    def __init__(self, as_json: bool, quiet: bool) -> None:
        self.as_json, self.quiet = as_json, quiet
        self.payload = None

    def log(self, msg: str) -> None:
        if not self.quiet and not self.as_json:
            print(msg, flush=True)

    def out(self, payload, code: int = 0) -> int:
        self.payload = payload
        if self.as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return code


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nexxt", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default=DEFAULT_BASE_URL)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--force", action="store_true",
                   help="skip firmware fingerprint guard")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("probe", help="read-only compatibility probe")

    p_doc = sub.add_parser("doctor", help="end-to-end health check")
    p_doc.add_argument("--key", help="SSH private key (enables SSH/WAN checks)")
    p_doc.add_argument("--port", type=int, default=2222)
    p_doc.add_argument("--no-injection", action="store_true")

    p_sess = sub.add_parser("session", help="web session management")
    sess_sub = p_sess.add_subparsers(dest="session_cmd", required=True)
    s_login = sess_sub.add_parser("login", help="button-assisted login")
    s_login.add_argument("--wait", type=int, default=60)
    sess_sub.add_parser("check")
    sess_sub.add_parser("dump")
    s_imp = sess_sub.add_parser("import-cookie")
    s_imp.add_argument("source", help="HAR file path or raw sessionID")

    sub.add_parser("verify", help="non-persistent injection proof")

    p_tr = sub.add_parser("transfer", help="push a file over the injection channel")
    p_tr.add_argument("file")
    p_tr.add_argument("target")
    p_tr.add_argument("--tag", default="xfer")

    p_ssh = sub.add_parser("ssh", help="persistent key-only SSH service")
    ssh_sub = p_ssh.add_subparsers(dest="ssh_cmd", required=True)
    s_boot = ssh_sub.add_parser("bootstrap")
    s_boot.add_argument("--pubkey", required=True)
    s_boot.add_argument("--privkey")
    s_boot.add_argument("--port", type=int, default=2222)
    s_boot.add_argument("--test", action="store_true")
    s_boot.add_argument("--dry-run", action="store_true")
    s_stat = ssh_sub.add_parser("status")
    s_stat.add_argument("--port", type=int, default=2222)
    s_run = ssh_sub.add_parser("run")
    s_run.add_argument("remote_command")
    s_run.add_argument("--key", required=True)
    s_run.add_argument("--port", type=int, default=2222)
    s_run.add_argument("--timeout", type=int, default=30)
    s_down = ssh_sub.add_parser("teardown")
    s_down.add_argument("--port", type=int, default=2222)

    p_fw = sub.add_parser("fw", help="precise firewall pinholes (over SSH)")
    fw_sub = p_fw.add_subparsers(dest="fw_cmd", required=True)
    for name in ("list", "allow", "delete"):
        sp = fw_sub.add_parser(name)
        sp.add_argument("--key", required=True)
        sp.add_argument("--port", type=int, default=2222)
        if name == "allow":
            sp.add_argument("--name", required=True)
            sp.add_argument("--proto", default="udp",
                            choices=["tcp", "udp", "tcpudp", "all"])
            sp.add_argument("--dest-ip", required=True)
            sp.add_argument("--dest-port", required=True)
            sp.add_argument("--family", default="ipv6",
                            choices=["ipv4", "ipv6", "any"])
            sp.add_argument("--src", default="wan")
            sp.add_argument("--dest", default="lan")
        if name == "delete":
            sp.add_argument("--name", required=True)

    p_ww = sub.add_parser("wanwatch", help="WAN provisioning watcher")
    p_ww.add_argument("--key", required=True)
    p_ww.add_argument("--port", type=int, default=2222)
    p_ww.add_argument("--state-file",
                      default="~/.nexxt_wanwatch_state.json")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rep = Reporter(args.json, args.quiet)
    log = rep.log

    try:
        if args.command == "probe":
            from . import probe as probe_mod
            result = probe_mod.run_probe(args.base_url)
            if not args.json:
                a = result["analysis"]
                print(f"compatibility: {a['compatibility_signal']}  "
                      f"stamps={a['asset_version_stamps']}  ports={result['tcp_ports']}")
            return rep.out(result, 0 if result["analysis"]["compatibility_signal"]
                           == "strong-front-end-match" else 1)

        if args.command == "doctor":
            from . import doctor as doctor_mod
            stages, code = doctor_mod.run_doctor(
                args.base_url, args.port, key=args.key,
                check_injection=not args.no_injection, log=log)
            return rep.out({"stages": stages}, code)

        if args.command == "session":
            client = NexxtClient(args.base_url)
            if args.session_cmd == "login":
                if client.is_authenticated():
                    log("[login] already authenticated")
                    return rep.out({"authenticated": True})
                ok = client.button_login(args.wait, log=log)
                log(f"[login] authenticated={ok}")
                return rep.out({"authenticated": ok}, 0 if ok else 1)
            if args.session_cmd == "check":
                ok = client.is_authenticated()
                if not args.json:
                    print(f"authenticated: {ok}")
                return rep.out({"authenticated": ok}, 0 if ok else 1)
            if args.session_cmd == "dump":
                data = client.dump()
                if not args.json:
                    print(json.dumps(data, ensure_ascii=False, indent=2))
                return rep.out(data)
            if args.session_cmd == "import-cookie":
                ok = client.import_cookie(args.source)
                if not args.json:
                    print(f"imported, authenticated: {ok}")
                return rep.out({"imported": True, "authenticated": ok}, 0 if ok else 1)

        if args.command == "verify":
            from . import verify as verify_mod
            inj = Injector(NexxtClient(args.base_url), force=args.force, log=log)
            report = verify_mod.verify(inj, log=log)
            ok = report["backend_command_execution"]
            if not args.json:
                print(f"backend command execution: {'CONFIRMED' if ok else 'NOT CONFIRMED'}")
            return rep.out(report, 0 if ok else 1)

        if args.command == "transfer":
            from . import transfer as transfer_mod
            inj = Injector(NexxtClient(args.base_url), force=args.force, log=log)
            data = open(args.file, "rb").read()
            parts = transfer_mod.push_data(inj, data, args.tag)
            transfer_mod.assemble(inj, parts, args.target)
            return rep.out({"target": args.target, "parts": len(parts)})

        if args.command == "ssh":
            from . import ssh as ssh_mod
            if args.ssh_cmd == "bootstrap":
                inj = Injector(NexxtClient(args.base_url), force=args.force,
                               dry_run=args.dry_run, log=log)
                ssh_mod.bootstrap(inj, args.pubkey, args.port, log=log)
                host = host_of(args.base_url)
                log(f"\n[ssh] connect: ssh -i <key> -p {args.port} "
                    f"-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa root@{host}")
                if args.test and not args.dry_run:
                    priv = args.privkey or args.pubkey.removesuffix(".pub")
                    proc = ssh_mod.ssh_run(host, args.port, priv, "echo SSH_OK; id")
                    if "SSH_OK" not in proc.stdout:
                        print(f"[ssh] handshake FAILED: {proc.stderr.strip()}",
                              file=sys.stderr)
                        return rep.out({"bootstrap": True, "handshake": False}, 1)
                    log("[ssh] handshake OK")
                return rep.out({"bootstrap": True})
            if args.ssh_cmd == "status":
                inj = Injector(NexxtClient(args.base_url), force=True, log=log)
                st = ssh_mod.status(inj, args.port)
                if not args.json:
                    for k, v in st.items():
                        print(f"{k}: {v}")
                return rep.out(st, 0 if st["listening"] else 1)
            if args.ssh_cmd == "run":
                proc = ssh_mod.ssh_run(host_of(args.base_url), args.port, args.key,
                                       args.remote_command, timeout=args.timeout)
                sys.stdout.write(proc.stdout)
                sys.stderr.write(proc.stderr)
                return proc.returncode
            if args.ssh_cmd == "teardown":
                inj = Injector(NexxtClient(args.base_url), force=True, log=log)
                ssh_mod.teardown(inj, args.port, log=log)
                return rep.out({"teardown": True})

        if args.command == "fw":
            from .firewall import FW
            fw = FW(host_of(args.base_url), args.port, args.key)
            if args.fw_cmd == "list":
                rules = fw.list_rules()
                if not args.json:
                    for r in rules:
                        print(f"{r.get('name', r['section'])}: {r.get('src','-')}→{r.get('dest','-')} "
                              f"{r.get('proto','-')} {r.get('dest_ip','-')}:{r.get('dest_port','-')} "
                              f"{r.get('target','-')} enabled={r.get('enabled','1')}")
                    if not rules:
                        print("(no pinhole rules)")
                return rep.out(rules)
            if args.fw_cmd == "allow":
                fw.allow(args.name, args.proto, args.dest_ip, args.dest_port,
                         args.family, args.src, args.dest)
                log(f"[fw] rule {args.name!r} added")
                return rep.out({"added": args.name})
            if args.fw_cmd == "delete":
                sections = fw.delete(args.name)
                log(f"[fw] deleted: {sections or 'nothing found'}")
                return rep.out({"deleted": sections})

        if args.command == "wanwatch":
            from . import wanwatch as ww_mod
            report, code = ww_mod.watch(host_of(args.base_url), args.port, args.key,
                                        args.state_file.replace("~", __import__("os").path.expanduser("~")))
            return rep.out(report, code)

    except SessionExpired as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
