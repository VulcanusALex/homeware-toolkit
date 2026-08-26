"""Unified CLI for nexxt-one-toolkit.

Usage: nexxt [--base-url URL] [--json] [--quiet] [--version] <command> [options]

Commands:
  probe                         read-only compatibility probe (no login)
  setup                         guided probe-to-SSH setup
  doctor                        end-to-end health check
  session login|check|dump|import-cookie
  verify                        non-persistent injection proof
  transfer <file> <target>      push a file over the injection channel
  ssh bootstrap|status|run|teardown
  fw list|allow|ensure|audit|delete
  inbound observe               watch a firewall rule during an external test
  support-bundle                write a sanitized issue-ready report
  audit-update                  post-firmware-update security audit
  wanwatch
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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

    p_setup = sub.add_parser("setup", help="guided, transactional first-time setup")
    p_setup.add_argument("--key", default="~/.nexxt-one-toolkit/id_rsa",
                         help="private-key path to create or reuse")
    p_setup.add_argument("--port", type=int, default=2222)
    p_setup.add_argument("--yes", action="store_true",
                         help="accept the displayed persistent-change step")
    p_setup.add_argument("--adopt-legacy", action="store_true",
                         help="adopt a confirmed <=1.4.0 toolkit installation")

    p_doc = sub.add_parser("doctor", help="end-to-end health check")
    p_doc.add_argument("--key", help="SSH private key (enables SSH/WAN checks)")
    p_doc.add_argument("--port", type=int, default=2222)
    p_doc.add_argument("--no-injection", action="store_true")
    p_doc.add_argument("--check-egress", action="store_true",
                       help="opt in to public IPv4/IPv6 lookup via ipify")

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
    s_boot.add_argument("--adopt-legacy", action="store_true",
                        help="adopt a confirmed <=1.4.0 toolkit installation")
    s_boot.add_argument("--original-shell", default="/bin/restricted_shell",
                        help="pre-toolkit shell used only with --adopt-legacy")
    s_stat = ssh_sub.add_parser("status")
    s_stat.add_argument("--port", type=int, default=2222)
    s_run = ssh_sub.add_parser("run")
    s_run.add_argument("remote_command")
    s_run.add_argument("--key", required=True)
    s_run.add_argument("--port", type=int, default=2222)
    s_run.add_argument("--timeout", type=int, default=30)
    s_down = ssh_sub.add_parser("teardown")
    s_down.add_argument("--port", type=int, default=2222)
    s_down.add_argument("--legacy-force", action="store_true",
                        help="use old destructive cleanup only for <=1.4.0 installs")

    p_fw = sub.add_parser("fw", help="precise firewall pinholes (over SSH)")
    fw_sub = p_fw.add_subparsers(dest="fw_cmd", required=True)
    for name in ("list", "allow", "ensure", "audit", "delete"):
        sp = fw_sub.add_parser(name)
        sp.add_argument("--key", required=True)
        sp.add_argument("--port", type=int, default=2222)
        if name in ("allow", "ensure"):
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

    p_in = sub.add_parser("inbound", help="observe inbound firewall counter changes")
    in_sub = p_in.add_subparsers(dest="inbound_cmd", required=True)
    in_obs = in_sub.add_parser("observe")
    in_obs.add_argument("--rule", required=True)
    in_obs.add_argument("--key", required=True)
    in_obs.add_argument("--port", type=int, default=2222)
    in_obs.add_argument("--wait", type=int, default=30)

    p_bundle = sub.add_parser("support-bundle", help="write a sanitized support bundle")
    p_bundle.add_argument("--output", help=".zip or .json output path")
    p_bundle.add_argument("--key", help="optional SSH key for sanitized doctor results")
    p_bundle.add_argument("--port", type=int, default=2222)

    p_audit = sub.add_parser("audit-update", help="audit security state after firmware changes")
    p_audit.add_argument("--key", required=True)
    p_audit.add_argument("--port", type=int, default=2222)
    p_audit.add_argument("--state-file",
                         default="~/.nexxt-one-toolkit/audit-state.json")
    p_audit.add_argument("--accept-change", action="store_true",
                         help="accept the current fingerprint as the new baseline")

    p_ww = sub.add_parser("wanwatch", help="WAN provisioning watcher")
    p_ww.add_argument("--key", required=True)
    p_ww.add_argument("--port", type=int, default=2222)
    p_ww.add_argument("--state-file",
                      default="~/.nexxt_wanwatch_state.json")
    p_ww.add_argument("--notify", action="store_true",
                      help="desktop notification on change (macOS; no-op elsewhere)")
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

        if args.command == "setup":
            from .setup import run_setup
            result, code = run_setup(
                args.base_url, args.port, args.key, assume_yes=args.yes,
                force=args.force, adopt_legacy=args.adopt_legacy, log=log)
            return rep.out(result, code)

        if args.command == "doctor":
            from . import doctor as doctor_mod
            stages, code = doctor_mod.run_doctor(
                args.base_url, args.port, key=args.key,
                check_injection=not args.no_injection,
                check_egress=args.check_egress, log=log)
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
            from .inject import I
            try:
                with open(args.file, "rb") as fh:
                    data = fh.read()
            except OSError as exc:
                raise RuntimeError(f"cannot read {args.file}: {exc}") from exc
            inj = Injector(NexxtClient(args.base_url), force=args.force, log=log)
            parts = transfer_mod.push_data(inj, data, args.tag)
            transfer_mod.assemble(inj, parts, args.target,
                                  expect_md5=hashlib.md5(data).hexdigest())
            inj.do(f"rm{I}-f{I}/tmp/nxseg_{args.tag}_*")
            log(f"[transfer] {args.target} written and md5-verified")
            return rep.out({"target": args.target, "parts": len(parts),
                            "md5_verified": True})

        if args.command == "ssh":
            from . import ssh as ssh_mod
            if args.ssh_cmd == "bootstrap":
                inj = Injector(NexxtClient(args.base_url), force=args.force,
                               dry_run=args.dry_run, log=log)
                ssh_mod.bootstrap(
                    inj, args.pubkey, args.port, log=log,
                    adopt_legacy=args.adopt_legacy,
                    original_shell=args.original_shell)
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
                ssh_mod.teardown(inj, args.port, log=log,
                                 legacy_force=args.legacy_force)
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
            if args.fw_cmd in ("allow", "ensure"):
                result = fw.ensure(args.name, args.proto, args.dest_ip,
                                   args.dest_port, args.family, args.src, args.dest)
                log(f"[fw] rule {args.name!r} "
                    f"{'updated' if result['changed'] else 'already exact'}")
                return rep.out(result)
            if args.fw_cmd == "audit":
                result = fw.audit()
                if not args.json:
                    if result["findings"]:
                        for finding in result["findings"]:
                            print(f"[{finding['severity']}] {finding['type']}: "
                                  f"{finding.get('rule', '-')}")
                    else:
                        print("firewall audit: no findings")
                return rep.out(result, 0 if result["ok"] else 1)
            if args.fw_cmd == "delete":
                sections = fw.delete(args.name)
                log(f"[fw] deleted: {sections or 'nothing found'}")
                return rep.out({"deleted": sections})

        if args.command == "inbound":
            from .firewall import FW
            from .inbound import observe
            fw = FW(host_of(args.base_url), args.port, args.key)
            result = observe(fw, args.rule, args.wait, log=log)
            return rep.out(result, 0 if result["state"] == "confirmed-at-gateway" else 2)

        if args.command == "support-bundle":
            from .support import build_report, default_output, write_bundle
            output = write_bundle(
                build_report(args.base_url, args.port, args.key),
                args.output or default_output())
            log(f"support bundle written: {output}")
            return rep.out({"output": output})

        if args.command == "audit-update":
            from .audit import run_audit
            result, code = run_audit(args.base_url, args.port, args.key,
                                     args.state_file, args.accept_change)
            if not args.json:
                for check in result["checks"]:
                    print(f"[{check['status']}] {check['check']}: {check['detail']}")
            return rep.out(result, code)

        if args.command == "wanwatch":
            from . import wanwatch as ww_mod
            report, code = ww_mod.watch(host_of(args.base_url), args.port, args.key,
                                        os.path.expanduser(args.state_file),
                                        notify=args.notify)
            return rep.out(report, code)

    except SessionExpired as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except (RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
