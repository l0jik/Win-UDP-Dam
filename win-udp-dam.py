#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ctypes
import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import psutil

APP_NAME = "WinUdpDam"
BASE_DIR = Path.home() / "AppData" / "Local" / APP_NAME
LOG_FILE = BASE_DIR / "win_udp_dam.log"
STATE_FILE = BASE_DIR / "state.json"
RULE_PREFIX = "WinUdpDam"
RULE_NAME_BLOCK = f"{RULE_PREFIX}_Block_All_Outbound_UDP"
RULE_NAME_BLOCK_EXCEPT_DNS = f"{RULE_PREFIX}_Block_All_Outbound_UDP_Except_DNS"
RULE_NAME_ALLOW_PROGRAM_PREFIX = f"{RULE_PREFIX}_Allow_Outbound_UDP_"

# Windows Firewall accepts comma-separated ports/ranges.
BLOCK_PORTS_EXCEPT_DNS = "0-52,54-65535"


def setup_logging() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        encoding="utf-8",
    )


def log_and_print(message: str, level: str = "info") -> None:
    print(message)
    getattr(logging, level)(message)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_admin() -> None:
    if not is_admin():
        log_and_print("Error: run this script as Administrator.", "error")
        sys.exit(1)


def powershell_available() -> str:
    for exe in ("powershell.exe", "pwsh.exe"):
        if shutil.which(exe):
            return exe
    log_and_print("Error: PowerShell was not found in PATH.", "error")
    sys.exit(1)


PS_EXE = None


def run_ps(command: str, check: bool = True) -> subprocess.CompletedProcess:
    global PS_EXE
    if PS_EXE is None:
        PS_EXE = powershell_available()

    full_cmd = [
        PS_EXE,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command,
    ]
    logging.info("PowerShell command: %s", command)
    cp = subprocess.run(full_cmd, capture_output=True, text=True, encoding="utf-8")

    if cp.stdout.strip():
        logging.info("PowerShell stdout: %s", cp.stdout.strip())
    if cp.stderr.strip():
        logging.warning("PowerShell stderr: %s", cp.stderr.strip())

    if check and cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout.strip() or "PowerShell error")
    return cp


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def normalize_program_paths(paths: list[str] | None) -> list[str]:
    if not paths:
        return []

    normalized = []
    seen = set()
    for path in paths:
        p = str(Path(path).expanduser())
        key = p.lower()
        if key not in seen:
            seen.add(key)
            normalized.append(p)
    return normalized


def collect_udp_ports_psutil() -> list[dict]:
    results = []
    seen = set()

    try:
        conns = psutil.net_connections(kind="udp")
    except Exception as e:
        logging.exception("psutil.net_connections failed")
        raise RuntimeError(f"Unable to enumerate UDP endpoints: {e}") from e

    for conn in conns:
        laddr = conn.laddr if conn.laddr else ()
        raddr = conn.raddr if conn.raddr else ()

        local_ip = laddr.ip if hasattr(laddr, "ip") else (laddr[0] if len(laddr) > 0 else "")
        local_port = laddr.port if hasattr(laddr, "port") else (laddr[1] if len(laddr) > 1 else None)
        remote_ip = raddr.ip if hasattr(raddr, "ip") else (raddr[0] if len(raddr) > 0 else "")
        remote_port = raddr.port if hasattr(raddr, "port") else (raddr[1] if len(raddr) > 1 else None)

        item = {
            "pid": conn.pid,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "process_name": None,
            "process_path": None,
        }

        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                item["process_name"] = proc.name()
                item["process_path"] = proc.exe()
            except Exception:
                item["process_name"] = None
                item["process_path"] = None

        key = (
            item["pid"],
            item["local_ip"],
            item["local_port"],
            item["remote_ip"],
            item["remote_port"],
            item["process_path"],
        )
        if key not in seen:
            seen.add(key)
            results.append(item)

    results.sort(
        key=lambda x: (
            x["local_port"] is None,
            x["local_port"] if x["local_port"] is not None else 0,
            x["process_name"] or "",
        )
    )
    return results


def save_state(data: dict) -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def firewall_rule_exists(display_name: str) -> bool:
    ps = f"""
$rule = Get-NetFirewallRule -DisplayName {ps_quote(display_name)} -ErrorAction SilentlyContinue
if ($null -ne $rule) {{ "YES" }} else {{ "NO" }}
"""
    cp = run_ps(ps, check=True)
    return cp.stdout.strip() == "YES"


def remove_rule_if_exists(display_name: str) -> None:
    if firewall_rule_exists(display_name):
        ps = f"Remove-NetFirewallRule -DisplayName {ps_quote(display_name)}"
        run_ps(ps, check=True)
        logging.info("Removed existing firewall rule: %s", display_name)


def get_all_winudpdam_rules() -> list[str]:
    ps = f"""
Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Where-Object {{ $_.DisplayName -like {ps_quote(RULE_PREFIX + '_*')} }} |
  Select-Object -ExpandProperty DisplayName |
  ConvertTo-Json -Depth 2
"""
    cp = run_ps(ps, check=True)
    raw = cp.stdout.strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, str):
        data = [data]
    return sorted(set(data))


def create_block_rule(allow_dns: bool, exempt_programs: list[str]) -> None:
    # Remove old block variants first.
    remove_rule_if_exists(RULE_NAME_BLOCK)
    remove_rule_if_exists(RULE_NAME_BLOCK_EXCEPT_DNS)

    # Program-specific allow rules.
    for program in exempt_programs:
        allow_rule = f"{RULE_NAME_ALLOW_PROGRAM_PREFIX}{Path(program).name}"
        remove_rule_if_exists(allow_rule)
        ps_allow = f"""
New-NetFirewallRule `
  -DisplayName {ps_quote(allow_rule)} `
  -Direction Outbound `
  -Action Allow `
  -Protocol UDP `
  -Program {ps_quote(program)} `
  -Profile Any `
  -Enabled True
"""
        run_ps(ps_allow, check=True)

    if allow_dns:
        # Important: do NOT create a broad block-all-UDP plus an allow-53 rule,
        # because explicit block rules win. Instead block only non-53 UDP ports.
        ps = f"""
New-NetFirewallRule `
  -DisplayName {ps_quote(RULE_NAME_BLOCK_EXCEPT_DNS)} `
  -Direction Outbound `
  -Action Block `
  -Protocol UDP `
  -RemotePort {BLOCK_PORTS_EXCEPT_DNS} `
  -Profile Any `
  -Enabled True
"""
    else:
        ps = f"""
New-NetFirewallRule `
  -DisplayName {ps_quote(RULE_NAME_BLOCK)} `
  -Direction Outbound `
  -Action Block `
  -Protocol UDP `
  -Profile Any `
  -Enabled True
"""

    run_ps(ps, check=True)


def enable_block(allow_dns: bool, exempt_programs: list[str]) -> None:
    ensure_admin()

    udp_before = collect_udp_ports_psutil()
    state = {
        "enabled_at": datetime.now().isoformat(timespec="seconds"),
        "allow_dns": allow_dns,
        "exempt_programs": exempt_programs,
        "udp_snapshot_before_enable": udp_before,
    }
    save_state(state)

    create_block_rule(allow_dns, exempt_programs)

    log_and_print("Outbound UDP blocking enabled.")
    if allow_dns:
        log_and_print("UDP DNS on remote port 53 is NOT blocked.")
        log_and_print("Note: DNS over TCP/53 or DoH/DoT may still depend on your system/app configuration.")
    if exempt_programs:
        log_and_print("Allowed UDP for these programs:")
        for program in exempt_programs:
            log_and_print(f"  - {program}")


def disable_block() -> None:
    ensure_admin()
    for rule in get_all_winudpdam_rules():
        remove_rule_if_exists(rule)
    log_and_print("WinUdpDam rules removed.")


def status() -> None:
    state = load_state()
    rules = get_all_winudpdam_rules()

    print("WinUdpDam rules present:")
    if not rules:
        print("  none")
    else:
        for rule in rules:
            print(f"  {rule}")

    if state:
        print("\nSaved state:")
        print(json.dumps(state, indent=2, ensure_ascii=False))

    print("\nUDP endpoints:")
    try:
        udp_eps = collect_udp_ports_psutil()
        if not udp_eps:
            print("  No UDP endpoints detected.")
        else:
            for item in udp_eps:
                print(
                    f"  pid={item['pid']} proc={item['process_name']} "
                    f"path={item['process_path']} "
                    f"{item['local_ip']}:{item['local_port']} -> "
                    f"{item['remote_ip']}:{item['remote_port']}"
                )
    except Exception as e:
        print(f"  Error: {e}")

    print(f"\nLog file:   {LOG_FILE}")
    print(f"State file: {STATE_FILE}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Block outbound UDP on Windows while optionally allowing DNS and specific programs."
    )
    parser.add_argument("command", choices=["enable", "disable", "status"], help="Action to perform")
    parser.add_argument(
        "--allow-dns",
        action="store_true",
        help="Do not block UDP traffic whose remote port is 53.",
    )
    parser.add_argument(
        "--allow-program",
        action="append",
        default=[],
        metavar="PATH",
        help="Allow outbound UDP for a specific executable path. Can be used multiple times.",
    )
    return parser.parse_args()


def main() -> None:
    setup_logging()
    args = parse_args()

    log_and_print(f"Requested command: {args.command}")
    exempt_programs = normalize_program_paths(args.allow_program)

    try:
        if args.command == "enable":
            enable_block(allow_dns=args.allow_dns, exempt_programs=exempt_programs)
        elif args.command == "disable":
            disable_block()
        elif args.command == "status":
            status()
    except Exception as e:
        logging.exception("Unhandled error")
        log_and_print(f"Error: {e}", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
