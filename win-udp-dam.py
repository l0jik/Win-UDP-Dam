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
RULE_NAME = "WinUdpDam_Block_All_Outbound_UDP"
BASE_DIR = Path.home() / "AppData" / "Local" / APP_NAME
LOG_FILE = BASE_DIR / "win_udp_dam.log"
STATE_FILE = BASE_DIR / "state.json"


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
    # Prefer Windows PowerShell 5.1 on Windows 11 for NetSecurity module support
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
    cp = subprocess.run(
        full_cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    if cp.stdout.strip():
        logging.info("PowerShell stdout: %s", cp.stdout.strip())
    if cp.stderr.strip():
        logging.warning("PowerShell stderr: %s", cp.stderr.strip())

    if check and cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout.strip() or "PowerShell error")

    return cp


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
        }

        if conn.pid:
            try:
                item["process_name"] = psutil.Process(conn.pid).name()
            except Exception:
                item["process_name"] = None

        key = (
            item["pid"],
            item["local_ip"],
            item["local_port"],
            item["remote_ip"],
            item["remote_port"],
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


def collect_udp_ports_powershell() -> list[dict]:
    # Native Windows fallback/integration
    ps = r"""
$eps = Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess
$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$eps | ForEach-Object {
    [PSCustomObject]@{
        local_ip = $_.LocalAddress
        local_port = $_.LocalPort
        pid = $_.OwningProcess
        process_name = $procs[$_.OwningProcess]
    }
} | ConvertTo-Json -Depth 3
"""
    cp = run_ps(ps, check=True)
    raw = cp.stdout.strip()
    if not raw:
        return []

    data = json.loads(raw)
    if isinstance(data, dict):
        data = [data]
    return data


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


def firewall_rule_exists() -> bool:
    ps = f"""
$rule = Get-NetFirewallRule -DisplayName "{RULE_NAME}" -ErrorAction SilentlyContinue
if ($null -ne $rule) {{ "YES" }} else {{ "NO" }}
"""
    cp = run_ps(ps, check=True)
    return cp.stdout.strip() == "YES"


def enable_block() -> None:
    ensure_admin()

    if firewall_rule_exists():
        log_and_print(f"Rule already exists: {RULE_NAME}")
        return

    udp_before = collect_udp_ports_psutil()
    state = {
        "enabled_at": datetime.now().isoformat(timespec="seconds"),
        "rule_name": RULE_NAME,
        "udp_snapshot_before_enable": udp_before,
    }
    save_state(state)

    ps = f"""
New-NetFirewallRule `
  -DisplayName "{RULE_NAME}" `
  -Direction Outbound `
  -Action Block `
  -Protocol UDP `
  -Profile Any `
  -Enabled True
"""
    run_ps(ps, check=True)
    log_and_print(f"Outbound UDP blocking enabled with rule: {RULE_NAME}")


def disable_block() -> None:
    ensure_admin()

    if not firewall_rule_exists():
        log_and_print("No matching rule found.")
        return

    ps = f'Remove-NetFirewallRule -DisplayName "{RULE_NAME}"'
    run_ps(ps, check=True)
    log_and_print(f"Rule removed: {RULE_NAME}")


def status() -> None:
    exists = firewall_rule_exists()
    print(f"Firewall rule present: {'YES' if exists else 'NO'}")

    print("\nUDP endpoints (psutil):")
    try:
        udp_eps = collect_udp_ports_psutil()
        if not udp_eps:
            print("  No UDP endpoints detected.")
        else:
            for item in udp_eps:
                print(
                    f"  pid={item['pid']} "
                    f"proc={item['process_name']} "
                    f"{item['local_ip']}:{item['local_port']} "
                    f"-> {item['remote_ip']}:{item['remote_port']}"
                )
    except Exception as e:
        print(f"  psutil error: {e}")

    print("\nUDP endpoints (PowerShell/Get-NetUDPEndpoint):")
    try:
        udp_ps = collect_udp_ports_powershell()
        if not udp_ps:
            print("  No UDP endpoints detected.")
        else:
            for item in udp_ps:
                print(
                    f"  pid={item.get('pid')} "
                    f"proc={item.get('process_name')} "
                    f"{item.get('local_ip')}:{item.get('local_port')}"
                )
    except Exception as e:
        print(f"  PowerShell error: {e}")

    if STATE_FILE.exists():
        print(f"\nState file: {STATE_FILE}")
    print(f"Log file:   {LOG_FILE}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Block all outbound UDP on Windows 11 and log activity."
    )
    parser.add_argument(
        "command",
        choices=["enable", "disable", "status"],
        help="Action to perform",
    )
    return parser.parse_args()


def main() -> None:
    setup_logging()
    args = parse_args()

    log_and_print(f"Requested command: {args.command}")

    try:
        if args.command == "enable":
            enable_block()
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
