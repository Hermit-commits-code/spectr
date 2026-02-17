import argparse
import hashlib
import os
import sys

import requests
import tomllib
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spectr.cache import CacheManager
from spectr.checker_logic import (
    calculate_spectr_score,
    check_author_reputation,
    check_for_typosquatting,
    check_reputation,
    check_resurrection,
    disable_hooks,
    scan_payload,
)
from spectr.sandbox import execute_in_sandbox

# --- CONFIGURATION ---
VERSION = "0.22.0"
console = Console()
cache = CacheManager()
WHITELIST_FILE = os.path.expanduser("~/.spectr-whitelist")
SIG_FILE = WHITELIST_FILE + ".sig"

# --- WHITELIST & INTEGRITY ---


def ensure_whitelist_exists():
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write("# Spectr Whitelist - Trusted packages\n")
        sign_whitelist()


def is_whitelisted(package_name):
    if not os.path.exists(WHITELIST_FILE):
        return False
    with open(WHITELIST_FILE, "r") as f:
        return package_name in [l.strip() for l in f if not l.startswith("#")]


def add_to_whitelist(package_name):
    if is_whitelisted(package_name):
        return
    with open(WHITELIST_FILE, "a") as f:
        f.write(f"{package_name}\n")
    console.print(f"✅ [green]{package_name}[/green] added to whitelist.")


def sign_whitelist():
    with open(WHITELIST_FILE, "rb") as f:
        new_hash = hashlib.sha256(f.read()).hexdigest()
    with open(SIG_FILE, "w") as f:
        f.write(new_hash)
    console.print("🖋️  [dim]Whitelist signature updated.[/dim]")


def verify_whitelist_integrity():
    if not os.path.exists(WHITELIST_FILE):
        return True
    if not os.path.exists(SIG_FILE):
        return False
    with open(WHITELIST_FILE, "rb") as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()
    with open(SIG_FILE, "r") as f:
        return current_hash == f.read().strip()


# --- FORENSIC ENGINE ---


def fetch_pypi_data(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(url, timeout=5)
        return response.json() if response.status_code == 200 else None
    except Exception:
        return None


def check_package(package, args, depth=0):
    if is_whitelisted(package):
        return True, 100

    cached = cache.get_cached_audit(package, "latest")
    if cached:
        score, _ = cached
        if score >= 80:
            return True, score

    data = fetch_pypi_data(package)
    if not data:
        console.print(f"❌ [red]Package '{package}' not found on PyPI.[/red]")
        return False, 0

    info = data.get("info", {})
    typo_check = check_for_typosquatting(package)
    payload_passed, payload_meta = scan_payload(package, data)
    sandbox_passed, sandbox_meta = execute_in_sandbox(info.get("description", ""))

    findings = {
        "Typosquatting": typo_check,
        "Identity": check_author_reputation(data),
        "Reputation": check_reputation(package, data),
        "Resurrection": check_resurrection(data),
        "Payload": (payload_passed, payload_meta),
        "Sandbox": (sandbox_passed, sandbox_meta),
    }

    score = calculate_spectr_score(findings)
    cache.save_audit(package, info.get("version", "0.0.0"), score, findings)
    display_report(package, findings, score)

    return score >= 80, score


def display_report(package, results, score):
    color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    table = Table(
        title=f"Spectr Report: [bold]{package}[/bold] (Score: [{color}]{score}[/{color}])"
    )
    table.add_column("Heuristic", style="cyan")
    table.add_column("Status")
    table.add_column("Evidence", style="dim")
    for name, val in results.items():
        # Typosquatting is an 'inverse' check: val[0]==True means it IS a squat (a fail)
        if name == "Typosquatting":
            is_squat, target = val
            status = "[red]FAIL[/red]" if is_squat else "[green]PASS[/green]"
            evidence = f"Possible squat of: {target}" if is_squat else "None detected"
        else:
            status = "[green]PASS[/green]" if val[0] else "[red]FAIL[/red]"
            evidence = str(val[1])

        table.add_row(name, status, evidence)
    console.print(table)


# --- COMMANDS ---


def audit_project(args):
    console.print(
        Panel(
            "🔍 [bold]Spectr Project Audit[/bold]\nTarget: pyproject.toml", expand=False
        )
    )
    try:
        with open("pyproject.toml", "rb") as f:
            project_data = tomllib.load(f)
            dependencies = project_data.get("project", {}).get("dependencies", [])
            for dep_str in dependencies:
                name = (
                    dep_str.split(">")[0]
                    .split("=")[0]
                    .split("<")[0]
                    .split("[")[0]
                    .strip()
                )
                passed, score = check_package(name, args)
                if not passed:
                    console.print(
                        f"\n⚠️  [bold yellow]Risk Detected:[/bold yellow] {name} scored {score}/100"
                    )
                    choice = input(f"   Trust and whitelist {name}? (y/N): ").lower()
                    if choice == "y":
                        add_to_whitelist(name)
                        sign_whitelist()
                    else:
                        console.print(
                            "🛑 [red]Audit failed. Installation blocked.[/red]"
                        )
                        sys.exit(1)
            console.print(
                "\n✨ [bold green]Audit Complete. Environment is secure.[/bold green]"
            )
    except FileNotFoundError:
        console.print("❌ [red]pyproject.toml not found.[/red]")
        sys.exit(1)


def install_shell_hook():
    shell = os.environ.get("SHELL", "")
    rc = os.path.expanduser("~/.zshrc" if "zsh" in shell else "~/.bashrc")
    hook = f'\n# Spectr v{VERSION}\nuv() {{ if [[ "$1" == "add" ]]; then spectr check "$2" || return 1; fi; command uv "$@"; }}\n'
    with open(rc, "a") as f:
        f.write(hook)
    console.print(f"✅ Hook installed in {rc}.")


def main():
    """v0.22.0: Official Entry Point"""
    ensure_whitelist_exists()
    if not verify_whitelist_integrity():
        console.print("🚨 [bold red]WHITELIST TAMPERED![/bold red] Signature mismatch.")
        sys.exit(1)

    parser = argparse.ArgumentParser(prog="spectr", description=f"🛡️ Spectr v{VERSION}")
    parser.add_argument("--version", action="version", version=f"Spectr v{VERSION}")
    subparsers = parser.add_subparsers(dest="command")

    check_p = subparsers.add_parser("check")
    check_p.add_argument("package")
    audit_p = subparsers.add_parser("audit")

    for p in [check_p, audit_p]:
        p.add_argument("--recursive", "-r", action="store_true")
        p.add_argument("--max-depth", type=int, default=2)

    parser.add_argument("--install-hook", action="store_true")
    parser.add_argument("--disable", action="store_true")

    args = parser.parse_args()

    if args.install_hook:
        install_shell_hook()
    elif args.disable:
        disable_hooks()
    elif args.command == "check":
        check_package(args.package, args)
    elif args.command == "audit":
        audit_project(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
