#!/usr/bin/env python3
"""
Automated Open Source Intelligence (OSINT) Tool for Digital Footprint
Aggregation and Social Media Reconnaissance.

Cross-platform CLI utility (Windows & Linux).
Strictly passive reconnaissance using publicly accessible sources only.
"""

import argparse
import os
import platform
import sys
from colorama import Fore, Style, init

from modules.domain_recon import normalize_domain, run_domain_recon
from modules.database import get_recent_scans
from modules.report_gen import save_reports
from modules.username_recon import run_username_recon

# Enable ANSI colors on both Windows CMD/PowerShell and Linux terminals
init(autoreset=True)


def print_banner():
    os_info = f"{platform.system()} {platform.release()}"
    print(Fore.CYAN + Style.BRIGHT + "=" * 68)
    print(Fore.CYAN + Style.BRIGHT + "   AUTOMATED OSINT TOOL - DIGITAL FOOTPRINT & SOCIAL RECONNAISSANCE")
    print(Fore.CYAN + Style.BRIGHT + "=" * 68)
    print(Fore.WHITE + f"   Environment : Python {platform.python_version()} on {os_info}")
    print(Fore.YELLOW + "   Ethical Use : Passive public OSINT only. Authorized & educational use.")
    print(Fore.CYAN + "=" * 68 + "\n")


def _print_platform_progress(res):
    status = res["status"]
    if status == "FOUND":
        print(
            Fore.GREEN
            + f"  [FOUND] {res['platform']:<15} -> {res['url']} ({res['response_time_ms']} ms)"
        )
        meta = res.get("metadata", {})
        if meta:
            summary_items = []
            for key in ("display_name", "location", "company", "website", "bio_snippet"):
                if meta.get(key):
                    val = str(meta[key]).replace("\n", " ")[:75]
                    summary_items.append(f"{key}={val}")
            if summary_items:
                print(Fore.CYAN + "          Metadata: " + " | ".join(summary_items))
    elif status == "ERROR":
        print(Fore.YELLOW + f"  [ERROR] {res['platform']:<15} -> {res.get('error', 'Failed')}")


def display_domain_results(d_data):
    print(Fore.CYAN + f"\n[*] Domain Reconnaissance Summary for: {d_data['target_domain']}")
    print(Fore.WHITE + f"    IP Address     : {d_data['ip_address']}")
    print(Fore.WHITE + f"    Scan Duration  : {d_data['execution_time_sec']}s")

    es = d_data["email_security"]
    print(
        Fore.WHITE
        + f"    Email Security : MX={es['has_mx']} | SPF={es['has_spf']} | DMARC={es['has_dmarc']}"
    )

    print(Fore.MAGENTA + "\n    [WHOIS Information]")
    for k, v in d_data["whois"].items():
        print(Fore.WHITE + f"      - {k}: {v}")

    print(Fore.MAGENTA + "\n    [DNS Records]")
    for rtype, recs in d_data["dns_records"].items():
        if recs:
            print(Fore.WHITE + f"      - {rtype}: {', '.join(recs[:3])}")

    print(Fore.MAGENTA + "\n    [HTTP Security Headers]")
    for k, v in d_data["http_headers"].items():
        color = Fore.RED if v == "Missing" else Fore.GREEN
        print(color + f"      - {k}: {v}")


def execute_scan(username=None, domain=None, auto_pivot=True, output_dir="reports"):
    username_data = None
    domain_data = None

    if username:
        clean_user = username.strip().lstrip("@")
        print(Fore.CYAN + f"[*] Starting Social Media Reconnaissance for: @{clean_user}")
        print(Fore.WHITE + "    Querying 18 public platforms concurrently...\n")
        username_data = run_username_recon(
            clean_user, max_workers=10, progress_callback=_print_platform_progress
        )
        print(
            Fore.CYAN
            + f"\n[+] Social Recon Complete: {username_data['accounts_found']}/"
            f"{username_data['platforms_checked']} accounts found in "
            f"{username_data['execution_time_sec']}s (Errors: {username_data['errors_count']})."
        )

        if not domain and auto_pivot and username_data.get("discovered_websites"):
            pivot_site = username_data["discovered_websites"][0]
            pivot_domain = normalize_domain(pivot_site)
            if pivot_domain and "." in pivot_domain:
                print(
                    Fore.YELLOW
                    + f"\n[*] Auto-Pivot Triggered: Discovered linked website '{pivot_domain}'."
                )
                domain = pivot_domain

    if domain:
        clean_dom = normalize_domain(domain)
        print(Fore.CYAN + f"\n[*] Starting Domain & Infrastructure Recon for: {clean_dom}")
        domain_data = run_domain_recon(clean_dom)
        display_domain_results(domain_data)

    if not username_data and not domain_data:
        print(Fore.RED + "[!] No valid target supplied.")
        return

    label_parts = []
    if username_data:
        label_parts.append(username_data["target_username"])
    if domain_data:
        label_parts.append(domain_data["target_domain"])
    target_label = "_".join(label_parts)

    saved = save_reports(
        target_label=target_label,
        username_data=username_data,
        domain_data=domain_data,
        output_dir=output_dir,
    )
    exp = saved["exposure_summary"]
    lvl_color = {
        "HIGH": Fore.RED,
        "MODERATE": Fore.YELLOW,
        "LOW": Fore.GREEN,
    }.get(exp["exposure_level"], Fore.CYAN)

    print(Fore.CYAN + "\n" + "=" * 68)
    print(
        lvl_color
        + Style.BRIGHT
        + f"[+] DIGITAL EXPOSURE LEVEL: {exp['exposure_level']} ({exp['exposure_score']}/100)"
    )
    for note in exp["observations"]:
        print(Fore.WHITE + f"    - {note}")
    print(Fore.GREEN + f"\n[+] Saved to SQLite Database (Scan ID #{saved.get('scan_id')}) & Report Files:")
    print(Fore.WHITE + f"    JSON : {saved['json']}")
    print(Fore.WHITE + f"    TXT  : {saved['txt']}")
    print(Fore.WHITE + f"    HTML : {saved['html']}")
    print(Fore.CYAN + "=" * 68 + "\n")


def list_reports(output_dir="reports"):
    scans = get_recent_scans(limit=10)
    if scans:
        print(Fore.CYAN + "\n[*] Recent Scans in SQLite Database (osint_recon.db):")
        for s in scans:
            print(Fore.WHITE + f"    [#{s['id']}] {s['created_utc']} | Target: {s['target_label']} | Found: {s['accounts_found']} | Exposure: {s['exposure_level']} ({s['exposure_score']}/100)")

    if not os.path.isdir(output_dir):
        print(Fore.YELLOW + "\n[!] No reports directory found yet. Run a scan first.\n")
        return
    files = sorted(os.listdir(output_dir), reverse=True)
    if not files:
        print(Fore.YELLOW + "\n[!] Reports directory is empty.\n")
        return
    print(Fore.CYAN + f"\n[*] Saved Reports in '{output_dir}/':")
    for fname in files[:15]:
        print(Fore.WHITE + f"    - {os.path.join(output_dir, fname)}")
    print()


def interactive_menu(output_dir="reports"):
    while True:
        print(Fore.CYAN + "Select an OSINT Module:")
        print(Fore.WHITE + "  [1] Social Media Username Reconnaissance")
        print(Fore.WHITE + "  [2] Domain / Website & Email Footprint Lookup")
        print(Fore.WHITE + "  [3] Full Digital Footprint Aggregation (Username + Domain)")
        print(Fore.WHITE + "  [4] List Saved Reports")
        print(Fore.WHITE + "  [5] Exit\n")

        choice = input(Fore.YELLOW + "Enter choice [1-5]: ").strip()

        if choice == "1":
            u = input("Enter target username (without @): ").strip()
            if u:
                execute_scan(username=u, auto_pivot=True, output_dir=output_dir)
        elif choice == "2":
            d = input("Enter target domain or email (e.g., example.com): ").strip()
            if d:
                execute_scan(domain=d, output_dir=output_dir)
        elif choice == "3":
            u = input("Enter target username: ").strip()
            d = input("Enter target domain (optional, press Enter to auto-pivot): ").strip()
            execute_scan(
                username=u or None,
                domain=d or None,
                auto_pivot=True,
                output_dir=output_dir,
            )
        elif choice == "4":
            list_reports(output_dir)
        elif choice == "5":
            print(Fore.GREEN + "Exiting OSINT Tool. Stay ethical!")
            break
        else:
            print(Fore.RED + "[!] Invalid option. Please choose 1-5.\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated OSINT Tool for Digital Footprint Aggregation & Social Media Reconnaissance"
    )
    parser.add_argument("-u", "--username", help="Target username for social media enumeration")
    parser.add_argument("-d", "--domain", help="Target domain, URL, or email for WHOIS/DNS lookup")
    parser.add_argument(
        "--no-pivot",
        action="store_true",
        help="Disable automatic domain recon on discovered profile websites",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="reports",
        help="Output directory for generated reports (default: reports)",
    )
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    if args.username or args.domain:
        execute_scan(
            username=args.username,
            domain=args.domain,
            auto_pivot=not args.no_pivot,
            output_dir=args.output,
        )
    else:
        try:
            interactive_menu(output_dir=args.output)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Scan interrupted by user.")
            sys.exit(0)


if __name__ == "__main__":
    main()
