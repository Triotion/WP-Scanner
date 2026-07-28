#!/usr/bin/env python3
"""WP-Scanner main entry point: CLI, WPScanner, MassScanner."""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from datetime import datetime
from threading import Lock
from typing import Any
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from modules.exploiter import Exploiter
from modules.fingerprinter import WPFingerprinter
from modules.reporter import Reporter
from modules.updater import Updater
from modules.utils import (
    Logger,
    banner,
    create_directory,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from modules.vuln_scanner import VulnerabilityScanner

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
init()


class WPScanner:
    """Single-target WordPress scanner."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.target: str = args.target
        self.output_dir: str = args.output or ""
        self.threads: int = args.threads
        self.timeout: int = args.timeout
        self.user_agent: str = args.user_agent
        self.proxy: str | None = args.proxy
        self.exploit: bool = args.exploit
        self.verbose: bool = args.verbose
        self.auto_update: bool = args.auto_update
        self.report_format: str = args.report_format
        self.scan_lock = Lock()

        # Normalise target URL
        if self.target:
            if not self.target.startswith(("http://", "https://")):
                self.target = "http://" + self.target
            if self.target.endswith("/"):
                self.target = self.target[:-1]

        # Output directory
        if self.output_dir:
            create_directory(self.output_dir)
        else:
            domain = urlparse(self.target).netloc
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = f"results_{domain}_{timestamp}"
            create_directory(self.output_dir)

        self.logger = Logger(os.path.join(self.output_dir, "scan_results.log"))

        # HTTP session
        self.session = requests.Session()
        self.session.keep_alive = True
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}

        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        # Sub-modules
        self.fingerprinter = WPFingerprinter(
            self.session, self.target, self.headers, self.timeout, self.output_dir, self.threads
        )
        self.vuln_scanner = VulnerabilityScanner(
            self.session, self.target, self.headers, self.timeout, self.threads, self.output_dir
        )
        self.exploiter = Exploiter(self.session, self.target, self.headers, self.timeout, self.output_dir)
        self.reporter = Reporter(self.output_dir, self.target)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main scanning method."""
        banner()
        print_info(f"Starting scan against {self.target}")
        self.logger.log(f"Scan started against {self.target}")

        exploitation_results: list[dict[str, Any]] = []

        try:
            wp_info = self._run_fingerprinting()
            if not wp_info.get("is_wordpress"):
                return

            vulnerabilities = self._run_vulnerability_scan(wp_info)

            if vulnerabilities and self.exploit:
                exploitation_results = self._run_exploitation(vulnerabilities)

            self._generate_report(wp_info, vulnerabilities, exploitation_results)

        except KeyboardInterrupt:
            print_warning("Scan interrupted by user")
            self.logger.log("Scan interrupted by user")
        except Exception as exc:
            print_error(f"An error occurred: {exc}")
            self.logger.log(f"Error: {exc}")

        print_info(f"Scan completed. Results saved to {self.output_dir}")
        self.logger.log(f"Scan completed. Results saved to {self.output_dir}")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_fingerprinting(self) -> dict[str, Any]:
        wp_info = self.fingerprinter.fingerprint()
        if wp_info.get("is_wordpress"):
            print_success("WordPress information gathered successfully")
            with open(os.path.join(self.output_dir, "wp_info.json"), "w", encoding="utf-8") as f:
                json.dump(wp_info, f, indent=4)
        else:
            self.logger.log(f"Target {self.target} is not running WordPress")
        return wp_info

    def _run_vulnerability_scan(self, wp_info: dict[str, Any]) -> dict[str, Any]:
        print_info("Scanning for vulnerabilities...")
        vulnerabilities = self.vuln_scanner.scan(wp_info)
        if vulnerabilities:
            with open(os.path.join(self.output_dir, "vulnerabilities.json"), "w", encoding="utf-8") as f:
                json.dump(vulnerabilities, f, indent=4)
        return vulnerabilities

    def _run_exploitation(self, vulnerabilities: dict[str, Any]) -> list[dict[str, Any]]:
        vuln_list: list[dict[str, Any]] = []

        if vulnerabilities.get("core"):
            vuln_list.extend(vulnerabilities["core"])

        if vulnerabilities.get("plugins"):
            for plugin, data in vulnerabilities["plugins"].items():
                for vuln in data.get("vulns", []):
                    vuln_copy = vuln.copy()
                    vuln_copy["plugin"] = plugin
                    vuln_list.append(vuln_copy)

        if vulnerabilities.get("themes"):
            for theme, data in vulnerabilities["themes"].items():
                for vuln in data.get("vulns", []):
                    vuln_copy = vuln.copy()
                    vuln_copy["theme"] = theme
                    vuln_list.append(vuln_copy)

        if not vuln_list:
            return []

        print_info("Attempting to exploit vulnerabilities...")
        exploitation_results = self.exploiter.exploit(vuln_list)

        with open(
            os.path.join(self.output_dir, "exploitation_results.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(exploitation_results, f, indent=4)

        return exploitation_results

    def _generate_report(
        self,
        wp_info: dict[str, Any],
        vulnerabilities: dict[str, Any],
        exploitation_results: list[dict[str, Any]],
    ) -> None:
        if self.report_format == "html":
            report_path = self.reporter.generate_html_report(wp_info, vulnerabilities, exploitation_results)
            print_success(f"HTML report generated: {report_path}")
        elif self.report_format == "md":
            report_path = self.reporter.generate_markdown_report(
                wp_info, vulnerabilities, exploitation_results
            )
            print_success(f"Markdown report generated: {report_path}")
        else:
            self._print_console_summary(wp_info, vulnerabilities)

    def _print_console_summary(
        self, wp_info: dict[str, Any], vulnerabilities: dict[str, Any]
    ) -> None:
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}SCAN SUMMARY FOR {self.target}{Style.RESET_ALL}")
        print("=" * 80)

        if wp_info:
            print(f"\n{Fore.BLUE}WordPress Information:{Style.RESET_ALL}")
            print(f"  - Version: {Fore.YELLOW}{wp_info.get('version', 'Unknown')}{Style.RESET_ALL}")
            if wp_info.get("version_sources"):
                print(f"  - Version Sources: {', '.join(wp_info.get('version_sources', []))}")

            if wp_info.get("themes"):
                themes_str = ", ".join(
                    f"{t.get('name', 'Unknown')} (v{t.get('version', 'Unknown')})"
                    for t in wp_info.get("themes", [])
                )
                print(f"  - Themes: {Fore.MAGENTA}{themes_str}{Style.RESET_ALL}")

            if wp_info.get("plugins"):
                plugins_str = ", ".join(
                    f"{p.get('name', 'Unknown')} (v{p.get('version', 'Unknown')})"
                    for p in wp_info.get("plugins", {}).values()
                )
                print(f"  - Plugins: {Fore.CYAN}{plugins_str}{Style.RESET_ALL}")

            user_count = len(wp_info.get("users", []))
            if user_count > 0:
                user_info = [
                    f"{u.get('name', u.get('slug', 'Unknown'))} (ID: {u.get('id')})"
                    for u in wp_info.get("users", [])[:5]
                ]
                print(f"  - Users: {user_count} found - {', '.join(user_info)}")

            print(
                f"  - XML-RPC Enabled: {Fore.GREEN if wp_info.get('xmlrpc_enabled') else Fore.RED}"
                f"{wp_info.get('xmlrpc_enabled', False)}{Style.RESET_ALL}"
            )
            print(
                f"  - REST API Enabled: {Fore.GREEN if wp_info.get('rest_api_enabled') else Fore.RED}"
                f"{wp_info.get('rest_api_enabled', False)}{Style.RESET_ALL}"
            )

        if vulnerabilities:
            print(f"\n{Fore.RED}Vulnerabilities Found:{Style.RESET_ALL}")
            if vulnerabilities.get("core"):
                print(f"  {Fore.YELLOW}Core:{Style.RESET_ALL}")
                for vuln in vulnerabilities["core"]:
                    print(f"    - {vuln.get('title')} ({vuln.get('severity')})")
            if vulnerabilities.get("plugins"):
                print(f"  {Fore.YELLOW}Plugins:{Style.RESET_ALL}")
                for plugin, data in vulnerabilities["plugins"].items():
                    for vuln in data.get("vulns", []):
                        print(f"    - {plugin}: {vuln.get('title')} ({vuln.get('severity')})")
            if vulnerabilities.get("themes"):
                print(f"  {Fore.YELLOW}Themes:{Style.RESET_ALL}")
                for theme, data in vulnerabilities["themes"].items():
                    for vuln in data.get("vulns", []):
                        print(f"    - {theme}: {vuln.get('title')} ({vuln.get('severity')})")

        print("\n" + "=" * 80)


class MassScanner:
    """Multi-target scanner using thread pool."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.targets_file: str = args.targets_file
        self.mass_output_dir: str = args.mass_output_dir or "mass_scan_results"
        self.threads: int = args.threads
        self.targets: list[str] = []

    def run(self) -> None:
        try:
            if not os.path.isfile(self.targets_file):
                print_error(f"File not found: {self.targets_file}")
                sys.exit(1)

            os.makedirs(self.mass_output_dir, exist_ok=True)

            with open(self.targets_file, "r", encoding="utf-8") as f:
                self.targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

            print_info(f"Loaded {len(self.targets)} targets from {self.targets_file}")

            summary_file = os.path.join(
                self.mass_output_dir,
                f"mass_scan_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            )
            summary_lock = Lock()

            with open(summary_file, "w", encoding="utf-8") as f:
                f.write("WP-Scanner Mass Scan Summary\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Targets: {len(self.targets)}\n")
                f.write(f"Threads: {self.threads}\n\n")
                f.write("=" * 80 + "\n\n")

            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [
                    executor.submit(self._scan_target, idx, target, summary_file, summary_lock)
                    for idx, target in enumerate(self.targets)
                ]
                results = [f.result() for f in futures]

            successful = sum(1 for _, success, _ in results if success)
            failed = len(self.targets) - successful

            print_success("\nMass scan completed!")
            print_info(f"Successful: {successful}/{len(self.targets)}")
            print_info(f"Failed: {failed}/{len(self.targets)}")
            print_success(f"Summary saved to {summary_file}")

        except Exception as exc:
            print_error(f"An error occurred during mass scan: {exc}")
            sys.exit(1)

    def _scan_target(
        self, idx: int, target: str, summary_file: str, summary_lock: Lock
    ) -> tuple[str, bool, None]:
        print_info(f"[{idx + 1}/{len(self.targets)}] Scanning target: {target}")

        # Create a deep copy of args to avoid thread-safety issues
        thread_args = copy.deepcopy(self.args)
        thread_args.target = target

        if self.args.output:
            target_output_dir = os.path.join(self.args.output, urlparse(target).netloc)
        else:
            target_output_dir = os.path.join(self.mass_output_dir, urlparse(target).netloc)
        thread_args.output = target_output_dir
        create_directory(target_output_dir)

        scanner = WPScanner(thread_args)
        scanner.run()

        # Thread-safe summary update
        with summary_lock:
            with open(summary_file, "a", encoding="utf-8") as f:
                f.write(f"Target: {target}\n")
                f.write("Status: Completed\n")
                f.write(f"Output Directory: {scanner.output_dir}\n")

                vuln_file = os.path.join(scanner.output_dir, "vulnerabilities.json")
                if os.path.exists(vuln_file):
                    try:
                        with open(vuln_file, "r", encoding="utf-8") as vf:
                            vulns = json.load(vf)
                            vuln_count = (
                                len(vulns.get("core", []))
                                + len(vulns.get("plugins", {}))
                                + len(vulns.get("themes", {}))
                            )
                            f.write(f"Vulnerabilities Found: {vuln_count}\n")
                    except Exception as exc:
                        f.write(f"Error reading vulnerabilities: {exc}\n")
                else:
                    f.write("Vulnerabilities Found: 0\n")

                f.write("\n" + "-" * 80 + "\n\n")

        return (target, True, None)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WordPress Vulnerability Scanner and Exploitation Tool"
    )
    parser.add_argument("-t", "--target", help="Target WordPress site URL")
    parser.add_argument("-l", "--targets-file", help="File containing list of target URLs (one per line)")
    parser.add_argument("-o", "--output", help="Output directory for scan results")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        help="Custom User-Agent string",
    )
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--exploit", action="store_true", help="Attempt to exploit found vulnerabilities")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--mass-output-dir", help="Base directory for mass scan results")
    parser.add_argument("--update", action="store_true", help="Update the tool and vulnerability databases")
    parser.add_argument("--auto-update", action="store_true", help="Automatically update before scanning")
    parser.add_argument(
        "--report-format",
        default="console",
        choices=["console", "html", "md"],
        help="Output report format (default: console)",
    )

    args = parser.parse_args()

    if not args.target and not args.targets_file:
        parser.error("Either --target or --targets-file must be specified")
    if args.target and args.targets_file:
        parser.error("--target and --targets-file cannot be used together")

    if args.update:
        updater = Updater()
        updater.update_all()
        return

    try:
        if args.target:
            scanner = WPScanner(args)
            scanner.run()
        elif args.targets_file:
            mass_scanner = MassScanner(args)
            mass_scanner.run()
    except KeyboardInterrupt:
        print_warning("Scan interrupted by user")
        sys.exit(0)
    except Exception as exc:
        print_error(f"An unexpected error occurred: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
