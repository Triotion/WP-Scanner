#!/usr/bin/env python3


import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from threading import Lock, Semaphore

import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning


from modules.fingerprinter import WPFingerprinter
from modules.vuln_scanner import VulnerabilityScanner
from modules.exploiter import Exploiter

from modules.utils import banner, Logger, create_directory, print_info, print_success, print_error, print_warning
from modules.reporter import Reporter


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


init()

class WPScanner:
    def __init__(self, args):
        self.target = args.target
        self.output_dir = args.output
        self.threads = args.threads
        self.timeout = args.timeout
        self.user_agent = args.user_agent
        self.proxy = args.proxy
        self.exploit = args.exploit
        self.verbose = args.verbose
        self.auto_update = args.auto_update
        self.report_format = args.report_format
        self.scan_lock = Lock()  
        
        

        
        

        
        
        if self.target:
            
            if not self.target.startswith(('http://', 'https://')):
                self.target = 'http://' + self.target
            
            
            if self.target.endswith('/'):
                self.target = self.target[:-1]
                
            
            if self.output_dir:
                create_directory(self.output_dir)
                self.logger = Logger(os.path.join(self.output_dir, 'scan_results.log'))
            else:
                domain = urlparse(self.target).netloc
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.output_dir = f"results_{domain}_{timestamp}"
                create_directory(self.output_dir)
                self.logger = Logger(os.path.join(self.output_dir, 'scan_results.log'))
            
            
            self.session = requests.Session()
            self.session.keep_alive = True  
            if self.proxy:
                self.session.proxies = {
                    'http': self.proxy,
                    'https': self.proxy
                }
            
            
            self.headers = {
                'User-Agent': self.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            
            self.fingerprinter = WPFingerprinter(self.session, self.target, self.headers, self.timeout, self.output_dir, self.threads)
            self.vuln_scanner = VulnerabilityScanner(self.session, self.target, self.headers, self.timeout, self.threads, self.output_dir)
            self.exploiter = Exploiter(self.session, self.target, self.headers, self.timeout, self.output_dir)
            self.reporter = Reporter(self.output_dir, self.target)
    

        
    def run(self):
        """Main scanning method"""
        banner()
        print_info(f"Starting scan against {self.target}")
        self.logger.log(f"Scan started against {self.target}")

        try:
            wp_info = self._run_fingerprinting()
            if not wp_info.get("is_wordpress"):
                return

            vulnerabilities = self._run_vulnerability_scan(wp_info)
            if vulnerabilities and self.exploit:
                self._run_exploitation(vulnerabilities)

            self._generate_report(wp_info, vulnerabilities, {})

        except KeyboardInterrupt:
            print_warning("Scan interrupted by user")
            self.logger.log("Scan interrupted by user")
        except Exception as e:
            print_error(f"An error occurred: {str(e)}")
            self.logger.log(f"Error: {str(e)}")
        except:
            print_error("An unexpected error occurred.")
            self.logger.log("An unexpected error occurred.")

        print_info(f"Scan completed. Results saved to {self.output_dir}")
        self.logger.log(f"Scan completed. Results saved to {self.output_dir}")

    def _run_fingerprinting(self):
        """Run the fingerprinting process."""
        wp_info = self.fingerprinter.fingerprint()
        if wp_info.get("is_wordpress"):
            print_success("WordPress information gathered successfully")
            with open(os.path.join(self.output_dir, 'wp_info.json'), 'w') as f:
                json.dump(wp_info, f, indent=4)
        else:
            self.logger.log(f"Target {self.target} is not running WordPress")
        return wp_info

    def _run_vulnerability_scan(self, wp_info):
        """Run the vulnerability scanning process."""
        print_info("Scanning for vulnerabilities...")
        vulnerabilities = self.vuln_scanner.scan(wp_info)
        if vulnerabilities:
            with open(os.path.join(self.output_dir, 'vulnerabilities.json'), 'w') as f:
                json.dump(vulnerabilities, f, indent=4)
        return vulnerabilities

    def _run_exploitation(self, vulnerabilities):
        """Run the exploitation process."""
        vuln_list = []
        if vulnerabilities.get("core"):
            vuln_list.extend(vulnerabilities["core"])
        if vulnerabilities.get("plugins"):
            for plugin, data in vulnerabilities["plugins"].items():
                if "vulns" in data:
                    for vuln in data["vulns"]:
                        vuln_copy = vuln.copy()
                        vuln_copy["plugin"] = plugin
                        vuln_list.append(vuln_copy)
        if vulnerabilities.get("themes"):
             for theme, data in vulnerabilities["themes"].items():
                if "vulns" in data:
                    for vuln in data["vulns"]:
                        vuln_copy = vuln.copy()
                        vuln_copy["theme"] = theme
                        vuln_list.append(vuln_copy)

        if not vuln_list:
            return {}

        print_info("Attempting to exploit vulnerabilities...")
        exploitation_results = self.exploiter.exploit(vuln_list)
        with open(os.path.join(self.output_dir, 'exploitation_results.json'), 'w') as f:
            json.dump(exploitation_results, f, indent=4)
        return exploitation_results

    def _generate_report(self, wp_info, vulnerabilities, exploitation_results):
        """Generate a summary report of the scan."""
        if self.report_format == "html":
            report_path = self.reporter.generate_html_report(wp_info, vulnerabilities, exploitation_results)
            print_success(f"HTML report generated: {report_path}")
        elif self.report_format == "md":
            report_path = self.reporter.generate_markdown_report(wp_info, vulnerabilities, exploitation_results)
            print_success(f"Markdown report generated: {report_path}")
        else: # Default to console output and JSON
            print("\n" + "="*80)
            print(f"{Fore.CYAN}SCAN SUMMARY FOR {self.target}{Style.RESET_ALL}")
            print("="*80)

            if wp_info:
                print(f"\n{Fore.BLUE}WordPress Information:{Style.RESET_ALL}")
                print(f"  • Version: {Fore.YELLOW}{wp_info.get('version', 'Unknown')}{Style.RESET_ALL}")
                if wp_info.get('version_sources'):
                    print(f"  • Version Sources: {', '.join(wp_info.get('version_sources', []))}")
                
                if wp_info.get('themes'):
                    themes_str = ", ".join([f"{t.get('name', 'Unknown')} (v{t.get('version', 'Unknown')})" for t in wp_info.get('themes', [])])
                    print(f"  • Themes: {Fore.MAGENTA}{themes_str}{Style.RESET_ALL}")

                if wp_info.get('plugins'):
                    plugins_str = ", ".join([f"{p.get('name', 'Unknown')} (v{p.get('version', 'Unknown')})" for p in wp_info.get('plugins', {}).values()])
                    print(f"  • Plugins: {Fore.CYAN}{plugins_str}{Style.RESET_ALL}")

                user_count = len(wp_info.get('users', []))
                if user_count > 0:
                    user_info = [f"{user.get('name', user.get('slug', 'Unknown'))} (ID: {user.get('id')})" for user in wp_info.get('users', [])[:5]]
                    print(f"  • Users: {user_count} found - {', '.join(user_info)}")

                print(f"  • XML-RPC Enabled: {Fore.GREEN if wp_info.get('xmlrpc_enabled') else Fore.RED}{wp_info.get('xmlrpc_enabled', False)}{Style.RESET_ALL}")
                print(f"  • REST API Enabled: {Fore.GREEN if wp_info.get('rest_api_enabled') else Fore.RED}{wp_info.get('rest_api_enabled', False)}{Style.RESET_ALL}")

            if vulnerabilities:
                print(f"\n{Fore.RED}Vulnerabilities Found:{Style.RESET_ALL}")
                # Core vulnerabilities
                if vulnerabilities.get("core"):
                    print(f"  {Fore.YELLOW}Core:{Style.RESET_ALL}")
                    for vuln in vulnerabilities["core"]:
                        print(f"    - {vuln.get('title')} ({vuln.get('severity')})")
                # Plugin vulnerabilities
                if vulnerabilities.get("plugins"):
                    print(f"  {Fore.YELLOW}Plugins:{Style.RESET_ALL}")
                    for plugin, data in vulnerabilities["plugins"].items():
                        if "vulns" in data:
                            for vuln in data["vulns"]:
                                print(f"    - {plugin}: {vuln.get('title')} ({vuln.get('severity')})")
                # Theme vulnerabilities
                if vulnerabilities.get("themes"):
                    print(f"  {Fore.YELLOW}Themes:{Style.RESET_ALL}")
                    for theme, data in vulnerabilities["themes"].items():
                        if "vulns" in data:
                            for vuln in data["vulns"]:
                                print(f"    - {theme}: {vuln.get('title')} ({vuln.get('severity')})")
            
            print("\n" + "="*80)
class MassScanner:
    def __init__(self, args):
        self.args = args
        self.targets_file = args.targets_file
        self.mass_output_dir = args.mass_output_dir or "mass_scan_results"
        self.threads = args.threads
        self.targets = []

    def run(self):
        """Run the mass scanning process."""
        try:
            if not os.path.isfile(self.targets_file):
                print_error(f"File not found: {self.targets_file}")
                sys.exit(1)

            if not os.path.exists(self.mass_output_dir):
                os.makedirs(self.mass_output_dir)

            with open(self.targets_file, 'r') as f:
                self.targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print_info(f"Loaded {len(self.targets)} targets from {self.targets_file}")

            summary_file = os.path.join(self.mass_output_dir, f"mass_scan_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            summary_lock = Lock()

            with open(summary_file, 'w') as f:
                f.write(f"WP-Scanner Mass Scan Summary\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Targets: {len(self.targets)}\n")
                f.write(f"Threads: {self.threads}\n\n")
                f.write("=" * 80 + "\n\n")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                scan_results = list(executor.map(self.scan_target, enumerate(self.targets), [summary_file]*len(self.targets), [summary_lock]*len(self.targets)))

            successful = sum(1 for _, success, _ in scan_results if success)
            failed = len(self.targets) - successful

            print_success(f"\nMass scan completed!")
            print_info(f"Successful: {successful}/{len(self.targets)}")
            print_info(f"Failed: {failed}/{len(self.targets)}")
            print_success(f"Summary saved to {summary_file}")

        except Exception as e:
            print_error(f"An error occurred during mass scan: {str(e)}")
            sys.exit(1)

    def scan_target(self, target_info, summary_file, summary_lock):
        """Scan a single target."""
        idx, target = target_info
        print_info(f"[{idx+1}/{len(self.targets)}] Scanning target: {target}")
        
        args = self.args
        args.target = target
        
        if args.output:
            target_output_dir = os.path.join(args.output, urlparse(target).netloc)
        else:
            target_output_dir = os.path.join(self.mass_output_dir, urlparse(target).netloc)
        args.output = target_output_dir
        create_directory(target_output_dir)
        
        scanner = WPScanner(args)
        scanner.run()
        
        # Update summary (thread-safe)
        with summary_lock:
            with open(summary_file, 'a') as f:
                f.write(f"Target: {target}\n")
                f.write(f"Status: Completed\n")
                f.write(f"Output Directory: {scanner.output_dir}\n")
                
                vuln_file = os.path.join(scanner.output_dir, 'vulnerabilities.json')
                if os.path.exists(vuln_file):
                    try:
                        with open(vuln_file, 'r') as vf:
                            vulns = json.load(vf)
                            vuln_count = len(vulns.get("core", [])) + len(vulns.get("plugins", {})) + len(vulns.get("themes", {}))
                            f.write(f"Vulnerabilities Found: {vuln_count}\n")
                    except Exception as e:
                        f.write(f"Error reading vulnerabilities: {str(e)}\n")
                else:
                    f.write("Vulnerabilities Found: 0\n")
                
                f.write("\n" + "-" * 80 + "\n\n")
        
        return (target, True, None)

def main():
    try:
        parser = argparse.ArgumentParser(description='WordPress Vulnerability Scanner and Exploitation Tool')
        parser.add_argument('-t', '--target', help='Target WordPress site URL')
        parser.add_argument('-l', '--targets-file', help='File containing list of target URLs (one per line)')
        parser.add_argument('-o', '--output', help='Output directory for scan results')
        parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
        parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
        parser.add_argument('--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36', help='Custom User-Agent string')
        parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
        parser.add_argument('--exploit', action='store_true', help='Attempt to exploit found vulnerabilities')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        parser.add_argument('--mass-output-dir', help='Base directory for mass scan results (default: mass_scan_results)')
        parser.add_argument('--update', action='store_true', help='Update the tool and vulnerability databases')
        parser.add_argument('--auto-update', action='store_true', help='Automatically update the tool before scanning')
        parser.add_argument('--report-format', default='console', choices=['console', 'html', 'md'], help='Output report format (default: console)')
        
        args = parser.parse_args()
        

        if not args.target and not args.targets_file:
            parser.error("Either --target or --targets-file must be specified")
        
        if args.target and args.targets_file:
            parser.error("--target and --targets-file cannot be used together")
        
        if args.target:
            scanner = WPScanner(args)
            scanner.run()
        elif args.targets_file:
            mass_scanner = MassScanner(args)
            mass_scanner.run()
    except Exception as e:
        print_error(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 