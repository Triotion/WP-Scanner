#!/usr/bin/env python3
# WP-Scanner - Advanced WordPress Vulnerability Scanner and Exploitation Tool
# Author: AI Assistant

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Import modules
from modules.fingerprinter import WPFingerprinter
from modules.vuln_scanner import VulnerabilityScanner
from modules.exploiter import Exploiter
from modules.updater import Updater
from modules.utils import banner, Logger, create_directory, print_info, print_success, print_error, print_warning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama
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
        
        # Set up updater
        self.updater = Updater()
        
        # Handle auto-updates if enabled
        if self.auto_update:
            if self.updater.check_for_updates():
                print_info("Auto-update is enabled. Checking for updates...")
                self._update_components()
        
        # Continue with scanner setup if we have a target
        if self.target:
            # Ensure target URL has proper format
            if not self.target.startswith(('http://', 'https://')):
                self.target = 'http://' + self.target
            
            # Remove trailing slash
            if self.target.endswith('/'):
                self.target = self.target[:-1]
                
            # Create output directory
            if self.output_dir:
                create_directory(self.output_dir)
                self.logger = Logger(os.path.join(self.output_dir, 'scan_results.log'))
            else:
                domain = urlparse(self.target).netloc
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.output_dir = f"results_{domain}_{timestamp}"
                create_directory(self.output_dir)
                self.logger = Logger(os.path.join(self.output_dir, 'scan_results.log'))
            
            # Set up session
            self.session = requests.Session()
            if self.proxy:
                self.session.proxies = {
                    'http': self.proxy,
                    'https': self.proxy
                }
            
            # Set default headers
            self.headers = {
                'User-Agent': self.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Initialize components
            self.fingerprinter = WPFingerprinter(self.session, self.target, self.headers, self.timeout, self.output_dir)
            self.vuln_scanner = VulnerabilityScanner(self.session, self.target, self.headers, self.timeout, self.threads, self.output_dir)
            self.exploiter = Exploiter(self.session, self.target, self.headers, self.timeout, self.output_dir)
    
    def _update_components(self):
        """Update tool components"""
        success, update_results = self.updater.update_all()
        return success
    
    def handle_update_command(self):
        """Handle the update command"""
        banner()
        print_info("Starting update process...")
        success, update_results = self.updater.update_all()
        
        if success:
            print_success("Update completed successfully")
        else:
            print_warning("Update completed with some issues")
        
        # Print detailed results
        print("\n" + "="*80)
        print(f"{Fore.YELLOW}UPDATE RESULTS{Style.RESET_ALL}")
        print("="*80 + "\n")
        
        # Tool update results
        tool_result = update_results.get('tool', {})
        tool_success = tool_result.get('success', False)
        tool_message = tool_result.get('message', 'Unknown')
        
        print(f"Tool update: {Fore.GREEN if tool_success else Fore.RED}{tool_success}{Style.RESET_ALL}")
        print(f"Details: {tool_message}\n")
        
        # Database update results
        db_result = update_results.get('databases', {})
        db_success = db_result.get('success', False)
        updated_dbs = db_result.get('updated', [])
        
        print(f"Database updates: {Fore.GREEN if db_success else Fore.RED}{db_success}{Style.RESET_ALL}")
        
        if updated_dbs:
            print(f"Updated databases: {', '.join(updated_dbs)}")
        else:
            print("No databases were updated (either up-to-date or failed)")
        
        return success
        
    def run(self):
        """Main scanning method"""
        banner()
        print_info(f"Starting scan against {self.target}")
        self.logger.log(f"Scan started against {self.target}")
        
        try:
            # Check if the target is running WordPress
            if not self.fingerprinter.is_wordpress():
                print_error(f"The target {self.target} does not appear to be running WordPress")
                self.logger.log(f"Target {self.target} is not running WordPress")
                return
            
            print_success(f"WordPress confirmed on {self.target}")
            
            # Gather WordPress information
            print_info("Fingerprinting WordPress...")
            wp_info = self.fingerprinter.fingerprint()
            
            if wp_info:
                print_success("WordPress information gathered successfully")
                for key, value in wp_info.items():
                    if key == 'users':
                        print_info(f"{key}: {len(value)} users found")
                        continue
                    if isinstance(value, list):
                        print_info(f"{key}: {', '.join(str(v) for v in value)}")
                    else:
                        print_info(f"{key}: {value}")
                
                # Save fingerprinting results
                with open(os.path.join(self.output_dir, 'wp_info.json'), 'w') as f:
                    json.dump(wp_info, f, indent=4)
                
                # Scan for vulnerabilities
                print_info("Scanning for vulnerabilities...")
                vulnerabilities = self.vuln_scanner.scan(wp_info)
                
                if vulnerabilities:
                    # Count actual vulnerabilities
                    vuln_list = []
                    
                    # Process core vulnerabilities
                    if vulnerabilities.get("core"):
                        if isinstance(vulnerabilities["core"], list):
                            vuln_list.extend(vulnerabilities["core"])
                        elif isinstance(vulnerabilities["core"], dict) and vulnerabilities["core"]:
                            # Handle potential dictionary format
                            for version, vulns in vulnerabilities["core"].items():
                                if isinstance(vulns, list):
                                    vuln_list.extend(vulns)
                    
                    # Process plugin vulnerabilities
                    if vulnerabilities.get("plugins"):
                        for plugin, plugin_data in vulnerabilities["plugins"].items():
                            if isinstance(plugin_data, dict) and "vulns" in plugin_data:
                                for vuln in plugin_data["vulns"]:
                                    vuln_copy = vuln.copy()
                                    vuln_copy["plugin"] = plugin
                                    vuln_list.append(vuln_copy)
                            elif isinstance(plugin_data, list):
                                vuln_list.extend(plugin_data)
                    
                    # Process theme vulnerabilities
                    if vulnerabilities.get("themes") and isinstance(vulnerabilities["themes"], list):
                        vuln_list.extend(vulnerabilities["themes"])
                    
                    print_success(f"Found {len(vuln_list)} potential vulnerabilities")
                    
                    # Display vulnerability details in terminal
                    print("\n" + "="*80)
                    print(f"{Fore.YELLOW}VULNERABILITY SCAN DETAILS{Style.RESET_ALL}")
                    print("="*80)
                    
                    # Core vulnerabilities
                    if vulnerabilities.get("core") and isinstance(vulnerabilities["core"], list) and vulnerabilities["core"]:
                        print(f"\n{Fore.RED}WordPress Core Vulnerabilities{Style.RESET_ALL}")
                        for vuln in vulnerabilities["core"]:
                            print(f"  • {Fore.RED}{vuln.get('severity', 'Unknown')}{Style.RESET_ALL}: {vuln.get('title', 'Unknown')}")
                            print(f"    - {vuln.get('description', 'No description available')}")
                            print(f"    - CVE: {vuln.get('cve', 'N/A')}")
                            print(f"    - Affected: {vuln.get('affected_version', 'Unknown')}, Fixed in: {vuln.get('fixed_in', 'Unknown')}")
                            print(f"    - Exploitability: {vuln.get('exploitability', 'Unknown')}")
                            print(f"    - Exploit Available: {'Yes' if vuln.get('exploit_available', False) else 'No'}")
                            print()
                    
                    # Plugin vulnerabilities
                    if vulnerabilities.get("plugins"):
                        has_plugin_vulns = False
                        for plugin, plugin_data in vulnerabilities["plugins"].items():
                            if isinstance(plugin_data, dict) and "vulns" in plugin_data and plugin_data["vulns"]:
                                if not has_plugin_vulns:
                                    print(f"\n{Fore.RED}Plugin Vulnerabilities{Style.RESET_ALL}")
                                    has_plugin_vulns = True
                                
                                print(f"  Plugin: {Fore.CYAN}{plugin}{Style.RESET_ALL} (v{plugin_data.get('version', 'Unknown')})")
                                for vuln in plugin_data["vulns"]:
                                    print(f"  • {Fore.RED}{vuln.get('severity', 'Unknown')}{Style.RESET_ALL}: {vuln.get('title', 'Unknown')}")
                                    print(f"    - {vuln.get('description', 'No description available')}")
                                    print(f"    - CVE: {vuln.get('cve', 'N/A')}")
                                    print(f"    - Fixed in: {vuln.get('fixed_in', 'Unknown')}")
                                    print(f"    - Exploitability: {vuln.get('exploitability', 'Unknown')}")
                                    print(f"    - Exploit Available: {'Yes' if vuln.get('exploit_available', False) else 'No'}")
                                    print()
                    
                    # Theme vulnerabilities
                    if vulnerabilities.get("themes") and isinstance(vulnerabilities["themes"], list) and vulnerabilities["themes"]:
                        print(f"\n{Fore.RED}Theme Vulnerabilities{Style.RESET_ALL}")
                        for vuln in vulnerabilities["themes"]:
                            theme_name = vuln.get('theme', 'Unknown')
                            print(f"  Theme: {Fore.CYAN}{theme_name}{Style.RESET_ALL}")
                            print(f"  • {Fore.RED}{vuln.get('severity', 'Unknown')}{Style.RESET_ALL}: {vuln.get('title', 'Unknown')}")
                            print(f"    - {vuln.get('description', 'No description available')}")
                            print(f"    - CVE: {vuln.get('cve', 'N/A')}")
                            print(f"    - Affected: {vuln.get('affected_version', 'Unknown')}, Fixed in: {vuln.get('fixed_in', 'Unknown')}")
                            print(f"    - Exploitability: {vuln.get('exploitability', 'Unknown')}")
                            print(f"    - Exploit Available: {'Yes' if vuln.get('exploit_available', False) else 'No'}")
                            print()
                    
                    print("="*80)
                    
                    # Save vulnerability results
                    with open(os.path.join(self.output_dir, 'vulnerabilities.json'), 'w') as f:
                        json.dump(vulnerabilities, f, indent=4)
                    
                    # Attempt exploitation if enabled
                    if self.exploit and vuln_list:
                        print_info("Attempting to exploit vulnerabilities...")
                        exploitation_results = self.exploiter.exploit(vuln_list)
                        
                        # Save exploitation results
                        with open(os.path.join(self.output_dir, 'exploitation_results.json'), 'w') as f:
                            json.dump(exploitation_results, f, indent=4)
                            
                        # Display exploitation results in terminal
                        print("\n" + "="*80)
                        print(f"{Fore.YELLOW}EXPLOITATION RESULTS{Style.RESET_ALL}")
                        print("="*80)
                        
                        # Count successful and failed exploits
                        successful = [r for r in exploitation_results if r.get('status') == 'success']
                        failed = [r for r in exploitation_results if r.get('status') in ['failed', 'error']]
                        skipped = [r for r in exploitation_results if r.get('status') == 'skipped']
                        
                        # Summary
                        print(f"\nTotal attempts: {len(exploitation_results)}")
                        print(f"{Fore.GREEN}Successful: {len(successful)}{Style.RESET_ALL}")
                        print(f"{Fore.RED}Failed: {len(failed)}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Skipped: {len(skipped)}{Style.RESET_ALL}\n")
                        
                        # Show successful exploits
                        if successful:
                            print(f"{Fore.GREEN}Successful Exploits:{Style.RESET_ALL}")
                            for result in successful:
                                vuln_title = result.get('vulnerability', 'Unknown Vulnerability')
                                print(f"  • {Fore.GREEN}{vuln_title}{Style.RESET_ALL}")
                                
                                # Show details if available
                                if 'details' in result:
                                    print(f"    - {result['details']}")
                                
                                # Show data if available
                                if 'data' in result and result['data']:
                                    for key, value in result['data'].items():
                                        if isinstance(value, list) and len(value) > 0:
                                            print(f"    - {key}: {', '.join(str(v) for v in value[:5])}{' ...' if len(value) > 5 else ''}")
                                        elif isinstance(value, dict) and value:
                                            print(f"    - {key}: {json.dumps(value, indent=2)[:100]}...")
                                        else:
                                            print(f"    - {key}: {value}")
                                print()
                        
                        # Show failed exploits
                        if failed:
                            print(f"{Fore.RED}Failed Exploits:{Style.RESET_ALL}")
                            for result in failed:
                                vuln_title = result.get('vulnerability', 'Unknown Vulnerability')
                                reason = result.get('reason', 'Unknown reason')
                                print(f"  • {Fore.RED}{vuln_title}{Style.RESET_ALL}: {reason}")
                            print()
                        
                        print("="*80)
                        print(f"Detailed results saved to: {os.path.join(self.output_dir, 'exploitation_results.json')}")
                        print("="*80)
                else:
                    print_info("No vulnerabilities found")
            else:
                print_error("Failed to gather WordPress information")
                
        except KeyboardInterrupt:
            print_warning("Scan interrupted by user")
            self.logger.log("Scan interrupted by user")
        except Exception as e:
            print_error(f"An error occurred: {str(e)}")
            self.logger.log(f"Error: {str(e)}")
        
        print_info(f"Scan completed. Results saved to {self.output_dir}")
        self.logger.log(f"Scan completed. Results saved to {self.output_dir}")
        
        # Display scan summary
        print("\n" + "="*80)
        print(f"{Fore.CYAN}SCAN SUMMARY FOR {self.target}{Style.RESET_ALL}")
        print("="*80)
        
        if wp_info:
            print(f"\n{Fore.BLUE}WordPress Information:{Style.RESET_ALL}")
            print(f"  • Version: {Fore.YELLOW}{wp_info.get('version', 'Unknown')}{Style.RESET_ALL}")
            if wp_info.get('version_sources'):
                print(f"  • Version Sources: {', '.join(wp_info.get('version_sources', []))}")
            
            # Themes
            if wp_info.get('themes'):
                print(f"  • Themes: {Fore.MAGENTA}{', '.join(wp_info.get('themes', []))}{Style.RESET_ALL}")
            
            # Plugins
            if wp_info.get('plugins'):
                if isinstance(wp_info['plugins'], list):
                    print(f"  • Plugins: {Fore.CYAN}{', '.join(wp_info.get('plugins', []))}{Style.RESET_ALL}")
                elif isinstance(wp_info['plugins'], dict):
                    plugin_list = list(wp_info['plugins'].keys())
                    print(f"  • Plugins: {Fore.CYAN}{', '.join(plugin_list)}{Style.RESET_ALL}")
            
            # Users
            user_count = len(wp_info.get('users', []))
            if user_count > 0:
                user_info = []
                for user in wp_info.get('users', [])[:5]:  # Show max 5 users
                    if isinstance(user, dict):
                        if 'name' in user and 'id' in user:
                            user_info.append(f"{user.get('name')} (ID: {user.get('id')})")
                        elif 'username' in user:
                            user_info.append(user.get('username'))
                
                print(f"  • Users: {user_count} found" + (f" - {', '.join(user_info)}" if user_info else ""))
            
            # API info
            print(f"  • XML-RPC Enabled: {Fore.GREEN if not wp_info.get('xmlrpc_enabled') else Fore.RED}{wp_info.get('xmlrpc_enabled', False)}{Style.RESET_ALL}")
            print(f"  • REST API Enabled: {Fore.GREEN if not wp_info.get('rest_api_enabled') else Fore.RED}{wp_info.get('rest_api_enabled', False)}{Style.RESET_ALL}")
        
        print("\n" + "="*80)

def main():
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
    
    args = parser.parse_args()
    
    # Handle update command
    if args.update:
        updater = Updater()
        scanner = WPScanner(args)
        success = scanner.handle_update_command()
        sys.exit(0 if success else 1)
    
    # Validate arguments for scanning
    if not args.target and not args.targets_file:
        parser.error("Either --target or --targets-file must be specified")
    
    if args.target and args.targets_file:
        parser.error("--target and --targets-file cannot be used together")
    
    # Single target scan
    if args.target:
        scanner = WPScanner(args)
        scanner.run()
    # Mass scan from file
    elif args.targets_file:
        try:
            # Check if file exists
            if not os.path.isfile(args.targets_file):
                print_error(f"File not found: {args.targets_file}")
                sys.exit(1)
            
            # Set up mass scan output directory
            mass_output_dir = args.mass_output_dir or "mass_scan_results"
            if not os.path.exists(mass_output_dir):
                os.makedirs(mass_output_dir)
            
            # Read targets from file
            with open(args.targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            print_info(f"Loaded {len(targets)} targets from {args.targets_file}")
            
            # Create summary file
            summary_file = os.path.join(mass_output_dir, f"mass_scan_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(summary_file, 'w') as f:
                f.write(f"WP-Scanner Mass Scan Summary\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Targets: {len(targets)}\n\n")
                f.write("=" * 80 + "\n\n")
            
            # Process each target
            for i, target in enumerate(targets):
                print_info(f"\n[{i+1}/{len(targets)}] Scanning target: {target}")
                
                # Update args with current target
                args.target = target
                
                # Ensure the output directory for this target is set properly
                if args.output:
                    target_output_dir = os.path.join(args.output, urlparse(target).netloc)
                else:
                    target_output_dir = os.path.join(mass_output_dir, urlparse(target).netloc)
                args.output = target_output_dir
                
                try:
                    # Create a new scanner instance for this target
                    scanner = WPScanner(args)
                    scanner.run()
                    
                    # Update summary
                    with open(summary_file, 'a') as f:
                        f.write(f"Target: {target}\n")
                        f.write(f"Status: Completed\n")
                        f.write(f"Output Directory: {scanner.output_dir}\n")
                        
                        # Check for vulnerabilities
                        vuln_file = os.path.join(scanner.output_dir, 'vulnerabilities.json')
                        if os.path.exists(vuln_file):
                            with open(vuln_file, 'r') as vf:
                                vulns = json.load(vf)
                                
                                # Count vulnerabilities across all categories
                                vuln_count = 0
                                severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
                                
                                # Process core vulnerabilities
                                if isinstance(vulns.get("core"), list):
                                    core_vulns = vulns["core"]
                                    vuln_count += len(core_vulns)
                                    for vuln in core_vulns:
                                        severity = vuln.get('severity', 'Unknown')
                                        severity_counts[severity] += 1
                                
                                # Process plugin vulnerabilities
                                if vulns.get("plugins"):
                                    for plugin, plugin_data in vulns["plugins"].items():
                                        if isinstance(plugin_data, dict) and "vulns" in plugin_data:
                                            plugin_vulns = plugin_data["vulns"]
                                            vuln_count += len(plugin_vulns)
                                            for vuln in plugin_vulns:
                                                severity = vuln.get('severity', 'Unknown')
                                                severity_counts[severity] += 1
                                
                                # Process theme vulnerabilities
                                if isinstance(vulns.get("themes"), list):
                                    theme_vulns = vulns["themes"]
                                    vuln_count += len(theme_vulns)
                                    for vuln in theme_vulns:
                                        severity = vuln.get('severity', 'Unknown')
                                        severity_counts[severity] += 1
                                
                                f.write(f"Vulnerabilities Found: {vuln_count}\n")
                                
                                f.write(f"  Critical: {severity_counts['Critical']}\n")
                                f.write(f"  High: {severity_counts['High']}\n")
                                f.write(f"  Medium: {severity_counts['Medium']}\n")
                                f.write(f"  Low: {severity_counts['Low']}\n")
                        else:
                            f.write("Vulnerabilities Found: 0\n")
                        
                        f.write("\n" + "-" * 80 + "\n\n")
                        
                except Exception as e:
                    print_error(f"Error scanning {target}: {str(e)}")
                    
                    # Update summary with error
                    with open(summary_file, 'a') as f:
                        f.write(f"Target: {target}\n")
                        f.write(f"Status: Error\n")
                        f.write(f"Error: {str(e)}\n")
                        f.write("\n" + "-" * 80 + "\n\n")
            
            print_success(f"Mass scan completed. Summary saved to {summary_file}")
                
        except Exception as e:
            print_error(f"An error occurred during mass scan: {str(e)}")
            sys.exit(1)

if __name__ == '__main__':
    main() 