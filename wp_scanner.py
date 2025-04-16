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
                    print_success(f"Found {len(vulnerabilities)} potential vulnerabilities")
                    
                    # Save vulnerability results
                    with open(os.path.join(self.output_dir, 'vulnerabilities.json'), 'w') as f:
                        json.dump(vulnerabilities, f, indent=4)
                    
                    # Attempt exploitation if enabled
                    if self.exploit:
                        print_info("Attempting to exploit vulnerabilities...")
                        exploitation_results = self.exploiter.exploit(vulnerabilities)
                        
                        # Save exploitation results
                        with open(os.path.join(self.output_dir, 'exploitation_results.json'), 'w') as f:
                            json.dump(exploitation_results, f, indent=4)
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
    
    args = parser.parse_args()
    
    # Validate arguments
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
                                f.write(f"Vulnerabilities Found: {len(vulns)}\n")
                                
                                # Count by severity
                                severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
                                for vuln in vulns:
                                    severity = vuln.get('severity', 'Unknown')
                                    severity_counts[severity] += 1
                                
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