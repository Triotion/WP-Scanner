#!/usr/bin/env python3
# Script to generate target lists for WP-Scanner mass scanning
# Improved: Better WordPress detection with scoring, SSL verification disable

import argparse
import os
import sys
import re
import warnings
from urllib.parse import urlparse

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

def validate_url(url):
    """Validate and normalize a URL"""
    if not url:
        return None
        
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash
    if url.endswith('/'):
        url = url[:-1]
    
    # Validate URL format
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return None
        return url
    except:
        return None

def read_urls_from_file(file_path):
    """Read URLs from a file, ignoring comments and empty lines"""
    urls = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                    
                # Extract URL from potential tool output
                # Common formats: 
                # - Plain URL: example.com or https://example.com
                # - CSV: example.com,open,443,https,title
                # - Tool output: [+] Found: https://example.com
                
                # Try to extract URL with regex
                url_match = re.search(r'(https?://[^\s,"\'\]\[]+|[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})', line)
                if url_match:
                    url = validate_url(url_match.group(1))
                    if url and url not in urls:
                        urls.append(url)
                        
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
    
    return urls

def main():
    parser = argparse.ArgumentParser(description='Generate target list for WP-Scanner mass scans')
    parser.add_argument('-o', '--output', default='targets.txt', help='Output file for the target list')
    parser.add_argument('-i', '--input', help='Input file with targets (one per line)')
    parser.add_argument('-u', '--urls', nargs='+', help='URLs to add to the target list')
    parser.add_argument('--subdomains', help='File with subdomains enumeration results')
    parser.add_argument('--append', action='store_true', help='Append to output file instead of overwriting')
    parser.add_argument('--check-wordpress', action='store_true', help='Basic check if targets are WordPress (slower)')
    
    args = parser.parse_args()
    
    # Validate that at least one input method is specified
    if not args.input and not args.urls and not args.subdomains:
        parser.error("At least one input method is required: --input, --urls, or --subdomains")
    
    all_urls = []
    
    # Process URLs from command line
    if args.urls:
        for url in args.urls:
            normalized_url = validate_url(url)
            if normalized_url and normalized_url not in all_urls:
                all_urls.append(normalized_url)
    
    # Process URLs from input file
    if args.input:
        if not os.path.isfile(args.input):
            print(f"Input file not found: {args.input}")
            sys.exit(1)
            
        urls_from_file = read_urls_from_file(args.input)
        for url in urls_from_file:
            if url not in all_urls:
                all_urls.append(url)
    
    # Process subdomains
    if args.subdomains:
        if not os.path.isfile(args.subdomains):
            print(f"Subdomains file not found: {args.subdomains}")
            sys.exit(1)
            
        subdomains = read_urls_from_file(args.subdomains)
        for url in subdomains:
            if url not in all_urls:
                all_urls.append(url)
    
    # Check if targets are WordPress
    if args.check_wordpress and all_urls:
        import requests
        from concurrent.futures import ThreadPoolExecutor
        
        def check_wordpress(url):
            """Check if a URL is hosting WordPress"""
            try:
                # Try to access the site with timeout
                response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                
                # Check 1: WordPress generator meta tag (most reliable)
                if '<meta name="generator" content="WordPress' in response.text:
                    return url
                
                # Check 2: WordPress in HTML source or common paths
                if 'wp-' in response.text or 'WordPress' in response.text:
                    return url
                
                # Check 3: Check common WordPress paths with confidence scoring
                wp_confidence = 0
                wp_indicators = [
                    '/wp-login.php',
                    '/wp-admin/',
                    '/wp-content/',
                    '/wp-includes/',
                    '/xmlrpc.php',
                    '/wp-json/'
                ]
                
                for indicator in wp_indicators:
                    try:
                        check_url = url + indicator
                        resp = requests.head(check_url, timeout=5, allow_redirects=False, verify=False)
                        # 200, 301, 302, 403 indicate the path exists
                        if resp.status_code in [200, 301, 302, 303, 307, 308, 403]:
                            wp_confidence += 1
                    except:
                        pass
                
                # Require at least 2 indicators to reduce false positives
                if wp_confidence >= 2:
                    return url
                    
                return None
            except Exception as e:
                print(f"[ERROR] Error checking {url}: {str(e)}")
                return None
        
        print(f"Checking {len(all_urls)} targets for WordPress... (this may take a while)")
        
        # Use ThreadPoolExecutor for parallel checking
        wp_urls = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(check_wordpress, all_urls))
            wp_urls = [url for url in results if url]
        
        print(f"Found {len(wp_urls)} WordPress sites out of {len(all_urls)} targets")
        all_urls = wp_urls
    
    # Save URLs to output file
    mode = 'a' if args.append else 'w'
    with open(args.output, mode) as f:
        for url in all_urls:
            f.write(f"{url}\n")
    
    print(f"Saved {len(all_urls)} targets to {args.output}")
    print(f"Run mass scan with: python wp_scanner.py -l {args.output} --exploit")

if __name__ == '__main__':
    main() 