#!/usr/bin/env python3
"""Generate and validate target lists for WP-Scanner mass scanning."""

from __future__ import annotations

import argparse
import os
import re
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")


def validate_url(url: str) -> Optional[str]:
    """Validate and normalise a URL. Returns None if invalid."""
    if not url:
        return None

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if url.endswith("/"):
        url = url[:-1]

    try:
        result = urlparse(url)
        if all([result.scheme, result.netloc]):
            return url
    except (ValueError, AttributeError):
        pass

    return None


def read_urls_from_file(file_path: str) -> list[str]:
    """Read URLs from a file, ignoring comments and empty lines."""
    urls: list[str] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                url_match = re.search(
                    r"(https?://[^\s,\"'\]\[]+|[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})", line
                )
                if url_match:
                    url = validate_url(url_match.group(1))
                    if url and url not in urls:
                        urls.append(url)
    except Exception as exc:
        print(f"Error reading file {file_path}: {exc}")

    return urls


def check_wordpress(url: str) -> Optional[str]:
    """Check if a URL is hosting WordPress. Returns the URL if WP detected, else None."""
    import requests

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)

        # Check 1: WordPress generator meta tag (most reliable)
        if '<meta name="generator" content="WordPress' in response.text:
            return url

        # Check 2: WordPress in HTML source
        if "wp-content" in response.text or "wp-includes" in response.text:
            wp_confidence = 0
            wp_indicators = [
                "/wp-login.php",
                "/wp-admin/",
                "/wp-content/",
                "/wp-includes/",
                "/xmlrpc.php",
                "/wp-json/",
            ]
            for indicator in wp_indicators:
                try:
                    resp = requests.head(
                        url + indicator, timeout=5, allow_redirects=False, verify=False
                    )
                    if resp.status_code in (200, 301, 302, 303, 307, 308, 403):
                        wp_confidence += 1
                except requests.RequestException:
                    continue
            if wp_confidence >= 2:
                return url

        return None
    except Exception as exc:
        print(f"[ERROR] Error checking {url}: {exc}")
        return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate target list for WP-Scanner mass scans"
    )
    parser.add_argument("-o", "--output", default="targets.txt", help="Output file for the target list")
    parser.add_argument("-i", "--input", dest="input_file", help="Input file with targets (one per line)")
    parser.add_argument("-u", "--urls", nargs="+", help="URLs to add to the target list")
    parser.add_argument("--subdomains", help="File with subdomain enumeration results")
    parser.add_argument("--append", action="store_true", help="Append to output file instead of overwriting")
    parser.add_argument(
        "--check-wordpress",
        action="store_true",
        help="Basic check if targets are WordPress (slower)",
    )

    args = parser.parse_args()

    if not args.input_file and not args.urls and not args.subdomains:
        parser.error("At least one input method is required: --input, --urls, or --subdomains")

    all_urls: list[str] = []

    # Process URLs from command line
    if args.urls:
        for url in args.urls:
            normalized = validate_url(url)
            if normalized and normalized not in all_urls:
                all_urls.append(normalized)

    # Process URLs from input file
    if args.input_file:
        if not os.path.isfile(args.input_file):
            print(f"Input file not found: {args.input_file}")
            sys.exit(1)
        for url in read_urls_from_file(args.input_file):
            if url not in all_urls:
                all_urls.append(url)

    # Process subdomains
    if args.subdomains:
        if not os.path.isfile(args.subdomains):
            print(f"Subdomains file not found: {args.subdomains}")
            sys.exit(1)
        for url in read_urls_from_file(args.subdomains):
            if url not in all_urls:
                all_urls.append(url)

    # Optionally filter for WordPress sites
    if args.check_wordpress and all_urls:
        print(f"Checking {len(all_urls)} targets for WordPress... (this may take a while)")

        wp_urls: list[str] = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_url = {executor.submit(check_wordpress, url): url for url in all_urls}
            for future in as_completed(future_to_url):
                result = future.result()
                if result:
                    wp_urls.append(result)

        print(f"Found {len(wp_urls)} WordPress sites out of {len(all_urls)} targets")
        all_urls = wp_urls

    # Save URLs to output file
    mode = "a" if args.append else "w"
    with open(args.output, mode, encoding="utf-8") as f:
        for url in all_urls:
            f.write(f"{url}\n")

    print(f"Saved {len(all_urls)} targets to {args.output}")
    print(f"Run mass scan with: python wp_scanner.py -l {args.output} --exploit")


if __name__ == "__main__":
    main()
