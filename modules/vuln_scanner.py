#!/usr/bin/env python3

import concurrent.futures
import json
import os
import re
import sys
from urllib.parse import urljoin
from packaging import version
from tqdm import tqdm

import requests
from bs4 import BeautifulSoup

from modules.utils import print_info, print_success, print_error, print_warning, print_verbose

class VulnerabilityScanner:
    def __init__(self, session, target, headers, timeout, threads, output_dir):
        self.session = session
        self.target = target
        self.headers = headers
        self.timeout = timeout
        self.threads = threads
        self.output_dir = output_dir
        self.wp_vulns_db, self.plugin_vulns_db, self.theme_vulns_db = self._load_vulns_db()

    def _load_vulns_db(self):
        """Load vulnerability database from file."""
        db_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'vulnerability_db.json')
        if not os.path.exists(db_file):
            os.makedirs(os.path.dirname(db_file), exist_ok=True)
            with open(db_file, 'w') as f:
                json.dump({"wordpress": {}, "plugins": {}, "themes": {}}, f)
            return {}, {}, {}
        try:
            with open(db_file, 'r') as f:
                db = json.load(f)
                return db.get("wordpress", {}), db.get("plugins", {}), db.get("themes", {})
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print_error(f"Error loading vulnerability database: {e}")
            return {}, {}, {}

    def scan(self, wp_info):
        """
        Scan WordPress for vulnerabilities concurrently.
        """
        results = {"core": [], "plugins": {}, "themes": {}}
        with tqdm(total=3, desc="Scanning for vulnerabilities") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_scan = {
                    executor.submit(self.check_wp_vulns, wp_info.get("version")): "core",
                    executor.submit(self.check_plugin_vulns, wp_info.get("plugins")): "plugins",
                    executor.submit(self.check_theme_vulns, wp_info.get("themes")): "themes"
                }

                for future in concurrent.futures.as_completed(future_to_scan):
                    scan_type = future_to_scan[future]
                    try:
                        data = future.result()
                        if data:
                            if scan_type == "core":
                                results["core"] = data
                            elif scan_type == "plugins":
                                for plugin, vulns in data.items():
                                    if vulns:
                                        results["plugins"][plugin] = vulns
                            elif scan_type == "themes":
                                for theme, vulns in data.items():
                                    if vulns:
                                        results["themes"][theme] = vulns
                    except Exception as exc:
                        print_error(f'{scan_type} scan generated an exception: {exc}')
                    pbar.update(1)
        return results

    def check_wp_vulns(self, wp_version):
        """Check WordPress core vulnerabilities."""
        if not wp_version or wp_version == 'Unknown':
            print_warning("WordPress version could not be determined, skipping core vulnerability check.")
            return []
        
        vulns = []
        if 'wordpress' in self.wp_vulns_db:
            for vuln_version, vuln_list in self.wp_vulns_db['wordpress'].items():
                if version.parse(wp_version) <= version.parse(vuln_version):
                    for vuln in vuln_list:
                        if self._is_version_affected(wp_version, vuln.get("affected_versions")):
                            vulns.append(vuln)
        vulns.extend(self._check_wp_common_vulns())
        return vulns

    def _check_wp_common_vulns(self):
        """Check for common WordPress vulnerabilities with active testing."""
        # This method can be expanded with more active checks.
        return []

    def check_plugin_vulns(self, plugins):
        """Check plugin vulnerabilities."""
        if not plugins:
            return {}
        
        vulns = {}
        with tqdm(total=len(plugins), desc="Scanning plugins", leave=False) as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_plugin = {executor.submit(self._check_plugin_vuln, plugin_name, plugin_info): plugin_name for plugin_name, plugin_info in plugins.items()}
                for future in concurrent.futures.as_completed(future_to_plugin):
                    plugin_name = future_to_plugin[future]
                    try:
                        plugin_vulns = future.result()
                        if plugin_vulns:
                            vulns[plugin_name] = plugin_vulns
                    except Exception as exc:
                        print_error(f'Plugin {plugin_name} generated an exception: {exc}')
                    pbar.update(1)
        return vulns

    def _check_plugin_vuln(self, plugin_name, plugin_info):
        """Check a single plugin for vulnerabilities."""
        vulns = []
        plugin_version = plugin_info.get("version", "Unknown")
        if plugin_name in self.plugin_vulns_db:
            for vuln in self.plugin_vulns_db[plugin_name]:
                if self._is_version_affected(plugin_version, vuln.get("affected_versions")):
                    vulns.append(vuln)
        return vulns

    def check_theme_vulns(self, themes):
        """Check theme vulnerabilities."""
        if not themes:
            return {}

        vulns = {}
        with tqdm(total=len(themes), desc="Scanning themes", leave=False) as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_theme = {executor.submit(self._check_theme_vuln, theme.get("name"), theme): theme.get("name") for theme in themes}
                for future in concurrent.futures.as_completed(future_to_theme):
                    theme_name = future_to_theme[future]
                    try:
                        theme_vulns = future.result()
                        if theme_vulns:
                            vulns[theme_name] = theme_vulns
                    except Exception as exc:
                        print_error(f'Theme {theme_name} generated an exception: {exc}')
                    pbar.update(1)
        return vulns

    def _check_theme_vuln(self, theme_name, theme_info):
        """Check a single theme for vulnerabilities."""
        vulns = []
        theme_version = theme_info.get("version", "Unknown")
        if theme_name in self.theme_vulns_db:
            for vuln in self.theme_vulns_db[theme_name]:
                if self._is_version_affected(theme_version, vuln.get("affected_versions")):
                    vulns.append(vuln)
        return vulns

    def _is_version_affected(self, detected_version, affected_versions):
        """Check if a detected version is within the affected version ranges."""
        if detected_version == "Unknown" or not affected_versions:
            return False
        
        try:
            parsed_version = version.parse(detected_version)
            for ver_range in affected_versions:
                if '-' in ver_range:
                    start_ver, end_ver = ver_range.split('-')
                    if version.parse(start_ver) <= parsed_version <= version.parse(end_ver):
                        return True
                elif ver_range.startswith('<='):
                    if parsed_version <= version.parse(ver_range[2:]):
                        return True
                elif ver_range.startswith('<'):
                    if parsed_version < version.parse(ver_range[1:]):
                        return True
                elif ver_range.startswith('>='):
                    if parsed_version >= version.parse(ver_range[2:]):
                        return True
                elif ver_range.startswith('>'):
                    if parsed_version > version.parse(ver_range[1:]):
                        return True
                else:
                    if parsed_version == version.parse(ver_range):
                        return True
        except (version.InvalidVersion, TypeError):
            return False
        return False