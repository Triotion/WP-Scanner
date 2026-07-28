#!/usr/bin/env python3
"""Vulnerability scanner: matches detected components against the local DB."""

from __future__ import annotations

import concurrent.futures
import json
import os
from typing import Any

from packaging import version
from tqdm import tqdm

from modules.utils import print_error, print_info, print_warning


class VulnerabilityScanner:
    """Loads the vulnerability database and scans for matching CVEs."""

    def __init__(
        self,
        session: Any,
        target: str,
        headers: dict[str, str],
        timeout: int,
        threads: int,
        output_dir: str,
    ) -> None:
        self.session = session
        self.target = target
        self.headers = headers
        self.timeout = timeout
        self.threads = threads
        self.output_dir = output_dir
        self.wp_vulns_db: dict[str, list[dict[str, Any]]] = {}
        self.plugin_vulns_db: dict[str, list[dict[str, Any]]] = {}
        self.theme_vulns_db: dict[str, list[dict[str, Any]]] = {}
        self._load_vulns_db()

    def _load_vulns_db(self) -> None:
        db_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data",
            "vulnerability_db.json",
        )
        if not os.path.exists(db_file):
            os.makedirs(os.path.dirname(db_file), exist_ok=True)
            with open(db_file, "w", encoding="utf-8") as f:
                json.dump({"wordpress": {}, "plugins": {}, "themes": {}}, f)
            return

        try:
            with open(db_file, "r", encoding="utf-8") as f:
                db = json.load(f)
            self.wp_vulns_db = db.get("wordpress", {})
            self.plugin_vulns_db = db.get("plugins", {})
            self.theme_vulns_db = db.get("themes", {})
        except (json.JSONDecodeError, FileNotFoundError) as exc:
            print_error(f"Error loading vulnerability database: {exc}")

    def scan(self, wp_info: dict[str, Any]) -> dict[str, Any]:
        """Scan for vulnerabilities concurrently across core, plugins, and themes."""
        results: dict[str, Any] = {"core": [], "plugins": {}, "themes": {}}

        with tqdm(total=3, desc="Scanning for vulnerabilities") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self.check_wp_vulns, wp_info.get("version")): "core",
                    executor.submit(self.check_plugin_vulns, wp_info.get("plugins")): "plugins",
                    executor.submit(self.check_theme_vulns, wp_info.get("themes")): "themes",
                }

                for future in concurrent.futures.as_completed(futures):
                    scan_type = futures[future]
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
                        print_error(f"{scan_type} scan generated an exception: {exc}")
                    pbar.update(1)

        return results

    def check_wp_vulns(self, wp_version: str | None) -> list[dict[str, Any]]:
        if not wp_version or wp_version == "Unknown":
            print_warning("WordPress version could not be determined, skipping core vulnerability check.")
            return []

        vulns: list[dict[str, Any]] = []
        if self.wp_vulns_db:
            for vuln_version, vuln_list in self.wp_vulns_db.items():
                try:
                    if version.parse(wp_version) <= version.parse(vuln_version):
                        for vuln in vuln_list:
                            affected_v = vuln.get("affected_versions") or vuln.get("affected_version")
                            if self._is_version_affected(wp_version, affected_v):
                                vulns.append(vuln)
                except (version.InvalidVersion, TypeError):
                    continue
        return vulns

    def check_plugin_vulns(self, plugins: dict[str, Any] | None) -> dict[str, Any]:
        if not plugins:
            return {}

        vulns: dict[str, Any] = {}
        with tqdm(total=len(plugins), desc="Scanning plugins", leave=False) as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_plugin = {
                    executor.submit(self._check_plugin_vuln, name, info): name
                    for name, info in plugins.items()
                }
                for future in concurrent.futures.as_completed(future_to_plugin):
                    plugin_name = future_to_plugin[future]
                    try:
                        plugin_data = future.result()
                        if plugin_data and plugin_data.get("vulns"):
                            vulns[plugin_name] = plugin_data
                    except Exception as exc:
                        print_error(f"Plugin {plugin_name} generated an exception: {exc}")
                    pbar.update(1)
        return vulns

    def _check_plugin_vuln(self, plugin_name: str, plugin_info: dict[str, Any]) -> dict[str, Any]:
        vulns: list[dict[str, Any]] = []
        plugin_version = plugin_info.get("version", "Unknown")
        if plugin_name in self.plugin_vulns_db:
            for vuln in self.plugin_vulns_db[plugin_name]:
                affected_v = vuln.get("affected_versions") or vuln.get("affected_version")
                if self._is_version_affected(plugin_version, affected_v):
                    vulns.append(vuln)
        return {"vulns": vulns, "version": plugin_version}

    def check_theme_vulns(self, themes: list[dict[str, Any]] | None) -> dict[str, Any]:
        if not themes:
            return {}

        vulns: dict[str, Any] = {}
        with tqdm(total=len(themes), desc="Scanning themes", leave=False) as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_theme = {
                    executor.submit(self._check_theme_vuln, t.get("name"), t): t.get("name")
                    for t in themes
                }
                for future in concurrent.futures.as_completed(future_to_theme):
                    theme_name = future_to_theme[future]
                    try:
                        theme_data = future.result()
                        if theme_data and theme_data.get("vulns"):
                            vulns[theme_name] = theme_data
                    except Exception as exc:
                        print_error(f"Theme {theme_name} generated an exception: {exc}")
                    pbar.update(1)
        return vulns

    def _check_theme_vuln(self, theme_name: str, theme_info: dict[str, Any]) -> dict[str, Any]:
        vulns: list[dict[str, Any]] = []
        theme_version = theme_info.get("version", "Unknown")
        if theme_name in self.theme_vulns_db:
            for vuln in self.theme_vulns_db[theme_name]:
                affected_v = vuln.get("affected_versions") or vuln.get("affected_version")
                if self._is_version_affected(theme_version, affected_v):
                    vulns.append(vuln)
        return {"vulns": vulns, "version": theme_version}

    def _is_version_affected(
        self, detected_version: str, affected_versions: str | list[str] | None
    ) -> bool:
        if detected_version == "Unknown" or not affected_versions:
            return False

        try:
            parsed = version.parse(detected_version)
            if isinstance(affected_versions, str):
                affected_versions = [affected_versions]

            for ver_range in affected_versions:
                ver_range = ver_range.strip()
                if "-" in ver_range and not ver_range.startswith("-"):
                    parts = ver_range.split("-", 1)
                    if version.parse(parts[0]) <= parsed <= version.parse(parts[1]):
                        return True
                elif ver_range.startswith("<="):
                    if parsed <= version.parse(ver_range[2:]):
                        return True
                elif ver_range.startswith("<"):
                    if parsed < version.parse(ver_range[1:]):
                        return True
                elif ver_range.startswith(">="):
                    if parsed >= version.parse(ver_range[2:]):
                        return True
                elif ver_range.startswith(">"):
                    if parsed > version.parse(ver_range[1:]):
                        return True
                elif ver_range.startswith("=="):
                    if parsed == version.parse(ver_range[2:]):
                        return True
                elif ver_range.startswith("!="):
                    if parsed != version.parse(ver_range[2:]):
                        return True
                else:
                    if parsed == version.parse(ver_range):
                        return True
        except (version.InvalidVersion, TypeError):
            return False

        return False
