#!/usr/bin/env python3
"""WordPress fingerprinting: detection, version, themes, plugins, users."""

from __future__ import annotations

import concurrent.futures
import json
import re
import threading
from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from modules.utils import print_error, print_info, print_success, print_verbose


class WPFingerprinter:
    """Performs comprehensive WordPress detection and information gathering."""

    def __init__(
        self,
        session: requests.Session,
        target: str,
        headers: dict[str, str],
        timeout: int,
        output_dir: str,
        threads: int = 5,
    ) -> None:
        self.session = session
        self.target = target
        self.headers = headers
        self.timeout = timeout
        self.output_dir = output_dir
        self.threads = threads
        self.api_url = f"{self.target}/wp-json/"
        self._lock = threading.Lock()
        self.wp_info: dict[str, Any] = {
            "is_wordpress": False,
            "detection_score": 0,
            "detection_methods": [],
            "version": "Unknown",
            "version_sources": [],
            "themes": [],
            "plugins": {},
            "users": [],
            "xmlrpc_enabled": False,
            "rest_api_enabled": False,
        }
        self._detection_score = 0
        self._homepage_html: str | None = None
        self._homepage_lock = threading.Lock()

    def _get_homepage(self) -> str | None:
        """Fetch and cache the homepage HTML (thread-safe, fetched once)."""
        if self._homepage_html is not None:
            return self._homepage_html
        with self._homepage_lock:
            if self._homepage_html is not None:
                return self._homepage_html
            try:
                resp = self.session.get(
                    self.target, headers=self.headers, timeout=self.timeout, verify=False
                )
                if resp.status_code == 200:
                    self._homepage_html = resp.text
            except requests.RequestException:
                pass
        return self._homepage_html

    def is_wordpress(self) -> bool:
        return self.wp_info["is_wordpress"]

    def fingerprint(self) -> dict[str, Any]:
        """Run all fingerprinting checks concurrently."""
        print_info("Fingerprinting WordPress...")

        checks = [
            self._check_wp_json,
            self._check_meta_generator,
            self._check_xmlrpc,
            self._check_common_paths,
            self._check_html_patterns,
            self._check_readme,
            self._check_wp_cron,
            self._check_license_txt,
            self._check_wp_links,
            self._check_oembed,
            self._check_trackback,
            self._check_feed,
            self._check_robots_txt,
            self._check_sitemap_xml,
            self._check_updraftplus,
            self._check_jetpack,
            self._check_wp_config,
            self._check_wp_content,
            self._check_wp_admin,
            self._check_wp_login,
            self._get_version,
            self._get_themes,
            self._get_plugins,
            self._enumerate_users,
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check): check for check in checks}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._update_wp_info(result)
                except Exception as exc:
                    print_verbose(f"Error during fingerprinting check: {exc}")

        self.wp_info["detection_score"] = self._detection_score
        self.wp_info["is_wordpress"] = self._detection_score >= 3

        if self.wp_info["is_wordpress"]:
            print_success(
                f"WordPress confirmed (score: {self._detection_score}/10) via: "
                f"{', '.join(self.wp_info['detection_methods'])}"
            )
        else:
            print_error(f"The target {self.target} does not appear to be running WordPress.")

        return self.wp_info

    def _update_wp_info(self, result: dict[str, Any]) -> None:
        with self._lock:
            for key, value in result.items():
                if key == "detection_score":
                    self._detection_score += value
                elif key in ("detection_methods", "version_sources", "themes", "users"):
                    self.wp_info[key].extend(value)
                elif key == "plugins":
                    self.wp_info[key].update(value)
                else:
                    self.wp_info[key] = value

    # ------------------------------------------------------------------
    # Detection checks
    # ------------------------------------------------------------------

    def _check_wp_json(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                self.api_url, headers=self.headers, timeout=self.timeout, verify=False
            )
            if resp.status_code == 200 and "routes" in resp.json():
                return {
                    "detection_score": 3,
                    "detection_methods": ["wp-json API"],
                    "rest_api_enabled": True,
                }
        except (requests.RequestException, json.JSONDecodeError):
            pass
        return {}

    def _check_meta_generator(self) -> dict[str, Any]:
        html_text = self._get_homepage()
        if not html_text:
            return {}
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            meta = soup.find("meta", attrs={"name": "generator"})
            if meta and "wordpress" in meta.get("content", "").lower():
                match = re.search(r"(\d+\.\d+(?:\.\d+)?)", meta["content"])
                if match:
                    return {
                        "detection_score": 3,
                        "detection_methods": ["meta generator tag"],
                        "version": match.group(1),
                        "version_sources": ["meta generator tag"],
                    }
                return {"detection_score": 3, "detection_methods": ["meta generator tag"]}
        except Exception:
            pass
        return {}

    def _check_xmlrpc(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "xmlrpc.php"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200 and "XML-RPC server accepts POST requests only" in resp.text:
                return {"detection_score": 2, "detection_methods": ["xmlrpc.php"], "xmlrpc_enabled": True}
        except requests.RequestException:
            pass
        return {}

    def _check_common_paths(self) -> dict[str, Any]:
        score = 0
        for path in ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"]:
            try:
                resp = self.session.get(
                    urljoin(self.target, path),
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                if resp.status_code in (200, 302, 403):
                    score += 1
            except requests.RequestException:
                continue
        return {"detection_score": score, "detection_methods": ["common paths"]} if score > 0 else {}

    def _check_html_patterns(self) -> dict[str, Any]:
        html_text = self._get_homepage()
        if not html_text:
            return {}
        patterns = [
            r"wp-content/themes/",
            r"wp-content/plugins/",
            r"wp-includes/js/wp-embed\.min\.js",
            r"wp-includes/css/dist/block-library/style\.min\.css",
        ]
        score = sum(1 for p in patterns if re.search(p, html_text))
        return {"detection_score": score, "detection_methods": ["HTML patterns"]} if score > 0 else {}

    def _check_readme(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "readme.html"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200 and "wordpress" in resp.text.lower():
                return {"detection_score": 2, "detection_methods": ["readme.html"]}
        except requests.RequestException:
            pass
        return {}

    def _check_wp_cron(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "wp-cron.php"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                return {"detection_score": 1, "detection_methods": ["wp-cron.php"]}
        except requests.RequestException:
            pass
        return {}

    def _check_license_txt(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "license.txt"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200 and "WordPress" in resp.text:
                return {"detection_score": 2, "detection_methods": ["license.txt"]}
        except requests.RequestException:
            pass
        return {}

    def _check_wp_links(self) -> dict[str, Any]:
        html_text = self._get_homepage()
        if not html_text:
            return {}
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            links = [a.get("href", "") for a in soup.find_all("a")]
            score = 0
            if any("wp-login.php" in str(link) for link in links):
                score += 1
            if any("wp-admin" in str(link) for link in links):
                score += 1
            return {"detection_score": score, "detection_methods": ["wp links"]} if score > 0 else {}
        except Exception:
            pass
        return {}

    def _check_oembed(self) -> dict[str, Any]:
        html_text = self._get_homepage()
        if not html_text:
            return {}
        if "wp-json/oembed" in html_text:
            return {"detection_score": 1, "detection_methods": ["oEmbed"]}
        return {}

    def _check_trackback(self) -> dict[str, Any]:
        html_text = self._get_homepage()
        if not html_text:
            return {}
        if "wp-trackback" in html_text:
            return {"detection_score": 1, "detection_methods": ["trackback"]}
        return {}

    def _check_feed(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "feed/"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200 and "wordpress" in resp.text.lower():
                return {"detection_score": 2, "detection_methods": ["feed"]}
        except requests.RequestException:
            pass
        return {}

    def _check_robots_txt(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "robots.txt"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200 and "wp-admin" in resp.text:
                return {"detection_score": 2, "detection_methods": ["robots.txt"]}
        except requests.RequestException:
            pass
        return {}

    def _check_sitemap_xml(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "sitemap.xml"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200 and "wp-sitemap" in resp.text:
                return {"detection_score": 2, "detection_methods": ["sitemap.xml"]}
        except requests.RequestException:
            pass
        return {}

    def _check_updraftplus(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "wp-content/updraft/"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["UpdraftPlus"]}
        except requests.RequestException:
            pass
        return {}

    def _check_jetpack(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "wp-content/plugins/jetpack/"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["Jetpack"]}
        except requests.RequestException:
            pass
        return {}

    def _check_wp_config(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "wp-config.php"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["wp-config.php"]}
        except requests.RequestException:
            pass
        return {}

    def _check_wp_content(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "wp-content/"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["wp-content"]}
        except requests.RequestException:
            pass
        return {}

    def _check_wp_admin(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "wp-admin/"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["wp-admin"]}
        except requests.RequestException:
            pass
        return {}

    def _check_wp_login(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                urljoin(self.target, "wp-login.php"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["wp-login.php"]}
        except requests.RequestException:
            pass
        return {}

    # ------------------------------------------------------------------
    # Version, themes, plugins, users
    # ------------------------------------------------------------------

    def get_version(self) -> str:
        return self.wp_info["version"]

    def _get_version(self) -> dict[str, Any]:
        # 1. wp-includes/version.php
        try:
            resp = self.session.get(
                urljoin(self.target, "wp-includes/version.php"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                match = re.search(r"\$wp_version\s*=\s*'([^']+)';", resp.text)
                if match:
                    return {"version": match.group(1), "version_sources": ["version.php"]}
        except requests.RequestException:
            pass

        # 2. RSS feed
        try:
            resp = self.session.get(
                urljoin(self.target, "feed/"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                match = re.search(
                    r"<generator>https://wordpress.org/\?v=([^<]+)</generator>", resp.text
                )
                if match:
                    return {"version": match.group(1), "version_sources": ["RSS feed"]}
        except requests.RequestException:
            pass

        return {}

    def get_themes(self) -> list[dict[str, str]]:
        return self.wp_info["themes"]

    def _get_themes(self) -> dict[str, Any]:
        html_text = self._get_homepage()
        if not html_text:
            return {}
        try:
            matches = re.findall(r"wp-content/themes/([^/]+)/", html_text)
            theme_names = list(set(matches))

            theme_details: list[dict[str, str]] = []
            for theme in theme_names:
                version = "Unknown"
                try:
                    style_url = urljoin(self.target, f"wp-content/themes/{theme}/style.css")
                    resp = self.session.get(
                        style_url, headers=self.headers, timeout=self.timeout, verify=False
                    )
                    if resp.status_code == 200:
                        vm = re.search(r"Version:\s*(\S+)", resp.text)
                        if vm:
                            version = vm.group(1)
                except requests.RequestException:
                    pass
                theme_details.append({"name": theme, "version": version})

            return {"themes": theme_details}
        except Exception:
            pass
        return {}

    def get_plugins(self) -> dict[str, Any]:
        return self.wp_info["plugins"]

    def _get_plugins(self) -> dict[str, Any]:
        html_text = self._get_homepage()
        if not html_text:
            return {}
        try:
            matches = re.findall(r"wp-content/plugins/([^/]+)/", html_text)
            plugin_names = list(set(matches))

            plugin_details: dict[str, dict[str, str]] = {}
            for plugin in plugin_names:
                version = "Unknown"
                try:
                    readme_url = urljoin(self.target, f"wp-content/plugins/{plugin}/readme.txt")
                    resp = self.session.get(
                        readme_url, headers=self.headers, timeout=self.timeout, verify=False
                    )
                    if resp.status_code == 200:
                        vm = re.search(r"Stable tag:\s*(\S+)", resp.text)
                        if vm:
                            version = vm.group(1)
                except requests.RequestException:
                    pass
                plugin_details[plugin] = {"name": plugin, "version": version}

            return {"plugins": plugin_details}
        except Exception:
            pass
        return {}

    def enumerate_users(self) -> list[dict[str, Any]]:
        return self.wp_info["users"]

    def _enumerate_users(self) -> dict[str, Any]:
        users: list[dict[str, Any]] = []

        # 1. Via WP-JSON API
        try:
            resp = self.session.get(
                urljoin(self.api_url, "wp/v2/users"),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                for user in resp.json():
                    users.append(
                        {"id": user.get("id"), "name": user.get("name"), "slug": user.get("slug")}
                    )
        except (requests.RequestException, json.JSONDecodeError):
            pass

        # 2. Via author archives (fallback)
        if not users:
            for i in range(1, 11):
                try:
                    resp = self.session.get(
                        urljoin(self.target, f"?author={i}"),
                        headers=self.headers,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False,
                    )
                    if resp.status_code in (301, 302):
                        location = resp.headers.get("Location", "")
                        match = re.search(r"/author/([^/]+)", location)
                        if match:
                            users.append({"id": i, "slug": match.group(1)})
                except requests.RequestException:
                    continue

        return {"users": users} if users else {}
