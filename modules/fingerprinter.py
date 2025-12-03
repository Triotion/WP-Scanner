#!/usr/bin/env python3

import json
import os
import re
import sys
import concurrent.futures
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from modules.utils import print_info, print_success, print_error, print_warning, print_verbose

class WPFingerprinter:
    def __init__(self, session, target, headers, timeout, output_dir, threads=5):
        self.session = session
        self.target = target
        self.headers = headers
        self.timeout = timeout
        self.output_dir = output_dir
        self.threads = threads
        self.api_url = f"{self.target}/wp-json/"
        self.wp_info = {
            "is_wordpress": False,
            "detection_score": 0,
            "detection_methods": [],
            "version": "Unknown",
            "version_sources": [],
            "themes": [],
            "plugins": {},
            "users": [],
            "xmlrpc_enabled": False,
            "rest_api_enabled": False
        }
        self.wp_detection_score = 0

    def is_wordpress(self):
        """
        Check if the target is a WordPress site.
        Returns True if the target is a WordPress site, False otherwise.
        """
        return self.wp_info["is_wordpress"]

    def fingerprint(self):
        """
        Fingerprint the WordPress installation by running a series of checks concurrently.
        Returns a dictionary with the fingerprinting information.
        """
        print_info("Fingerprinting WordPress...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self._check_wp_json),
                executor.submit(self._check_meta_generator),
                executor.submit(self._check_xmlrpc),
                executor.submit(self._check_common_paths),
                executor.submit(self._check_html_patterns),
                executor.submit(self._check_readme),
                executor.submit(self._check_wp_cron),
                executor.submit(self._check_license_txt),
                executor.submit(self._check_wp_links),
                executor.submit(self._check_oembed),
                executor.submit(self._check_trackback),
                executor.submit(self._check_feed),
                executor.submit(self._check_robots_txt),
                executor.submit(self._check_sitemap_xml),
                executor.submit(self._check_updraftplus),
                executor.submit(self._check_jetpack),
                executor.submit(self._check_wp_config),
                executor.submit(self._check_wp_content),
                executor.submit(self._check_wp_admin),
                executor.submit(self._check_wp_login),
                executor.submit(self._get_version),
                executor.submit(self._get_themes),
                executor.submit(self._get_plugins),
                executor.submit(self._enumerate_users)
            ]

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._update_wp_info(result)
                except Exception as e:
                    print_verbose(f"Error during fingerprinting check: {str(e)}")
        
        self.wp_info["detection_score"] = self.wp_detection_score
        self.wp_info["is_wordpress"] = self.wp_detection_score >= 3
        if self.wp_info["is_wordpress"]:
            print_success(f"WordPress confirmed (score: {self.wp_info['detection_score']}/10) via: {', '.join(self.wp_info['detection_methods'])}")
        else:
            print_error(f"The target {self.target} does not appear to be running WordPress.")

        return self.wp_info

    def _update_wp_info(self, result):
        """Update the main wp_info dictionary with the results from a check."""
        for key, value in result.items():
            if key in ["detection_score"]:
                self.wp_detection_score += value
            elif key in ["detection_methods", "version_sources", "themes", "users"]:
                self.wp_info[key].extend(value)
            elif key == "plugins":
                self.wp_info[key].update(value)
            else:
                self.wp_info[key] = value

    def _check_wp_json(self):
        """Check for the presence of the WP-JSON API."""
        try:
            response = self.session.get(self.api_url, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 and 'routes' in response.json():
                return {"detection_score": 3, "detection_methods": ["wp-json API"], "rest_api_enabled": True}
        except (requests.RequestException, json.JSONDecodeError) as e:
            print_verbose(f"Error checking WP-JSON API: {e}")
        return {}

    def _check_meta_generator(self):
        """Check for the WordPress generator meta tag."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            meta = soup.find('meta', attrs={'name': 'generator'})
            if meta and 'wordpress' in meta.get('content', '').lower():
                version_match = re.search(r'(\d+\.\d+(\.\d+)?)', meta['content'])
                if version_match:
                    return {
                        "detection_score": 3,
                        "detection_methods": ["meta generator tag"],
                        "version": version_match.group(1),
                        "version_sources": ["meta generator tag"]
                    }
                return {"detection_score": 3, "detection_methods": ["meta generator tag"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking meta generator tag: {e}")
        return {}

    def _check_xmlrpc(self):
        """Check for the XML-RPC endpoint."""
        try:
            response = self.session.get(urljoin(self.target, 'xmlrpc.php'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 and 'XML-RPC server accepts POST requests only' in response.text:
                return {"detection_score": 2, "detection_methods": ["xmlrpc.php"], "xmlrpc_enabled": True}
        except requests.RequestException as e:
            print_verbose(f"Error checking xmlrpc.php: {e}")
        return {}

    def _check_common_paths(self):
        """Check for common WordPress paths."""
        score = 0
        paths = ['/wp-login.php', '/wp-admin/', '/wp-content/', '/wp-includes/']
        for path in paths:
            try:
                response = self.session.get(urljoin(self.target, path), headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                if response.status_code in [200, 302, 403]:
                    score += 1
            except requests.RequestException:
                continue
        if score > 0:
            return {"detection_score": score, "detection_methods": ["common paths"]}
        return {}

    def _check_html_patterns(self):
        """Check for WordPress-specific patterns in the HTML source."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            patterns = [
                r'wp-content/themes/',
                r'wp-content/plugins/',
                r'wp-includes/js/wp-embed.min.js',
                r'wp-includes/css/dist/block-library/style.min.css'
            ]
            score = sum(1 for pattern in patterns if re.search(pattern, response.text))
            if score > 0:
                return {"detection_score": score, "detection_methods": ["HTML patterns"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking HTML patterns: {e}")
        return {}

    def _check_readme(self):
        """Check for the readme.html file."""
        try:
            response = self.session.get(urljoin(self.target, 'readme.html'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 and 'wordpress' in response.text.lower():
                return {"detection_score": 2, "detection_methods": ["readme.html"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking readme.html: {e}")
        return {}

    def _check_wp_cron(self):
        """Check for wp-cron.php."""
        try:
            response = self.session.get(urljoin(self.target, 'wp-cron.php'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return {"detection_score": 1, "detection_methods": ["wp-cron.php"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking wp-cron.php: {e}")
        return {}

    def _check_license_txt(self):
        """Check for license.txt."""
        try:
            response = self.session.get(urljoin(self.target, 'license.txt'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 and 'WordPress' in response.text:
                return {"detection_score": 2, "detection_methods": ["license.txt"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking license.txt: {e}")
        return {}

    def _check_wp_links(self):
        """Check for WordPress specific links in the homepage."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [a.get('href') for a in soup.find_all('a')]
                score = 0
                if any('wp-login.php' in str(link) for link in links):
                    score += 1
                if any('wp-admin' in str(link) for link in links):
                    score += 1
                if score > 0:
                    return {"detection_score": score, "detection_methods": ["wp links"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking wp links: {e}")
        return {}

    def _check_oembed(self):
        """Check for oEmbed links."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                if 'wp-json/oembed' in response.text:
                    return {"detection_score": 1, "detection_methods": ["oEmbed"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking oEmbed: {e}")
        return {}

    def _check_trackback(self):
        """Check for trackback link."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                if 'wp-trackback' in response.text:
                    return {"detection_score": 1, "detection_methods": ["trackback"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking trackback: {e}")
        return {}

    def _check_feed(self):
        """Check for feed link."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                if 'feed' in response.text:
                    return {"detection_score": 1, "detection_methods": ["feed"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking feed: {e}")
        return {}

    def _check_robots_txt(self):
        """Check for robots.txt."""
        try:
            response = self.session.get(urljoin(self.target, 'robots.txt'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 and 'wp-admin' in response.text:
                return {"detection_score": 2, "detection_methods": ["robots.txt"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking robots.txt: {e}")
        return {}

    def _check_sitemap_xml(self):
        """Check for sitemap.xml."""
        try:
            response = self.session.get(urljoin(self.target, 'sitemap.xml'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 and 'wp-sitemap' in response.text:
                return {"detection_score": 2, "detection_methods": ["sitemap.xml"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking sitemap.xml: {e}")
        return {}

    def _check_updraftplus(self):
        """Check for UpdraftPlus backup files."""
        try:
            response = self.session.get(urljoin(self.target, 'wp-content/updraft/'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["UpdraftPlus"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking UpdraftPlus: {e}")
        return {}

    def _check_jetpack(self):
        """Check for Jetpack files."""
        try:
            response = self.session.get(urljoin(self.target, 'wp-content/plugins/jetpack/'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["Jetpack"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking Jetpack: {e}")
        return {}

    def _check_wp_config(self):
        """Check for wp-config.php."""
        try:
            response = self.session.get(urljoin(self.target, 'wp-config.php'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["wp-config.php"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking wp-config.php: {e}")
        return {}

    def _check_wp_content(self):
        """Check for wp-content."""
        try:
            response = self.session.get(urljoin(self.target, 'wp-content/'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["wp-content"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking wp-content: {e}")
        return {}

    def _check_wp_admin(self):
        """Check for wp-admin."""
        try:
            response = self.session.get(urljoin(self.target, 'wp-admin/'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["wp-admin"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking wp-admin: {e}")
        return {}

    def _check_wp_login(self):
        """Check for wp-login.php."""
        try:
            response = self.session.get(urljoin(self.target, 'wp-login.php'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return {"detection_score": 2, "detection_methods": ["wp-login.php"]}
        except requests.RequestException as e:
            print_verbose(f"Error checking wp-login.php: {e}")
        return {}

    def get_version(self):
        """
        Get the WordPress version.
        Returns the WordPress version as a string.
        """
        return self.wp_info["version"]

    def _get_version(self):
        """Get the WordPress version from various sources."""
        # 1. From wp-includes/version.php
        try:
            response = self.session.get(urljoin(self.target, 'wp-includes/version.php'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                match = re.search(r"\$wp_version\s*=\s*'([^']+)';", response.text)
                if match:
                    return {"version": match.group(1), "version_sources": ["version.php"]}
        except requests.RequestException:
            pass

        # 2. From RSS feed
        try:
            response = self.session.get(urljoin(self.target, 'feed/'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                match = re.search(r'<generator>https://wordpress.org/\?v=([^<]+)</generator>', response.text)
                if match:
                    return {"version": match.group(1), "version_sources": ["RSS feed"]}
        except requests.RequestException:
            pass
        
        return {}

    def get_theme(self):
        """
        Get the theme.
        Returns the theme.
        """
        return self.wp_info["themes"]

    def get_themes(self):
        """
        Get the list of themes.
        Returns a list of themes.
        """
        return self.wp_info["themes"]

    def _get_themes(self):
        """Get the list of themes."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            matches = re.findall(r'wp-content/themes/([^/]+)/', response.text)
            themes = list(set(matches))
            
            # Get theme versions
            theme_details = []
            for theme in themes:
                try:
                    style_url = urljoin(self.target, f"wp-content/themes/{theme}/style.css")
                    style_response = self.session.get(style_url, headers=self.headers, timeout=self.timeout, verify=False)
                    if style_response.status_code == 200:
                        version_match = re.search(r'Version:\s*(\S+)', style_response.text)
                        if version_match:
                            theme_details.append({"name": theme, "version": version_match.group(1)})
                        else:
                            theme_details.append({"name": theme, "version": "Unknown"})
                except requests.RequestException:
                    theme_details.append({"name": theme, "version": "Unknown"})
            return {"themes": theme_details}
        except requests.RequestException as e:
            print_verbose(f"Error getting themes: {e}")
        return {}

    def get_plugins(self):
        """
        Get the list of plugins.
        Returns a list of plugins.
        """
        return self.wp_info["plugins"]

    def _get_plugins(self):
        """Get the list of plugins."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            matches = re.findall(r'wp-content/plugins/([^/]+)/', response.text)
            plugins = list(set(matches))
            
            plugin_details = {}
            for plugin in plugins:
                plugin_details[plugin] = {"name": plugin, "version": "Unknown"}
                try:
                    readme_url = urljoin(self.target, f"wp-content/plugins/{plugin}/readme.txt")
                    readme_response = self.session.get(readme_url, headers=self.headers, timeout=self.timeout, verify=False)
                    if readme_response.status_code == 200:
                        version_match = re.search(r'Stable tag:\s*(\S+)', readme_response.text)
                        if version_match:
                            plugin_details[plugin]["version"] = version_match.group(1)
                except requests.RequestException:
                    continue
            return {"plugins": plugin_details}
        except requests.RequestException as e:
            print_verbose(f"Error getting plugins: {e}")
        return {}

    def enumerate_users(self):
        """
        Enumerate users.
        Returns a list of users.
        """
        return self.wp_info["users"]

    def _enumerate_users(self):
        """Enumerate users."""
        users = []
        # 1. Via WP-JSON API
        try:
            response = self.session.get(urljoin(self.api_url, 'wp/v2/users'), headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                for user in response.json():
                    users.append({"id": user.get("id"), "name": user.get("name"), "slug": user.get("slug")})
        except (requests.RequestException, json.JSONDecodeError):
            pass

        # 2. Via author archives
        if not users:
            for i in range(1, 11):
                try:
                    response = self.session.get(urljoin(self.target, f'?author={i}'), headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                    if response.status_code == 301 or response.status_code == 302:
                        location = response.headers.get('Location')
                        if location:
                            match = re.search(r'/author/([^/]+)', location)
                            if match:
                                users.append({"id": i, "slug": match.group(1)})
                except requests.RequestException:
                    continue
        
        if users:
            return {"users": users}
        return {}
