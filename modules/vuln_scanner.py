#!/usr/bin/env python3

import concurrent.futures
import json
import os
import re
import sys
import time
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from modules.utils import print_info, print_success, print_error, print_warning, print_verbose, ProgressBar

class VulnerabilityScanner:
    def __init__(self, session, target, headers, timeout, threads, output_dir):
        self.session = session
        self.target = target
        self.headers = headers
        self.timeout = timeout
        self.threads = threads
        self.output_dir = output_dir
        
        # Load vulnerability database
        self.wp_vulns_db = self._load_vulns_db('wordpress')
        self.plugin_vulns_db = self._load_vulns_db('plugins')
        self.theme_vulns_db = self._load_vulns_db('themes')
        
    def _load_vulns_db(self, db_type):
        """Load vulnerability database from file or create default structure"""
        db_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                              'data', f'{db_type}_vulns.json')
        
        # Create default structure if file doesn't exist
        if not os.path.exists(db_file):
            os.makedirs(os.path.dirname(db_file), exist_ok=True)
            
            if db_type == 'wordpress':
                default_db = {'wordpress': {}}
            else:
                default_db = {}
                
            with open(db_file, 'w') as f:
                json.dump(default_db, f, indent=4)
            
            return default_db
        
        # Load database from file
        try:
            with open(db_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print_error(f"Error loading {db_type} vulnerability database: {str(e)}")
            
            if db_type == 'wordpress':
                return {'wordpress': {}}
            else:
                return {}
    
    def check_wp_vulns(self, wp_version):
        """Check WordPress core vulnerabilities"""
        vulns = []
        
        if not wp_version or wp_version == 'Unknown':
            return []
        
        # Parse version
        version_parts = wp_version.split('.')
        major_minor = '.'.join(version_parts[:2])
        
        # Check if version exists in database
        if 'wordpress' in self.wp_vulns_db and major_minor in self.wp_vulns_db['wordpress']:
            for vuln in self.wp_vulns_db['wordpress'][major_minor]:
                # Check if the version is vulnerable
                if 'affected_versions' in vuln:
                    for affected_version in vuln['affected_versions']:
                        if self._is_version_affected(wp_version, affected_version):
                            vulns.append({
                                'title': vuln.get('title', 'WordPress Core Vulnerability'),
                                'description': vuln.get('description', 'No description available'),
                                'severity': vuln.get('severity', 'Unknown'),
                                'cve': vuln.get('cve', 'Unknown'),
                                'type': 'WordPress Core',
                                'affected_version': wp_version,
                                'fixed_in': vuln.get('fixed_in', 'Unknown'),
                                'exploitability': vuln.get('exploitability', 'Unknown'),
                                'exploit_available': vuln.get('exploit_available', False),
                                'exploit_method': vuln.get('exploit_method', None)
                            })
                            break
        
        # If no vulnerabilities found in database, perform active checks
        if not vulns:
            # Check for common WordPress vulnerabilities
            vulns.extend(self._check_wp_common_vulns())
        
        return vulns
    
    def _check_wp_common_vulns(self):
        """Check for common WordPress vulnerabilities with active testing"""
        vulns = []
        
        # Check for user enumeration vulnerability
        try:
            author_url = f"{self.target}/?author=1"
            response = self.session.get(author_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200 and '/author/' in response.url:
                vulns.append({
                    'title': 'WordPress User Enumeration',
                    'description': 'The WordPress site is vulnerable to user enumeration via /?author=X parameter',
                    'severity': 'Medium',
                    'cve': 'N/A',
                    'type': 'WordPress Core',
                    'affected_version': 'All',
                    'fixed_in': 'N/A (requires manual hardening)',
                    'exploitability': 'Easy',
                    'exploit_available': True,
                    'exploit_method': 'user_enumeration'
                })
        except Exception:
            pass
        
        # Check for path traversal vulnerability
        try:
            # WordPress core path traversal vulnerability in load-scripts.php and load-styles.php
            # This vulnerability affects WordPress < 5.7
            path_traversal_urls = [
                f"{self.target}/wp-admin/load-scripts.php?load=/../../../wp-config.php",
                f"{self.target}/wp-admin/load-styles.php?load=/../../../wp-config.php"
            ]
            
            for pt_url in path_traversal_urls:
                response = self.session.get(pt_url, headers=self.headers, timeout=self.timeout, verify=False)
                # If the response contains database credentials or WordPress configuration code,
                # the site is vulnerable to path traversal
                if response.status_code == 200 and ('DB_NAME' in response.text or 'ABSPATH' in response.text):
                    vulns.append({
                        'title': 'WordPress Core Path Traversal',
                        'description': 'The WordPress site is vulnerable to path traversal via load-scripts.php or load-styles.php',
                        'severity': 'Critical',
                        'cve': 'CVE-2022-21663',
                        'type': 'WordPress Core',
                        'affected_version': '<5.7',
                        'fixed_in': '5.7+',
                        'exploitability': 'High',
                        'exploit_available': True,
                        'exploit_method': 'wp_core_path_traversal',
                        'additional_info': {
                            'vulnerable_url': pt_url
                        }
                    })
                    break
        except Exception:
            pass
        
        # Check for xmlrpc.php system.multicall vulnerability
        try:
            xmlrpc_url = f"{self.target}/xmlrpc.php"
            xml_payload = """
            <?xml version="1.0" encoding="UTF-8"?>
            <methodCall>
                <methodName>system.multicall</methodName>
                <params>
                    <param>
                        <value>
                            <array>
                                <data>
                                    <value>
                                        <struct>
                                            <member>
                                                <name>methodName</name>
                                                <value><string>system.listMethods</string></value>
                                            </member>
                                            <member>
                                                <name>params</name>
                                                <value>
                                                    <array>
                                                        <data></data>
                                                    </array>
                                                </value>
                                            </member>
                                        </struct>
                                    </value>
                                </data>
                            </array>
                        </value>
                    </param>
                </params>
            </methodCall>
            """
            
            headers = self.headers.copy()
            headers['Content-Type'] = 'text/xml'
            
            response = self.session.post(xmlrpc_url, data=xml_payload, headers=headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200 and 'XML-RPC server accepts POST requests only' not in response.text and '<methodResponse>' in response.text:
                vulns.append({
                    'title': 'WordPress XML-RPC system.multicall Enabled',
                    'description': 'The WordPress xmlrpc.php has system.multicall method enabled which could be abused for brute force amplification attacks',
                    'severity': 'High',
                    'cve': 'CVE-2014-8559',
                    'type': 'WordPress Core',
                    'affected_version': 'All',
                    'fixed_in': 'N/A (requires manual disabling)',
                    'exploitability': 'Medium',
                    'exploit_available': True,
                    'exploit_method': 'xmlrpc_multicall'
                })
        except Exception:
            pass
        
        # Check for REST API user enumeration
        try:
            api_users_url = f"{self.target}/wp-json/wp/v2/users"
            response = self.session.get(api_users_url, headers=self.headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200 and isinstance(response.json(), list) and len(response.json()) > 0:
                vulns.append({
                    'title': 'WordPress REST API User Enumeration',
                    'description': 'The WordPress REST API exposes user information without authentication',
                    'severity': 'Medium',
                    'cve': 'N/A',
                    'type': 'WordPress Core',
                    'affected_version': 'All',
                    'fixed_in': 'N/A (requires REST API hardening)',
                    'exploitability': 'Easy',
                    'exploit_available': True,
                    'exploit_method': 'rest_api_user_enum'
                })
        except Exception:
            pass
        
        # Check for password reset token vulnerability
        try:
            # Try to get a username from the target site
            username = None
            # First check if we have already enumerated users via REST API
            api_users_url = f"{self.target}/wp-json/wp/v2/users"
            response = self.session.get(api_users_url, headers=self.headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                try:
                    users_data = response.json()
                    if isinstance(users_data, list) and len(users_data) > 0 and "slug" in users_data[0]:
                        username = users_data[0]["slug"]
                except:
                    pass
            
            # If no username found via REST API, try author pages
            if not username:
                for i in range(1, 3):  # Just try first few IDs
                    author_url = f"{self.target}/?author={i}"
                    response = self.session.get(author_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
                    if response.status_code == 200 and '/author/' in response.url:
                        author_pattern = r'/author/([^/]+)/'
                        matches = re.findall(author_pattern, response.url)
                        if matches:
                            username = matches[0]
                            break
            
            # If we have a username, test for the password reset vulnerability
            if username:
                # Step 1: Request password reset
                reset_url = f"{self.target}/wp-login.php?action=lostpassword"
                reset_data = {
                    'user_login': username,
                    'redirect_to': '',
                    'wp-submit': 'Get New Password'
                }
                
                response = self.session.post(reset_url, data=reset_data, headers=self.headers, timeout=self.timeout, verify=False)
                
                # Check for successful reset request
                if response.status_code == 200 and 'check your email' in response.text.lower():
                    # Check if the site leaks the reset key in the HTML (older WordPress versions)
                    reset_key_pattern = r'key=([a-zA-Z0-9]+)'
                    matches = re.findall(reset_key_pattern, response.text)
                    
                    if matches:
                        vulns.append({
                            'title': 'WordPress Password Reset Token Exposure',
                            'description': 'The WordPress site exposes password reset tokens in the response HTML',
                            'severity': 'Critical',
                            'cve': 'N/A',
                            'type': 'WordPress Core',
                            'affected_version': '<=4.3',
                            'fixed_in': '4.3+',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'password_reset_token_leak',
                            'additional_info': {
                                'username': username,
                                'reset_key': matches[0]
                            }
                        })
        except Exception:
            pass
        
        # Check for 'allowedtags' XSS vulnerability 
        try:
            # This vulnerability affects WordPress < 5.0.4
            response = self.session.get(f"{self.target}/wp-includes/kses.php", headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 and '$allowedtags' in response.text and 'wp_kses' in response.text:
                vulns.append({
                    'title': 'WordPress Stored XSS in $allowedtags',
                    'description': 'The WordPress site is vulnerable to stored XSS via $allowedtags',
                    'severity': 'High',
                    'cve': 'CVE-2019-8942',
                    'type': 'WordPress Core',
                    'affected_version': '<5.0.4',
                    'fixed_in': '5.0.4',
                    'exploitability': 'Medium',
                    'exploit_available': False,
                    'exploit_method': None
                })
        except Exception:
            pass
        
        return vulns
    
    def check_plugin_vulns(self, plugins):
        """Check plugin vulnerabilities"""
        vulns = []
        
        if not plugins:
            return []
        
        print_info(f"Checking {len(plugins)} plugins for vulnerabilities...")
        progress = ProgressBar(len(plugins), prefix='Plugin Scan:', suffix='Complete')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_plugin = {executor.submit(self._check_plugin_vuln, plugin): plugin for plugin in plugins}
            
            for future in concurrent.futures.as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                progress.update()
                
                try:
                    plugin_vulns = future.result()
                    if plugin_vulns:
                        vulns.extend(plugin_vulns)
                except Exception as e:
                    print_error(f"Error checking plugin {plugin}: {str(e)}")
        
        return vulns
    
    def _check_plugin_vuln(self, plugin):
        """Check if a specific plugin is vulnerable"""
        vulns = []
        plugin_name = plugin.split(' ')[0]  # Remove version if present
        
        # Check plugin in database
        if plugin_name in self.plugin_vulns_db:
            for vuln in self.plugin_vulns_db[plugin_name]:
                vulns.append({
                    'title': vuln.get('title', f'{plugin_name} Plugin Vulnerability'),
                    'description': vuln.get('description', 'No description available'),
                    'severity': vuln.get('severity', 'Unknown'),
                    'cve': vuln.get('cve', 'Unknown'),
                    'type': 'Plugin',
                    'plugin': plugin_name,
                    'affected_version': vuln.get('affected_version', 'Unknown'),
                    'fixed_in': vuln.get('fixed_in', 'Unknown'),
                    'exploitability': vuln.get('exploitability', 'Unknown'),
                    'exploit_available': vuln.get('exploit_available', False),
                    'exploit_method': vuln.get('exploit_method', None)
                })
        
        # Perform additional active checks
        # Check for readme.txt to get version info
        try:
            readme_url = f"{self.target}/wp-content/plugins/{plugin_name}/readme.txt"
            response = self.session.get(readme_url, headers=self.headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                # Extract version information
                version_match = re.search(r'Stable tag:\s*(\d+\.\d+\.?\d*)', response.text)
                if version_match:
                    plugin_version = version_match.group(1)
                    
                    # Check for known vulnerable versions based on common knowledge
                    # This could be expanded with more comprehensive checks
                    if plugin_name == 'contact-form-7' and self._is_version_less_than(plugin_version, '5.3.2'):
                        vulns.append({
                            'title': 'Contact Form 7 - Unrestricted File Upload',
                            'description': 'Contact Form 7 before 5.3.2 allows unrestricted file upload and remote code execution',
                            'severity': 'Critical',
                            'cve': 'CVE-2020-35489',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '5.3.2',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'cf7_file_upload'
                        })
                    elif plugin_name == 'wp-super-cache' and self._is_version_less_than(plugin_version, '1.7.2'):
                        vulns.append({
                            'title': 'WP Super Cache - Unauthenticated RCE',
                            'description': 'WP Super Cache before 1.7.2 allows unauthenticated remote code execution',
                            'severity': 'Critical',
                            'cve': 'CVE-2019-20041',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '1.7.2',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'wp_super_cache_rce'
                        })
                    elif plugin_name == 'wpdatatables' and self._is_version_less_than(plugin_version, '3.7.1'):
                        vulns.append({
                            'title': 'wpDataTables - SQL Injection Vulnerability',
                            'description': 'wpDataTables before 3.7.1 is vulnerable to SQL injection attacks',
                            'severity': 'Critical',
                            'cve': 'CVE-2023-26540',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '3.7.1',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'wpdatatables_sqli'
                        })
                    elif plugin_name == 'js_composer' and self._is_version_less_than(plugin_version, '6.5.0'):
                        vulns.append({
                            'title': 'WP Bakery Page Builder - Remote Code Execution',
                            'description': 'WP Bakery Page Builder (js_composer) before 6.5.0 is vulnerable to remote code execution',
                            'severity': 'Critical',
                            'cve': 'CVE-2021-34397',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '6.5.0',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'wp_bakery_rce'
                        })
                    elif plugin_name == 'elementor-pro' and self._is_version_less_than(plugin_version, '3.13.4'):
                        vulns.append({
                            'title': 'Elementor Pro - Remote Code Execution',
                            'description': 'Elementor Pro before 3.13.4 allows unauthorized users to upload arbitrary files, leading to remote code execution',
                            'severity': 'Critical',
                            'cve': 'CVE-2023-3490',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '3.13.4',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'elementor_rce'
                        })
                    elif plugin_name == 'wp-fastest-cache' and self._is_version_less_than(plugin_version, '0.9.5'):
                        vulns.append({
                            'title': 'WP Fastest Cache - Unauthenticated RCE',
                            'description': 'WP Fastest Cache before 0.9.5 allows unauthenticated users to delete arbitrary files and upload malicious code',
                            'severity': 'Critical',
                            'cve': 'CVE-2021-24869',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '0.9.5',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'wp_fastest_cache_rce'
                        })
                    elif plugin_name == 'wordfence' and self._is_version_less_than(plugin_version, '7.5.11'):
                        vulns.append({
                            'title': 'Wordfence - Authenticated RCE',
                            'description': 'Wordfence before 7.5.11 is vulnerable to authenticated remote code execution via file upload',
                            'severity': 'High',
                            'cve': 'CVE-2022-24947',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '7.5.11',
                            'exploitability': 'Medium',
                            'exploit_available': True,
                            'exploit_method': 'wordfence_rce'
                        })
                    elif plugin_name == 'woocommerce' and self._is_version_less_than(plugin_version, '5.5.1'):
                        vulns.append({
                            'title': 'WooCommerce Arbitrary File Download',
                            'description': 'WooCommerce before 5.5.1 is vulnerable to arbitrary file download via the product reviews logs',
                            'severity': 'High',
                            'cve': 'CVE-2021-32620',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '5.5.1',
                            'exploitability': 'Medium',
                            'exploit_available': True,
                            'exploit_method': 'woocommerce_file_download'
                        })
                    elif plugin_name == 'woocommerce' and self._is_version_less_than(plugin_version, '4.6.2'):
                        vulns.append({
                            'title': 'WooCommerce SQL Injection',
                            'description': 'WooCommerce before 4.6.2 is vulnerable to SQL injection in the Orders table functionality',
                            'severity': 'Critical',
                            'cve': 'CVE-2021-32052',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '4.6.2',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'woocommerce_sqli'
                        })
                    
                    # Check for WooCommerce Product Import Export vulnerability
                    elif (plugin_name == 'woocommerce-product-import-export' or 
                          plugin_name == 'product-import-export-for-woo') and self._is_version_less_than(plugin_version, '3.3.5'):
                        vulns.append({
                            'title': 'WooCommerce Product Import Export RCE',
                            'description': 'WooCommerce Product Import Export before 3.3.5 is vulnerable to formula injection in CSV files leading to remote code execution',
                            'severity': 'Critical',
                            'cve': 'CVE-2021-4095',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '3.3.5',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'woocommerce_product_rce'
                        })
                    
                    # Check for WooCommerce Checkout Field Editor vulnerability
                    elif plugin_name == 'woocommerce-checkout-field-editor' and self._is_version_less_than(plugin_version, '2.0.3'):
                        vulns.append({
                            'title': 'WooCommerce Checkout Field Editor Vulnerability',
                            'description': 'WooCommerce Checkout Field Editor before 2.0.3 allows unauthorized users to access and modify checkout fields',
                            'severity': 'High',
                            'cve': 'CVE-2022-0409',
                            'type': 'Plugin',
                            'plugin': plugin_name,
                            'affected_version': plugin_version,
                            'fixed_in': '2.0.3',
                            'exploitability': 'Medium',
                            'exploit_available': True,
                            'exploit_method': 'woocommerce_checkout_vulnerability'
                        })
        except Exception:
            pass
        
        # Check for common plugin security issues
        # Example: Check if plugin directory listing is enabled
        try:
            plugin_dir_url = f"{self.target}/wp-content/plugins/{plugin_name}/"
            response = self.session.get(plugin_dir_url, headers=self.headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200 and 'Index of' in response.text:
                vulns.append({
                    'title': f'{plugin_name} - Directory Listing Enabled',
                    'description': f'The {plugin_name} plugin directory has directory listing enabled which could expose sensitive information',
                    'severity': 'Low',
                    'cve': 'N/A',
                    'type': 'Plugin',
                    'plugin': plugin_name,
                    'affected_version': 'All',
                    'fixed_in': 'N/A (requires server configuration)',
                    'exploitability': 'Low',
                    'exploit_available': False,
                    'exploit_method': None
                })
        except Exception:
            pass
        
        # Specific check for wpDataTables SQL injection
        if plugin_name == 'wpdatatables':
            try:
                # Test for SQL injection in tablepress_id parameter
                test_url = f"{self.target}/wp-admin/admin-ajax.php?action=get_wdtable&tablepress_id='+AND+1=1--"
                response = self.session.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                
                test_url2 = f"{self.target}/wp-admin/admin-ajax.php?action=get_wdtable&tablepress_id='+AND+1=2--"
                response2 = self.session.get(test_url2, headers=self.headers, timeout=self.timeout, verify=False)
                
                # If the responses are different, it might be vulnerable
                if response.status_code == 200 and response2.status_code == 200 and response.text != response2.text:
                    vulns.append({
                        'title': 'wpDataTables - SQL Injection in tablepress_id Parameter',
                        'description': 'The wpDataTables plugin is vulnerable to SQL injection via the tablepress_id parameter',
                        'severity': 'Critical',
                        'cve': 'CVE-2023-26540',
                        'type': 'Plugin',
                        'plugin': plugin_name,
                        'affected_version': 'Detected via active testing',
                        'fixed_in': '3.7.1',
                        'exploitability': 'High',
                        'exploit_available': True,
                        'exploit_method': 'wpdatatables_sqli'
                    })
            except Exception:
                pass
        
        return vulns
    
    def check_theme_vulns(self, themes):
        """Check theme vulnerabilities"""
        vulns = []
        
        if not themes:
            return []
        
        print_info(f"Checking {len(themes)} themes for vulnerabilities...")
        progress = ProgressBar(len(themes), prefix='Theme Scan:', suffix='Complete')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_theme = {executor.submit(self._check_theme_vuln, theme): theme for theme in themes}
            
            for future in concurrent.futures.as_completed(future_to_theme):
                theme = future_to_theme[future]
                progress.update()
                
                try:
                    theme_vulns = future.result()
                    if theme_vulns:
                        vulns.extend(theme_vulns)
                except Exception as e:
                    print_error(f"Error checking theme {theme}: {str(e)}")
        
        return vulns
    
    def _check_theme_vuln(self, theme):
        """Check if a specific theme is vulnerable"""
        vulns = []
        theme_name = theme.split(' ')[0]  # Remove version if present
        
        # Check theme in database
        if theme_name in self.theme_vulns_db:
            for vuln in self.theme_vulns_db[theme_name]:
                vulns.append({
                    'title': vuln.get('title', f'{theme_name} Theme Vulnerability'),
                    'description': vuln.get('description', 'No description available'),
                    'severity': vuln.get('severity', 'Unknown'),
                    'cve': vuln.get('cve', 'Unknown'),
                    'type': 'Theme',
                    'theme': theme_name,
                    'affected_version': vuln.get('affected_version', 'Unknown'),
                    'fixed_in': vuln.get('fixed_in', 'Unknown'),
                    'exploitability': vuln.get('exploitability', 'Unknown'),
                    'exploit_available': vuln.get('exploit_available', False),
                    'exploit_method': vuln.get('exploit_method', None)
                })
        
        # Perform additional active checks
        # Check for common theme vulnerabilities
        # Example: Check if theme has directory listing enabled
        try:
            theme_dir_url = f"{self.target}/wp-content/themes/{theme_name}/"
            response = self.session.get(theme_dir_url, headers=self.headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200 and 'Index of' in response.text:
                vulns.append({
                    'title': f'{theme_name} - Directory Listing Enabled',
                    'description': f'The {theme_name} theme directory has directory listing enabled which could expose sensitive information',
                    'severity': 'Low',
                    'cve': 'N/A',
                    'type': 'Theme',
                    'theme': theme_name,
                    'affected_version': 'All',
                    'fixed_in': 'N/A (requires server configuration)',
                    'exploitability': 'Low',
                    'exploit_available': False,
                    'exploit_method': None
                })
        except Exception:
            pass
        
        # Check for theme-specific vulnerabilities
        # Example: Check for TimThumb vulnerability (common in older themes)
        try:
            timthumb_paths = [
                f"{self.target}/wp-content/themes/{theme_name}/timthumb.php",
                f"{self.target}/wp-content/themes/{theme_name}/includes/timthumb.php",
                f"{self.target}/wp-content/themes/{theme_name}/scripts/timthumb.php",
                f"{self.target}/wp-content/themes/{theme_name}/lib/timthumb.php"
            ]
            
            for timthumb_url in timthumb_paths:
                response = self.session.get(timthumb_url, headers=self.headers, timeout=self.timeout, verify=False)
                
                if response.status_code == 200 and ('TimThumb' in response.text or 'timthumb' in response.text):
                    # Try to determine version
                    version_match = re.search(r'version\s*=\s*[\'"](\d+\.\d+\.?\d*)[\'"]', response.text, re.IGNORECASE)
                    if version_match and self._is_version_less_than(version_match.group(1), '2.0'):
                        vulns.append({
                            'title': f'{theme_name} - TimThumb RCE Vulnerability',
                            'description': 'The theme uses TimThumb script which has a known remote code execution vulnerability in versions before 2.0',
                            'severity': 'Critical',
                            'cve': 'CVE-2011-4106',
                            'type': 'Theme',
                            'theme': theme_name,
                            'affected_version': version_match.group(1) if version_match else 'Unknown',
                            'fixed_in': '2.0',
                            'exploitability': 'High',
                            'exploit_available': True,
                            'exploit_method': 'timthumb_rce'
                        })
                        break
        except Exception:
            pass
        
        return vulns
    
    def _is_version_affected(self, detected_version, affected_versions):
        """
        Determines if the detected version is affected by the vulnerability
        
        Args:
            detected_version (str): The detected version of the plugin/theme
            affected_versions (list): List of affected version ranges
            
        Returns:
            bool: True if the version is affected, False otherwise
        """
        try:
            if not affected_versions:
                # If no affected versions are specified, assume it's affected
                return True

            from packaging import version
            
            # Parse the detected version
            try:
                parsed_version = version.parse(detected_version)
            except:
                # If we can't parse the version, be cautious and return True
                print_verbose(f"Could not parse version {detected_version}, assuming vulnerable")
                return True
            
            for ver_range in affected_versions:
                # Handle different version range formats
                if '-' in ver_range:
                    # Range like "1.0.0-2.0.0"
                    start_ver, end_ver = ver_range.split('-')
                    
                    try:
                        start = version.parse(start_ver.strip())
                        end = version.parse(end_ver.strip())
                        
                        if start <= parsed_version <= end:
                            return True
                    except Exception as e:
                        print_verbose(f"Error parsing version range {ver_range}: {str(e)}")
                        continue
                
                elif ver_range.startswith('<='):
                    # Range like "<=2.0.0"
                    try:
                        max_ver = version.parse(ver_range[2:].strip())
                        if parsed_version <= max_ver:
                            return True
                    except Exception as e:
                        print_verbose(f"Error parsing version range {ver_range}: {str(e)}")
                        continue
                
                elif ver_range.startswith('<'):
                    # Range like "<2.0.0"
                    try:
                        max_ver = version.parse(ver_range[1:].strip())
                        if parsed_version < max_ver:
                            return True
                    except Exception as e:
                        print_verbose(f"Error parsing version range {ver_range}: {str(e)}")
                        continue
                
                elif ver_range.startswith('>='):
                    # Range like ">=1.0.0"
                    try:
                        min_ver = version.parse(ver_range[2:].strip())
                        if parsed_version >= min_ver:
                            return True
                    except Exception as e:
                        print_verbose(f"Error parsing version range {ver_range}: {str(e)}")
                        continue
                
                elif ver_range.startswith('>'):
                    # Range like ">1.0.0"
                    try:
                        min_ver = version.parse(ver_range[1:].strip())
                        if parsed_version > min_ver:
                            return True
                    except Exception as e:
                        print_verbose(f"Error parsing version range {ver_range}: {str(e)}")
                        continue
                
                else:
                    # Exact version match
                    try:
                        if parsed_version == version.parse(ver_range.strip()):
                            return True
                    except Exception as e:
                        print_verbose(f"Error parsing version {ver_range}: {str(e)}")
                        continue
            
            return False
                
        except Exception as e:
            print_verbose(f"Error in version comparison: {str(e)}")
            # If there's any error, be cautious and assume it's vulnerable
            return True
    
    def _is_version_less_than(self, version1, version2):
        """Check if version1 is less than version2"""
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        # Pad shorter version with zeros
        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)
        
        for i in range(len(v1_parts)):
            if v1_parts[i] < v2_parts[i]:
                return True
            elif v1_parts[i] > v2_parts[i]:
                return False
        
        return False
    
    def _is_version_less_than_or_equal(self, version1, version2):
        """Check if version1 is less than or equal to version2"""
        return version1 == version2 or self._is_version_less_than(version1, version2)
    
    def _is_version_greater_than(self, version1, version2):
        """Check if version1 is greater than version2"""
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        # Pad shorter version with zeros
        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)
        
        for i in range(len(v1_parts)):
            if v1_parts[i] > v2_parts[i]:
                return True
            elif v1_parts[i] < v2_parts[i]:
                return False
        
        return False
    
    def _is_version_greater_than_or_equal(self, version1, version2):
        """Check if version1 is greater than or equal to version2"""
        return version1 == version2 or self._is_version_greater_than(version1, version2)
    
    def _get_plugin_version(self, plugin_slug):
        """
        Enhanced method to detect plugin version using multiple techniques
        Returns the detected version or None if not found
        """
        version = None
        
        # List of all techniques we'll try for version detection
        techniques = [
            self._get_version_from_readme,
            self._get_version_from_js,
            self._get_version_from_css,
            self._get_version_from_changelog,
            self._get_version_from_meta
        ]
        
        for technique in techniques:
            try:
                detected_version = technique(plugin_slug)
                if detected_version:
                    print_verbose(f"Detected {plugin_slug} version {detected_version} using {technique.__name__}")
                    version = detected_version
                    break
            except Exception as e:
                print_verbose(f"Error detecting version with {technique.__name__}: {str(e)}")
                continue
        
        return version
    
    def _get_version_from_readme(self, plugin_slug):
        """Extract version from readme.txt"""
        readme_url = f"{self.target}/wp-content/plugins/{plugin_slug}/readme.txt"
        response = self.session.get(readme_url, headers=self.headers, timeout=self.timeout, verify=False)
        
        if response.status_code == 200:
            # Look for stable tag or version
            stable_tag_match = re.search(r'Stable tag:\s*([0-9.]+)', response.text, re.IGNORECASE)
            version_match = re.search(r'Version:\s*([0-9.]+)', response.text, re.IGNORECASE)
            
            if stable_tag_match:
                return stable_tag_match.group(1)
            elif version_match:
                return version_match.group(1)
        
        return None
    
    def _get_version_from_js(self, plugin_slug):
        """Extract version from JS files"""
        # Try the main JS file if it exists
        js_url = f"{self.target}/wp-content/plugins/{plugin_slug}/js/{plugin_slug}.js"
        response = self.session.get(js_url, headers=self.headers, timeout=self.timeout, verify=False)
        
        if response.status_code == 200:
            # Look for version in JS comments or variables
            version_match = re.search(r'[Vv]ersion\s*[:=]\s*[\'"]([0-9.]+)[\'"]', response.text)
            if version_match:
                return version_match.group(1)
        
        # Try the main plugin file with .min.js extension
        minjs_url = f"{self.target}/wp-content/plugins/{plugin_slug}/js/{plugin_slug}.min.js"
        response = self.session.get(minjs_url, headers=self.headers, timeout=self.timeout, verify=False)
        
        if response.status_code == 200:
            version_match = re.search(r'[Vv]ersion\s*[:=]\s*[\'"]([0-9.]+)[\'"]', response.text)
            if version_match:
                return version_match.group(1)
        
        return None
    
    def _get_version_from_css(self, plugin_slug):
        """Extract version from CSS files"""
        css_url = f"{self.target}/wp-content/plugins/{plugin_slug}/css/{plugin_slug}.css"
        response = self.session.get(css_url, headers=self.headers, timeout=self.timeout, verify=False)
        
        if response.status_code == 200:
            # Look for version in CSS comments
            version_match = re.search(r'/\*\s*[Vv]ersion\s*:\s*([0-9.]+)\s*\*/', response.text)
            if version_match:
                return version_match.group(1)
        
        return None
    
    def _get_version_from_changelog(self, plugin_slug):
        """Extract version from changelog.txt or CHANGELOG.md"""
        for changelog_file in ['changelog.txt', 'CHANGELOG.txt', 'CHANGELOG.md', 'changelog.md']:
            changelog_url = f"{self.target}/wp-content/plugins/{plugin_slug}/{changelog_file}"
            response = self.session.get(changelog_url, headers=self.headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                # Look for the latest version in the changelog
                version_match = re.search(r'[#=]\s*([0-9.]+)\s*[-–]', response.text)
                if version_match:
                    return version_match.group(1)
        
        return None
    
    def _get_version_from_meta(self, plugin_slug):
        """Extract version from plugin meta tags in the HTML"""
        homepage_url = self.target
        response = self.session.get(homepage_url, headers=self.headers, timeout=self.timeout, verify=False)
        
        if response.status_code == 200:
            # Try to find meta tags with plugin version info
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = soup.find_all('meta')
            
            # Look for generator tag with plugin info
            for tag in meta_tags:
                if tag.get('name') == 'generator':
                    content = tag.get('content', '')
                    if plugin_slug in content.lower():
                        version_match = re.search(r'([0-9.]+)', content)
                        if version_match:
                            return version_match.group(1)
            
            # Look for plugin-specific version comments or HTML
            plugin_marker = f"<!-- {plugin_slug} version"
            if plugin_marker.lower() in response.text.lower():
                version_match = re.search(f"{plugin_marker}[^0-9]*([0-9.]+)", response.text, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
        
        return None
    
    def scan(self, wp_info):
        """Scan WordPress for vulnerabilities"""
        results = {
            "core": {},
            "plugins": {},
            "themes": {}
        }
        
        print_info("[*] Checking for WordPress core vulnerabilities...")
        if "wp_version" in wp_info and wp_info["wp_version"]:
            results["core"] = self.check_wp_vulns(wp_info["wp_version"])
        else:
            print_warning("[!] WordPress version not found, skipping core vulnerability check")
        
        print_info("[*] Checking for vulnerable plugins...")
        if "plugins" in wp_info and wp_info["plugins"]:
            plugins_bar = ProgressBar(len(wp_info["plugins"]), "[*] Checking plugins")
            
            for plugin in wp_info["plugins"]:
                plugins_bar.step()
                
                # Use enhanced version detection for more accuracy
                detected_version = None
                
                # First check if we already have a version from the plugin detection
                if wp_info["plugins"][plugin].get("version"):
                    detected_version = wp_info["plugins"][plugin]["version"]
                    print_verbose(f"Using previously detected version for {plugin}: {detected_version}")
                
                # If no version was detected during plugin enumeration, try our enhanced detection
                if not detected_version:
                    detected_version = self._get_plugin_version(plugin)
                    
                    # If we found a version, update it in the wp_info structure
                    if detected_version:
                        wp_info["plugins"][plugin]["version"] = detected_version
                
                if detected_version:
                    print_verbose(f"Checking {plugin} version {detected_version} for vulnerabilities")
                    if plugin in self.plugin_vulns:
                        vulns = []
                        for vuln in self.plugin_vulns[plugin]:
                            if self._is_version_affected(detected_version, vuln.get("affected_versions", [])):
                                vulns.append(vuln)
                        
                        if vulns:
                            results["plugins"][plugin] = {
                                "version": detected_version,
                                "vulns": vulns
                            }
                else:
                    print_verbose(f"No version detected for plugin {plugin}")
            
            plugins_bar.finish()
        else:
            print_warning("[!] No plugins found, skipping plugin vulnerability check")
        
        print_info("[*] Checking for vulnerable themes...")
        if "themes" in wp_info and wp_info["themes"]:
            results["themes"] = self.check_theme_vulns(wp_info["themes"])
        else:
            print_warning("[!] No themes found, skipping theme vulnerability check")
        
        return results 