#!/usr/bin/env python3

import json
import os
import re
import sys
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from modules.utils import print_info, print_success, print_error, print_warning, print_verbose

class WPFingerprinter:
    def __init__(self, session, target, headers, timeout, output_dir):
        self.session = session
        self.target = target
        self.headers = headers
        self.timeout = timeout
        self.output_dir = output_dir
        
        # WordPress API endpoints for WP API v2
        self.api_url = f"{self.target}/wp-json/wp/v2"
        self.api_endpoints = {
            'posts': f"{self.api_url}/posts",
            'pages': f"{self.api_url}/pages",
            'users': f"{self.api_url}/users",
            'categories': f"{self.api_url}/categories",
            'tags': f"{self.api_url}/tags"
        }
        
        # Common WordPress files and paths
        self.wp_paths = [
            '/wp-login.php',
            '/wp-admin/',
            '/wp-content/',
            '/wp-includes/',
            '/xmlrpc.php',
            '/wp-cron.php',
            '/wp-config.php',
            '/wp-json/'
        ]
        
    def is_wordpress(self):
        """Check if the target is running WordPress"""
        print_info("Checking if target is running WordPress...")
        
        # Method 1: Check for WordPress common paths
        for path in self.wp_paths[:4]:  # Only check the first few common paths
            try:
                url = self.target + path
                response = self.session.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    print_success(f"WordPress path found: {path}")
                    return True
            except Exception as e:
                print_verbose(f"Error checking {path}: {str(e)}")
        
        # Method 2: Check HTML source for WordPress indicators
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                html = response.text.lower()
                
                # Check for WordPress indicators in HTML
                wp_indicators = [
                    'wp-content',
                    'wp-includes',
                    'wordpress',
                    'generator" content="wordpress'
                ]
                
                for indicator in wp_indicators:
                    if indicator in html:
                        print_success(f"WordPress indicator found: {indicator}")
                        return True
                
                # Check for WordPress in generator meta tag
                soup = BeautifulSoup(response.text, 'html.parser')
                meta_generator = soup.find('meta', {'name': 'generator'})
                if meta_generator and 'wordpress' in meta_generator.get('content', '').lower():
                    print_success("WordPress detected in meta generator tag")
                    return True
        except Exception as e:
            print_error(f"Error checking main page: {str(e)}")
        
        # Method 3: Check for WP API
        try:
            response = self.session.get(self.api_url, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                print_success("WordPress API detected")
                return True
        except Exception as e:
            print_verbose(f"Error checking WP API: {str(e)}")
        
        return False
    
    def get_version(self):
        """Get WordPress version"""
        version = None
        version_sources = []
        
        # Method 1: Check meta generator tag
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                meta_generator = soup.find('meta', {'name': 'generator'})
                
                if meta_generator and 'wordpress' in meta_generator.get('content', '').lower():
                    meta_version = re.search(r'WordPress (\d+\.\d+\.?\d*)', meta_generator['content'])
                    if meta_version:
                        version = meta_version.group(1)
                        version_sources.append("meta generator tag")
        except Exception as e:
            print_verbose(f"Error getting version from meta tag: {str(e)}")
        
        # Method 2: Check readme.html
        if not version:
            try:
                readme_url = f"{self.target}/readme.html"
                response = self.session.get(readme_url, headers=self.headers, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    version_text = soup.find(text=re.compile(r'Version \d+\.\d+'))
                    
                    if version_text:
                        version_match = re.search(r'Version (\d+\.\d+\.?\d*)', version_text)
                        if version_match:
                            version = version_match.group(1)
                            version_sources.append("readme.html")
            except Exception as e:
                print_verbose(f"Error getting version from readme.html: {str(e)}")
        
        # Method 3: Check feed
        if not version:
            try:
                feed_url = f"{self.target}/feed/"
                response = self.session.get(feed_url, headers=self.headers, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'xml')
                    generator = soup.find('generator')
                    
                    if generator and 'wordpress' in generator.text.lower():
                        version_match = re.search(r'wordpress\.org/\?v=(\d+\.\d+\.?\d*)', generator.text)
                        if version_match:
                            version = version_match.group(1)
                            version_sources.append("RSS feed")
            except Exception as e:
                print_verbose(f"Error getting version from feed: {str(e)}")
        
        return version, version_sources
    
    def get_theme(self):
        """Get WordPress theme information"""
        themes = []
        
        # Method 1: Check HTML source
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # Look for theme info in HTML
                theme_patterns = [
                    r'/wp-content/themes/([^/]+)/',
                    r'themes/([^/]+)/style\.css'
                ]
                
                for pattern in theme_patterns:
                    matches = re.findall(pattern, response.text)
                    themes.extend(matches)
                
                # Remove duplicates
                themes = list(set(themes))
                
                # Check if theme has style.css with version info
                for theme in themes:
                    try:
                        style_url = f"{self.target}/wp-content/themes/{theme}/style.css"
                        style_response = self.session.get(style_url, headers=self.headers, timeout=self.timeout, verify=False)
                        
                        if style_response.status_code == 200:
                            # Extract theme version if available
                            version_match = re.search(r'Version:\s*(\d+\.\d+\.?\d*)', style_response.text)
                            if version_match:
                                theme_version = version_match.group(1)
                                theme_index = themes.index(theme)
                                themes[theme_index] = f"{theme} (v{theme_version})"
                    except Exception:
                        pass
        except Exception as e:
            print_verbose(f"Error getting theme info: {str(e)}")
        
        return themes
    
    def get_plugins(self):
        """Get WordPress plugins information"""
        plugins = []
        
        # Method 1: Check for plugin paths in HTML and JS files
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # Look for plugin info in HTML
                plugin_pattern = r'/wp-content/plugins/([^/]+)/'
                matches = re.findall(plugin_pattern, response.text)
                plugins.extend(matches)
                
                # Check for plugin references in JavaScript files
                soup = BeautifulSoup(response.text, 'html.parser')
                scripts = soup.find_all('script', src=True)
                
                for script in scripts:
                    if 'wp-content' in script['src']:
                        try:
                            js_url = script['src']
                            if not js_url.startswith(('http://', 'https://')):
                                if js_url.startswith('//'):
                                    js_url = 'https:' + js_url
                                elif js_url.startswith('/'):
                                    js_url = urljoin(self.target, js_url)
                                else:
                                    js_url = urljoin(self.target, '/' + js_url)
                            
                            js_response = self.session.get(js_url, headers=self.headers, timeout=self.timeout, verify=False)
                            if js_response.status_code == 200:
                                plugin_matches = re.findall(plugin_pattern, js_response.text)
                                plugins.extend(plugin_matches)
                        except Exception:
                            pass
                
                # Remove duplicates
                plugins = list(set(plugins))
        except Exception as e:
            print_verbose(f"Error getting plugin info: {str(e)}")
        
        return plugins
    
    def enumerate_users(self):
        """Enumerate WordPress users"""
        users = []
        
        # Method 1: Check WP API
        try:
            response = self.session.get(self.api_endpoints['users'], headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                api_users = response.json()
                for user in api_users:
                    if 'name' in user and 'id' in user:
                        users.append({
                            'id': user['id'],
                            'name': user['name'],
                            'slug': user.get('slug', ''),
                            'role': user.get('roles', ['unknown'])[0] if 'roles' in user else 'unknown'
                        })
        except Exception as e:
            print_verbose(f"Error enumerating users via API: {str(e)}")
        
        # Method 2: Check author archives
        if not users:
            try:
                for i in range(1, 11):  # Try the first 10 author IDs
                    author_url = f"{self.target}/?author={i}"
                    response = self.session.get(author_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200:
                        # Check for author in URL (redirect)
                        author_pattern = r'/author/([^/]+)/'
                        matches = re.findall(author_pattern, response.url)
                        
                        if matches:
                            users.append({
                                'id': i,
                                'name': 'Unknown',
                                'slug': matches[0],
                                'role': 'unknown'
                            })
                            
                            # Try to get name from page
                            soup = BeautifulSoup(response.text, 'html.parser')
                            title = soup.find('title')
                            if title:
                                name_match = re.search(r'Author: (.+) |', title.text)
                                if name_match:
                                    users[-1]['name'] = name_match.group(1).strip()
            except Exception as e:
                print_verbose(f"Error enumerating users via author pages: {str(e)}")
        
        return users
    
    def fingerprint(self):
        """Fingerprint WordPress installation"""
        wp_info = {}
        
        # Get WordPress version
        version, version_sources = self.get_version()
        if version:
            wp_info['version'] = version
            wp_info['version_sources'] = version_sources
        else:
            wp_info['version'] = 'Unknown'
            wp_info['version_sources'] = []
        
        # Get WordPress theme
        themes = self.get_theme()
        if themes:
            wp_info['themes'] = themes
        else:
            wp_info['themes'] = ['Unknown']
        
        # Get WordPress plugins
        plugins = self.get_plugins()
        if plugins:
            wp_info['plugins'] = plugins
        else:
            wp_info['plugins'] = []
        
        # Enumerate users
        users = self.enumerate_users()
        if users:
            wp_info['users'] = users
        else:
            wp_info['users'] = []
        
        # Check if xmlrpc.php is enabled
        try:
            xmlrpc_url = f"{self.target}/xmlrpc.php"
            response = self.session.get(xmlrpc_url, headers=self.headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200 and 'XML-RPC server accepts POST requests only' in response.text:
                wp_info['xmlrpc_enabled'] = True
            else:
                wp_info['xmlrpc_enabled'] = False
        except Exception:
            wp_info['xmlrpc_enabled'] = False
        
        # Check if REST API is enabled
        try:
            response = self.session.get(self.api_url, headers=self.headers, timeout=self.timeout, verify=False)
            wp_info['rest_api_enabled'] = response.status_code == 200
        except Exception:
            wp_info['rest_api_enabled'] = False
        
        return wp_info 