#!/usr/bin/env python3
# WP-Scanner - Updater module
# This module handles updates for both the tool and vulnerability databases

import os
import sys
import json
import subprocess
import time
import requests
import shutil
import tempfile
import zipfile
from datetime import datetime
from packaging import version
from colorama import Fore, Style

class Updater:
    """Handles updates for the WP-Scanner tool and vulnerability databases"""
    
    def __init__(self, db_path=None):
        # Load version info
        self.version_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "version.json")
        self.version_info = self._load_version_info()
        self.current_version = self.version_info.get("version", "1.0.0")
        self.repo_url = self.version_info.get("repository", "https://github.com/Triotion/wp-scanner")
        self.latest_version_url = self.version_info.get("latest_version_url", 
                                 "https://raw.githubusercontent.com/Triotion/wp-scanner/master/version.json")
        # Use correct path for vulnerability databases
        self.db_path = db_path or os.path.join("data")
        
        # Create database directory if it doesn't exist
        if not os.path.exists(self.db_path):
            os.makedirs(self.db_path, exist_ok=True)
    
    def _load_version_info(self):
        """Load version information from version.json file"""
        try:
            if os.path.exists(self.version_file):
                with open(self.version_file, "r") as f:
                    return json.load(f)
            else:
                print(f"{Fore.YELLOW}[!] Version file not found. Using default version.{Style.RESET_ALL}")
                return {"version": "1.0.0"}
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading version info: {str(e)}{Style.RESET_ALL}")
            return {"version": "1.0.0"}
    
    def _save_version_info(self, version_info):
        """Save version information to version.json file"""
        try:
            with open(self.version_file, "w") as f:
                json.dump(version_info, f, indent=4)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving version info: {str(e)}{Style.RESET_ALL}")
            return False
    
    def check_for_updates(self):
        """Check if updates are available for the tool
        
        Returns:
            bool: True if updates are available, False otherwise
        """
        print(f"{Fore.BLUE}[*] Checking for tool updates...{Style.RESET_ALL}")
        
        try:
    
            print(f"{Fore.BLUE}[*] Current version: {self.current_version}{Style.RESET_ALL}")
            
            try:
                # Try to get the latest version info from the repository
                response = requests.get(self.latest_version_url, timeout=10)
                if response.status_code == 200:
                    latest_info = response.json()
                    latest_version = latest_info.get("version", "0.0.0")
                    
                    print(f"{Fore.BLUE}[*] Latest version: {latest_version}{Style.RESET_ALL}")
                    
                    # Compare versions using the packaging module
                    if version.parse(latest_version) > version.parse(self.current_version):
                        print(f"{Fore.GREEN}[+] New version available: {latest_version}{Style.RESET_ALL}")
                        return True
                    else:
                        print(f"{Fore.GREEN}[+] You are running the latest version.{Style.RESET_ALL}")
                        return False
                else:
                    # If we can't reach the remote, just assume there might be an update
                    print(f"{Fore.YELLOW}[!] Could not check latest version. Status code: {response.status_code}{Style.RESET_ALL}")
                    return True
            
            except requests.RequestException as e:
                print(f"{Fore.YELLOW}[!] Network error checking for updates: {str(e)}{Style.RESET_ALL}")
                # For demonstration, we'll simulate that an update is available
                return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking for updates: {str(e)}{Style.RESET_ALL}")
            return False
    
    def _get_user_confirmation(self, message="Do you want to update? (y/n): "):
        """Get user confirmation for updates
        
        Returns:
            bool: True if user confirmed, False otherwise
        """
        while True:
            try:
                response = input(f"{Fore.YELLOW}{message}{Style.RESET_ALL}").strip().lower()
                if response in ["y", "yes"]:
                    return True
                elif response in ["n", "no"]:
                    return False
                else:
                    print(f"{Fore.YELLOW}[!] Please enter 'y' for yes or 'n' for no.{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Update canceled by user.{Style.RESET_ALL}")
                return False
    
    def update_tool(self):
        """Update the tool to the latest version
        
        Returns:
            dict: Result of the update operation
        """
        print(f"{Fore.BLUE}[*] Checking for WP-Scanner updates...{Style.RESET_ALL}")
        
        result = {
            "success": False,
            "message": "",
            "old_version": self.current_version,
            "new_version": self.current_version
        }
        
        # First check if update is needed
        try:
            response = requests.get(self.latest_version_url, timeout=10)
            if response.status_code == 200:
                latest_info = response.json()
                latest_version = latest_info.get("version", "0.0.0")
                
                # If no update is needed, return success
                if version.parse(latest_version) <= version.parse(self.current_version):
                    result["success"] = True
                    result["message"] = "Already up to date."
                    print(f"{Fore.GREEN}[+] Already running the latest version ({self.current_version}).{Style.RESET_ALL}")
                    return result
                
                # Set the new version for return value
                result["new_version"] = latest_version
                
                # Ask for user confirmation
                print(f"{Fore.YELLOW}[!] New version ({latest_version}) available. Current version: {self.current_version}{Style.RESET_ALL}")
                if not self._get_user_confirmation():
                    result["message"] = "Update canceled by user."
                    print(f"{Fore.YELLOW}[!] Update canceled by user.{Style.RESET_ALL}")
                    return result
                
                print(f"{Fore.BLUE}[*] Updating WP-Scanner...{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Could not fetch latest version info. Status code: {response.status_code}{Style.RESET_ALL}")
                
                # Ask for forced update
                if not self._get_user_confirmation("Could not check latest version. Force update anyway? (y/n): "):
                    result["message"] = "Update canceled by user."
                    print(f"{Fore.YELLOW}[!] Update canceled by user.{Style.RESET_ALL}")
                    return result
        
        except requests.RequestException as e:
            print(f"{Fore.YELLOW}[!] Network error fetching latest version: {str(e)}{Style.RESET_ALL}")
            
            # Ask for forced update
            if not self._get_user_confirmation("Could not check latest version. Force update anyway? (y/n): "):
                result["message"] = "Update canceled by user."
                print(f"{Fore.YELLOW}[!] Update canceled by user.{Style.RESET_ALL}")
                return result
        
        # Try to update using git clone
        try:
            print(f"{Fore.BLUE}[*] Updating via git clone...{Style.RESET_ALL}")
            
            # Create a temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone the repository to the temporary directory
                print(f"{Fore.BLUE}[*] Cloning repository from {self.repo_url}...{Style.RESET_ALL}")
                clone_process = subprocess.run(
                    ["git", "clone", self.repo_url, temp_dir],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if clone_process.returncode != 0:
                    print(f"{Fore.RED}[-] Git clone failed: {clone_process.stderr}{Style.RESET_ALL}")
                    raise subprocess.SubprocessError("Git clone failed")
                
                # Get the current directory (where our tool is installed)
                current_dir = os.path.dirname(self.version_file)
                
                # Backup the data directory
                data_backup_path = None
                if os.path.exists(os.path.join(current_dir, "data")):
                    data_backup_path = os.path.join(tempfile.gettempdir(), f"wp_scanner_data_backup_{int(time.time())}")
                    print(f"{Fore.BLUE}[*] Backing up data directory to {data_backup_path}...{Style.RESET_ALL}")
                    shutil.copytree(os.path.join(current_dir, "data"), data_backup_path)
                
                # Copy files from the cloned repository to the current directory
                print(f"{Fore.BLUE}[*] Updating files...{Style.RESET_ALL}")
                for item in os.listdir(temp_dir):
                    src_path = os.path.join(temp_dir, item)
                    dst_path = os.path.join(current_dir, item)
                    
                    # Skip the data directory to preserve user data
                    if item == "data" and os.path.exists(dst_path):
                        continue
                    
                    # Skip the version.json file if it exists (keep current version info)
                    if item == "version.json" and os.path.exists(dst_path):
                        continue
                    
                    # Remove existing file/directory
                    if os.path.exists(dst_path):
                        if os.path.isdir(dst_path):
                            shutil.rmtree(dst_path)
                        else:
                            os.remove(dst_path)
                    
                    # Copy new file/directory
                    if os.path.isdir(src_path):
                        shutil.copytree(src_path, dst_path)
                    else:
                        shutil.copy2(src_path, dst_path)
                
                # Restore the data directory if it was backed up
                if data_backup_path and os.path.exists(data_backup_path):
                    # Only restore files that don't exist in the current data directory
                    data_dir = os.path.join(current_dir, "data")
                    if not os.path.exists(data_dir):
                        os.makedirs(data_dir)
                    
                    for root, dirs, files in os.walk(data_backup_path):
                        # Get relative path from the backup directory
                        rel_path = os.path.relpath(root, data_backup_path)
                        
                        # Create directories in the current data directory
                        if rel_path != '.':
                            os.makedirs(os.path.join(data_dir, rel_path), exist_ok=True)
                        
                        # Copy files
                        for file in files:
                            src_file = os.path.join(root, file)
                            dst_file = os.path.join(data_dir, rel_path, file)
                            
                            # Only copy if file doesn't exist or is a database file
                            if not os.path.exists(dst_file) or file.endswith("_vulns.json"):
                                shutil.copy2(src_file, dst_file)
                
                # Update version info with the new version
                try:
                    temp_version_file = os.path.join(temp_dir, "version.json")
                    if os.path.exists(temp_version_file):
                        with open(temp_version_file, "r") as f:
                            new_version_info = json.load(f)
                            new_version = new_version_info.get("version", latest_version or "1.0.0")
                            
                            # Update our version info
                            self.version_info["version"] = new_version
                            self.version_info["last_updated"] = datetime.now().strftime("%Y-%m-%d")
                            
                            # Save the updated version info
                            self._save_version_info(self.version_info)
                            
                            # Update the current version
                            self.current_version = new_version
                            result["new_version"] = new_version
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error updating version info: {str(e)}{Style.RESET_ALL}")
                
                # Update successful
                result["success"] = True
                result["message"] = f"Successfully updated to version {result['new_version']} via git clone"
                print(f"{Fore.GREEN}[+] Successfully updated WP-Scanner to version {result['new_version']}{Style.RESET_ALL}")
                
                return result
                
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            print(f"{Fore.YELLOW}[!] Git clone failed: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Falling back to direct download...{Style.RESET_ALL}")
        
        # If git clone failed, try direct download
        try:
            # Download the latest release zip
            zip_url = f"{self.repo_url}/archive/refs/heads/main.zip"
            print(f"{Fore.BLUE}[*] Downloading latest version from {zip_url}{Style.RESET_ALL}")
            
            try:
                response = requests.get(zip_url, stream=True, timeout=30)
                if response.status_code != 200:
                    result["message"] = f"Failed to download latest version. Status code: {response.status_code}"
                    print(f"{Fore.RED}[-] {result['message']}{Style.RESET_ALL}")
                    return result
                
                # Create a temporary directory for the download
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Save the zip file
                    zip_path = os.path.join(temp_dir, "wp-scanner.zip")
                    with open(zip_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    print(f"{Fore.BLUE}[*] Extracting files...{Style.RESET_ALL}")
                    
                    # Extract the zip file
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                    
                    # Find the extracted directory (usually repo_name-branch)
                    extracted_dirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
                    if not extracted_dirs:
                        result["message"] = "Extraction failed: No directories found in zip file"
                        print(f"{Fore.RED}[-] {result['message']}{Style.RESET_ALL}")
                        return result
                    
                    extracted_dir = os.path.join(temp_dir, extracted_dirs[0])
                    
                    # Get the current directory (where our tool is installed)
                    current_dir = os.path.dirname(self.version_file)
                    
                    # Backup the data directory
                    data_backup_path = None
                    if os.path.exists(os.path.join(current_dir, "data")):
                        data_backup_path = os.path.join(tempfile.gettempdir(), f"wp_scanner_data_backup_{int(time.time())}")
                        print(f"{Fore.BLUE}[*] Backing up data directory to {data_backup_path}...{Style.RESET_ALL}")
                        shutil.copytree(os.path.join(current_dir, "data"), data_backup_path)
                    
                    # Copy all files from the extracted directory to the current directory
                    print(f"{Fore.BLUE}[*] Updating files...{Style.RESET_ALL}")
                    for item in os.listdir(extracted_dir):
                        src_path = os.path.join(extracted_dir, item)
                        dst_path = os.path.join(current_dir, item)
                        
                        # Skip the data directory to preserve user data
                        if item == "data" and os.path.exists(dst_path):
                            continue
                        
                        # Skip the version.json file if it exists (keep current version info)
                        if item == "version.json" and os.path.exists(dst_path):
                            continue
                        
                        # Remove existing file/directory
                        if os.path.exists(dst_path):
                            if os.path.isdir(dst_path):
                                shutil.rmtree(dst_path)
                            else:
                                os.remove(dst_path)
                        
                        # Copy new file/directory
                        if os.path.isdir(src_path):
                            shutil.copytree(src_path, dst_path)
                        else:
                            shutil.copy2(src_path, dst_path)
                    
                    # Restore the data directory if it was backed up
                    if data_backup_path and os.path.exists(data_backup_path):
                        # Only restore files that don't exist in the current data directory
                        data_dir = os.path.join(current_dir, "data")
                        if not os.path.exists(data_dir):
                            os.makedirs(data_dir)
                        
                        for root, dirs, files in os.walk(data_backup_path):
                            # Get relative path from the backup directory
                            rel_path = os.path.relpath(root, data_backup_path)
                            
                            # Create directories in the current data directory
                            if rel_path != '.':
                                os.makedirs(os.path.join(data_dir, rel_path), exist_ok=True)
                            
                            # Copy files
                            for file in files:
                                src_file = os.path.join(root, file)
                                dst_file = os.path.join(data_dir, rel_path, file)
                                
                                # Only copy if file doesn't exist or is a database file
                                if not os.path.exists(dst_file) or file.endswith("_vulns.json"):
                                    shutil.copy2(src_file, dst_file)
                    
                    # Update version info with the new version
                    try:
                        temp_version_file = os.path.join(extracted_dir, "version.json")
                        if os.path.exists(temp_version_file):
                            with open(temp_version_file, "r") as f:
                                new_version_info = json.load(f)
                                new_version = new_version_info.get("version", latest_version or "1.0.0")
                                
                                # Update our version info
                                self.version_info["version"] = new_version
                                self.version_info["last_updated"] = datetime.now().strftime("%Y-%m-%d")
                                
                                # Save the updated version info
                                self._save_version_info(self.version_info)
                                
                                # Update the current version
                                self.current_version = new_version
                                result["new_version"] = new_version
                    except Exception as e:
                        print(f"{Fore.YELLOW}[!] Error updating version info: {str(e)}{Style.RESET_ALL}")
                    
                    # Update successful
                    result["success"] = True
                    result["message"] = f"Successfully updated to version {result['new_version']} via direct download"
                    print(f"{Fore.GREEN}[+] Successfully updated WP-Scanner to version {result['new_version']}{Style.RESET_ALL}")
                    
                    return result
            
            except requests.RequestException as e:
                result["message"] = f"Download failed: {str(e)}"
                print(f"{Fore.RED}[-] {result['message']}{Style.RESET_ALL}")
                return result
        
        except Exception as e:
            result["message"] = f"Unexpected error during update: {str(e)}"
            print(f"{Fore.RED}[-] {result['message']}{Style.RESET_ALL}")
            return result
    
    def update_vulnerability_databases(self):
        """Update the vulnerability databases
        
        Returns:
            dict: Result of the database update operation
        """
        print(f"{Fore.BLUE}[*] Updating vulnerability databases...{Style.RESET_ALL}")
        
        result = {
            "success": False,
            "message": "",
            "updated": []
        }
        
        try:
           
            database_urls = {
                "wordpress_vulns.json": "https://raw.githubusercontent.com/Triotion/WP-Scanner/refs/heads/main/data/wordpress_vulns.json",
                "plugins_vulns.json": "https://raw.githubusercontent.com/Triotion/WP-Scanner/refs/heads/main/data/plugins_vulns.json",
                "themes_vulns.json": "https://raw.githubusercontent.com/Triotion/WP-Scanner/refs/heads/main/data/themes_vulns.json"
            }
            
            for db_name, url in database_urls.items():
                db_path = os.path.join(self.db_path, db_name)
                
                
                try:
                    
                    print(f"{Fore.BLUE}[*] Downloading {db_name}...{Style.RESET_ALL}")
                    
                    
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        # Create or update the database file
                        with open(db_path, 'w') as f:
                            try:
                                # Try to parse as JSON
                                json_data = response.json()
                                json.dump(json_data, f, indent=4)
                            except:
                                # If not JSON, just write the content
                                f.write(response.text)
                        
                        result["updated"].append(db_name)
                        print(f"{Fore.GREEN}[+] Updated {db_name}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[-] Failed to download {db_name}. Status code: {response.status_code}{Style.RESET_ALL}")
                        
                        # Create a default file if it doesn't exist
                        if not os.path.exists(db_path):
                            with open(db_path, 'w') as f:
                                default_data = {
                                    "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "vulnerabilities": []
                                }
                                json.dump(default_data, f, indent=4)
                            print(f"{Fore.YELLOW}[!] Created default {db_name}{Style.RESET_ALL}")
                
                except Exception as e:
                    print(f"{Fore.RED}[-] Error updating {db_name}: {str(e)}{Style.RESET_ALL}")
                    
                    # Create a default file if it doesn't exist
                    if not os.path.exists(db_path):
                        with open(db_path, 'w') as f:
                            default_data = {
                                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "vulnerabilities": []
                            }
                            json.dump(default_data, f, indent=4)
                        print(f"{Fore.YELLOW}[!] Created default {db_name}{Style.RESET_ALL}")
            
            if result["updated"]:
                result["success"] = True
                result["message"] = f"Successfully updated {len(result['updated'])} databases"
            else:
                result["message"] = "No databases were updated"
            
        except Exception as e:
            result["message"] = f"Error updating databases: {str(e)}"
            print(f"{Fore.RED}[-] Error updating vulnerability databases: {str(e)}{Style.RESET_ALL}")
        
        return result
    
    def update_all(self):
        """Update both the tool and vulnerability databases
        
        Returns:
            tuple: (success, results) where success is a boolean and results is a dict
        """
        results = {
            "tool": {},
            "databases": {}
        }
        
        # Update the tool
        results["tool"] = self.update_tool()
        
        # Update the vulnerability databases
        results["databases"] = self.update_vulnerability_databases()
        
        # Overall success is determined by both operations
        success = results["tool"]["success"] and results["databases"]["success"]
        
        return success, results 