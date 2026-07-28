#!/usr/bin/env python3
"""Self-updater and vulnerability database updater for WP-Scanner."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime
from typing import Any

import requests
from colorama import Fore, Style
from packaging import version as pkg_version

from modules.utils import print_error, print_info, print_success, print_warning


class Updater:
    """Handles updates for the WP-Scanner tool and vulnerability databases."""

    def __init__(self, db_path: str | None = None) -> None:
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.version_file = os.path.join(self.project_root, "version.json")
        self.version_info = self._load_version_info()
        self.current_version: str = self.version_info.get("version", "1.0.0")
        self.repo_url: str = self.version_info.get(
            "repository", "https://github.com/Triotion/wp-scanner"
        )
        self.latest_version_url: str = self.version_info.get(
            "latest_version_url",
            "https://raw.githubusercontent.com/Triotion/wp-scanner/master/version.json",
        )
        self.db_path = db_path or os.path.join(self.project_root, "data")

        os.makedirs(self.db_path, exist_ok=True)

    def _load_version_info(self) -> dict[str, Any]:
        try:
            if os.path.exists(self.version_file):
                with open(self.version_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            print_warning("Version file not found. Using default version.")
            return {"version": "1.0.0"}
        except Exception as exc:
            print_error(f"Error loading version info: {exc}")
            return {"version": "1.0.0"}

    def _save_version_info(self, info: dict[str, Any]) -> bool:
        try:
            with open(self.version_file, "w", encoding="utf-8") as f:
                json.dump(info, f, indent=4)
            return True
        except Exception as exc:
            print_error(f"Error saving version info: {exc}")
            return False

    @staticmethod
    def _sha256_file(filepath: str) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def check_for_updates(self) -> bool:
        """Check if updates are available for the tool."""
        print_info("Checking for tool updates...")
        print_info(f"Current version: {self.current_version}")

        try:
            response = requests.get(self.latest_version_url, timeout=10, verify=False)
            if response.status_code == 200:
                latest_info = response.json()
                latest_version = latest_info.get("version", "0.0.0")
                print_info(f"Latest version: {latest_version}")

                if pkg_version.parse(latest_version) > pkg_version.parse(self.current_version):
                    print_success(f"New version available: {latest_version}")
                    return True
                else:
                    print_success("You are running the latest version.")
                    return False
            else:
                print_warning(f"Could not check latest version. Status code: {response.status_code}")
                return True
        except requests.RequestException as exc:
            print_warning(f"Network error checking for updates: {exc}")
            return True
        except Exception as exc:
            print_error(f"Error checking for updates: {exc}")
            return False

    def _get_user_confirmation(self, message: str = "Do you want to update? (y/n): ") -> bool:
        while True:
            try:
                response = input(f"{Fore.YELLOW}{message}{Style.RESET_ALL}").strip().lower()
                if response in ("y", "yes"):
                    return True
                if response in ("n", "no"):
                    return False
                print_warning("Please enter 'y' for yes or 'n' for no.")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Update canceled by user.{Style.RESET_ALL}")
                return False

    def update_tool(self) -> dict[str, Any]:
        """Update the tool to the latest version."""
        print_info("Checking for WP-Scanner updates...")

        result: dict[str, Any] = {
            "success": False,
            "message": "",
            "old_version": self.current_version,
            "new_version": self.current_version,
        }

        # Check for latest version
        latest_version: str | None = None
        try:
            response = requests.get(self.latest_version_url, timeout=10, verify=False)
            if response.status_code == 200:
                latest_info = response.json()
                latest_version = latest_info.get("version", "0.0.0")

                if pkg_version.parse(latest_version) <= pkg_version.parse(self.current_version):
                    result["success"] = True
                    result["message"] = "Already up to date."
                    print_success(f"Already running the latest version ({self.current_version}).")
                    return result

                result["new_version"] = latest_version
                print_warning(f"New version ({latest_version}) available. Current: {self.current_version}")
                if not self._get_user_confirmation():
                    result["message"] = "Update canceled by user."
                    return result
            else:
                print_warning(f"Could not fetch latest version info. Status: {response.status_code}")
                if not self._get_user_confirmation("Could not check latest version. Force update? (y/n): "):
                    result["message"] = "Update canceled by user."
                    return result
        except requests.RequestException as exc:
            print_warning(f"Network error fetching latest version: {exc}")
            if not self._get_user_confirmation("Could not check latest version. Force update? (y/n): "):
                result["message"] = "Update canceled by user."
                return result

        # Try git clone first, fall back to zip download
        if self._update_via_git(result, latest_version):
            return result
        return self._update_via_zip(result, latest_version)

    def _apply_update(self, source_dir: str, latest_version: str | None) -> dict[str, Any]:
        """Common logic to apply an update from a source directory."""
        result: dict[str, Any] = {
            "success": False,
            "message": "",
            "new_version": self.current_version,
        }

        current_dir = self.project_root

        for item in os.listdir(source_dir):
            src_path = os.path.join(source_dir, item)
            dst_path = os.path.join(current_dir, item)

            # Preserve user data
            if item == "data" and os.path.exists(dst_path):
                continue
            if item == "version.json" and os.path.exists(dst_path):
                continue

            if os.path.exists(dst_path):
                if os.path.isdir(dst_path):
                    shutil.rmtree(dst_path)
                else:
                    os.remove(dst_path)

            if os.path.isdir(src_path):
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)

        # Update version info
        temp_version_file = os.path.join(source_dir, "version.json")
        if os.path.exists(temp_version_file):
            try:
                with open(temp_version_file, "r", encoding="utf-8") as f:
                    new_info = json.load(f)
                new_ver = new_info.get("version", latest_version or "1.0.0")
                self.version_info["version"] = new_ver
                self.version_info["last_updated"] = datetime.now().strftime("%Y-%m-%d")
                self._save_version_info(self.version_info)
                self.current_version = new_ver
                result["new_version"] = new_ver
            except Exception as exc:
                print_warning(f"Error updating version info: {exc}")

        result["success"] = True
        result["message"] = f"Successfully updated to version {result['new_version']}"
        print_success(f"Successfully updated WP-Scanner to version {result['new_version']}")
        return result

    def _update_via_git(self, result: dict[str, Any], latest_version: str | None) -> dict[str, Any]:
        try:
            print_info("Updating via git clone...")
            with tempfile.TemporaryDirectory() as temp_dir:
                clone = subprocess.run(
                    ["git", "clone", "--depth", "1", self.repo_url, temp_dir],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if clone.returncode != 0:
                    print_warning(f"Git clone failed: {clone.stderr}")
                    raise subprocess.SubprocessError("Git clone failed")

                return self._apply_update(temp_dir, latest_version)
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            print_warning(f"Git clone failed: {exc}")
            print_info("Falling back to direct download...")
        return result

    def _update_via_zip(self, result: dict[str, Any], latest_version: str | None) -> dict[str, Any]:
        try:
            zip_url = f"{self.repo_url}/archive/refs/heads/main.zip"
            print_info(f"Downloading latest version from {zip_url}")

            response = requests.get(zip_url, stream=True, timeout=30, verify=False)
            if response.status_code != 200:
                result["message"] = f"Failed to download. Status code: {response.status_code}"
                print_error(result["message"])
                return result

            with tempfile.TemporaryDirectory() as temp_dir:
                zip_path = os.path.join(temp_dir, "wp-scanner.zip")
                with open(zip_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                print_info("Extracting files...")
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(temp_dir)

                extracted_dirs = [
                    d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))
                ]
                if not extracted_dirs:
                    result["message"] = "Extraction failed: no directories found"
                    print_error(result["message"])
                    return result

                extracted_dir = os.path.join(temp_dir, extracted_dirs[0])
                return self._apply_update(extracted_dir, latest_version)

        except requests.RequestException as exc:
            result["message"] = f"Download failed: {exc}"
            print_error(result["message"])
            return result
        except Exception as exc:
            result["message"] = f"Unexpected error during update: {exc}"
            print_error(result["message"])
            return result

    def update_vulnerability_databases(self) -> dict[str, Any]:
        """Update the vulnerability databases."""
        print_info("Updating vulnerability databases...")

        result: dict[str, Any] = {"success": False, "message": "", "updated": []}

        try:
            # Download the master vulnerability DB from remote
            db_url = self.version_info.get(
                "vulnerability_db_url",
                "https://raw.githubusercontent.com/Triotion/wp-scanner/master/data/vulnerability_db.json",
            )

            response = requests.get(db_url, timeout=15, verify=False)
            if response.status_code == 200:
                try:
                    remote_db = response.json()
                    local_db_path = os.path.join(self.db_path, "vulnerability_db.json")

                    # Validate remote DB structure
                    if all(k in remote_db for k in ("wordpress", "plugins", "themes")):
                        with open(local_db_path, "w", encoding="utf-8") as f:
                            json.dump(remote_db, f, indent=4)
                        result["updated"].append("vulnerability_db.json")
                        print_success("Updated vulnerability_db.json")
                    else:
                        print_warning("Remote DB has invalid structure, skipping update")
                except json.JSONDecodeError:
                    print_warning("Remote DB is not valid JSON, skipping update")
            else:
                print_warning(f"Could not download vulnerability DB. Status: {response.status_code}")

            if result["updated"]:
                result["success"] = True
                result["message"] = f"Updated {len(result['updated'])} databases"
            else:
                result["success"] = True
                result["message"] = "Databases already up to date"

        except Exception as exc:
            result["message"] = f"Error updating databases: {exc}"
            print_error(f"Error updating vulnerability databases: {exc}")

        return result

    def update_all(self) -> tuple[bool, dict[str, Any]]:
        """Update both the tool and vulnerability databases."""
        results: dict[str, Any] = {"tool": {}, "databases": {}}
        results["tool"] = self.update_tool()
        results["databases"] = self.update_vulnerability_databases()
        success = results["tool"].get("success", False) and results["databases"].get("success", False)
        return success, results
