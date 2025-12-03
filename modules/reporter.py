#!/usr/bin/env python3

import os
import json
from datetime import datetime

class Reporter:
    def __init__(self, output_dir, target):
        self.output_dir = output_dir
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_html_report(self, wp_info, vulnerabilities, exploitation_results):
        """Generates an HTML report of the scan results."""
        report_path = os.path.join(self.output_dir, f"report_{self.timestamp}.html")
        with open(report_path, 'w') as f:
            f.write("<!DOCTYPE html>\n")
            f.write("<html lang='en'>\n")
            f.write("<head>\n")
            f.write("    <meta charset='UTF-8'>\n")
            f.write("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n")
            f.write("    <title>WP-Scanner Report - " + self.target + "</title>\n")
            f.write("    <style>\n")
            f.write("        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }\n")
            f.write("        .container { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n")
            f.write("        h1, h2, h3 { color: #0056b3; }\n")
            f.write("        .section { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background-color: #fdfdfd; }\n")
            f.write("        .info-item { margin-bottom: 5px; }\n")
            f.write("        .vulnerability { border: 1px solid #ffc107; background-color: #fff3cd; padding: 10px; margin-bottom: 10px; border-radius: 5px; }\n")
            f.write("        .vulnerability.critical { border-color: #dc3545; background-color: #f8d7da; }\n")
            f.write("        .vulnerability.high { border-color: #fd7e14; background-color: #fff3cd; }\n")
            f.write("        .vulnerability.medium { border-color: #ffc107; background-color: #fff3cd; }\n")
            f.write("        .vulnerability.low { border-color: #17a2b8; background-color: #d1ecf1; }\n")
            f.write("        .exploit-success { border: 1px solid #28a745; background-color: #d4edda; padding: 10px; margin-bottom: 10px; border-radius: 5px; }\n")
            f.write("        .exploit-failed { border: 1px solid #dc3545; background-color: #f8d7da; padding: 10px; margin-bottom: 10px; border-radius: 5px; }\n")
            f.write("        pre { background-color: #eee; padding: 10px; border-radius: 5px; overflow-x: auto; }\n")
            f.write("        .summary-table { width: 100%; border-collapse: collapse; margin-top: 15px; }\n")
            f.write("        .summary-table th, .summary-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
            f.write("        .summary-table th { background-color: #e9e9e9; }\n")
            f.write("    </style>\n")
            f.write("</head>\n")
            f.write("<body>\n")
            f.write("    <div class='container'>\n")
            f.write("        <h1>WP-Scanner Report</h1>\n")
            f.write("        <p><strong>Target:</strong> " + self.target + "</p>\n")
            f.write("        <p><strong>Scan Date:</strong> " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "</p>\n")

            # WordPress Information
            f.write("        <div class='section'>\n")
            f.write("            <h2>WordPress Information</h2>\n")
            f.write("            <div class='info-item'><strong>Version:</strong> " + wp_info.get("version", "Unknown") + "</div>\n")
            f.write("            <div class='info-item'><strong>Version Sources:</strong> " + ", ".join(wp_info.get("version_sources", [])) + "</div>\n")
            f.write("            <div class='info-item'><strong>Themes:</strong> " + ", ".join([f"{t.get('name', 'Unknown')} (v{t.get('version', 'Unknown')})" for t in wp_info.get("themes", [])]) + "</div>\n")
            f.write("            <div class='info-item'><strong>Plugins:</strong> " + ", ".join([f"{p.get('name', 'Unknown')} (v{p.get('version', 'Unknown')})" for p in wp_info.get("plugins", {{}}).values()]) + "</div>\n")
            f.write("            <div class='info-item'><strong>Users:</strong> " + str(len(wp_info.get("users", []))) + " found</div>\n")
            f.write("            <div class='info-item'><strong>XML-RPC Enabled:</strong> " + ("Yes" if wp_info.get("xmlrpc_enabled") else "No") + "</div>\n")
            f.write("            <div class='info-item'><strong>REST API Enabled:</strong> " + ("Yes" if wp_info.get("rest_api_enabled") else "No") + "</div>\n")
            f.write("        </div>\n")

            # Vulnerabilities
            f.write("        <div class='section'>\n")
            f.write("            <h2>Vulnerabilities Found</h2>\n")
            # Core Vulnerabilities
            f.write("            <h3>WordPress Core Vulnerabilities</h3>\n")
            for vuln in vulnerabilities["core"]:
                f.write(f"            <div class='vulnerability {vuln.get('severity', 'unknown').lower()}'>\n")
                f.write(f"                <h4>{vuln.get('title', 'Unknown')}</h4>\n")
                f.write(f"                <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>\n")
                f.write(f"                <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>\n")
                f.write(f"                <p><strong>CVE:</strong> {vuln.get('cve', 'N/A')}</p>\n")
                f.write(f"                <p><strong>Affected Version:</strong> {vuln.get('affected_version', 'N/A')}</p>\n")
                f.write(f"                <p><strong>Fixed In:</strong> {vuln.get('fixed_in', 'N/A')}</p>\n")
                f.write(f"                <p><strong>Exploitability:</strong> {vuln.get('exploitability', 'N/A')}</p>\n")
                f.write(f"                <p><strong>Exploit Available:</strong> {'Yes' if vuln.get('exploit_available') else 'No'}</p>\n")
                f.write("            </div>\n")
            
            # Plugin Vulnerabilities
            f.write("            <h3>Plugin Vulnerabilities</h3>\n")
            for plugin_name, plugin_data in vulnerabilities["plugins"].items():
                for vuln in plugin_data.get("vulns", []):
                    f.write(f"            <div class='vulnerability {vuln.get('severity', 'unknown').lower()}'>\n")
                    f.write(f"                <h4>{plugin_name}: {vuln.get('title', 'Unknown')}</h4>\n")
                    f.write(f"                <p><strong>Version:</strong> {plugin_data.get('version', 'Unknown')}</p>\n")
                    f.write(f"                <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>\n")
                    f.write(f"                <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>CVE:</strong> {vuln.get('cve', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>Affected Version:</strong> {vuln.get('affected_version', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>Fixed In:</strong> {vuln.get('fixed_in', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>Exploitability:</strong> {vuln.get('exploitability', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>Exploit Available:</strong> {'Yes' if vuln.get('exploit_available') else 'No'}</p>\n")
                    f.write("            </div>\n")

            # Theme Vulnerabilities
            f.write("            <h3>Theme Vulnerabilities</h3>\n")
            for theme_name, theme_data in vulnerabilities["themes"].items():
                for vuln in theme_data.get("vulns", []):
                    f.write(f"            <div class='vulnerability {vuln.get('severity', 'unknown').lower()}'>\n")
                    f.write(f"                <h4>{theme_name}: {vuln.get('title', 'Unknown')}</h4>\n")
                    f.write(f"                <p><strong>Version:</strong> {theme_data.get('version', 'Unknown')}</p>\n")
                    f.write(f"                <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>\n")
                    f.write(f"                <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>CVE:</strong> {vuln.get('cve', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>Affected Version:</strong> {vuln.get('affected_version', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>Fixed In:</strong> {vuln.get('fixed_in', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>Exploitability:</strong> {vuln.get('exploitability', 'N/A')}</p>\n")
                    f.write(f"                <p><strong>Exploit Available:</strong> {'Yes' if vuln.get('exploit_available') else 'No'}</p>\n")
                    f.write("            </div>\n")
            f.write("        </div>\n")

            # Exploitation Results
            f.write("        <div class='section'>\n")
            f.write("            <h2>Exploitation Results</h2>\n")
            for result in exploitation_results:
                status_class = "exploit-success" if result.get("status") == "success" else "exploit-failed"
                f.write(f"            <div class='{status_class}'>\n")
                f.write(f"                <h4>{result.get('vulnerability', 'Unknown Exploit')} - Status: {result.get('status')}</h4>\n")
                f.write(f"                <p><strong>Details:</strong> {result.get('details', 'N/A')}</p>\n")
                if result.get('reason'):
                    f.write(f"                <p><strong>Reason:</strong> {result.get('reason')}</p>\n")
                if result.get('data'):
                    f.write("                <p><strong>Data:</strong></p>\n")
                    f.write("                <pre>" + json.dumps(result['data'], indent=2) + "</pre>\n")
                f.write("            </div>\n")
            f.write("        </div>\n")

            f.write("    </div>\n")
            f.write("</body>\n")
            f.write("</html>\n")
        return report_path

    def generate_markdown_report(self, wp_info, vulnerabilities, exploitation_results):
        """Generates a Markdown report of the scan results."""
        report_path = os.path.join(self.output_dir, f"report_{self.timestamp}.md")
        with open(report_path, 'w') as f:
            f.write(f"# WP-Scanner Report - {self.target}\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # WordPress Information
            f.write("## WordPress Information\n")
            f.write(f"- **Version:** {wp_info.get('version', 'Unknown')}\n")
            f.write(f"- **Version Sources:** {', '.join(wp_info.get('version_sources', []))}\n")
            f.write(f"- **Themes:** {', '.join([f'{t.get('name', 'Unknown')} (v{t.get('version', 'Unknown')})' for t in wp_info.get('themes', [])])}\n")
            f.write(f"- **Plugins:** {', '.join([f'{p.get('name', 'Unknown')} (v{p.get('version', 'Unknown')})' for p in wp_info.get('plugins', {}).values()])}\n")
            f.write(f"- **Users Found:** {len(wp_info.get('users', []))}\n")
            f.write(f"- **XML-RPC Enabled:** {'Yes' if wp_info.get('xmlrpc_enabled') else 'No'}\n")
            f.write(f"- **REST API Enabled:** {'Yes' if wp_info.get('rest_api_enabled') else 'No'}\n")
            f.write("\n")

            # Vulnerabilities
            f.write("## Vulnerabilities Found\n")
            # Core Vulnerabilities
            f.write("### WordPress Core Vulnerabilities\n")
            for vuln in vulnerabilities["core"]:
                f.write(f"- **Title:** {vuln.get('title', 'Unknown')}\n")
                f.write(f"  - **Severity:** {vuln.get('severity', 'Unknown')}\n")
                f.write(f"  - **Description:** {vuln.get('description', 'N/A')}\n")
                f.write(f"  - **CVE:** {vuln.get('cve', 'N/A')}\n")
                f.write(f"  - **Affected Version:** {vuln.get('affected_version', 'N/A')}\n")
                f.write(f"  - **Fixed In:** {vuln.get('fixed_in', 'N/A')}\n")
                f.write(f"  - **Exploitability:** {vuln.get('exploitability', 'N/A')}\n")
                f.write(f"  - **Exploit Available:** {'Yes' if vuln.get('exploit_available') else 'No'}\n")
                f.write("\n")
            
            # Plugin Vulnerabilities
            f.write("### Plugin Vulnerabilities\n")
            for plugin_name, plugin_data in vulnerabilities["plugins"].items():
                for vuln in plugin_data.get("vulns", []):
                    f.write(f"- **Plugin:** {plugin_name} (v{plugin_data.get('version', 'Unknown')})\n")
                    f.write(f"  - **Title:** {vuln.get('title', 'Unknown')}\n")
                    f.write(f"  - **Severity:** {vuln.get('severity', 'Unknown')}\n")
                    f.write(f"  - **Description:** {vuln.get('description', 'N/A')}\n")
                    f.write(f"  - **CVE:** {vuln.get('cve', 'N/A')}\n")
                    f.write(f"  - **Affected Version:** {vuln.get('affected_version', 'N/A')}\n")
                    f.write(f"  - **Fixed In:** {vuln.get('fixed_in', 'N/A')}\n")
                    f.write(f"  - **Exploitability:** {vuln.get('exploitability', 'N/A')}\n")
                    f.write(f"  - **Exploit Available:** {'Yes' if vuln.get('exploit_available') else 'No'}\n")
                    f.write("\n")

            # Theme Vulnerabilities
            f.write("### Theme Vulnerabilities\n")
            for theme_name, theme_data in vulnerabilities["themes"].items():
                for vuln in theme_data.get("vulns", []):
                    f.write(f"- **Theme:** {theme_name} (v{theme_data.get('version', 'Unknown')})\n")
                    f.write(f"  - **Title:** {vuln.get('title', 'Unknown')}\n")
                    f.write(f"  - **Severity:** {vuln.get('severity', 'Unknown')}\n")
                    f.write(f"  - **Description:** {vuln.get('description', 'N/A')}\n")
                    f.write(f"  - **CVE:** {vuln.get('cve', 'N/A')}\n")
                    f.write(f"  - **Affected Version:** {vuln.get('affected_version', 'N/A')}\n")
                    f.write(f"  - **Fixed In:** {vuln.get('fixed_in', 'N/A')}\n")
                    f.write(f"  - **Exploitability:** {vuln.get('exploitability', 'N/A')}\n")
                    f.write(f"  - **Exploit Available:** {'Yes' if vuln.get('exploit_available') else 'No'}\n")
                    f.write("\n")
            f.write("\n")

            # Exploitation Results
            f.write("## Exploitation Results\n")
            for result in exploitation_results:
                f.write(f"### {result.get('vulnerability', 'Unknown Exploit')} - Status: {result.get('status')}\n")
                f.write(f"- **Details:** {result.get('details', 'N/A')}\n")
                if result.get('reason'):
                    f.write(f"- **Reason:** {result.get('reason')}\n")
                if result.get('data'):
                    f.write("- **Data:**\n")
                    f.write("```json\n" + json.dumps(result['data'], indent=2) + "\n```\n")
                f.write("\n")
            f.write("\n")
        return report_path
