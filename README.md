# WP-Scanner v3.0.0

![WP-Scanner Banner](screenshots/banner.png)

**Advanced WordPress Vulnerability Scanner and Exploitation Framework**

---

## Features

- **75 CVEs** across WordPress core, 33 plugins, and 15 themes
- Comprehensive fingerprinting (version, themes, plugins, users, 24 detection methods)
- Active exploitation with 36 exploit handlers (RCE, SQLi, file upload, LFI, deserialization)
- Latest 2024-2026 CVEs including **wp2shell RCE chain** (CVE-2026-63030 + CVE-2026-60137)
- Mass scanning with thread-safe parallel execution
- HTML and Markdown report generation with XSS protection
- Automatic tool and vulnerability database updates

## Requirements

- **Python 3.10+** (uses `from __future__ import annotations`)
- 6 dependencies only: `requests`, `beautifulsoup4`, `colorama`, `urllib3`, `packaging`, `tqdm`

## Installation

```bash
git clone https://github.com/Triotion/wp-scanner.git
cd wp-scanner
pip install -r requirements.txt
```

## Quick Start

### Basic Scan

```bash
python wp_scanner.py -t example.com
```

### Scan with Exploitation

```bash
python wp_scanner.py -t example.com --exploit
```

### Scan with HTML Report

```bash
python wp_scanner.py -t example.com --report-format html
```

### Mass Scan from File

```bash
python wp_scanner.py -l targets.txt --mass-output-dir mass_results
```

### Update Tool and Database

```bash
python wp_scanner.py --update
```

### Auto-Update Before Scanning

```bash
python wp_scanner.py -t example.com --auto-update
```

## Target List Builder

Generate and validate target lists for mass scanning:

```bash
python create_targets_list.py -i raw_urls.txt -o targets.txt --check-wordpress
```

### Options

```
python create_targets_list.py [-h] [-o OUTPUT] [-i INPUT_FILE]
                              [-u URLS [URLS ...]] [--subdomains SUBDOMAINS]
                              [--append] [--check-wordpress]
```

| Flag | Description |
|------|-------------|
| `-i`, `--input` | Input file with targets (one per line) |
| `-o`, `--output` | Output file for the target list |
| `-u`, `--urls` | URLs to add directly |
| `--subdomains` | Subdomain enumeration results file |
| `--append` | Append to output instead of overwriting |
| `--check-wordpress` | Verify targets run WordPress (slower) |

## CLI Options

```
python wp_scanner.py [-h] [-t TARGET] [-l TARGETS_FILE] [-o OUTPUT]
                     [--threads THREADS] [--timeout TIMEOUT]
                     [--user-agent USER_AGENT] [--proxy PROXY]
                     [--exploit] [-v] [--mass-output-dir MASS_OUTPUT_DIR]
                     [--update] [--auto-update]
                     [--report-format {console,html,md}]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target WordPress site URL | - |
| `-l`, `--targets-file` | File with target URLs | - |
| `-o`, `--output` | Output directory | `results_<target>_<timestamp>` |
| `--threads` | Scan threads | 5 |
| `--timeout` | Request timeout (seconds) | 30 |
| `--user-agent` | Custom User-Agent | `WPS-Scanner/3.0` |
| `--proxy` | HTTP proxy URL | - |
| `--exploit` | Run exploit modules | off |
| `-v`, `--verbose` | Verbose output | off |
| `--mass-output-dir` | Mass scan results root | `mass_scan_results` |
| `--update` | Update tool + DB | - |
| `--auto-update` | Auto-update before scan | off |
| `--report-format` | Output format | `console` |

## Output Structure

```
results_example.com_20260728_143022/
├── scan_results.log
├── wp_info.json
├── vulnerabilities.json
├── report.html              (if --report-format html)
├── report.md                (if --report-format md)
└── exploits/
    └── <exploit_artifacts>
```

## Vulnerability Database

**75 CVEs** covering the latest WordPress attack surface:

| Category | Count | Notable CVEs |
|----------|-------|--------------|
| WordPress Core | 20 | CVE-2026-63030 (wp2shell RCE), CVE-2026-60137 (WP_Query SQLi), CVE-2024-2802 (HTML API DoS) |
| Plugins | 40 | CVE-2026-3891 (Pix WooCommerce RCE), CVE-2026-58480 (Blocksy RCE), CVE-2026-1357 (WPvivid RCE), CVE-2025-25833 (LayerSlider RCE) |
| Themes | 15 | Multiple stored XSS and open redirect vulnerabilities |

### Plugin Coverage (33 plugins)

Elementor, WooCommerce, Wordfence, Contact Form 7, WP File Manager, LayerSlider, Yoast SEO, Classic Editor, Akismet, Jetpack, wpAutomatic, Fancy Product Designer, WP Activity Log, Custom CSS-JS-PHP, Chatbot with ChatGPT, The Events Calendar, Pix for WooCommerce, Blocksy Companion Pro, WPvivid Backup & Migration, WP User Manager, Remote API, and more.

### Exploit Methods (36 handlers)

| Method | Target | CVE |
|--------|--------|-----|
| `wp2shell_rce` | WP Core 6.9-7.0 | CVE-2026-63030 + CVE-2026-60137 |
| `wp_query_sqli` | WP Core <6.8.6 | CVE-2026-60137 |
| `elementor_rce` | Elementor Pro | CVE-2024-28019 |
| `layerslider_rce` | LayerSlider | CVE-2025-25833 |
| `file_upload_rce` | WP File Upload | CVE-2024-11613 |
| `fpd_file_upload` | Fancy Product Designer | CVE-2024-51919 |
| `wp_automatic_sqli_rce` | wpAutomatic | CVE-2024-27956 |
| `custom_css_js_php_rce` | Custom CSS-JS-PHP | CVE-2026-6433 |
| `pix_woocommerce_rce` | Pix for WooCommerce | CVE-2026-3891 |
| `blocksy_file_upload_rce` | Blocksy Companion Pro | CVE-2026-58480 |
| `wpvivid_backup_rce` | WPvivid Backup & Migration | CVE-2026-1357 |
| `wp_user_manager_lfi` | WP User Manager | CVE-2026-9290 |
| `remote_api_deserialization_rce` | Remote API | CVE-2026-14602 |
| `woocommerce_file_download` | WooCommerce | CVE-2024-28023 |
| `woocommerce_sqli` | WooCommerce | CVE-2024-28024 |
| `wp_core_path_traversal` | WP Core | CVE-2024-28025 |
| `wp_file_manager_rce` | WP File Manager | CVE-2024-28021 |
| `wpdatatables_sqli` | WPDataTables | CVE-2024-28022 |
| `wp_super_cache_rce` | WP Super Cache | CVE-2024-28020 |
| `yuzo_related_posts` | Yuzo Related Posts | CVE-2024-28026 |
| `nextgen_gallery_sqli` | NextGEN Gallery | CVE-2024-28027 |
| `rest_api_content_injection` | WP Core 4.7.x | CVE-2017-1001000 |
| `wp_mail_content_injection` | WP Core <4.6.2 | CVE-2016-10033 |
| + 13 more | Various | - |

## Project Structure

```
wp-scanner/
├── wp_scanner.py              # Main entry point, CLI, WPScanner, MassScanner
├── create_targets_list.py     # Target list builder with WP detection
├── modules/
│   ├── __init__.py
│   ├── utils.py               # Banner, logging, colored output
│   ├── fingerprinter.py       # WP detection (24 checks, cached homepage)
│   ├── vuln_scanner.py        # DB loader, version matching
│   ├── exploiter.py           # 36 exploit handlers
│   ├── reporter.py            # HTML/Markdown report generation
│   └── updater.py             # Self-update with SHA-256 verification
├── data/
│   └── vulnerability_db.json  # Master vulnerability database (75 CVEs)
├── requirements.txt           # 6 dependencies
├── pyproject.toml             # Build config, ruff, mypy, pytest
├── version.json               # v3.0.0
└── .gitignore
```

## Development

### Linting

```bash
ruff check .
```

### Type Checking

```bash
mypy wp_scanner.py modules/
```

### Testing

```bash
pytest tests/ -v
```

## Security Notes

- All user inputs are sanitized; HTML reports use `html.escape()` to prevent XSS
- Exploit modules are for authorized testing only
- Mass scanner uses `copy.deepcopy()` to prevent thread-argument mutation
- Thread-safe shared state via `threading.Lock`
- SHA-256 hash verification on self-updates

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper written authorization before scanning or exploiting any system. The authors are not responsible for misuse or damage.

## Contributing

Contributions welcome. Submit a Pull Request or open an issue.

## Donations

- **BTC**: `bc1qtkm7dzjp76gx8t9c02pshfd8rzarj6gj9yzglu`
- **ETH**: `0x88Aa0E09a5A62919321f38Fb4782A17f4dc91A9B`
- **XMR**: `0x6730c52B3369fD22E3ACc6090a3Ee7d5C617aBE0`

## Author

Created by [@Triotion](https://github.com/Triotion/) - [Telegram](https://t.me/Triotion)

## License

MIT License - see [LICENSE](LICENSE) for details.
