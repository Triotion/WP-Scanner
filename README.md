# WP-Scanner

An advanced WordPress vulnerability scanner and exploitation tool written in Python.

## Features

- WordPress installation detection and fingerprinting
- WordPress version, theme, and plugin detection
- User enumeration
- Vulnerability scanning for WordPress core, themes, and plugins
- Advanced exploit capabilities including:
  - XML-RPC brute force attacks
  - Authentication bypass
  - Various plugin-specific RCE exploits
  - SQL injection exploitation
  - Password reset token leak exploitation
- Multi-threaded scanning for faster performance
- Detailed reporting of findings

## Installation

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Setup

1. Clone the repository:
```
git clone https://github.com/Triotion/wp-scanner.git
cd wp-scanner
```

2. Install dependencies:
```
pip install -r requirements.txt
```

## Usage

Basic usage:
```
python wp_scanner.py -t example.com
```

Advanced usage:
```
python wp_scanner.py -t example.com --threads 10 --timeout 30 --proxy http://127.0.0.1:8080 --exploit -v
```

### Command-line Arguments

- `-t, --target`: Target WordPress site URL (required)
- `-o, --output`: Output directory for scan results
- `--threads`: Number of threads for scanning (default: 5)
- `--timeout`: Request timeout in seconds (default: 30)
- `--user-agent`: Custom User-Agent string
- `--proxy`: Proxy URL (e.g., http://127.0.0.1:8080)
- `--exploit`: Attempt to exploit found vulnerabilities
- `-v, --verbose`: Enable verbose output

## Examples

### Basic Scan
```
python wp_scanner.py -t example.com
```

### Vulnerability Scan with Custom Output Directory
```
python wp_scanner.py -t example.com -o scan_results
```

### Scan with Proxy and Exploitation
```
python wp_scanner.py -t example.com --proxy http://127.0.0.1:8080 --exploit
```

### Custom Threads and Timeout
```
python wp_scanner.py -t example.com --threads 10 --timeout 60
```

## Supported Exploits

- **Authentication Bypass**: XML-RPC authentication bypass exploitation
- **RCE Exploits**: 
  - Contact Form 7 file upload vulnerability
  - WP Super Cache code injection
  - TimThumb RCE vulnerability
  - WP Bakery page builder vulnerability
  - WP File Manager RCE vulnerability
- **SQL Injection**: 
  - wpDataTables SQL injection vulnerability
- **Enumeration**:
  - User enumeration via author parameter
  - XML-RPC user enumeration
  - REST API user information exposure
- **Authentication Exploits**:
  - Password reset token leak vulnerability
  - Authenticated code injection via theme/plugin editors

## Project Structure

- `wp_scanner.py`: Main scanner script
- `modules/`: Directory containing the scanner modules
  - `fingerprinter.py`: WordPress detection and fingerprinting
  - `vuln_scanner.py`: Vulnerability scanning
  - `exploiter.py`: Exploitation of discovered vulnerabilities
  - `utils.py`: Utility functions
- `data/`: Directory for vulnerability databases
  - `wordpress_vulns.json`: WordPress core vulnerabilities
  - `plugins_vulns.json`: Plugin vulnerabilities
  - `themes_vulns.json`: Theme vulnerabilities

## Security Bypass Techniques

The scanner includes techniques to bypass common WordPress security measures:
- WAF evasion techniques in HTTP requests
- Security plugin detection and evasion
- XML-RPC restrictions bypass
- REST API restrictions bypass

## Legal Disclaimer

This tool is provided for educational and research purposes only. The author is not responsible for any misuse or damage caused by this program. Users are responsible for compliance with all applicable laws and regulations in their jurisdiction. Use of this tool for attacking targets without prior mutual consent is illegal and prohibited. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

**Use at your own risk.**

## License

This project is licensed under the MIT License - see the LICENSE file for details. 