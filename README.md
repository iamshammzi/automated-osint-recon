# Automated OSINT Tool for Digital Footprint Aggregation and Social Media Reconnaissance

A lightweight, cross-platform Python Open Source Intelligence (OSINT) tool featuring both a Command-Line Interface (CLI) and a local Flask Web UI with SQLite database storage for digital footprint aggregation, social media reconnaissance, public metadata extraction, and domain/infrastructure analysis.

> **Ethical & Legal Notice:** This tool is developed strictly for academic research, cybersecurity education, and defensive self-auditing. It aggregates **only publicly accessible, unauthenticated data** and does not bypass logins, scrape private accounts, or perform intrusive scanning.

## Core Features
1. **Multi-Threaded Social Media Reconnaissance (`modules/username_recon.py`)**
   - Concurrently queries 18 public platforms using API checks, HTTP status validation, and HTML signature filtering.
   - Extracts public metadata (display name, bio, location, company, linked websites).
2. **Automated Pivot & Domain Infrastructure Recon (`modules/domain_recon.py`)**
   - Automatically pivots to inspect personal websites discovered in social profiles.
   - Retrieves IPv4 address, DNS records (`A`, `AAAA`, `MX`, `NS`, `TXT`, `DMARC`), email security posture (`SPF`/`DMARC`), public WHOIS data, and passive HTTP security headers.
3. **Digital Footprint Aggregation & Reporting (`modules/report_gen.py`)**
   - Computes an educational Digital Exposure Score (`LOW`, `MODERATE`, `HIGH`).
   - Exports unified reports in **JSON**, **TXT**, and **HTML Dashboard** formats inside `reports/`.

## Cross-Platform Installation

### Prerequisites
- Python 3.9+
- pip (Python Package Installer)
- Git (Version Control)

### Linux / macOS / Termux
    git clone https://github.com/iamshammzi/automated-osint-recon.git
    cd automated-osint-recon
    pip install -r requirements.txt
    python3 osint_tool.py

### Windows (PowerShell / Command Prompt)
    git clone https://github.com/iamshammzi/automated-osint-recon.git
    cd automated-osint-recon
    pip install -r requirements.txt
    python osint_tool.py

## Usage Examples
- Interactive Menu: `python osint_tool.py`
- Username Recon: `python osint_tool.py -u torvalds`
- Domain Recon: `python osint_tool.py -d kernel.org`
- Combined Scan: `python osint_tool.py -u torvalds -d kernel.org`

### Flask Local Web Interface & SQLite Database
- Launch the local web dashboard: `python app.py`
- Open `http://127.0.0.1:5000` in your browser to run scans and browse historical records stored in the local **SQLite database (`osint_recon.db`)**.
