#  SubZero: The Autonomous Subdomain Sleuth

This tool performs automated security analysis on discovered subdomains of a target domain. It aggregates data from modules like port scanning, HTTP response checks, WAF detection, and subdomain takeover analysis to compute a risk score for each subdomain. The results are presented in a user-friendly web interface

# Features

- Subdomain enumeration using multiple sources (e.g., subfinder, Wayback, JavaScript).
- CNAME-based subdomain takeover detection for popular cloud services.
- HTTP status code checking over HTTP and HTTPS.
- WAF (Web Application Firewall) detection logic.
- Port scanning for identifying open and risky ports.
- Risk scoring based on multiple vulnerability signals.
- Interactive HTML dashboard with expandable sections.

# Installation

```
# Clone Repository
git clone https://github.com/shikha1149myprojects/Subdomain-Enumeration-Tool.git

# Move into directory
cd subdomain_enumerator

# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Add it in path
export PATH="$HOME/go/bin:$PATH"
source ~/.zshrc                             # or ~/.bashrc depending on your shell

# Run tool
python3 dashboard.py

```
