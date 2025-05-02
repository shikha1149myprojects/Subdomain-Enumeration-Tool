#  SubZero: The Autonomous Subdomain Sleuth

This tool performs automated security analysis on discovered subdomains of a target domain. It aggregates data from modules like port scanning, HTTP response checks, WAF detection, and subdomain takeover analysis to compute a risk score for each subdomain. The results are presented in a user-friendly web interface

<img width="700" alt="Screenshot 2025-05-01 at 10 30 24 PM" src="https://github.com/user-attachments/assets/d59b5d71-9b22-4d9c-a4a3-c1e8f4bd4deb" />

<img width="700" alt="Screenshot 2025-05-01 at 10 31 37 PM" src="https://github.com/user-attachments/assets/aef70b66-0532-418d-9ea8-de0607539e06" />

# Features


- **Domain-Specific Dashboard**: Displays scan results for a specific domain.

- **Subdomain Enumeration**: Shows discovered subdomains.
- **Resolved Subdomains**: Lists subdomains successfully resolved to IP addresses.
- **WAF/CDN Detection**: Identifies whether a Web Application Firewall or CDN is present per subdomain.
- **HTTP/HTTPS Status Codes**: Displays HTTP response status codes for subdomains.
- **JavaScript Subdomain Extraction**: Lists subdomains discovered in JavaScript files.
- **Wayback Machine Integration**: Retrieves historical subdomain data from the Wayback Machine.
- **Subdomain Takeover Detection**: Identifies potential vulnerable subdomains that could be taken over.
- **Port Scan Results**: Displays open ports found for each subdomain.
- **Risk Scoring System**: Assigns a risk score to each subdomain based on gathered intelligence.

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
