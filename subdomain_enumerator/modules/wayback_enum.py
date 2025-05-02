import sys
import requests
import re
import os
from urllib.parse import urlparse

def wayback_subdomain_enum(domain):
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        res = requests.get(url, timeout=30)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Wayback request failed: {e}")
        return []

    data = res.json()

    if not data or len(data) <= 1:
        print("[*] No historical subdomains found.")
        return []

    raw_urls = [entry[0] for entry in data[1:]]  # Skip header row
    subdomains = set()

    for raw_url in raw_urls:
        parsed = urlparse(raw_url)
        hostname = parsed.hostname
        if hostname and hostname.endswith(domain):
            # Filter out weird ones like 'www.google.com/favicon.ico'
            if re.match(r"^[\w\.-]+\." + re.escape(domain) + r"$", hostname):
                subdomains.add(hostname)

    return sorted(subdomains)

def save_wayback_results(domain, subdomains):
    os.makedirs("output", exist_ok=True)
    filepath = f"output/{domain}_wayback_subdomains.txt"
    with open(filepath, "w") as f:
        for sub in subdomains:
            f.write(sub + "\n")
    print(f"[+] Saved Wayback Machine subdomains to {filepath}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 wayback_subdomain_enum.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"[+] Fetching historical subdomains for {domain}...")
    
    # Fetch subdomains using Wayback
    subdomains = wayback_subdomain_enum(domain)
    
    if subdomains:
        print(f"[+] Found {len(subdomains)} historical subdomains for {domain}:")
        for sub in subdomains:
            print(f" - {sub}")

        # Save the results to a file
        save_wayback_results(domain, subdomains)
    else:
        print("[*] No subdomains found.")