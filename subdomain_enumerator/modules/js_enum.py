import sys
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

def extract_subdomains(text, domain):
    regex = re.compile(r"([\w\.-]+\." + re.escape(domain) + r")")
    return set(match.group(1) for match in regex.finditer(text))

def fetch_file(url):
    try:
        res = requests.get(url, timeout=7, verify=False)
        if res.status_code == 200:
            return res.text
    except requests.RequestException:
        return None
    return None

def parse_js_files(domain):
    found_subdomains = set()

    # Start from the main domain's pages
    for scheme in ["http", "https"]:
        base_url = f"{scheme}://{domain}"
        try:
            res = requests.get(base_url, timeout=7, verify=False)
            if res.status_code != 200:
                continue
        except requests.RequestException:
            continue

        # 1. Check /robots.txt
        robots_txt = fetch_file(urljoin(base_url, "/robots.txt"))
        if robots_txt:
            found_subdomains.update(extract_subdomains(robots_txt, domain))

        # 2. Check /sitemap.xml
        sitemap_xml = fetch_file(urljoin(base_url, "/sitemap.xml"))
        if sitemap_xml:
            found_subdomains.update(extract_subdomains(sitemap_xml, domain))

        # 3. Parse inline HTML for <script src="...">
        soup = BeautifulSoup(res.text, "html.parser")
        script_tags = soup.find_all("script", src=True)
        for tag in script_tags:
            src = tag['src']
            full_js_url = urljoin(base_url, src)
            js_content = fetch_file(full_js_url)
            if js_content:
                found_subdomains.update(extract_subdomains(js_content, domain))

    return sorted(found_subdomains)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 js_enum.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    js_subdomains = parse_js_files(domain)

    if js_subdomains:
        for sub in js_subdomains:
            print(sub)
    else:
        print("[!] No JavaScript subdomains found.")
