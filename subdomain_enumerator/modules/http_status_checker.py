import sys
import requests
from concurrent.futures import ThreadPoolExecutor
import os

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def check_http_status(subdomains, domain):
    status_map = {}
    waf_map = {}

    def fetch_status(sub):
        statuses = {}
        detected_wafs = set()
        for scheme in ["http", "https"]:
            url = f"{scheme}://{sub}"
            try:
                res = requests.get(url, timeout=5, verify=False)
                statuses[scheme] = res.status_code

                # WAF/CDN detection from headers
                headers = res.headers
                server = headers.get("Server", "").lower()
                powered_by = headers.get("X-Powered-By", "").lower()
                all_headers = str(headers).lower()

                if "cloudflare" in server or "cf-ray" in headers or "cloudflare" in all_headers:
                    detected_wafs.add("Cloudflare")
                if "akamai" in server or "akamai" in all_headers:
                    detected_wafs.add("Akamai")
                if "sucuri" in server or "x-sucuri-id" in headers or "sucuri" in all_headers:
                    detected_wafs.add("Sucuri")
                if "aws" in server or "x-amzn-requestid" in headers or "x-amz-apigw-id" in headers:
                    detected_wafs.add("AWS WAF/ALB")
                if "imperva" in server or "incapsula" in all_headers:
                    detected_wafs.add("Imperva Incapsula")

            except requests.RequestException:
                statuses[scheme] = None

        status_map[sub] = statuses
        if detected_wafs:
            waf_map[sub] = list(detected_wafs)

    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(fetch_status, subdomains)

    save_waf_results(domain, waf_map)

    # NEW: Format output for dashboard
    formatted_status_list = []
    for subdomain, statuses in status_map.items():
        http_code = statuses.get('http', 'N/A')
        https_code = statuses.get('https', 'N/A')
        if http_code is None:
            http_code = 'N/A'
        if https_code is None:
            https_code = 'N/A'
        formatted_status = f"{subdomain} - HTTP: {http_code}, HTTPS: {https_code}"
        formatted_status_list.append(formatted_status)

    return formatted_status_list

def save_waf_results(domain, waf_map):
    os.makedirs("output", exist_ok=True)
    filepath = f"output/{domain}_waf_detection.txt"
    with open(filepath, "w") as f:
        for sub, wafs in waf_map.items():
            f.write(f"{sub}: {', '.join(wafs)}\n")
    print(f"[+] Saved WAF/CDN detection results to {filepath}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 http_status_checker.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    # Common subdomains to check
    common_subdomains = [
        f"www.{domain}",
        f"mail.{domain}",
        f"ftp.{domain}",
        f"test.{domain}",
        f"dev.{domain}",
        f"staging.{domain}",
        f"api.{domain}",
        f"blog.{domain}",
        f"shop.{domain}"
    ]

    status_results = check_http_status(common_subdomains, domain)

    if status_results:
        for line in status_results:
            print(line)
    else:
        print("No HTTP status data found.")
