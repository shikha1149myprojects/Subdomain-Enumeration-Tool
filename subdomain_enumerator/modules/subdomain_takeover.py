import sys
import dns.resolver
import requests

# Common fingerprint map for known services
VULNERABLE_SERVICES = {
    "s3.amazonaws.com": "AWS S3",
    "github.io": "GitHub Pages",
    "herokudns.com": "Heroku",
    "cloudfront.net": "CloudFront",
    "bitbucket.io": "Bitbucket",
    "shopify.com": "Shopify",
    "azurewebsites.net": "Azure",
    "fastly.net": "Fastly",
    "readthedocs.io": "ReadTheDocs",
    "ghost.io": "Ghost"
}

def check_cname_takeover(subdomains):
    takeover_candidates = {}

    for sub in subdomains:
        try:
            answers = dns.resolver.resolve(sub, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                for service, name in VULNERABLE_SERVICES.items():
                    if service in cname:
                        # Make a quick HTTP check to see if it's truly dangling
                        try:
                            r = requests.get(f"http://{sub}", timeout=5)
                            if r.status_code in [404, 400]:
                                takeover_candidates[sub] = f"{name} ({cname})"
                        except requests.RequestException:
                            takeover_candidates[sub] = f"{name} ({cname})"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            continue

    return takeover_candidates

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cname_takeover_check.py <subdomain1> <subdomain2> ...")
        sys.exit(1)

    subdomains = sys.argv[1:]

    print(f"[+] Checking CNAME takeover for subdomains: {', '.join(subdomains)}")

    takeover_candidates = check_cname_takeover(subdomains)

    if takeover_candidates:
        print("\n[+] Potential CNAME takeover vulnerabilities found:")
        for subdomain, service_info in takeover_candidates.items():
            print(f" - {subdomain} -> {service_info}")
    else:
        print("[*] No CNAME takeover vulnerabilities found.")

if __name__ == "__main__":
    main()