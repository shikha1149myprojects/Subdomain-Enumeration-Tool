import argparse
import os
from modules.subfinder_enum import run_subfinder
from modules.crtsh_enum import query_crtsh
from modules.resolve_subdomains import resolve_subdomains
from modules.http_status_checker import check_http_status
from modules.subdomain_takeover import check_cname_takeover
from modules.wayback_enum import wayback_subdomain_enum, save_wayback_results
from modules.js_enum import parse_js_files, save_js_subdomains
from modules.port_scanner import scan_ports, save_portscan_results
from modules.risk_scorer import compute_risk_scores, save_risk_scores
# Reset output folder
import shutil
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def save_takeover_candidates(domain, takeover_dict):
    filepath = f"output/{domain}_takeover.txt"
    with open(filepath, "w") as f:
        for sub, info in sorted(takeover_dict.items()):
            f.write(f"{sub} -> {info}\n")
    print(f"[+] Saved potential takeover subdomains to {filepath}")

def save_results(domain, subdomains):
    os.makedirs("output", exist_ok=True)
    filepath = f"output/{domain}_subdomains.txt"
    with open(filepath, "w") as f:
        for sub in sorted(subdomains):
            f.write(sub + "\n")
    print(f"[+] Saved results to {filepath}")

def save_resolved(domain, resolved_dict):
        filepath = f"output/{domain}_resolved.txt"
        with open(filepath, "w") as f:
            for sub, ip in sorted(resolved_dict.items()):
                f.write(f"{sub} -> {ip}\n")
        print(f"[+] Saved resolved subdomains to {filepath}")

    
def save_http_status(domain, status_dict):
        filepath = f"output/{domain}_http_status.txt"
        with open(filepath, "w") as f:
            for sub, statuses in sorted(status_dict.items()):
                http_code = statuses.get("http")
                https_code = statuses.get("https")
                f.write(f"{sub} -> HTTP: {http_code}, HTTPS: {https_code}\n")
        print(f"[+] Saved HTTP status codes to {filepath}")

def reset_output():
    if os.path.exists("output"):
        shutil.rmtree("output")
    os.makedirs("output", exist_ok=True)

def main():
    reset_output()
    parser = argparse.ArgumentParser(description="Subdomain Enumerator")
    parser.add_argument("domain", help="Domain to enumerate subdomains for")
    args = parser.parse_args()

    print(f"[*] Enumerating subdomains for: {args.domain}")
    
    print("[*] Using subfinder...")
    subfinder_subs = run_subfinder(args.domain)

    print("[*] Using crt.sh...")
    crtsh_subs = query_crtsh(args.domain)

    print("[*] Using Wayback Machine...")
    wayback_subs = wayback_subdomain_enum(args.domain)
    save_wayback_results(args.domain, wayback_subs)

    all_subs = set(subfinder_subs + crtsh_subs + wayback_subs)
    print(f"[+] Total unique subdomains found: {len(all_subs)}")
    
    print("[*] Resolving subdomains to IP addresses...")
    resolved_subs = resolve_subdomains(all_subs)
    print(f"[+] Successfully resolved: {len(resolved_subs)} subdomains")
 
    print("[*] Starting light port scan on resolved subdomains...")
    portscan_results = scan_ports(resolved_subs)
    save_portscan_results(args.domain, portscan_results)

    # Print a preview
    for sub, ports in list(portscan_results.items())[:10]:
         print(f"  {sub} -> Open Ports: {ports}")


    save_results(args.domain, resolved_subs.keys())
    save_resolved(args.domain, resolved_subs)


    print("[*] Checking HTTP status codes...")
    http_status = check_http_status(resolved_subs.keys(),args.domain)
    
    save_http_status(args.domain, http_status)

    print("[*] Parsing JavaScript files for hidden subdomains...")
    js_subs = parse_js_files(resolved_subs.keys(), args.domain)
    save_js_subdomains(args.domain, js_subs)

    # Update all_subs with these new findings too
    all_subs.update(js_subs)

    print("[*] Checking for potential subdomain takeovers...")
    takeover_candidates = check_cname_takeover(resolved_subs.keys())

    save_takeover_candidates(args.domain, takeover_candidates)

    print("[*] Calculating risk scores for subdomains...")
    risk_scores = compute_risk_scores(resolved_subs, {}, takeover_candidates, http_status, portscan_results)
    save_risk_scores(args.domain, risk_scores)

    # Preview top risky subdomains
    for sub, details in list(sorted(risk_scores.items(), key=lambda x: -x[1]['score']))[:10]:
         print(f"  {sub} -> Risk Score: {details['score']}")


if __name__ == "__main__":
    main()

