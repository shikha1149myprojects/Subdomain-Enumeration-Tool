import socket
from concurrent.futures import ThreadPoolExecutor
import sys

COMMON_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 3306, 53, 3389]  # Expand if needed

def resolve_domain(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None

def scan_ports(domain):
    results = {}

    subdomains = [domain]  # You could also scan *.domain if you want
    resolved_subdomains = {}

    for sub in subdomains:
        ip = resolve_domain(sub)
        if ip:
            resolved_subdomains[sub] = ip

    def scan(sub, ip):
        open_ports = []
        for port in COMMON_PORTS:
            try:
                sock = socket.create_connection((ip, port), timeout=2)
                open_ports.append(port)
                sock.close()
            except (socket.timeout, socket.error):
                pass
        if open_ports:
            results[sub] = open_ports

    with ThreadPoolExecutor(max_workers=30) as executor:
        for sub, ip in resolved_subdomains.items():
            executor.submit(scan, sub, ip)

    # Important: wait for all threads to finish
    executor.shutdown(wait=True)

    return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 port_scan.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    scan_results = scan_ports(domain)

    if scan_results:
        for sub, ports in scan_results.items():
            ports_str = ", ".join(map(str, ports))
            print(f"{sub} ({ports_str})")
    else:
        print("[!] No open ports found.")
