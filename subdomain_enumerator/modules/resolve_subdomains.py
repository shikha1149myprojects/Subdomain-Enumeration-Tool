import socket
import sys

def resolve_subdomains(subdomains):
    resolved = {}
    for sub in subdomains:
        try:
            if not sub or len(sub) > 253 or any(len(label) > 63 for label in sub.split(".")):
                continue  # Skip invalid subdomains

            ip = socket.gethostbyname(sub)
            resolved[sub] = ip
        except Exception as e:
            continue
    return resolved

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 resolve_subdomains.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    # Assume subdomains like www.domain.com, mail.domain.com, etc.
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

    resolved = resolve_subdomains(common_subdomains)
    
    if resolved:
        for sub, ip in resolved.items():
            print(f"{sub} {ip}")
    else:
        print("No resolved subdomains found.")
