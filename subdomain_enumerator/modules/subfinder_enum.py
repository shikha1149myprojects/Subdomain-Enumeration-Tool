import subprocess

def run_subfinder(domain):
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=True
        )
        subdomains = result.stdout.strip().split("\n")
        return list(set(filter(None, subdomains)))
    except subprocess.CalledProcessError as e:
        print(f"[!] subfinder error: {e}")
        return []

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 subfinder_enum.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    subdomains = run_subfinder(domain)
    for sub in subdomains:
        print(sub)
