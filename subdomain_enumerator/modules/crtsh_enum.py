import requests

def query_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                if domain in sub:
                    subdomains.add(sub.strip())

        return sorted(subdomains)
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return []
