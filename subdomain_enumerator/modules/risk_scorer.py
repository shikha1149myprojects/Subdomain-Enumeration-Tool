
import json


def compute_risk_scores(risk_input):
    """
    Compute risk scores based on the input data.
    
    Args:
        risk_input (dict): Contains resolved subdomains, WAF status, takeover status, etc.

    Returns:
        dict: A dictionary mapping subdomain to its computed risk score.
    """
    risk_scores = {}

    # Debugging: Print the input
    print("===== Risk Input =====")
    print(json.dumps(risk_input, indent=4))

    for subdomain, ip in risk_input['resolved_subdomains'].items():
        score = 0
        

        # HTTP Status check
        http_info = risk_input['http_statuses'].get(subdomain, {})
        if isinstance(http_info, dict):
            http_status = http_info.get("http", 0)
        else:
            http_status = http_info  # In case it's a direct value (e.g., "200")

        # Normalize to int
        try:
            http_status_int = int(http_status)
        except (ValueError, TypeError):
            http_status_int = 0

        # Debugging with type
        print(f"HTTP Status for {subdomain}: {http_status}")
        print(f"Parsed HTTP Status for {subdomain}: {http_status_int}")

        if http_status_int == 200:
            score += 1
        elif http_status_int == 404:
            score -= 1

        # WAF check
        waf = risk_input['waf_results'].get(subdomain, None)
        print(f"WAF for {subdomain}: {waf}")  # Debugging
        if waf == "Cloudflare":
            score -= 1

        # Takeover check
        takeover = risk_input['takeover_results'].get(subdomain, None)
        print(f"Takeover for {subdomain}: {takeover}")  # Debugging
        if takeover == True:
            score += 2
        
        normalized_subdomain = subdomain.removeprefix("www.")
        # Open ports check
        open_ports = risk_input['portscan_results'].get(normalized_subdomain, [])
        print(f"Open Ports for {normalized_subdomain}: {open_ports}")  # Debugging
        score += len(open_ports)  # Add points for each open port


        # Store in dictionary
        risk_scores[subdomain] = score
        print(f"Score for {subdomain}: {score}")  # Debugging

    # Debug table print (optional)
    print("\nRisk Score Table:")
    print("{:<40} {:>10}".format("Subdomain", "Score"))
    print("-" * 52)
    for sub, sc in risk_scores.items():
        print("{:<40} {:>10}".format(sub, sc))

    return risk_scores
