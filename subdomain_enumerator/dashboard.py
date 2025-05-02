import json
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for
from modules.risk_scorer import compute_risk_scores  # ✅ Import function directly

app = Flask(__name__)

def run_script(script_name, domain):
    """Run the script and capture its output."""
    script_path = os.path.join('modules', script_name)
    try:
        print(f"Running script: {script_path} with domain: {domain}")
        result = subprocess.check_output(['python3', script_path, domain], stderr=subprocess.STDOUT)
        output = result.decode('utf-8')
        return output.strip().splitlines()
    except subprocess.CalledProcessError as e:
        return [f"Error occurred while running {script_name}: {e.output.decode()}"]

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        domain = request.form.get("domain")
        return redirect(url_for('show_results', domain=domain))
    return render_template("home.html")

@app.route("/results/<domain>")
def show_results(domain):
    # Run all modules
    subdomains = run_script('subfinder_enum.py', domain)
    resolved = run_script('resolve_subdomains.py', domain)
    http_statuses = run_script('http_status_checker.py', domain)
    portscan = run_script('port_scanner.py', domain)
    js_subdomains = run_script('js_enum.py', domain)
    wayback_subdomains = run_script('wayback_enum.py', domain)   
    takeover = run_script('subdomain_takeover.py', domain)

    # Parse results into dictionary structures
    resolved_subdomains = {
        line.split()[0]: line.split()[1] if len(line.split()) > 1 else "0.0.0.0"
        for line in resolved
    }

    # Update parsing for http_statuses (new format)
    http_status_dict = {}
    for line in http_statuses:
        # Expected format: subdomain - HTTP: code, HTTPS: code
        parts = line.split(" - ")
        if len(parts) == 2:
            subdomain, status_str = parts
            status_parts = status_str.split(", ")
            http_code = https_code = "N/A"
            for part in status_parts:
                if "HTTP" in part:
                    http_code = part.split(":")[1].strip()
                elif "HTTPS" in part:
                    https_code = part.split(":")[1].strip()
            http_status_dict[subdomain] = {"http": http_code, "https": https_code}

    print("HTTP Status Dict:")
    print(json.dumps(http_status_dict, indent=4))



    #waf_results = {sub: None for sub in resolved_subdomains}
    def parse_waf_results(filepath):
        waf_map = {}
        with open(filepath, 'r') as f:
            for line in f:
                if ':' in line:
                    parts = line.strip().split(':', 1)
                    subdomain = parts[0].strip()
                    waf_name = parts[1].strip()
                    waf_map[subdomain] = waf_name
        return waf_map
    
    waf_file = f"output/{domain}_waf_detection.txt"
    waf_results = parse_waf_results(waf_file)

    takeover_dict = {line.strip(): True for line in takeover}

    print("Portscan Raw Output:")
    print(portscan)

    portscan_dict = {
    line.split()[0]: [int(p.strip()) for p in line.split("(", 1)[1].strip(")\n").split(",") if p.strip().isdigit()]
    for line in portscan if "(" in line and ")" in line
}
    print("Portscan Dict before passing to compute_risk_scores:")
    print(json.dumps(portscan_dict, indent=4))

    # Construct input for risk scoring
    risk_input = {
        "resolved_subdomains": resolved_subdomains,
        "waf_results": waf_results,
        "takeover_results": takeover_dict,
        "http_statuses": http_status_dict,
        "portscan_results": portscan_dict
    }
    print("===== Risk Input =====")
    print(json.dumps(risk_input, indent=4))

    # ✅ Call risk scoring function directly (not subprocess)
    risk_scores = compute_risk_scores(risk_input)

    return render_template(
        "results.html",
        domain=domain,
        subdomains=subdomains,
        resolved_subs=resolved,
        http_statuses=http_statuses,
        portscan_results=portscan_dict,
        risk_scores=risk_scores,
        js_subdomains=js_subdomains,
        takeover=takeover,
        wayback_subdomains=wayback_subdomains,
        waf_results=waf_results
    )

if __name__ == "__main__":
    app.run(debug=True)
