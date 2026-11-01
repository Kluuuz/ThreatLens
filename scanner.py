import requests
import time

API_KEY = "YOUR_API_KEY"

VT_URLS = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSES = "https://www.virustotal.com/api/v3/analyses/{}"


def url_rep(url):  # local heuristic URL reputation score
    score = 0
    url = url.lower()
    keywords = ["login", "verify", "update", "secure", "account", "bank"]
    shorteners = ["bit.ly", "tinyurl", "t.co", "is.gd"]

    if not url.startswith("https://"):
        score += 20

    for clues in keywords:
        if clues in url:
            score += 10

    for short in shorteners:
        if short in url:
            score += 15

    if len(url) > 75:
        score += 10

    if any(char.isdigit() for char in url.split("//")[-1].split("/")[0]):
        score += 25

    if score > 100:  # just a limit cap
        score = 100
    return score


def risk_label(score):
    if score >= 70:
        return "HIGH RISK (Possible phishing)"
    elif score >= 40:
        return "MEDIUM RISK (Suspicious)"
    return "LOW RISK (Seems safe)"


def scan_url(url, max_wait=60):
    """Submit a URL to VirusTotal and return the local score + VT stats.

    Returns a dict: {score, risk, stats} or {error} on failure.
    """
    score = url_rep(url)
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.post(VT_URLS, headers=headers, data={"url": url}, timeout=30)
        result = response.json()
    except (requests.RequestException, ValueError) as e:
        return {"error": f"Submission failed: {e}"}

    if "data" not in result:
        msg = result.get("error", {}).get("message", "Unexpected VirusTotal response")
        return {"error": msg}

    scan_id = result["data"]["id"]
    result_url = VT_ANALYSES.format(scan_id)

    waited = 0
    while True:  # poll until analysis completes (bounded by max_wait)
        try:
            scan_data = requests.get(result_url, headers=headers, timeout=30).json()
            status = scan_data["data"]["attributes"]["status"]
        except (requests.RequestException, ValueError, KeyError) as e:
            return {"error": f"Result fetch failed: {e}"}

        if status == "completed":
            break
        if waited >= max_wait:
            return {"error": "Timed out waiting for VirusTotal analysis"}
        time.sleep(5)
        waited += 5

    stats = scan_data["data"]["attributes"]["stats"]
    return {"score": score, "risk": risk_label(score), "stats": stats}


def _cli():
    features = int(input("OPTIONS:\n1. Scan URL \n2. Scan IP reputation \nEnter: "))
    match features:
        case 1:
            url = input("Enter URL: ")
            result = scan_url(url)

            if "error" in result:
                print("Error:", result["error"])
                return

            print("\n===== URL Reputation =====")
            print(f"Risk Score: {result['score']}")
            print(result["risk"])

            stats = result["stats"]
            print("\n===== RESULTS =====")
            print("Malicious :", stats["malicious"])
            print("Suspicious:", stats["suspicious"])
            print("Harmless  :", stats["harmless"])
            print("Undetected:", stats["undetected"])

        case 2:
            print("\n Still underdevelopment")


if __name__ == "__main__":
    _cli()
