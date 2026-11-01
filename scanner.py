import requests
import time

API_KEY = "YOUR_API_KEY"


def url_rep(url): # URL Rep scanner

    score = 0
    url = url.lower()
    keywords = ["login", "verify", "update", "secure", "account", "bank"]
    shorteners = ["bit.ly", "tinyurl", "t.co", "is.gd"]

    if not url.startswith("https://"):
        score += 20

    for clues in keywords:
        if clues in url:
            score+=10

    for short in shorteners:
        if short in url:
            score +=15

    if len(url) > 75:
        score += 10

    if any(char.isdigit() for char in url.split("//")[-1].split("/")[0]):
        score += 25

    if score > 100: # just a limit cap
        score = 100
    return score


features = int(input("OPTIONS:\n1. Scan URL \n2. Scan IP reputation \nEnter: "))

match features:
    case 1:
        url = input("Enter URL: ")
        score = url_rep(url)
        api_url = "https://www.virustotal.com/api/v3/urls"

        headers={
            "x-apikey": API_KEY
        }

        data = {
            "url":url
        }

        response = requests.post(api_url, headers=headers, data=data)

        result = response.json()

        scan_id = result["data"]["id"]

        result_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"


        while True: #Scan completion timer
            scan_result = requests.get(result_url, headers=headers)
            scan_data = scan_result.json()

            status = scan_data["data"]["attributes"]["status"]

            if status == "completed":
                break

            print("Scanning... waiting 5 seconds")
            time.sleep(5)


        stats = scan_data["data"]["attributes"]["stats"]

        print("\n===== URL Reputation =====")
        print(f"Risk Score: {score}")
        if score >= 70:
            print("⚠ HIGH RISK (Possible phishing)")
        elif score >= 40:
            print("⚠ MEDIUM RISK (Suspicious)")
        else:
             print("✔ LOW RISK (Seems safe)")

        print("\n===== RESULTS =====")
        print("Malicious :", stats["malicious"])
        print("Suspicious:", stats["suspicious"])
        print("Harmless  :", stats["harmless"])
        print("Undetected:", stats["undetected"])
    
    case 2: 
        print("\n Still underdevelopment")

