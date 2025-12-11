import os
import json
import requests
import datetime

OUTPUT_FILE = "data/raw/abuseipdb.json"
API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

def fetch_abuseipdb():
    if not API_KEY:
        print("ABUSEIPDB_API_KEY not found. Using mock data.")
        return [
            {
                "type": "ip",
                "value": "1.2.3.4", 
                "source": "AbuseIPDB",
                "tags": ["bruteforce", "mock"],
                "first_seen": datetime.date.today().isoformat()
            }
        ]
    
    print("Fetching from AbuseIPDB (Simulated)...")
    return [
        {
            "type": "ip",
            "value": "203.0.113.5",
            "source": "AbuseIPDB",
            "tags": ["ssh-bruteforce"],
            "first_seen": datetime.date.today().isoformat()
        }
    ]

if __name__ == "__main__":
    data = fetch_abuseipdb()
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved {len(data)} indicators to {OUTPUT_FILE}")
