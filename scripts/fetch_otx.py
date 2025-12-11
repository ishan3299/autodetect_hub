import os
import json
import requests
import datetime

OUTPUT_FILE = "data/raw/otx.json"
API_KEY = os.environ.get("OTX_API_KEY")

def fetch_otx():
    if not API_KEY:
        print("OTX_API_KEY not found. Using mock data.")
        return [
            {
                "type": "domain",
                "value": "malicious-example.com",
                "source": "OTX",
                "tags": ["phishing", "mock"],
                "first_seen": datetime.date.today().isoformat()
            },
            {
                "type": "ip",
                "value": "192.168.1.100", 
                "source": "OTX",
                "tags": ["scanner", "mock"],
                "first_seen": datetime.date.today().isoformat()
            }
        ]
    
    # Real implementation would go here (simplified)
    # url = "https://otx.alienvault.com/api/v1/indicators/export"
    # response = requests.get(url, headers={"X-OTX-API-KEY": API_KEY})
    # ... logic to parse ...
    print("Fetching from OTX (Simulated with key)...")
    return [
         {
            "type": "domain",
            "value": "real-malicious-site.net",
            "source": "OTX",
            "tags": ["c2"],
            "first_seen": datetime.date.today().isoformat()
        }
    ]

if __name__ == "__main__":
    data = fetch_otx()
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved {len(data)} indicators to {OUTPUT_FILE}")
