import json
import requests
import datetime

OUTPUT_FILE = "data/raw/urlhaus.json"
URLHAUS_API = "https://urlhaus.abuse.ch/downloads/json_recent/"

def fetch_urlhaus():
    print("Fetching from URLhaus (Public)...")
    try:
        response = requests.get(URLHAUS_API, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # URLhaus recent JSON is a dict of ID -> list of objects
        normalized_data = []
        
        for pid, items in data.items():
            if isinstance(items, list):
                for item in items:
                    normalized_data.append({
                        "type": "url",
                        "value": item.get("url"),
                        "source": "URLhaus",
                        "tags": item.get("tags") or [],
                        "first_seen": item.get("dateadded", datetime.date.today().isoformat())
                    })
            
        return normalized_data
        
    except Exception as e:
        print(f"Error fetching URLhaus: {e}")
        return []

if __name__ == "__main__":
    data = fetch_urlhaus()
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved {len(data)} indicators to {OUTPUT_FILE}")
