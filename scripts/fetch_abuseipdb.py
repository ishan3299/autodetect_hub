import os
import json
import requests
import datetime
import yaml
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def fetch_abuseipdb():
    config = load_config()
    output_file = config["paths"]["raw_abuseipdb"]
    api_key_env = config["api_keys"]["abuseipdb"]
    api_key = os.environ.get(api_key_env)

    if not api_key:
        logging.warning("ABUSEIPDB_API_KEY not found. Using mock data.")
        return [
            {
                "type": "ip",
                "value": "1.2.3.4", 
                "source": "AbuseIPDB",
                "tags": ["bruteforce", "mock"],
                "first_seen": datetime.date.today().isoformat()
            }
        ]
    
    logging.info("Fetching from AbuseIPDB...")
    try:
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "confidenceMinimum": 90,
            "limit": 50 # limit for demo purposes
        }
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json().get("data", [])
        indicators = []
        for item in data:
            indicators.append({
                "type": "ip",
                "value": item.get("ipAddress"),
                "source": "AbuseIPDB",
                "tags": ["reputation"], # AbuseIPDB blacklist doesn't always provide granular tags in this endpoint easily without parsing
                "first_seen": datetime.date.today().isoformat() # Use current date as fetch date
            })
        
        logging.info(f"Fetched {len(indicators)} indicators from AbuseIPDB.")
        return indicators

    except Exception as e:
        logging.error(f"Failed to fetch from AbuseIPDB: {e}")
        return []

if __name__ == "__main__":
    config = load_config()
    output_file = config["paths"]["raw_abuseipdb"]
    
    data = fetch_abuseipdb()
    
    if data:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        logging.info(f"Saved {len(data)} indicators to {output_file}")

