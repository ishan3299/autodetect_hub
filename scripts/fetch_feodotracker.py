import json
import requests
import datetime
import yaml
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

FEODO_API = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

def fetch_feodo():
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry

    def get_session():
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        return session

    logging.info("Fetching from Feodo Tracker...")
    try:
        response = get_session().get(FEODO_API, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        normalized_data = []
        
        # Feodo Tracker JSON structure is list of objects
        for item in data:
            normalized_data.append({
                "type": "ip",
                "value": item.get("ip_address"),
                "source": "FeodoTracker",
                "tags": [item.get("malware")] if item.get("malware") else ["c2"],
                "first_seen": item.get("first_seen_utc", datetime.date.today().isoformat())
            })
            
        return normalized_data
        
    except Exception as e:
        logging.error(f"Error fetching Feodo Tracker: {e}")
        return []

if __name__ == "__main__":
    config = load_config()
    output_file = config["paths"]["raw_feodo"]
    
    data = fetch_feodo()
    
    if data:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        logging.info(f"Saved {len(data)} indicators to {output_file}")
