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

URLHAUS_API = "https://urlhaus.abuse.ch/downloads/json_recent/"

def fetch_urlhaus():
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry

    def get_session():
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        return session

    logging.info("Fetching from URLhaus (Public)...")
    try:
        response = get_session().get(URLHAUS_API, timeout=15)
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
        logging.error(f"Error fetching URLhaus: {e}")
        return []

if __name__ == "__main__":
    config = load_config()
    output_file = config["paths"]["raw_urlhaus"]
    
    data = fetch_urlhaus()
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    logging.info(f"Saved {len(data)} indicators to {output_file}")

