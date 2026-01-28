import os
import json
import yaml
import logging
from datetime import datetime, timedelta
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def generate():
    config = load_config()
    input_file = config["paths"]["normalized"]
    mapping_file = "mappings.json"
    output_file = "docs/analytics.json"

    if not os.path.exists(input_file):
        logging.error(f"Input file {input_file} not found.")
        return

    with open(input_file, "r") as f:
        indicators = json.load(f)

    with open(mapping_file, "r") as f:
        mitre_map = json.load(f)

    now = datetime.now()
    yesterday = now - timedelta(hours=24)
    yesterday_iso = yesterday.date().isoformat() # Approximating to date for comp, ideally use timestamps

    # Metrics
    total_iocs = len(indicators)
    new_iocs_24h = 0
    
    types_counter = Counter()
    tags_counter = Counter()
    sources_counter = Counter()
    mitre_counter = Counter()

    recent_indicators = []

    for item in indicators:
        first_seen = item.get("first_seen", "")
        # Check if new in last 24h
        if first_seen >= yesterday_iso:
            new_iocs_24h += 1
            recent_indicators.append(item)

        # Counting
        types_counter[item.get("indicator_type")] += 1
        sources_counter[item.get("source")] += 1
        
        for tag in item.get("tags", []):
            tags_counter[tag] += 1
            # MITRE Map
            if tag in mitre_map:
                mitre_counter[mitre_map[tag]] += 1
    
    # Sort recent list
    recent_indicators.sort(key=lambda x: x.get("first_seen", ""), reverse=True)

    analytics = {
        "generated_at": now.isoformat(),
        "total_iocs": total_iocs,
        "new_iocs_24h": new_iocs_24h,
        "top_types": dict(types_counter.most_common(5)),
        "top_tags": dict(tags_counter.most_common(10)),
        "top_sources": dict(sources_counter.most_common(5)),
        "mitre_coverage": dict(mitre_counter.most_common(20)),
        "recent_iocs": recent_indicators[:50] # Limit for UI
    }

    with open(output_file, "w") as f:
        json.dump(analytics, f, indent=2)

    logging.info(f"Analytics generated to {output_file}")

if __name__ == "__main__":
    generate()
