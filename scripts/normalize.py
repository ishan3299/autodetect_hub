import argparse
import os
import json
import glob
import logging
from common import load_config, setup_logging

setup_logging()

def normalize():
    config = load_config()
    raw_dir = config["paths"]["raw_dir"]
    output_file = config["paths"]["normalized"]

    all_indicators = []
    
    files = glob.glob(raw_dir)
    logging.info(f"Found {len(files)} raw files to process.")
    
    for fpath in files:
        with open(fpath, "r") as f:
            try:
                data = json.load(f)
                
                # Validation: Filter out invalid items
                valid_data = []
                for item in data:
                    if not item.get("value") or not item.get("type"):
                        logging.warning(f"Skipping invalid item in {fpath}: {item}")
                        continue
                    valid_data.append(item)
                
                all_indicators.extend(valid_data)
            except json.JSONDecodeError:
                logging.error(f"Error reading {fpath}")

    # Deduplicate based on value
    unique_map = {}
    for item in all_indicators:
        val = item.get("value")
        if val:
            current_date = item.get("first_seen")
            if not current_date:
                 import datetime
                 current_date = datetime.date.today().isoformat()
                 
            if val not in unique_map:
                unique_map[val] = {
                    "indicator": val,
                    "indicator_type": item.get("type"),
                    "source": item.get("source"),
                    "tags": item.get("tags", []),
                    "first_seen": current_date,
                    "last_seen": current_date,
                    "sightings": 1
                }
            else:
                # Merge tags
                existing_tags = set(unique_map[val]["tags"])
                new_tags = set(item.get("tags", []))
                unique_map[val]["tags"] = list(existing_tags.union(new_tags))

                # Update First Seen (Keep Earliest)
                existing_fs = unique_map[val].get("first_seen") or current_date
                unique_map[val]["first_seen"] = min(existing_fs, current_date)

                # Update Last Seen (Keep Latest)
                existing_ls = unique_map[val].get("last_seen") or current_date
                unique_map[val]["last_seen"] = max(existing_ls, current_date)

                # Increment Sightings
                unique_map[val]["sightings"] = unique_map[val].get("sightings", 1) + 1

    
    final_list = list(unique_map.values())
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(final_list, f, indent=2)
    logging.info(f"Normalized {len(final_list)} unique indicators to {output_file}")

if __name__ == "__main__":
    normalize()

