import argparse
import os
import json
import glob
import logging
from datetime import datetime, date
from common import load_config, setup_logging

setup_logging()

def calculate_status_and_severity(item):
    # Determine severity based on sightings and critical tags
    tags_lower = [t.lower() for t in item.get("tags", [])]
    sightings = item.get("sightings", 1)
    
    high_threat_tags = {"ransomware", "stealer", "c2", "cobaltstrike", "agenttesla", "lokibot", "redline"}
    med_threat_tags = {"mirai", "mozi", "gootloader", "socgholish", "asyncrat", "njrat", "remcos"}
    
    if sightings > 2 or any(tag in high_threat_tags for tag in tags_lower):
        severity = "high"
    elif sightings == 2 or any(tag in med_threat_tags for tag in tags_lower):
        severity = "medium"
    else:
        severity = "low"
        
    # Determine active status (last seen within 7 days)
    status = "inactive"
    last_seen_str = item.get("last_seen", "")
    if last_seen_str:
        try:
            # extract YYYY-MM-DD
            date_part = last_seen_str.split()[0]
            last_seen_date = datetime.strptime(date_part, "%Y-%m-%d").date()
            today_date = date.today()
            delta = (today_date - last_seen_date).days
            if delta <= 7:
                status = "active"
        except Exception:
            status = "active" # fallback if parsing error occurs
    else:
        status = "active"
        
    return severity, status

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
                 current_date = date.today().isoformat()
                 
            # Standardize date format to start with YYYY-MM-DD if ISO representation
            if "T" in current_date:
                current_date = current_date.replace("T", " ")
                 
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
    
    # Calculate status and severity for each normalized indicator
    for item in final_list:
        severity, status = calculate_status_and_severity(item)
        item["severity"] = severity
        item["status"] = status
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(final_list, f, indent=2)
    logging.info(f"Normalized {len(final_list)} unique indicators to {output_file}")

if __name__ == "__main__":
    normalize()


