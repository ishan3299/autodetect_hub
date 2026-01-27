import os
import json
import glob
import yaml
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

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
                all_indicators.extend(data)
            except json.JSONDecodeError:
                logging.error(f"Error reading {fpath}")

    # Deduplicate based on value
    unique_map = {}
    for item in all_indicators:
        val = item.get("value")
        if val:
            if val not in unique_map:
                unique_map[val] = {
                    "indicator": val,
                    "indicator_type": item.get("type"),
                    "source": item.get("source"),
                    "tags": item.get("tags", []),
                    "first_seen": item.get("first_seen")
                }
            else:
                # Merge tags
                existing_tags = set(unique_map[val]["tags"])
                new_tags = set(item.get("tags", []))
                unique_map[val]["tags"] = list(existing_tags.union(new_tags))

                # Update timestamp (keep earliest)
                existing_fs = unique_map[val].get("first_seen")
                new_fs = item.get("first_seen")
                if new_fs and existing_fs:
                    unique_map[val]["first_seen"] = min(existing_fs, new_fs)
                elif new_fs:
                    unique_map[val]["first_seen"] = new_fs

    
    final_list = list(unique_map.values())
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(final_list, f, indent=2)
    logging.info(f"Normalized {len(final_list)} unique indicators to {output_file}")

if __name__ == "__main__":
    normalize()

