import os
import json
import glob

RAW_DIR = "data/raw/*.json"
OUTPUT_FILE = "data/normalized/indicators.json"

def normalize():
    all_indicators = []
    
    files = glob.glob(RAW_DIR)
    print(f"Found {len(files)} raw files to process.")
    
    for fpath in files:
        with open(fpath, "r") as f:
            try:
                data = json.load(f)
                all_indicators.extend(data)
            except json.JSONDecodeError:
                print(f"Error reading {fpath}")

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
                # Merge tags if needed, or keep first seen
                pass
    
    final_list = list(unique_map.values())
    
    with open(OUTPUT_FILE, "w") as f:
        json.dump(final_list, f, indent=2)
    print(f"Normalized {len(final_list)} unique indicators to {OUTPUT_FILE}")

if __name__ == "__main__":
    normalize()
