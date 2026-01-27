import json
import os
import yaml
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def build_heatmap():
    config = load_config()
    input_file = config["paths"]["normalized"]
    output_file = config["paths"]["docs_coverage"]
    mappings_file = config["paths"]["mappings"]

    if not os.path.exists(input_file):
        logging.warning("No normalized data found.")
        return

    # Load mappings
    with open(mappings_file, "r") as f:
        mappings = json.load(f)

    with open(input_file, "r") as f:
        indicators = json.load(f)

    coverage = {}
    
    for item in indicators:
        tags = item.get("tags") or []
        
        # Default
        t_code = "T1071" # Application Layer Protocol
        
        # Dynamic mapping
        for tag in tags:
            if tag in mappings:
                t_code = mappings[tag]
                break # Prioritize first match, or could implement hierarchy
            
        coverage[t_code] = coverage.get(t_code, 0) + 1
        
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(coverage, f, indent=2)
    
    logging.info(f"Generated MITRE coverage map: {coverage}")

if __name__ == "__main__":
    build_heatmap()

