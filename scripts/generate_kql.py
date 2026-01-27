import json
import os
import yaml
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def generate_kql():
    config = load_config()
    input_file = config["paths"]["normalized"]
    output_file = config["paths"]["kql_output"]

    if not os.path.exists(input_file):
        logging.warning("No normalized data found.")
        return

    with open(input_file, "r") as f:
        indicators = json.load(f)

    # We'll just make one big KQL file that looks for any of them, or separate queries? 
    # Instructions imply a file. I'll make a list of queries.
    queries = []
    
    for item in indicators:
        val = item["indicator"]
        if item["indicator_type"] == "domain":
            query = f"""DNS
| where QueryName contains "{val}"
| extend ThreatSource = "{item['source']}"
// Generated for {val}
"""
            queries.append(query)
        elif item["indicator_type"] == "url":
             query = f"""UrlClickEvents
| where Url contains "{val}"
| extend ThreatSource = "{item['source']}"
"""
             queries.append(query)
            
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(queries))
    
    logging.info(f"Generated {len(queries)} KQL queries in {output_file}.")

if __name__ == "__main__":
    generate_kql()

