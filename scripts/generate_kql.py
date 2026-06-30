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

    # Group indicators by type and source
    grouped = {}
    for item in indicators:
        ind_type = item["indicator_type"]
        source = item["source"]
        val = item["indicator"]
        
        key = (ind_type, source)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(val)

    queries = []
    chunk_size = 500

    for (ind_type, source), vals in grouped.items():
        for i in range(0, len(vals), chunk_size):
            chunk = vals[i:i+chunk_size]
            chunk_num = (i // chunk_size) + 1
            formatted_list = ",\n    ".join(f'"{v}"' for v in chunk)

            if ind_type == "domain":
                query = f"""// Malicious Domains - Chunk {chunk_num} (Source: {source})
DNS
| where QueryName has_any (
    {formatted_list}
  )
| extend ThreatSource = "{source}"
| extend ThreatIndicator = QueryName
"""
                queries.append(query)
            elif ind_type == "url":
                query = f"""// Malicious URLs - Chunk {chunk_num} (Source: {source})
UrlClickEvents
| where Url has_any (
    {formatted_list}
  )
| extend ThreatSource = "{source}"
| extend ThreatIndicator = Url
"""
                queries.append(query)
            elif ind_type == "ip":
                query = f"""// Malicious IPs - Chunk {chunk_num} (Source: {source})
DeviceNetworkEvents
| where RemoteIP in (
    {formatted_list}
  )
| extend ThreatSource = "{source}"
| extend ThreatIndicator = RemoteIP
"""
                queries.append(query)
            elif ind_type == "hash":
                query = f"""// Malicious Hashes - Chunk {chunk_num} (Source: {source})
DeviceProcessEvents
| where SHA256 in (
    {formatted_list}
  )
| extend ThreatSource = "{source}"
| extend ThreatIndicator = SHA256
"""
                queries.append(query)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n\n".join(queries))
    
    logging.info(f"Generated {len(queries)} KQL query blocks in {output_file}.")

if __name__ == "__main__":
    generate_kql()

