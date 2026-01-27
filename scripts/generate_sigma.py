import json
import os
import hashlib
import yaml
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

TEMPLATE = """title: Detect Activity to Known Malicious Indicator - {indicator}
id: {rule_id}
status: experimental
description: Detects traffic or activity related to {indicator} which is a known malicious {type}.
logsource:
  category: {category}
detection:
  selection:
    {field}:
      - '*{indicator}*'
  condition: selection
level: high
tags:
  - attack.t1071
  - source.{source}
"""

def generate_sigma():
    config = load_config()
    input_file = config["paths"]["normalized"]
    output_file = config["paths"]["sigma_output"]

    if not os.path.exists(input_file):
        logging.warning("No normalized data found.")
        return

    with open(input_file, "r") as f:
        indicators = json.load(f)

    all_rules = []
    
    # Process ALL indicators (optimization: single file output prevents inode exhaustion)
    for item in indicators:
        val = item["indicator"]
        # Basic mapping
        if item["indicator_type"] == "domain":
            category = "dns"
            field = "query"
        elif item["indicator_type"] == "ip":
            category = "firewall" # simplified
            field = "dst_ip"
        elif item["indicator_type"] == "hash":
            category = "process_creation"
            field = "hashes"
        elif item["indicator_type"] == "url":
            category = "proxy"
            field = "c-uri"
        else:
            continue
        
        # Generate stable ID
        rule_id = "auto-" + hashlib.sha256(val.encode()).hexdigest()
        
        rule_content = TEMPLATE.format(
            indicator=val,
            rule_id=rule_id,
            type=item["indicator_type"],
            category=category,
            field=field,
            source=item["source"]
        )
        all_rules.append(rule_content)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    # Write to single file with YAML document separator
    with open(output_file, "w") as f:
        f.write("---\n".join(all_rules))

    logging.info(f"Generated {len(all_rules)} Sigma rules in {output_file}.")

if __name__ == "__main__":
    generate_sigma()

