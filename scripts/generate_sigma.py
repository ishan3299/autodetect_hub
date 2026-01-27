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
  - attack.{t_code}
  - source.{source}
"""

def determine_category(tags):
    # Try to find a high-level category based on tags
    for tag in tags:
        tag_lower = tag.lower()
        if "ransomware" in tag_lower: return "ransomware"
        if "c2" in tag_lower or "cnc" in tag_lower: return "c2"
        if "phish" in tag_lower: return "phishing"
        if "stealer" in tag_lower: return "stealer"
        if "botnet" in tag_lower: return "botnet"
        if "backdoor" in tag_lower: return "backdoor"
        if "crypto" in tag_lower or "miner" in tag_lower: return "cryptomining"
    return "other"

def generate_sigma():
    config = load_config()
    input_file = config["paths"]["normalized"]
    sigma_output = config["paths"]["sigma_output"] # This is 'docs/sigma/all_rules.yml'
    sigma_dir = os.path.dirname(sigma_output) # docs/sigma/
    mappings_file = config["paths"]["mappings"]

    if not os.path.exists(input_file):
        logging.warning("No normalized data found.")
        return

    # Load mappings for T-Codes
    try:
        with open(mappings_file, "r") as f:
            mappings = json.load(f)
    except FileNotFoundError:
        mappings = {}

    with open(input_file, "r") as f:
        indicators = json.load(f)

    # Dictionary to hold rules by category
    categorized_rules = {
        "ransomware": [],
        "c2": [],
        "phishing": [],
        "stealer": [],
        "botnet": [],
        "backdoor": [],
        "cryptomining": [],
        "other": []
    }
    
    all_rules = []

    for item in indicators:
        val = item["indicator"]
        ind_type = item["indicator_type"]
        tags = item.get("tags", [])
        
        # Determine category for file segregation
        category_slug = determine_category(tags)
        
        # Determine T-Code
        t_code = "T1071" # Default
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in mappings:
                t_code = mappings[tag_lower].lower()
                break

        # Basic mapping
        if ind_type == "domain":
            category = "dns"
            field = "query"
        elif ind_type == "ip":
            category = "firewall" # simplified
            field = "dst_ip"
        elif ind_type == "hash":
            category = "process_creation"
            field = "hashes"
        elif ind_type == "url":
            category = "proxy"
            field = "c-uri"
        else:
            continue
        
        # Generate stable ID
        rule_id = "auto-" + hashlib.sha256(val.encode()).hexdigest()
        
        rule_content = TEMPLATE.format(
            indicator=val,
            rule_id=rule_id,
            type=ind_type,
            category=category,
            field=field,
            t_code=t_code,
            source=item["source"]
        )
        
        all_rules.append(rule_content)
        categorized_rules[category_slug].append(rule_content)

    os.makedirs(sigma_dir, exist_ok=True)
    
    # Write "all_rules.yml" for backward compatibility
    with open(sigma_output, "w") as f:
        f.write("---\n".join(all_rules))
    
    # Write segregated files
    for cat, rules in categorized_rules.items():
        if rules:
            filename = os.path.join(sigma_dir, f"{cat}.yml")
            with open(filename, "w") as f:
                f.write("---\n".join(rules))
            logging.info(f"Generated {len(rules)} rules in {filename}")

    logging.info(f"Generated {len(all_rules)} Sigma rules in {sigma_output}.")

if __name__ == "__main__":
    generate_sigma()
