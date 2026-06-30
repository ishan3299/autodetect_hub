import json
import os
import uuid
import yaml
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

TEMPLATE = """title: Detect Activity to Known Malicious {category} - {source} {type}s - Chunk {chunk_num}
id: {rule_id}
status: experimental
description: Detects traffic or activity related to known malicious {type}s associated with {category} from {source} (Chunk {chunk_num}).
logsource:
  category: {logsource_category}
detection:
  selection:
    {field}:
{value_list}
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

    # Group indicators by: (ind_type, source, category_slug, t_code)
    groups = {}
    
    for item in indicators:
        val = item["indicator"]
        ind_type = item["indicator_type"]
        tags = item.get("tags", [])
        source = item["source"]
        
        # Determine category slug
        category_slug = determine_category(tags)
        
        # Determine T-Code
        t_code = "T1071" # Default
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in mappings:
                t_code = mappings[tag_lower]
                break

        key = (ind_type, source, category_slug, t_code)
        if key not in groups:
            groups[key] = []
        groups[key].append(val)

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
    chunk_size = 500

    for key, vals in groups.items():
        ind_type, source, category_slug, t_code = key
        
        # Determine logsource category and field
        if ind_type == "domain":
            logsource_category = "dns"
            field = "query"
            wildcard = True
        elif ind_type == "ip":
            logsource_category = "firewall"
            field = "dst_ip"
            wildcard = False
        elif ind_type == "hash":
            logsource_category = "process_creation"
            field = "hashes"
            wildcard = False
        elif ind_type == "url":
            logsource_category = "proxy"
            field = "c-uri"
            wildcard = True
        else:
            continue

        # Chunk values
        for i in range(0, len(vals), chunk_size):
            chunk = vals[i:i+chunk_size]
            chunk_num = (i // chunk_size) + 1
            
            # Format values
            if wildcard:
                value_list = "\n".join(f"      - '*{v}*'" for v in chunk)
            else:
                value_list = "\n".join(f"      - '{v}'" for v in chunk)

            # Generate stable UUIDv5 based on fields
            uuid_seed = f"{ind_type}-{source}-{category_slug}-{t_code}-{chunk_num}"
            rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, uuid_seed))

            rule_content = TEMPLATE.format(
                category=category_slug.capitalize(),
                source=source,
                type=ind_type,
                chunk_num=chunk_num,
                rule_id=rule_id,
                logsource_category=logsource_category,
                field=field,
                value_list=value_list,
                t_code=t_code.lower()
            )
            
            all_rules.append(rule_content)
            
            if category_slug in categorized_rules:
                categorized_rules[category_slug].append(rule_content)
            else:
                categorized_rules["other"].append(rule_content)

    os.makedirs(sigma_dir, exist_ok=True)
    
    # Clean up old yml files to prevent stale rules from remaining
    import glob
    for old_file in glob.glob(os.path.join(sigma_dir, "*.yml")):
        try:
            os.remove(old_file)
        except OSError:
            pass
    
    # Write "all_rules.yml"
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
