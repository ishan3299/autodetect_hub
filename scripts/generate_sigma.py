import json
import os
import hashlib

INPUT_FILE = "data/normalized/indicators.json"
OUTPUT_FILE = "detections/sigma/all_rules.yml"

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
    if not os.path.exists(INPUT_FILE):
        print("No normalized data found.")
        return

    with open(INPUT_FILE, "r") as f:
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

    # Write to single file with YAML document separator
    with open(OUTPUT_FILE, "w") as f:
        f.write("---\n".join(all_rules))

    print(f"Generated {len(all_rules)} Sigma rules in {OUTPUT_FILE}.")

if __name__ == "__main__":
    generate_sigma()
