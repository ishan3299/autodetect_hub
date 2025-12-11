import json
import os
import hashlib

INPUT_FILE = "data/normalized/indicators.json"
OUTPUT_DIR = "detections/sigma/"

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

    count = 0
    # Limit to top 50 to avoid filesystem explosion with 30k+ indicators
    for item in indicators[:50]:
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
        
        safe_name = val.replace(':', '_').replace('/', '_').replace('.', '_')
        if len(safe_name) > 200: safe_name = safe_name[:200] # Truncate if too long
        
        filename = f"{OUTPUT_DIR}detect_{item['indicator_type']}_{safe_name}.yml"
        with open(filename, "w") as f:
            f.write(rule_content)
        count += 1

    print(f"Generated {count} Sigma rules.")

if __name__ == "__main__":
    generate_sigma()
