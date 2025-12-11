import json
import os

INPUT_FILE = "data/normalized/indicators.json"
OUTPUT_FILE = "detections/suricata/emerging-threats.rules"

def generate_suricata():
    if not os.path.exists(INPUT_FILE):
        print("No normalized data found.")
        return

    with open(INPUT_FILE, "r") as f:
        indicators = json.load(f)

    rules = []
    sid_start = 1000000
    
    for idx, item in enumerate(indicators):
        val = item["indicator"]
        sid = sid_start + idx
        
        if item["indicator_type"] == "domain":
            rule = f'alert dns any any -> any any (msg:"Known Malicious Domain {val}"; dns.query; content:"{val}"; sid:{sid}; rev:1;)'
            rules.append(rule)
        elif item["indicator_type"] == "ip":
            rule = f'alert ip any any -> {val} any (msg:"Known Malicious IP {val}"; sid:{sid}; rev:1;)'
            rules.append(rule)
            
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(rules))
    
    print(f"Generated {len(rules)} Suricata rules.")

if __name__ == "__main__":
    generate_suricata()
