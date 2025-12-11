import json
import os

INPUT_FILE = "data/normalized/indicators.json"
OUTPUT_FILE = "detections/kql/dns_queries.kql"

def generate_kql():
    if not os.path.exists(INPUT_FILE):
        print("No normalized data found.")
        return

    with open(INPUT_FILE, "r") as f:
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
            
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(queries))
    
    print(f"Generated {len(queries)} KQL queries.")

if __name__ == "__main__":
    generate_kql()
