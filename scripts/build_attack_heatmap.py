import json
import os

INPUT_FILE = "data/normalized/indicators.json"
OUTPUT_FILE = "docs/attack-coverage.json"

# In a real system, we'd map tags/types to T-codes.
# For now, we'll hardcode some logical mappings or use random for demo if tags match.

def build_heatmap():
    if not os.path.exists(INPUT_FILE):
        print("No normalized data found.")
        return

    with open(INPUT_FILE, "r") as f:
        indicators = json.load(f)

    coverage = {}
    
    for item in indicators:
        # Simple heuristic mapping
        tags = item.get("tags") or []
        
        # Default
        t_code = "T1071" # Application Layer Protocol
        
        if "phishing" in tags:
            t_code = "T1566"
        elif "c2" in tags:
            t_code = "T1071"
        elif "ransomware" in tags:
            t_code = "T1486"
            
        coverage[t_code] = coverage.get(t_code, 0) + 1
        
    with open(OUTPUT_FILE, "w") as f:
        json.dump(coverage, f, indent=2)
    
    print(f"Generated MITRE coverage map: {coverage}")

if __name__ == "__main__":
    build_heatmap()
