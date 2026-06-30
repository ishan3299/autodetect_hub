import json
import os
import yaml
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def generate_suricata():
    config = load_config()
    input_file = config["paths"]["normalized"]
    output_file = config["paths"]["suricata_output"]

    if not os.path.exists(input_file):
        logging.warning("No normalized data found.")
        return

    with open(input_file, "r") as f:
        indicators = json.load(f)

    rules = []
    sid_start = 1000000
    
    from urllib.parse import urlparse

    for idx, item in enumerate(indicators):
        val = item["indicator"]
        sid = sid_start + idx
        
        if item["indicator_type"] == "domain":
            rule = f'alert dns any any -> any any (msg:"Known Malicious Domain {val}"; dns.query; content:"{val}"; nocase; sid:{sid}; rev:1;)'
            rules.append(rule)
        elif item["indicator_type"] == "ip":
            rule = f'alert ip any any -> {val} any (msg:"Known Malicious IP {val}"; sid:{sid}; rev:1;)'
            rules.append(rule)
        elif item["indicator_type"] == "url":
            try:
                parsed = urlparse(val)
                host = parsed.netloc.split(":")[0] if parsed.netloc else ""
                path = parsed.path
                if parsed.query:
                    path += "?" + parsed.query
                
                if host and path and path != "/":
                    safe_host = host.replace(":", "\\:").replace(";", "\\;")
                    safe_path = path.replace(":", "\\:").replace(";", "\\;")
                    rule = f'alert http any any -> any any (msg:"Known Malicious URL {val}"; http.host; content:"{safe_host}"; nocase; http.uri; content:"{safe_path}"; nocase; sid:{sid}; rev:1;)'
                elif host:
                    safe_host = host.replace(":", "\\:").replace(";", "\\;")
                    rule = f'alert http any any -> any any (msg:"Known Malicious URL {val}"; http.host; content:"{safe_host}"; nocase; sid:{sid}; rev:1;)'
                else:
                    safe_val = val.replace(":", "\\:").replace(";", "\\;")
                    rule = f'alert http any any -> any any (msg:"Known Malicious URL {safe_val}"; http.uri; content:"{safe_val}"; nocase; sid:{sid}; rev:1;)'
            except Exception:
                safe_val = val.replace(":", "\\:").replace(";", "\\;")
                rule = f'alert http any any -> any any (msg:"Known Malicious URL {safe_val}"; http.uri; content:"{safe_val}"; nocase; sid:{sid}; rev:1;)'
            rules.append(rule)
            
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(rules))
    
    logging.info(f"Generated {len(rules)} Suricata rules in {output_file}.")

if __name__ == "__main__":
    generate_suricata()

