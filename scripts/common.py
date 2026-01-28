import yaml
import logging
import os

def setup_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def load_config(config_path="config.yaml"):
    if not os.path.exists(config_path):
        # search in parent if not found (for running from scripts/)
        if os.path.exists(os.path.join("..", config_path)):
             config_path = os.path.join("..", config_path)
        else:
             logging.error(f"Config file not found at {config_path}")
             return {}
        
    with open(config_path, "r") as f:
        return yaml.safe_load(f)
