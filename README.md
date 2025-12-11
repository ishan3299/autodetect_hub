# AutoDetect Hub

**AutoDetect Hub** is a fully automated detection engineering system. It fetches threat intelligence daily, normalizes it, and generates detection rules for Sigma, Suricata, and Azure Sentinel (KQL).

## Features
- **Automated Ingestion**: Fetches from OTX, MalwareBazaar, AbuseIPDB.
- **Normalization**: Unified JSON schema for all indicators.
- **Rule Generation**: Automatically creates Sigma, Suricata, and KQL rules.
- **MITRE Mapping**: Maps coverage to ATT&CK Matrix.
- **Static Dashboard**: View indicators and stats on [GitHub Pages](https://ishan3299.github.io/autodetect_hub/).

## Architecture
1. **GitHub Actions** runs daily.
2. **Python Scripts** fetch and process data.
3. **Outputs** are committed to the repo.
4. **GitHub Pages** serves the `/docs` folder.

## Usage
Run manually via GitHub Actions "Run workflow" or wait for the daily scheduler.
Add secrets `OTX_API_KEY`, etc. for real data.

## Directory Structure
- `data/`: Raw and normalized JSON.
- `detections/`: Generated rules.
- `scripts/`: Python logic.
- `docs/`: Frontend code.
