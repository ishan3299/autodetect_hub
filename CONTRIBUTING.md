# Contributing to AutoDetect Hub

Thank you for your interest in contributing! We welcome contributions from the community.

## How to Contribute

1. **Fork the repository** and create a new branch for your feature or fix.
2. **Make your changes**. Ensure your code is clean and documented.
3. **Run the scripts locally** to ensure everything works (normalization, rule generation).
4. **Submit a Pull Request** describing your changes.

## Reporting Bugs

Please open an issue on GitHub and include:
- Steps to reproduce
- Expected vs actual behavior
- Any relevant logs

## Adding New Fetchers

If you want to add a new threat intel source:
1. Create `scripts/fetch_sourcename.py`.
2. Ensure it outputs a standard JSON list (see other scripts for format).
3. Add it to `.github/workflows/daily-update.yml`.
