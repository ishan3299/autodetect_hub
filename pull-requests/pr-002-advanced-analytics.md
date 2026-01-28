# PR: Advanced Analytics & Filtering

**PR ID**: #002
**Related Issue**: #002
**Branch**: `feat/advanced-analytics` -> `master`
**Status**: Ready to Merge

## Summary
Adds visual analytics to the dashboard and advanced filtering capabilities to the indicators list.

## Changes
- **Dashboard**:
    - Integrated Chart.js.
    - Added "Indicators by Type" (Doughnut) and "Threat Sources" (Bar) charts.
- **Indicators**:
    - Added Dropdown filters for `Type` and `Source`.
    - Added `Export CSV` button.
    - Added `Reset` button.
- **Logic**:
    - Updated `main.js` with `renderCharts()` and `downloadCSV()`.

## Verification
- Verified Charts render on dashboard load.
- Verified Filters correctly update the table.
- Verified Export generates a valid CSV file.
