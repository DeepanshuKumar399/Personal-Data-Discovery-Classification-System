# Personal Data Discovery & Classification System

A tool to scan files for personally identifiable information (PII), classify sensitivity levels, mask sensitive data, and generate reports.

## Features
- Detect PII: emails, phone numbers, SSNs, credit cards, names, addresses, and more
- Classify data by sensitivity (Critical / High / Medium / Low)
- Mask or redact sensitive values
- Generate JSON, CSV, and HTML reports
- SQLite-backed scan history

## Setup

```bash
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Usage

```bash
python app.py --scan data/sample_data.csv
python app.py --scan data/sample_data.csv --mask
python app.py --report html
```

## Project Structure

```
src/
  patterns.py        - Regex patterns for PII detection
  scanner.py         - File scanning logic
  classifier.py      - Sensitivity classification
  masking.py         - Data masking/redaction
  report_generator.py- Report generation
  database.py        - Scan history persistence
```
