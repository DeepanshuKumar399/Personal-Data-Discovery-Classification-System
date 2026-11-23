import os
import csv
from src.patterns import PII_PATTERNS


SUPPORTED_EXTENSIONS = {".txt", ".csv", ".log", ".json", ".xml", ".html"}


def scan_text(text, source="unknown", line_number=None):
    findings = []
    for pii_type, config in PII_PATTERNS.items():
        for match in config["pattern"].finditer(text):
            findings.append({
                "type": pii_type,
                "value": match.group(),
                "sensitivity": config["sensitivity"],
                "source": source,
                "line": line_number,
                "start": match.start(),
                "end": match.end(),
            })
    return findings


def scan_file(filepath):
    findings = []
    ext = os.path.splitext(filepath)[1].lower()

    if ext not in SUPPORTED_EXTENSIONS:
        return findings

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        if ext == ".csv":
            reader = csv.reader(f)
            for line_num, row in enumerate(reader, start=1):
                line_text = " ".join(row)
                findings.extend(scan_text(line_text, source=filepath, line_number=line_num))
        else:
            for line_num, line in enumerate(f, start=1):
                findings.extend(scan_text(line, source=filepath, line_number=line_num))

    return findings


def scan_directory(directory):
    all_findings = []
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            all_findings.extend(scan_file(filepath))
    return all_findings
