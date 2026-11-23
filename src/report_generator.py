import json
import csv
import os
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font

REPORTS_DIR = "reports"
SENSITIVITY_COLORS = {
    "Critical": "FF4C4C",
    "High":     "FFA500",
    "Medium":   "FFD700",
    "Low":      "90EE90",
}


def _timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def generate_json(findings, summary):
    path = os.path.join(REPORTS_DIR, f"report_{_timestamp()}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "findings": findings}, f, indent=2)
    return path


def generate_csv(findings):
    path = os.path.join(REPORTS_DIR, f"report_{_timestamp()}.csv")
    if not findings:
        return path
    fields = ["type", "value", "masked_value", "sensitivity", "source", "line"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)
    return path


def generate_excel(findings, summary):
    path = os.path.join(REPORTS_DIR, f"report_{_timestamp()}.xlsx")
    wb = Workbook()

    # Summary sheet
    ws1 = wb.active
    ws1.title = "Summary"
    ws1.append(["PII Scan Report", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    ws1.append([])
    ws1.append(["Sensitivity", "Count"])
    for level, count in summary["by_sensitivity"].items():
        ws1.append([level, count])
    ws1.append([])
    ws1.append(["PII Type", "Count"])
    for pii_type, count in summary["by_type"].items():
        ws1.append([pii_type, count])

    # Findings sheet
    ws2 = wb.create_sheet("Findings")
    headers = ["Type", "Value", "Masked Value", "Sensitivity", "Source", "Line"]
    ws2.append(headers)
    for cell in ws2[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="4A90D9")

    for f in findings:
        row = [f["type"], f["value"], f.get("masked_value", ""), f["sensitivity"], f["source"], f["line"]]
        ws2.append(row)
        color = SENSITIVITY_COLORS.get(f["sensitivity"], "FFFFFF")
        for cell in ws2[ws2.max_row]:
            cell.fill = PatternFill("solid", fgColor=color)

    wb.save(path)
    return path
