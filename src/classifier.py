SENSITIVITY_ORDER = ["Critical", "High", "Medium", "Low"]


def classify_findings(findings):
    classified = {level: [] for level in SENSITIVITY_ORDER}
    for finding in findings:
        level = finding.get("sensitivity", "Low")
        classified.setdefault(level, []).append(finding)
    return classified


def summarize(findings):
    summary = {level: 0 for level in SENSITIVITY_ORDER}
    type_counts = {}
    for f in findings:
        summary[f["sensitivity"]] = summary.get(f["sensitivity"], 0) + 1
        type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1
    return {"by_sensitivity": summary, "by_type": type_counts, "total": len(findings)}
