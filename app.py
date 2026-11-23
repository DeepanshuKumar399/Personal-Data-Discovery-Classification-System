import argparse
import os
from src.scanner import scan_file, scan_directory
from src.classifier import classify_findings, summarize
from src.masking import mask_findings
from src.report_generator import generate_json, generate_csv, generate_html
from src.database import save_scan, get_history


def main():
    parser = argparse.ArgumentParser(description="Personal Data Discovery & Classification System")
    parser.add_argument("--scan", metavar="PATH", help="File or directory to scan")
    parser.add_argument("--mask", action="store_true", help="Mask PII values in findings")
    parser.add_argument("--report", choices=["json", "csv", "html"], help="Generate a report")
    parser.add_argument("--history", action="store_true", help="Show scan history")
    args = parser.parse_args()

    if args.history:
        from tabulate import tabulate
        history = get_history()
        if not history:
            print("No scan history found.")
        else:
            print(tabulate(
                [[h["id"], h["scanned_at"], h["target"], h["total_findings"]] for h in history],
                headers=["ID", "Scanned At", "Target", "Findings"],
                tablefmt="grid"
            ))
        return

    if not args.scan:
        parser.print_help()
        return

    target = args.scan
    if os.path.isdir(target):
        findings = scan_directory(target)
    elif os.path.isfile(target):
        findings = scan_file(target)
    else:
        print(f"Error: '{target}' is not a valid file or directory.")
        return

    if args.mask:
        findings = mask_findings(findings)

    summary = summarize(findings)
    save_scan(target, findings, summary)

    print(f"\nScan complete: {summary['total']} finding(s) in '{target}'")
    print(f"  Critical : {summary['by_sensitivity'].get('Critical', 0)}")
    print(f"  High     : {summary['by_sensitivity'].get('High', 0)}")
    print(f"  Medium   : {summary['by_sensitivity'].get('Medium', 0)}")
    print(f"  Low      : {summary['by_sensitivity'].get('Low', 0)}")

    if args.report:
        if args.report == "json":
            path = generate_json(findings, summary)
        elif args.report == "csv":
            path = generate_csv(findings)
        elif args.report == "html":
            path = generate_html(findings, summary)
        print(f"\nReport saved: {path}")


if __name__ == "__main__":
    main()
