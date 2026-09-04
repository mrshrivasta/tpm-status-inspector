#!/usr/bin/env python3
"""
TPM Status Inspector — Command Line Interface
Developed by Karanam Shrivasta
GitHub: https://github.com/mrshrivasta | LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

DISCLAIMER: Inspects REAL TPM state on this machine via /sys/class/tpm,
/dev/tpm*, and tpm2-tools. Read-only — never sends TPM commands that
change ownership, hierarchy authorization, or NV state. Only run against
systems you own or are authorized to assess. Provided AS IS, no warranty.
See README.md for the full disclaimer.

Usage:
    python3 cli/main.py scan
    python3 cli/main.py scan --json
    python3 cli/main.py scan --csv findings.csv
    python3 cli/main.py rules
"""
import argparse
import csv
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine
from app.detection_rules import ALL_RULES

BANNER = """\
==============================================================
 TPM Status Inspector (CLI)
 Developed by Karanam Shrivasta
 GitHub:   https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta
 DISCLAIMER: Authorized use only. Provided AS IS, no warranty.
==============================================================\
"""

SEVERITY_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[92m",
}
RESET = "\033[0m"


def cmd_scan(args):
    print(BANNER)
    print("Inspecting real TPM state (/sys/class/tpm, /dev/tpm*, tpm2-tools)...\n")

    engine = ScanEngine()
    result = engine.run()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    print(f"TPM present          : {result['tpm_present']}")
    print(f"TPM devices inspected : {result['files_scanned']}")
    print(f"tpm2-tools available  : {result['tpm2_tools_available']}")
    print(f"Errors                : {result['errors_count']}")
    print(f"Elapsed               : {result['elapsed_seconds']}s")
    print(f"Findings              : {len(result['findings'])}\n")

    for f in result["findings"]:
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"{color}[{f['severity'].upper():8}]{RESET} {f['rule_id']} {f['rule_name']}")
        print(f"           subject: {f['file_path']}  detail: {f['permissions_octal']}")
        print(f"           {f['description']}\n")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["rule_id", "rule_name", "severity", "subject", "detail", "description"])
            for f in result["findings"]:
                writer.writerow([f["rule_id"], f["rule_name"], f["severity"], f["file_path"], f["permissions_octal"], f["description"]])
        print(f"CSV report written to {args.csv}")

    if result["findings"]:
        sys.exit(1)
    sys.exit(0)


def cmd_rules(args):
    print(BANNER)
    print("Detection rules:\n")
    for rule in ALL_RULES:
        doc = (rule.__doc__ or "").strip().split("\n")[0]
        print(f" - {rule.__name__}: {doc}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="tsi-cli",
        description="TPM Status Inspector — real TPM device inspector (by Karanam Shrivasta).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Inspect real TPM state on this machine")
    scan_p.add_argument("--json", action="store_true", help="Output raw JSON")
    scan_p.add_argument("--csv", type=str, default=None, help="Write findings to a CSV file")
    scan_p.set_defaults(func=cmd_scan)

    rules_p = sub.add_parser("rules", help="List all detection rules")
    rules_p.set_defaults(func=cmd_rules)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
