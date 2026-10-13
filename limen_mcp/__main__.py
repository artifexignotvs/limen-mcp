from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import MAX_BYTES, VERSION, Report, parse_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="limen-mcp",
        description="Audit local MCP server JSON configurations without executing commands or contacting servers.",
    )
    parser.add_argument("config", help="JSON configuration file, or - for standard input")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="report format (default: text)")
    parser.add_argument("--fail-on", choices=("low", "medium", "high", "critical", "never"), default="medium",
                        help="minimum finding severity that exits 1 (default: medium); invalid input always exits 2")
    parser.add_argument("--version", action="version", version=f"limen-mcp {VERSION}")
    options = parser.parse_args(argv)
    try:
        if options.config == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(options.config).open("rb") as handle:
                data = handle.read(MAX_BYTES + 1)
        report = parse_config(data)
    except (OSError, ValueError):
        report = Report(0, [], ["Configuration could not be read; file path and operating system details withheld."])
    if options.format == "json":
        print(json.dumps(report.to_dict(), ensure_ascii=True, indent=2))
    else:
        print(f"Limen MCP | {report.servers} server(s) | {len(report.findings)} finding(s) | {len(report.errors)} input error(s)")
        for error in report.errors:
            print(f"ERROR {error}")
        for finding in report.findings:
            print(f"{finding.severity.upper():8} {finding.rule_id} {finding.location}")
            print(f"         {finding.message}")
            print(f"         Fix: {finding.remediation}")
        if not report.findings and not report.errors:
            print("No findings from supported checks. This is not a security guarantee.")
    return report.exit_code(options.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
