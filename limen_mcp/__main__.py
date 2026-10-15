from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import MAX_BYTES, VERSION, Report, parse_config
from .reporting import BaselineError, artifact_value, compare, fail_new, label_value, read_baseline, sarif, snapshot, write_baseline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="limen-mcp",
        description="Audit local MCP server JSON configurations without executing commands or contacting servers.",
    )
    parser.add_argument("config", help="JSON configuration file, or - for standard input")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="report format (default: text)")
    parser.add_argument("--fail-on", choices=("low", "medium", "high", "critical", "never"), default="medium",
                        help="minimum finding severity that exits 1 (default: medium); invalid input always exits 2")
    parser.add_argument("--baseline", help="compare with a versioned baseline snapshot")
    parser.add_argument("--write-baseline", metavar="FILE", help="create a baseline snapshot; existing files are never overwritten")
    parser.add_argument("--baseline-label", help="public label identifying the configuration being compared")
    parser.add_argument("--fail-on-new", action="store_true", help="with --baseline, fail only on added findings or severity increases at --fail-on")
    parser.add_argument("--sarif-artifact", help="optional public repository-relative artifact path; never inferred from input")
    parser.add_argument("--version", action="version", version=f"limen-mcp {VERSION}")
    options = parser.parse_args(argv)
    comparison = None
    artifact = None
    try:
        if options.fail_on_new and not options.baseline:
            raise BaselineError("--fail-on-new requires --baseline.")
        if options.baseline or options.write_baseline:
            label_value(options.baseline_label)
        elif options.baseline_label:
            raise BaselineError("--baseline-label requires a baseline operation.")
        if options.sarif_artifact:
            if options.format != "sarif":
                raise BaselineError("--sarif-artifact requires --format sarif.")
            artifact = artifact_value(options.sarif_artifact)
        previous = read_baseline(options.baseline, options.baseline_label) if options.baseline else None
        if options.config == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(options.config).open("rb") as handle:
                data = handle.read(MAX_BYTES + 1)
        report = parse_config(data)
        if not report.errors and (options.baseline or options.write_baseline):
            current = snapshot(report.to_dict()["findings"], options.baseline_label)
            if previous is not None:
                comparison = compare(current, previous)
            if options.write_baseline:
                write_baseline(options.write_baseline, current)
    except BaselineError as exc:
        report = Report(0, [], [str(exc)])
        comparison = None
    except (OSError, ValueError):
        report = Report(0, [], ["Configuration could not be read; file path and operating system details withheld."])
    result = report.to_dict()
    if comparison is not None:
        result["comparison"] = comparison
    if options.format == "sarif":
        print(json.dumps(sarif(result["findings"], report.errors, comparison, artifact), ensure_ascii=True, indent=2))
    elif options.format == "json":
        print(json.dumps(result, ensure_ascii=True, indent=2))
    else:
        print(f"Limen MCP | {report.servers} server(s) | {len(report.findings)} finding(s) | {len(report.errors)} input error(s)")
        for error in report.errors:
            print(f"ERROR {error}")
        for finding in report.findings:
            print(f"{finding.severity.upper():8} {finding.rule_id} {finding.location}")
            print(f"         {finding.message}")
            print(f"         Fix: {finding.remediation}")
        if comparison is not None:
            print("Comparison: " + ", ".join(f"{value} {key}" for key, value in comparison["summary"].items()))
        if not report.findings and not report.errors:
            print("No findings from supported checks. This is not a security guarantee.")
    if options.fail_on_new and comparison is not None and not report.errors:
        return int(fail_new(comparison, options.fail_on))
    return report.exit_code(options.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
