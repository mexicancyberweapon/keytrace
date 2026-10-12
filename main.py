"""Command-line entry point for KeyTrace."""
import argparse
import json
from pathlib import Path
from scanner import scan_path


def main():
    parser = argparse.ArgumentParser(description="Scan Python files for potential credential flows without executing them.")
    parser.add_argument("path", type=Path)
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--entry-points", choices=["module", "tests"], default="module", help="Optionally assume unittest test methods are framework entry points")
    args = parser.parse_args()
    scanners, errors = scan_path(args.path, entry_points=args.entry_points)
    report = {"schema_version": 1, "files": [s.report() for s in scanners], "errors": errors}
    if args.format == "json":
        output = json.dumps(report, indent=2)
    else:
        lines = [f"KeyTrace: {len(scanners)} files, {sum(len(s.candidates) for s in scanners)} candidates, {sum(len(s.findings) for s in scanners)} sensitive-use findings"]
        for scanner in scanners:
            for assessment in scanner.assessments():
                status = 'potential secret' if assessment['is_secret'] is True else 'likely false alarm' if assessment['is_secret'] is False else 'needs review'
                lines.append(f"{assessment['file']}:{assessment['line']} {assessment['source']} [REDACTED]: {status} ({assessment['reason']})")
            for finding in scanner.findings:
                lines.append(f"{finding['file']}:{finding['source_line']} {finding['source']} [REDACTED] -> {finding['sink']}:{finding['line']} ({finding['argument']})")
            lines.extend(f"{scanner.filename}: warning: {warning}" for warning in scanner.warnings)
        lines.extend(f"{e['file']}: {e['error']}" for e in errors)
        output = "\n".join(lines)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n")
    else:
        print(output)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
