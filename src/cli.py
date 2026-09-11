import argparse
from .io import load_events
from .detector import detect
from .reporting import markdown_report


def main():
    parser = argparse.ArgumentParser(description="Analyze synthetic persistence telemetry")
    parser.add_argument("input", help="Path to synthetic JSON event data")
    parser.add_argument("--output", default="persistence-report.md")
    args = parser.parse_args()
    findings = detect(load_events(args.input))
    report = markdown_report(findings)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(report)
    print(f"Wrote {len(findings)} findings to {args.output}")


if __name__ == "__main__":
    main()
