#!/usr/bin/env python3
"""KL-DeepScan CLI — detection-only web vulnerability scanner.

Usage:
    python3 deepscan.py https://example.com --yes
    python3 deepscan.py http://localhost:8080 --format html --out report.html

Safety gate: targets that are not localhost require --yes, by which the
operator confirms the target is their own or otherwise authorized.
Detection-only: checks use harmless marker probes, nothing destructive.
"""
import argparse
import sys
import urllib.parse
from collections import Counter

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def is_local_target(target):
    t = target if "://" in target else "http://" + target
    host = urllib.parse.urlparse(t).hostname or ""
    return host.lower() in LOCAL_HOSTS


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="deepscan.py",
        description="KL-DeepScan — detection-only web vulnerability scanner (stdlib only).")
    parser.add_argument("target", help="Base URL to scan, e.g. https://example.com")
    parser.add_argument("--yes", action="store_true",
                        help="Confirm the target is yours / authorized (required for non-localhost targets)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Concurrent check threads (default: 10)")
    parser.add_argument("--format", choices=["json", "html", "sarif"], default=None,
                        help="Report format to write (requires --out, default json)")
    parser.add_argument("--out", default=None, help="Write a report file to this path")
    parser.add_argument("--triage", action="store_true",
                        help="Add online AI triage summary (needs an AI provider API key in env)")
    args = parser.parse_args(argv)

    if not is_local_target(args.target) and not args.yes:
        print("Refusing to scan a non-localhost target without --yes.\n"
              "KL-DeepScan is detection-only, but scanning systems you do not\n"
              "own or have permission to test may be illegal. Re-run with\n"
              "--yes to confirm this target is yours or authorized.",
              file=sys.stderr)
        return 2

    from kl_deepscan.engine import run_scan
    findings = run_scan(args.target, threads=args.threads)

    for f in findings:
        print("[%-8s] %-28s %s — %s" % (f.severity.upper(), f.id, f.url, f.title))

    counts = Counter(f.severity for f in findings)
    order = ["critical", "high", "medium", "low", "info"]
    summary = "  ".join("%s: %d" % (s, counts.get(s, 0)) for s in order)
    print("\nTarget: %s" % args.target)
    print("Findings: %d (%s)" % (len(findings), summary))

    if args.out or args.format:
        from kl_deepscan import report
        fmt = args.format or "json"
        out = args.out or ("deepscan-report." + ("html" if fmt == "html" else fmt))
        report.generate(findings, args.target, fmt, out)
        print("Report written: %s (%s)" % (out, fmt))

    if args.triage:
        from kl_deepscan import ai_triage
        text = ai_triage.triage(findings)
        if text:
            print("\n--- AI triage ---\n%s" % text)
        else:
            print("\nAI triage unavailable (no AI provider key configured or provider unreachable); skipped.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
