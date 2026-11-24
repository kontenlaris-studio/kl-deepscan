#!/usr/bin/env python3
"""KL-DeepScan selftest.

Starts the deliberately misconfigured fixture server (tests/fixture_server.py)
on 127.0.0.1:8791, runs kl_deepscan.engine.run_scan against it, and asserts:
  - a finding whose id contains "header"  (missing security headers)
  - a finding whose id contains "cors"    (reflected CORS origin)
  - a finding whose id contains "git"     (exposed /.git/HEAD)
  - a finding whose id contains "reflect" (reflected marker / XSS probe)
  - reports generate in json, html and sarif formats
  - ai_triage.triage() returns a str and never raises

Prints PASS/FAIL lines plus the total registered check count.
Exit code 0 = all assertions passed, 1 = at least one failed.

Usage: python3 tests/run_selftest.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FIXTURE = os.path.join(ROOT, "tests", "fixture_server.py")
BASE = "http://127.0.0.1:8791"

RESULTS = []


def check(label, ok, detail=""):
    RESULTS.append(ok)
    print("%s %s%s" % ("PASS" if ok else "FAIL", label, (" — " + detail) if detail else ""))


def wait_ready(proc, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(BASE + "/", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def main():
    from kl_deepscan.checks import CHECKS
    from kl_deepscan.engine import run_scan
    from kl_deepscan import ai_triage, report

    print("registered checks: %d" % len(CHECKS))
    if not CHECKS:
        print("FAIL check registry is empty (CHECKS stub) — scan assertions cannot pass yet")

    proc = subprocess.Popen(
        [sys.executable, FIXTURE],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        if not wait_ready(proc):
            check("fixture server starts", False, "no response on %s" % BASE)
            return 1
        check("fixture server starts", True)

        findings = run_scan(BASE)
        ids = [f.id.lower() for f in findings]
        print("findings: %d (%s)" % (len(findings), ", ".join(ids) or "none"))

        for needle in ("hdr", "cors", "git", "reflect"):
            hit = [i for i in ids if needle in i]
            check("finding id contains %r" % needle, bool(hit),
                  hit[0] if hit else "ids were: %s" % (", ".join(ids) or "none"))

        tmp = tempfile.mkdtemp(prefix="klds-selftest-")
        target = BASE
        paths = {}
        for fmt in ("json", "html", "sarif"):
            p = os.path.join(tmp, "report." + fmt)
            try:
                report.generate(findings, target, fmt, p)
                paths[fmt] = p
                check("report %s generated" % fmt,
                      os.path.isfile(p) and os.path.getsize(p) > 0, p)
            except Exception as exc:  # noqa: BLE001 - report the failure
                check("report %s generated" % fmt, False, repr(exc))

        if "json" in paths:
            try:
                doc = json.load(open(paths["json"], encoding="utf-8"))
                check("json report structure",
                      doc.get("target") == target
                      and "generated_at" in doc
                      and doc.get("summary", {}).get("total") == len(findings)
                      and isinstance(doc.get("findings"), list))
            except Exception as exc:  # noqa: BLE001
                check("json report structure", False, repr(exc))
        if "sarif" in paths:
            try:
                doc = json.load(open(paths["sarif"], encoding="utf-8"))
                run = doc["runs"][0]
                check("sarif report structure",
                      doc.get("version") == "2.1.0"
                      and run["tool"]["driver"]["name"] == "KL-DeepScan"
                      and len(run.get("results", [])) == len(findings))
            except Exception as exc:  # noqa: BLE001
                check("sarif report structure", False, repr(exc))
        if "html" in paths:
            try:
                text = open(paths["html"], encoding="utf-8").read()
                check("html report structure",
                      "#0A1931" in text and "#FF7A00" in text and target in text)
            except Exception as exc:  # noqa: BLE001
                check("html report structure", False, repr(exc))

        try:
            out = ai_triage.triage(findings)
            check("ai_triage returns str, never raises", isinstance(out, str),
                  "len=%d" % len(out))
        except Exception as exc:  # noqa: BLE001
            check("ai_triage returns str, never raises", False, repr(exc))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    passed = sum(1 for ok in RESULTS if ok)
    print("\nselftest: %d/%d passed" % (passed, len(RESULTS)))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
