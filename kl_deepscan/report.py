"""Report generation for KL-DeepScan.

generate(findings, target, fmt, out_path) writes one of:
  - json : structured report (target, generated_at, summary, findings)
  - html : single self-contained file, inline CSS, brand navy/orange
  - sarif: SARIF 2.1.0 for code-scanning dashboards

Python stdlib only.
"""
import dataclasses
import html
import json
import os
from datetime import datetime, timezone

from kl_deepscan.models import SEVERITIES, SEVERITY_RANK

TOOL_NAME = "KL-DeepScan"
TOOL_VERSION = "1.0.0"

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SEV_COLOR = {
    "critical": "#b00020",
    "high": "#e65100",
    "medium": "#FF7A00",
    "low": "#8a6d00",
    "info": "#546e7a",
}


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summary(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return {"total": len(findings), "by_severity": counts}


def _sorted(findings):
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id, f.url))


def _write(out_path, text):
    d = os.path.dirname(os.path.abspath(out_path))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return out_path


# ---------------------------------------------------------------- JSON

def _to_json(findings, target):
    doc = {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "target": target,
        "generated_at": _now_iso(),
        "summary": _summary(findings),
        "findings": [dataclasses.asdict(f) for f in _sorted(findings)],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- SARIF

def _to_sarif(findings, target):
    ordered = _sorted(findings)
    rules = {}
    for f in ordered:
        if f.id not in rules:
            rule = {
                "id": f.id,
                "name": f.id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "help": {"text": f.remediation or f.description or f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
            }
            if f.cwe:
                rule["properties"] = {"cwe": f.cwe}
            rules[f.id] = rule
    results = []
    for f in ordered:
        results.append({
            "ruleId": f.id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": "%s — %s" % (f.title, f.evidence) if f.evidence else f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url or target},
                }
            }],
            "properties": {"severity": f.severity, "cwe": f.cwe},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/kontenlaris-studio/kl-deepscan",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- HTML

_CSS = """
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       background: #f4f6f9; color: #1c2733; }
header { background: #0A1931; color: #fff; padding: 28px 36px; }
header h1 { margin: 0 0 6px; font-size: 26px; }
header h1 span { color: #FF7A00; }
header .meta { color: #b9c6d4; font-size: 13px; word-break: break-all; }
main { padding: 24px 36px 40px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 26px; }
.card { background: #fff; border: 1px solid #dde3ea; border-top: 4px solid #0A1931;
        border-radius: 6px; padding: 12px 18px; min-width: 110px; }
.card .n { font-size: 24px; font-weight: 700; }
.card .l { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #5b6b7c; }
h2 { color: #0A1931; border-bottom: 2px solid #FF7A00; padding-bottom: 4px; margin-top: 30px; }
table { width: 100%; border-collapse: collapse; background: #fff; }
th, td { border: 1px solid #dde3ea; padding: 8px 10px; vertical-align: top;
         font-size: 13px; text-align: left; }
th { background: #0A1931; color: #fff; }
td.url, td.ev { word-break: break-all; font-family: ui-monospace, Menlo, Consolas, monospace;
                font-size: 12px; }
.badge { display: inline-block; color: #fff; border-radius: 3px; padding: 1px 7px;
         font-size: 11px; font-weight: 700; text-transform: uppercase; }
.empty { background: #fff; border: 1px solid #dde3ea; border-radius: 6px; padding: 18px; }
footer { color: #5b6b7c; font-size: 12px; padding: 0 36px 28px; }
"""


def _to_html(findings, target):
    esc = html.escape
    summary = _summary(findings)
    cards = ['<div class="card"><div class="n">%d</div><div class="l">Total</div></div>'
             % summary["total"]]
    for sev in SEVERITIES:
        cards.append(
            '<div class="card" style="border-top-color:%s"><div class="n">%d</div>'
            '<div class="l">%s</div></div>'
            % (_SEV_COLOR[sev], summary["by_severity"][sev], sev))
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>KL-DeepScan Report — %s</title>" % esc(target),
        "<style>%s</style></head><body>" % _CSS,
        "<header><h1>KL-<span>DeepScan</span> Report</h1>",
        '<div class="meta">Target: %s<br>Generated: %s</div></header>'
        % (esc(target), esc(_now_iso())),
        "<main>",
        '<div class="cards">%s</div>' % "".join(cards),
    ]
    ordered = _sorted(findings)
    if not ordered:
        parts.append('<div class="empty">No findings. All checks passed for this target.</div>')
    for sev in SEVERITIES:
        group = [f for f in ordered if f.severity == sev]
        if not group:
            continue
        parts.append("<h2>%s (%d)</h2>" % (esc(sev.capitalize()), len(group)))
        parts.append("<table><tr><th>Finding</th><th>URL</th><th>Evidence</th>"
                     "<th>Description</th><th>Remediation</th><th>CWE</th></tr>")
        for f in group:
            parts.append(
                "<tr><td><span class=\"badge\" style=\"background:%s\">%s</span> %s</td>"
                "<td class=\"url\">%s</td><td class=\"ev\">%s</td><td>%s</td><td>%s</td>"
                "<td>%s</td></tr>"
                % (_SEV_COLOR.get(f.severity, "#546e7a"), esc(f.severity), esc(f.title),
                   esc(f.url), esc(f.evidence), esc(f.description), esc(f.remediation),
                   esc(f.cwe)))
        parts.append("</table>")
    parts.append("</main>")
    parts.append("<footer>Generated by KL-DeepScan (Kontenlaris Studio) — "
                 "detection-only scanner. Verify findings before acting on them.</footer>")
    parts.append("</body></html>")
    return "\n".join(parts)


# ---------------------------------------------------------------- API

_BUILDERS = {"json": _to_json, "html": _to_html, "sarif": _to_sarif}


def generate(findings, target, fmt, out_path):
    """Write a report of `findings` for `target` in format `fmt` to `out_path`.

    fmt is one of "json", "html", "sarif". Returns out_path.
    """
    fmt = (fmt or "json").lower()
    if fmt not in _BUILDERS:
        raise ValueError("unsupported report format: %r (use json, html or sarif)" % fmt)
    return _write(out_path, _BUILDERS[fmt](list(findings), target))
