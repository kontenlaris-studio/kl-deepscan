"""Active-but-harmless probes: marker reflection, SQL error signatures,
open redirects, and a GraphQL introspection query. Payloads are the
per-scan marker token or a single quote character only — nothing else.
"""
import json
import urllib.parse

from ._common import F, register

SQL_ERRORS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-01756",
    "ora-00933",
    "sqlstate[",
    "sqlite3.",
    "microsoft ole db provider for sql server",
    "supplied argument is not a valid mysql",
    "syntax error at or near",
    "unterminated quoted string",
    "pg_query(",
    "mysql_fetch",
)

REDIRECT_PARAMS = ("next", "url", "redirect", "return", "returnUrl",
                   "continue", "dest", "destination", "goto", "r")
REFLECT_PARAMS = ("q", "s", "search", "query", "keyword", "term", "input", "name")
SQL_PARAMS = ("id", "q", "search", "query", "cat", "product", "page")


def _with_params(ctx, params):
    qs = urllib.parse.urlencode(params)
    return ctx.target + "/?" + qs


@register("probe-reflected-marker", "Input reflected unescaped in the response (possible XSS)")
def check_reflected(ctx):
    marker = ctx.marker
    for path in ("", "/search"):
        for param in REFLECT_PARAMS:
            url = ctx.target + path + "?" + urllib.parse.urlencode({param: marker}) \
                if path else _with_params(ctx, {param: marker})
            resp = ctx.client.get(url)
            if resp.status == 200 and marker in (resp.text or ""):
                return [F("low", url,
                      "Marker %s reflected verbatim in the response body" % marker,
                      "User input is reflected into the page without visible "
                      "encoding. If the reflection lands in an HTML/JS context, "
                      "this is reflected XSS. (Detected with a harmless marker "
                      "only — no script payload was sent.)",
                      "Contextually encode all reflected input; add a strict CSP.", "CWE-79")]
    return []


@register("probe-sql-error", "Database error disclosed by a quote probe (possible SQL injection)")
def check_sql_error(ctx):
    for param in SQL_PARAMS:
        resp = ctx.client.get(_with_params(ctx, {param: "1'"}))
        body = (resp.text or "").lower()
        found = [s for s in SQL_ERRORS if s in body]
        if found:
            return [F("medium", _with_params(ctx, {param: "1'"}),
                      "Response contains DB error signature: %r" % found[0],
                      "A single quote in a parameter produced a database error "
                      "message, which strongly suggests unsanitized input "
                      "reaches a SQL query (possible SQL injection) and that "
                      "errors are shown to users.",
                      "Use parameterized queries everywhere and suppress DB "
                      "errors in production responses.", "CWE-89")]
    return []


@register("probe-open-redirect", "Open redirect via a common redirect parameter")
def check_open_redirect(ctx):
    evil = "https://%s.evil.example/" % ctx.marker
    for param in REDIRECT_PARAMS:
        resp = ctx.client.get(_with_params(ctx, {param: evil}))
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location", "")
            if loc.startswith(evil) or loc.startswith("//" + ctx.marker):
                return [F("medium", _with_params(ctx, {param: evil}),
                          "Redirect Location: %s" % loc[:120],
                          "The '%s' parameter controls the redirect target "
                          "without validation, enabling phishing links on a "
                          "trusted domain." % param,
                          "Allowlist redirect targets or use relative paths only.", "CWE-601")]
    return []


@register("probe-graphql-introspection", "GraphQL introspection enabled")
def check_graphql(ctx):
    payload = json.dumps({"query": "{__schema{queryType{name}}}"})
    for path in ("/graphql", "/api/graphql"):
        resp = ctx.client.request(
            "POST", ctx.target + path,
            headers={"Content-Type": "application/json"}, data=payload)
        body = resp.text or ""
        if resp.status == 200 and "__schema" in body and "queryType" in body:
            return [F("medium", ctx.target + path,
                      "Introspection query returned the schema",
                      "With introspection enabled, anyone can download the "
                      "entire API schema — every type, field and mutation — "
                      "which maps the attack surface precisely.",
                      "Disable introspection in production (or gate it behind auth).", "CWE-200")]
    return []
