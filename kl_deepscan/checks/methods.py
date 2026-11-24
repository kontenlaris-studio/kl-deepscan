"""HTTP method checks (TRACE / dangerous methods advertised via Allow)."""
from ._common import F, register

DANGEROUS = ("PUT", "DELETE", "PATCH", "CONNECT")


@register("method-trace-enabled", "HTTP TRACE method enabled")
def check_trace(ctx):
    resp = ctx.client.request("TRACE", ctx.target + "/")
    if resp.status == 200:
        return [F("medium", ctx.target + "/", "TRACE request returned status 200",
                  "TRACE echoes request headers back and can be abused for "
                  "cross-site tracing (XST) to steal headers/cookies.",
                  "Disable the TRACE method on the web server.", "CWE-693")]
    return []


@register("method-dangerous-allowed", "Dangerous HTTP methods advertised in Allow")
def check_dangerous(ctx):
    resp = ctx.client.request("OPTIONS", ctx.target + "/")
    allow = resp.headers.get("allow", "") or resp.headers.get(
        "access-control-allow-methods", "")
    present = [m for m in DANGEROUS if m in allow.upper()]
    if not present:
        return []
    return [F("low", ctx.target + "/",
              "Allow advertises: %s" % ", ".join(present),
              "Write-capable methods (PUT/DELETE/PATCH) exposed on the web "
              "root may allow content upload or deletion if handlers exist.",
              "Restrict allowed methods to GET/POST/HEAD/OPTIONS where possible.", "CWE-693")]
