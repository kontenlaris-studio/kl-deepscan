"""Cross-Origin Resource Sharing (CORS) misconfiguration checks."""
from ._common import F, register


def _probe(ctx, origin):
    return ctx.client.get(ctx.target + "/", headers={"Origin": origin})


@register("cors-reflected-origin", "CORS reflects arbitrary Origin")
def check_reflected(ctx):
    evil = "https://%s.evil.example" % ctx.marker
    resp = _probe(ctx, evil)
    acao = resp.headers.get("access-control-allow-origin", "")
    if acao.strip() != evil:
        return []
    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    sev = "high" if acac else "medium"
    return [F(sev, ctx.target + "/",
              "Origin %s reflected in Access-Control-Allow-Origin%s"
              % (evil, " with credentials allowed" if acac else ""),
              "The server reflects any Origin, so a malicious site can read "
              "authenticated API responses from a victim's browser.",
              "Allowlist trusted origins server-side; never reflect arbitrary "
              "Origin values, especially with credentials.", "CWE-942")]


@register("cors-wildcard-credentials", "CORS wildcard origin combined with credentials")
def check_wildcard_creds(ctx):
    resp = _probe(ctx, "https://example.com")
    acao = resp.headers.get("access-control-allow-origin", "").strip()
    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    if acao == "*" and acac:
        return [F("high", ctx.target + "/",
                  "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                  "A wildcard origin together with credentialed requests is an "
                  "invalid, dangerous combination that some clients mishandle.",
                  "Use an explicit origin allowlist when credentials are involved.", "CWE-942")]
    return []


@register("cors-null-origin", "CORS trusts the null origin")
def check_null_origin(ctx):
    resp = _probe(ctx, "null")
    acao = resp.headers.get("access-control-allow-origin", "").strip()
    if acao != "null":
        return []
    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    return [F("medium" if not acac else "high", ctx.target + "/",
              "Origin 'null' reflected in Access-Control-Allow-Origin",
              "The null origin is sent by sandboxed iframes, redirects and "
              "file:// pages; trusting it lets attacker pages read responses.",
              "Remove 'null' from the CORS origin allowlist.", "CWE-942")]
