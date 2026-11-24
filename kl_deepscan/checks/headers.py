"""Security response-header checks (one check per header / weakness)."""
import re

from ._common import F, home, register

FIX_GENERIC = "Set the header with a restrictive value on all HTML responses."


def _h(ctx, name):
    return (home(ctx).headers.get(name, "") or "").strip()


def _reachable(ctx):
    """False when the homepage fetch failed outright (no HTTP response)."""
    return home(ctx).status != 0


@register("hdr-csp-missing", "Content-Security-Policy header missing")
def check_csp_missing(ctx):
    if not _reachable(ctx):
        return []
    if _h(ctx, "content-security-policy"):
        return []
    return [F("medium", ctx.target + "/", "No Content-Security-Policy header",
              "Without CSP the browser applies no allowlist for scripts, styles or "
              "framing, so any injected markup executes freely.",
              "Add a Content-Security-Policy header, starting with "
              "default-src 'self' and loosening only where required.", "CWE-693")]


@register("hdr-csp-unsafe-inline", "CSP allows 'unsafe-inline'")
def check_csp_unsafe_inline(ctx):
    csp = _h(ctx, "content-security-policy")
    if "'unsafe-inline'" not in csp:
        return []
    return [F("medium", ctx.target + "/", "CSP contains 'unsafe-inline': " + csp[:120],
              "'unsafe-inline' lets any injected inline script run, largely "
              "defeating the XSS protection CSP is meant to provide.",
              "Remove 'unsafe-inline'; use nonces or hashes for inline scripts.", "CWE-79")]


@register("hdr-csp-unsafe-eval", "CSP allows 'unsafe-eval'")
def check_csp_unsafe_eval(ctx):
    csp = _h(ctx, "content-security-policy")
    if "'unsafe-eval'" not in csp:
        return []
    return [F("low", ctx.target + "/", "CSP contains 'unsafe-eval': " + csp[:120],
              "'unsafe-eval' permits eval()-style code execution, widening the "
              "impact of any injection flaw.",
              "Remove 'unsafe-eval' and refactor code that relies on eval().", "CWE-79")]


@register("hdr-csp-wildcard", "CSP uses a wildcard source")
def check_csp_wildcard(ctx):
    csp = _h(ctx, "content-security-policy")
    if not re.search(r"(default-src|script-src)[^;]*\*", csp):
        return []
    return [F("medium", ctx.target + "/", "CSP wildcard source: " + csp[:120],
              "A wildcard in default-src/script-src allows loading code from any "
              "origin, negating the policy.",
              "Replace * with an explicit allowlist of trusted origins.", "CWE-693")]


@register("hdr-xcto-missing", "X-Content-Type-Options missing or not nosniff")
def check_xcto(ctx):
    if not _reachable(ctx):
        return []
    v = _h(ctx, "x-content-type-options").lower()
    if v == "nosniff":
        return []
    return [F("low", ctx.target + "/", "X-Content-Type-Options: %r" % v,
              "Without nosniff, browsers may MIME-sniff responses and execute "
              "uploaded files as script.",
              "Set X-Content-Type-Options: nosniff.", "CWE-693")]


@register("hdr-xfo-missing", "Clickjacking protection missing (X-Frame-Options / frame-ancestors)")
def check_xfo(ctx):
    if not _reachable(ctx):
        return []
    if _h(ctx, "x-frame-options"):
        return []
    if "frame-ancestors" in _h(ctx, "content-security-policy"):
        return []
    return [F("medium", ctx.target + "/", "No X-Frame-Options and no CSP frame-ancestors",
              "The site can be framed by any origin, enabling clickjacking "
              "attacks against logged-in users.",
              "Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors 'self'.", "CWE-1021")]


@register("hdr-hsts-missing", "Strict-Transport-Security missing on HTTPS")
def check_hsts_missing(ctx):
    if not _reachable(ctx):
        return []
    if not ctx.target.lower().startswith("https://"):
        return []
    if _h(ctx, "strict-transport-security"):
        return []
    return [F("medium", ctx.target + "/", "No Strict-Transport-Security header",
              "Without HSTS, a first visit or any plain-HTTP link can be "
              "downgraded and intercepted (SSL stripping).",
              "Set Strict-Transport-Security: max-age=31536000; includeSubDomains.", "CWE-319")]


@register("hdr-hsts-weak", "HSTS max-age too short (< 1 year)")
def check_hsts_weak(ctx):
    v = _h(ctx, "strict-transport-security")
    m = re.search(r"max-age\s*=\s*(\d+)", v)
    if not m or int(m.group(1)) >= 31536000:
        return []
    return [F("low", ctx.target + "/", "HSTS header: " + v[:80],
              "A short max-age leaves long windows where returning users are "
              "not forced onto HTTPS.",
              "Raise max-age to at least 31536000 (one year).", "CWE-319")]


@register("hdr-hsts-no-subdomains", "HSTS without includeSubDomains")
def check_hsts_subdomains(ctx):
    v = _h(ctx, "strict-transport-security")
    if not v or "includesubdomains" in v.lower().replace(" ", ""):
        return []
    return [F("info", ctx.target + "/", "HSTS header: " + v[:80],
              "Subdomains are not covered by HSTS, so a plain-HTTP subdomain "
              "can still leak session cookies scoped to the parent domain.",
              "Add includeSubDomains to the HSTS header.", "CWE-319")]


@register("hdr-referrer-missing", "Referrer-Policy header missing")
def check_referrer(ctx):
    if not _reachable(ctx):
        return []
    if _h(ctx, "referrer-policy"):
        return []
    return [F("low", ctx.target + "/", "No Referrer-Policy header",
              "Browsers may send full URLs (including paths and query strings) "
              "in the Referer header to third parties.",
              "Set Referrer-Policy: strict-origin-when-cross-origin.", "CWE-359")]


@register("hdr-permissions-missing", "Permissions-Policy header missing")
def check_permissions(ctx):
    if not _reachable(ctx):
        return []
    if _h(ctx, "permissions-policy"):
        return []
    return [F("info", ctx.target + "/", "No Permissions-Policy header",
              "Powerful browser features (camera, microphone, geolocation) are "
              "not explicitly restricted for this origin.",
              "Add a Permissions-Policy disabling features the site does not use.", "CWE-693")]


@register("hdr-xss-protection-disabled", "Legacy X-XSS-Protection header present but disabled")
def check_xxsp(ctx):
    v = _h(ctx, "x-xss-protection")
    if not v.startswith("0"):
        return []
    return [F("info", ctx.target + "/", "X-XSS-Protection: " + v[:40],
              "The legacy XSS filter header is present but set to 0. Modern "
              "browsers ignore it; protection should come from CSP instead.",
              "Rely on a strong Content-Security-Policy; the legacy header may be removed.", "CWE-693")]


@register("hdr-server-version", "Server header discloses software version")
def check_server_version(ctx):
    v = _h(ctx, "server")
    if not v or not re.search(r"\d+\.\d+", v):
        return []
    return [F("low", ctx.target + "/", "Server: " + v[:80],
              "An exact server version lets attackers match the site against "
              "known CVE lists without probing.",
              "Suppress version tokens in the Server header.", "CWE-200")]


@register("hdr-powered-by", "X-Powered-By header discloses technology")
def check_powered_by(ctx):
    v = _h(ctx, "x-powered-by")
    if not v:
        return []
    return [F("low", ctx.target + "/", "X-Powered-By: " + v[:80],
              "Framework/language disclosure helps attackers target "
              "technology-specific exploits.",
              "Remove the X-Powered-By header.", "CWE-200")]


@register("hdr-aspnet-version", "X-AspNet-Version header present")
def check_aspnet(ctx):
    v = _h(ctx, "x-aspnet-version")
    if not v:
        return []
    return [F("low", ctx.target + "/", "X-AspNet-Version: " + v[:40],
              "Exact ASP.NET version disclosure aids targeted exploitation.",
              "Set <httpRuntime enableVersionHeader=\"false\" />.", "CWE-200")]


@register("hdr-corp-missing", "Cross-Origin-Resource-Policy header missing")
def check_corp(ctx):
    if not _reachable(ctx):
        return []
    if _h(ctx, "cross-origin-resource-policy"):
        return []
    return [F("info", ctx.target + "/", "No Cross-Origin-Resource-Policy header",
              "Without CORP, other origins can embed this site's resources, "
              "which matters for Spectre-style cross-origin data leaks.",
              "Set Cross-Origin-Resource-Policy: same-origin (or same-site).", "CWE-693")]


@register("hdr-coop-missing", "Cross-Origin-Opener-Policy header missing")
def check_coop(ctx):
    if not _reachable(ctx):
        return []
    if _h(ctx, "cross-origin-opener-policy"):
        return []
    return [F("info", ctx.target + "/", "No Cross-Origin-Opener-Policy header",
              "Without COOP, pages opened from this site retain a window "
              "reference, enabling cross-origin window manipulation.",
              "Set Cross-Origin-Opener-Policy: same-origin.", "CWE-693")]
