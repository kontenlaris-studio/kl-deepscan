"""HTML-level checks on the homepage body."""
import re

from ._common import F, home, register


def _body(ctx):
    return home(ctx).text or ""


def _is_https(ctx):
    return ctx.target.lower().startswith("https://")


@register("misc-mixed-content", "HTTPS page loads HTTP subresources (mixed content)")
def check_mixed(ctx):
    if not _is_https(ctx):
        return []
    hits = re.findall(r"(?:src|href)\s*=\s*[\"']http://[^\"']+", _body(ctx), re.I)
    if not hits:
        return []
    return [F("medium", ctx.target + "/",
              "Insecure subresource: %s" % hits[0][:100],
              "Scripts/styles loaded over HTTP on an HTTPS page can be "
              "modified in transit, defeating the page's encryption.",
              "Serve all subresources over HTTPS or use relative URLs.", "CWE-319")]


@register("misc-form-over-http", "Form submits to an HTTP action from an HTTPS page")
def check_form_http(ctx):
    if not _is_https(ctx):
        return []
    hits = re.findall(r"<form[^>]+action\s*=\s*[\"']http://[^\"']+", _body(ctx), re.I)
    if not hits:
        return []
    return [F("medium", ctx.target + "/",
              "Form action uses http:// on an HTTPS page",
              "Data entered in this form (possibly credentials) is sent "
              "unencrypted despite the page itself being HTTPS.",
              "Point form actions at HTTPS endpoints.", "CWE-319")]


@register("misc-login-over-http", "Password field served over plain HTTP")
def check_login_http(ctx):
    if _is_https(ctx):
        return []
    if re.search(r"<input[^>]+type\s*=\s*[\"']?password", _body(ctx), re.I):
        return [F("high", ctx.target + "/",
                  "Login form with a password field served over HTTP",
                  "Credentials entered here cross the network in clear text "
                  "and can be captured by anyone on the path.",
                  "Serve login pages exclusively over HTTPS with HSTS.", "CWE-319")]
    return []


@register("misc-meta-generator", "Generator meta tag discloses CMS and version")
def check_generator(ctx):
    m = re.search(r"<meta[^>]+name\s*=\s*[\"']generator[\"'][^>]+content\s*=\s*[\"']([^\"']+)",
                  _body(ctx), re.I)
    if not m:
        m = re.search(r"<meta[^>]+content\s*=\s*[\"']([^\"']+)[\"'][^>]+name\s*=\s*[\"']generator",
                      _body(ctx), re.I)
    if not m:
        return []
    return [F("low", ctx.target + "/",
              "Generator: %s" % m.group(1)[:80],
              "The generator tag names the CMS (and often its exact version), "
              "letting attackers pick matching public exploits.",
              "Remove or genericize the generator meta tag.", "CWE-200")]


@register("misc-sri-missing", "External scripts loaded without Subresource Integrity")
def check_sri(ctx):
    body = _body(ctx)
    scripts = re.findall(r"<script[^>]+src\s*=\s*[\"']https?://[^\"']+[\"'][^>]*>", body, re.I)
    missing = [s for s in scripts if "integrity=" not in s.lower()]
    if not missing:
        return []
    return [F("low", ctx.target + "/",
              "%d external script(s) without integrity attribute, e.g. %s"
              % (len(missing), missing[0][:100]),
              "If a CDN or third-party script is compromised, browsers run "
              "the altered code with no integrity check.",
              "Add integrity=\"sha384-...\" (and crossorigin) to external scripts.", "CWE-353")]


@register("misc-target-blank-noopener", "target=_blank links without rel=noopener")
def check_blank(ctx):
    links = re.findall(r"<a[^>]+target\s*=\s*[\"']_blank[\"'][^>]*>", _body(ctx), re.I)
    bad = [a for a in links if "noopener" not in a.lower()]
    if not bad:
        return []
    return [F("low", ctx.target + "/",
              "%d target=_blank link(s) lack rel=noopener" % len(bad),
              "Pages opened via target=_blank keep a window.opener reference "
              "and can navigate the original tab (reverse tabnabbing).",
              "Add rel=\"noopener noreferrer\" to target=_blank links.", "CWE-1022")]
