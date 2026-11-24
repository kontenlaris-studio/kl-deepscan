"""Cookie attribute checks (evaluated per cookie set by the homepage)."""
from ._common import F, home_cookies, register


def _url(ctx):
    return ctx.target + "/"


@register("cookie-no-secure", "Cookie set without the Secure flag")
def check_no_secure(ctx):
    if not ctx.target.lower().startswith("https://"):
        return []
    out = []
    for c in home_cookies(ctx):
        if "secure" not in c["flags"]:
            out.append(F("medium", _url(ctx),
                         "Cookie %s lacks Secure" % c["name"],
                         "A cookie without Secure is also sent over plain HTTP, "
                         "where it can be captured on hostile networks.",
                         "Add the Secure attribute to all cookies on HTTPS sites.", "CWE-614",
                         title="Cookie '%s' lacks the Secure flag" % c["name"]))
    return out


@register("cookie-no-httponly", "Cookie set without the HttpOnly flag")
def check_no_httponly(ctx):
    out = []
    for c in home_cookies(ctx):
        if "httponly" not in c["flags"]:
            out.append(F("low", _url(ctx),
                         "Cookie %s lacks HttpOnly" % c["name"],
                         "Without HttpOnly, any XSS flaw can read this cookie "
                         "from JavaScript and exfiltrate it.",
                         "Add HttpOnly to session and other sensitive cookies.", "CWE-1004",
                         title="Cookie '%s' lacks the HttpOnly flag" % c["name"]))
    return out


@register("cookie-no-samesite", "Cookie set without SameSite")
def check_no_samesite(ctx):
    out = []
    for c in home_cookies(ctx):
        if "samesite" not in c["attrs"]:
            out.append(F("low", _url(ctx),
                         "Cookie %s has no SameSite attribute" % c["name"],
                         "Cookies without SameSite rely on browser defaults and "
                         "may be sent on cross-site requests, enabling CSRF.",
                         "Set SameSite=Lax (or Strict) on cookies.", "CWE-1275",
                         title="Cookie '%s' has no SameSite attribute" % c["name"]))
    return out


@register("cookie-samesite-none-no-secure", "SameSite=None cookie without Secure")
def check_samesite_none(ctx):
    out = []
    for c in home_cookies(ctx):
        if c["attrs"].get("samesite", "").lower() == "none" and "secure" not in c["flags"]:
            out.append(F("medium", _url(ctx),
                         "Cookie %s: SameSite=None without Secure" % c["name"],
                         "SameSite=None cookies are sent cross-site; without "
                         "Secure they also travel over plain HTTP. Modern "
                         "browsers reject this combination.",
                         "Add Secure to any SameSite=None cookie, or use Lax.", "CWE-1275",
                         title="Cookie '%s' uses SameSite=None without Secure" % c["name"]))
    return out
