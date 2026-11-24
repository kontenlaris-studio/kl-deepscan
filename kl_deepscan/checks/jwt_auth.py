"""JWT checks on tokens found in homepage cookies (decode only, no
signature attacks, no credential use)."""
import base64
import json
import re
import time

from ._common import F, home_cookies, register

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64json(segment):
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None


def _tokens(ctx):
    """Yield (cookie_name, header_dict, payload_dict) for JWT-looking cookies."""
    out = []
    for cookie in home_cookies(ctx):
        m = JWT_RE.search(cookie.get("value", ""))
        if not m:
            continue
        parts = m.group(0).split(".")
        header = _b64json(parts[0])
        payload = _b64json(parts[1])
        if isinstance(header, dict) and isinstance(payload, dict) and "alg" in header:
            out.append((cookie["name"], header, payload))
    return out


def _url(ctx):
    return ctx.target + "/"


@register("jwt-none-alg", "JWT with alg=none accepted in a cookie")
def check_none_alg(ctx):
    out = []
    for name, header, _payload in _tokens(ctx):
        if str(header.get("alg", "")).lower() == "none":
            out.append(F("critical", _url(ctx),
                         "Cookie %s carries a JWT with alg=none" % name,
                         "An unsigned JWT (alg=none) can be forged by anyone "
                         "if the server accepts it, giving full session control.",
                         "Reject alg=none server-side; pin the expected algorithm.", "CWE-347",
                         title="JWT in cookie '%s' uses alg=none" % name))
    return out


@register("jwt-no-expiry", "JWT without an expiry (exp) claim")
def check_no_exp(ctx):
    out = []
    for name, _header, payload in _tokens(ctx):
        if "exp" not in payload:
            out.append(F("medium", _url(ctx),
                         "JWT in cookie %s has no exp claim" % name,
                         "A token that never expires stays valid forever if "
                         "leaked, and cannot be aged out.",
                         "Issue short-lived tokens with exp and refresh rotation.", "CWE-613",
                         title="JWT in cookie '%s' never expires" % name))
    return out


@register("jwt-expired-token-set", "Server sets an already-expired JWT")
def check_expired(ctx):
    out = []
    now = time.time()
    for name, _header, payload in _tokens(ctx):
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and exp < now:
            out.append(F("low", _url(ctx),
                         "JWT in cookie %s has exp=%d (in the past)" % (name, int(exp)),
                         "The server is issuing expired tokens, which points "
                         "to clock skew or a broken token-issuing flow and "
                         "often pairs with lax expiry validation.",
                         "Fix token issuance and enforce exp validation.", "CWE-613",
                         title="JWT in cookie '%s' is already expired" % name))
    return out


@register("jwt-long-lived", "JWT lifetime over 30 days")
def check_long_lived(ctx):
    out = []
    for name, _header, payload in _tokens(ctx):
        exp, iat = payload.get("exp"), payload.get("iat")
        if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
            if exp - iat > 30 * 24 * 3600:
                out.append(F("low", _url(ctx),
                             "JWT in cookie %s lives %d days" % (name, int((exp - iat) / 86400)),
                             "Very long-lived tokens widen the window for "
                             "stolen-token abuse.",
                             "Shorten token lifetime; use refresh-token rotation.", "CWE-613",
                             title="JWT in cookie '%s' is valid for over 30 days" % name))
    return out


@register("jwt-sensitive-claims", "JWT payload carries sensitive claims")
def check_sensitive(ctx):
    bad_keys = ("password", "passwd", "secret", "ssn", "credit_card",
                "card_number", "private_key", "api_key")
    out = []
    for name, _header, payload in _tokens(ctx):
        found = [k for k in payload if any(b in k.lower() for b in bad_keys)]
        if found:
            out.append(F("medium", _url(ctx),
                         "JWT in cookie %s contains claims: %s" % (name, ", ".join(found)),
                         "JWT payloads are only base64-encoded, not encrypted: "
                         "anyone holding the cookie can read these values.",
                         "Never place secrets or credentials inside a JWT payload.", "CWE-359",
                         title="JWT in cookie '%s' exposes sensitive claims" % name))
    return out
