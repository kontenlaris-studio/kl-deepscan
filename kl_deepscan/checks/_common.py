"""Shared helpers + registry for KL-DeepScan checks.

Every check module decorates its functions with @register("id", "title").
The decorator (a) appends to ALL_CHECKS, (b) swallows all exceptions
(failed check -> no findings), and (c) stamps the registered id onto
every returned Finding so registry ids and finding ids can never drift.
"""
import functools
import re

from kl_deepscan.models import Finding

ALL_CHECKS = []


def register(check_id, title):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(ctx):
            try:
                out = fn(ctx) or []
            except Exception:
                return []
            for f in out:
                try:
                    f.id = check_id
                except Exception:
                    pass
            return out
        ALL_CHECKS.append((check_id, title, wrapper))
        return wrapper
    return deco


def F(severity, url, evidence, description, remediation, cwe="", title=""):
    return Finding(id="", title=title, severity=severity, url=url,
                   evidence=evidence, description=description,
                   remediation=remediation, cwe=cwe)


# ---------------------------------------------------------------- ctx cache

def _cached(ctx, key, producer):
    cache = getattr(ctx, "_kl_cache", None)
    if cache is None:
        cache = {}
        try:
            ctx._kl_cache = cache
        except Exception:
            return producer()
    if key not in cache:
        cache[key] = producer()
    return cache[key]


def home(ctx):
    """Homepage response (target + '/'), fetched once per scan."""
    return _cached(ctx, "home", lambda: ctx.client.get(ctx.target + "/"))


def bogus(ctx):
    """Response for a certainly-nonexistent path (soft-404 baseline)."""
    return _cached(ctx, "bogus",
                   lambda: ctx.client.get(ctx.target + "/" + ctx.marker + "-notfound"))


def is_real_hit(ctx, resp):
    """True if resp looks like real content, not a soft-404 / error page."""
    if resp is None or resp.status != 200:
        return False
    base = bogus(ctx)
    if base is not None and base.status == 200:
        blen = max(len(base.text or ""), 1)
        rlen = len(resp.text or "")
        # Soft-404: same status and near-identical body size as the bogus page.
        if abs(rlen - blen) / float(blen) < 0.05:
            return False
    return True


# ---------------------------------------------------------------- cookies

def parse_cookies(resp):
    """Parse the Set-Cookie header(s) of a response into dicts.

    Resp.headers is a flat dict, so multiple Set-Cookie headers arrive
    combined into one string; split on ', ' only when followed by a
    fresh cookie name (avoids splitting inside Expires dates).
    """
    raw = ""
    try:
        raw = resp.headers.get("set-cookie", "") or ""
    except Exception:
        return []
    if not raw:
        return []
    parts = re.split(r",\s*(?=[^;,= ]+=[^;,]*)", raw)
    cookies = []
    for part in parts:
        segs = [s.strip() for s in part.split(";")]
        if not segs or "=" not in segs[0]:
            continue
        name, _, value = segs[0].partition("=")
        attrs = {}
        flags = set()
        for seg in segs[1:]:
            if "=" in seg:
                k, _, v = seg.partition("=")
                attrs[k.strip().lower()] = v.strip()
            elif seg:
                flags.add(seg.lower())
        cookies.append({"name": name.strip(), "value": value.strip(),
                        "attrs": attrs, "flags": flags})
    return cookies


def home_cookies(ctx):
    return _cached(ctx, "cookies", lambda: parse_cookies(home(ctx)))
