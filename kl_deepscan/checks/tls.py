"""TLS / certificate checks using raw ssl sockets (stdlib only)."""
import logging
import os
import socket
import ssl
import tempfile
from datetime import datetime
from urllib.parse import urlparse

from ._common import F, _cached, register


def _hostport(ctx):
    u = urlparse(ctx.target)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port


def _is_https(ctx):
    return urlparse(ctx.target).scheme == "https"


def _cert_info(ctx):
    """Decoded peer certificate dict (or None). Fetched once per scan."""
    def fetch():
        host, port = _hostport(ctx)
        raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        raw_ctx.check_hostname = False
        raw_ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with raw_ctx.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
        except Exception:
            return None
        if not der:
            return None
        path = None
        try:
            fd, path = tempfile.mkstemp(suffix=".der")
            with os.fdopen(fd, "wb") as fh:
                fh.write(der)
            return ssl._ssl._test_decode_cert(path)  # stdlib CPython helper
        except Exception:
            return None
        finally:
            if path:
                try:
                    os.unlink(path)
                except Exception as e:
                    logging.getLogger(__name__).debug("gagal hapus file sertifikat sementara %s: %s", path, e)
    return _cached(ctx, "cert_info", fetch)


def _parse_date(value):
    try:
        norm = " ".join(str(value).split())
        return datetime.strptime(norm, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        return None


def _cert_dates(ctx):
    info = _cert_info(ctx)
    if not info:
        return None, None
    return _parse_date(info.get("notBefore")), _parse_date(info.get("notAfter"))


def _verified_error(ctx):
    """Error string from a fully-verifying handshake ('' if it succeeds)."""
    def attempt():
        host, port = _hostport(ctx)
        vctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with vctx.wrap_socket(sock, server_hostname=host):
                    return ""
        except Exception as exc:  # SSLCertVerificationError and friends
            return str(exc)
    return _cached(ctx, "verified_error", attempt)


def _old_tls_accepted(ctx, version):
    host, port = _hostport(ctx)
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tctx.check_hostname = False
            tctx.verify_mode = ssl.CERT_NONE
            tctx.minimum_version = version
            tctx.maximum_version = version
            with socket.create_connection((host, port), timeout=8) as sock:
                with tctx.wrap_socket(sock, server_hostname=host):
                    return True
    except Exception:
        return False
    return False


@register("tls-cert-expired", "TLS certificate is expired")
def check_cert_expired(ctx):
    if not _is_https(ctx):
        return []
    _, not_after = _cert_dates(ctx)
    if not_after and not_after < datetime.utcnow():
        return [F("high", ctx.target, "Certificate notAfter: %s" % not_after,
                  "The TLS certificate has expired; browsers block the site and "
                  "users are trained to click through warnings.",
                  "Renew the certificate immediately and automate renewal.", "CWE-298")]
    return []


@register("tls-cert-expiring-soon", "TLS certificate expires within 30 days")
def check_cert_expiring(ctx):
    if not _is_https(ctx):
        return []
    _, not_after = _cert_dates(ctx)
    if not not_after:
        return []
    days = (not_after - datetime.utcnow()).days
    if 0 <= days < 30:
        return [F("medium", ctx.target, "Certificate expires in %d day(s): %s" % (days, not_after),
                  "A certificate close to expiry risks an outage and user-facing "
                  "browser warnings if renewal is missed.",
                  "Renew now and set up automated renewal (e.g. ACME) plus expiry alerts.", "CWE-298")]
    return []


@register("tls-cert-long-validity", "TLS certificate validity period over 398 days")
def check_cert_long_validity(ctx):
    if not _is_https(ctx):
        return []
    not_before, not_after = _cert_dates(ctx)
    if not_before and not_after and (not_after - not_before).days > 398:
        return [F("low", ctx.target,
                  "Validity: %s -> %s (%d days)" % (not_before, not_after, (not_after - not_before).days),
                  "Certificates valid longer than 398 days violate current "
                  "CA/Browser Forum baselines and slow revocation hygiene.",
                  "Reissue with a validity period of 398 days or less.", "CWE-298")]
    return []


@register("tls-untrusted-cert", "Certificate chain not trusted (self-signed / incomplete chain)")
def check_untrusted(ctx):
    if not _is_https(ctx):
        return []
    err = _verified_error(ctx)
    low = err.lower()
    if err and ("self signed" in low or "self-signed" in low
                or "unable to get local issuer" in low
                or "unable to verify" in low):
        return [F("high", ctx.target, "Verified handshake failed: " + err[:140],
                  "The certificate is self-signed or its chain is incomplete, so "
                  "browsers cannot authenticate the server and show warnings.",
                  "Install a certificate from a public CA with the full chain.", "CWE-295")]
    return []


@register("tls-hostname-mismatch", "Certificate does not match the hostname")
def check_hostname_mismatch(ctx):
    if not _is_https(ctx):
        return []
    err = _verified_error(ctx)
    low = err.lower()
    if err and ("hostname mismatch" in low or "doesn't match" in low
                or "does not match" in low):
        return [F("high", ctx.target, "Verified handshake failed: " + err[:140],
                  "The certificate was issued for a different hostname; users "
                  "get browser warnings and the connection is not authenticated.",
                  "Issue a certificate covering this exact hostname (SAN).", "CWE-297")]
    return []


@register("tls-version-10", "TLS 1.0 still accepted")
def check_tls10(ctx):
    if not _is_https(ctx):
        return []
    if _old_tls_accepted(ctx, ssl.TLSVersion.TLSv1):
        return [F("medium", ctx.target, "Handshake with TLS 1.0 succeeded",
                  "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST and "
                  "downgrade attacks; PCI DSS forbids it.",
                  "Disable TLS 1.0 and 1.1; require TLS 1.2 or newer.", "CWE-327")]
    return []


@register("tls-version-11", "TLS 1.1 still accepted")
def check_tls11(ctx):
    if not _is_https(ctx):
        return []
    if _old_tls_accepted(ctx, ssl.TLSVersion.TLSv1_1):
        return [F("medium", ctx.target, "Handshake with TLS 1.1 succeeded",
                  "TLS 1.1 is deprecated (RFC 8996) and lacks modern cipher and "
                  "AEAD support.",
                  "Disable TLS 1.1; require TLS 1.2 or newer.", "CWE-327")]
    return []


@register("tls-http-not-redirected", "Plain HTTP does not redirect to HTTPS")
def check_http_redirect(ctx):
    if not _is_https(ctx):
        return []
    host, _ = _hostport(ctx)
    u = urlparse(ctx.target)
    http_url = "http://" + host + ((":" + str(u.port)) if u.port else "") + "/"
    resp = ctx.client.get(http_url)
    if resp.status in (301, 302, 307, 308):
        loc = resp.headers.get("location", "")
        if loc.startswith("https://"):
            return []
    if resp.status == 200:
        return [F("medium", ctx.target, "HTTP version served content with status 200",
                  "The site is fully usable over plain HTTP, so credentials and "
                  "session cookies can be intercepted on hostile networks.",
                  "Redirect all HTTP traffic to HTTPS and enable HSTS.", "CWE-319")]
    return []
