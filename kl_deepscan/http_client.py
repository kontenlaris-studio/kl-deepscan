"""Minimal urllib-based HTTP client for KL-DeepScan.

Design rules:
- Never raises on HTTP error statuses: the response is returned as-is.
- Never raises on network errors either: returns Resp(status=0, ...).
- TLS certificate verification is disabled on purpose (scanning tool:
  targets with broken/expired/self-signed certs must still be scannable;
  cert problems are reported by the TLS checks instead).
"""
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "KL-DeepScan/1.0"
TIMEOUT = 10

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


@dataclass
class Resp:
    status: int
    headers: dict = field(default_factory=dict)  # keys lower-cased
    text: str = ""
    url: str = ""


def _lower_headers(msg):
    out = {}
    if msg is None:
        return out
    try:
        items = msg.items()
    except Exception:
        return out
    for k, v in items:
        out[str(k).lower()] = str(v)
    return out


def _read_body(raw):
    try:
        data = raw.read()
    except Exception:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


class Client:
    """Small wrapper around urllib.request with scanner-friendly defaults."""

    def __init__(self, timeout=TIMEOUT, user_agent=USER_AGENT):
        self.timeout = timeout
        self.user_agent = user_agent

    def request(self, method, url, headers=None, data=None):
        hdrs = {"User-Agent": self.user_agent}
        if headers:
            hdrs.update(headers)
        body = None
        if data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode("utf-8")
            elif isinstance(data, str):
                body = data.encode("utf-8")
            else:
                body = data
        req = urllib.request.Request(url, data=body, headers=hdrs,
                                     method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=_CTX) as resp:
                return Resp(status=resp.getcode(),
                            headers=_lower_headers(resp.headers),
                            text=_read_body(resp),
                            url=resp.geturl() or url)
        except urllib.error.HTTPError as e:
            # HTTP error status: still a valid scan response.
            try:
                text = _read_body(e)
            except Exception:
                text = ""
            return Resp(status=e.code or 0,
                        headers=_lower_headers(e.headers),
                        text=text,
                        url=url)
        except Exception:
            # Network/DNS/TLS/timeout failure: report as status 0.
            return Resp(status=0, headers={}, text="", url=url)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def options(self, url, **kw):
        return self.request("OPTIONS", url, **kw)
