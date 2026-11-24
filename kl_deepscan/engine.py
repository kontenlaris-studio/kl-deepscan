"""Scan engine: runs all registered checks concurrently and normalizes results."""
import secrets
from concurrent.futures import ThreadPoolExecutor

from kl_deepscan.checks import CHECKS
from kl_deepscan.http_client import Client
from kl_deepscan.models import SEVERITY_RANK


class Ctx:
    """Context object handed to every check function."""

    def __init__(self, client, target, marker):
        self.client = client
        self.target = target  # base URL, no trailing slash
        self.marker = marker  # unique random token for this run


def normalize_target(target):
    t = (target or "").strip()
    if "://" not in t:
        t = "http://" + t
    return t.rstrip("/")


def run_scan(target, threads=10):
    """Run every check in CHECKS against target; return deduped, sorted findings."""
    base = normalize_target(target)
    ctx = Ctx(client=Client(), target=base, marker=secrets.token_hex(8))

    def _run(entry):
        _check_id, _title, fn = entry
        try:
            return fn(ctx) or []
        except Exception:
            # A broken check must never kill the whole scan.
            return []

    findings = []
    if CHECKS:
        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            for batch in pool.map(_run, CHECKS):
                findings.extend(batch)

    seen = set()
    unique = []
    for f in findings:
        key = (f.id, f.url)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 99))
    return unique
