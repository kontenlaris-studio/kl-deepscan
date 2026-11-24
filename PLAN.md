# KL-DeepScan — build plan (Tugas Besar, user picked parallel mode 24 Nov 2026)

## Pre-mortem
- Assumption most expensive if wrong: parallel agents diverge on the check/engine contract → integration fails. Cheapest check: one written contract below, every agent follows it verbatim; I integrate + selftest.
- Opponent lenses: grader — claims must be measured (real check count, real selftest), no inflated "60+" if not true. Buyer — must run with `python3 deepscan.py <url>` stdlib-only, Termux OK. Safety reviewer — detection-only marker probes, no destructive payloads, --yes gate for non-local targets.
- Stop criteria: selftest passes against local fixture server + repo pushed & verified + trending cron live. No paid APIs, no external keys.

## Contract (ALL agents follow verbatim)
- Layout: repo root ~/workspace/kl-deepscan/; entry `deepscan.py`; package `kl_deepscan/`.
- `kl_deepscan/models.py`: `@dataclass Finding(id, title, severity, url, evidence, description, remediation, cwe="")`, severity in {critical, high, medium, low, info}.
- HTTP: `kl_deepscan/http_client.py` class `Client`: `request(method, url, headers=None, data=None) -> Resp(status:int, headers:dict[str,str] lower-cased keys, text:str, url:str)`; `get(url, **kw)` shortcut. urllib-based, timeout 10s, ignores cert errors for scanning, UA `KL-DeepScan/1.0`.
- Check ctx: object with `.client`, `.target` (base URL string, no trailing slash), `.marker` (unique random token string per run).
- Check function: `def check(ctx) -> list[Finding]` (sync; engine runs checks in a ThreadPoolExecutor).
- `kl_deepscan/checks/__init__.py` exports `CHECKS`: list of `(check_id:str, title:str, fn)`.
- Engine `kl_deepscan/engine.py`: `run_scan(target, threads=10) -> list[Finding]` — imports CHECKS, runs all, dedupes by (id, url).
- Safety gate in CLI: target host not in {localhost, 127.0.0.1, ::1} requires `--yes` flag (user confirms own/authorized target), else exit 2 with explanation.
- Reports `kl_deepscan/report.py`: `generate(findings, target, fmt, out_path)` for fmt in {json, html, sarif}; HTML self-contained, brand navy #0A1931 / orange #FF7A00.
- AI triage `kl_deepscan/ai_triage.py`: `triage(findings) -> str` — uses local Ollama at 127.0.0.1:11434 if reachable (model from env KLDS_MODEL or qwen2.5:1.5b), else returns "" gracefully. Never required.
- Python stdlib ONLY. No pip deps. Python 3.8+ compatible syntax (no match statements).

## Checklist
- [x] Core engine + CLI + safety gate (agent A)
- [x] Checks library, honest count (agent B)
- [x] Reports + AI triage + fixture selftest + README/docs (agent C)
- [x] Integration: run selftest, fix, verify check count
- [x] GitHub repo kontenlaris-studio/kl-deepscan created, pushed, verified (README renders, release v1.0)
- [x] Daily GitHub Trending Top 10 cron → this chat (~08:30 WIB)
- [x] Report to user (1 bubble) + MEMORY line
