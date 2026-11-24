# KL-DeepScan

**A modern, detection-only web vulnerability scanner — Python standard library only.**
Built by [Kontenlaris Studio](https://github.com/kontenlaris-studio). No pip installs, no build step: clone it and run it, on a server, a laptop, or a phone with Termux.

KL-DeepScan checks a web target for common, high-impact misconfigurations and weaknesses using **harmless marker probes only** — it detects and reports, it never exploits, brute-forces, or modifies anything on the target.

## Features

- **70 detection checks** covering, among others:
  - Missing or weak security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, …)
  - CORS misconfiguration (reflected origins, credentials with wildcard/reflected origin)
  - Exposed sensitive paths (`.git`, `.env`, backup/config leftovers)
  - Cookie flags (HttpOnly, Secure, SameSite)
  - Server / technology version disclosure
  - Reflected marker probes (XSS indication without a harmful payload)
  - Dangerous HTTP methods (TRACE, etc.)
  - TLS / redirect hygiene for HTTPS targets
- **Concurrent engine** — checks run in a thread pool; a failing check never kills the scan.
- **Three report formats**
  - `json` — structured report with per-severity summary counts
  - `html` — single self-contained report file (inline CSS, no external assets)
  - `sarif` — SARIF 2.1.0 for GitHub code-scanning and other dashboards
- **Optional AI triage** — a short plain-language summary of top risks and fix order, from an online AI provider (see below). Fully optional; the scanner works without it.
- **Safety gate built in** — non-localhost targets require an explicit `--yes` confirmation that the target is yours or authorized.
- **Zero dependencies** — Python 3.8+ standard library only, so it runs anywhere Python does, including Termux on Android.

## Usage

```bash
# Local targets need no confirmation flag
python3 deepscan.py http://127.0.0.1:8080

# Your own / authorized remote target (the --yes flag is your confirmation)
python3 deepscan.py https://example.com --yes

# Write a report (json | html | sarif)
python3 deepscan.py https://example.com --yes --format html --out reports/example.html

# Add an AI triage summary (if a provider is configured, see below)
python3 deepscan.py https://example.com --yes --triage
```

Findings are printed to the terminal grouped by severity (critical → info), followed by a summary line.

## AI Triage

With `--triage`, KL-DeepScan asks an AI provider to summarize the top risks and the recommended fix order. Set `KLDS_AI_PROVIDER` to pick one explicitly; if you don't, it auto-picks the first provider whose API key is present (priority: Groq → Gemini → OpenRouter → OpenAI → Anthropic) and falls back once to the next keyed provider if a call fails.

| Provider | `KLDS_AI_PROVIDER` | API key env var | Default model |
|---|---|---|---|
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | `claude-haiku-4-5` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` | `gemini-2.0-flash` |
| Groq | `groq` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `openai/gpt-4o-mini` |

Set `KLDS_MODEL` to override the model for any provider. Example:

```bash
export KLDS_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...        # your own key
python3 deepscan.py https://example.com --yes --triage
```

**Keys are user-supplied and never bundled.** They are read from environment variables only, never stored in the repo, never printed, and never sent anywhere except the provider being called. Note that triage sends a compact list of your findings (severity, title, URL) to the selected online provider — don't use `--triage` if that is not acceptable for a target. If no key is set or the providers are unreachable, triage is skipped silently and the scan result is unaffected.

## Safety & legal

- **Authorized targets only.** Scan only systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.
- The CLI enforces this with the `--yes` gate for any non-localhost target.
- KL-DeepScan is **detection-only**: probes use unique random markers and read-only requests. It ships no destructive payloads, no credential attacks, and no persistence or evasion features.
- Findings are indicators, not proof — verify before acting, and disclose responsibly to the site owner.

## Selftest

A deliberately misconfigured local fixture server plus an end-to-end test are included:

```bash
python3 tests/run_selftest.py
```

It starts the fixture on `127.0.0.1:8791`, scans it, asserts the expected finding families (headers, CORS, `.git` exposure, reflection) appear, and verifies all three report formats.

## Termux (Android)

```bash
pkg install python git
git clone https://github.com/kontenlaris-studio/kl-deepscan
cd kl-deepscan
python3 deepscan.py http://127.0.0.1:8080
```

No compilation and no pip packages are required, so Termux works out of the box.

## License

MIT — see [LICENSE](LICENSE). Security policy: see [SECURITY.md](SECURITY.md).

---

## Bahasa Indonesia (ringkas)

**KL-DeepScan** adalah scanner kerentanan web modern yang sifatnya **deteksi saja** — hanya memakai probe penanda yang tidak berbahaya, tanpa eksploitasi. Murni Python standard library (tanpa `pip install`), jadi bisa jalan di server, laptop, dan Termux.

- Menjalankan 70 pemeriksaan: header keamanan, CORS, cookie, path sensitif (`.git`, `.env`), kebocoran versi server, refleksi marker, metode HTTP berbahaya, dan lainnya.
- Laporan dalam 3 format: JSON, HTML (satu file mandiri), dan SARIF 2.1.0.
- Triage AI opsional (OpenAI/Anthropic/Gemini/Groq/OpenRouter dengan API key milikmu sendiri — tidak pernah disertakan dalam repo; tanpa key pun scanner tetap jalan penuh).
- **Keamanan & legal:** target selain localhost wajib memakai flag `--yes` sebagai konfirmasi bahwa target itu milikmu atau kamu berizin mengujinya. Scan sistem orang lain tanpa izin bisa melanggar hukum. Selalu verifikasi temuan dan laporkan secara bertanggung jawab.
- Tes mandiri: `python3 tests/run_selftest.py`

Lisensi MIT © 2026 Kontenlaris Studio.
