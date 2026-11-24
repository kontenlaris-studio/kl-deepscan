"""AI triage for KL-DeepScan findings — online providers only, always optional.

triage(findings) -> str asks an AI provider for a short summary of the top
risks and the order in which to fix them.

Providers (stdlib urllib, keys from environment only):
  openai     OPENAI_API_KEY      default model gpt-4o-mini
  anthropic  ANTHROPIC_API_KEY   default model claude-haiku-4-5
  gemini     GEMINI_API_KEY      default model gemini-2.0-flash
  groq       GROQ_API_KEY        default model llama-3.3-70b-versatile
  openrouter OPENROUTER_API_KEY  default model openai/gpt-4o-mini

Selection: KLDS_AI_PROVIDER if set; otherwise the first provider whose key
exists, in priority order groq -> gemini -> openrouter -> openai -> anthropic.
KLDS_MODEL overrides the model for any provider. If the chosen provider call
fails, triage falls back once to the next provider that has a key.

Keys are never bundled, never stored, never printed. ANY failure (no key
anywhere, network error, bad response, unknown provider) returns "" so the
scanner works fully without AI.
"""
import json
import os
import urllib.request

TIMEOUT = 30
MAX_TOKENS = 400
MAX_FINDINGS_IN_PROMPT = 25

_DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-haiku-4-5",
    "gemini": "gemini-2.0-flash",
    "groq": "llama-3.3-70b-versatile",
    "openrouter": "openai/gpt-4o-mini",
}

_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}

# Auto-pick priority when KLDS_AI_PROVIDER is not set.
_PRIORITY = ("groq", "gemini", "openrouter", "openai", "anthropic")

_CHAT_URL = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
}


def _model(provider):
    return os.environ.get("KLDS_MODEL") or _DEFAULT_MODELS[provider]


def _build_prompt(findings):
    lines = []
    for f in list(findings)[:MAX_FINDINGS_IN_PROMPT]:
        lines.append("- [%s] %s (%s) at %s" % (f.severity.upper(), f.title, f.id, f.url))
    if not lines:
        lines.append("- (no findings)")
    return (
        "You are a security triage assistant. Below are web vulnerability scan "
        "findings from KL-DeepScan.\n\n%s\n\n"
        "Reply briefly: (1) the top risks in plain language, (2) the order in "
        "which to fix them and why. Keep it under 200 words, no markdown tables."
        % "\n".join(lines)
    )


def _post_json(url, payload, headers=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _chat_completions(provider, prompt):
    doc = _post_json(
        _CHAT_URL[provider],
        {"model": _model(provider), "max_tokens": MAX_TOKENS,
         "messages": [{"role": "user", "content": prompt}]},
        headers={"Authorization": "Bearer " + os.environ[_KEY_ENV[provider]]},
    )
    return doc["choices"][0]["message"]["content"].strip()


def _anthropic(prompt):
    doc = _post_json(
        "https://api.anthropic.com/v1/messages",
        {"model": _model("anthropic"), "max_tokens": MAX_TOKENS,
         "messages": [{"role": "user", "content": prompt}]},
        headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                 "anthropic-version": "2023-06-01"},
    )
    parts = [b.get("text", "") for b in doc.get("content", []) if b.get("type") == "text"]
    return "".join(parts).strip()


def _gemini(prompt):
    url = ("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent"
           % _model("gemini"))
    doc = _post_json(
        url,
        {"contents": [{"parts": [{"text": prompt}]}],
         "generationConfig": {"maxOutputTokens": MAX_TOKENS}},
        headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"]},
    )
    parts = doc["candidates"][0]["content"]["parts"]
    return "".join(p.get("text", "") for p in parts).strip()


_CALLS = {
    "openai": lambda p: _chat_completions("openai", p),
    "anthropic": _anthropic,
    "gemini": _gemini,
    "groq": lambda p: _chat_completions("groq", p),
    "openrouter": lambda p: _chat_completions("openrouter", p),
}


def _candidates():
    """Ordered provider names to try: explicit choice first, then auto-pick
    priority — only providers whose API key is present."""
    ordered = []
    chosen = (os.environ.get("KLDS_AI_PROVIDER") or "").strip().lower()
    if chosen in _CALLS:
        ordered.append(chosen)
    for name in _PRIORITY:
        if name not in ordered:
            ordered.append(name)
    return [name for name in ordered if os.environ.get(_KEY_ENV[name])]


def triage(findings):
    """Return a short AI triage summary, or "" if AI is unavailable.

    Tries the selected provider, falls back once to the next provider with
    a key on failure. Never raises and never prints credentials.
    """
    try:
        prompt = _build_prompt(findings)
    except Exception:
        return ""
    for provider in _candidates()[:2]:  # chosen provider + one fallback
        try:
            text = _CALLS[provider](prompt)
            if text:
                return text
        except Exception:
            continue
    return ""
