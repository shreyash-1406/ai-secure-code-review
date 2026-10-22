# AI Secure Code Review Platform

A web platform that reviews source code for security vulnerabilities by combining a **static rule engine** with a **local large language model**.

Static scanners are fast but noisy; LLMs understand context but can hallucinate. This platform uses each for what it is good at:

1. **Rules find candidates.** The [`secscan`](https://github.com/shreyash-1406/code-security-scanner) engine flags risky patterns (SQL injection, command injection, XSS, secrets, weak crypto…) with CWE ids.
2. **The LLM checks each one in context.** It reads the surrounding code, marks likely false positives, explains how an attacker would exploit the issue, and writes a fixed version.
3. **The LLM looks for logic flaws** that regex cannot see: missing authentication, IDOR, insecure defaults, sensitive data in logs.

By default the model runs locally through **Ollama**, so client or private code never leaves the machine.

## Features

- Paste code or upload a file (Python, JavaScript/TypeScript, PHP, Java, Go, Ruby)
- Per-finding AI verdict (**true / false positive**), confidence, plain-English explanation and suggested fix
- Extra AI-only findings for business-logic and access-control issues
- Security score and grade; false positives are excluded from the score
- Review history stored in SQLite
- **JSON API** (`POST /api/review`) for scripts and CI
- Works without a model too: falls back to rules-only mode and says so
- Docker Compose setup with Ollama included

## Architecture

```
 Browser / API client
        │
        ▼
 Flask app (app/main.py) ── input validation, size limits, SQLite history
        │
        ▼
 Reviewer (app/reviewer.py)
   ├─ secscan rule engine ──► candidate findings (rule, CWE, line)
   ├─ LLM: per-finding check (code ±6 lines) ──► verdict, explanation, fix
   └─ LLM: whole-file logic review ──► extra findings
        │
        ▼
 LLM client (app/llm.py) ── any OpenAI-compatible endpoint (Ollama by default)
```

## Quick start

### Option 1: Docker Compose (includes Ollama)

```bash
git clone https://github.com/shreyash-1406/ai-secure-code-review.git
cd ai-secure-code-review
docker compose up -d
docker compose exec ollama ollama pull qwen2.5-coder:7b
```

Open http://127.0.0.1:5000

### Option 2: Run locally

```bash
# 1. Install Ollama from https://ollama.com and pull a code model
ollama pull qwen2.5-coder:7b

# 2. Install and run the app
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # adjust model or endpoint if needed
python run.py
```

No GPU? Use a smaller model (`qwen2.5-coder:1.5b`) or run with `USE_AI=0` for rules-only mode.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LLM_BASE_URL` | `http://localhost:11434/v1` | OpenAI-compatible endpoint (Ollama, LM Studio, vLLM, hosted provider) |
| `LLM_MODEL` | `qwen2.5-coder:7b` | Model name |
| `LLM_API_KEY` | `ollama` | Only needed for hosted providers |
| `USE_AI` | `1` | Set to `0` for rules-only mode |
| `REVIEW_DB` | `reviews.db` | SQLite file for history |

## API

```bash
curl -X POST http://127.0.0.1:5000/api/review \
  -H "Content-Type: application/json" \
  -d '{"filename": "app.py", "code": "import os\nos.system(input())"}'
```

Response (shortened):

```json
{
  "score": 96, "grade": "A", "ai_used": true, "model": "qwen2.5-coder:7b",
  "counts": {"HIGH": 0, "MEDIUM": 1, ...},
  "findings": [{
    "rule_id": "INJ004", "title": "os.system / os.popen call", "severity": "MEDIUM", "line": 2,
    "verdict": "true_positive", "explanation": "...", "fixed_code": "..."
  }]
}
```

`GET /api/health` reports whether the model is reachable. `examples/api_request.sh` sends a whole file.

## Security of the platform itself

- Uploads limited to 200 KB and an allowlist of extensions; filenames are stripped of paths
- Submitted code is **never executed**, only read
- All output is HTML-escaped by Jinja2 (tested against a `<script>` payload)
- Binds to `127.0.0.1` by default; the Docker image runs as a non-root user
- Not built for multi-user internet exposure yet: add authentication and CSRF protection before hosting it publicly

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

Tests use a fake LLM, so they run offline in under a second. GitHub Actions runs them on every push.

## Limitations

- AI verdicts can be wrong; every result keeps the original rule match so a human can check it
- Single-file analysis: cross-file data flow is not traced
- Local 7B models are slower than hosted ones (roughly 10–60 s per review on a laptop)

## Roadmap

- [ ] Upload a whole repository (zip) or point to a GitHub URL
- [ ] GitHub pull request bot that comments on changed lines
- [ ] User accounts and team workspaces
- [ ] Export review as PDF

## Author

**Shreyash Uparkar** · [GitHub](https://github.com/shreyash-1406)

## License

MIT
