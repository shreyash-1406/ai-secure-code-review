"""
Review engine: combines the static scanner with an LLM.

1. secscan finds candidate issues with its rules (fast, deterministic).
2. The LLM looks at each finding *with the surrounding code* and decides
   whether it is a real vulnerability or a false positive, explains the
   risk in plain English, and proposes fixed code.
3. The LLM also reviews the whole file for logic flaws that regex rules
   cannot see (missing auth checks, IDOR, race conditions...).

The AI is an assistant, not the judge: every result keeps the original rule
finding so a reviewer can see exactly why something was flagged.
"""

from dataclasses import dataclass, field, asdict

from secscan.scanner import scan_source, security_score, grade

from .llm import LLMClient, LLMUnavailable, extract_json

CONTEXT_LINES = 6
MAX_FINDINGS_FOR_AI = 15     # keep prompts small for local models

SYSTEM_PROMPT = (
    "You are a senior application security engineer doing a code review. "
    "Be precise and practical. Never invent code that is not shown. "
    "Answer ONLY with valid JSON, no extra text."
)

FINDING_PROMPT = """A static analysis rule flagged this code.

Rule: {rule_id} - {title} ({cwe}, severity {severity})
File: {filename}, line {line}

Code (line {line} marked with >>):
```{language}
{snippet}
```

Return JSON with exactly these keys:
{{
  "verdict": "true_positive" or "false_positive",
  "confidence": "high" | "medium" | "low",
  "explanation": "2-3 sentences: what the risk is and how an attacker would exploit it",
  "fixed_code": "corrected version of the flagged lines only",
  "references": ["OWASP or CWE link"]
}}"""

LOGIC_PROMPT = """Review this {language} file for security problems that pattern
matching would miss: broken access control / IDOR, missing authentication,
business logic flaws, race conditions, insecure defaults, sensitive data in logs.

Ignore these issues, they are already reported: {known}

```{language}
{code}
```

Return a JSON list (empty list if nothing found). Each item:
{{"title": "...", "severity": "HIGH|MEDIUM|LOW", "line": <number or null>,
  "explanation": "...", "recommendation": "..."}}"""

LANGUAGES = {".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
             ".tsx": "typescript", ".php": "php", ".java": "java", ".go": "go", ".rb": "ruby"}


@dataclass
class ReviewedFinding:
    rule_id: str
    title: str
    severity: str
    line: int
    code: str
    cwe: str
    recommendation: str
    source: str = "rule"                  # "rule" or "ai"
    verdict: str = "unreviewed"           # true_positive / false_positive / unreviewed
    confidence: str = ""
    explanation: str = ""
    fixed_code: str = ""
    references: list = field(default_factory=list)


@dataclass
class ReviewResult:
    filename: str
    language: str
    ai_used: bool
    model: str
    score: int
    grade: str
    findings: list
    notes: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["counts"] = self.counts()
        return d

    def counts(self):
        out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.verdict != "false_positive":
                out[f.severity] = out.get(f.severity, 0) + 1
        return out


def snippet_around(code: str, line: int) -> str:
    lines = code.splitlines()
    start = max(0, line - 1 - CONTEXT_LINES)
    end = min(len(lines), line + CONTEXT_LINES)
    out = []
    for i in range(start, end):
        marker = ">>" if i == line - 1 else "  "
        out.append(f"{marker} {i + 1:>4} | {lines[i]}")
    return "\n".join(out)


def detect_language(filename: str) -> str:
    for ext, lang in LANGUAGES.items():
        if filename.lower().endswith(ext):
            return lang
    return "text"


class Reviewer:
    def __init__(self, llm: LLMClient = None, use_ai: bool = True):
        self.llm = llm or LLMClient()
        self.use_ai = use_ai

    def review(self, code: str, filename: str = "snippet.py") -> ReviewResult:
        language = detect_language(filename)
        raw = [f for f in scan_source(code, filename, include_quality=False)]

        findings = [ReviewedFinding(
            rule_id=f.rule_id, title=f.title, severity=f.severity, line=f.line,
            code=f.code, cwe=f.cwe, recommendation=f.recommendation) for f in raw]

        notes = []
        ai_used = False

        if self.use_ai:
            try:
                for item in findings[:MAX_FINDINGS_FOR_AI]:
                    self._ai_review_finding(item, code, filename, language)
                findings.extend(self._ai_logic_review(code, language, findings))
                ai_used = True
                if len(findings) > MAX_FINDINGS_FOR_AI:
                    notes.append(f"AI reviewed the first {MAX_FINDINGS_FOR_AI} rule findings only.")
            except LLMUnavailable as exc:
                notes.append(f"AI model unavailable ({exc.__class__.__name__}); showing rule-based results only.")

        # Score only what was not dismissed as a false positive
        confirmed = [f for f in raw if not any(
            r.rule_id == f.rule_id and r.line == f.line and r.verdict == "false_positive"
            for r in findings)]
        score = security_score(confirmed)
        for f in findings:
            if f.source == "ai":
                score -= {"HIGH": 10, "MEDIUM": 4, "LOW": 1}.get(f.severity, 0)
        score = max(score, 0)

        findings.sort(key=lambda f: (f.verdict == "false_positive",
                                     -["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(f.severity),
                                     f.line or 0))
        return ReviewResult(filename=filename, language=language, ai_used=ai_used,
                            model=self.llm.model if ai_used else "", score=score,
                            grade=grade(score), findings=findings, notes=notes)

    def _ai_review_finding(self, item: ReviewedFinding, code, filename, language):
        prompt = FINDING_PROMPT.format(
            rule_id=item.rule_id, title=item.title, cwe=item.cwe, severity=item.severity,
            filename=filename, line=item.line, language=language,
            snippet=snippet_around(code, item.line))
        reply = self.llm.chat(SYSTEM_PROMPT, prompt)
        try:
            data = extract_json(reply)
        except ValueError:
            item.explanation = reply.strip()[:800]
            return
        item.verdict = data.get("verdict", "unreviewed")
        item.confidence = data.get("confidence", "")
        item.explanation = data.get("explanation", "")
        item.fixed_code = data.get("fixed_code", "")
        item.references = data.get("references", []) or []

    def _ai_logic_review(self, code, language, existing):
        known = ", ".join(sorted({f"{f.title} (line {f.line})" for f in existing})) or "none"
        reply = self.llm.chat(SYSTEM_PROMPT, LOGIC_PROMPT.format(
            language=language, known=known, code=code[:12000]))
        try:
            items = extract_json(reply)
        except ValueError:
            return []
        if isinstance(items, dict):
            items = items.get("issues", [])
        out = []
        for i in items:
            sev = str(i.get("severity", "LOW")).upper()
            out.append(ReviewedFinding(
                rule_id="AI", title=i.get("title", "AI finding"),
                severity=sev if sev in ("HIGH", "MEDIUM", "LOW") else "LOW",
                line=i.get("line") or 0, code="", cwe="",
                recommendation=i.get("recommendation", ""), source="ai",
                verdict="true_positive", explanation=i.get("explanation", "")))
        return out
