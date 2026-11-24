import re
from dataclasses import dataclass

from pydantic import BaseModel


class RedactionFinding(BaseModel):
    """Summary count of redacted secrets or PII tokens by category."""

    category: str
    count: int
    placeholder: str


class RedactionResult(BaseModel):
    """Result returned by PII/secret scrubbing before outbound cloud inference."""

    redacted_text: str
    findings: list[RedactionFinding]
    total_redactions: int


@dataclass(frozen=True)
class _PatternRule:
    category: str
    placeholder: str
    pattern: re.Pattern[str]


_RULES: tuple[_PatternRule, ...] = (
    _PatternRule(
        category="private_key",
        placeholder="[REDACTED_PRIVATE_KEY]",
        pattern=re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
    ),
    _PatternRule(
        category="aws_access_key",
        placeholder="[REDACTED_AWS_KEY]",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    _PatternRule(
        category="jwt",
        placeholder="[REDACTED_TOKEN]",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    _PatternRule(
        category="bearer_token",
        placeholder="[REDACTED_TOKEN]",
        pattern=re.compile(r"(?i)\bBearer\s+(?!\[REDACTED_)[A-Za-z0-9._~+/-]{16,}=*"),
    ),
    _PatternRule(
        category="saas_token",
        placeholder="[REDACTED_SECRET]",
        pattern=re.compile(r"\b(?:ghp|gho|ghs|xoxb|xoxp|sk)[_-][A-Za-z0-9_-]{12,}\b"),
    ),
    _PatternRule(
        category="api_secret",
        placeholder="[REDACTED_SECRET]",
        pattern=re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"']?"
            r"(?!\[REDACTED_)[^\s\"',;]{6,}[\"']?"
        ),
    ),
    _PatternRule(
        category="ssn",
        placeholder="[REDACTED_SSN]",
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    _PatternRule(
        category="email",
        placeholder="[REDACTED_EMAIL]",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    _PatternRule(
        category="phone",
        placeholder="[REDACTED_PHONE]",
        pattern=re.compile(r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b"),
    ),
    _PatternRule(
        category="ipv4",
        placeholder="[REDACTED_IP]",
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
    ),
)


def redact_pii(text: str) -> RedactionResult:
    """Scrub secrets, credentials, and PII from text before sending to external LLMs."""
    if not text:
        return RedactionResult(redacted_text="", findings=[], total_redactions=0)

    working = text
    counts: dict[tuple[str, str], int] = {}

    for rule in _RULES:
        working, n = rule.pattern.subn(rule.placeholder, working)
        if n > 0:
            key = (rule.category, rule.placeholder)
            counts[key] = counts.get(key, 0) + n

    findings = [
        RedactionFinding(category=cat, count=cnt, placeholder=ph)
        for (cat, ph), cnt in counts.items()
    ]
    total = sum(f.count for f in findings)
    return RedactionResult(
        redacted_text=working,
        findings=findings,
        total_redactions=total,
    )
