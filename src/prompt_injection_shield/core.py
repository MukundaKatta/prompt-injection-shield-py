"""Core scanner for prompt-injection-shield.

Mirrors the JS sibling's ``RULES`` table 1:1: each rule is a ``(name, pattern,
weight)`` triple. Weights are summed (clipped at 1.0) to produce the result
``score``. ``safe`` is ``True`` iff the score is below ``threshold`` (default
0.7, same as the JS default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern

DEFAULT_THRESHOLD = 0.7


# (rule_name, compiled_pattern, weight). Patterns mirror the JS source verbatim,
# compiled once at import time.
RULES: list[tuple[str, Pattern[str], float]] = [
    (
        "ignore_instructions",
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|system|developer)\s+instructions?",
            re.IGNORECASE,
        ),
        0.95,
    ),
    (
        "role_override",
        re.compile(
            r"\b(you are now|act as|pretend to be|developer mode|jailbreak)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "secret_exfiltration",
        re.compile(
            r"\b(reveal|print|send|exfiltrate|copy).{0,32}(secret|token|api key|password|system prompt)\b",
            re.IGNORECASE,
        ),
        0.9,
    ),
    (
        "hidden_instruction",
        re.compile(
            r"\b(do not tell|hide this|invisible instruction|confidential instruction)\b",
            re.IGNORECASE,
        ),
        0.7,
    ),
    (
        "tool_abuse",
        re.compile(
            r"\b(call|invoke|use).{0,24}(shell|browser|http|email|delete|transfer)\b",
            re.IGNORECASE,
        ),
        0.55,
    ),
]


def _severity_for(weight: float) -> str:
    # Mirrors the JS ternary: >=0.85 high, >=0.7 medium, else low.
    if weight >= 0.85:
        return "high"
    if weight >= 0.7:
        return "medium"
    return "low"


@dataclass(frozen=True)
class Finding:
    """A single rule hit.

    Attributes:
        type: rule name (e.g. ``ignore_instructions``).
        severity: ``low`` / ``medium`` / ``high`` bucket from the rule weight.
        score: rule's contribution to the aggregate score (0.0-1.0).
        match: the literal substring that matched the rule's regex.
    """

    type: str
    severity: str
    score: float
    match: str


@dataclass(frozen=True)
class ScanResult:
    """Aggregate scan output.

    Attributes:
        safe: ``True`` iff ``score`` is below ``threshold``.
        score: clipped sum of all matched rule weights, in ``[0.0, 1.0]``.
        findings: per-rule hits, in the order rules are evaluated.
        threshold: the cutoff used to compute ``safe``.
    """

    safe: bool
    score: float
    findings: list[Finding] = field(default_factory=list)
    threshold: float = DEFAULT_THRESHOLD


def scan(text: object, threshold: float = DEFAULT_THRESHOLD) -> ScanResult:
    """Scan ``text`` against the bundled rule table.

    Returns a ``ScanResult``. ``text`` is coerced to ``str`` (matching the JS
    ``String(text)`` step) so callers can pass arbitrary values.
    """
    value = str(text)
    findings: list[Finding] = []
    for type_name, pattern, weight in RULES:
        m = pattern.search(value)
        if m:
            findings.append(
                Finding(
                    type=type_name,
                    severity=_severity_for(weight),
                    score=weight,
                    match=m.group(0),
                )
            )
    score = min(1.0, sum(f.score for f in findings))
    return ScanResult(
        safe=score < threshold,
        score=score,
        findings=findings,
        threshold=threshold,
    )


def is_suspicious(text: object, threshold: float = DEFAULT_THRESHOLD) -> bool:
    """Return ``True`` iff ``scan(text)`` is *not* safe. Convenience wrapper."""
    return not scan(text, threshold=threshold).safe


def strip_dangerous_lines(
    text: object,
    threshold: float = DEFAULT_THRESHOLD,
) -> str:
    """Drop lines from ``text`` that don't pass ``scan(line)``.

    Splits on ``\\r\\n`` or ``\\n`` (matching the JS ``split(/\\r?\\n/)``) and
    rejoins the survivors with ``\\n``. Useful for sanitizing multi-line tool
    output before feeding it back into a model.
    """
    value = str(text)
    safe_lines: list[str] = []
    for line in re.split(r"\r?\n", value):
        if scan(line, threshold=threshold).safe:
            safe_lines.append(line)
    return "\n".join(safe_lines)


# JS-style alias for callers porting from ``@mukundakatta/prompt-injection-shield``.
scan_prompt_injection = scan
