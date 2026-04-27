"""prompt-injection-shield -- scan untrusted text for prompt-injection risk.

Public surface (mirrors the JS sibling ``@mukundakatta/prompt-injection-shield``):

    from prompt_injection_shield import scan, strip_dangerous_lines, ScanResult, Finding

* ``scan(text, threshold=0.7)`` -> ``ScanResult`` -- regex rule pass with severity scoring.
* ``strip_dangerous_lines(text, threshold=0.7)`` -> ``str`` -- drop lines that fail ``scan``.
* ``Finding`` / ``ScanResult`` -- dataclasses with the per-rule hits and aggregate score.

The library is zero-dep (stdlib ``re`` only). It catches the common patterns
(``ignore previous instructions``, ``act as``, jailbreak markers, secret-exfil
language, tool-abuse phrasings) but is by design a heuristic; layer it with a
classifier or LLM judge for high-stakes flows.
"""

from .core import (
    DEFAULT_THRESHOLD,
    RULES,
    Finding,
    ScanResult,
    is_suspicious,
    scan,
    scan_prompt_injection,
    strip_dangerous_lines,
)

__version__ = "0.1.0"
VERSION = __version__

__all__ = [
    "DEFAULT_THRESHOLD",
    "RULES",
    "VERSION",
    "Finding",
    "ScanResult",
    "is_suspicious",
    "scan",
    "scan_prompt_injection",
    "strip_dangerous_lines",
]
