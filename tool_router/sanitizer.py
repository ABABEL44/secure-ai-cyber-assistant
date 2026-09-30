"""
sanitizer.py
============
Tool output (Nmap banners, scan results, file contents, etc.) is treated as
UNTRUSTED before it's allowed back into the AI model's context — the same
discipline applied to user input, applied here to tool output. A malicious
or misconfigured target could otherwise return text crafted to look like
an instruction to the model (a prompt-injection vector).
"""
import re

# Patterns that look like an attempt to redirect the model's behavior via
# tool output rather than legitimate scan data.
_INJECTION_MARKERS = [
    r"(?i)ignore (all|previous|prior) instructions",
    r"(?i)system\s*:\s*",
    r"(?i)you are now",
    r"(?i)</?(system|assistant|user)>",
]

_MAX_OUTPUT_CHARS = 8000  # cap what re-enters model context


def sanitize_tool_output(raw: str) -> str:
    text = raw[:_MAX_OUTPUT_CHARS]

    for pattern in _INJECTION_MARKERS:
        text = re.sub(pattern, "[FILTERED]", text)

    return text
