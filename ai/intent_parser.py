"""
AI Intent Parser

Converts a user's natural-language request into a structured intent.

Important:
    This module does NOT authorize or execute tools.

    Flow:

        User request
             |
             v
        IntentParser
             |
             v
        Structured intent
             |
             v
        PolicyEngine
             |
        +----+----+
        |         |
      DENY      ALLOW
                  |
                  v
              Tool Router
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedIntent:
    """
    Structured representation of a user's requested action.
    """

    action: str
    tool: str | None = None
    target: str | None = None
    ports: list[int] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_input: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "tool": self.tool,
            "target": self.target,
            "ports": self.ports,
            "flags": self.flags,
            "confidence": self.confidence,
            "raw_input": self.raw_input,
        }


class IntentParser:
    """
    Initial deterministic intent parser.

    This is deliberately NOT an LLM yet.

    The parser extracts obvious intent from controlled patterns.
    PolicyEngine remains responsible for authorization.
    """

    def parse(self, text: str) -> ParsedIntent:
        if not isinstance(text, str):
            raise TypeError("Intent input must be a string")

        text = text.strip()

        if not text:
            return ParsedIntent(
                action="unknown",
                confidence=1.0,
                raw_input=text,
            )

        normalized = text.lower()

        # ---------------------------------------------------------
        # Nmap / network scanning
        # ---------------------------------------------------------

        if "nmap" in normalized or "scan" in normalized:
            target = self._extract_target(text)
            ports = self._extract_ports(text)
            flags = self._extract_flags(normalized)

            return ParsedIntent(
                action="network_scan",
                tool="nmap",
                target=target,
                ports=ports,
                flags=flags,
                confidence=0.85,
                raw_input=text,
            )

        # ---------------------------------------------------------
        # Unknown intent
        # ---------------------------------------------------------

        return ParsedIntent(
            action="unknown",
            confidence=0.20,
            raw_input=text,
        )

    @staticmethod
    def _extract_target(text: str) -> str | None:
        """
        Extract a simple IPv4 address or hostname.

        This is intentionally conservative.
        """

        import re

        ipv4 = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            text,
        )

        if ipv4:
            return ipv4.group(0)

        hostname = re.search(
            r"\b[a-zA-Z0-9.-]+\.(?:com|net|org|local|internal)\b",
            text,
        )

        if hostname:
            return hostname.group(0)

        return None

    @staticmethod
    def _extract_ports(text: str) -> list[int]:
        """
        Extract explicit ports from phrases such as:

            port 80
            ports 80,443
            22 80 443

        Only ports explicitly identified as ports are extracted.
        """

        import re

        matches = re.findall(
            r"\bport[s]?\s+([0-9,\-\s]+)",
            text.lower(),
        )

        ports: list[int] = []

        for match in matches:
            for value in re.findall(r"\b\d{1,5}\b", match):
                port = int(value)

                if 1 <= port <= 65535:
                    ports.append(port)

        return sorted(set(ports))

    @staticmethod
    def _extract_flags(normalized: str) -> list[str]:
        """
        Extract known nmap-style flags.

        The parser only recognizes known flags.
        """

        known_flags = [
            "-sV",
            "-sC",
            "-O",
            "-A",
            "-Pn",
            "-p",
        ]

        flags: list[str] = []

        for flag in known_flags:
            if flag.lower() in normalized:
                flags.append(flag)

        return flags


def parse_intent(text: str) -> dict[str, Any]:
    """
    Convenience function for callers that want a dictionary.
    """

    parser = IntentParser()
    return parser.parse(text).to_dict()
