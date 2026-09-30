"""AI provider boundary.

Providers may interpret a chat message, but they never authorize or execute a
tool. Every proposal is still validated by ``PolicyEngine`` in the API layer.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

from ai.intent_parser import IntentParser


@dataclass(frozen=True)
class ChatReply:
    message: str
    proposal: dict[str, Any] | None = None
    provider: str = "deterministic"


class ChatProvider(Protocol):
    def reply(self, message: str) -> ChatReply: ...


class DeterministicProvider:
    """Offline fallback that supports the controlled scan grammar."""

    def __init__(self) -> None:
        self.parser = IntentParser()

    def reply(self, message: str) -> ChatReply:
        intent = self.parser.parse(message)
        if intent.action != "network_scan":
            return ChatReply(
                "I can help propose an authorized sandbox Nmap scan. "
                "For example: 'scan 10.50.0.12 port 8080'.",
            )
        if intent.target is None or not intent.ports:
            return ChatReply(
                "Please include one target and one port, for example: "
                "'scan 10.50.0.12 port 8080'.",
            )
        return ChatReply(
            "I prepared a scan proposal. The policy engine must authorize it "
            "before anything can run.",
            {
                "tool": intent.tool,
                "target_host": intent.target,
                "target_port": intent.ports[0],
                "flags": intent.flags or ["-sV"],
            },
        )


class OpenAIProvider:
    """Optional Responses-API provider for structured, non-authoritative proposals."""

    _FORMAT = {
        "type": "json_schema",
        "name": "security_assistant_reply",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["assistant_message", "action", "tool", "target_host", "target_port", "flags"],
            "properties": {
                "assistant_message": {"type": "string"},
                "action": {"type": "string", "enum": ["respond", "propose_tool"]},
                "tool": {"type": "string"},
                "target_host": {"type": "string"},
                "target_port": {"type": "integer", "minimum": 0, "maximum": 65535},
                "flags": {"type": "array", "items": {"type": "string"}},
            },
        },
    }

    def __init__(self, api_key: str, model: str | None = None) -> None:
        from openai import OpenAI

        self.client = OpenAI(api_key=api_key)
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-5-mini")

    def reply(self, message: str) -> ChatReply:
        response = self.client.responses.create(
            model=self.model,
            store=False,
            instructions=(
                "You are a cybersecurity assistant for an isolated lab. "
                "Never claim a scan ran. Only propose a tool when the user "
                "explicitly asks for a scan and provides a target and port. "
                "Use nmap for network scans. Do not propose shell commands, "
                "credentials, or non-sandbox targets. Policy enforcement is "
                "outside your control."
            ),
            input=message,
            text={"format": self._FORMAT},
        )
        data = json.loads(response.output_text)
        if data["action"] != "propose_tool":
            return ChatReply(data["assistant_message"], provider="openai")
        return ChatReply(
            data["assistant_message"],
            {
                "tool": data["tool"],
                "target_host": data["target_host"],
                "target_port": data["target_port"],
                "flags": data["flags"],
            },
            provider="openai",
        )


def build_provider() -> ChatProvider:
    """Use OpenAI only when a server-side API key is explicitly configured."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return DeterministicProvider()
    return OpenAIProvider(api_key)
