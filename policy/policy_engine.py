"""
policy_engine.py
=================
Reference implementation of the Policy Engine described in policy.yaml.

This module does NOT execute any security tools itself. Its only job is to
answer one question for the Tool Router: "Is this specific request allowed,
and if so, does it need human approval first?"

Design principles:
- Default-deny: anything not explicitly permitted is rejected.
- Fail closed: any parsing/validation error blocks the request rather than
  allowing it.
- Every decision is returned as a structured Decision object suitable for
  the immutable audit log — never just True/False.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

try:
    import jsonschema
    _HAS_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    _HAS_JSONSCHEMA = False


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    ALLOW = "allow"
    ALLOW_PENDING_APPROVAL = "allow_pending_approval"
    DENY = "deny"


@dataclass
class ToolRequest:
    """What the AI model / Tool Router wants to do."""
    user: str
    role: str
    tool: str
    flags: list[str]
    target_host: str
    target_port: int | None = None


@dataclass
class Decision:
    """What the Policy Engine decided, ready to hand to the logger."""
    timestamp: str
    user: str
    role: str
    tool: str
    verdict: Verdict
    reason: str
    risk_tier: RiskTier | None = None
    policy_version: int | None = None

    def to_log_row(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "user": self.user,
            "role": self.role,
            "request": self.tool,
            "tools_used": self.tool if self.verdict == Verdict.ALLOW else "",
            "decision": self.verdict.value,
            "result": self.reason,
            "policy_version": self.policy_version,
        }


class PolicyViolation(Exception):
    """Raised for malformed policy files — fails closed by design."""


class PolicyEngine:
    def __init__(self, policy_path: str | Path, schema_path: str | Path):
        self.policy_path = Path(policy_path)
        self.schema_path = Path(schema_path)
        self.policy: dict[str, Any] = {}
        self._load_and_validate()

    # -- loading ------------------------------------------------------------

    def _load_and_validate(self) -> None:
        try:
            with open(self.policy_path) as f:
                policy = yaml.safe_load(f)
            with open(self.schema_path) as f:
                schema = yaml.safe_load(f) if self.schema_path.suffix in (".yml", ".yaml") \
                    else __import__("json").load(f)
        except (OSError, yaml.YAMLError) as e:
            raise PolicyViolation(f"Could not load policy files: {e}") from e

        if _HAS_JSONSCHEMA:
            try:
                jsonschema.validate(instance=policy, schema=schema)
            except jsonschema.ValidationError as e:
                raise PolicyViolation(f"policy.yaml failed schema validation: {e.message}") from e
        else:  # pragma: no cover
            # jsonschema not installed — fail loud rather than silently
            # skip validation, since this is a security-critical config.
            import warnings
            warnings.warn(
                "jsonschema not installed — policy.yaml schema validation "
                "SKIPPED. Install `jsonschema` before running in any "
                "non-trivial environment: pip install jsonschema",
                RuntimeWarning,
            )

        self.policy = policy

    def reload(self) -> None:
        """Hot-reload the policy file. Call this on a file-change watcher
        so scope/tool changes take effect without restarting the service."""
        self._load_and_validate()

    # -- core evaluation ------------------------------------------------------

    def evaluate(self, request: ToolRequest) -> Decision:
        now = datetime.now(timezone.utc).isoformat()
        version = self.policy["policy_version"]

        def deny(reason: str, tier: RiskTier | None = None) -> Decision:
            return Decision(now, request.user, request.role, request.tool,
                             Verdict.DENY, reason, tier, version)

        validation_error = self._validate_request(request)
        if validation_error:
            return deny(validation_error)

        # Sandbox attestation happens in the router immediately before an
        # adapter runs. Keeping policy evaluation pure allows queued requests
        # to be safely re-evaluated before approval.

        # 1. Tool must be explicitly listed and enabled
        tool_cfg = self.policy["tools"].get(request.tool)
        if tool_cfg is None or not tool_cfg.get("enabled", False):
            return deny(f"Tool '{request.tool}' is not enabled in policy")

        risk_tier = RiskTier(tool_cfg["risk_tier"])
        if risk_tier == RiskTier.CRITICAL:
            return deny(f"Tool '{request.tool}' is tier CRITICAL — never permitted", risk_tier)

        # 3. Flags must be on the allowlist and not on the denylist
        allowed_flags = set(tool_cfg.get("allowed_flags", []))
        denied_flags = set(tool_cfg.get("denied_flags", []))
        for flag in request.flags:
            base_flag = flag.split("=")[0]
            if base_flag in denied_flags:
                return deny(f"Flag '{flag}' is explicitly denied for {request.tool}", risk_tier)
            if allowed_flags and base_flag not in allowed_flags:
                return deny(f"Flag '{flag}' is not on the allowlist for {request.tool}", risk_tier)

        # 4. Target must be in scope (host + port + not expired)
        scope_ok, scope_reason = self._check_scope(request)
        if not scope_ok:
            return deny(scope_reason, risk_tier)

        # 5. Role must be permitted to run this tier
        if not self._role_can_run(request.role, risk_tier):
            return deny(f"Role '{request.role}' is not permitted to run {risk_tier.value}-tier tools", risk_tier)

        # 6. Route to auto-allow vs approval queue based on tier
        approval_cfg = self.policy["approval"]
        if risk_tier.value in approval_cfg.get("auto_allow_tiers", []):
            return Decision(now, request.user, request.role, request.tool,
                             Verdict.ALLOW, "Auto-allowed (low risk, in scope)", risk_tier, version)

        if risk_tier.value in approval_cfg.get("require_human_approval_tiers", []):
            return Decision(now, request.user, request.role, request.tool,
                             Verdict.ALLOW_PENDING_APPROVAL,
                             "Requires human approval before execution", risk_tier, version)

        # medium tier: allowed, but flagged for prominent logging by the caller
        return Decision(now, request.user, request.role, request.tool,
                         Verdict.ALLOW, "Auto-allowed (medium risk — logged prominently)",
                         risk_tier, version)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _validate_request(request: ToolRequest) -> str | None:
        if not isinstance(request.user, str) or not request.user.strip():
            return "Request user must be a non-empty string"
        if not isinstance(request.role, str) or not request.role.strip():
            return "Request role must be a non-empty string"
        if not isinstance(request.tool, str) or not request.tool.strip():
            return "Request tool must be a non-empty string"
        if not isinstance(request.target_host, str) or not request.target_host.strip():
            return "Request target_host must be a non-empty string"
        if not isinstance(request.flags, list) or not all(isinstance(flag, str) for flag in request.flags):
            return "Request flags must be a list of strings"
        if not isinstance(request.target_port, int) or isinstance(request.target_port, bool):
            return "Request target_port must be an integer"
        if not 1 <= request.target_port <= 65535:
            return "Request target_port must be between 1 and 65535"
        return None

    def _role_can_run(self, role: str, tier: RiskTier) -> bool:
        tier_order = [RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL]
        for approver in self.policy["approval"].get("approvers", []):
            if approver["role"] == role:
                max_tier = RiskTier(approver["can_approve_up_to"])
                return tier_order.index(tier) <= tier_order.index(max_tier)
        return False

    def _check_scope(self, request: ToolRequest) -> tuple[bool, str]:
        targets = self.policy["scope"].get("targets", [])
        now = datetime.now(timezone.utc)

        for target in targets:
            expires = datetime.fromisoformat(target["expires_at"].replace("Z", "+00:00"))
            if now > expires:
                continue  # expired scope entry, skip

            host_match = False
            for cidr in target.get("hosts", []):
                try:
                    if ipaddress.ip_address(request.target_host) in ipaddress.ip_network(cidr):
                        host_match = True
                        break
                except ValueError:
                    continue
            if not host_match and request.target_host in target.get("hostnames", []):
                host_match = True

            if host_match:
                if request.target_port and request.target_port not in target.get("allowed_ports", []):
                    return False, f"Port {request.target_port} not in scope for target '{target['id']}'"
                return True, "In scope"

        return False, f"Target '{request.target_host}' is not covered by any active scope entry"

    # -- memory scrubbing -----------------------------------------------------

    def scrub_for_memory(self, text: str) -> str:
        """Redact anything matching never_store_patterns before it is
        written to the memory database. Call this on every field before
        persisting, not just once on the whole payload."""
        patterns = self.policy["memory"].get("never_store_patterns", [])
        for pattern in patterns:
            text = re.sub(pattern + r"\S*", "[REDACTED]", text)
        return text


# ---------------------------------------------------------------------------
# Example usage (Tool Router would call this, not run this file directly)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    engine = PolicyEngine("policy.yaml", "policy.schema.json")

    req = ToolRequest(
        user="analyst_jane",
        role="analyst",
        tool="nmap",
        flags=["-sV", "-p"],
        target_host="10.50.0.12",
        target_port=443,
    )

    decision = engine.evaluate(req)
    print(decision.to_log_row())
