"""Policy-gated tool routing for the sandboxed security assistant."""

from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for path in (ROOT, ROOT / "policy"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from audit.audit_log import AuditLogger
from policy_engine import PolicyEngine, ToolRequest, Verdict
from tool_router.adapters import nmap_adapter
from tool_router.attestation import DockerSandboxAttestor, SandboxAttestationError
from tool_router.sanitizer import sanitize_tool_output

ADAPTERS = {"nmap": nmap_adapter.execute, "nmap_aggressive": nmap_adapter.execute}
AUDIT = AuditLogger()


@dataclass(frozen=True)
class PendingRequest:
    request_id: str
    request: ToolRequest
    created_at: str


class ApprovalQueue:
    """In-memory queue for requests awaiting human approval."""

    def __init__(self) -> None:
        self._pending: dict[str, PendingRequest] = {}

    def enqueue(self, request_id: str, request: ToolRequest, created_at: str) -> None:
        if request_id in self._pending:
            raise ValueError("request_id is already pending")
        self._pending[request_id] = PendingRequest(request_id, request, created_at)

    def pending(self) -> dict[str, PendingRequest]:
        return dict(self._pending)

    def get(self, request_id: str) -> PendingRequest | None:
        return self._pending.get(request_id)

    def remove(self, request_id: str) -> PendingRequest | None:
        return self._pending.pop(request_id, None)


def _audit(event: str, request_id: str, request: ToolRequest, decision: str,
           result: str, policy_version: int | None, **extra: object) -> None:
    AUDIT.append({
        "event": event, "request_id": request_id, "user": request.user,
        "role": request.role, "tool": request.tool, "decision": decision,
        "result": result, "policy_version": policy_version, **extra,
    })


def _execute(request: ToolRequest) -> str:
    """Execute an authorized request only after runtime sandbox attestation."""
    try:
        DockerSandboxAttestor().attest()
    except SandboxAttestationError as exc:
        return f"ERROR: sandbox attestation failed: {exc}"

    adapter = ADAPTERS.get(request.tool)
    if adapter is None:
        return f"ERROR: no adapter registered for '{request.tool}'"
    try:
        return sanitize_tool_output(adapter(request))
    except Exception as exc:  # adapters are an isolation boundary
        return f"ERROR: adapter execution failed: {exc}"


def handle_request(request: ToolRequest, engine: PolicyEngine, queue: ApprovalQueue,
                   request_id: str | None = None) -> dict:
    """Evaluate a request and either deny it, queue it, or execute it."""
    request_id = request_id or str(uuid.uuid4())
    if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 128:
        raise ValueError("request_id must be a non-empty string of at most 128 characters")

    decision = engine.evaluate(request)
    result = {**decision.to_log_row(), "request_id": request_id, "output": None}
    _audit("policy_decision", request_id, request, decision.verdict.value,
           decision.reason, decision.policy_version)

    if decision.verdict == Verdict.DENY:
        return result
    if decision.verdict == Verdict.ALLOW_PENDING_APPROVAL:
        try:
            queue.enqueue(request_id, request, decision.timestamp)
        except ValueError as exc:
            return {**result, "decision": "error", "reason": str(exc)}
        return {**result, "approval_required": True}

    output = _execute(request)
    _audit("tool_execution", request_id, request, "executed", output,
           decision.policy_version)
    return {**result, "output": output}


def _can_approve_high_risk(approver_role: str, engine: PolicyEngine) -> bool:
    for approver in engine.policy["approval"].get("approvers", []):
        if approver.get("role") == approver_role:
            return approver.get("can_approve_up_to") == "high"
    return False


def _is_expired(pending: PendingRequest, engine: PolicyEngine) -> bool:
    try:
        created_at = datetime.fromisoformat(pending.created_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    timeout = engine.policy["approval"].get("approval_timeout_seconds", 0)
    return datetime.now(timezone.utc) > created_at + timedelta(seconds=timeout)


def approve_request(request_id: str, approver_user: str, approver_role: str,
                    engine: PolicyEngine, queue: ApprovalQueue) -> dict:
    pending = queue.get(request_id)
    if pending is None:
        return {"request_id": request_id, "decision": "error", "reason": "No pending request with that ID"}
    if not _can_approve_high_risk(approver_role, engine):
        return {"request_id": request_id, "decision": "denied", "reason": f"Role '{approver_role}' is not authorized to approve high-risk requests"}

    request = pending.request
    if _is_expired(pending, engine):
        queue.remove(request_id)
        reason = "Approval request expired before it was approved"
        _audit("approval_expired", request_id, request, "expired", reason, engine.policy.get("policy_version"))
        return {"request_id": request_id, "decision": "expired", "reason": reason}

    # Re-check the original request immediately before executing it.
    decision = engine.evaluate(request)
    if decision.verdict != Verdict.ALLOW_PENDING_APPROVAL:
        queue.remove(request_id)
        reason = "Policy changed or request is no longer eligible for approval"
        _audit("approval_invalidated", request_id, request, "approval_invalidated", reason, decision.policy_version)
        return {**decision.to_log_row(), "request_id": request_id, "decision": "approval_invalidated", "reason": reason, "output": None}

    queue.remove(request_id)
    output = _execute(request)
    _audit("approval_execution", request_id, request, "approved_and_executed", output,
           decision.policy_version, approver=approver_user, approval_role=approver_role)
    return {**decision.to_log_row(), "request_id": request_id, "decision": "approved_and_executed",
            "approver": approver_user, "approval_role": approver_role, "output": output}


def deny_request(request_id: str, approver_user: str, approver_role: str,
                 engine: PolicyEngine, queue: ApprovalQueue) -> dict:
    pending = queue.get(request_id)
    if pending is None:
        return {"request_id": request_id, "decision": "error", "reason": "No pending request with that ID"}
    if not _can_approve_high_risk(approver_role, engine):
        return {"request_id": request_id, "decision": "denied", "reason": f"Role '{approver_role}' is not authorized to deny high-risk requests"}

    queue.remove(request_id)
    reason = "Request denied by authorized approver"
    _audit("approval_denial", request_id, pending.request, "denied", reason,
           engine.policy.get("policy_version"), approver=approver_user, approval_role=approver_role)
    return {"request_id": request_id, "decision": "denied", "approver": approver_user,
            "approval_role": approver_role, "reason": reason}


if __name__ == "__main__":
    engine = PolicyEngine(
        ROOT / "policy" / "policy.yaml",
        ROOT / "policy" / "policy.schema.json",
    )
    response = handle_request(
        ToolRequest(
            user="local_smoke_test",
            role="analyst",
            tool="nmap",
            flags=["-sV"],
            target_host="10.50.0.12",
            target_port=8080,
        ),
        engine,
        ApprovalQueue(),
    )
    print(response)
