from pathlib import Path

from policy_engine import PolicyEngine, ToolRequest, Verdict
from router import ApprovalQueue, approve_request, handle_request


ROOT = Path(__file__).resolve().parent.parent


def make_engine():
    return PolicyEngine(
        ROOT / "policy" / "policy.yaml",
        ROOT / "policy" / "policy.schema.json",
    )


def make_request():
    return ToolRequest(
        user="analyst_jane",
        role="lead_analyst",
        tool="nmap_aggressive",
        flags=["-A"],
        target_host="10.50.0.12",
        target_port=8080,
    )


def test_high_risk_request_requires_approval():
    engine = make_engine()
    queue = ApprovalQueue()

    result = handle_request(
        request=make_request(),
        engine=engine,
        queue=queue,
        request_id="approval-integrity-001",
    )

    assert result["decision"] == "allow_pending_approval"
    assert result["approval_required"] is True
    assert "approval-integrity-001" in queue.pending()


def test_approval_rechecks_policy_before_execution(monkeypatch):
    engine = make_engine()
    queue = ApprovalQueue()

    request = make_request()

    result = handle_request(
        request=request,
        engine=engine,
        queue=queue,
        request_id="approval-integrity-002",
    )

    assert result["decision"] == "allow_pending_approval"

    # Simulate the policy changing between queueing and approval.
    original_evaluate = engine.evaluate

    def deny_now(req):
        decision = original_evaluate(req)

        # Return an object with the same shape but DENY.
        decision.verdict = Verdict.DENY
        decision.reason = "Policy changed after request was queued"

        return decision

    monkeypatch.setattr(engine, "evaluate", deny_now)

    approval = approve_request(
        request_id="approval-integrity-002",
        approver_user="lead_analyst",
        approver_role="lead_analyst",
        engine=engine,
        queue=queue,
    )

    assert approval["decision"] == "approval_invalidated"
    assert "Policy changed" in approval["reason"]

    # The request must not remain executable.
    assert "approval-integrity-002" not in queue.pending()
    assert approval.get("output") is None
