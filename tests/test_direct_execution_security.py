from pathlib import Path

import pytest

from policy_engine import PolicyEngine, ToolRequest, Verdict
from router import handle_request, ApprovalQueue


ROOT = Path(__file__).resolve().parent.parent


def make_engine():
    return PolicyEngine(
        ROOT / "policy" / "policy.yaml",
        ROOT / "policy" / "policy.schema.json",
    )


def make_out_of_scope_request():
    return ToolRequest(
        user="test_user",
        role="analyst",
        tool="nmap",
        flags=["-sV"],
        target_host="8.8.8.8",
        target_port=443,
    )


def test_out_of_scope_request_never_reaches_adapter(monkeypatch):
    import router

    called = False

    def fake_execute(request):
        nonlocal called
        called = True
        return "EXECUTED"

    monkeypatch.setitem(router.ADAPTERS, "nmap", fake_execute)

    result = handle_request(
        request=make_out_of_scope_request(),
        engine=make_engine(),
        queue=ApprovalQueue(),
    )

    assert result["decision"] == "deny"
    assert result["output"] is None
    assert called is False


def test_denied_flag_never_reaches_adapter(monkeypatch):
    import router

    called = False

    def fake_execute(request):
        nonlocal called
        called = True
        return "EXECUTED"

    monkeypatch.setitem(router.ADAPTERS, "nmap", fake_execute)

    request = make_out_of_scope_request()

    request.target_host = "10.50.0.12"
    request.target_port = 8080
    request.flags = ["--script=vuln"]

    result = handle_request(
        request=request,
        engine=make_engine(),
        queue=ApprovalQueue(),
    )

    assert result["decision"] == "deny"
    assert called is False


def test_high_risk_request_never_executes_without_approval(monkeypatch):
    import router

    called = False

    def fake_execute(request):
        nonlocal called
        called = True
        return "EXECUTED"

    monkeypatch.setitem(router.ADAPTERS, "nmap_aggressive", fake_execute)

    request = ToolRequest(
        user="test_user",
        role="lead_analyst",
        tool="nmap_aggressive",
        flags=["-A"],
        target_host="10.50.0.12",
        target_port=8080,
    )

    result = handle_request(
        request=request,
        engine=make_engine(),
        queue=ApprovalQueue(),
    )

    assert result["decision"] == "allow_pending_approval"
    assert result["output"] is None
    assert called is False
