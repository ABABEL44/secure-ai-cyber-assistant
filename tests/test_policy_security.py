from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT / "policy"))

from policy_engine import PolicyEngine, ToolRequest, Verdict


def make_engine():
    return PolicyEngine(
        ROOT / "policy" / "policy.yaml",
        ROOT / "policy" / "policy.schema.json",
    )


def make_request(
    role="analyst",
    tool="nmap",
    flags=None,
    host="10.50.0.12",
    port=8080,
):
    return ToolRequest(
        user="test_user",
        role=role,
        tool=tool,
        flags=flags if flags is not None else ["-sV"],
        target_host=host,
        target_port=port,
    )


def test_in_scope_low_risk_is_allowed():
    decision = make_engine().evaluate(make_request())

    assert decision.verdict == Verdict.ALLOW


def test_out_of_scope_target_is_denied():
    decision = make_engine().evaluate(
        make_request(
            host="8.8.8.8",
            port=443,
        )
    )

    assert decision.verdict == Verdict.DENY
    assert "not covered" in decision.reason


def test_unauthorized_flag_is_denied():
    decision = make_engine().evaluate(
        make_request(
            flags=["--script=vuln"],
        )
    )

    assert decision.verdict == Verdict.DENY
    assert "allowlist" in decision.reason


def test_analyst_cannot_run_high_risk_tool():
    decision = make_engine().evaluate(
        make_request(
            role="analyst",
            tool="nmap_aggressive",
            flags=["-A"],
        )
    )

    assert decision.verdict == Verdict.DENY
    assert "not permitted" in decision.reason


def test_lead_analyst_high_risk_requires_approval():
    decision = make_engine().evaluate(
        make_request(
            role="lead_analyst",
            tool="nmap_aggressive",
            flags=["-A"],
        )
    )

    assert decision.verdict == Verdict.ALLOW_PENDING_APPROVAL


def test_unknown_tool_is_denied():
    decision = make_engine().evaluate(
        make_request(
            tool="totally_fake_tool",
            flags=[],
        )
    )

    assert decision.verdict == Verdict.DENY
    assert "not enabled" in decision.reason


def test_port_outside_scope_is_denied():
    decision = make_engine().evaluate(
        make_request(
            port=9999,
        )
    )

    assert decision.verdict == Verdict.DENY
    assert "not in scope" in decision.reason
