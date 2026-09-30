import json

from audit.audit_log import AuditLogger


def test_audit_chain_valid(tmp_path):
    log = tmp_path / "audit.log"
    logger = AuditLogger(log)

    logger.append({
        "event": "policy_decision",
        "decision": "allow",
        "tool": "nmap",
    })

    logger.append({
        "event": "tool_execution",
        "decision": "executed",
        "tool": "nmap",
    })

    valid, message = logger.verify()

    assert valid is True
    assert "valid" in message.lower()


def test_audit_chain_detects_tampering(tmp_path):
    log = tmp_path / "audit.log"
    logger = AuditLogger(log)

    logger.append({
        "event": "policy_decision",
        "decision": "allow",
        "tool": "nmap",
    })

    logger.append({
        "event": "tool_execution",
        "decision": "executed",
        "tool": "nmap",
    })

    lines = log.read_text().splitlines()

    record = json.loads(lines[0])
    record["decision"] = "deny"

    lines[0] = json.dumps(record)
    log.write_text("\n".join(lines) + "\n")

    valid, message = logger.verify()

    assert valid is False
    assert "tampering" in message.lower()
