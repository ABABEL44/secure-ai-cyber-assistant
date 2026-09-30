import json
import threading
from http.client import HTTPConnection

import api.server as server


def api_request(method, path, payload=None):
    connection = HTTPConnection("127.0.0.1", 8081, timeout=3)

    body = None
    headers = {}

    if payload is not None:
        body = json.dumps(payload)
        headers["Content-Type"] = "application/json"

    connection.request(method, path, body=body, headers=headers)

    response = connection.getresponse()
    raw = response.read()

    connection.close()

    return response.status, json.loads(raw)


def test_health_endpoint():
    status, body = api_request("GET", "/health")

    assert status == 200
    assert body["status"] == "ok"


def test_unknown_endpoint_returns_404():
    status, body = api_request("GET", "/does-not-exist")

    assert status == 404
    assert body["error"] == "not_found"


def test_missing_request_body_returns_400():
    status, body = api_request("POST", "/tool-request")

    assert status == 400
    assert "error" in body


def test_invalid_json_returns_400():
    connection = HTTPConnection("127.0.0.1", 8081, timeout=3)

    connection.request(
        "POST",
        "/tool-request",
        body="{not valid json",
        headers={"Content-Type": "application/json"},
    )

    response = connection.getresponse()
    raw = response.read()

    connection.close()

    assert response.status == 400

    body = json.loads(raw)
    assert "error" in body


def test_missing_tool_request_fields_returns_400():
    status, body = api_request(
        "POST",
        "/tool-request",
        {
            "user": "analyst_jane",
            "role": "analyst",
        },
    )

    assert status == 400
    assert body["error"] == "invalid tool request"


def test_unauthorized_approver_returns_403():
    status, body = api_request(
        "POST",
        "/approve",
        {
            "request_id": "does-not-exist",
            "approver_user": "attacker",
            "approver_token": "wrong-token",
        },
    )

    assert status == 403
    assert body["error"] == "approver authentication failed"

def test_missing_approval_fields_returns_400():
    status, body = api_request(
        "POST",
        "/approve",
        {
            "request_id": "something",
        },
    )

    assert status == 400
    assert "required" in body["error"]


def test_nonexistent_approval_returns_error():
    status, body = api_request(
        "POST",
        "/approve",
        {
            "request_id": "does-not-exist",
            "approver_user": "lead_analyst",
            "approver_token": server.APPROVER_TOKENS["lead_analyst"],
        },
    )

    assert status == 200
    assert body["decision"] == "error"

def test_unauthorized_denier_returns_403():
    status, body = api_request(
        "POST",
        "/deny",
        {
            "request_id": "does-not-exist",
            "approver_user": "attacker",
            "approver_token": "wrong-token",
        },
    )

    assert status == 403
    assert body["error"] == "approver authentication failed"


def test_missing_denial_fields_returns_400():
    status, body = api_request(
        "POST",
        "/deny",
        {
            "request_id": "something",
        },
    )

    assert status == 400
    assert "required" in body["error"]


def test_nonexistent_denial_returns_error():
    status, body = api_request(
        "POST",
        "/deny",
        {
            "request_id": "does-not-exist",
            "approver_user": "lead_analyst",
            "approver_token": server.APPROVER_TOKENS["lead_analyst"],
        },
    )

    assert status == 200
    assert body["decision"] == "error"


def high_risk_request(request_id):
    return api_request(
        "POST",
        "/tool-request",
        {
            "request_id": request_id,
            "user": "analyst_jane",
            "role": "lead_analyst",
            "tool": "nmap_aggressive",
            "flags": ["-A"],
            "target_host": "10.50.0.12",
            "target_port": 8080,
        },
    )


def test_pending_request_can_be_approved(monkeypatch):
    import router

    monkeypatch.setattr(router, "_execute", lambda request: "safe test output")
    request_id = "api-approve-lifecycle"

    status, body = high_risk_request(request_id)
    assert status == 200
    assert body["decision"] == "allow_pending_approval"
    assert body["approval_required"] is True

    status, body = api_request("GET", "/pending")
    assert status == 200
    assert request_id in body["requests"]

    status, body = api_request(
        "POST",
        "/approve",
        {
            "request_id": request_id,
            "approver_user": "lead_analyst",
            "approver_token": server.APPROVER_TOKENS["lead_analyst"],
        },
    )
    assert status == 200
    assert body["decision"] == "approved_and_executed"
    assert body["output"] == "safe test output"

    status, body = api_request("GET", "/pending")
    assert request_id not in body["requests"]


def test_pending_request_can_be_denied():
    request_id = "api-deny-lifecycle"
    status, body = high_risk_request(request_id)
    assert status == 200
    assert body["approval_required"] is True

    status, body = api_request(
        "POST",
        "/deny",
        {
            "request_id": request_id,
            "approver_user": "lead_analyst",
            "approver_token": server.APPROVER_TOKENS["lead_analyst"],
        },
    )
    assert status == 200
    assert body["decision"] == "denied"


def test_expired_pending_request_is_not_executed(monkeypatch):
    import router

    monkeypatch.setattr(router, "_is_expired", lambda pending, engine: True)
    monkeypatch.setattr(router, "_execute", lambda request: "must not execute")
    request_id = "api-expired-lifecycle"
    status, body = high_risk_request(request_id)
    assert status == 200
    assert body["approval_required"] is True

    status, body = api_request(
        "POST",
        "/approve",
        {
            "request_id": request_id,
            "approver_user": "lead_analyst",
            "approver_token": server.APPROVER_TOKENS["lead_analyst"],
        },
    )
    assert status == 200
    assert body["decision"] == "expired"
