"""
Minimal HTTP API boundary for the secure tool router.

The API accepts tool proposals but never executes tools directly.
Every request is converted into ToolRequest and passed through
PolicyEngine + ApprovalQueue.
"""

from __future__ import annotations

import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "policy"))
sys.path.insert(0, str(ROOT / "tool_router"))

from policy_engine import PolicyEngine, ToolRequest
from router import ApprovalQueue, handle_request
from ai.providers import ChatProvider, build_provider


ENGINE = PolicyEngine(
    ROOT / "policy" / "policy.yaml",
    ROOT / "policy" / "policy.schema.json",
)

QUEUE = ApprovalQueue()
PROVIDER: ChatProvider = build_provider()
APPROVERS = {
    "lead_analyst": "lead_analyst",
}

# Demo authentication boundary.
# Replace with real identity/JWT/mTLS authentication in production.
APPROVER_TOKENS = {
    "lead_analyst": "CHANGE-ME-APPROVER-TOKEN",
}

CHAT_PAGE = """<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Secure AI Cyber Assistant</title><style>
body{font:16px system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;background:#101827;color:#e5e7eb}h1{color:#7dd3fc}.note{color:#a5b4fc}#chat{min-height:240px;border:1px solid #334155;padding:16px;background:#0f172a;white-space:pre-wrap}.user{color:#fbbf24}.assistant{color:#86efac}form{display:flex;gap:8px;margin-top:16px}input,select,button{padding:10px;border-radius:6px;border:1px solid #475569}input{flex:1}button{background:#0284c7;color:white;cursor:pointer}</style></head>
<body><h1>Secure AI Cyber Assistant</h1><p class=\"note\">The AI proposes actions. Policy and approval decide whether they run.</p>
<label>User <input id=\"user\" value=\"analyst_jane\"></label> <label>Role <select id=\"role\"><option>analyst</option><option>lead_analyst</option><option>viewer</option></select></label>
<div id=\"chat\" aria-live=\"polite\">Assistant: Ask for an authorized sandbox scan, e.g. “scan 10.50.0.12 port 8080”.</div>
<form id=\"form\"><input id=\"message\" autocomplete=\"off\" placeholder=\"Type a request\" required><button>Send</button></form>
<script>const chat=document.querySelector('#chat'),form=document.querySelector('#form'),message=document.querySelector('#message');
form.addEventListener('submit',async e=>{e.preventDefault();const text=message.value.trim();if(!text)return;chat.innerHTML+=`\\n\\n<span class=\"user\">You: ${text.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}</span>`;message.value='';const r=await fetch('/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:document.querySelector('#user').value,role:document.querySelector('#role').value,message:text})});const d=await r.json();chat.innerHTML+=`\\n<span class=\"assistant\">Assistant: ${d.message||d.error}</span>`+(d.decision?`\\nPolicy: ${d.decision} — ${d.reason||''}`:'');chat.scrollTop=chat.scrollHeight;});</script></body></html>"""

class APIHandler(BaseHTTPRequestHandler):

    def _read_json(self) -> dict:
        content_length = int(
            self.headers.get("Content-Length", "0")
        )

        if content_length <= 0:
            raise ValueError("request body is required")

        if content_length > 16_384:
            raise ValueError("request body too large")

        raw_body = self.rfile.read(content_length)
        data = json.loads(raw_body)

        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")

        return data

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    def _send_html(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _tool_request_from(data: dict) -> ToolRequest:
        required = ("user", "role", "tool", "target_host", "target_port")
        if any(field not in data for field in required):
            raise ValueError(
                "user, role, tool, target_host and target_port are required"
            )

        flags = data.get("flags", [])
        if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
            raise ValueError("flags must be a list of strings")
        if not isinstance(data["target_port"], int) or isinstance(data["target_port"], bool):
            raise ValueError("target_port must be an integer")

        return ToolRequest(
            user=data["user"],
            role=data["role"],
            tool=data["tool"],
            flags=flags,
            target_host=data["target_host"],
            target_port=data["target_port"],
        )

    @staticmethod
    def _authenticated_approver(data: dict) -> tuple[str, str] | None:
        user = data.get("approver_user")
        token = data.get("approver_token")
        expected = APPROVER_TOKENS.get(user) if isinstance(user, str) else None
        role = APPROVERS.get(user) if isinstance(user, str) else None

        if expected is None or role is None or not isinstance(token, str):
            return None
        if not hmac.compare_digest(token, expected):
            return None
        return user, role

    @staticmethod
    def _chat_fields(data: dict) -> tuple[str, str, str]:
        user, role, message = data.get("user"), data.get("role"), data.get("message")
        if not all(isinstance(value, str) and value.strip() for value in (user, role, message)):
            raise ValueError("user, role and message must be non-empty strings")
        if len(message) > 4_000:
            raise ValueError("message is too large")
        return user, role, message

    def do_POST(self) -> None:
        try:
            data = self._read_json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(
                400,
                {"error": str(exc)},
            )
            return

        # ---------------------------------------------------------
        # Tool request
        # ---------------------------------------------------------

        if self.path == "/tool-request":
            try:
                request = self._tool_request_from(data)
            except (KeyError, TypeError, ValueError) as exc:
                self._send_json(
                    400,
                    {
                        "error": "invalid tool request",
                        "detail": str(exc),
                    },
                )
                return

            result = handle_request(
                request=request,
                engine=ENGINE,
                queue=QUEUE,
                request_id=data.get("request_id"),
            )

            self._send_json(200, result)
            return

        # ---------------------------------------------------------
        # Chat: provider may propose, but cannot authorize or execute.
        # ---------------------------------------------------------

        if self.path == "/chat":
            try:
                user, role, message = self._chat_fields(data)
                reply = PROVIDER.reply(message)
            except (ValueError, TypeError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            except Exception:
                self._send_json(502, {"error": "AI provider unavailable"})
                return

            result = {"message": reply.message, "provider": reply.provider}
            if reply.proposal is not None:
                request = ToolRequest(user=user, role=role, **reply.proposal)
                result.update(handle_request(request, ENGINE, QUEUE))
            self._send_json(200, result)
            return

        # ---------------------------------------------------------
        # Approval
        # ---------------------------------------------------------

        if self.path == "/approve":
            request_id = data.get("request_id")
            approver_user = data.get("approver_user")
            approver_token = data.get("approver_token")

            if not request_id or not approver_user:
                self._send_json(
                    400,
                    {
                        "error": (
                            "request_id, approver_user and "
                            "approver_token are required"
                        ),
                    },
                )
                return

            authenticated = self._authenticated_approver(data)

            if authenticated is None:
                self._send_json(
                    403,
                    {
                        "error": "approver authentication failed",
                    },
                )
                return

            approver_user, approver_role = authenticated

            from router import approve_request

            result = approve_request(
                request_id=request_id,
                approver_user=approver_user,
                approver_role=approver_role,
                engine=ENGINE,
                queue=QUEUE,
            )

            self._send_json(200, result)
            return

        # ---------------------------------------------------------
        # Denial
        # ---------------------------------------------------------

        if self.path == "/deny":
            request_id = data.get("request_id")
            approver_user = data.get("approver_user")
            approver_token = data.get("approver_token")

            if not request_id or not approver_user or not approver_token:
                self._send_json(
                    400,
                    {
                        "error": (
                            "request_id and approver_user are required"
                        ),
                    },
                )
                return

            authenticated = self._authenticated_approver(data)

            if authenticated is None:
                self._send_json(
                    403,
                    {
                        "error": "approver authentication failed",
                    },
                )
                return

            approver_user, approver_role = authenticated

            from router import deny_request

            result = deny_request(
                request_id=request_id,
                approver_user=approver_user,
                approver_role=approver_role,
                engine=ENGINE,
                queue=QUEUE,
            )

            self._send_json(200, result)
            return

        self._send_json(
            404,
            {"error": "not_found"},
        )

    def do_GET(self) -> None:
        if self.path == "/":
            self._send_html(CHAT_PAGE.encode("utf-8"))
            return
        if self.path == "/health":
            self._send_json(
                200,
                {"status": "ok"},
            )
            return

        if self.path == "/pending":
            self._send_json(
                200,
                {
                    "requests": list(QUEUE.pending().keys()),
                },
            )
            return

        self._send_json(
            404,
            {"error": "not_found"},
        )

    def log_message(self, format: str, *args) -> None:
        # Keep the demo server output quiet.
        return


def main() -> None:
    server = ThreadingHTTPServer(
        ("127.0.0.1", 8081),
        APIHandler,
    )

    print("Secure API listening on http://127.0.0.1:8081")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
