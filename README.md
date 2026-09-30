# Milestone: Policy Engine + Tool Router + Sandboxed Nmap

This is a working vertical slice of the Secure AI Cybersecurity Assistant: a
proposed tool call goes through the Policy Engine, and — only on `ALLOW` —
actually executes inside an isolated Docker sandbox. Tool output is sanitized
before it can re-enter an AI model's context.

## Structure

```
policy/          Policy Engine (rules, schema, evaluator) — from the previous milestone
sandbox/         Docker sandbox: isolated network, target app, nmap execution
tool_router/      Router that gates every tool call through the Policy Engine
api/              Local HTTP boundary for requests and approvals
audit/            Hash-chained JSONL audit logger
ai/               Non-authorizing deterministic intent parser
```

## Requirements

- Docker + Docker Compose
- Python 3.10+
- `pip install -r requirements.txt`

## Running it

1. **Start the sandbox** (isolated network, target app, nmap runner):
   ```bash
   cd sandbox
   docker compose -f docker-compose.sandbox.yml up -d --build
   ```
   This creates a private bridge network (`10.50.0.0/24`, `internal: true` —
   no route to the internet or your host LAN), with:
   - `lab-webapp` at `10.50.0.12:8080` — the disposable scan target
   - `toolrunner` at `10.50.0.20` — has Nmap installed, waits for commands

2. **Run the Tool Router smoke test**:
   ```bash
   cd ../tool_router
   python3 router.py
   ```
   This proposes an Nmap scan against the sandboxed target. You should see
   the Policy Engine's decision (`allow`, in-scope, low-tier auto-approved)
   followed by real Nmap output from inside the sandbox container.

3. **Optional: start the local API**:
   ```bash
   python3 api/server.py
   ```
   The API binds only to `127.0.0.1:8081`. The included approver token is a
   demo value and must be replaced by real authentication before deployment.
   Open `http://127.0.0.1:8081` in a browser for the chat interface. Without
   an API key it uses the safe deterministic parser. To enable the optional
   OpenAI provider, set `OPENAI_API_KEY` in the server environment (and
   optionally `OPENAI_MODEL`); the key is never sent to the browser.

4. **Tear down** when done — sandbox containers are disposable:
   ```bash
   cd ../sandbox
   docker compose -f docker-compose.sandbox.yml down
   ```

## What this proves

- A proposed action never reaches Nmap without an explicit `ALLOW` from
  `PolicyEngine.evaluate()`.
- Denied requests (wrong scope, wrong role, disallowed flag) never touch
  the adapter at all — verified in testing.
- High-tier tools go to `ALLOW_PENDING_APPROVAL`
  and sit in `ApprovalQueue` — they do not execute until a `lead_analyst`
  calls the approval endpoint.
- Nmap itself only ever runs inside the `toolrunner` container, on a network
  with no route out — even if the router logic had a bug, blast radius is
  contained to the sandbox.

## Known gaps at this milestone (by design — next steps)

- The audit log is hash-chained JSONL, which is tamper-evident but not
  immutable storage. Export it to protected/WORM storage for production.
- Only one tool adapter (Nmap) exists. Adding another tool means: add it to
  `policy.yaml`, write an adapter following `adapters/nmap_adapter.py` as a
  template, and register it in `router.py`'s `ADAPTERS` dict — no other
  changes needed.
- The approval queue is intentionally in-memory. Restarting the API loses
  pending approvals; use durable storage before deployment.
- The configured approver identity and token are demo-only. Replace them with
  real identity/JWT/mTLS authentication before deployment.
