"""
adapters/nmap_adapter.py (Tool Router side)
============================================
This is the Tool Router's adapter for Nmap. It does NOT run Nmap itself —
it shells out to the isolated `toolrunner` sandbox container via
`docker exec`, which is where sandbox/nmap_adapter.py actually lives and
runs. This split keeps Nmap execution physically confined to a container
with no route to the internet or host network (see docker-compose.sandbox.yml).
"""
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from policy.policy_engine import ToolRequest


def execute(request: ToolRequest) -> str:
    """Run nmap inside the toolrunner sandbox container for an ALLOWED
    request. Caller (router.py) must have already confirmed the Policy
    Engine returned ALLOW before calling this."""

    argv = [
        "docker", "exec", "toolrunner",
        "python3", "/app/nmap_adapter.py",
        "--target", request.target_host,
        "--port", str(request.target_port),
        "--flags", *request.flags,
    ]

    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=150)
    except subprocess.TimeoutExpired:
        return "ERROR: sandboxed nmap execution timed out"
    except FileNotFoundError:
        return "ERROR: docker not available on this host — is the sandbox running?"

    if result.returncode != 0:
        return f"ERROR: sandbox execution failed ({result.returncode})\n{result.stderr}"

    return result.stdout
