from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


class SandboxAttestationError(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxAttestation:
    toolrunner: str = "toolrunner"
    target: str = "lab-webapp"
    network: str = "sandbox_sandbox-net"
    toolrunner_ip: str = "10.50.0.20"
    target_ip: str = "10.50.0.12"
    subnet: str = "10.50.0.0/24"


class DockerSandboxAttestor:
    """
    Verifies the Docker runtime immediately before tool execution.

    This is intentionally fail-closed. If Docker cannot be inspected,
    execution is refused.
    """

    def __init__(self, expected: SandboxAttestation | None = None):
        self.expected = expected or SandboxAttestation()

    def _docker(self, *args: str) -> object:
        try:
            result = subprocess.run(
                ["docker", *args],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxAttestationError(
                f"Unable to inspect Docker sandbox: {exc}"
            ) from exc

        if result.returncode != 0:
            raise SandboxAttestationError(
                "Docker inspection failed: "
                f"{result.stderr.strip()}"
            )

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxAttestationError(
                "Docker returned invalid JSON"
            ) from exc

    def attest(self) -> SandboxAttestation:
        network_data = self._docker(
            "network",
            "inspect",
            self.expected.network,
        )

        if not isinstance(network_data, list) or not network_data:
            raise SandboxAttestationError(
                "Expected sandbox network was not found"
            )

        network = network_data[0]

        if network.get("Driver") != "bridge":
            raise SandboxAttestationError(
                "Sandbox network is not a Docker bridge"
            )

        if network.get("Internal") is not True:
            raise SandboxAttestationError(
                "Sandbox network is not internal"
            )

        configs = network.get("IPAM", {}).get("Config", [])

        if not any(
            config.get("Subnet") == self.expected.subnet
            for config in configs
        ):
            raise SandboxAttestationError(
                f"Expected subnet {self.expected.subnet} not present"
            )

        containers = network.get("Containers", {})

        found = {
            container.get("Name"): container.get("IPv4Address")
            for container in containers.values()
        }

        expected = {
            self.expected.toolrunner: f"{self.expected.toolrunner_ip}/24",
            self.expected.target: f"{self.expected.target_ip}/24",
        }

        for name, ip in expected.items():
            if found.get(name) != ip:
                raise SandboxAttestationError(
                    f"Sandbox container attestation failed for "
                    f"{name}: expected {ip}, got {found.get(name)!r}"
                )

        return self.expected
