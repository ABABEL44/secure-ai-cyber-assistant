"""
nmap_adapter.py

Runs INSIDE the toolrunner sandbox container.

The Tool Router invokes this script only after the Policy Engine has
returned ALLOW. This script does not make authorization decisions.

Arguments are passed using argv directly; no shell interpolation is used.
"""

import argparse
import subprocess


def run_nmap(target: str, port: str, flags: list[str]) -> str:
    # The Policy Engine is responsible for validating the flags.
    # This process only constructs argv and executes Nmap without a shell.
    argv = ["nmap", *flags, "-p", port, target]

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "ERROR: nmap scan timed out after 120s"

    if result.returncode != 0:
        return (
            f"ERROR: nmap exited {result.returncode}\n"
            f"{result.stderr}"
        )

    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument("--target", required=True)
    parser.add_argument("--port", required=True)

    # Everything following --flags is treated as a flag value, including
    # values beginning with "-". The Policy Engine has already validated
    # these flags before this adapter is invoked.
    parser.add_argument(
        "--flags",
        nargs=argparse.REMAINDER,
        default=[],
    )

    args = parser.parse_args()

    output = run_nmap(
        target=args.target,
        port=args.port,
        flags=args.flags,
    )

    print(output, end="")


if __name__ == "__main__":
    main()
