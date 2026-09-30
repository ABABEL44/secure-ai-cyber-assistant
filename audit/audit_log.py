"""
Tamper-evident audit logger.

Every security decision is written as one JSON object per line.
Each record contains the SHA-256 hash of the previous record,
forming a simple hash chain.

This provides tamper evidence, not absolute immutability. For production,
the resulting log should additionally be copied to protected/WORM storage.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_LOG_PATH = (
    Path(__file__).resolve().parent.parent / "logs" / "audit.log"
)


class AuditLogger:
    def __init__(self, log_path: str | Path = DEFAULT_LOG_PATH):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.log_path.exists():
            return "GENESIS"

        last_hash = "GENESIS"

        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # A malformed record means the chain cannot safely
                    # continue. Fail closed.
                    raise RuntimeError(
                        "Audit log contains malformed JSON"
                    )

                last_hash = record.get("entry_hash")

                if not last_hash:
                    raise RuntimeError(
                        "Audit log contains record without entry_hash"
                    )

        return last_hash

    @staticmethod
    def _canonical_json(record: dict[str, Any]) -> bytes:
        return json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        previous_hash = self._last_hash()

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": previous_hash,
            **event,
        }

        # Hash everything except entry_hash itself.
        digest = hashlib.sha256(
            self._canonical_json(record)
        ).hexdigest()

        record["entry_hash"] = digest

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    record,
                    sort_keys=True,
                    ensure_ascii=False,
                )
                + "\n"
            )

        return record

    def verify(self) -> tuple[bool, str]:
        """
        Verify the entire hash chain.

        Returns:
            (True, message) if valid.
            (False, message) if tampering/corruption is detected.
        """

        if not self.log_path.exists():
            return True, "Audit log does not exist yet"

        expected_previous = "GENESIS"
        line_number = 0

        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line_number += 1
                line = line.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return False, (
                        f"Malformed JSON at audit log line {line_number}"
                    )

                stored_hash = record.pop("entry_hash", None)

                if stored_hash is None:
                    return False, (
                        f"Missing entry_hash at line {line_number}"
                    )

                previous_hash = record.get("previous_hash")

                if previous_hash != expected_previous:
                    return False, (
                        f"Hash-chain break at line {line_number}: "
                        f"expected previous hash {expected_previous}, "
                        f"found {previous_hash}"
                    )

                calculated_hash = hashlib.sha256(
                    self._canonical_json(record)
                ).hexdigest()

                if calculated_hash != stored_hash:
                    return False, (
                        f"Entry tampering detected at line {line_number}"
                    )

                expected_previous = stored_hash

        return True, "Audit log hash chain is valid"


if __name__ == "__main__":
    logger = AuditLogger()

    valid, message = logger.verify()

    print(f"Verification: {'PASS' if valid else 'FAIL'}")
    print(message)
