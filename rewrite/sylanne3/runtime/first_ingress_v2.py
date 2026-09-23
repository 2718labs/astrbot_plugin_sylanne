"""Pure identities and clock arithmetic for the atomic v2 first ingress."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import math
import time

from ..contracts import canonical_json
from ..runtime_contracts import canonical_digest


def ingress_ids(source_ref: str) -> tuple[str, str, str, str, str, str]:
    identity = hashlib.sha256(
        ("sylanne3.host-ingress.v1:" + source_ref).encode("ascii")
    ).hexdigest()
    return (
        identity,
        "ingress-" + identity[:24],
        "host-ingress-" + identity[:32],
        "encode-" + identity[:24],
        "encode-outbox-" + identity[:24],
        "host-ingress:" + identity,
    )


def policy_identity(installation, clock, encoding, fingerprint: str,
                    source_ref: str, conversation_ref: str) -> str:
    return canonical_json({
        "fingerprint": fingerprint,
        "source_ref": source_ref,
        "conversation_ref": conversation_ref,
        "installation_digest": canonical_digest(installation.digest_payload()),
        "clock_policy": asdict(clock),
        "encoding_policy": {
            "deadline_after_seconds": encoding.deadline_after_seconds,
            "quote_ceiling": dict(encoding.quote_ceiling),
            "snapshot_ref": encoding.snapshot_ref,
            "resource_ref": encoding.resource_ref,
            "character_interval_ref": encoding.character_interval_ref,
        },
    })


def trusted_upper(clock_reading) -> float:
    """Advance the paired UTC upper bound with local monotonic time only."""
    elapsed = time.monotonic() - clock_reading.monotonic_after_seconds
    if elapsed < 0 or not math.isfinite(elapsed):
        raise ValueError("paired ingress monotonic clock changed")
    upper = math.nextafter(
        math.fsum((clock_reading.utc_upper_bound_seconds, elapsed)), math.inf)
    if not math.isfinite(upper):
        raise ValueError("paired ingress clock upper bound is invalid")
    return upper


def finish_digest(attempt_id: str, permit_token: str, operation_id: str,
                  bundle_digest: str | None, *, rejected: bool = False) -> str:
    if rejected:
        payload = {
            "operation_id": attempt_id, "permit_token": permit_token,
            "action": "rejected_no_commit",
            "business_operation_id": operation_id,
            "first_ingress": True,
        }
    else:
        payload = {
            "operation_id": attempt_id, "permit_token": permit_token,
            "action": "finish_first_ingress",
            "business_operation_id": operation_id,
            "bundle_digest": bundle_digest,
        }
    return "sha256:" + canonical_digest(payload)
