"""Read-only C09 V4 recovery fact assembly from installed original readers.

The caller supplies an Authority-owned installed port and operation identity,
never facts or arbitrary text.
Each port method must authenticate and exhaustively read its category from
current immutable originals; ``None`` means the category cannot be proven.
The returned DTO is a candidate for Authority verification, not a cleanup
receipt or permission to switch storage identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..runtime_contracts import canonical_digest
from .c09_storage_rebase_contract_v1 import (
    SanitizedD02FactV4, SanitizedD11FactV4, SanitizedExecutionFactV4,
    SanitizedGraphFactV4, SanitizedRecoveryFactsV4, SanitizedUnknownFactV4,
)


class C09RecoveryFactsHold(ValueError):
    """A required current immutable original or verifier is unavailable."""

    def __init__(self, missing: tuple[str, ...]):
        self.missing = missing
        super().__init__("C09 sanitized recovery originals unavailable: "
                         + ", ".join(missing))


@dataclass(frozen=True, slots=True)
class C09RecoveryAnchorOriginalV4:
    """Identity facts verified against current Core PREPARED and old chain."""

    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    old_chain_head_digest: str
    verifier_commitment: str


class C09TrustedRecoveryOriginalsPortV4(Protocol):
    """Installer/Authority injection point; every read proves completeness.

    A missing table, unpaired signed terminal, stale Core seal, or incomplete
    W01 graph barrier must return None or raise. Methods must not use browser
    facts or metadata fields as substitutes for immutable originals.
    """

    def read_current_anchor_v4(
        self, *, namespace: str, operation_id: str,
    ) -> C09RecoveryAnchorOriginalV4 | None: ...

    def read_current_execution_originals_v4(
        self, *, namespace: str, operation_id: str,
    ) -> tuple[SanitizedExecutionFactV4, ...] | None: ...

    def read_current_d02_originals_v4(
        self, *, namespace: str, operation_id: str,
    ) -> tuple[SanitizedD02FactV4, ...] | None: ...

    def read_current_d11_originals_v4(
        self, *, namespace: str, operation_id: str,
    ) -> tuple[SanitizedD11FactV4, ...] | None: ...

    def read_current_unknown_originals_v4(
        self, *, namespace: str, operation_id: str,
    ) -> tuple[SanitizedUnknownFactV4, ...] | None: ...

    def read_current_graph_originals_v4(
        self, *, namespace: str, operation_id: str,
    ) -> tuple[SanitizedGraphFactV4, ...] | None: ...


_READS = (
    ("anchor", "read_current_anchor_v4", C09RecoveryAnchorOriginalV4),
    ("execution", "read_current_execution_originals_v4", SanitizedExecutionFactV4),
    ("d02", "read_current_d02_originals_v4", SanitizedD02FactV4),
    ("d11", "read_current_d11_originals_v4", SanitizedD11FactV4),
    ("unknown", "read_current_unknown_originals_v4", SanitizedUnknownFactV4),
    ("graph", "read_current_graph_originals_v4", SanitizedGraphFactV4),
)


def extract_sanitized_recovery_facts_v4(
    *, port: C09TrustedRecoveryOriginalsPortV4, namespace: str,
    operation_id: str,
) -> SanitizedRecoveryFactsV4:
    """Assemble only complete, typed current-original reads; otherwise HOLD.

    The installed caller owns the trust of ``port`` and must pin the returned
    facts digest to Core before any storage rebase. This function has no direct
    access to Authority credentials, graph state, or old journal bytes.
    """
    if type(namespace) is not str or not namespace or type(operation_id) is not str \
            or not operation_id:
        raise C09RecoveryFactsHold(("operation_identity",))
    found = {}
    missing = []
    for category, method_name, item_type in _READS:
        read = getattr(port, method_name, None)
        if not callable(read):
            missing.append(category)
            continue
        try:
            value = read(namespace=namespace, operation_id=operation_id)
        except C09RecoveryFactsHold as exc:
            missing.extend(exc.missing)
            continue
        except Exception:
            missing.append(category)
            continue
        if category == "anchor":
            if type(value) is not item_type or (value.namespace, value.operation_id) \
                    != (namespace, operation_id):
                missing.append(category)
                continue
        elif type(value) is not tuple or any(type(item) is not item_type for item in value):
            missing.append(category)
            continue
        found[category] = value
    if missing:
        raise C09RecoveryFactsHold(tuple(missing))
    anchor = found["anchor"]
    body = (
        anchor.authority_id, anchor.installation_id, namespace, operation_id,
        anchor.old_chain_head_digest, anchor.verifier_commitment,
        found["execution"], found["d02"], found["d11"], found["unknown"],
        found["graph"], "sylanne3.authority.sanitized_recovery_facts.v4",
    )
    try:
        return SanitizedRecoveryFactsV4(
            *body[:-1], canonical_digest(body), body[-1],
        )
    except (TypeError, ValueError) as exc:
        raise C09RecoveryFactsHold(("cross_category_consistency",)) from exc


__all__ = [
    "C09RecoveryAnchorOriginalV4", "C09RecoveryFactsHold",
    "C09TrustedRecoveryOriginalsPortV4", "extract_sanitized_recovery_facts_v4",
]
