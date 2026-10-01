"""Evidence-bound candidate for acknowledging a bilateral commitment.

D08 cannot authenticate graph rows or interpret an inbound message alone.
The graph coordinator must supply a current, complete read and verify it under
its barrier before adopting the returned revision with CAS.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from typing import Callable

from ...graph_types import GraphVersion, GraphWrite
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_serialize
from .execution import Commitment


@dataclass(frozen=True, slots=True)
class BilateralAcknowledgementReadV1:
    namespace: NamespaceId
    commitment: Commitment
    commitment_head: GraphVersion
    outbound_receipt: VersionedRef
    outbound_status: str
    inbound_source: GraphVersion
    inbound_access: GraphVersion
    inbound_actor_ref: str
    accepted_commitment_id: str
    accepted_scope: str
    acceptance_result: str
    coverage: str

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or type(self.commitment) is not Commitment
                or type(self.commitment_head) is not GraphVersion
                or type(self.outbound_receipt) is not VersionedRef
                or type(self.inbound_source) is not GraphVersion
                or type(self.inbound_access) is not GraphVersion):
            raise TypeError("typed bilateral commitment read required")
        key = self.commitment_head.key
        source = self.inbound_source.key
        access = self.inbound_access.key
        if (key.type_name != "d08.commitment.v1"
                or key.name != self.commitment.commitment_id
                or source.type_name != "memory.source"
                or access.type_name != "memory.access"
                or source.owner.subject != access.owner.subject
                or any((item.owner.bot, item.owner.persona) != self.namespace.as_tuple
                       for item in (key, source, access))
                or min(self.commitment_head.revision,
                       self.inbound_source.revision,
                       self.inbound_access.revision) < 1):
            raise ValueError("commitment and inbound source heads differ from namespace")
        if self.outbound_status not in {"accepted", "unknown", "known_not_accepted"}:
            raise ValueError("outbound receipt status is invalid")
        if self.acceptance_result not in {"accepted", "unknown", "disputed"}:
            raise ValueError("inbound acceptance result is invalid")
        if self.coverage not in {"full", "partial", "none"}:
            raise ValueError("acceptance read coverage is invalid")
        if any(type(value) is not str or not value for value in (
            self.inbound_actor_ref, self.accepted_commitment_id,
            self.accepted_scope,
        )):
            raise ValueError("inbound actor and accepted scope are required")


@dataclass(frozen=True, slots=True)
class BilateralAcknowledgementCandidateV1:
    status: str
    commitment: Commitment | None
    required_versions: tuple[GraphVersion, ...]
    outbound_receipt: VersionedRef
    reasons: tuple[str, ...]


def propose_bilateral_acknowledgement_v1(
    read: BilateralAcknowledgementReadV1, *,
    read_verifier: Callable[[BilateralAcknowledgementReadV1], bool] | None,
) -> BilateralAcknowledgementCandidateV1:
    """Only explicit, current bilateral acceptance can create an ACK candidate.

    The verifier must prove the outbound receipt, D06 source/access, inbound
    actor, semantic acceptance, and all read heads. A caller-supplied ``accepted``
    string is never sufficient. The result cannot dispatch or commit itself.
    """
    if type(read) is not BilateralAcknowledgementReadV1:
        raise TypeError("typed bilateral acknowledgement read required")
    heads = (read.commitment_head, read.inbound_source, read.inbound_access)

    def hold(*reasons: str) -> BilateralAcknowledgementCandidateV1:
        return BilateralAcknowledgementCandidateV1(
            "hold", None, heads, read.outbound_receipt, reasons,
        )

    current = read.commitment
    if (current.establishment_kind != "bilateral"
            or current.establishment_state not in {"offered", "communicated"}
            or current.counterparty_ref != read.inbound_actor_ref
            or read.accepted_commitment_id != current.commitment_id
            or read.accepted_scope != current.semantic_scope):
        return hold("commitment_scope")
    if read.outbound_status != "accepted":
        return hold("outbound_unknown" if read.outbound_status == "unknown"
                    else "outbound_not_accepted")
    if read.acceptance_result != "accepted":
        return hold("inbound_not_confirmed")
    if read.coverage != "full" or read_verifier is None:
        return hold("current_read_unavailable")
    try:
        verified = read_verifier(read) is True
    except Exception:
        verified = False
    if not verified:
        return hold("current_read_unverified")
    outbound_ref = read.outbound_receipt.ref
    source_ref = read.inbound_source.key.token
    candidate = replace(
        current,
        revision=current.revision + 1,
        establishment_state="acknowledged",
        communicated_refs=tuple(dict.fromkeys((*current.communicated_refs, outbound_ref))),
        acknowledged_refs=tuple(dict.fromkeys((*current.acknowledged_refs, source_ref))),
        parent_revision_ref=f"{current.commitment_id}@{current.revision}",
        source_refs=tuple(dict.fromkeys((*current.source_refs, source_ref))),
    )
    return BilateralAcknowledgementCandidateV1(
        "candidate", candidate, heads, read.outbound_receipt, (),
    )


def prepare_coordinator_bilateral_acknowledgement_write_v1(
    read: BilateralAcknowledgementReadV1, *,
    read_verifier: Callable[[BilateralAcknowledgementReadV1], bool],
) -> tuple[BilateralAcknowledgementCandidateV1, GraphWrite]:
    """Privileged W01 entry; use only inside its current CAS/read barrier.

    Ordinary D08 proposals reject acknowledged writes. W01 must also pin the
    returned graph versions and outbound receipt in its transaction and reject
    any graph/access/semantic change before commit.
    """
    candidate = propose_bilateral_acknowledgement_v1(
        read, read_verifier=read_verifier,
    )
    if candidate.status != "candidate" or candidate.commitment is None:
        raise ValueError("bilateral acknowledgement evidence is not current")
    write = GraphWrite(
        read.commitment_head.key,
        json.loads(canonical_serialize(asdict(candidate.commitment))),
        (read.inbound_source.key, read.inbound_access.key),
    )
    return candidate, write


__all__ = [
    "BilateralAcknowledgementReadV1", "BilateralAcknowledgementCandidateV1",
    "propose_bilateral_acknowledgement_v1",
    "prepare_coordinator_bilateral_acknowledgement_write_v1",
]
