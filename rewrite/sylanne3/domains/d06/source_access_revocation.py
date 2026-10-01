"""D06 candidate for withdrawing one source's current access.

Only W01 can authenticate the Owner actor and atomically commit this graph
write with an access-epoch advance and operation receipt under an Authority
write fence. This module does not delete source bytes, create a job/outbox, or
grant a direct GraphStore mutation path. Model egress and pending dispatch
must each synchronize against the advanced current access barrier.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from uuid import UUID

from ...graph_types import GraphSnapshot, GraphVersion, GraphWrite
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import CommandEnvelope, DependencySet, DomainProposal, canonical_digest


REVOCATION_PHASE = "source-access-revoke"


@dataclass(frozen=True, slots=True)
class SourceAccessRevocationRequest:
    source_id: str
    owner_actor: str
    request_id: str
    recorded_at: float

    def __post_init__(self) -> None:
        if (type(self.source_id) is not str or not self.source_id
                or type(self.owner_actor) is not str or not self.owner_actor):
            raise ValueError("revocation source and Owner actor are required")
        try:
            value = UUID(self.request_id)
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("revocation request requires a UUID4 identity") from exc
        if value.version != 4 or str(value) != self.request_id:
            raise ValueError("revocation request requires a canonical UUID4 identity")
        if (type(self.recorded_at) not in (int, float)
                or isinstance(self.recorded_at, bool)
                or not math.isfinite(self.recorded_at)
                or self.recorded_at < 0):
            raise ValueError("revocation time must be finite and nonnegative")


@dataclass(frozen=True, slots=True)
class SourceAccessRevocationCandidate:
    proposal: DomainProposal
    source_version: GraphVersion
    access_version: GraphVersion
    operation_id: str
    requires_atomic_access_barrier: bool = True
    status: str = "candidate_hold_authority_write_fence"


def revocation_operation_id(namespace, request: SourceAccessRevocationRequest) -> str:
    return "d06.source-access-revoke:" + canonical_digest({
        "namespace": namespace.as_tuple,
        "source_id": request.source_id,
        "owner_actor": request.owner_actor,
        "request_id": request.request_id,
    })


def compile_source_access_revocation(
    adapter, envelope: CommandEnvelope, request: SourceAccessRevocationRequest,
    snapshot: GraphSnapshot,
) -> SourceAccessRevocationCandidate:
    """Bind current source/access values to one non-replayable Owner request.

    W01 must authenticate owner_actor and the Owner session, establish a fresh
    write fence and unused request/operation identity, validate graph CAS plus
    current access/deletion epochs, then commit this access write, access epoch
    advance, and operation receipt in one transaction. The source remains.
    """
    from . import D06DomainAdapter, D06DomainProvider

    if (type(adapter) is not D06DomainAdapter or type(envelope) is not CommandEnvelope
            or type(request) is not SourceAccessRevocationRequest
            or type(snapshot) is not GraphSnapshot):
        raise TypeError("typed D06 revocation inputs are required")
    namespace = adapter.namespace
    source = source_key(*namespace.as_tuple, request.source_id)
    access = access_key(*namespace.as_tuple, request.source_id)
    operation_id = revocation_operation_id(namespace, request)
    expected_inputs = (source.token, access.token,
                       f"owner:{request.owner_actor}",
                       f"revocation-request:{request.request_id}")
    authority = envelope.authority
    identity = envelope.identity
    if (authority.namespace != namespace or authority.issuer_domain != "d06"
            or authority.actor != request.owner_actor
            or authority.purpose != "audit"
            or authority.audience != ("owner",)
            or "persona" not in authority.owner_scope
            or identity.phase != REVOCATION_PHASE
            or identity.activity_id != request.request_id
            or identity.effect_id != operation_id
            or identity.operation_id != operation_id
            or envelope.input_refs != expected_inputs):
        raise ValueError("revocation Owner scope or operation identity differs")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona)
            != namespace.as_tuple):
        raise ValueError("revocation snapshot crosses namespace")
    source_atom, access_atom = snapshot.get(source), snapshot.get(access)
    if (source_atom is None or access_atom is None
            or not source_atom.valid or not access_atom.valid
            or source_atom.revision < 1 or access_atom.revision < 1):
        raise ValueError("revocation needs current source and access heads")
    record = SourceRecord.from_dict(source_atom.value)
    validate_access(access_atom.value)
    if (record.source_id != request.source_id
            or access_atom.value["source_id"] != request.source_id
            or access_atom.value["status"] != "active"
            or request.recorded_at <= access_atom.value["recorded_at"]):
        raise ValueError("source access is absent, withdrawn, or not newer")
    source_version = GraphVersion(source, source_atom.revision)
    access_version = GraphVersion(access, access_atom.revision)
    reads = envelope.version_guard.read_versions
    if (len(reads) != 2 or set(reads) != {source_version, access_version}
            or envelope.source_qualification.source_refs != (source.token,)):
        raise ValueError("revocation lacks exact current source/access CAS")
    value = {**access_atom.value, "status": "withdrawn",
             "recorded_at": float(request.recorded_at)}
    validate_access(value)
    proposal = adapter.wrap_runtime_proposal(
        envelope,
        typed_writes=(GraphWrite(access, value, (source,)),),
        dependencies=DependencySet(
            current_invalidation=(access_version,),
            historical_provenance=(source_version,),
        ),
        contribution_keys=(f"source-access-revoke:{operation_id}",),
        required_bundle_parts=(),
    )
    D06DomainProvider().validate(proposal, snapshot)
    return SourceAccessRevocationCandidate(
        proposal, source_version, access_version, operation_id,
    )


def validate_revocation_proposal_shape(proposal: DomainProposal) -> None:
    """Reject a generic D06 memory.access withdrawal that bypasses the path."""
    writes = tuple(write for write in proposal.typed_writes
                   if write.key.type_name == "memory.access"
                   and write.value.get("status") == "withdrawn")
    if not writes:
        return
    if len(writes) != 1 or len(proposal.typed_writes) != 1:
        raise ValueError("source withdrawal must be one isolated D06 write")
    write = writes[0]
    envelope = proposal.envelope
    source = source_key(write.key.owner.bot, write.key.owner.persona,
                        write.key.owner.subject)
    request_token = envelope.input_refs[-1] if envelope.input_refs else ""
    if not request_token.startswith("revocation-request:"):
        raise ValueError("source withdrawal lacks revocation request identity")
    request = SourceAccessRevocationRequest(
        write.key.owner.subject, envelope.authority.actor,
        request_token.removeprefix("revocation-request:"),
        write.value["recorded_at"],
    )
    operation_id = revocation_operation_id(envelope.authority.namespace, request)
    access_version = next((version for version in envelope.version_guard.read_versions
                           if version.key == write.key), None)
    source_version = next((version for version in envelope.version_guard.read_versions
                           if version.key == source), None)
    if (envelope.authority.issuer_domain != "d06"
            or envelope.authority.actor != request.owner_actor
            or envelope.authority.purpose != "audit"
            or envelope.authority.audience != ("owner",)
            or "persona" not in envelope.authority.owner_scope
            or envelope.identity.phase != REVOCATION_PHASE
            or envelope.identity.activity_id != request.request_id
            or envelope.identity.effect_id != operation_id
            or envelope.identity.operation_id != operation_id
            or envelope.input_refs != (source.token, write.key.token,
                                       f"owner:{request.owner_actor}",
                                       f"revocation-request:{request.request_id}")
            or write.dependencies != (source,)
            or source_version is None or source_version.revision < 1
            or access_version is None or access_version.revision < 1
            or set(envelope.version_guard.read_versions)
            != {source_version, access_version}
            or proposal.dependencies.current_invalidation != (access_version,)
            or proposal.dependencies.historical_provenance != (source_version,)
            or proposal.required_bundle_parts):
        raise ValueError("source withdrawal bypasses the D06 revocation contract")


__all__ = ["REVOCATION_PHASE", "SourceAccessRevocationRequest",
           "SourceAccessRevocationCandidate", "revocation_operation_id",
           "compile_source_access_revocation", "validate_revocation_proposal_shape"]
