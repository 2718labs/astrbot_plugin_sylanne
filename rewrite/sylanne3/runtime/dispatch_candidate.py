"""Durable D08/D09 candidate linkage and graph-backed D06 source proof."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace

from ..domains.d06 import D06DomainProvider, SourceGrantRead
from ..domains.d08 import ActionIntent, ActionSchema, ActionSchemaRecord, GoalExecutionProvider
from ..domains.d09 import ClaimUse, D09ExpressionProvider
from ..domains.d09.natural_batch import (
    NATURAL_BATCH_SCHEMA_V2, NATURAL_BATCH_SCHEMA_V3, validate_natural_verified_batch_value,
)
from ..graph_types import GraphWrite
from ..memory_types import access_key, source_key
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..runtime_contracts import NamespaceId, OperationIdentity, canonical_digest


_LINKED_TYPES = {
    "d08.action_intent.v1": "d08",
    "d08.action_schema.v1": "d08",
    "d08.communication_intent_grant.v1": "d08",
    "d09.verified_segment_batch.v1": "d09",
}

def dispatch_segment_payload_ref(batch_ref: str, index: int) -> str:
    """Name one D09 graph segment without embedding its JSON atom token."""
    if (type(batch_ref) is not str
            or AtomKey.from_token(batch_ref).type_name != "d09.verified_segment_batch.v1"):
        raise ValueError("payload reference requires a D09 verified batch atom")
    if type(index) is not int or index < 0:
        raise ValueError("segment index must be a nonnegative exact integer")
    return "d09:" + canonical_digest({
        "batch_ref": batch_ref, "segment_index": index,
    })


def natural_dispatch_segment_payload_ref_v2(batch_ref: str, index: int) -> str:
    """Name a natural V2 segment without changing existing V1 payload IDs."""
    if (type(batch_ref) is not str
            or AtomKey.from_token(batch_ref).type_name not in {NATURAL_BATCH_SCHEMA_V2, NATURAL_BATCH_SCHEMA_V3}):
        raise ValueError("payload reference requires a natural V2 batch atom")
    if type(index) is not int or index < 0:
        raise ValueError("segment index must be a nonnegative exact integer")
    return "d09-natural:" + canonical_digest({
        "schema": AtomKey.from_token(batch_ref).type_name,
        "batch_ref": batch_ref, "segment_index": index,
    })


@dataclass(frozen=True)
class DispatchCandidateEvidenceV1:
    """Content identity of one graph-committed candidate, never admission."""

    operation_id: str
    action_ref: str
    schema_ref: str
    grant_ref: str
    batch_ref: str
    action_digest: str
    schema_digest: str
    grant_digest: str
    batch_digest: str
    source_refs: tuple[str, ...]
    source_read_versions: tuple[tuple[str, int], ...]
    access_read_versions: tuple[tuple[str, int], ...]
    access_epoch: int
    delete_epoch: int
    query_epoch: int
    status: str = "source_hold"
    source_audience: tuple[str, ...] = ()
    source_proof_versions: tuple[tuple[str, int], ...] = ()
    source_proof_digest: str | None = None

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True)
class DispatchCandidateRecoveryV1:
    evidence: DispatchCandidateEvidenceV1
    write_versions: tuple[tuple[str, int], ...]
    graph_epoch: int
    graph_incarnation: str | None
    graph_revision: int | None


@dataclass(frozen=True)
class NaturalDispatchCandidateEvidenceV2:
    """Typed same-bundle identity for a reviewed natural segment, not admission."""

    operation_id: str
    effect_id: str
    action_ref: str
    schema_ref: str
    grant_ref: str
    batch_ref: str
    action_digest: str
    schema_digest: str
    grant_digest: str
    batch_digest: str
    segment_id: str
    payload_digest: str
    paid_review_digest: str
    generation_original_operation_id: str
    review_original_operation_id: str
    source_refs: tuple[str, ...]
    current_read_versions: tuple[GraphVersion, ...]
    access_epoch: int
    delete_epoch: int
    query_epoch: int
    status: str = "natural_paid_review_current_hold"

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True)
class NaturalDispatchCandidateRecoveryV2:
    evidence: NaturalDispatchCandidateEvidenceV2
    write_versions: tuple[tuple[str, int], ...]
    graph_epoch: int
    graph_incarnation: str | None
    graph_revision: int | None


@dataclass(frozen=True)
class GraphDispatchTextSegmentV1:
    """One committed D09 text segment with a proven AstrBot route."""

    body: str
    media_refs: tuple[str, ...]
    claim_uses: tuple[ClaimUse, ...]
    platform_id: str
    platform_name: str
    self_id: str
    umo: str
    conversation_id: str
    scene_ref: str


def validate_dispatch_candidate_writes(
    writes: tuple[tuple[str, GraphWrite], ...], *,
    namespace: NamespaceId, identity: OperationIdentity,
    read_versions: tuple[GraphVersion, ...], source_refs: tuple[str, ...],
    access_epoch: int, delete_epoch: int, query_epoch: int,
) -> DispatchCandidateEvidenceV1 | NaturalDispatchCandidateEvidenceV2 | None:
    """Require a single exact D08/D09 candidate in the same bundle transaction."""
    natural_writes = tuple((domain, write) for domain, write in writes
                           if write.key.type_name in {NATURAL_BATCH_SCHEMA_V2, NATURAL_BATCH_SCHEMA_V3})
    if natural_writes:
        if len(natural_writes) != 1 or any(
                write.key.type_name == "d09.verified_segment_batch.v1"
                for _, write in writes):
            raise ValueError("natural and source reply batches cannot share a bundle")
        return validate_natural_dispatch_candidate_writes(
            writes, namespace=namespace, identity=identity,
            read_versions=read_versions, source_refs=source_refs,
            access_epoch=access_epoch, delete_epoch=delete_epoch,
            query_epoch=query_epoch)
    selected: dict[str, GraphWrite] = {}
    for domain, write in writes:
        expected = _LINKED_TYPES.get(write.key.type_name)
        if expected is None:
            continue
        if domain != expected or write.key.type_name in selected:
            raise ValueError("dispatch candidate has duplicate or foreign domain writes")
        if ((write.key.owner.bot, write.key.owner.persona) != namespace.as_tuple
                or write.key.owner.kind != "activity"
                or write.key.owner.subject != identity.activity_id):
            raise ValueError("dispatch candidate graph owner differs from operation")
        selected[write.key.type_name] = write
    if "d09.verified_segment_batch.v1" not in selected:
        return None
    if set(selected) != set(_LINKED_TYPES):
        raise ValueError("verified D09 batch requires paired D08 action, schema and grant")
    if (type(access_epoch) is not int or access_epoch < 0
            or type(delete_epoch) is not int or delete_epoch < 0
            or type(query_epoch) is not int or query_epoch < 0):
        raise ValueError("dispatch candidate requires exact nonnegative graph epochs")

    d08_types = {spec.name: spec for spec in GoalExecutionProvider().register_types()}
    action_write = selected["d08.action_intent.v1"]
    schema_write = selected["d08.action_schema.v1"]
    grant_write = selected["d08.communication_intent_grant.v1"]
    batch_write = selected["d09.verified_segment_batch.v1"]
    intent = d08_types[action_write.key.type_name].validator(action_write.value)
    schema = d08_types[schema_write.key.type_name].validator(schema_write.value)
    grant = d08_types[grant_write.key.type_name].validator(grant_write.value)
    next(spec for spec in D09ExpressionProvider.register_types()
         if spec.name == "d09.verified_segment_batch.v1").validator(batch_write.value)
    batch = batch_write.value
    frozen = ActionSchema(
        schema.schema_id, schema.action_kind, schema.proactive, schema.required_checks,
    )
    if (type(schema) is not ActionSchemaRecord
            or ActionSchemaRecord.bind(intent, frozen) != schema
            or intent.identity != identity
            or action_write.key.name != intent.action_id
            or schema_write.key.name != schema.schema_ref
            or grant_write.key.name != grant.grant_id
            or batch_write.key.name != batch["batch_id"]
            or grant.intent_ref != intent.action_id
            or grant.action_id != intent.action_id
            or grant.intent_revision != intent.revision
            or grant.target_ref != intent.target_ref
            or grant.purpose != "expression"
            or batch["action_id"] != intent.action_id
            or batch["intent_revision"] != intent.revision
            or batch["target_ref"] != intent.target_ref
            or batch["grant_id"] != grant.grant_id
            or batch["communication_action_id"] != grant.communication_action_id
            or batch["contact_id"] != grant.contact_id
            or batch["batch_revision"] != grant.batch_revision
            or batch["intent_ref"] != grant.intent_ref
            or batch["grant_digest"] != canonical_digest(grant)
            or batch["grant_manifest_digest"] != grant.segment_manifest_digest
            or batch["required_check_refs"] != list(grant.required_check_refs)
            or batch["audiences"] != list(grant.audiences)
            or batch["purpose"] != grant.purpose
            or batch["cancellation_epoch"] != grant.cancellation_epoch
            or batch["valid_until"] != grant.valid_until
            or not {ref for part in batch["segments"] for ref in part["source_refs"]}
            <= set(intent.source_refs)):
        raise ValueError("D08/D09 candidate identity or source scope differs")
    check_refs = tuple("check:" + canonical_digest({
        "kind": item.check_kind, "provider": item.provider_id,
        "subject": item.subject_ref, "action": item.action_ref,
        "purpose": item.purpose, "criteria_version": item.criteria_version,
        "input_versions": item.required_input_versions,
    }) for item in schema.required_checks)
    if (grant.required_check_refs != check_refs
            or len(batch["segments"]) != len(grant.segment_grants)
            or any((part["segment_id"], part["effect_id"], part["position"],
                    part["payload_digest"], part["segment_authorization_ref"])
                   != (segment.segment_id, segment.effect_id, segment.position,
                       segment.payload_digest,
                       grant.segment_authorization_ref(segment.segment_id))
                   for part, segment in zip(batch["segments"], grant.segment_grants))):
        raise ValueError("D08/D09 finite check or segment grant differs")
    reads = {item.key.token: item.revision for item in read_versions}
    if set(source_refs) != set(intent.source_refs) or len(source_refs) != len(intent.source_refs):
        raise ValueError("dispatch candidate source qualification differs")
    source_versions = []
    access_versions = []
    for ref in intent.source_refs:
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise ValueError("dispatch candidate source is not a D06 graph source")
        access = access_key(*namespace.as_tuple, key.owner.subject or "")
        if reads.get(ref, 0) < 1 or reads.get(access.token, 0) < 1:
            raise ValueError("dispatch candidate lacks source and access read versions")
        source_versions.append((ref, reads[ref]))
        access_versions.append((access.token, reads[access.token]))
    return DispatchCandidateEvidenceV1(
        identity.operation_id, action_write.key.token, schema_write.key.token,
        grant_write.key.token, batch_write.key.token,
        canonical_digest(intent), canonical_digest(schema),
        canonical_digest(grant), batch["batch_digest"],
        tuple(intent.source_refs), tuple(source_versions), tuple(access_versions),
        access_epoch, delete_epoch, query_epoch,
    )


def validate_natural_dispatch_candidate_writes(
    writes: tuple[tuple[str, GraphWrite], ...], *,
    namespace: NamespaceId, identity: OperationIdentity,
    read_versions: tuple[GraphVersion, ...], source_refs: tuple[str, ...],
    access_epoch: int, delete_epoch: int, query_epoch: int,
) -> NaturalDispatchCandidateEvidenceV2:
    """Bind D08 and natural D09 graph writes without granting dispatch."""
    batch_names = {write.key.type_name for _, write in writes
                   if write.key.type_name in {NATURAL_BATCH_SCHEMA_V2, NATURAL_BATCH_SCHEMA_V3}}
    if len(batch_names) != 1:
        raise ValueError("one explicit natural batch version required")
    batch_name = next(iter(batch_names))
    names = {"d08.action_intent.v1", "d08.action_schema.v1",
             "d08.communication_intent_grant.v1", batch_name}
    selected: dict[str, GraphWrite] = {}
    for domain, write in writes:
        name = write.key.type_name
        if name not in names:
            continue
        if (name in selected or domain != ("d09" if name == batch_name
                                             else "d08")
                or (write.key.owner.bot, write.key.owner.persona)
                   != namespace.as_tuple
                or write.key.owner.kind != "activity"
                or write.key.owner.subject != identity.activity_id):
            raise ValueError("natural dispatch graph owner or writer differs")
        selected[name] = write
    if set(selected) != names:
        raise ValueError("natural batch requires paired D08 action, schema and grant")
    if (type(access_epoch) is not int or access_epoch < 0
            or type(delete_epoch) is not int or delete_epoch < 0
            or type(query_epoch) is not int or query_epoch < 0):
        raise ValueError("natural dispatch requires current graph barriers")
    d08 = {spec.name: spec for spec in GoalExecutionProvider().register_types()}
    action_write = selected["d08.action_intent.v1"]
    schema_write = selected["d08.action_schema.v1"]
    grant_write = selected["d08.communication_intent_grant.v1"]
    batch_write = selected[batch_name]
    action = d08[action_write.key.type_name].validator(action_write.value)
    schema = d08[schema_write.key.type_name].validator(schema_write.value)
    grant = d08[grant_write.key.type_name].validator(grant_write.value)
    validate_natural_verified_batch_value(batch_write.value)
    batch = batch_write.value
    paid = batch["paid_review"]
    segment = batch["segment"]
    if (type(schema) is not ActionSchemaRecord
            or ActionSchemaRecord.bind(action, ActionSchema(
                schema.schema_id, schema.action_kind, schema.proactive,
                schema.required_checks)) != schema
            or action.identity != identity
            or action_write.key.name != action.action_id
            or schema_write.key.name != schema.schema_ref
            or grant_write.key.name != grant.grant_id
            or batch_write.key.name != batch["batch_id"]
            or grant.action_id != action.action_id
            or grant.intent_revision != action.revision
            or grant.target_ref != action.target_ref
            or grant.purpose != "expression"
            or grant.route_binding_digest != batch["route_binding_digest"]
            or batch["activity_id"] != identity.activity_id
            or batch["operation_id"] != identity.operation_id
            or batch["effect_id"] != identity.effect_id
            or batch["grant_id"] != grant.grant_id
            or batch["grant_digest"] != canonical_digest(grant)
            or batch["action_id"] != action.action_id
            or batch["intent_ref"] != grant.intent_ref
            or batch["segment_authorization_ref"]
               != grant.segment_authorization_ref(segment["segment_id"])
            or batch["required_check_refs"] != list(grant.required_check_refs)
            or grant.audiences != (batch["audience_id"],)
            or len(grant.segment_grants) != 1
            or (grant.segment_grants[0].segment_id,
                grant.segment_grants[0].effect_id,
                grant.segment_grants[0].payload_digest)
               != (segment["segment_id"], identity.effect_id,
                   segment["payload_digest"])):
        raise ValueError("natural D08/D09 action or segment identity differs")
    reads = {item.key.token: item.revision for item in read_versions}
    if (len(reads) != len(read_versions)
            or tuple(source_refs) != tuple(action.source_refs)
            or batch["source_ref"]["ref"] not in source_refs):
        raise ValueError("natural source qualification differs")
    for ref in source_refs:
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise ValueError("natural source is not a canonical D06 graph source")
    if reads.get(batch["source_ref"]["ref"]) != batch["source_ref"]["version"]:
        raise ValueError("natural triggering source version differs")
    current = tuple(GraphVersion(AtomKey.from_token(item["ref"]),
                                 item["version"])
                    for item in batch["current_reads"])
    if (len({item.key for item in current}) != len(current)
            or any(reads.get(item.key.token) != item.revision for item in current)
            or any(reads.get(ref, 0) < 1 or reads.get(access_key(
                *namespace.as_tuple,
                AtomKey.from_token(ref).owner.subject or "").token, 0) < 1
                   for ref in source_refs)):
        raise ValueError("natural current source or paid read closure differs")
    return NaturalDispatchCandidateEvidenceV2(
        identity.operation_id, identity.effect_id,
        action_write.key.token, schema_write.key.token,
        grant_write.key.token, batch_write.key.token,
        canonical_digest(action), canonical_digest(schema),
        canonical_digest(grant), batch["batch_digest"],
        segment["segment_id"], segment["payload_digest"],
        paid["receipt_digest"],
        paid["generation_original_operation_id"],
        paid["review_original_operation_id"], tuple(source_refs), current,
        access_epoch, delete_epoch, query_epoch)


def qualify_dispatch_candidate_sources(
    candidate: DispatchCandidateEvidenceV1, intent: ActionIntent,
    snapshot: GraphSnapshot, *, audience: tuple[str, ...],
    batch_audiences: tuple[str, ...], current_barrier_confirmed: bool,
    valid_until: float,
) -> DispatchCandidateEvidenceV1:
    """Promote only a complete, pinned D06 source-grant check from this graph read."""
    if (candidate.status != "source_hold" or len(snapshot.epochs) != 1
            or candidate.query_epoch != snapshot.epochs[0].revision
            or audience != batch_audiences
            or not current_barrier_confirmed):
        return candidate
    reads = {item.key.token: item.revision for item in snapshot.versions}
    if (len(reads) != len(snapshot.versions)
            or any(reads.get(ref) != version
                   for ref, version in (*candidate.source_read_versions,
                                        *candidate.access_read_versions))):
        return candidate
    try:
        check = D06DomainProvider.provide_required_check(
            intent, SourceGrantRead(snapshot, audience, "expression", True, True),
            valid_until=valid_until,
        )
    except (TypeError, ValueError):
        return candidate
    if (check.result, check.coverage) != ("pass", "full"):
        return candidate
    atoms = {atom.key.token: atom for atom in snapshot.atoms}
    proof = []
    for item in check.input_versions:
        atom = atoms.get(item.ref)
        if atom is None or atom.key.type_name not in {"memory.source", "memory.access"}:
            return candidate
        proof.append((item.ref, item.version, canonical_digest(atom.value)))
    return replace(
        candidate, status="source_qualified",
        source_audience=audience,
        source_proof_versions=tuple((ref, revision) for ref, revision, _ in proof),
        source_proof_digest=canonical_digest(proof),
    )


__all__ = [
    "DispatchCandidateEvidenceV1", "DispatchCandidateRecoveryV1",
    "NaturalDispatchCandidateEvidenceV2", "NaturalDispatchCandidateRecoveryV2",
    "GraphDispatchTextSegmentV1", "dispatch_segment_payload_ref",
    "natural_dispatch_segment_payload_ref_v2",
    "qualify_dispatch_candidate_sources", "validate_dispatch_candidate_writes",
    "validate_natural_dispatch_candidate_writes",
]
