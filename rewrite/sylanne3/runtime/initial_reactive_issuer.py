"""Assemble one reactive D08/D09 candidate for the graph coordinator.

This boundary creates a durable *candidate* bundle.  It never issues a
dispatch admission or interprets a caller supplied check receipt as authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import math

from ..domains.d08 import (
    ActionCancellationState, ActionIntent, ActionSchema, ActionSchemaRecord, CommunicationIntentGrant,
    GoalExecutionProvider,
)
from ..domains.d09 import (
    D09ExpressionProvider, ExpressionBlueprint, SegmentCandidate,
)
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..runtime_contracts import (
    CommandEnvelope, DependencySet, DomainBundle, DomainProposal, QueryEpoch,
)
from .dispatch_candidate import (
    DispatchCandidateEvidenceV1, validate_dispatch_candidate_writes,
)


@dataclass(frozen=True)
class InitialReactiveCandidateV1:
    bundle: DomainBundle
    evidence: DispatchCandidateEvidenceV1

    @property
    def missing_for_admission(self) -> tuple[str, ...]:
        # The coordinator may qualify D06 sources during commit.  These other
        # gates need current, independently read domain/Authority evidence.
        return (
            "d06.committed_source_qualification",
            "d01.current_owner_and_resource",
            "d08.grant_provenance",
            "d08.current_execution_and_cancellation",
            "d09.committed_content_provenance",
            "d11.current_budget_and_execution_fence",
        )


def _graph_json(value: object) -> object:
    if isinstance(value, tuple):
        return [_graph_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _graph_json(item) for key, item in value.items()}
    return value


def assemble_initial_reactive_candidate(
    envelope: CommandEnvelope, intent: ActionIntent, schema: ActionSchemaRecord,
    grant: CommunicationIntentGrant, blueprint: ExpressionBlueprint,
    segments: tuple[SegmentCandidate, ...], *, now_utc: float,
) -> InitialReactiveCandidateV1:
    """Build a single segment candidate from real D08 and D09 domain outputs.

    The caller owns the frozen envelope and source graph read set.  This pure
    function checks their linkage, then the coordinator must validate and
    commit the returned bundle under its own capability and write fence.
    """
    if (type(envelope) is not CommandEnvelope or type(intent) is not ActionIntent
            or type(schema) is not ActionSchemaRecord
            or type(grant) is not CommunicationIntentGrant
            or type(blueprint) is not ExpressionBlueprint
            or type(segments) is not tuple
            or any(type(item) is not SegmentCandidate for item in segments)):
        raise TypeError("typed envelope and D08/D09 candidate inputs required")
    if type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        raise ValueError("current UTC time must be finite")
    if len(segments) != 1 or len(grant.segment_grants) != 1:
        raise ValueError("initial reactive candidate requires exactly one segment")
    if (intent.identity != envelope.identity
            or envelope.source_qualification.source_refs != intent.source_refs
            or grant.intent_ref != intent.action_id
            or grant.action_id != intent.action_id
            or grant.intent_revision != intent.revision
            or grant.target_ref != intent.target_ref
            or grant.purpose != "expression"):
        raise ValueError("reactive candidate operation, source or grant differs")
    if schema != ActionSchemaRecord.bind(intent, ActionSchema(
            schema.schema_id, schema.action_kind, schema.proactive,
            schema.required_checks)) or schema.proactive:
        raise ValueError("initial reactive action needs its frozen nonproactive schema")
    guard = envelope.version_guard
    namespace = envelope.authority.namespace
    if (len(guard.query_epochs) != 1
            or guard.query_epochs[0] != QueryEpoch(
                namespace, "all", guard.query_epochs[0].revision)):
        raise ValueError("reactive candidate needs one full namespace query epoch")
    if now_utc >= min(grant.valid_until, envelope.deadline_utc):
        raise ValueError("reactive candidate deadline has expired")
    # D09 recomputes the finite body, claims and manifest from supplied inputs.
    batch = D09ExpressionProvider.build_verified_batch_v1(
        grant, blueprint, segments, now=now_utc,
    )
    owner = Owner("activity", *namespace.as_tuple, intent.identity.activity_id)
    initial = ActionCancellationState.for_action(
        intent, state="active", actor=envelope.authority.actor,
        source_refs=envelope.source_qualification.source_refs,
        operation_id=intent.identity.operation_id,
    )
    state_key = AtomKey(owner, "d08.action_cancellation.v1", intent.action_id)
    state_reads = tuple(item.revision for item in guard.read_versions
                        if item.key == state_key)
    if state_reads not in {(), (0,)}:
        raise ValueError("initial action cancellation requires an absent graph head")
    if not state_reads:
        guard = replace(guard, read_versions=guard.read_versions + (GraphVersion(state_key, 0),))
        envelope = replace(envelope, version_guard=guard)
    values = (
        ("d08.action_intent.v1", intent.action_id, intent),
        ("d08.action_schema.v1", schema.schema_ref, schema),
        ("d08.action_cancellation.v1", intent.action_id, initial),
        ("d08.communication_intent_grant.v1", grant.grant_id, grant),
        ("d09.verified_segment_batch.v1", batch["batch_id"], batch),
    )
    writes = tuple(GraphWrite(
        AtomKey(owner, type_name, name),
        _graph_json(asdict(value) if not isinstance(value, dict) else value),
    ) for type_name, name, value in values)
    d08_provider = GoalExecutionProvider()
    d09_provider = D09ExpressionProvider()
    d08 = DomainProposal(
        "d08", "d08.proposal.v1", d08_provider.descriptor.request_schema_hash,
        envelope, writes[:4], DependencySet(), (), (),
    )
    d09 = DomainProposal(
        "d09", "d09.proposal.v1", d09_provider.descriptor.request_schema_hash,
        envelope, writes[4:], DependencySet(), (), (),
    )
    d08_provider.validate(d08)
    d09_provider.validate(d09)
    evidence = validate_dispatch_candidate_writes(
        (("d08", writes[0]), ("d08", writes[1]), ("d08", writes[2]),
         ("d08", writes[3]), ("d09", writes[4])),
        namespace=namespace, identity=envelope.identity,
        read_versions=guard.read_versions,
        source_refs=envelope.source_qualification.source_refs,
        access_epoch=guard.access_epoch, delete_epoch=guard.delete_epoch,
        query_epoch=guard.query_epochs[0].revision,
    )
    if evidence is None or evidence.status != "source_hold":
        raise ValueError("D08/D09 candidate was not linked as source HOLD")
    bundle = DomainBundle(envelope, (d08, d09), (), (), (), (), (), (), ())
    return InitialReactiveCandidateV1(bundle, evidence)


__all__ = ["InitialReactiveCandidateV1", "assemble_initial_reactive_candidate"]
