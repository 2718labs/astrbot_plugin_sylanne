"""Build one passive private-reply candidate from a committed C02 source.

This is the host composition boundary before D11 admission.  The caller must
read the C02 receipt, source/access heads, action checks and graph guard from
the installed coordinator.  No check or source grant is minted here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json

from ..domains.d07 import (
    AttentionTicket, FocusState, attention_ticket_key,
    read_current_focus_attention_ticket,
)
from ..domains.d08 import (
    ActionIntent, ActionSchema, CommunicationGrantRequest, GoalExecutionProvider,
    RequiredCheckRegistry,
)
from ..domains.d09 import D09ExpressionProvider, ExpressionClaim, SegmentCandidate
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ..memory_types import access_key
from ..runtime_contracts import (
    CheckReceipt, CommandEnvelope, CommitReceipt, DependencySet, DomainProposal,
    canonical_digest, canonical_serialize,
)


@dataclass(frozen=True)
class PostC02ReplyCandidate:
    """Same-operation domain writes, pending GraphCoordinator/D11 admission."""

    envelope: CommandEnvelope
    proposals: tuple[DomainProposal, ...]
    focus: FocusState
    action: ActionIntent
    batch_id: str


def post_c02_reply_operation_id(c02_operation_id: str, source_ref: str) -> str:
    """One durable reply operation per original C02/source pair."""
    return "post-c02-reply:" + canonical_digest({
        "version": 1, "c02_operation_id": c02_operation_id,
        "source_ref": source_ref,
    })


def prepare_post_c02_private_reply_v1(
    *, c02_receipt: CommitReceipt, envelope: CommandEnvelope,
    source_ref: str, snapshot: GraphSnapshot,
    current_focus: FocusState, attention: AttentionTicket,
    action: ActionIntent, schema: ActionSchema,
    checks: tuple[CheckReceipt, ...], communication: CommunicationGrantRequest,
    claims: tuple[ExpressionClaim, ...], segments: tuple[SegmentCandidate, ...],
    scene_ref: str, conversation_epoch: int, now: float,
) -> PostC02ReplyCandidate:
    """Prepare the finite D07/D08/D09 writes for a real, source-bound reply.

    ``envelope`` and ``checks`` must come from current installed graph/domain
    reads.  The operation ID must be stable for this C02 receipt and inbound
    source.  The coordinator checks those reads again at commit time.
    """
    if (type(c02_receipt) is not CommitReceipt
            or c02_receipt.status not in {"committed", "duplicate"}
            or not {"memory.episode.v1", "memory.subjective_trace.v2"}
               <= {item.key.type_name for item in c02_receipt.write_versions}):
        raise ValueError("committed original C02 receipt required")
    source = AtomKey.from_token(source_ref)
    namespace = envelope.authority.namespace
    if (source.type_name != "memory.source"
            or (source.owner.bot, source.owner.persona) != namespace.as_tuple
            or envelope.source_qualification.source_refs != (source_ref,)
            or action.source_refs != (source_ref,)
            or action.identity != envelope.identity
            or c02_receipt.operation_id not in envelope.causation
            or source_ref not in envelope.input_refs
            or envelope.identity.operation_id != post_c02_reply_operation_id(
                c02_receipt.operation_id, source_ref)):
        raise ValueError("reply must bind one C02 operation and its original D06 source")
    reads = {item.key: item.revision for item in envelope.version_guard.read_versions}
    source_access = access_key(*namespace.as_tuple, source.owner.subject or "")
    focus_key = AtomKey(
        Owner("persona", namespace.bot_id, namespace.persona_id),
        "d07.focus.v1", namespace.persona_id)
    if (reads.get(source, 0) < 1 or reads.get(source_access, 0) < 1
            or focus_key not in reads
            or len(envelope.version_guard.query_epochs) != 1
            or envelope.version_guard.query_epochs[0].scope_ref != "all"):
        raise ValueError("reply needs current source/access/focus and one full graph read")
    if (schema.proactive or schema.action_kind != "message"
            or action.action_kind != "message"
            or communication.cancellation_epoch != 0
            or len(segments) != 1 or len(communication.segment_specs) != 1):
        raise ValueError("only one ordinary passive private text reply is supported")
    if type(snapshot) is not GraphSnapshot:
        raise ValueError("current graph attention snapshot required")
    current_attention = read_current_focus_attention_ticket(
        snapshot, namespace, now=now)
    if (current_attention is None or current_attention.ticket != attention
            or current_attention.focus != current_focus
            or attention.causal_root != source_ref
            or attention.source_refs != (source_ref,)
            or attention.category != "interaction"):
        raise ValueError("current D07 attention must select the original C02 source")
    ticket_key = attention_ticket_key(namespace, attention.ticket_id)
    if (reads.get(ticket_key) != current_attention.ticket_version.revision
            or reads.get(focus_key) != current_attention.focus_version.revision):
        raise ValueError("reply attention and focus require current graph reads")

    registry = RequiredCheckRegistry()
    registry.register(schema)
    decision = registry.qualify(action, checks, now=now)
    if decision.status != "qualified":
        raise ValueError(f"current D08 action checks did not qualify: {decision.status}")
    grant = registry.freeze_communication_grant(
        action, decision, communication, now=now)
    d09 = D09ExpressionProvider()
    blueprint_result = d09.prepare_blueprint(
        grant, scene_ref, conversation_epoch, claims, now=now)
    if blueprint_result.status != "complete" or blueprint_result.blueprint is None:
        raise ValueError(f"D09 blueprint is {blueprint_result.status}")
    batch = d09.build_verified_batch_v1(
        grant, blueprint_result.blueprint, segments, now=now)

    activity_owner = Owner(
        "activity", namespace.bot_id, namespace.persona_id,
        envelope.identity.activity_id)
    grant_key = AtomKey(
        activity_owner, "d08.communication_intent_grant.v1", grant.grant_id)
    batch_key = AtomKey(
        activity_owner, "d09.verified_segment_batch.v1", batch["batch_id"])
    if reads.get(grant_key, 0) != 0 or reads.get(batch_key, 0) != 0:
        raise ValueError("reply grant and finite batch must be new graph heads")
    extra = tuple(GraphVersion(key, 0) for key in (grant_key, batch_key)
                  if key not in reads)
    envelope = replace(envelope, version_guard=replace(
        envelope.version_guard,
        read_versions=envelope.version_guard.read_versions + extra))

    d08 = GoalExecutionProvider()
    empty_d08 = DomainProposal(
        "d08", "d08.proposal.v1", d08.descriptor.request_schema_hash,
        envelope, (), DependencySet(), (), (),
    )
    action_proposal = d08.prepare_action_candidate(empty_d08, action, schema)
    # D08 adds absent action/schema/cancellation read guards. All proposals in
    # a bundle must share that exact envelope, so propagate it before building.
    envelope = action_proposal.envelope
    grant_write = GraphWrite(
        grant_key,
        json.loads(canonical_serialize(asdict(grant))))
    d08_proposal = d08.validate(replace(
        action_proposal, typed_writes=action_proposal.typed_writes + (grant_write,)))
    d09_proposal = d09.validate(DomainProposal(
        "d09", "d09.proposal.v1", d09.descriptor.request_schema_hash,
        envelope, (GraphWrite(batch_key, batch),), DependencySet(), (), (),
    ))
    return PostC02ReplyCandidate(
        envelope, (d08_proposal, d09_proposal), current_focus, action,
        batch["batch_id"])


__all__ = (
    "PostC02ReplyCandidate", "post_c02_reply_operation_id",
    "prepare_post_c02_private_reply_v1",
)
