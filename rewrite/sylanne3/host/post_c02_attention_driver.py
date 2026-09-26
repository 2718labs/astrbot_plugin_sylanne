"""Prepare a durable D07 focus for one settled, private C02 source.

The graph coordinator supplies the fenced C02, source/access and guard facts.
This module only makes the deterministic attention decision and proposal; it
cannot attest to settlement, grant access, or write the graph itself.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..domains.d07 import (
    AttentionPolicy, AttentionTicket, D07DomainProvider, FocusState,
    attention_ticket_key,
)
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, Owner
from ..memory_types import access_key, source_key
from ..runtime_contracts import (
    AuthorityContext, CommandEnvelope, CommitReceipt, DomainBundle,
    OperationIdentity, SourceQualification, VersionGuard, canonical_digest,
)


def post_c02_attention_operation_id(c02_operation_id: str, source_ref: str) -> str:
    return "post-c02-attention:" + canonical_digest({
        "schema": "sylanne.post-c02-attention.v1",
        "c02_operation_id": c02_operation_id, "source_ref": source_ref,
    })


@dataclass(frozen=True)
class PostC02AttentionCandidateV1:
    bundle: DomainBundle
    ticket: AttentionTicket
    focus: FocusState


def prepare_post_c02_attention_v1(
    *, c02_receipt: CommitReceipt, source_ref: str,
    snapshot: GraphSnapshot, qualification: SourceQualification,
    authority: AuthorityContext, guard: VersionGuard,
    parent_budget_lease_ref: str, conversation_ref: str,
    now_utc: float, monotonic_deadline: float,
    ticket_lifetime_seconds: float = 300.0,
) -> PostC02AttentionCandidateV1:
    """Build one source-bound ticket and advance focus one graph revision."""
    namespace = authority.namespace
    source = AtomKey.from_token(source_ref)
    if (type(c02_receipt) is not CommitReceipt
            or c02_receipt.status != "committed"
            or not {"memory.episode.v1", "memory.subjective_trace.v2"}
               <= {version.key.type_name for version in c02_receipt.write_versions}
            or source != source_key(*namespace.as_tuple, source.owner.subject or "")
            or qualification.source_refs != (source_ref,)
            or authority.purpose != "expression"
            or authority.audience != (conversation_ref,)
            or type(snapshot) is not GraphSnapshot
            or len(snapshot.epochs) != 1
            or snapshot.epochs[0].bot != namespace.bot_id
            or snapshot.epochs[0].persona != namespace.persona_id
            or len(guard.query_epochs) != 1
            or guard.query_epochs[0].scope_ref != "all"
            or guard.query_epochs[0].revision != snapshot.epochs[0].revision
            or ticket_lifetime_seconds <= 0):
        raise ValueError("fenced settled C02 and exact private source required")
    access = access_key(*namespace.as_tuple, source.owner.subject or "")
    focus_key = AtomKey(Owner("persona", *namespace.as_tuple),
                        "d07.focus.v1", namespace.persona_id)
    source_atom = snapshot.get(source)
    access_atom = snapshot.get(access)
    focus_atom = snapshot.get(focus_key)
    reads = {version.key: version.revision for version in guard.read_versions}
    if (source_atom is None or not source_atom.valid or source_atom.revision < 1
            or access_atom is None or not access_atom.valid or access_atom.revision < 1
            or access_atom.value.get("status") != "active"
            or "expression" not in access_atom.value.get("purposes", ())
            or conversation_ref not in access_atom.value.get("audiences", ())
            or reads.get(source) != source_atom.revision
            or reads.get(access) != access_atom.revision
            or reads.get(focus_key) != (focus_atom.revision if focus_atom else 0)):
        raise ValueError("current source, access, and focus guards required")
    if focus_atom is not None and focus_atom.revision:
        if not focus_atom.valid:
            raise ValueError("invalid current focus")
        value = focus_atom.value
        current = FocusState(value["persona_id"], value["focus_epoch"],
                             value["primary_ticket_ref"],
                             tuple(value["auxiliary_ticket_refs"]),
                             value["switch_reason"])
    else:
        current = FocusState(namespace.persona_id, 0, None, (), "no_eligible_ticket")
    operation_id = post_c02_attention_operation_id(c02_receipt.operation_id, source_ref)
    ticket_id = "attention:" + canonical_digest({"operation_id": operation_id})[:48]
    ticket_key = attention_ticket_key(namespace, ticket_id)
    if reads.get(ticket_key, 0) != 0:
        raise ValueError("attention ticket already exists without committed operation")
    ticket = AttentionTicket(
        ticket_id, "inbound:" + (source.owner.subject or ""), None, source_ref,
        "interaction", 1.0, 0.5, 0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0,
        c02_receipt.commit_seq or 0, now_utc + ticket_lifetime_seconds,
        True, True, (), (source_ref,),
    )
    provider = D07DomainProvider()
    focus = provider.allocate_focus(current, (ticket,), AttentionPolicy.default(),
                                    now=now_utc)
    if focus.primary_ticket_ref != ticket_id:
        raise ValueError("inbound source was not selected for focus")
    focus = replace(focus, primary_ticket_ref=ticket_key.token)
    inputs = (source_ref,)
    identity = OperationIdentity(
        c02_receipt.activity_id, None, "attention-attempt", "post_c02_attention",
        operation_id, canonical_digest({"input_refs": list(inputs)}),
    )
    envelope = CommandEnvelope(
        "sylanne.runtime.v1", identity, authority, guard, qualification,
        inputs, parent_budget_lease_ref, now_utc + ticket_lifetime_seconds,
        monotonic_deadline, "character-v1", (c02_receipt.operation_id,),
    )
    proposal = provider.attention_focus_proposal(
        envelope, snapshot, ticket, focus, now=now_utc)
    bundle = DomainBundle(proposal.envelope, (proposal,), (), (), (), (), (), (), ())
    return PostC02AttentionCandidateV1(bundle, ticket, focus)


__all__ = (
    "PostC02AttentionCandidateV1", "post_c02_attention_operation_id",
    "prepare_post_c02_attention_v1",
)
