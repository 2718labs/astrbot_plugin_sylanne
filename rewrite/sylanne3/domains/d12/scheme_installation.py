"""D12's typed graph write for a W01-authorized scheme adoption.

W01 must obtain the candidate from its current Owner/lease and durable-original
read inside the same graph write transaction. This module only describes the
CAS write; it cannot commit through ProductionGraphStore or grant authority.
"""

from __future__ import annotations

from dataclasses import asdict

from ...contracts import Event, Scope
from ...graph_types import GraphCandidate, GraphReceipt, GraphVersion, GraphWrite
from ...runtime.scheme_port_v1 import D12SchemeAdoptionCandidateV1
from .scheme_command import D12SchemeAdoptionReceiptV1
from .types import ActiveSchemeHeadV1, active_scheme_head_key, character_draft_key


def scheme_adoption_graph_candidate_v1(
    adoption: D12SchemeAdoptionCandidateV1, *, occurred_at: float,
) -> GraphCandidate:
    """Build the exact head CAS for W01's already fenced transaction."""
    if type(adoption) is not D12SchemeAdoptionCandidateV1:
        raise TypeError("W01 adoption candidate is required")
    namespace = adoption.namespace
    head_key = active_scheme_head_key(namespace)
    draft_key = character_draft_key(namespace)
    versions = {version.key: version for version in adoption.read_versions}
    compiled = adoption.compiled
    previous = adoption.previous_head
    if (set(versions) != {draft_key, head_key}
            or versions[draft_key].revision != compiled.draft_revision
            or versions[head_key].revision != compiled.active_head_revision
            or adoption.query_epoch.revision != adoption.graph_epoch
            or adoption.query_epoch.bot != namespace.bot_id
            or adoption.query_epoch.persona != namespace.persona_id
            or compiled.namespace != namespace
            or compiled.draft_ref != draft_key.token
            or compiled.active_head_ref != head_key.token
            or compiled.graph_revision != adoption.graph_epoch
            or compiled.access_epoch != adoption.access_epoch
            or compiled.delete_epoch != adoption.delete_epoch
            or compiled.compiled_digest != adoption.compiled_digest
            or adoption.preview.compiled_digest != adoption.compiled_digest
            or previous.draft_ref != draft_key.token
            or previous.scope != namespace.persona_id):
        raise ValueError("adoption read set differs from the current scheme")
    head = ActiveSchemeHeadV1(
        namespace.persona_id, previous.generation + 1,
        adoption.compiled_digest, draft_key.token, compiled.draft_revision,
        compiled.draft_digest, previous.compiled_digest,
        adoption.operation_id, "administrative_edit",
    )
    event = Event(
        Scope(namespace.bot_id, namespace.persona_id, "d12.scheme_adoption.v1"),
        adoption.operation_id, occurred_at, "scheme_adoption",
        {"compiled_digest": adoption.compiled_digest,
         "preview_seal": adoption.preview.issuer_seal},
    )
    return GraphCandidate(
        event, adoption.read_versions,
        (GraphWrite(head_key, {"schema": head_key.type_name, **asdict(head)}),),
        (adoption.query_epoch,),
    )


def scheme_adoption_receipt_v1(
    adoption: D12SchemeAdoptionCandidateV1, graph_receipt: GraphReceipt,
) -> D12SchemeAdoptionReceiptV1:
    """Translate only a committed one-head GraphStore CAS into a D12 receipt."""
    key = active_scheme_head_key(adoption.namespace)
    old_revision = adoption.compiled.active_head_revision
    if (type(graph_receipt) is not GraphReceipt
            or graph_receipt.status != "committed"
            or graph_receipt.revisions != (GraphVersion(key, old_revision + 1),)
            or graph_receipt.epoch.revision != adoption.graph_epoch + 1
            or graph_receipt.epoch.bot != adoption.namespace.bot_id
            or graph_receipt.epoch.persona != adoption.namespace.persona_id):
        raise ValueError("scheme head CAS did not commit exactly once")
    return D12SchemeAdoptionReceiptV1(
        adoption.operation_id, adoption.namespace, adoption.compiled_digest,
        key.token, old_revision, key.token, old_revision + 1,
        graph_receipt.epoch.revision,
    )


__all__ = ("scheme_adoption_graph_candidate_v1", "scheme_adoption_receipt_v1")
