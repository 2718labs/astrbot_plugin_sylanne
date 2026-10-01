"""Current, typed D07 experiment input for a D12 preview operation.

The caller owns the GraphStore transaction and the signed Owner fence.  This
reader authenticates the compiled original against the current draft and the
persisted domain candidate; it does not reserve compute or issue a preview.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import sqlite3

from ..domains.d07 import AttentionPolicy
from ..domains.d12.scheme_command import D12SchemeHold
from ..domains.d12.types import (
    ActiveSchemeHeadV1, CharacterDraft, active_scheme_head_key,
    character_draft_key,
)
from ..runtime_contracts import NamespaceId, canonical_digest
from .d12_compiled_candidate_store_v1 import verify_d12_domain_candidate_v1
from .d12_domain_scheme_compile_v1 import (
    ATTENTION_POLICY_FIELD, D12AttentionPolicyCandidateV1,
    compile_d12_domain_scheme_candidate_v1,
)
from .d12_scheme_behavior_preview_v1 import D12BehaviorExperimentSpecV1
from .scheme_original_store_v1 import (
    CompilationOriginalV1, read_compilation_original_for_operation_v1,
)


@dataclass(frozen=True, slots=True)
class D12CurrentPreviewPlanV1:
    original: CompilationOriginalV1
    spec: D12BehaviorExperimentSpecV1
    baseline: AttentionPolicy
    candidate: D12AttentionPolicyCandidateV1
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    plan_digest: str


def read_current_d12_preview_plan_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *,
    operation_id: str, compiled_digest: str, graph_revision: int,
    access_epoch: int, delete_epoch: int,
) -> D12CurrentPreviewPlanV1:
    """Require the complete current D07 draft and its immutable compilation."""
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise D12SchemeHold("current graph transaction is required")
    original = read_compilation_original_for_operation_v1(
        db, namespace, compiled_digest=compiled_digest)
    if original is None:
        raise D12SchemeHold("compiled scheme original is unavailable")
    compiled = original.compiled
    if (compiled.namespace != namespace
            or compiled.graph_revision != graph_revision
            or compiled.access_epoch != access_epoch
            or compiled.delete_epoch != delete_epoch
            or len(compiled.domain_receipts) != 1):
        raise D12SchemeHold("compiled scheme is not current D07-only input")
    receipt = compiled.domain_receipts[0]
    if (receipt.domain != "d07"
            or receipt.field_names != (ATTENTION_POLICY_FIELD,)):
        raise D12SchemeHold("mixed or unsupported preview scheme")
    draft_key = character_draft_key(namespace)
    head_key = active_scheme_head_key(namespace)
    draft_row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (draft_key.token,),
    ).fetchone()
    head_row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (head_key.token,),
    ).fetchone()
    if (draft_row is None or head_row is None
            or draft_row[2] != 1 or head_row[2] != 1
            or draft_row[0] != compiled.draft_revision
            or head_row[0] != compiled.active_head_revision
            or compiled.draft_ref != draft_key.token
            or compiled.active_head_ref != head_key.token):
        raise D12SchemeHold("current draft or active head differs")
    try:
        raw_draft = json.loads(draft_row[1])
        raw_head = json.loads(head_row[1])
        if (raw_draft.pop("schema") != draft_key.type_name
                or raw_head.pop("schema") != head_key.type_name):
            raise ValueError("scheme graph type differs")
        draft = CharacterDraft(**raw_draft)
        head = ActiveSchemeHeadV1(**raw_head)
    except (KeyError, TypeError, ValueError) as exc:
        raise D12SchemeHold("current scheme graph value differs") from exc
    if (draft.scope != namespace.persona_id
            or draft.revision != draft_row[0]
            or canonical_digest(draft) != compiled.draft_digest
            or head.scope != namespace.persona_id
            or head.generation != head_row[0]
            or set(draft.fields) != {ATTENTION_POLICY_FIELD}
            or set(draft.field_sources) != {ATTENTION_POLICY_FIELD}):
        raise D12SchemeHold("current scheme draft is not the compiled D07 input")
    if (head.generation != 1 or head.adoption_kind != "initial"
            or head.previous_compiled_digest is not None):
        raise D12SchemeHold(
            "adopted D07 control policy reader is unavailable")
    fields = ((ATTENTION_POLICY_FIELD, draft.fields[ATTENTION_POLICY_FIELD],
               draft.field_sources[ATTENTION_POLICY_FIELD]),)
    candidate = compile_d12_domain_scheme_candidate_v1(
        namespace=namespace, draft_digest=compiled.draft_digest,
        domain="d07", fields=fields,
        field_input_digest=canonical_digest((compiled.draft_digest, "d07", fields)),
    )
    if (type(candidate) is not D12AttentionPolicyCandidateV1
            or not verify_d12_domain_candidate_v1(
                db, namespace, candidate, receipt)):
        raise D12SchemeHold("persisted D07 candidate differs from current draft")
    # The live D07 post-C02 driver currently consumes AttentionPolicy.default().
    # Adoption must replace that consumer before a non-default active policy can
    # be used as a preview baseline.
    baseline = AttentionPolicy.default()
    spec = D12BehaviorExperimentSpecV1(
        namespace, operation_id, compiled_digest,
        canonical_digest(asdict(baseline)), candidate.candidate_digest,
        (ATTENTION_POLICY_FIELD,),
    )
    plan_digest = canonical_digest({
        "schema": "d12.current-d07-preview-plan.v1",
        "compilation_operation_id": original.operation_id,
        "compilation_source_digest": original.source_input_digest,
        "spec": spec, "draft_revision": draft_row[0],
        "head_revision": head_row[0], "head_digest": canonical_digest(head),
        "graph_revision": graph_revision,
        "access_epoch": access_epoch, "delete_epoch": delete_epoch,
    })
    return D12CurrentPreviewPlanV1(
        original, spec, baseline, candidate, graph_revision,
        access_epoch, delete_epoch, plan_digest,
    )


__all__ = ("D12CurrentPreviewPlanV1", "read_current_d12_preview_plan_v1")
