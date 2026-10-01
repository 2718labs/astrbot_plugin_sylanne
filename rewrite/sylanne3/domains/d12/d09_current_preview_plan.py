"""Read one current D09-only D12 preview input inside W01's graph fence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import sqlite3

from ...runtime.d12_compiled_candidate_store_v1 import verify_d12_domain_candidate_v1
from ...runtime.d12_current_d07_policy_v1 import read_current_d07_attention_policy_v1
from ...runtime.d12_current_d09_policy_v1 import read_current_d09_expression_policy_v1
from ...runtime.d12_domain_scheme_compile_v1 import (
    D12ExpressionPolicyCandidateV1, EXPRESSION_POLICY_FIELD,
    compile_d12_domain_scheme_candidate_v1,
)
from ...runtime.scheme_original_store_v1 import (
    CompilationOriginalV1, read_compilation_original_for_operation_v1,
)
from ...runtime_contracts import NamespaceId, canonical_digest
from ..d09 import D09ExpressionPolicyV1
from .d09_preview import D12D09PreviewSpecV1, d09_preview_control_digest_v1
from .scheme_command import D12SchemeHold
from .types import (
    ActiveSchemeHeadV1, CharacterDraft, active_scheme_head_key,
    character_draft_key,
)


@dataclass(frozen=True, slots=True)
class D12CurrentD09PreviewPlanV1:
    original: CompilationOriginalV1
    spec: D12D09PreviewSpecV1
    baseline: D09ExpressionPolicyV1 | None
    candidate: D12ExpressionPolicyCandidateV1
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    plan_digest: str


def read_current_d09_preview_plan_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *,
    operation_id: str, compiled_digest: str, graph_revision: int,
    access_epoch: int, delete_epoch: int,
) -> D12CurrentD09PreviewPlanV1:
    """Bind complete current D09 draft, candidate and independent active control."""
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
        raise D12SchemeHold("compiled scheme is not current D09-only input")
    receipt = compiled.domain_receipts[0]
    if (receipt.domain != "d09"
            or receipt.field_names != (EXPRESSION_POLICY_FIELD,)):
        raise D12SchemeHold("mixed or unsupported D09 preview scheme")
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
            or set(draft.fields) != {EXPRESSION_POLICY_FIELD}
            or set(draft.field_sources) != {EXPRESSION_POLICY_FIELD}):
        raise D12SchemeHold("current scheme draft is not compiled D09 input")

    # A head carries one scheme. The other domain remains at its independent
    # default only when its authenticated prior state was initial.
    if head.adoption_kind == "initial":
        if head.generation != 1 or head.previous_compiled_digest is not None:
            raise D12SchemeHold("initial scheme head differs")
        baseline = None
    elif head.adoption_kind == "administrative_edit":
        active = read_compilation_original_for_operation_v1(
            db, namespace, compiled_digest=head.compiled_digest)
        if active is None or len(active.compiled.domain_receipts) != 1:
            raise D12SchemeHold("active scheme original unavailable")
        active_receipt = active.compiled.domain_receipts[0]
        if active_receipt.domain == "d07":
            if head.generation != 2:
                raise D12SchemeHold("inherited D09 control history is unavailable")
            try:
                d07 = read_current_d07_attention_policy_v1(db, namespace)
            except ValueError as exc:
                raise D12SchemeHold("active D07 control differs") from exc
            if d07.active_head_ref.revision != head.generation:
                raise D12SchemeHold("active D07 head differs")
            baseline = None
        elif active_receipt.domain == "d09":
            try:
                d09 = read_current_d09_expression_policy_v1(db, namespace)
            except ValueError as exc:
                raise D12SchemeHold("active D09 control differs") from exc
            if d09.active_head_ref.revision != head.generation or d09.policy is None:
                raise D12SchemeHold("active D09 head differs")
            baseline = d09.policy
        else:
            raise D12SchemeHold("active domain control is unavailable")
    else:
        raise D12SchemeHold("active domain control is unavailable")

    fields = ((EXPRESSION_POLICY_FIELD, draft.fields[EXPRESSION_POLICY_FIELD],
               draft.field_sources[EXPRESSION_POLICY_FIELD]),)
    candidate = compile_d12_domain_scheme_candidate_v1(
        namespace=namespace, draft_digest=compiled.draft_digest,
        domain="d09", fields=fields,
        field_input_digest=canonical_digest((compiled.draft_digest, "d09", fields)),
    )
    if (type(candidate) is not D12ExpressionPolicyCandidateV1
            or not verify_d12_domain_candidate_v1(
                db, namespace, candidate, receipt)):
        raise D12SchemeHold("persisted D09 candidate differs from current draft")
    spec = D12D09PreviewSpecV1(
        namespace, operation_id, compiled_digest,
        d09_preview_control_digest_v1(baseline), candidate.candidate_digest,
        (EXPRESSION_POLICY_FIELD,),
    )
    plan_digest = canonical_digest({
        "schema": "d12.current-d09-preview-plan.v1",
        "compilation_operation_id": original.operation_id,
        "compilation_source_digest": original.source_input_digest,
        "spec": spec, "draft_revision": draft_row[0],
        "head_revision": head_row[0], "head_digest": canonical_digest(head),
        "baseline": asdict(baseline) if baseline is not None else None,
        "graph_revision": graph_revision,
        "access_epoch": access_epoch, "delete_epoch": delete_epoch,
    })
    return D12CurrentD09PreviewPlanV1(
        original, spec, baseline, candidate, graph_revision,
        access_epoch, delete_epoch, plan_digest,
    )


__all__ = ("D12CurrentD09PreviewPlanV1", "read_current_d09_preview_plan_v1")
