"""Mechanical review of language-v2 natural expression, before semantic review.

This module does not infer semantic faithfulness from character coverage. A
current Authority-paid generation and independent paid review are required by
the coordinator before any candidate may be adopted or sent.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import access_key
from ...runtime_contracts import (
    NamespaceId, NaturalReplyPaidReviewReceiptV2, VersionedRef,
    canonical_digest,
)
from . import ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate, segment_payload_digest
from .expression_policy import (
    DEFAULT_MAX_VISIBLE_CHARS_V1, D09ExpressionPolicyV1,
)


NATURAL_REPLY_OUTPUT_SCHEMA_V2 = "sylanne.d09.context_reply_output.v2"
_UNSCOPED_COMMITMENT_CUE = re.compile(
    r"(?:\bI\s+(?:will|promise\s+to|guarantee\b)|\bI'll\b|"
    r"(?:我|我们)(?:会|将|一定|保证))", re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class QualifiedExpressionUnitV2:
    basis_id: str
    kind: ClaimKind
    qualified_text: str
    qualification_ref: VersionedRef | None
    source_refs: tuple[VersionedRef, ...]
    access_refs: tuple[VersionedRef, ...]
    correction_refs: tuple[VersionedRef, ...]
    audience_ref: str
    purpose: str
    expires_at_utc: float
    direct_quote: bool = False
    speaker_id: str | None = None
    content_reality: str | None = None
    stance: str | None = None
    uncertainty: str | None = None
    self_description_hypotheses: tuple[str, ...] = ()
    semantic_constraints: tuple[str, ...] = ()
    qualification_digest: str | None = None
    occurred_at: float | None = None
    learned_at: float | None = None
    source_kind: str | None = None
    assertion_status: str | None = None
    d06_claim_kind: str | None = None
    attribution_required: bool | None = None
    polarity_status: str | None = None
    source_excerpt: str | None = None
    evidence_span: tuple[int, int] | None = None
    direct_quote_span: tuple[int, int] | None = None
    negation_cue_span: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class NaturalExpressionPlanV2:
    namespace: NamespaceId
    plan_ref: VersionedRef
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    required_slots: tuple[str, ...]
    allowed_speech_acts: tuple[str, ...]
    promise_grants: tuple[VersionedRef, ...]
    units: tuple[QualifiedExpressionUnitV2, ...]
    valid_until_utc: float
    final_activity_id: str
    final_operation_id: str
    final_effect_id: str
    scene_id: str
    audience_id: str


@dataclass(frozen=True, slots=True)
class NaturalMechanicalCandidateV2:
    status: str
    claims: tuple[ExpressionClaim, ...]
    segment: SegmentCandidate | None
    output_digest: str | None
    payload_digest: str | None
    source_refs: tuple[str, ...]
    missing: tuple[str, ...]
    qualified_units_digest: str | None = None


def mechanically_verify_natural_reply_v2(
    output: dict, *, plan: NaturalExpressionPlanV2,
    current_reads: tuple[GraphVersion, ...], now_utc: float,
    expression_policy: D09ExpressionPolicyV1 | None = None,
) -> NaturalMechanicalCandidateV2:
    """Check structure, current qualified references and finite visible units.

    ``current_reads`` must be supplied by W01's current authoritative read;
    this pure candidate is never evidence that the read was authenticated.
    """

    def hold(reason: str) -> NaturalMechanicalCandidateV2:
        return NaturalMechanicalCandidateV2("hold", (), None, None, None, (), (reason,))

    if type(plan) is not NaturalExpressionPlanV2 or type(current_reads) is not tuple:
        raise TypeError("typed natural plan and read set required")
    if expression_policy is not None and type(expression_policy) is not D09ExpressionPolicyV1:
        raise TypeError("typed D09 expression policy required")
    if type(output) is not dict or set(output) != {"schema", "body", "units"}:
        return hold("output_schema")
    body, units = output.get("body"), output.get("units")
    if (output["schema"] != NATURAL_REPLY_OUTPUT_SCHEMA_V2
            or type(body) is not str or not 0 < len(body) <= DEFAULT_MAX_VISIBLE_CHARS_V1
            or type(units) is not list or not 0 < len(units) <= 16
            or any(ord(char) < 32 and char not in "\n\t" for char in body)):
        return hold("output_bounds")
    if expression_policy is not None and len(body) > expression_policy.max_visible_chars:
        return hold("expression_policy_max_visible_chars")
    # This narrow cue catches a model hiding a future commitment under
    # paraphrase/rhetoric. The independent review and D08 checks remain the
    # semantic authority for expressions outside this finite cue set.
    if _UNSCOPED_COMMITMENT_CUE.search(body):
        return hold("possible_unscoped_commitment")
    if (now_utc >= plan.valid_until_utc or not plan.units
            or not plan.final_activity_id or not plan.final_operation_id
            or not plan.final_effect_id or not plan.scene_id
            or not plan.audience_id):
        return hold("plan_expired_or_empty")
    read_map = {row.key.token: row.revision for row in current_reads}
    if len(read_map) != len(current_reads):
        return hold("duplicate_current_read")
    plan_refs = (plan.plan_ref, plan.scene_ref, plan.audience_ref, *plan.promise_grants)
    if any(read_map.get(ref.ref) != ref.version for ref in plan_refs):
        return hold("current_plan_or_grant_changed")
    basis = {unit.basis_id: unit for unit in plan.units}
    if len(basis) != len(plan.units):
        return hold("duplicate_basis")
    claims: list[ExpressionClaim] = []
    uses: list[ClaimUse] = []
    source_refs: set[str] = set()
    covered_slots: set[str] = set()
    cursor = 0
    output_digest = canonical_digest(output)
    for index, item in enumerate(units):
        if type(item) is not dict or set(item) != {
            "start", "end", "kind", "basis_ids", "speech_act",
            "promise_grant_id", "slot_ids",
        }:
            return hold("unit_schema")
        start, end = item["start"], item["end"]
        if (type(start) is not int or type(end) is not int
                or not cursor <= start < end <= len(body) or body[cursor:start].strip()):
            return hold("unit_coverage")
        kind, act = item["kind"], item["speech_act"]
        ids, slots = item["basis_ids"], item["slot_ids"]
        if (type(ids) is not list or not ids
                or any(type(i) is not str or i not in basis for i in ids)
                or len(ids) != len(set(ids))
                or type(slots) is not list
                or any(type(slot) is not str or slot not in plan.required_slots for slot in slots)
                or len(slots) != len(set(slots))
                or type(kind) is not str or kind not in {member.value for member in ClaimKind}
                or type(act) is not str or act not in plan.allowed_speech_acts):
            return hold("unit_scope")
        selected = tuple(basis[i] for i in ids)
        if any(unit.kind.value != kind or unit.audience_ref != plan.audience_id
               or unit.purpose != "expression" or now_utc >= unit.expires_at_utc
               for unit in selected):
            return hold("basis_scope_or_expiry")
        for unit in selected:
            if (unit.qualification_ref is None and
                    (type(unit.qualification_digest) is not str
                     or len(unit.qualification_digest) != 64)):
                return hold("qualification_identity_missing")
            if (unit.kind in {ClaimKind.EXTERNAL_FACT, ClaimKind.REPORTED_CLAIM}
                    and (not unit.speaker_id or not unit.content_reality)):
                return hold("speaker_or_reality_qualifier_missing")
            if unit.kind in {ClaimKind.EXTERNAL_FACT, ClaimKind.REPORTED_CLAIM}:
                span = unit.evidence_span
                if (not unit.source_kind or not unit.assertion_status
                        or not unit.source_excerpt or type(span) is not tuple
                        or len(span) != 2 or type(span[0]) is not int
                        or type(span[1]) is not int
                        or not 0 <= span[0] < span[1]
                        or span[1] - span[0] != len(unit.source_excerpt)
                        or type(unit.attribution_required) is not bool):
                    return hold("d06_qualifier_incomplete")
            if (unit.kind is ClaimKind.EXTERNAL_FACT
                    and unit.d06_claim_kind != "confirmed_external_fact"):
                return hold("reported_source_cannot_be_external_fact")
            if (unit.kind is ClaimKind.REPORTED_CLAIM
                    and unit.d06_claim_kind != "attributed_report"):
                return hold("reported_source_qualification_missing")
            if (unit.kind is ClaimKind.SUBJECTIVE_JUDGMENT
                    and (not unit.stance or not unit.uncertainty)):
                return hold("judgment_qualifier_missing")
            if (unit.kind is ClaimKind.SELF_UNDERSTANDING
                    and (not unit.self_description_hypotheses
                         or unit.uncertainty != "tentative_self_interpretation")):
                return hold("self_understanding_qualifier_missing")
        if act == "direct_quote" and (len(selected) != 1
                                      or body[start:end] != selected[0].qualified_text
                                      or not selected[0].direct_quote):
            return hold("quote_mismatch")
        if act == "direct_quote" and selected[0].direct_quote_span is not None:
            quote_span = selected[0].direct_quote_span
            excerpt = selected[0].source_excerpt
            evidence = selected[0].evidence_span
            if (excerpt is None or evidence is None or len(quote_span) != 2
                    or not evidence[0] <= quote_span[0] < quote_span[1] <= evidence[1]
                    or excerpt[quote_span[0] - evidence[0]:quote_span[1] - evidence[0]]
                    != body[start:end]):
                return hold("quote_source_span_mismatch")
        promise_ref = item["promise_grant_id"]
        if act == "promise":
            return hold("promise_scope_unavailable")
        elif promise_ref is not None:
            return hold("unrequested_promise_grant")
        refs = tuple(dict.fromkeys(ref for unit in selected for ref in (
            *((unit.qualification_ref,) if unit.qualification_ref is not None else ()),
            *unit.source_refs, *unit.access_refs,
            *unit.correction_refs,
        )))
        if any(read_map.get(ref.ref) != ref.version for ref in refs):
            return hold("qualified_source_changed")
        for unit in selected:
            if (unit.kind not in {ClaimKind.RHETORIC, ClaimKind.SELF_UNDERSTANDING,
                                  ClaimKind.INTERNAL_ACTIVITY, ClaimKind.SIMULATED}
                    and not unit.source_refs):
                return hold("qualified_source_missing")
            for ref in unit.source_refs:
                try:
                    key = AtomKey.from_token(ref.ref)
                except (TypeError, ValueError):
                    return hold("source_ref_invalid")
                if (key.type_name != "memory.source" or key.owner.kind != "event"
                        or (key.owner.bot, key.owner.persona) != plan.namespace.as_tuple):
                    return hold("source_ref_invalid")
                from ..d06 import source_correction_head_key

                subject = key.owner.subject
                if (subject is None
                        or access_key(*plan.namespace.as_tuple, subject).token
                        not in {item.ref for item in unit.access_refs}
                        or source_correction_head_key(plan.namespace, subject).token
                        not in {item.ref for item in unit.correction_refs}):
                    return hold("source_access_correction_closure")
                source_refs.add(ref.ref)
        phrase = body[start:end]
        claim_id = "natural-unit:" + canonical_digest({
            "output": output_digest, "index": index, "basis": ids,
        })
        claims.append(ExpressionClaim(
            claim_id, phrase, ClaimKind(kind), tuple(sorted({
                ref.ref for unit in selected for ref in unit.source_refs
            } or {
                unit.qualification_ref.ref for unit in selected
                if unit.kind is not ClaimKind.RHETORIC and unit.qualification_ref is not None
            })), (plan.audience_id,), ("expression",), selected[0].basis_id,
        ))
        uses.append(ClaimUse(claim_id, start, end, ClaimKind(kind)))
        covered_slots.update(slots)
        cursor = end
    if body[cursor:].strip() or not set(plan.required_slots).issubset(covered_slots):
        return hold("unmapped_text_or_required_slot")
    segment_id = "segment:" + canonical_digest({
        "plan": plan.plan_ref, "output": output_digest,
    })
    segment = SegmentCandidate(
        segment_id, plan.final_effect_id,
        body, tuple(uses), tuple(sorted(covered_slots)), (), 0.0,
    )
    return NaturalMechanicalCandidateV2(
        "mechanical_verified_semantic_hold", tuple(claims), segment,
        output_digest, segment_payload_digest(body, (), tuple(uses)),
        tuple(sorted(source_refs)), (
            "current_qualification_recompute", "independent_paid_semantic_review",
        ), canonical_digest(plan.units),
    )


def verify_current_qualified_natural_reply_v2(
    output: dict, *, plan: NaturalExpressionPlanV2,
    current_snapshot: GraphSnapshot,
    d06_candidates: tuple[object, ...],
    current_reads: tuple[GraphVersion, ...],
    access_epoch: int, deletion_epoch: int, now_utc: float,
    expression_policy: D09ExpressionPolicyV1 | None = None,
) -> NaturalMechanicalCandidateV2:
    """Recompute every D06 candidate under W01's authenticated current read.

    A D06 candidate is a digest-bound projection, not a graph qualification
    head. W01 still owns the read fence and all cross-domain adoption.
    """
    from ..d06.qualified_expression import (
        QualifiedExpressionUnitCandidate, recompute_qualified_expression_unit,
    )

    def hold(reason: str) -> NaturalMechanicalCandidateV2:
        return NaturalMechanicalCandidateV2("hold", (), None, None, None, (), (reason,))

    if (type(current_snapshot) is not GraphSnapshot
            or type(d06_candidates) is not tuple
            or any(type(item) is not QualifiedExpressionUnitCandidate
                   for item in d06_candidates)):
        return hold("typed_current_d06_read_required")
    current = mechanically_verify_natural_reply_v2(
        output, plan=plan, current_reads=current_reads, now_utc=now_utc,
        expression_policy=expression_policy,
    )
    if current.status != "mechanical_verified_semantic_hold":
        return current
    candidates = {item.qualification_digest: item for item in d06_candidates}
    used = {unit.qualification_digest for unit in plan.units
            if unit.d06_claim_kind is not None}
    if (len(candidates) != len(d06_candidates) or None in used
            or set(candidates) != used):
        return hold("d06_qualification_set_incomplete")
    read_map = {row.key: row.revision for row in current_reads}
    snapshot_map = {atom.key: atom for atom in current_snapshot.atoms}
    if (len(read_map) != len(current_reads)
            or any(key not in snapshot_map
                   or snapshot_map[key].revision != revision
                   or snapshot_map[key].valid != (revision > 0)
                   for key, revision in read_map.items())):
        return hold("current_snapshot_read_set_changed")
    for unit in plan.units:
        if unit.d06_claim_kind is None:
            continue
        candidate = candidates[unit.qualification_digest]
        try:
            rebuilt = recompute_qualified_expression_unit(
                current_snapshot, namespace=plan.namespace,
                candidate=candidate, audiences=(plan.audience_id,),
                access_epoch=access_epoch, deletion_epoch=deletion_epoch,
                now=now_utc,
            )
        except (ValueError, TypeError, PermissionError):
            return hold("d06_qualification_recompute_failed")
        source_rows = {row.key.token: row.revision
                       for row in rebuilt.read_versions}
        if any(read_map.get(row.key) != row.revision for row in rebuilt.read_versions):
            return hold("d06_ancestor_read_set_incomplete")
        source_refs = tuple(VersionedRef(ref, source_rows[ref])
                            for ref in rebuilt.lineage_source_refs)
        access_refs = tuple(VersionedRef(row.key.token, row.revision)
                            for row in rebuilt.read_versions
                            if row.key.type_name == "memory.access")
        correction_refs = tuple(VersionedRef(row.key.token, row.revision)
                                for row in rebuilt.read_versions
                                if row.key.type_name == "d06.source_correction_head.v1")
        # Exact projection match prevents a caller rewriting speaker, negation,
        # privacy, qualifier, or any ancestor lineage under the same digest.
        if (unit.kind.value != ("reported_claim" if rebuilt.claim_kind == "attributed_report"
                                else "external_fact")
                or unit.d06_claim_kind != rebuilt.claim_kind
                or unit.qualification_ref is not None
                or unit.qualification_digest != rebuilt.qualification_digest
                or unit.expires_at_utc > rebuilt.valid_until
                or unit.content_reality != (
                    "external_report" if rebuilt.claim_kind == "attributed_report"
                    else "external_observation")
                or unit.source_refs != source_refs
                or set(unit.access_refs) != set(access_refs)
                or set(unit.correction_refs) != set(correction_refs)
                or unit.speaker_id != rebuilt.speaker_id
                or unit.occurred_at != rebuilt.occurred_at
                or unit.learned_at != rebuilt.learned_at
                or unit.source_kind != rebuilt.source_kind
                or unit.assertion_status != rebuilt.assertion_status
                or unit.attribution_required != rebuilt.attribution_required
                or unit.polarity_status != rebuilt.polarity_status
                or unit.source_excerpt != rebuilt.source_excerpt
                or unit.evidence_span != (rebuilt.evidence_span.start, rebuilt.evidence_span.end)
                or unit.direct_quote_span != (
                    (rebuilt.direct_quote_span.start, rebuilt.direct_quote_span.end)
                    if rebuilt.direct_quote_span is not None else None)
                or unit.negation_cue_span != (
                    (rebuilt.negation_cue_span.start, rebuilt.negation_cue_span.end)
                    if rebuilt.negation_cue_span is not None else None)
                or unit.qualified_text != (
                    rebuilt.direct_quote_text if unit.direct_quote else rebuilt.source_excerpt)):
            return hold("d06_qualified_projection_changed")
    return NaturalMechanicalCandidateV2(
        "current_qualification_verified_semantic_hold", current.claims,
        current.segment, current.output_digest, current.payload_digest,
        current.source_refs, ("independent_paid_semantic_review",),
        current.qualified_units_digest,
    )


@dataclass(frozen=True, slots=True)
class NaturalReviewCandidateV2:
    status: str
    generation_output_digest: str | None
    review_output_digest: str | None
    review_policy_version: str | None
    missing: tuple[str, ...]


def assess_untrusted_natural_review_v2(
    mechanical: NaturalMechanicalCandidateV2,
    frozen_review: object, review_output: object,
) -> NaturalReviewCandidateV2:
    """Bind W15's parsed review candidate; never promote it to Authority pass."""
    from ...model_broker.natural_review import (
        FrozenNaturalReplyReviewV1, UntrustedNaturalReplyReviewOutputV1,
    )

    def hold(reason: str) -> NaturalReviewCandidateV2:
        return NaturalReviewCandidateV2("hold", None, None, None, (reason,))

    if (type(mechanical) is not NaturalMechanicalCandidateV2
            or mechanical.status != "current_qualification_verified_semantic_hold"
            or type(frozen_review) is not FrozenNaturalReplyReviewV1
            or type(review_output) is not UntrustedNaturalReplyReviewOutputV1):
        return hold("current_mechanical_and_typed_review_required")
    if (frozen_review.generation_output_digest != mechanical.output_digest
            or frozen_review.qualified_units_digest != mechanical.qualified_units_digest
            or review_output.generation_output_digest != mechanical.output_digest
            or review_output.generation_frozen_input_digest
            != frozen_review.generation_frozen_input_digest
            or review_output.review_frozen_input_digest != frozen_review.digest):
        return hold("review_bound_to_old_generation_or_basis")
    if any(unit.speech_act == "promise" for unit in frozen_review.units):
        return hold("promise_scope_unavailable")
    if review_output.verdict != "pass" or review_output.issues:
        return hold("semantic_review_did_not_pass")
    return NaturalReviewCandidateV2(
        "untrusted_semantic_pass_authority_hold", mechanical.output_digest,
        review_output.output_digest, frozen_review.review_policy_version,
        ("paid_review_authority_receipt", "current_cross_domain_adoption"),
    )


class NaturalPaidReviewVerifierV2(Protocol):
    """W01-installed Authority adapter; a caller's receipt has no authority."""

    def verify_current_paid_review_v2(
        self, receipt: NaturalReplyPaidReviewReceiptV2, *,
        plan: NaturalExpressionPlanV2, adopted: object,
        generation_output: dict, current_reads: tuple[GraphVersion, ...],
        now_utc: float,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class NaturalFinalActionMaterialV2:
    final_activity_id: str
    final_operation_id: str
    final_effect_id: str
    c02_operation_id: str
    source_ref: VersionedRef
    scene_id: str
    audience_id: str
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    focus_ref: VersionedRef
    ticket_ref: VersionedRef
    route_binding_digest: str
    required_slots: tuple[str, ...]
    allowed_speech_acts: tuple[str, ...]
    qualified_units_digest: str
    claims: tuple[ExpressionClaim, ...]
    segment: SegmentCandidate
    payload_digest: str
    current_reads: tuple[GraphVersion, ...]
    paid_receipt: NaturalReplyPaidReviewReceiptV2


@dataclass(frozen=True, slots=True)
class NaturalFinalActionCandidateV2:
    status: str
    material: NaturalFinalActionMaterialV2 | None
    missing: tuple[str, ...]


def prepare_natural_final_action_candidate_v2(
    *, plan: NaturalExpressionPlanV2, adopted: object,
    generation_output: dict, review: NaturalReviewCandidateV2,
    paid_receipt: NaturalReplyPaidReviewReceiptV2,
    current_snapshot: GraphSnapshot, d06_candidates: tuple[object, ...],
    current_reads: tuple[GraphVersion, ...], access_epoch: int,
    deletion_epoch: int, now_utc: float,
    paid_verifier: NaturalPaidReviewVerifierV2 | None,
    expression_policy: D09ExpressionPolicyV1 | None = None,
) -> NaturalFinalActionCandidateV2:
    """Produce final-transaction material; W01 alone may issue action/grant."""
    from ..d08.natural_plan import AdoptedNaturalPlanV2, NATURAL_PLAN_TYPE_V2

    def hold(reason: str) -> NaturalFinalActionCandidateV2:
        return NaturalFinalActionCandidateV2("hold", None, (reason,))

    if (type(plan) is not NaturalExpressionPlanV2
            or type(adopted) is not AdoptedNaturalPlanV2
            or type(review) is not NaturalReviewCandidateV2
            or type(paid_receipt) is not NaturalReplyPaidReviewReceiptV2
            or type(current_reads) is not tuple):
        return hold("typed_current_final_material_required")
    if paid_verifier is None:
        return hold("authority_paid_receipt_required_hold")
    mechanical = verify_current_qualified_natural_reply_v2(
        generation_output, plan=plan, current_snapshot=current_snapshot,
        d06_candidates=d06_candidates, current_reads=current_reads,
        access_epoch=access_epoch, deletion_epoch=deletion_epoch,
        now_utc=now_utc, expression_policy=expression_policy,
    )
    if (mechanical.status != "current_qualification_verified_semantic_hold"
            or mechanical.segment is None or mechanical.payload_digest is None
            or mechanical.output_digest != canonical_digest(generation_output)
            or mechanical.segment.effect_id != plan.final_effect_id):
        return hold("current_generation_mechanical_hold")
    if (adopted.schema != NATURAL_PLAN_TYPE_V2
            or adopted.status != "scope_adopted_payload_pending"
            or AtomKey.from_token(plan.plan_ref.ref).type_name != NATURAL_PLAN_TYPE_V2
            or adopted.plan_id != AtomKey.from_token(plan.plan_ref.ref).name
            or adopted.final_activity_id != plan.final_activity_id
            or adopted.final_operation_id != plan.final_operation_id
            or adopted.final_effect_id != plan.final_effect_id
            or adopted.scene_id != plan.scene_id
            or adopted.audience_id != plan.audience_id
            or adopted.scene_ref != plan.scene_ref
            or adopted.audience_ref != plan.audience_ref
            or adopted.required_slots != plan.required_slots
            or adopted.allowed_speech_acts != plan.allowed_speech_acts
            or adopted.promise_grants != plan.promise_grants
            or adopted.qualified_units_digest != mechanical.qualified_units_digest
            or adopted.valid_until_utc != plan.valid_until_utc
            or GraphVersion(AtomKey.from_token(plan.plan_ref.ref),
                            plan.plan_ref.version) not in current_reads
            or any(row not in current_reads
                   for row in adopted.qualified_read_versions)):
        return hold("adopted_scope_or_read_closure_changed")
    paid = paid_receipt
    if (paid.namespace != plan.namespace or paid.verdict != "pass"
            or paid.parent_budget_lease_id != adopted.parent_budget_lease_id
            or paid.generation_reservation_operation_id
               != adopted.generation_reservation_id
            or paid.review_reservation_operation_id
               != adopted.review_reservation_id
            or paid.qualified_units_digest != adopted.qualified_units_digest
            or paid.generation_output_digest != mechanical.output_digest
            or review.status != "untrusted_semantic_pass_authority_hold"
            or review.generation_output_digest != mechanical.output_digest
            or review.review_output_digest != paid.review_output_digest
            or review.review_policy_version != paid.review_policy_version):
        return hold("paid_review_or_original_terminal_mismatch")
    try:
        verified = paid_verifier.verify_current_paid_review_v2(
            paid, plan=plan, adopted=adopted,
            generation_output=generation_output,
            current_reads=current_reads, now_utc=now_utc,
        )
    except Exception:
        return hold("authority_paid_receipt_verification_failed")
    if verified is not True:
        return hold("authority_paid_receipt_required_hold")
    material = NaturalFinalActionMaterialV2(
        plan.final_activity_id, plan.final_operation_id, plan.final_effect_id,
        adopted.c02_operation_id, adopted.source_ref,
        plan.scene_id, plan.audience_id, plan.scene_ref, plan.audience_ref,
        adopted.focus_ref, adopted.ticket_ref, adopted.route_binding_digest,
        plan.required_slots, plan.allowed_speech_acts,
        adopted.qualified_units_digest, mechanical.claims,
        mechanical.segment, mechanical.payload_digest, current_reads, paid,
    )
    return NaturalFinalActionCandidateV2(
        "candidate_hold_w01_final_admission", material,
        ("w01_final_checks", "payload_bound_communication_grant", "d11_admission"),
    )


__all__ = [
    "NATURAL_REPLY_OUTPUT_SCHEMA_V2", "QualifiedExpressionUnitV2",
    "NaturalExpressionPlanV2", "NaturalMechanicalCandidateV2",
    "mechanically_verify_natural_reply_v2",
    "verify_current_qualified_natural_reply_v2",
    "NaturalReviewCandidateV2", "assess_untrusted_natural_review_v2",
    "NaturalPaidReviewVerifierV2", "NaturalFinalActionMaterialV2",
    "NaturalFinalActionCandidateV2", "prepare_natural_final_action_candidate_v2",
]
