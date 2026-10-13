"""Adopted pre-generation expression scope, before any visible payload exists."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize


NATURAL_PLAN_TYPE_V2 = "d08.natural_expression_plan.v2"


def natural_plan_id_v2(
    namespace: NamespaceId, c02_operation_id: str, source_ref: str,
) -> str:
    return "natural-plan:" + canonical_digest({
        "schema": NATURAL_PLAN_TYPE_V2, "namespace": namespace,
        "c02_operation_id": c02_operation_id, "source_ref": source_ref,
    })[:48]


def natural_final_effect_id_v2(
    namespace: NamespaceId, c02_operation_id: str, source_ref: str,
) -> str:
    if (type(namespace) is not NamespaceId or not c02_operation_id
            or not source_ref):
        raise ValueError("natural final effect identity is incomplete")
    return "effect:" + canonical_digest({
        "schema": "sylanne.d09.natural-send-effect.v2",
        "namespace": namespace, "c02_operation_id": c02_operation_id,
        "source_ref": source_ref,
    })[:48]


def natural_route_semantic_digest_v2(route_binding: object) -> str:
    """Stable route identity; W01 rechecks the live negative scan separately."""
    from ...runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2

    if type(route_binding) is not CurrentReplyEntityRouteBindingV2:
        raise TypeError("typed current reply route binding required")
    route = route_binding
    return canonical_digest({
        "schema": "sylanne.d08.natural-route-semantic.v2",
        "namespace": route.namespace,
        "c02_operation_id": route.c02_operation_id,
        "source_ref": route.source_ref,
        "platform_ref": route.platform_ref,
        "sender_ref": route.sender_ref,
        "conversation_ref": route.conversation_ref,
        "scene_ref": route.scene_ref,
        "target_entity_ref": route.target_entity_ref,
        "account_id": route.account_id,
        "anchor_version": route.anchor_version,
        "binding_version": route.binding_version,
        "arrival_event_version": route.arrival_event_version,
        "binding_evidence_event_version": route.binding_evidence_event_version,
        "source_version": route.source_version,
        "access_version": route.access_version,
        "valid_until_utc": route.valid_until_utc,
    })


def natural_plan_key_v2(
    namespace: NamespaceId, activity_id: str, plan_id: str,
) -> AtomKey:
    if type(namespace) is not NamespaceId or not activity_id or not plan_id:
        raise ValueError("natural plan namespace/activity/identity required")
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id),
                   NATURAL_PLAN_TYPE_V2, plan_id)


@dataclass(frozen=True, slots=True)
class AdoptedNaturalPlanV2:
    schema: str
    plan_id: str
    c02_operation_id: str
    source_ref: VersionedRef
    final_activity_id: str
    final_operation_id: str
    final_effect_id: str
    focus_ref: VersionedRef
    ticket_ref: VersionedRef
    preparation_evidence_digest: str
    route_binding_digest: str
    parent_budget_lease_id: str
    budget_grant_version: int
    budget_grant_digest: str
    generation_reservation_id: str
    review_reservation_id: str
    generation_ceiling: tuple[tuple[str, int], ...]
    review_ceiling: tuple[tuple[str, int], ...]
    scene_id: str
    audience_id: str
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    required_slots: tuple[str, ...]
    allowed_speech_acts: tuple[str, ...]
    promise_grants: tuple[VersionedRef, ...]
    qualified_units_digest: str
    d06_qualification_digests: tuple[str, ...]
    qualification_refs: tuple[VersionedRef, ...]
    qualified_read_versions: tuple[GraphVersion, ...]
    valid_until_utc: float
    status: str = "scope_adopted_payload_pending"
    version: int = 1

    def __post_init__(self) -> None:
        if (self.schema != NATURAL_PLAN_TYPE_V2 or self.version != 1
                or self.status != "scope_adopted_payload_pending"
                or not self.plan_id or not self.c02_operation_id
                or not self.final_activity_id or not self.final_operation_id
                or not self.final_effect_id or not self.scene_id
                or not self.audience_id
                or type(self.source_ref) is not VersionedRef
                or type(self.focus_ref) is not VersionedRef
                or type(self.ticket_ref) is not VersionedRef
                or type(self.scene_ref) is not VersionedRef
                or type(self.audience_ref) is not VersionedRef
                or any(type(ref) is not VersionedRef for ref in self.promise_grants)
                or type(self.qualified_read_versions) is not tuple
                or any(type(ref) is not GraphVersion for ref in self.qualified_read_versions)
                or not self.qualified_read_versions
                or not self.allowed_speech_acts
                or any(type(item) is not str or not item for item in self.required_slots
                       + self.allowed_speech_acts)
                or len(set(self.required_slots)) != len(self.required_slots)
                or len(set(self.allowed_speech_acts)) != len(self.allowed_speech_acts)
                or not 0 < self.valid_until_utc):
            raise ValueError("natural plan scope is invalid")
        if (self.budget_grant_version < 1
                or not self.parent_budget_lease_id
                or not self.generation_reservation_id
                or not self.review_reservation_id
                or self.generation_reservation_id == self.review_reservation_id
                or any(not ceiling or tuple(sorted(ceiling)) != ceiling
                       or any(type(name) is not str or not name
                              or type(amount) is not int or amount <= 0
                              for name, amount in ceiling)
                       for ceiling in (self.generation_ceiling, self.review_ceiling))):
            raise ValueError("natural plan budget scope is invalid")
        for name in ("preparation_evidence_digest", "budget_grant_digest",
                     "route_binding_digest", "qualified_units_digest"):
            value = getattr(self, name)
            if (type(value) is not str or len(value) != 64
                    or any(ch not in "0123456789abcdef" for ch in value)):
                raise ValueError(f"{name} must be a SHA-256 digest")
        if (len(set(self.d06_qualification_digests)) != len(self.d06_qualification_digests)
                or any(type(item) is not str or len(item) != 64
                       for item in self.d06_qualification_digests)
                or len(set(self.qualification_refs)) != len(self.qualification_refs)
                or len({row.key for row in self.qualified_read_versions})
                != len(self.qualified_read_versions)):
            raise ValueError("natural plan qualification closure repeats an identity")


def decode_natural_plan_v2(value: dict) -> AdoptedNaturalPlanV2:
    if type(value) is not dict or set(value) != {field.name for field in fields(AdoptedNaturalPlanV2)}:
        raise ValueError("natural plan graph fields differ")
    data = dict(value)
    for name in ("source_ref", "focus_ref", "ticket_ref", "scene_ref", "audience_ref"):
        data[name] = VersionedRef(**data[name])
    for name in ("promise_grants", "qualification_refs"):
        data[name] = tuple(VersionedRef(**item) for item in data[name])
    data["qualified_read_versions"] = tuple(GraphVersion(
        AtomKey(Owner(**item["key"]["owner"]),
                item["key"]["type_name"], item["key"]["name"]),
        item["revision"],
    ) for item in data["qualified_read_versions"])
    for name in ("required_slots", "allowed_speech_acts",
                 "d06_qualification_digests"):
        data[name] = tuple(data[name])
    for name in ("generation_ceiling", "review_ceiling"):
        data[name] = tuple(tuple(item) for item in data[name])
    return AdoptedNaturalPlanV2(**data)


def _current(snapshot: GraphSnapshot, ref: VersionedRef) -> bool:
    try:
        key = AtomKey.from_token(ref.ref)
    except (TypeError, ValueError):
        return False
    atom = snapshot.get(key)
    return (atom is not None and atom.revision == ref.version
            and atom.valid == (ref.version > 0))


def _qualified_refs(plan) -> tuple[VersionedRef, ...]:
    return tuple(dict.fromkeys(ref for unit in plan.units for ref in (
        *((unit.qualification_ref,) if unit.qualification_ref is not None else ()),
        *unit.source_refs, *unit.access_refs, *unit.correction_refs,
    )))


def _verify_d06_units_current(
    plan, snapshot: GraphSnapshot, d06_candidates: tuple[object, ...],
    *, access_epoch: int, deletion_epoch: int, now_utc: float,
) -> None:
    from ..d06.qualified_expression import (
        QualifiedExpressionUnitCandidate, recompute_qualified_expression_unit,
    )

    from ...runtime.natural_producer_qualification_v1 import (
        CANDIDATE_TYPES, C04_KIND, DRAFT_KIND, verify_live_producer_candidate_v1)
    if (type(d06_candidates) is not tuple
            or any(type(item) not in (QualifiedExpressionUnitCandidate, *CANDIDATE_TYPES)
                   for item in d06_candidates)
            or any(unit.d06_claim_kind not in {
                "attributed_report", "confirmed_external_fact", C04_KIND, DRAFT_KIND} for unit in plan.units)):
        raise TypeError("finite typed natural qualification candidates required")
    candidates = {item.qualification_digest: item for item in d06_candidates}
    units = {unit.qualification_digest: unit for unit in plan.units
             if unit.d06_claim_kind is not None}
    if (len(candidates) != len(d06_candidates) or len(units) != sum(
            unit.d06_claim_kind is not None for unit in plan.units)
            or None in units or set(candidates) != set(units)):
        raise ValueError("D06 qualification set is incomplete")
    for digest, unit in units.items():
        candidate = candidates[digest]
        if unit.d06_claim_kind in {C04_KIND, DRAFT_KIND}:
            if type(candidate) not in CANDIDATE_TYPES:
                raise TypeError("producer unit requires its exact reconstructed candidate")
            verify_live_producer_candidate_v1(candidate, unit, snapshot=snapshot,
                current_reads=snapshot.versions, access_epoch=access_epoch,
                deletion_epoch=deletion_epoch, now_utc=now_utc)
            continue
        if type(candidate) is not QualifiedExpressionUnitCandidate:
            raise TypeError("Source unit requires its original D06 candidate")
        rebuilt = recompute_qualified_expression_unit(
            snapshot, namespace=plan.namespace, candidate=candidates[digest],
            audiences=(plan.audience_id,), access_epoch=access_epoch,
            deletion_epoch=deletion_epoch, now=now_utc,
        )
        versions = {row.key.token: row.revision for row in rebuilt.read_versions}
        source_refs = tuple(VersionedRef(ref, versions[ref])
                            for ref in rebuilt.lineage_source_refs)
        access_refs = {VersionedRef(row.key.token, row.revision)
                       for row in rebuilt.read_versions
                       if row.key.type_name == "memory.access"}
        correction_refs = {VersionedRef(row.key.token, row.revision)
                           for row in rebuilt.read_versions
                           if row.key.type_name == "d06.source_correction_head.v1"}
        if (unit.kind.value != ("reported_claim" if rebuilt.claim_kind == "attributed_report"
                                else "external_fact")
                or unit.qualification_ref is not None
                or unit.qualification_digest != rebuilt.qualification_digest
                or unit.d06_claim_kind != rebuilt.claim_kind
                or unit.expires_at_utc > rebuilt.valid_until
                or unit.content_reality != ("external_report" if rebuilt.claim_kind
                                            == "attributed_report" else "external_observation")
                or unit.source_refs != source_refs
                or set(unit.access_refs) != access_refs
                or set(unit.correction_refs) != correction_refs
                or unit.speaker_id != rebuilt.speaker_id
                or unit.occurred_at != rebuilt.occurred_at
                or unit.learned_at != rebuilt.learned_at
                or unit.source_kind != rebuilt.source_kind
                or unit.assertion_status != rebuilt.assertion_status
                or unit.attribution_required != rebuilt.attribution_required
                or unit.polarity_status != rebuilt.polarity_status
                or unit.source_excerpt != rebuilt.source_excerpt
                or unit.evidence_span != (rebuilt.evidence_span.start,
                                          rebuilt.evidence_span.end)
                or unit.direct_quote_span != (
                    (rebuilt.direct_quote_span.start, rebuilt.direct_quote_span.end)
                    if rebuilt.direct_quote_span is not None else None)
                or unit.negation_cue_span != (
                    (rebuilt.negation_cue_span.start, rebuilt.negation_cue_span.end)
                    if rebuilt.negation_cue_span is not None else None)
                or unit.qualified_text != (
                    rebuilt.direct_quote_text if unit.direct_quote else rebuilt.source_excerpt)):
            raise ValueError("D06 qualified expression projection changed")


@dataclass(frozen=True, slots=True)
class NaturalPlanPreparationEvidenceV2:
    """W01-computed inputs; this DTO alone does not authenticate a read."""

    c02_operation_id: str
    source_ref: VersionedRef
    focus_ref: VersionedRef
    ticket_ref: VersionedRef
    preparation_evidence_digest: str
    route_binding_digest: str
    parent_budget_lease_id: str
    budget_grant_version: int
    budget_grant_digest: str
    generation_ceiling: tuple[tuple[str, int], ...]
    review_ceiling: tuple[tuple[str, int], ...]


def _expected_record(
    *, plan, evidence: NaturalPlanPreparationEvidenceV2,
    snapshot: GraphSnapshot, d06_candidates: tuple[object, ...],
    access_epoch: int, deletion_epoch: int, now_utc: float,
) -> AdoptedNaturalPlanV2:
    from ..d09.natural_reply import NaturalExpressionPlanV2
    from ...host.post_c02_reply_driver import post_c02_reply_operation_id
    from ...runtime.natural_reply_job_v2 import natural_job_ids_v2

    if (type(plan) is not NaturalExpressionPlanV2
            or type(evidence) is not NaturalPlanPreparationEvidenceV2
            or type(snapshot) is not GraphSnapshot
            or now_utc >= plan.valid_until_utc
            or any(plan.valid_until_utc > unit.expires_at_utc
                   for unit in plan.units)):
        raise ValueError("current typed natural preparation is required")
    key = AtomKey.from_token(plan.plan_ref.ref)
    if (key != natural_plan_key_v2(plan.namespace, plan.final_activity_id, key.name)
            or key.name != natural_plan_id_v2(
                plan.namespace, evidence.c02_operation_id, evidence.source_ref.ref)
            or plan.plan_ref != VersionedRef(key.token, 1)
            or plan.final_operation_id != post_c02_reply_operation_id(
                evidence.c02_operation_id, evidence.source_ref.ref)
            or plan.final_effect_id != natural_final_effect_id_v2(
                plan.namespace, evidence.c02_operation_id, evidence.source_ref.ref)):
        raise ValueError("natural preparation final identity or source differs")
    refs = (evidence.source_ref, evidence.focus_ref, evidence.ticket_ref,
            plan.scene_ref, plan.audience_ref, *plan.promise_grants,
            *_qualified_refs(plan))
    if any(not _current(snapshot, ref) for ref in refs):
        raise ValueError("natural preparation scope changed")
    _verify_d06_units_current(
        plan, snapshot, d06_candidates, access_epoch=access_epoch,
        deletion_epoch=deletion_epoch, now_utc=now_utc,
    )
    source_digests = tuple(sorted({unit.qualification_digest for unit in plan.units
                                   if unit.d06_claim_kind is not None}))
    reads = tuple(sorted((GraphVersion(AtomKey.from_token(ref.ref), ref.version)
                          for ref in dict.fromkeys(refs)),
                         key=lambda row: row.key.token))
    from ...runtime.natural_producer_qualification_v1 import producer_candidate_read_versions_v1
    producer_reads = producer_candidate_read_versions_v1(d06_candidates)
    if producer_reads:
        by_key = {row.key: row for row in reads}
        for row in producer_reads:
            prior = by_key.get(row.key)
            if prior is not None and prior != row:
                raise ValueError("producer qualification changed a natural plan read")
            by_key[row.key] = row
        reads = tuple(by_key[key] for key in sorted(by_key, key=lambda key:key.token))
    generation_reservation_id = natural_job_ids_v2(
        plan.namespace, evidence.c02_operation_id, "generation")[4]
    review_reservation_id = natural_job_ids_v2(
        plan.namespace, evidence.c02_operation_id, "review")[4]
    return AdoptedNaturalPlanV2(
        NATURAL_PLAN_TYPE_V2, key.name,
        evidence.c02_operation_id, evidence.source_ref,
        plan.final_activity_id, plan.final_operation_id, plan.final_effect_id,
        evidence.focus_ref, evidence.ticket_ref,
        evidence.preparation_evidence_digest, evidence.route_binding_digest,
        evidence.parent_budget_lease_id, evidence.budget_grant_version,
        evidence.budget_grant_digest, generation_reservation_id,
        review_reservation_id, evidence.generation_ceiling,
        evidence.review_ceiling, plan.scene_id, plan.audience_id,
        plan.scene_ref, plan.audience_ref,
        plan.required_slots, plan.allowed_speech_acts, plan.promise_grants,
        canonical_digest(plan.units), source_digests,
        tuple(dict.fromkeys(unit.qualification_ref for unit in plan.units
                                 if unit.qualification_ref is not None)),
        reads, plan.valid_until_utc,
    )


def prepare_coordinator_natural_plan_write_v2(
    *, plan, evidence: NaturalPlanPreparationEvidenceV2,
    snapshot: GraphSnapshot, d06_candidates: tuple[object, ...],
    access_epoch: int, deletion_epoch: int, now_utc: float,
) -> tuple[GraphWrite, tuple[GraphVersion, ...]]:
    """Prepare W01's CAS write after its held C02/route/attention/budget reads."""
    record = _expected_record(
        plan=plan, evidence=evidence, snapshot=snapshot,
        d06_candidates=d06_candidates, access_epoch=access_epoch,
        deletion_epoch=deletion_epoch, now_utc=now_utc,
    )
    key = AtomKey.from_token(plan.plan_ref.ref)
    if snapshot.get(key) is not None and snapshot.get(key).valid:
        raise ValueError("natural preparation already adopted")
    return (GraphWrite(key, json.loads(canonical_serialize(asdict(record)))),
            (*record.qualified_read_versions, GraphVersion(key, 0)))


def verify_current_natural_plan_v2(
    *, plan, evidence: NaturalPlanPreparationEvidenceV2,
    snapshot: GraphSnapshot, d06_candidates: tuple[object, ...],
    access_epoch: int, deletion_epoch: int, now_utc: float,
) -> tuple[AdoptedNaturalPlanV2, tuple[GraphVersion, ...]]:
    """Compare a current adopted scope with W01's fresh evidence reads."""
    key = AtomKey.from_token(plan.plan_ref.ref)
    atom = snapshot.get(key)
    if atom is None or not atom.valid or atom.revision != 1:
        raise ValueError("natural preparation has no adopted graph head")
    record = decode_natural_plan_v2(atom.value)
    expected = _expected_record(
        plan=plan, evidence=evidence, snapshot=snapshot,
        d06_candidates=d06_candidates, access_epoch=access_epoch,
        deletion_epoch=deletion_epoch, now_utc=now_utc,
    )
    if record != expected:
        raise ValueError("natural preparation changed from adopted scope")
    return record, (GraphVersion(key, 1), *record.qualified_read_versions)


__all__ = [
    "NATURAL_PLAN_TYPE_V2", "AdoptedNaturalPlanV2", "natural_plan_key_v2",
    "natural_plan_id_v2",
    "natural_final_effect_id_v2", "NaturalPlanPreparationEvidenceV2",
    "natural_route_semantic_digest_v2",
    "decode_natural_plan_v2", "prepare_coordinator_natural_plan_write_v2",
    "verify_current_natural_plan_v2",
]
