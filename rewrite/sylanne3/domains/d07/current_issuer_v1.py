"""Installed D07 current issuers. Inputs are originals, never candidate writes.

W01 supplies current fenced heads and authenticates paid/adoption originals.
These deterministic functions do not grant authority, execute models or commit.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId, canonical_digest
from ...runtime.c04_v3_contracts import (
    AssociationWorkInputV3, AssociationWorkResultV3, GraphHeadV3,
)
from ..d06 import SelectionTicket, source_correction_head_key
from . import CurrentInterpretationCandidate, D07DomainProvider, EvidenceStatus, Stance


@dataclass(frozen=True, slots=True)
class InstalledCurrentInterpretationPolicyV3:
    policy_id: str
    policy_version: str
    mode: str = "recollection_presence"
    interpretation_ref: str | None = None
    schema: str = "d07.installed-current-interpretation-policy.v3"

    def __post_init__(self) -> None:
        if self.schema != "d07.installed-current-interpretation-policy.v3" or not self.policy_id or not self.policy_version or self.mode not in {
                "recollection_presence", "adopted_interpretation", "paid_cognitive_candidate"}:
            raise ValueError("installed D07 interpretation policy is invalid")
        if self.mode == "recollection_presence":
            if self.interpretation_ref is not None:
                raise ValueError("presence policy cannot name an interpretation")
        elif self.interpretation_ref is None:
            raise ValueError("semantic policy needs an exact adopted original")
        else:
            AtomKey.from_token(self.interpretation_ref)

    @property
    def content_digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class PaidCognitiveAdoptionOriginalV1:
    """Read by W01 from durable D11 cost and D07 adoption originals."""
    interpretation_ref: str
    interpretation_revision: int
    call_id: str
    frozen_request_digest: str
    durable_result_digest: str
    cost_receipt_refs: tuple[str, ...]
    adoption_receipt_ref: str
    parent_budget_ref: str
    activation_generation: int

    def __post_init__(self) -> None:
        AtomKey.from_token(self.interpretation_ref)
        if self.interpretation_revision < 1 or self.activation_generation < 1:
            raise ValueError("paid cognitive original needs adopted current identity")
        for value in (self.call_id, self.adoption_receipt_ref, self.parent_budget_ref):
            if type(value) is not str or not value:
                raise ValueError("paid cognitive original is incomplete")
        for digest in (self.frozen_request_digest, self.durable_result_digest):
            if len(digest.removeprefix("sha256:")) != 64:
                raise ValueError("paid cognitive original digest is invalid")
        if not self.cost_receipt_refs or len(set(self.cost_receipt_refs)) != len(self.cost_receipt_refs):
            raise ValueError("paid cognitive original needs actual cost originals")


@dataclass(frozen=True, slots=True)
class AdoptedInterpretationOriginalV1:
    interpretation_ref: str
    interpretation_revision: int
    adoption_operation_id: str
    issuer_ref: str
    proposal_digest: str
    adoption_receipt_ref: str
    question_scope: str
    supporting_refs: tuple[str, ...]
    counter_refs: tuple[str, ...]
    meaningful_unknowns: tuple[str, ...]

    def __post_init__(self) -> None:
        AtomKey.from_token(self.interpretation_ref)
        if self.interpretation_revision < 1 or any(not value for value in (
                self.adoption_operation_id, self.issuer_ref, self.proposal_digest,
                self.adoption_receipt_ref, self.question_scope)):
            raise ValueError("current interpretation adoption original is incomplete")


@dataclass(frozen=True, slots=True)
class IssuedCurrentInterpretationV3:
    candidate: CurrentInterpretationCandidate
    provenance_payload: dict
    read_versions: tuple[GraphVersion, ...]

    @property
    def provenance_digest(self) -> str:
        return canonical_digest(self.provenance_payload)


def qualify_current_source_heads_v1(
    namespace: NamespaceId, roots: tuple[str, ...], heads: tuple[GraphHeadV3, ...],
    *, audience: str, purpose: str,
) -> tuple[tuple[SourceRecord, ...], tuple[str, ...], tuple[GraphVersion, ...]]:
    """Qualify complete D06 ancestors and derive unique provenance families."""
    if (type(namespace) is not NamespaceId or not roots or len(roots) > 256
            or type(heads) is not tuple or len({h.ref for h in heads}) != len(heads)):
        raise ValueError("current source closure is incomplete or duplicated")
    by_ref = {head.ref: head for head in heads}
    records: dict[str, SourceRecord] = {}
    versions: dict[str, GraphVersion] = {}
    active: set[str] = set()
    families: set[str] = set()

    def visit(ref: str) -> None:
        if ref in active:
            raise ValueError("current source closure is cyclic")
        if ref in records:
            return
        if len(records) + len(active) >= 256:
            raise ValueError("current source closure exceeds its bound")
        key = AtomKey.from_token(ref)
        source_id = key.owner.subject or ""
        if key != source_key(*namespace.as_tuple, source_id):
            raise ValueError("current source namespace differs")
        keys = (key, access_key(*namespace.as_tuple, source_id),
                source_correction_head_key(namespace, source_id))
        try:
            source, access, correction = (by_ref[item.token] for item in keys)
        except KeyError as exc:
            raise ValueError("current source positive/negative heads are missing") from exc
        if (not source.valid or source.revision < 1 or not access.valid
                or access.revision < 1 or correction.valid or correction.revision != 0):
            raise ValueError("current source is corrected or inaccessible")
        record = SourceRecord.from_dict(source.value)
        access_value = access.value
        validate_access(access_value)
        if (record.source_id != source_id
                or record.assertion_status not in {"confirmed", "reported"}
                or audience not in record.audiences or purpose not in record.purposes
                or access_value["source_id"] != source_id
                or access_value["status"] != "active"
                or audience not in access_value["audiences"]
                or purpose not in access_value["purposes"]):
            raise ValueError("current source lacks requested audience/purpose")
        active.add(ref)
        for parent in record.parent_source_ids:
            visit(source_key(*namespace.as_tuple, parent).token)
        active.remove(ref)
        records[ref] = record
        # D06's stored provenance root, not parent absence, names a family.
        # A derived source may retain one root among several parent families.
        if record.parent_source_ids and record.provenance_root not in {
                records[source_key(*namespace.as_tuple, parent).token].provenance_root
                for parent in record.parent_source_ids}:
            raise ValueError("source provenance family disagrees with its ancestors")
        families.add(record.provenance_root)
        for item in (source, access, correction):
            versions[item.ref] = GraphVersion(AtomKey.from_token(item.ref), item.revision)

    for ref in roots:
        visit(ref)
    return (tuple(records[ref] for ref in sorted(records)), tuple(sorted(families)),
            tuple(versions[ref] for ref in sorted(versions)))


def issue_current_recollection_interpretation_v3(
    work: AssociationWorkInputV3, result: AssociationWorkResultV3,
    selection: SelectionTicket, source_heads: tuple[GraphHeadV3, ...],
    interpretation_originals: tuple[GraphHeadV3, ...],
    installed_policy: InstalledCurrentInterpretationPolicyV3, *,
    binding_digest: str, execution_id: str, activation_generation: int,
    adoption_original: AdoptedInterpretationOriginalV1 | None = None,
    paid_original: PaidCognitiveAdoptionOriginalV1 | None = None,
) -> IssuedCurrentInterpretationV3:
    """Reissue selected current meaning from the same Authority association.

    The selected source may be a newly traversed target outside the old attention
    ticket. Its frozen and current source head must agree. An installed semantic
    branch names a current D07 adopted head; historical baseline meaning cannot
    be substituted for that head. W01 independently reads all supplied originals.
    """
    from ...runtime.c04_result_adoption_v3 import select_c04_result_v3

    if (type(work) is not AssociationWorkInputV3
            or type(result) is not AssociationWorkResultV3
            or type(installed_policy) is not InstalledCurrentInterpretationPolicyV3
            or not binding_digest or not execution_id or activation_generation < 1):
        raise ValueError("current D07 issuer requires installed typed originals")
    return _issue_current_recollection_interpretation_checked_v3(
        work, result, selection, source_heads, interpretation_originals, installed_policy,
        binding_digest=binding_digest, execution_id=execution_id, activation_generation=activation_generation,
        adoption_original=adoption_original, paid_original=paid_original)


def issue_current_recollection_interpretation_v4(
    work: AssociationWorkInputV3, result: AssociationWorkResultV3,
    selection: SelectionTicket, source_heads: tuple[GraphHeadV3, ...],
    interpretation_originals: tuple[GraphHeadV3, ...],
    installed_policy: InstalledCurrentInterpretationPolicyV3, *,
    binding_digest: str, execution_id: str, activation_generation: int,
    adoption_original: AdoptedInterpretationOriginalV1 | None = None,
    paid_original: PaidCognitiveAdoptionOriginalV1 | None = None,
) -> IssuedCurrentInterpretationV3:
    from ...runtime.c04_direct_seed_v4 import AssociationWorkInputV4, AssociationWorkResultV4
    if (type(work) is not AssociationWorkInputV4 or type(result) is not AssociationWorkResultV4
            or type(installed_policy) is not InstalledCurrentInterpretationPolicyV3
            or not binding_digest or not execution_id or activation_generation < 1):
        raise ValueError("current Self C04 issuer requires exact installed V4 originals")
    return _issue_current_recollection_interpretation_checked_v3(
        work, result, selection, source_heads, interpretation_originals, installed_policy,
        binding_digest=binding_digest, execution_id=execution_id, activation_generation=activation_generation,
        adoption_original=adoption_original, paid_original=paid_original)


def _issue_current_recollection_interpretation_checked_v3(
    work: AssociationWorkInputV3, result: AssociationWorkResultV3,
    selection: SelectionTicket, source_heads: tuple[GraphHeadV3, ...],
    interpretation_originals: tuple[GraphHeadV3, ...],
    installed_policy: InstalledCurrentInterpretationPolicyV3, *,
    binding_digest: str, execution_id: str, activation_generation: int,
    adoption_original: AdoptedInterpretationOriginalV1 | None = None,
    paid_original: PaidCognitiveAdoptionOriginalV1 | None = None,
) -> IssuedCurrentInterpretationV3:
    from ...runtime.c04_result_adoption_v3 import select_c04_result_v3
    result.validate_input(work)
    _, expected = select_c04_result_v3(work, result, focus_epoch=work.selection_ticket.focus_epoch)
    if selection != expected.selection_ticket or len(selection.selected_candidate_ids) != 1:
        raise ValueError("current interpretation selection differs from Authority result")
    selected_ref = source_key(*work.namespace.as_tuple, selection.selected_candidate_ids[0]).token
    if selected_ref not in {target.source_ref for target in work.targets}:
        raise ValueError("selected source is outside frozen qualified targets")
    frozen = {head.ref: head for head in work.reads}
    current = {head.ref: head for head in source_heads}
    if current.get(selected_ref) != frozen.get(selected_ref):
        raise ValueError("selected source changed after frozen association")
    records, families, reads = qualify_current_source_heads_v1(
        work.namespace, (selected_ref,), source_heads,
        audience=work.audience, purpose=work.purpose)
    record = next(item for item in records if item.source_id == selection.selected_candidate_ids[0])
    provenance = {
        "schema": "d07.current_recollection_interpretation.v3",
        "mode": installed_policy.mode, "policy": installed_policy,
        "namespace": work.namespace, "operation_id": work.operation_id,
        "activity_id": work.activity_id, "input_digest": work.input_digest,
        "result_digest": result.result_digest, "binding_digest": binding_digest,
        "execution_id": execution_id, "algorithm_build": work.algorithm_build_digest,
        "selection": selection, "source_heads": tuple(sorted(source_heads, key=lambda h: h.ref)),
        "focus": frozen[work.focus_ref], "ticket": frozen[work.attention_ticket_ref],
        "audience": work.audience, "purpose": work.purpose,
        "owner_epoch": work.owner_epoch, "access_epoch": work.access_epoch,
        "delete_epoch": work.delete_epoch, "activation_generation": activation_generation,
        "interpretation_original": None, "paid_original": None,
    }
    question_key = "recollection:" + selected_ref
    proposition = "本次回忆选中了来源 " + selected_ref + " 所记载的内容。"
    stance, conviction, evidence = Stance.SUSPEND, 0.0, EvidenceStatus.INSUFFICIENT
    unknowns = ("外界真实性未重新评估", "语义校准未完成",
                "原来源 assertion_status=" + record.assertion_status)
    if installed_policy.mode != "recollection_presence":
        originals = {head.ref: head for head in interpretation_originals}
        if len(originals) != len(interpretation_originals):
            raise ValueError("duplicate adopted interpretation originals")
        head = originals.get(installed_policy.interpretation_ref)
        if head is None or not head.valid or head.revision < 1:
            raise ValueError("installed current interpretation is unavailable")
        key = AtomKey.from_token(head.ref)
        if NamespaceId.from_key(key) != work.namespace or key.type_name not in {
                "d07.current_interpretation.v1", "d07.belief_revision.v1"}:
            raise ValueError("current interpretation must be an adopted D07 original")
        value = head.value
        next(spec for spec in D07DomainProvider.type_specs() if spec.name == key.type_name).validator(value)
        if (not value["current"] or selected_ref not in value["source_refs"]
                or value.get("replaced_by") is not None or value.get("invalidation_refs")):
            raise ValueError("interpretation is not current for selected source")
        if (type(adoption_original) is not AdoptedInterpretationOriginalV1
                or adoption_original.interpretation_ref != head.ref
                or adoption_original.interpretation_revision != head.revision
                or adoption_original.question_scope != value["question_key"]):
            raise ValueError("current interpretation lacks its original D07 issuer adoption")
        original_roots = tuple(dict.fromkeys((*value["source_refs"],
            *adoption_original.supporting_refs, *adoption_original.counter_refs)))
        _, original_families, extra_reads = qualify_current_source_heads_v1(
            work.namespace, original_roots, source_heads,
            audience=work.audience, purpose=work.purpose)
        if tuple(value["source_families"]) != original_families:
            raise ValueError("adopted interpretation contribution families differ")
        families = original_families
        reads = tuple(dict.fromkeys((*reads, *extra_reads, GraphVersion(key, head.revision))))
        proposition = value["proposition"]
        question_key = value["question_key"]
        stance, conviction = Stance(value["stance"]), value["subjective_conviction"]
        evidence = EvidenceStatus(value["evidence_status"])
        unknowns = tuple(value.get("meaningful_unknowns", adoption_original.meaningful_unknowns))
        if unknowns != adoption_original.meaningful_unknowns:
            raise ValueError("current interpretation unknowns differ from adoption original")
        provenance["interpretation_original"] = head
        provenance["adoption_original"] = adoption_original
        if installed_policy.mode == "paid_cognitive_candidate":
            if (type(paid_original) is not PaidCognitiveAdoptionOriginalV1
                    or paid_original.interpretation_ref != head.ref
                    or paid_original.interpretation_revision != head.revision
                    or paid_original.activation_generation != activation_generation):
                raise ValueError("paid interpretation lacks same current adopted cost original")
            provenance["paid_original"] = paid_original
    identifier = "interpretation:" + canonical_digest(provenance)[:48]
    candidate = CurrentInterpretationCandidate(
        identifier, work.activity_id, question_key, proposition,
        stance, conviction, evidence, (selected_ref,), families, unknowns)
    return IssuedCurrentInterpretationV3(candidate, provenance, reads)


__all__ = ["InstalledCurrentInterpretationPolicyV3", "PaidCognitiveAdoptionOriginalV1",
           "AdoptedInterpretationOriginalV1", "IssuedCurrentInterpretationV3", "qualify_current_source_heads_v1",
           "issue_current_recollection_interpretation_v3"]
