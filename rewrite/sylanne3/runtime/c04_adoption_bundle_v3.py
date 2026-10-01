"""W01 assembly of five domain writes from the actual paid C04 result."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import sqlite3

from ..authority_service.installed_c04_executor_v3 import decode_completed_c04_output_v3
from ..domains.d04.affect import RecollectionExperience
from ..domains.d06 import D06DomainAdapter, RecollectionContext
from ..domains.d07 import D07DomainProvider
from .d07_current_behavior_v1 import issue_current_association_interpretation_in_transaction_v3
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..runtime_contracts import DependencySet, DomainBundle, DomainProposal, QueryEpoch, SourceQualification, canonical_digest
from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1
from .c04_d04_state_codec_v3 import decode_c04_mood_v3
from .c04_frozen_association_original_v3 import read_c04_frozen_association_original_v3, verify_current_association_input_heads_v3
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_product_original_v3 import read_c04_product_request_v3
from .c04_result_adoption_v3 import select_c04_result_v3, reconstruct_c04_result_v3
from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1


@dataclass(frozen=True, slots=True)
class C04AdoptionAssemblyV3:
    bundle: DomainBundle
    interpretation_provenance: dict


def c04_adoption_outbox_ref_v3(namespace, operation_id, activity_id):
    from .d11_types import runtime_outbox_key
    name = "c04-outbox-" + canonical_digest(("c04.adoption.outbox.v3", namespace, operation_id))[:48]
    return runtime_outbox_key(*namespace.as_tuple, activity_id, name).token


def build_current_c04_adoption_bundle_v3(
    db: sqlite3.Connection, *, authority, proof, verified, now_utc,
    query_epoch, current_owner_version, catalogue_version, scheme,
    policy_version, projection_policy, interpretation_policy,
    d04_provider, d06_provider, d07_provider,
) -> C04AdoptionAssemblyV3:
    """Called only inside the current W01 Owner write transaction.

    The request envelope is reread from its immutable original. Content is
    never supplied by a caller, and no D02/D11 reservation or bill is repeated.
    """
    if not db.in_transaction:
        raise ValueError("current C04 adoption transaction required")
    namespace, operation_id = authority.namespace, proof.binding.operation_id
    prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
    request = read_c04_product_request_v3(db, namespace, operation_id)
    if prepared is None or request is None or prepared.binding != proof.binding:
        raise ValueError("C04 adoption original preparation is absent")
    work = read_c04_frozen_association_original_v3(db, namespace, prepared.binding)
    verify_current_association_input_heads_v3(db, work)
    result = decode_completed_c04_output_v3(prepared.binding, proof.terminal)
    result.validate_input(work)
    if (request.envelope.deadline_utc <= now_utc
            or (authority.audience, authority.purpose, authority.activation_generation) !=
               ((work.audience,), work.purpose, proof.binding.activation_generation)
            or verified.proof_digest != canonical_digest(proof)):
        raise ValueError("C04 current adoption lifetime or Authority original differs")
    cpu = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
    body = read_c04_body_cost_original_v1(db, namespace, operation_id)
    if cpu is None or body is None:
        raise ValueError("C04 independently paid originals are absent")
    candidates, selected = select_c04_result_v3(work, result,
                                             focus_epoch=work.selection_ticket.focus_epoch)
    issued = issue_current_association_interpretation_in_transaction_v3(
        db, work, result, selected.selection_ticket, interpretation_policy,
        binding_digest=prepared.binding.binding_digest,
        execution_id=prepared.binding.execution_id,
        activation_generation=prepared.binding.activation_generation)
    selected_id = selected.selection_ticket.selected_candidate_ids[0]
    source_ref = next(candidate.source_ref for candidate in result.candidates
                      if AtomKey.from_token(candidate.source_ref).owner.subject == selected_id)
    target = next(target for target in work.targets if target.source_ref == source_ref)
    mood = decode_c04_mood_v3(work.mood_ref,
                             next(head.value for head in work.reads if head.ref == work.mood_ref))
    versions = {AtomKey.from_token(head.ref): GraphVersion(
        AtomKey.from_token(head.ref), head.revision) for head in work.reads}
    versions.update({AtomKey.from_token(target.condition.current_checkpoint.ref): GraphVersion(
        AtomKey.from_token(target.condition.current_checkpoint.ref),
        target.condition.current_checkpoint.revision) for target in work.targets})
    versions[current_owner_version.key] = current_owner_version
    envelope = replace(request.envelope, authority=authority,
        source_qualification=SourceQualification(
            tuple(sorted(head.ref for head in work.reads
                         if AtomKey.from_token(head.ref).type_name == "memory.source")),
            "derived", None, now_utc, "inference", "ineligible", None, "actual"),
        version_guard=replace(request.envelope.version_guard,
            read_versions=tuple(sorted(versions.values(), key=lambda item: item.key.token)),
            query_epochs=(QueryEpoch(namespace, "all", query_epoch.revision),),
            access_epoch=work.access_epoch, delete_epoch=work.delete_epoch,
            catalogue_version=catalogue_version, scheme_version=scheme.scheme_version,
            operator_version=scheme.operator_version, policy_version=policy_version,
            resource_lease_versions=()))
    source_dependencies = (AtomKey.from_token(source_ref),)
    selection_write = D07DomainProvider.selection_choice_write(
        envelope, selected.selection_ticket, source_dependencies=source_dependencies)
    interpretation_write = D07DomainProvider.current_interpretation_write(
        envelope, issued.candidate, source_dependencies=source_dependencies)
    experience_id = "c04-experience-" + canonical_digest((
        "c04.subjective-experience.v3", work.input_digest, result.result_digest))[:48]
    experience_key = AtomKey(Owner("activity", *namespace.as_tuple, work.activity_id),
                             "d04.recollection_experience.v1", experience_id)
    adapter = D06DomainAdapter(namespace)
    context = RecollectionContext((interpretation_write.key.token,), (experience_key.token,), ())
    proposal, reconstruction = reconstruct_c04_result_v3(
        work, result, candidates=candidates, handoff=selected, adapter=adapter, context=context)
    recollection_write = adapter.recollection_write(
        proposal, candidate_set_id=candidates.candidate_set_id,
        focus_epoch=selected.selection_ticket.focus_epoch,
        access_epoch=work.access_epoch, delete_epoch=work.delete_epoch)
    experience = RecollectionExperience(experience_id, work.activity_id,
        recollection_write.key.token, source_ref, (source_ref,), work.mood_ref,
        mood.source_refs, target.condition.conditioned_salience_interval,
        target.condition.conditioned_tone_interval, projection_policy.policy_id,
        mood.coupling_version, 0.0)
    experience_write = GraphWrite(experience_key, asdict(experience), ())
    projection_write = adapter.recollection_projection_write(reconstruction, experience_write)
    writes = (experience_write, recollection_write, projection_write,
              selection_write, interpretation_write)
    for write in writes:
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone():
            raise ValueError("C04 adoption output is not absent")
        versions[write.key] = GraphVersion(write.key, 0)
    envelope = replace(envelope, version_guard=replace(envelope.version_guard,
        read_versions=tuple(sorted(versions.values(), key=lambda item: item.key.token))))
    providers = {"d04": d04_provider, "d06": d06_provider, "d07": d07_provider}
    by_domain = {"d04": (experience_write,), "d06": (recollection_write, projection_write),
                 "d07": (selection_write, interpretation_write)}
    domain_proposals = []
    for domain, domain_writes in by_domain.items():
        current = tuple(sorted({dependency for write in domain_writes
                                for dependency in write.dependencies}, key=lambda key: key.token))
        dependencies = DependencySet(
            current_invalidation=tuple(versions[key] for key in current),
            historical_provenance=tuple(version for version in versions.values()
                                        if version.revision > 0))
        domain_proposals.append(DomainProposal(
            domain, domain + ".proposal.v1", providers[domain].descriptor.request_schema_hash,
            envelope, domain_writes, dependencies,
            ("recollection-selection:" + work.activity_id,) if domain == "d07" else (),
            ("experience", "choice", "d02_settlement", "cost_settlement", "outbox")))
    bundle = DomainBundle(envelope, tuple(domain_proposals),
        (experience_key.token,), (selection_write.key.token,), (body.settlement_ref,),
        (cpu.budget_operation_id,), (), (),
        (c04_adoption_outbox_ref_v3(namespace, operation_id, work.activity_id),))
    return C04AdoptionAssemblyV3(bundle, issued.provenance_payload)


__all__ = ["C04AdoptionAssemblyV3", "c04_adoption_outbox_ref_v3",
           "build_current_c04_adoption_bundle_v3"]
