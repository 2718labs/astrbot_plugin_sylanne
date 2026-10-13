"""W01 assembly of five domain writes from the actual paid C04 result."""

from __future__ import annotations

from dataclasses import asdict, replace
import sqlite3

from ..domains.d04.affect import RecollectionExperience
from ..domains.d06 import D06DomainAdapter, RecollectionContext
from ..domains.d07 import D07DomainProvider
from .d07_current_behavior_v1 import issue_current_association_interpretation_in_transaction_v3
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..runtime_contracts import DependencySet, DomainBundle, DomainProposal, QueryEpoch, SourceQualification, canonical_digest
from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1
from .c04_d04_state_codec_v3 import decode_c04_mood_v3
from .c04_frozen_association_original_v3 import read_c04_frozen_association_original_v4, _verify_current_association_input_heads_common_v3
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_product_original_v3 import read_c04_product_request_v3
from .c04_result_adoption_v3 import select_c04_result_v3, reconstruct_c04_result_v3
from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1


from .c04_adoption_bundle_v3 import C04AdoptionAssemblyV3, c04_adoption_outbox_ref_v3


from ..authority_service.internal_work_contract import InternalWorkTerminalProofV1
from ..authority_service.internal_work_service import AuthorityInternalWorkVerifiedReceiptV1
from ..domains.d04.affect import _decode_recollection_experience
from ..memory_types import source_key
from ..runtime_contracts import NamespaceId
from .c04_v3_contracts import C04AdoptionPlanV3, PlannedWriteV3, canonical_v3_digest
from .c04_adoption_plan_v3 import C04AdoptionPlanHold, _current_self_understanding_reads


def decode_completed_c04_output_v4(binding, terminal):
    # Concrete installed Authority decoder; no response/provider callback.
    from ..authority_service.installed_c04_executor_v3 import decode_completed_c04_output_v4 as decode
    return decode(binding, terminal)


def build_self_c04_adoption_bundle_v4(
    db: sqlite3.Connection, *, authority, proof, verified, now_utc,
    query_epoch, current_owner_version, catalogue_version, scheme,
    policy_version, projection_policy, interpretation_policy,
    d04_provider, d06_provider, d07_provider, adoption_identity,
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
    work = read_c04_frozen_association_original_v4(db, namespace, prepared.binding)
    _verify_current_association_input_heads_common_v3(db, work)
    result = decode_completed_c04_output_v4(prepared.binding, proof.terminal)
    result.validate_input(work)
    from .c04_self_scope_v4 import ingress_c04_ids_v4
    expected = ingress_c04_ids_v4(namespace, work.direct_selection.c02_operation_id, work.c03_selection_original_digest)
    if (adoption_identity.operation_id != expected["adopt"]
            or adoption_identity.activity_id != work.activity_id
            or adoption_identity.effect_id != request.envelope.identity.effect_id):
        raise ValueError("Self C04 adoption changed its distinct fixed command identity")
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
    envelope = replace(request.envelope, authority=authority, identity=adoption_identity,
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

def build_self_c04_adoption_plan_v4(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str, adoption_operation_id: str,
    proof: InternalWorkTerminalProofV1,
    verified: AuthorityInternalWorkVerifiedReceiptV1,
    bundle: DomainBundle,
    installation_id: str, manifest_digest: str,
) -> C04AdoptionPlanV3:
    """Read current originals; return exact writes for W01's final CAS.

    W01 must get ``verified`` from Authority's independent terminal reread
    immediately before entering this Owner-fenced graph transaction.
    """
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(proof) is not InternalWorkTerminalProofV1
            or type(verified) is not AuthorityInternalWorkVerifiedReceiptV1
            or type(bundle) is not DomainBundle):
        raise C04AdoptionPlanHold("typed current C04 W01 transaction required")
    prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
    if prepared is None or prepared.binding != proof.binding:
        raise C04AdoptionPlanHold("frozen C04 preparation differs")
    binding = prepared.binding
    work = read_c04_frozen_association_original_v4(db, namespace, binding)
    if work is None:
        raise C04AdoptionPlanHold("frozen C04 V3 input is absent")
    result = decode_completed_c04_output_v4(binding, proof.terminal)
    result.validate_input(work)
    from .c04_self_scope_v4 import ingress_c04_ids_v4
    ids = ingress_c04_ids_v4(namespace, work.direct_selection.c02_operation_id, work.c03_selection_original_digest)
    if (operation_id, adoption_operation_id) != (ids["prepare"], ids["adopt"]):
        raise C04AdoptionPlanHold("Self C04 fixed prepare/adopt relation differs")
    if (verified.proof_digest != canonical_digest(proof)
            or verified.operation_id != operation_id
            or verified.input_digest != binding.input_digest
            or verified.actual_cpu_ms != proof.terminal.actual_cpu_ms
            or verified.terminal_receipt_digest != proof.terminal_receipt_digest
            or verified.status != "completed"
            or not verified.component_completed
            or bundle.envelope.identity.operation_id != adoption_operation_id
            or bundle.envelope.authority.namespace != namespace
            or bundle.envelope.identity.activity_id != work.activity_id
            or bundle.envelope.authority.audience != (work.audience,)
            or bundle.envelope.authority.purpose != work.purpose
            or bundle.envelope.authority.activation_generation
               != binding.activation_generation
            or bundle.envelope.parent_budget_lease_ref
               != binding.parent_budget_lease_ref):
        raise C04AdoptionPlanHold("Authority result or W01 operation differs")
    cpu = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
    body = read_c04_body_cost_original_v1(db, namespace, operation_id)
    if (cpu is None or body is None
            or cpu.binding_digest != binding.binding_digest
            or cpu.prepared_digest != prepared.prepared_digest
            or cpu.proof_digest != verified.proof_digest
            or cpu.terminal_receipt_digest != proof.terminal_receipt_digest
            or cpu.status != "completed"
            or cpu.actual_cpu_ms != verified.actual_cpu_ms
            or cpu.budget_lease_id != binding.parent_budget_lease_ref
            or cpu.budget_receipt_status != "settled"
            or not cpu.component_completed
            or body.binding_digest != binding.binding_digest
            or body.proof_digest != cpu.proof_digest
            or body.component_receipt_ref != proof.terminal.component_receipt_ref
            or bundle.d02_settlement_refs != (body.settlement_ref,)
            or bundle.d11_cost_settlement_refs != (cpu.budget_operation_id,)):
        raise C04AdoptionPlanHold("independently settled D02/D11 originals differ")
    rights = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if rights != (work.access_epoch, work.delete_epoch):
        raise C04AdoptionPlanHold("C04 access or deletion epoch changed")
    _verify_current_association_input_heads_common_v3(db, work)
    guard = bundle.envelope.version_guard
    reads = {version.key: version for version in guard.read_versions}
    required = tuple(GraphVersion(AtomKey.from_token(head.ref), head.revision)
                     for head in work.reads) + tuple(
        GraphVersion(AtomKey.from_token(target.condition.current_checkpoint.ref),
                     target.condition.current_checkpoint.revision)
        for target in work.targets)
    if (len(reads) != len(guard.read_versions)
            or (guard.access_epoch, guard.delete_epoch)
               != (work.access_epoch, work.delete_epoch)
            or any(reads.get(version.key) != version for version in required)):
        raise C04AdoptionPlanHold("final C04 guard lacks its frozen content closure")
    domains = {item.domain for item in bundle.proposals}
    if len(bundle.proposals) != 3 or domains != {"d04", "d06", "d07"}:
        raise C04AdoptionPlanHold("final C04 proposal domains differ")
    writes = tuple(write for proposal in bundle.proposals
                   for write in proposal.typed_writes)
    if len({write.key for write in writes}) != len(writes):
        raise C04AdoptionPlanHold("duplicate final C04 write")
    kinds = {write.key.type_name for write in writes}
    if (len(writes) != 5 or kinds != {
            "d04.recollection_experience.v1", "d06.recollection.v1",
            "d06.recollection_projection.v1", "d07.selection_ticket.v1",
            "d07.current_interpretation.v1"}):
        raise C04AdoptionPlanHold("five-domain C04 experience writes incomplete")
    domain_kinds = {
        "d04": {"d04.recollection_experience.v1"},
        "d06": {"d06.recollection.v1", "d06.recollection_projection.v1"},
        "d07": {"d07.selection_ticket.v1", "d07.current_interpretation.v1"},
    }
    if any(proposal.envelope != bundle.envelope or
           {write.key.type_name for write in proposal.typed_writes}
               != domain_kinds[proposal.domain]
           for proposal in bundle.proposals):
        raise C04AdoptionPlanHold("final C04 writes differ from domain ownership")
    for write in writes:
        if (NamespaceId.from_key(write.key) != namespace
                or write.key.owner.kind != "activity"
                or write.key.owner.subject != work.activity_id
                or reads.get(write.key) != GraphVersion(write.key, 0)
                or db.execute("SELECT 1 FROM graph_atoms WHERE token=?",
                              (write.key.token,)).fetchone() is not None):
            raise C04AdoptionPlanHold("new C04 write lacks revision-zero absence")
    planned = tuple(sorted((PlannedWriteV3(
        write.key.token, canonical_v3_digest(write.value)) for write in writes),
        key=lambda item: item.ref))
    selection = next(write for write in writes
                     if write.key.type_name == "d07.selection_ticket.v1")
    interpretation = next(write for write in writes
                          if write.key.type_name == "d07.current_interpretation.v1")
    try:
        candidates, selected = select_c04_result_v3(
            work, result, focus_epoch=work.selection_ticket.focus_epoch)
        ticket = selected.selection_ticket
        selected_source_id = ticket.selected_candidate_ids[0]
        selected_source = source_key(*namespace.as_tuple, selected_source_id).token
        experience = next(write for write in writes
                          if write.key.type_name == "d04.recollection_experience.v1")
        recollection = next(write for write in writes
                            if write.key.type_name == "d06.recollection.v1")
        projection = next(write for write in writes
                          if write.key.type_name == "d06.recollection_projection.v1")
        expected_selection = D07DomainProvider.selection_choice_write(
            bundle.envelope, ticket,
            source_dependencies=(AtomKey.from_token(selected_source),))
        from .c04_interpretation_policy_v3 import read_installed_c04_interpretation_policy_v3
        from .d07_current_behavior_v1 import issue_current_association_interpretation_in_transaction_v3
        installed_policy, _policy_original = read_installed_c04_interpretation_policy_v3(
            db, namespace, prepared, installation_id=installation_id, manifest_digest=manifest_digest)
        issued = issue_current_association_interpretation_in_transaction_v3(
            db, work, result, ticket, installed_policy,
            binding_digest=binding.binding_digest, execution_id=binding.execution_id,
            activation_generation=binding.activation_generation)
        expected_interpretation = D07DomainProvider.current_interpretation_write(
            bundle.envelope, issued.candidate,
            source_dependencies=(AtomKey.from_token(selected_source),))
        target = next(target for target in work.targets
                      if target.source_ref == selected_source)
        mood_head = next(head for head in work.reads if head.ref == work.mood_ref)
        from .c04_d04_state_codec_v3 import decode_c04_mood_v3
        mood = decode_c04_mood_v3(work.mood_ref, mood_head.value)
        felt = _decode_recollection_experience(experience.value)
        context = RecollectionContext(
            (interpretation.key.token,), (experience.key.token,),
            tuple(recollection.value["self_understanding_refs"]))
        _current_self_understanding_reads(
            db, namespace, context.self_understanding_refs, reads)
        adapter = D06DomainAdapter(namespace)
        proposal, reconstruction = reconstruct_c04_result_v3(
            work, result, candidates=candidates, handoff=selected,
            adapter=adapter, context=context)
        expected_recollection = adapter.recollection_write(
            proposal, candidate_set_id=candidates.candidate_set_id,
            focus_epoch=ticket.focus_epoch, access_epoch=work.access_epoch,
            delete_epoch=work.delete_epoch)
        expected_projection = adapter.recollection_projection_write(
            reconstruction, experience)
        if (selection != expected_selection
                or interpretation != expected_interpretation
                or recollection != expected_recollection
                or projection != expected_projection
                or felt.experience_id != experience.key.name
                or felt.activity_id != work.activity_id
                or felt.recollection_ref != recollection.key.token
                or felt.memory_ref != selected_source
                or felt.memory_source_refs != (selected_source,)
                or felt.mood_ref != work.mood_ref
                or felt.mood_source_refs != mood.source_refs
                or felt.coupling_version != mood.coupling_version
                or felt.salience_interval != target.condition.conditioned_salience_interval
                or felt.tone_interval != target.condition.conditioned_tone_interval
                or felt.evidence_weight_delta != 0
                or bundle.experience_refs != (experience.key.token,)
                or bundle.choice_refs != (selection.key.token,)):
            raise ValueError("selected C04 result differs from domain writes")
    except (IndexError, KeyError, StopIteration, TypeError, ValueError) as exc:
        raise C04AdoptionPlanHold(
            "final D04/D06/D07 writes do not adopt the signed C04 result") from exc
    return C04AdoptionPlanV3(
        namespace, adoption_operation_id, work.input_digest, result.result_digest,
        work.algorithm_build_digest,
        "sha256:" + proof.terminal_receipt_digest,
        "sha256:" + canonical_digest(asdict(body)),
        "sha256:" + canonical_digest(asdict(cpu)),
        canonical_v3_digest(selection.value),
        canonical_v3_digest(interpretation.value),
        work.owner_epoch, work.access_epoch, work.delete_epoch,
        canonical_v3_digest(work.reads), planned,
        canonical_v3_digest(planned),
    )
