"""W01 C04 V3 plan from signed work and already settled D02/D11 originals.

The returned plan names the exact new D04/D06/D07 writes and the two paid
cost originals. W01 authenticates proposal issuers and commits all new writes
with its Owner fence and revision-zero read set in one graph transaction.
"""

from __future__ import annotations

from dataclasses import asdict
import sqlite3

from ..authority_service.installed_c04_executor_v3 import (
    decode_completed_c04_output_v3,
)
from ..authority_service.internal_work_contract import InternalWorkTerminalProofV1
from ..authority_service.internal_work_service import (
    AuthorityInternalWorkVerifiedReceiptV1,
)
from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1
from ..domains.d04.affect import (
    _decode_mood, _decode_recollection_experience, _decode_understanding,
)
from ..domains.d06 import D06DomainAdapter, RecollectionContext
from ..domains.d07 import (
    CurrentInterpretationCandidate, D07DomainProvider, EvidenceStatus, Stance,
)
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import source_key
from ..runtime_contracts import DomainBundle, NamespaceId, canonical_digest
from .c04_frozen_association_original_v3 import (
    read_c04_frozen_association_original_v3,
    verify_current_association_input_heads_v3,
)
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_result_adoption_v3 import reconstruct_c04_result_v3, select_c04_result_v3
from .c04_v3_contracts import (
    C04AdoptionPlanV3, GraphHeadV3, PlannedWriteV3, canonical_v3_digest,
)
from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1


class C04AdoptionPlanHold(ValueError):
    """The paid execution or final five-domain proposal differs."""


def _current_self_understanding_reads(
    db: sqlite3.Connection, namespace: NamespaceId,
    refs: tuple[str, ...], reads: dict[AtomKey, GraphVersion],
) -> tuple[GraphHeadV3, ...]:
    """Read the current D04 originals named by the final W01 guard.

    These optional adoption-context originals are outside the frozen CPU
    association closure and must not be inserted into that immutable input.
    """
    heads = []
    for ref in refs:
        key = AtomKey.from_token(ref)
        version = reads.get(key)
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?", (ref, *namespace.as_tuple),
        ).fetchone()
        if (NamespaceId.from_key(key) != namespace
                or key.type_name != "d04.self_understanding.v1"
                or key.owner.kind != "persona"
                or version is None or version.revision < 1
                or row is None or row[0] != version.revision or row[2] != 1):
            raise ValueError("C04 self understanding lacks its current positive read")
        head = GraphHeadV3(ref, row[0], True, row[1])
        understanding = _decode_understanding(head.value)
        if (understanding.understanding_id != key.name
                or understanding.revision != head.revision):
            raise ValueError("C04 current self understanding identity differs")
        heads.append(head)
    return tuple(heads)


def build_c04_adoption_plan_v3(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
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
    work = read_c04_frozen_association_original_v3(db, namespace, binding)
    if work is None:
        raise C04AdoptionPlanHold("frozen C04 V3 input is absent")
    result = decode_completed_c04_output_v3(binding, proof.terminal)
    result.validate_input(work)
    if (verified.proof_digest != canonical_digest(proof)
            or verified.operation_id != operation_id
            or verified.input_digest != binding.input_digest
            or verified.actual_cpu_ms != proof.terminal.actual_cpu_ms
            or verified.terminal_receipt_digest != proof.terminal_receipt_digest
            or verified.status != "completed"
            or not verified.component_completed
            or bundle.envelope.identity.operation_id != operation_id
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
    verify_current_association_input_heads_v3(db, work)
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
        namespace, operation_id, work.input_digest, result.result_digest,
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


__all__ = ["C04AdoptionPlanHold", "build_c04_adoption_plan_v3"]
