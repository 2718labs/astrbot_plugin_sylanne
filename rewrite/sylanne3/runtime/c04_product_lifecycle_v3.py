"""Typed C04 job recovery from an independently reread Authority journal.

Leasing or waking this job never grants execution rights. The production
worker must inspect the same immutable binding before every possible start.
"""

from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from ..authority_service.internal_work_contract import InternalWorkTerminalProofV1, InternalWorkTerminalV2
from ..authority_service.internal_work_service import InternalWorkJournalInspectionV1
from ..authority_service.contract import JournalHead
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1
from .c04_prepare_service_v3 import c04_prepare_job_id_v3
from .c04_cpu_quote_policy import C04_INTERNAL_CPU_WORK_KIND
from .jobs import PersistentJob, get_job, checkpoint_job, transition_job, wake_job


class C04ProductLifecycleHold(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class C04ProductProgressV3:
    operation_id: str
    binding_digest: str
    status: str
    job_id: str
    terminal_proof_digest: str | None = None
    adoption_receipt_digest: str | None = None


def c04_terminal_proof_from_inspection_v3(
    inspection: InternalWorkJournalInspectionV1,
) -> InternalWorkTerminalProofV1 | None:
    if type(inspection) is not InternalWorkJournalInspectionV1:
        raise C04ProductLifecycleHold("installed Authority journal inspection required")
    if inspection.terminal is None:
        if (inspection.claim is None) != (inspection.claim_append is None):
            raise C04ProductLifecycleHold("Authority claim and journal append differ")
        if inspection.terminal_append is not None:
            raise C04ProductLifecycleHold("terminal append without terminal")
        return None
    if (type(inspection.terminal) is not InternalWorkTerminalV2
            or inspection.claim is None or inspection.claim_append is None
            or inspection.terminal_append is None):
        raise C04ProductLifecycleHold("V3 original has no complete signed terminal chain")
    return InternalWorkTerminalProofV1(
        inspection.binding, inspection.claim, inspection.terminal,
        inspection.claim_append.receipt_ref, inspection.claim_append.content_digest,
        inspection.terminal_append.receipt_ref, inspection.terminal_append.content_digest,
        JournalHead(inspection.terminal_append.journal_id, inspection.terminal_append.sequence,
                    inspection.terminal_append.chain_digest))


def read_original_c04_product_job_v3(db: sqlite3.Connection, namespace: NamespaceId,
                                    prepared: C04InternalWorkPreparedV1) -> PersistentJob:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise C04ProductLifecycleHold("W01 product job transaction required")
    binding = prepared.binding
    job = get_job(db, c04_prepare_job_id_v3(namespace, binding.operation_id))
    core = {"schema": "c04.prepared-job-continuation.v3",
            "operation_id": binding.operation_id,
            "execution_id": binding.execution_id,
            "binding_digest": binding.binding_digest,
            "input_digest": binding.input_digest,
            "prepared_digest": prepared.prepared_digest,
            "algorithm_id": binding.algorithm_ref,
            "algorithm_build_digest": binding.algorithm_build_digest,
            "activation_generation": binding.activation_generation,
            "recovery_policy": "inspect_original_binding_before_execution"}
    if job.continuation.get("schema") == "c04.prepared-job-continuation.v4":
        core = {"schema": "c04.prepared-job-continuation.v4", "operation_id": binding.operation_id,
            "execution_id": binding.execution_id, "prepared_ref": "graph_c04_internal_work_prepared_v1/" + binding.operation_id,
            "frozen_input_ref": "graph_c04_association_inputs_v3/" + binding.operation_id,
            "algorithm_id": binding.algorithm_ref, "algorithm_build_digest": binding.algorithm_build_digest,
            "activation_generation": binding.activation_generation,
            "recovery_policy": "inspect_original_binding_before_execution"}
    if ((job.bot_id, job.persona_id, job.operation_id, job.activity_id,
         job.budget_ref, job.work_kind) !=
        (*namespace.as_tuple, binding.operation_id, binding.activity_id,
         binding.parent_budget_lease_ref, C04_INTERNAL_CPU_WORK_KIND)
            or any(job.continuation.get(name) != value for name, value in core.items())):
        raise C04ProductLifecycleHold("C04 original recovery job identity changed")
    return job


def wake_inspected_c04_job_v3(db, namespace, prepared, inspection):
    job = read_original_c04_product_job_v3(db, namespace, prepared)
    if (type(inspection) is not InternalWorkJournalInspectionV1
            or inspection.binding != prepared.binding):
        raise C04ProductLifecycleHold("wake requires the same original Authority inspection")
    if job.phase == "waiting":
        # Waking schedules another inspection only, never a replacement claim.
        observation = canonical_digest(inspection)
        job = wake_job(db, job.job_id,
            "c04-wake-" + canonical_digest((job.job_id, observation))[:48],
            canonical_digest(("c04.inspected-wake.v3", job.job_id, observation)))
    return job


def record_c04_job_observation_v3(db, namespace, prepared, inspection,
                                  *, holder, fence):
    job = read_original_c04_product_job_v3(db, namespace, prepared)
    if inspection.binding != prepared.binding:
        raise C04ProductLifecycleHold("C04 journal changed original binding")
    proof = c04_terminal_proof_from_inspection_v3(inspection)
    status = ("terminal_observed" if proof is not None else
              "claim_only_unknown" if inspection.claim is not None else "unclaimed")
    continuation = dict(job.continuation)
    continuation.update({"last_observation_status": status,
                         "journal_observation_digest": canonical_digest(inspection)})
    if proof is not None:
        continuation["terminal_proof_digest"] = canonical_digest(proof)
    checkpoint_job(db, job.job_id, holder, fence,
                   continuation=continuation, usage=job.usage)
    if status == "claim_only_unknown":
        return transition_job(db, job.job_id, holder, fence,
                              target_phase="waiting", wake_condition={
                                  "kind": "c04.original-terminal-inspection.v3",
                                  "binding_digest": prepared.binding.binding_digest,
                                  "execution_id": prepared.binding.execution_id})
    return get_job(db, job.job_id)


def finish_c04_adoption_job_v3(db, namespace, prepared, *, holder, fence,
                              plan_digest, receipt_digest, actual_cpu_ms):
    job = read_original_c04_product_job_v3(db, namespace, prepared)
    continuation = dict(job.continuation)
    continuation.update({"product_status": "adopted", "adoption_plan_digest": plan_digest,
                         "adoption_receipt_digest": receipt_digest})
    checkpoint_job(db, job.job_id, holder, fence, continuation=continuation,
                   usage={**job.usage, "cpu_ms": actual_cpu_ms})
    return transition_job(db, job.job_id, holder, fence,
                          target_phase="completed", result_ref="c04-adoption:" + receipt_digest)


__all__ = ["C04ProductLifecycleHold", "C04ProductProgressV3",
           "c04_terminal_proof_from_inspection_v3", "read_original_c04_product_job_v3",
           "wake_inspected_c04_job_v3", "record_c04_job_observation_v3",
           "finish_c04_adoption_job_v3"]
