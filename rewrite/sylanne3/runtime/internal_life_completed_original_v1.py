"""Completed Life originals for a trusted, transaction-scoped maintenance reader.

This authenticates historical evidence, including the actual completed job.
It neither issues a C09 retained original nor grants deletion/current-use rights.
The returned domain content must remain inside the caller's frozen transaction;
it is not a sanitized export. Core terminal/consumed obligations and complete
carrier inventory remain the installed C09 issuer's separate responsibility.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
from typing import TYPE_CHECKING

from ..runtime_contracts import NamespaceId, CommitReceipt, canonical_serialize

if TYPE_CHECKING:
    from ..authority_service.internal_life_model_result_contract_v2 import InternalLifeModelResultReadV2
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from .internal_life_content_adoption_v1 import InternalLifeContentProvenanceV1
    from .internal_life_content_preparation_v1 import InternalLifeContentPreparedV1
    from .internal_life_worker_binding_v2 import InternalLifeWorkerBindingV2
    from .issuers import D11BudgetJobIssuer
    from .jobs import PersistentJob
    from .model_cost_settlement import OriginalModelCostCommitV1


@dataclass(frozen=True, slots=True)
class CompletedInternalLifeOriginalV1:
    """Authenticated input evidence; constructing this value confers no rights."""

    prepared: InternalLifeContentPreparedV1
    binding: InternalLifeWorkerBindingV2
    intent: ModelEgressIntentV1
    delivered: InternalLifeModelResultReadV2
    cost: OriginalModelCostCommitV1
    validated_proof: InternalLifeContentProvenanceV1
    receipt: CommitReceipt
    job: PersistentJob


def read_completed_internal_life_original_v1(
    db: sqlite3.Connection, *, namespace: NamespaceId,
    issuer: D11BudgetJobIssuer, job_id: str,
) -> CompletedInternalLifeOriginalV1:
    """Read real signed originals under the caller's existing SQL snapshot.

    The installed caller must supply its actual D11 issuer, not a caller-supplied
    verifier callback. Missing adoption, running/unknown jobs, unsettled cost or
    inconsistent four-member history fail closed. Historical source invalidation
    does not become a current-use permission through this reader.
    """
    from .issuers import D11BudgetJobIssuer
    from .internal_life_content_worker_v2 import (
        read_committed_internal_life_request_v2, read_life_worker_original_v2,
    )
    from .internal_life_paid_result_v2 import (
        read_life_paid_original_v2, read_life_cost_commit_v2,
    )
    from .internal_life_content_adoption_v1 import (
        PROVENANCE, content_keys_v1, decode_content_v1,
        validate_content_history_v1,
    )
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.v2_model_egress_wire import from_wire
    from ..authority_service.internal_life_model_result_contract_v2 import (
        InternalLifeModelResultReadV2, internal_life_result_from_wire_v2,
    )
    from ..model_broker.internal_life_content_v1 import thaw_internal_life_content_request_v1
    from .d04_root_original_store_v1 import _receipt
    from .d11_types import job_graph_write
    from .jobs import get_job

    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(issuer) is not D11BudgetJobIssuer
            or type(job_id) is not str or not job_id):
        raise ValueError('Life completed original requires actual SQL snapshot and installed D11 issuer')
    prepared, binding, _ = read_committed_internal_life_request_v2(
        db, namespace=namespace, issuer=issuer, job_id=job_id)
    job = get_job(db, job_id)
    if (prepared.namespace != namespace or prepared.job_id != job_id
            or (job.bot_id, job.persona_id, job.activity_id, job.operation_id)
            != (*namespace.as_tuple, prepared.activity_id, prepared.prepare_operation_id)
            or job.phase != 'completed' or job.result_ref != prepared.call_id
            or job.fence != 1 or job.cancel_epoch != 0
            or job.lease_holder is not None or job.lease_expires_utc is not None):
        raise ValueError('Life running/unknown or incomplete job cannot be retained as completed')
    job_write = job_graph_write(job)
    head = db.execute(
        'SELECT revision,value,valid FROM graph_atoms WHERE token=?',
        (job_write.key.token,),
    ).fetchone()
    if head != (3, canonical_serialize(job_write.value), 1):
        raise ValueError('Life completed SQL job differs from its actual Graph head')

    proof_key = content_keys_v1(prepared.episode_ref)[1]
    row = db.execute(
        'SELECT value,valid FROM graph_history WHERE token=? AND revision=1',
        (proof_key.token,),
    ).fetchone()
    if row is None or row[1] != 1:
        raise ValueError('Life completed job lacks durable content provenance')
    proof = decode_content_v1(PROVENANCE, json.loads(row[0]))
    if (proof.trace.namespace != namespace or proof.trace.job_id != job_id
            or proof.trace.call_id != prepared.call_id
            or proof.trace.episode_ref != prepared.episode_ref):
        raise ValueError('Life completed historical provenance scope differs')
    validated = validate_content_history_v1(db, proof, issuer)

    sealed = read_life_worker_original_v2(
        db, namespace=namespace, issuer=issuer, kind='call', job_id=job_id)
    if sealed is None:
        raise ValueError('Life completed original lacks signed call')
    intent = from_wire(sealed['intent'], ModelEgressIntentV1)
    raw = read_life_paid_original_v2(db, namespace, issuer, 'result', job_id)
    if raw is None:
        raise ValueError('Life completed original lacks signed delivered result')
    delivered = internal_life_result_from_wire_v2(raw, InternalLifeModelResultReadV2)
    frozen = thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json))
    delivered.require_original(intent, prepared, frozen, binding)
    cost = read_life_cost_commit_v2(
        db, namespace=namespace, issuer=issuer, prepared=prepared,
        intent=intent, terminal=delivered.terminal_receipt)
    receipt = _receipt(db, namespace, proof.trace.producing_operation_id)
    return CompletedInternalLifeOriginalV1(
        prepared, binding, intent, delivered, cost, validated, receipt, job)
