"""Pure construction of the first D06 source and D11 encoding bundle."""

from __future__ import annotations

import hashlib

from ..domains.d06 import D06DomainAdapter, SourceAdmission
from ..memory_types import access_key, source_key
from ..runtime_contracts import CommandEnvelope, DependencySet, DomainBundle, DomainProposal
from .d11_types import (
    D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, RuntimeOutboxValue,
    job_graph_write, outbox_graph_write, runtime_job_key, runtime_outbox_key,
)
from .jobs import PersistentJob


def build_first_ingress_bundle(
    command: CommandEnvelope,
    job: PersistentJob,
    admission: SourceAdmission,
    *,
    source_identity: str,
    payload_ref: str,
    idempotency_key: str,
) -> DomainBundle:
    """Build the canonical first-ingress bundle from issued, immutable inputs.

    The caller owns observation, authorization, lease handling and sealing.
    ``source_identity`` is the host ingress SHA-256 identity of the source ref.
    """

    expected_identity = hashlib.sha256(
        ("sylanne3.host-ingress.v1:" + admission.source_id).encode("ascii")
    ).hexdigest()
    if source_identity != expected_identity:
        raise ValueError("first ingress source identity differs from admission")
    namespace = command.authority.namespace
    activity_id = "ingress-" + source_identity[:24]
    operation_id = "host-ingress-" + source_identity[:32]
    job_id = "encode-" + source_identity[:24]
    outbox_id = "encode-outbox-" + source_identity[:24]
    job_key = runtime_job_key(*namespace.as_tuple, activity_id, job_id)
    outbox_key = runtime_outbox_key(*namespace.as_tuple, activity_id, outbox_id)
    candidate = D06DomainAdapter(namespace).admit_source(admission)
    if (
        command.identity.activity_id != activity_id
        or command.identity.operation_id != operation_id
        or command.identity.effect_id is not None
        or command.source_qualification != candidate.qualification
        or command.input_refs != candidate.qualification.source_refs
    ):
        raise ValueError("trusted ingress authorization changed host identity or scope")

    source = source_key(*namespace.as_tuple, admission.source_id)
    access = access_key(*namespace.as_tuple, admission.source_id)
    reads = {item.key: item for item in command.version_guard.read_versions}
    if (set(reads) != {source, access, job_key, outbox_key}
            or len(reads) != len(command.version_guard.read_versions)
            or any(item.revision != 0 for item in reads.values())):
        raise ValueError("first ingress requires complete revision-0 source/runtime proofs")
    if (
        job.job_id != job_id
        or job.operation_id != operation_id
        or job.activity_id != activity_id
        or job.effect_id is not None
        or (job.bot_id, job.persona_id) != namespace.as_tuple
        or job.phase != "queued"
        or job.work_kind != "d06.encode_source"
        or job.budget_ref != command.parent_budget_lease_ref
    ):
        raise ValueError("D11 issuer job differs from ingress encoding work")

    d06_proposal = D06DomainAdapter(namespace).compile_source_ingress(command, admission)
    outbox_value = RuntimeOutboxValue(
        namespace.bot_id, namespace.persona_id, activity_id, operation_id,
        None, outbox_id, job_id, job_key.token, payload_ref,
        idempotency_key, "pending", command.authority.activation_generation,
    )
    d11_proposal = DomainProposal(
        "d11", D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, command,
        (job_graph_write(job), outbox_graph_write(outbox_value, job_key)),
        DependencySet(current_invalidation=(reads[job_key],)),
        ("source-encoding:" + source_identity,), (),
    )
    return DomainBundle(
        command, (d06_proposal, d11_proposal), (), (), (), (),
        (idempotency_key,), (job_key.token,), (outbox_key.token,),
    )


__all__ = ("build_first_ingress_bundle",)
