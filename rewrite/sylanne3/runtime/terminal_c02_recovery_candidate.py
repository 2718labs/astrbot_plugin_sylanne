"""Passive inspection of a sealed first-ingress C02 graph candidate.

This decoder proves internal identity consistency only. It cannot authenticate
the Authority result body, grant a new read, or resume a graph commit.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re

from ..authority_service.v2_terminal_c02_recovery_contract import OriginalC02ResultKeyV1
from ..authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, from_wire,
)
from ..contracts import canonical_json
from ..runtime_contracts import DomainBundle, NamespaceId, canonical_digest
from .c02_bundle_codec import c02_bundle_from_wire, c02_bundle_to_wire
from .first_ingress_c02_identity import first_ingress_c02_consumer_operation_id_v1


_SCHEMA = "sylanne.first-ingress-c02-candidate.v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_EVIDENCE_FIELDS = frozenset({
    "schema", "read_request", "read_result_digest",
    "original_intent_digest", "terminal_receipt_digest",
    "observation_digest", "result_payload_digest",
    "admin_policy_digest", "installation_id", "manifest_digest",
    "source_ref", "encoding_baseline_ref", "call_id",
    "model_request_digest", "authority_operation_id", "binding_digest",
})


@dataclass(frozen=True, slots=True)
class FrozenTerminalC02CandidateV1:
    bundle: DomainBundle
    original_key: OriginalC02ResultKeyV1
    original_read_request: WorkerModelResultReadRequestV1
    evidence_digest: str
    status: str = "frozen_candidate_unqualified"


def inspect_frozen_terminal_c02_candidate_v1(
    *, namespace: NamespaceId, consumer_operation_id: str,
    original_key: OriginalC02ResultKeyV1,
    candidate_schema: str, candidate_bundle_digest: str,
    candidate_fence_attempt_id: str, bundle_json: str, evidence_json: str,
    intent_digest: str, intent_fence_attempt_id: str,
) -> FrozenTerminalC02CandidateV1:
    """Reject changed bytes and identities before a future Authority handoff.

    Inputs must come from a trusted, consistent graph read. This function
    deliberately returns no read fact or commit permission.
    """
    if type(namespace) is not NamespaceId or type(original_key) is not OriginalC02ResultKeyV1:
        raise TypeError("typed terminal C02 namespace and original key required")
    try:
        expected_operation = first_ingress_c02_consumer_operation_id_v1(
            namespace=namespace, authority_id=original_key.authority_id,
            authority_namespace=original_key.authority_namespace,
            installation_id=original_key.installation_id,
            job_id=original_key.job_id,
            acquire_operation_id=original_key.acquire_operation_id,
            original_operation_id=original_key.original_operation_id,
            call_id=original_key.call_id,
            binding_digest=original_key.binding_digest,
            model_request_digest=original_key.model_request_digest,
        )
        if (namespace != original_key.namespace
                or consumer_operation_id != expected_operation
                or candidate_schema != _SCHEMA
                or type(candidate_bundle_digest) is not str
                or _HEX.fullmatch(candidate_bundle_digest) is None
                or candidate_bundle_digest != intent_digest
                or type(candidate_fence_attempt_id) is not str
                or candidate_fence_attempt_id != intent_fence_attempt_id):
            raise ValueError("frozen C02 graph identity differs")
        bundle = c02_bundle_from_wire(bundle_json)
        if (c02_bundle_to_wire(bundle) != bundle_json
                or bundle.digest != candidate_bundle_digest
                or bundle.envelope.identity.operation_id != consumer_operation_id
                or bundle.envelope.authority.namespace != namespace):
            raise ValueError("frozen C02 bundle differs")
        evidence = json.loads(evidence_json)
        if (type(evidence) is not dict or set(evidence) != _EVIDENCE_FIELDS
                or canonical_json(evidence) != evidence_json
                or evidence["schema"] != candidate_schema):
            raise ValueError("frozen C02 evidence wire differs")
        read = from_wire(evidence["read_request"], WorkerModelResultReadRequestV1)
        if (read.namespace != namespace
                or read.consumer_operation_id != consumer_operation_id
                or (read.authority_id, read.authority_namespace,
                    read.installation_id, read.job_id,
                    read.original_operation_id, read.acquire_operation_id,
                    read.call_id, read.binding_digest,
                    read.model_request_digest) !=
                   (original_key.authority_id, original_key.authority_namespace,
                    original_key.installation_id, original_key.job_id,
                    original_key.original_operation_id,
                    original_key.acquire_operation_id, original_key.call_id,
                    original_key.binding_digest, original_key.model_request_digest)
                or (evidence["original_intent_digest"],
                    evidence["observation_digest"],
                    evidence["terminal_receipt_digest"]) !=
                   (original_key.original_intent_digest,
                    original_key.observation_digest,
                    original_key.terminal_receipt_digest)
                or (evidence["installation_id"], evidence["call_id"],
                    evidence["model_request_digest"],
                    evidence["authority_operation_id"],
                    evidence["binding_digest"]) !=
                   (read.installation_id, read.call_id,
                    read.model_request_digest, read.acquire_operation_id,
                    read.binding_digest)
                or any(type(evidence[name]) is not str
                       or _HEX.fullmatch(evidence[name]) is None
                       for name in ("read_result_digest", "result_payload_digest",
                                    "admin_policy_digest", "manifest_digest"))):
            raise ValueError("frozen C02 result identity differs")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("frozen terminal C02 candidate unavailable") from exc
    return FrozenTerminalC02CandidateV1(
        bundle, original_key, read, canonical_digest(evidence),
    )


__all__ = ("FrozenTerminalC02CandidateV1", "inspect_frozen_terminal_c02_candidate_v1")
