"""A sealed C02 candidate is inspectable but grants no resumed commit."""

from dataclasses import replace
import json

import pytest

from sylanne3.authority_service.v2_terminal_c02_recovery_contract import OriginalC02ResultKeyV1
from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    TerminalRecoveryReadFactV1, TerminalRecoveryReadRequestV1,
)
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, to_wire,
)
from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from sylanne3.runtime.c02_bundle_codec import c02_bundle_to_wire
from sylanne3.runtime.first_ingress_c02_identity import first_ingress_c02_consumer_operation_id_v1
from sylanne3.runtime.terminal_c02_recovery_candidate import (
    inspect_frozen_terminal_c02_candidate_v1,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle,
    DomainProposal, NamespaceId, OperationIdentity, QueryEpoch,
    SourceQualification, VersionGuard, canonical_digest,
)


def _bundle():
    namespace = NamespaceId("bot-a", "persona-a")
    source = AtomKey(Owner("persona", "bot-a", "persona-a"),
                     "memory.source.v1", "source-a")
    inputs = (source.token,)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity-a", None, "first-ingress-c02",
                          "first_ingress_c02", "initial-operation",
                          canonical_digest({"input_refs": list(inputs)})),
        AuthorityContext("worker-a", "d06", "capability-a", namespace,
                         ("persona",), "consolidation", ("self",),
                         "provider-policy-a", 1, 2),
        VersionGuard((GraphVersion(source, 3),),
                     (QueryEpoch(namespace, "all", 4),), 1, 0,
                     "catalogue-a", "scheme-a", "operator-a", "policy-a",
                     (), (), ()),
        SourceQualification(inputs, "observed", 1.0, 2.0,
                            "external_observation", "eligible", None, "actual"),
        inputs, "budget-a", 100.0, 200.0, "character-a", ("origin-a",),
    )
    episode = AtomKey(Owner("persona", "bot-a", "persona-a"),
                      "memory.episode.v1", "episode-a")
    job = AtomKey(Owner("persona", "bot-a", "persona-a"),
                  "runtime.job", "job-a")
    d06 = DomainProposal("d06", "d06.proposal.v1", "a" * 64, envelope,
                         (GraphWrite(episode, {"episode_id": "episode-a"},
                                     (source,)),),
                         DependencySet((GraphVersion(source, 3),), (), (), ()),
                         (), ())
    d11 = DomainProposal("d11", "d11.proposal.v1", "b" * 64, envelope,
                         (GraphWrite(job, {"job_id": "job-a", "phase": "completed"}),),
                         DependencySet(), (), ())
    return DomainBundle(envelope, (d06, d11), (), (), (), (), (), (), ())


def fixture():
    namespace = NamespaceId("bot-a", "persona-a")
    key = OriginalC02ResultKeyV1(
        "authority-a", "authority-namespace-a", namespace, "installation-a",
        "job-a", "original-operation-a", "acquire-a", "acquire-a", "call-a",
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
    )
    operation = first_ingress_c02_consumer_operation_id_v1(
        namespace=namespace, authority_id=key.authority_id,
        authority_namespace=key.authority_namespace,
        installation_id=key.installation_id, job_id=key.job_id,
        acquire_operation_id=key.acquire_operation_id,
        original_operation_id=key.original_operation_id, call_id=key.call_id,
        binding_digest=key.binding_digest,
        model_request_digest=key.model_request_digest,
    )
    original = _bundle()
    envelope = replace(original.envelope,
                       identity=replace(original.envelope.identity, operation_id=operation))
    bundle = replace(original, envelope=envelope,
                     proposals=tuple(replace(proposal, envelope=envelope)
                                     for proposal in original.proposals))
    request = WorkerModelResultReadRequestV1(
        key.authority_id, key.authority_namespace, namespace,
        key.installation_id, key.job_id, key.acquire_operation_id,
        key.original_operation_id, key.call_id, key.binding_digest,
        key.model_request_digest, operation, "read-attempt-a",
    )
    evidence = {
        "schema": "sylanne.first-ingress-c02-candidate.v1",
        "read_request": to_wire(request), "read_result_digest": "f" * 64,
        "original_intent_digest": key.original_intent_digest,
        "terminal_receipt_digest": key.terminal_receipt_digest,
        "observation_digest": key.observation_digest,
        "result_payload_digest": "1" * 64,
        "admin_policy_digest": "2" * 64,
        "installation_id": key.installation_id, "manifest_digest": "3" * 64,
        "source_ref": "source-a", "encoding_baseline_ref": "baseline-a",
        "call_id": key.call_id, "model_request_digest": key.model_request_digest,
        "authority_operation_id": key.acquire_operation_id,
        "binding_digest": key.binding_digest,
    }
    args = dict(
        namespace=namespace, consumer_operation_id=operation, original_key=key,
        candidate_schema=evidence["schema"], candidate_bundle_digest=bundle.digest,
        candidate_fence_attempt_id="fence-attempt-a",
        bundle_json=c02_bundle_to_wire(bundle), evidence_json=canonical_json(evidence),
        intent_digest=bundle.digest, intent_fence_attempt_id="fence-attempt-a",
    )
    return args, evidence


def test_frozen_candidate_binds_original_terminal_identity_without_grant():
    args, _ = fixture()
    candidate = inspect_frozen_terminal_c02_candidate_v1(**args)
    assert candidate.status == "frozen_candidate_unqualified"
    assert candidate.original_key == args["original_key"]
    assert candidate.bundle.digest == args["candidate_bundle_digest"]
    assert candidate.original_read_request.read_attempt_id == "read-attempt-a"
    assert not hasattr(candidate, "read_fact")
    assert not hasattr(candidate, "commit_permit")


def test_expired_frozen_deadline_cannot_be_extended_by_recovery_read_fact():
    args, _ = fixture()
    frozen = inspect_frozen_terminal_c02_candidate_v1(**args)
    assert frozen.bundle.envelope.deadline_utc == 100.0
    recovery_request = TerminalRecoveryReadRequestV1(
        args["original_key"], args["consumer_operation_id"], "recovery-attempt-a")
    fact = TerminalRecoveryReadFactV1(
        recovery_request, "4" * 64,
        args["original_key"].stable_result_digest, "5" * 64)
    assert fact.request != frozen.original_read_request
    assert not hasattr(fact, "read_request")  # cannot impersonate the worker fact port
    extended = replace(
        frozen.bundle.envelope, deadline_utc=101.0)
    changed = replace(
        frozen.bundle, envelope=extended,
        proposals=tuple(replace(proposal, envelope=extended)
                        for proposal in frozen.bundle.proposals))
    changed_args = dict(args, bundle_json=c02_bundle_to_wire(changed))
    with pytest.raises(ValueError, match="candidate unavailable"):
        inspect_frozen_terminal_c02_candidate_v1(**changed_args)


@pytest.mark.parametrize("field,replacement", [
    ("consumer_operation_id", "different-operation"),
    ("candidate_bundle_digest", "0" * 64),
    ("candidate_fence_attempt_id", "different-fence"),
])
def test_frozen_candidate_rejects_changed_graph_identity(field, replacement):
    args, _ = fixture()
    args[field] = replacement
    with pytest.raises(ValueError, match="candidate unavailable"):
        inspect_frozen_terminal_c02_candidate_v1(**args)


@pytest.mark.parametrize("field,replacement", [
    ("terminal_receipt_digest", "0" * 64),
    ("observation_digest", "0" * 64),
    ("binding_digest", "0" * 64),
    ("call_id", "other-call"),
])
def test_frozen_candidate_rejects_changed_terminal_evidence(field, replacement):
    args, evidence = fixture()
    evidence[field] = replacement
    args["evidence_json"] = canonical_json(evidence)
    with pytest.raises(ValueError, match="candidate unavailable"):
        inspect_frozen_terminal_c02_candidate_v1(**args)


def test_frozen_candidate_rejects_noncanonical_and_unexpected_evidence():
    args, evidence = fixture()
    args["evidence_json"] += " "
    with pytest.raises(ValueError, match="candidate unavailable"):
        inspect_frozen_terminal_c02_candidate_v1(**args)
    evidence["result_json"] = {"unauthorized": True}
    args["evidence_json"] = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    with pytest.raises(ValueError, match="candidate unavailable"):
        inspect_frozen_terminal_c02_candidate_v1(**args)
