"""A v2 seal retains the original quote and business UTC bounds."""

from dataclasses import asdict, replace
import json

import pytest

from rewrite.tests.alpha1.contracts.test_terminal_c02_recovery_candidate import fixture
from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    TerminalRecoveryReadFactV1, TerminalRecoveryReadRequestV1,
)
from sylanne3.runtime.c02_bundle_codec import c02_bundle_from_wire, c02_bundle_to_wire
from sylanne3.runtime.issuers import (
    D06_FIRST_INGRESS_C02_WORK_KIND, ResourceQuote,
    d06_first_ingress_c02_quote_id,
)
from sylanne3.runtime.terminal_c02_recovery_candidate_v2 import (
    FrozenTerminalC02CandidateV2, inspect_frozen_terminal_c02_candidate_v2,
    recovery_fact_matches_frozen_v2,
)
from sylanne3.runtime_contracts import (
    VersionedRef, canonical_digest, canonical_serialize,
)


def _case():
    args, _ = fixture()
    old = c02_bundle_from_wire(args["bundle_json"])
    key = args["original_key"]
    operation = args["consumer_operation_id"]
    quote_id = d06_first_ingress_c02_quote_id(key.namespace, operation)
    guard = replace(old.envelope.version_guard,
                    resource_lease_versions=(VersionedRef(quote_id, 1),))
    envelope = replace(old.envelope, version_guard=guard,
                       deadline_utc=130.0, monotonic_deadline=230.0)
    bundle = replace(old, envelope=envelope,
                     proposals=tuple(replace(proposal, envelope=envelope)
                                     for proposal in old.proposals))
    quote = ResourceQuote(
        quote_id, 1, *key.namespace.as_tuple,
        envelope.identity.activity_id, operation, None,
        envelope.parent_budget_lease_ref, D06_FIRST_INGRESS_C02_WORK_KIND,
        "snapshot-a", 130.0, "resource-a", None, (), (),
        {"cpu_ms": 3}, envelope.authority.worker_fence, 130.0)
    seal = FrozenTerminalC02CandidateV2(
        key, bundle.digest, quote_id, 1, canonical_digest(asdict(quote)),
        90.0, 100.0, 130.0, 50.0, 135.0)
    read_request = TerminalRecoveryReadRequestV1(
        key, operation, "recovery-attempt-a")
    fact = TerminalRecoveryReadFactV1(
        read_request, "4" * 64, key.stable_result_digest, "5" * 64)
    return dict(namespace=key.namespace, operation_id=operation, seal=seal,
                bundle_json=c02_bundle_to_wire(bundle),
                quote_json=canonical_serialize(asdict(quote))), fact


def test_v2_seal_accepts_expired_worker_before_independent_business_deadline():
    args, fact = _case()
    inspection = inspect_frozen_terminal_c02_candidate_v2(**args)
    assert inspection.bundle.digest == args["seal"].bundle_digest
    assert inspection.status == "frozen_v2_unqualified"
    assert recovery_fact_matches_frozen_v2(
        seal=args["seal"], fact=fact, trusted_now_utc=101.0)
    assert not hasattr(args["seal"], "commit_permit")


def test_v2_seal_rejects_deadline_extension_and_quote_replacement():
    args, _ = _case()
    seal = args["seal"]
    with pytest.raises(ValueError, match="admin or grant"):
        replace(seal, business_deadline_utc=141.0)
    with pytest.raises(ValueError, match="quote identity"):
        replace(seal, quote_id="another-quote")
    bundle = c02_bundle_from_wire(args["bundle_json"])
    changed = replace(bundle.envelope, deadline_utc=131.0)
    args["bundle_json"] = c02_bundle_to_wire(replace(
        bundle, envelope=changed,
        proposals=tuple(replace(item, envelope=changed)
                        for item in bundle.proposals)))
    with pytest.raises(ValueError, match="quote or bundle differs"):
        inspect_frozen_terminal_c02_candidate_v2(**args)


def test_v1_candidate_cannot_be_reinterpreted_as_v2():
    old, _ = fixture()
    args, _ = _case()
    args["bundle_json"] = old["bundle_json"]
    with pytest.raises(ValueError, match="quote or bundle differs"):
        inspect_frozen_terminal_c02_candidate_v2(**args)


def test_v2_changed_quote_bytes_or_grant_bound_hold():
    args, _ = _case()
    quote = json.loads(args["quote_json"])
    quote["ceiling"]["cpu_ms"] = 4
    args["quote_json"] = canonical_serialize(quote)
    with pytest.raises(ValueError, match="quote or bundle differs"):
        inspect_frozen_terminal_c02_candidate_v2(**args)
    with pytest.raises(ValueError, match="admin or grant"):
        replace(args["seal"], root_grant_valid_until_utc=129.0)


def test_v2_fact_rejects_old_worker_window_and_late_or_changed_identity():
    args, fact = _case()
    seal = args["seal"]
    assert not recovery_fact_matches_frozen_v2(
        seal=seal, fact=fact, trusted_now_utc=99.0)
    assert not recovery_fact_matches_frozen_v2(
        seal=seal, fact=fact, trusted_now_utc=130.0)
    changed_request = replace(fact.request, read_attempt_id="other-attempt")
    changed_fact = replace(fact, request=changed_request)
    # Attempt identity may vary while the original result and operation cannot.
    assert recovery_fact_matches_frozen_v2(
        seal=seal, fact=changed_fact, trusted_now_utc=101.0)
    changed_key = replace(fact.request.original_key, call_id="other-call")
    other = replace(fact.request, original_key=changed_key)
    other_fact = replace(fact, request=other,
                         result_digest=changed_key.stable_result_digest)
    assert not recovery_fact_matches_frozen_v2(
        seal=seal, fact=other_fact, trusted_now_utc=101.0)
