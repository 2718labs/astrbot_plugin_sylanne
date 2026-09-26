"""C02 v2 first-seal quote remains historical after the worker lease ends."""

from dataclasses import asdict, replace
import sqlite3
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_terminal_c02_recovery_contract import OriginalC02ResultKeyV1
from sylanne3.host.authority_profile import AdminD06FirstIngressC02Policy
from sylanne3.runtime.c02_bundle_codec import c02_bundle_to_wire
from sylanne3.runtime import install_schema as install_runtime_schema
from sylanne3.runtime.budget import BudgetLease, create_budget_lease
from sylanne3.runtime.first_ingress_c02_identity import first_ingress_c02_consumer_operation_id_v1
from sylanne3.runtime import issuers
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D06FirstIngressC02QuotePolicy, IssuerAuthorityDenied,
    ResourceQuote, build_runtime_issuers, install_schema,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle,
    DomainProposal, NamespaceId, OperationIdentity, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest,
    canonical_serialize,
)


def _case():
    namespace = NamespaceId("bot", "persona")
    fields = dict(
        authority_id="authority", authority_namespace="authority-ns",
        namespace=namespace, installation_id="installation", job_id="job",
        original_operation_id="original-op", acquire_operation_id="acquire-op",
        original_model_operation_id="acquire-op", call_id="call",
        binding_digest="a" * 64, model_request_digest="b" * 64,
        original_intent_digest="c" * 64, observation_digest="d" * 64,
        terminal_receipt_digest="e" * 64,
    )
    key = OriginalC02ResultKeyV1(**fields)
    operation = first_ingress_c02_consumer_operation_id_v1(
        namespace=namespace, authority_id=key.authority_id,
        authority_namespace=key.authority_namespace,
        installation_id=key.installation_id, job_id=key.job_id,
        acquire_operation_id=key.acquire_operation_id,
        original_operation_id=key.original_operation_id,
        call_id=key.call_id, binding_digest=key.binding_digest,
        model_request_digest=key.model_request_digest)
    quote_id = issuers.d06_first_ingress_c02_quote_id(namespace, operation)
    identity = OperationIdentity(
        "activity", None, "attempt", "first_ingress_c02", operation,
        canonical_digest({"input_refs": []}))
    authority = AuthorityContext(
        "worker", "d06", "capability", namespace, ("event",),
        "encode", ("internal",), "provider-policy", 1, 1)
    guard = VersionGuard(
        (), (), 0, 0, "catalogue", "scheme", "operator", "policy",
        (), (), (VersionedRef(quote_id, 1),))
    source = SourceQualification(
        (), "reported", None, 1.0, "external_report", "qualified",
        None, "not_applicable")
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity, authority, guard, source, (), "lease",
        120.0, 120.0, "interval", ())
    deps = DependencySet((), (), (), ())
    proposals = tuple(DomainProposal(
        domain, "proposal", "f" * 64, envelope, (), deps, (), ())
        for domain in ("d06", "d11"))
    bundle = DomainBundle(envelope, proposals, (), (), (), (), (), (), ())
    admin = AdminD06FirstIngressC02Policy(
        40.0, {"cpu_ms": 3}, "snapshot", "resource")
    db = sqlite3.connect(":memory:")
    install_runtime_schema(db)
    install_schema(db)
    create_budget_lease(
        db, BudgetLease("lease", None, "bot", "persona", "USD",
                        {"cpu_ms": 10}, {}, {}, {}, 1, "active"),
        "create-lease", "1" * 64)
    d02, d11 = build_runtime_issuers(b"k" * 32)
    grant = BudgetLeaseGrant(
        "grant", 1, "bot", "persona", "lease", "USD",
        {"cpu_ms": 10}, ("d06.first_ingress_c02",), 150.0,
        "provider-policy")
    d11.issue_budget_grant(db, grant)
    policy = D06FirstIngressC02QuotePolicy(
        issuers._d06_c02_policy_id(key.installation_id, grant, operation),
        "bot", "persona", key.installation_id, grant.grant_id,
        grant.version, grant.lease_id, grant.policy_ref, {"cpu_ms": 3},
        admin.deadline_after_seconds, admin.snapshot_ref, admin.resource_ref,
        key.job_id, "activity", key.original_operation_id,
        key.acquire_operation_id, key.call_id, key.binding_digest,
        key.model_request_digest, "model-cost", "0" * 64,
        "source", "baseline", 1, operation)
    pre_quote = replace(envelope, version_guard=replace(
        guard, resource_lease_versions=()))
    snapshot_ref, resource_ref = issuers._d06_c02_quote_refs(policy, pre_quote)
    quote = ResourceQuote(
        quote_id, 1, "bot", "persona", "activity", operation, None,
        "lease", "d06.first_ingress_c02", snapshot_ref, 120.0,
        resource_ref, None, (), (), {"cpu_ms": 3}, 1, 120.0)
    d02._install_d06_c02_policy(db, policy)
    d02.issue_quote(db, quote)
    db.commit()
    return db, d11, key, bundle, admin, quote


def test_first_seal_requires_transaction_and_historical_read_rejects_tampering(monkeypatch):
    db, d11, key, bundle, admin, quote = _case()
    origin = issuers._D06C02Origin(
        key.job_id, "activity", key.original_operation_id,
        key.acquire_operation_id, key.call_id, key.binding_digest,
        key.model_request_digest, "model-cost", "0" * 64,
        "source", bundle.envelope.identity.operation_id, key.installation_id)
    monkeypatch.setattr(issuers, "_d06_c02_origin", lambda *args, **kwargs: origin)
    monkeypatch.setattr(issuers, "get_job", lambda *args: SimpleNamespace(
        lease_expires_utc="1970-01-01T00:01:40Z"))
    monkeypatch.setattr(d11, "issue_d06_first_ingress_c02_quote",
                        lambda *args, **kwargs: quote)
    with pytest.raises(IssuerAuthorityDenied, match="transaction"):
        d11.issue_d06_first_ingress_c02_quote_at_first_seal_v2(
            db, bundle, admin, original_key=key, sealed_at_utc=90.0)
    db.execute("BEGIN IMMEDIATE")
    try:
        signed, seal = d11.issue_d06_first_ingress_c02_quote_at_first_seal_v2(
            db, bundle, admin, original_key=key, sealed_at_utc=90.0)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    assert signed == quote
    quote_json = canonical_serialize(asdict(quote))
    bundle_json = c02_bundle_to_wire(bundle)
    assert d11.verify_original_d06_first_ingress_c02_quote_v2(
        db, seal=seal, bundle_json=bundle_json, quote_json=quote_json,
        trusted_now_utc=101.0) == quote
    monkeypatch.setattr(issuers, "_d06_c02_origin", lambda *_, **__: (
        _ for _ in ()).throw(AssertionError("expired worker must not be requalified")))
    admission = d11.admit_terminal_d06_first_ingress_c02_v2(
        db, bundle, seal=seal, bundle_json=bundle_json,
        quote_json=quote_json, now_utc=101.0)
    assert admission.budget.ceiling == {"cpu_ms": 3}
    assert admission.budget.lease_id == "lease"
    assert admission.jobs == ()
    with pytest.raises((ValueError, IssuerAuthorityDenied)):
        d11.verify_original_d06_first_ingress_c02_quote_v2(
            db, seal=seal, bundle_json=bundle_json,
            quote_json=quote_json.replace("cpu_ms", "gpu_ms"),
            trusted_now_utc=101.0)
    with pytest.raises(IssuerAuthorityDenied, match="outside recovery window"):
        d11.verify_original_d06_first_ingress_c02_quote_v2(
            db, seal=seal, bundle_json=bundle_json, quote_json=quote_json,
            trusted_now_utc=120.0)
    db.execute("UPDATE runtime_budget_grants SET status='revoked' WHERE lease_id='lease'")
    with pytest.raises(IssuerAuthorityDenied):
        d11.admit_terminal_d06_first_ingress_c02_v2(
            db, bundle, seal=seal, bundle_json=bundle_json,
            quote_json=quote_json, now_utc=101.0)
    assert db.execute("SELECT COUNT(*) FROM runtime_resource_quotes").fetchone() == (1,)
