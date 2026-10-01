"""The installed CPU quote policy has a signature and exact operation replay."""

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.graph_coordinator import OwnerLeaseBindingV1
from sylanne3.runtime.budget import install_schema as install_budget_schema
from sylanne3.runtime.c04_cpu_quote_policy import (
    C04_INTERNAL_CPU_WORK_KIND, C04InternalCpuQuotePolicyAuthorityV1,
    C04InternalCpuQuotePolicyV1,
)
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D11BudgetGrantIssuer, IssuerAuthorityDenied,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_digest,
    canonical_serialize,
)


def _originals(db):
    namespace = NamespaceId("bot", "persona")
    owner = OwnerLeaseBindingV1(
        object(), "actor", namespace, "purpose", "audience", "owner-grant",
        "scope", "issuer", frozenset({"c04.internal_work.prepare"}),
        frozenset({"purpose"}), frozenset({"audience"}), "a" * 64, 1,
        0, 0, "incarnation", "head", 1, 0,
    )
    authority = AuthorityContext(
        "actor", "d12", "capability", namespace, ("persona",), "purpose",
        ("audience",), "provider-policy", 1,
    )
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity("activity", "effect", "attempt", "realize-recollection",
                          "operation", canonical_digest({"input_refs": []})),
        authority,
        VersionGuard((), (), 0, 0, "catalogue", "scheme", "operator", "policy",
                     (), (), ()),
        SourceQualification((), "observed", 1.0, 2.0,
                            "external_observation", "eligible", 0.8,
                            "not_applicable"),
        (), "lease", 200.0, 100.0, "interval", (),
    )
    install_budget_schema(db)
    install_issuer_schema(db)
    db.execute(
        "INSERT INTO runtime_budget_leases VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("lease", None, "bot", "persona", "USD", canonical_serialize({"cpu_ms": 30}),
         "{}", "{}", "{}", 1, "active"),
    )
    d11 = D11BudgetGrantIssuer(b"d" * 32)
    d11.issue_budget_grant(db, BudgetLeaseGrant(
        "grant", 1, "bot", "persona", "lease", "USD", {"cpu_ms": 30},
        (C04_INTERNAL_CPU_WORK_KIND,), 300.0, "provider-policy"))
    return namespace, owner, envelope, d11


def test_installed_cpu_policy_reopen_quote_replay_and_conflict(tmp_path):
    path = tmp_path / "business.sqlite"
    policy = C04InternalCpuQuotePolicyV1(
        "c04-policy", 1, NamespaceId("bot", "persona"), "installation",
        "algorithm", 7, 250.0)
    signer = C04InternalCpuQuotePolicyAuthorityV1(b"c" * 32)
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        namespace, owner, envelope, d11 = _originals(db)
        assert signer.install_policy(db, policy) == signer.install_policy(db, policy)
        quote = signer.request_quote(
            db, namespace=namespace, policy_id=policy.policy_id, policy_version=1,
            envelope=envelope, owner=owner, d11_issuer=d11,
            algorithm_ref="algorithm", now_utc=100.0)
        assert quote.ceiling == {"cpu_ms": 7}
        assert quote.work_kind == C04_INTERNAL_CPU_WORK_KIND
        assert quote.d02_settlement_refs == ("c04.cpu:" + quote.quote_id,)
        db.commit()
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        assert signer.read_policy(db, namespace, "c04-policy", 1) == policy
        assert signer.request_quote(
            db, namespace=namespace, policy_id="c04-policy", policy_version=1,
            envelope=envelope, owner=owner, d11_issuer=d11,
            algorithm_ref="algorithm", now_utc=101.0) == quote
        with pytest.raises(IssuerAuthorityDenied, match="replay differs"):
            signer.request_quote(
                db, namespace=namespace, policy_id="c04-policy", policy_version=1,
                envelope=replace(envelope, identity=replace(
                    envelope.identity, attempt_id="another-attempt")),
                owner=owner, d11_issuer=d11, algorithm_ref="algorithm",
                now_utc=101.0)
        with pytest.raises(IssuerAuthorityDenied, match="policy replay differs"):
            signer.install_policy(db, replace(policy, cpu_ms_ceiling=8))
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("DELETE FROM runtime_c04_cpu_quote_policies_v1")
        db.rollback()


def test_unsigned_or_unaffordable_cpu_policy_never_requests_quote():
    with sqlite3.connect(":memory:") as db:
        db.execute("BEGIN IMMEDIATE")
        namespace, owner, envelope, d11 = _originals(db)
        signer = C04InternalCpuQuotePolicyAuthorityV1(b"c" * 32)
        policy = C04InternalCpuQuotePolicyV1(
            "c04-policy", 1, namespace, "installation", "algorithm", 31, 250.0)
        signer.install_policy(db, policy)
        with pytest.raises(IssuerAuthorityDenied, match="capacity insufficient"):
            signer.request_quote(
                db, namespace=namespace, policy_id="c04-policy", policy_version=1,
                envelope=envelope, owner=owner, d11_issuer=d11,
                algorithm_ref="algorithm", now_utc=100.0)
        with pytest.raises(IssuerAuthorityDenied, match="signature differs"):
            C04InternalCpuQuotePolicyAuthorityV1(b"x" * 32).read_policy(
                db, namespace, "c04-policy", 1)
        # Simulate storage corruption past the immutability trigger: the HMAC
        # still prevents the row from being promoted to an installed policy.
        db.execute("DROP TRIGGER runtime_c04_cpu_policy_no_update_v1")
        db.execute("UPDATE runtime_c04_cpu_quote_policies_v1 SET signature=?",
                   ("0" * 64,))
        with pytest.raises(IssuerAuthorityDenied, match="signature differs"):
            signer.read_policy(db, namespace, "c04-policy", 1)
        assert db.execute("SELECT COUNT(*) FROM runtime_c04_cpu_quote_requests_v1").fetchone() == (0,)
