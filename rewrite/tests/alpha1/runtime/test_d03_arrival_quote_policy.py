"""D03 arrival quotes require an installed price and a signed current grant."""

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, _d03_arrival_from_payload, _policy_from_payload,
)
from sylanne3.memory_types import source_key
from sylanne3.runtime import install_schema as install_runtime_schema
from sylanne3.runtime.budget import BudgetLease, create_budget_lease
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D03_ARRIVAL_WORK_KIND, IssuerAuthorityDenied,
    build_runtime_issuers, install_schema as install_issuer_schema,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DomainBundle, GraphVersion,
    NamespaceId, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest,
)


def _case(*, allowed=True, ceiling=7):
    db = sqlite3.connect(":memory:")
    install_runtime_schema(db)
    install_issuer_schema(db)
    d02, d11 = build_runtime_issuers(b"q" * 32)
    namespace = NamespaceId("bot", "persona")
    create_budget_lease(db, BudgetLease(
        "lease", None, "bot", "persona", "USD", {"cpu_ms": 100},
        {}, {}, {}, 1, "active"), "create-lease", "a" * 64)
    grant = BudgetLeaseGrant(
        "grant", 1, "bot", "persona", "lease", "USD",
        {"cpu_ms": 50}, (D03_ARRIVAL_WORK_KIND,) if allowed else ("d06.encode_source",),
        2000.0, "host-policy")
    d11.issue_budget_grant(db, grant)
    source = source_key("bot", "persona", "source-1")
    refs = (source.token,)
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity("activity", None, "attempt", "arrival", "arrival-op",
                          canonical_digest({"input_refs": list(refs)})),
        AuthorityContext("host", "d11", "capability", namespace,
                         ("persona", "event"), "context", ("conversation",),
                         "host-policy", 1),
        VersionGuard((GraphVersion(source, 1),),
                     (QueryEpoch(namespace, "all", 1),), 0, 0,
                     "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification(refs, "reported", 900.0, 950.0, "external_report",
                            "qualified", 0.5, "not_applicable"),
        refs, "lease", 1010.0, 20.0, "character", ("message",),
    )
    policy = AdminD03ArrivalPolicy(30.0, {"cpu_ms": ceiling},
                                   "admin-snapshot", "admin-resource")
    return db, d02, d11, envelope, policy


def test_signed_d03_arrival_quote_uses_explicit_price_and_replays_exactly():
    db, d02, d11, envelope, policy = _case()
    try:
        with db:
            quote = d11.issue_d03_arrival_quote(
                db, envelope, policy, installation_id="installation", now_utc=1000.0)
        assert quote.work_kind == D03_ARRIVAL_WORK_KIND
        assert quote.ceiling == {"cpu_ms": 7}
        assert d11.issue_d03_arrival_quote(
            db, envelope, policy, installation_id="installation", now_utc=1000.0) == quote
        assert db.execute("SELECT count(*) FROM runtime_resource_quotes").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM runtime_d03_arrival_quote_policies").fetchone()[0] == 1
        admitted = replace(envelope, version_guard=replace(
            envelope.version_guard,
            resource_lease_versions=(VersionedRef(quote.quote_id, 1),)))
        admission = d11.admit_runtime(
            DomainBundle(admitted, (), (), (), (), (), (), (), ()), db,
            now_utc=1000.0)
        assert admission.budget.ceiling == {"cpu_ms": 7}
        assert admission.budget.settle_now is False
        assert db.execute("SELECT count(*) FROM runtime_resource_outcomes").fetchone()[0] == 0
        assert d02.qualified_quote(admitted, db, now_utc=1000.0) == quote
        with pytest.raises(IssuerAuthorityDenied, match="policy replay differs"):
            d11.issue_d03_arrival_quote(
                db, envelope, replace(policy, quote_ceiling={"cpu_ms": 8}),
                installation_id="installation", now_utc=1000.0)
    finally:
        db.close()


def test_missing_kind_budget_or_signed_policy_holds():
    db, _, d11, envelope, policy = _case(allowed=False)
    try:
        with pytest.raises(IssuerAuthorityDenied, match="signed grant"):
            d11.issue_d03_arrival_quote(
                db, envelope, policy, installation_id="installation", now_utc=1000.0)
    finally:
        db.close()
    db, _, d11, envelope, policy = _case(ceiling=51)
    try:
        with pytest.raises(IssuerAuthorityDenied, match="exceeds signed grant"):
            d11.issue_d03_arrival_quote(
                db, envelope, policy, installation_id="installation", now_utc=1000.0)
    finally:
        db.close()
    db, _, d11, envelope, policy = _case()
    try:
        with db:
            quote = d11.issue_d03_arrival_quote(
                db, envelope, policy, installation_id="installation", now_utc=1000.0)
        admitted = replace(envelope, version_guard=replace(
            envelope.version_guard,
            resource_lease_versions=(VersionedRef(quote.quote_id, 1),)))
        db.execute("UPDATE runtime_d03_arrival_quote_policies "
                   "SET policy_json=replace(policy_json,'7','8')")
        with pytest.raises(IssuerAuthorityDenied, match="signature is invalid"):
            d11.admit_runtime(
                DomainBundle(admitted, (), (), (), (), (), (), (), ()), db,
                now_utc=1000.0)
    finally:
        db.close()


def test_profile_parses_only_explicit_arrival_policy_and_kind():
    db, _, d11, _, policy = _case()
    try:
        grant = d11.current_budget_grant(db, "lease")
        profile = {
            "schema": 2, "host": "authority.example", "port": 443,
            "server_name": "authority.example", "expected_authority_id": "authority",
            "installation_policy": {
                "namespace": {"bot_id": "bot", "persona_id": "persona"},
                "authority_namespace": "opaque", "installation_id": "installation",
                "manifest_digest": "a" * 64, "administrator_holder": "administrator",
                "expected_authority_id": "authority", "catalogue_hash": "b" * 64,
                "scheme_version": "scheme", "operator_version": "operator",
                "policy_version": "policy",
                "root_lease": {"lease_id": "lease", "parent_id": None,
                               "bot_id": "bot", "persona_id": "persona",
                               "currency": "USD", "limits": {"cpu_ms": 100},
                               "used": {}, "reserved": {}, "unconfirmed": {},
                               "version": 1, "state": "active"},
                "root_grant": {"grant_id": grant.grant_id, "version": grant.version,
                               "bot_id": "bot", "persona_id": "persona",
                               "lease_id": "lease", "currency": "USD",
                               "max_ceiling": dict(grant.max_ceiling),
                               "allowed_work_kinds": list(grant.allowed_work_kinds),
                               "valid_until_utc": grant.valid_until_utc,
                               "policy_ref": grant.policy_ref},
            },
            "d03_arrival": {"deadline_after_seconds": policy.deadline_after_seconds,
                            "quote_ceiling": dict(policy.quote_ceiling),
                            "snapshot_ref": policy.snapshot_ref,
                            "resource_ref": policy.resource_ref},
        }
        assert _d03_arrival_from_payload(profile) == policy
        assert _policy_from_payload(profile).root_grant == grant
        profile["installation_policy"]["root_grant"]["allowed_work_kinds"] = ["d06.encode_source"]
        with pytest.raises(ValueError, match="explicit root grant work kind"):
            _policy_from_payload(profile)
        profile.pop("d03_arrival")
        assert _d03_arrival_from_payload(profile) is None
    finally:
        db.close()
