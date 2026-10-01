"""D02 fixed body quotes require installed policy and original binding."""

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.domains.d02 import (
    BodyProfile, BodyState, WorkComponent,
)
from sylanne3.domains.d02.body_quote_original import (
    BodyQuoteUnavailable, D02BodyQuoteAuthority, FixedBodyPolicyV1,
    install_body_quote_schema,
)
from sylanne3.runtime.issuers import (
    D02ResourceIssuer, ResourceQuote, install_schema,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, VersionedRef,
    canonical_digest,
)


def _envelope(quote):
    namespace = NamespaceId(quote.bot_id, quote.persona_id)
    return CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(
            quote.activity_id, quote.effect_id, "attempt-1", "work",
            quote.operation_id, canonical_digest({"input_refs": []}),
        ),
        AuthorityContext(
            "owner", "d02", "capability", namespace, ("activity",),
            "consolidation", ("internal",), "policy-1", 1,
        ),
        VersionGuard(
            (), (), 0, 0, "catalogue", "scheme", "operator", "policy",
            (), (), (VersionedRef(quote.quote_id, quote.version),),
        ),
        SourceQualification(
            (), "reported", 1.0, 1.0, "external_report", "qualified",
            0.5, "not_applicable",
        ),
        (), quote.parent_budget_lease_ref, quote.deadline_utc, 100.0,
        "character", (),
    )


def test_fixed_body_quote_requires_installed_policy_and_reads_original():
    db = sqlite3.connect(":memory:")
    install_schema(db)
    install_body_quote_schema(db)
    resource_issuer = D02ResourceIssuer(b"resource-key" * 3)
    body_authority = D02BodyQuoteAuthority(b"body-key" * 4)
    namespace = NamespaceId("bot", "persona")
    quote = ResourceQuote(
        "resource-quote", 1, "bot", "persona", "activity", "operation",
        "effect", "lease", "work", "snapshot", 4_102_444_800.0,
        "resource", None, (), (), {"cpu_ms": 1000}, None, 4_102_444_900.0,
    )
    envelope = _envelope(quote)
    profile = BodyProfile("profile", namespace, 1, ("energy",), ("work",))
    state = BodyState("profile", 1, 0.8, {"work": 0.0}, 0.0, 0.0)
    policy = FixedBodyPolicyV1(
        "body-policy", 1, profile, state, "work",
        WorkComponent("think", "cognition", 0.1), 4_102_444_900.0,
    )
    db.execute("BEGIN")
    resource_issuer.issue_quote(db, quote)
    with pytest.raises(BodyQuoteUnavailable, match="absent"):
        body_authority.issue_fixed_quote_and_reservation(
            db, resource_issuer, envelope, quote, policy.policy_id,
            policy.version, state, (), "reservation", "effect",
        )
    body_authority.install_policy(db, policy)
    profile_write, state_write = body_authority.initial_writes(
        db, namespace, policy.policy_id, policy.version,
    )
    assert profile_write.key.type_name == "d02.body_profile.v1"
    assert state_write.key.type_name == "d02.body_state.v1"
    with pytest.raises(BodyQuoteUnavailable, match="absent"):
        body_authority.initial_writes(
            db, NamespaceId("other", "persona"), policy.policy_id,
            policy.version,
        )
    issued = body_authority.issue_fixed_quote_and_reservation(
        db, resource_issuer, envelope, quote, policy.policy_id,
        policy.version, state, (), "reservation", "effect",
    )
    assert issued.reservation.quote_id == issued.body_quote.quote_id
    assert issued.body_quote_version == 1
    assert issued.replayed is False
    assert issued.reservation_write.key.type_name == "d02.reservation.v1"
    assert body_authority.original_body_quote(
        db, issued.body_quote.quote_id, issued.body_quote_version,
        quote, quote.operation_id,
    ) == issued.body_quote
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute(
            "UPDATE d02_body_quotes_v1 SET operation_id='other' "
            "WHERE bot='bot' AND persona='persona' AND quote_id=?",
            (issued.body_quote.quote_id,),
        )
    replay = body_authority.issue_fixed_quote_and_reservation(
        db, resource_issuer, envelope, quote, policy.policy_id,
        policy.version, state, (issued.reservation,), "reservation", "effect",
    )
    assert replay.replayed is True
    assert replay.body_quote == issued.body_quote
    assert replay.reservation == issued.reservation
    with pytest.raises(BodyQuoteUnavailable, match="replay differs"):
        body_authority.issue_fixed_quote_and_reservation(
            db, resource_issuer, envelope, quote, policy.policy_id,
            policy.version, state, (issued.reservation,), "reservation", "other",
        )
    with pytest.raises(BodyQuoteUnavailable, match="binding differs"):
        body_authority.original_body_quote(
            db, issued.body_quote.quote_id,
            issued.body_quote_version,
            replace(quote, ceiling={"cpu_ms": 2}), quote.operation_id,
        )
    db.rollback()
    db.close()
