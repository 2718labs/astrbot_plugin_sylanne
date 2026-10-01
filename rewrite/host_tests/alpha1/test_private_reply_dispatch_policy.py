"""Installed K03 dispatch price is explicit and bound to a signed quote."""

from __future__ import annotations

from copy import deepcopy
import sqlite3
import time

import pytest

from test_authority_profile import _schema2_payload, authority_profile
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, install_schema as install_budget_schema
from sylanne3.runtime.d11_types import runtime_job_key, runtime_outbox_key
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, IssuerAuthorityDenied, build_runtime_issuers, install_schema,
)
from sylanne3.runtime_contracts import NamespaceId, OperationIdentity, canonical_digest


def _dispatch_payload() -> dict[str, object]:
    payload = _schema2_payload()
    payload["installation_policy"]["root_grant"]["allowed_work_kinds"].append("message")
    payload["private_reply_dispatch"] = {
        "deadline_after_seconds": 30,
        "quote_ceiling": {"tokens": 10},
        "snapshot_ref": "k03-snapshot-v1",
        "resource_ref": "k03-resource-v1",
        "segment_max_chars": 800,
        "host_takeover_wait_seconds": 15,
    }
    return payload


def test_dispatch_policy_requires_explicit_installed_price_and_message_grant() -> None:
    legacy = _schema2_payload()
    authority_profile._policy_from_payload(legacy)
    assert authority_profile._private_reply_dispatch_from_payload(legacy) is None

    payload = _dispatch_payload()
    authority_profile._policy_from_payload(payload)
    policy = authority_profile._private_reply_dispatch_from_payload(payload)
    assert policy.digest_payload() == payload["private_reply_dispatch"]
    with pytest.raises(TypeError):
        policy.quote_ceiling["tokens"] = 11

    changed = deepcopy(payload)
    changed["installation_policy"]["root_grant"]["allowed_work_kinds"].remove("message")
    with pytest.raises(ValueError, match="message root grant"):
        authority_profile._policy_from_payload(changed)

    for change in (
        {"quote_ceiling": {"tokens": 101}},
        {"quote_ceiling": {"other": 1}},
        {"segment_max_chars": 2049},
        {"deadline_after_seconds": 0},
        {"resource_ref": "bad ref"},
        {"host_takeover_wait_seconds": 0},
        {"host_takeover_wait_seconds": 301},
    ):
        changed = deepcopy(payload)
        changed["private_reply_dispatch"].update(change)
        with pytest.raises(ValueError):
            authority_profile._policy_from_payload(changed)


def test_dispatch_quote_signed_exact_replay_and_conflict() -> None:
    payload = _dispatch_payload()
    installation = authority_profile._policy_from_payload(payload)
    policy = authority_profile._private_reply_dispatch_from_payload(payload)
    namespace = NamespaceId("bot-a", "persona-a")
    identity = OperationIdentity(
        "activity-a", "effect-a", "attempt-a", "dispatch", "operation-a",
        canonical_digest({"input_refs": []}),
    )
    db = sqlite3.connect(":memory:")
    install_budget_schema(db)
    install_schema(db)
    lease = installation.root_lease
    create_budget_lease(db, BudgetLease(
        lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
        lease.currency, dict(lease.limits), {}, {}, {}, 1, "active",
    ), "create-root", "0" * 64)
    d02, d11 = build_runtime_issuers(b"k03-test-signing-key-" * 2)
    root_grant = installation.root_grant
    grant = BudgetLeaseGrant(
        root_grant.grant_id, root_grant.version, root_grant.bot_id,
        root_grant.persona_id, root_grant.lease_id, root_grant.currency,
        dict(root_grant.max_ceiling), root_grant.allowed_work_kinds,
        root_grant.valid_until_utc, root_grant.policy_ref,
    )
    d11.issue_budget_grant(db, grant)
    job_ref = runtime_job_key("bot-a", "persona-a", "activity-a", "job-a").token
    outbox_ref = runtime_outbox_key("bot-a", "persona-a", "activity-a", "outbox-a").token
    kwargs = dict(
        policy=policy, namespace=namespace, identity=identity,
        parent_grant=grant, deadline_utc=time.time() + 10,
        graph_job_ref=job_ref, outbox_refs=(outbox_ref,),
    )
    first = d11.issue_private_reply_dispatch_quote_v2(db, **kwargs)
    assert first == d11.issue_private_reply_dispatch_quote_v2(db, **kwargs)
    assert first == d02.original_signed_quote(db, first.quote_id, 1)
    assert first.work_kind == "message" and first.ceiling == {"tokens": 10}
    assert first.graph_job_ref == job_ref and first.outbox_refs == (outbox_ref,)
    with pytest.raises(IssuerAuthorityDenied, match="replay differs"):
        d11.issue_private_reply_dispatch_quote_v2(
            db, **{**kwargs, "outbox_refs": (
                runtime_outbox_key("bot-a", "persona-a", "activity-a", "outbox-b").token,
            )},
        )
    db.close()
