"""D11 V3 freezes authored lineage only after a real W01 Owner read."""

from dataclasses import replace
import json
import sqlite3
import time

import pytest

from sylanne3.graph_types import AtomKey, Owner
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, install_schema
from sylanne3.runtime.d11_d04_root_freeze_v3 import (
    ROOT_WORK_KIND_V3, D11RootFreezeReadV3, D11RootFreezeV3Hold,
    install_d11_root_freeze_v3,
    issue_d11_root_freeze_v3, read_d11_root_freeze_v3,
)
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D11BudgetGrantIssuer, install_schema as install_issuer_schema,
)
from sylanne3.runtime_contracts import (
    NamespaceId, VersionedRef, canonical_digest, canonical_serialize,
)


NS = NamespaceId("bot", "persona")
OWNER = Owner("persona", "bot", "persona")
SHA = "a" * 64


def _read() -> D11RootFreezeReadV3:
    rows = []
    for name, state_type in (
        ("a", "d04.authored_feeling_state.v1"),
        ("b", "d04.authored_feeling_state.v1"),
        ("c", "d04.authored_mood_state.v1"),
    ):
        rows.extend((
            (AtomKey(OWNER, "d04.numeric_checkpoint.v2", name).token, 1, {"id": name}),
            (AtomKey(OWNER, state_type, name).token, 1, {"id": name}),
        ))
    writes = tuple(sorted(rows, key=lambda item: item[0]))
    return D11RootFreezeReadV3(
        namespace=NS, operation_id="root-op", owner_actor_id="owner:one",
        owner_session_id="session:one", owner_session_binding_digest=SHA,
        active_scheme_head=VersionedRef(
            AtomKey(OWNER, "d12.active_scheme_head.v1", "current").token, 1),
        draft_head=VersionedRef(AtomKey(OWNER, "d12.character_draft.v1", "draft").token, 1),
        draft_digest=SHA, root_input_digest=SHA, candidate_digest=SHA,
        preset_digest=SHA, asset_digest=SHA, native_manifest_sha256=SHA,
        native_sha256=SHA, abi2_initial_box_digest=SHA, abi2_readout_digest=SHA,
        initial_transcript_digest=SHA, output_projection_digest=SHA,
        authored_write_set_json=canonical_serialize(writes),
        authored_write_set_digest=canonical_digest(writes),
        graph_read_set_digest=SHA, owner_fence_digest=SHA,
    )


def test_v3_requires_authored_types_and_trusted_w01_read_before_budget_change() -> None:
    candidate = _read()
    assert candidate.schema.endswith(".v3")
    with pytest.raises(D11RootFreezeV3Hold, match="active scheme"):
        replace(candidate, active_scheme_head=VersionedRef(
            AtomKey(OWNER, "d01.role_head.v1", "current").token, 1))
    legacy_rows = json.loads(candidate.authored_write_set_json)
    legacy_rows[0][0] = AtomKey(OWNER, "d04.feeling_state.v1", "a").token
    legacy_rows.sort(key=lambda item: item[0])
    legacy = canonical_serialize(legacy_rows)
    with pytest.raises(D11RootFreezeV3Hold, match="V3 lineage"):
        replace(candidate, authored_write_set_json=legacy,
                authored_write_set_digest=canonical_digest(legacy_rows))
    db = sqlite3.connect(":memory:")
    install_schema(db)
    db.commit()
    install_d11_root_freeze_v3(db)
    db.execute("BEGIN IMMEDIATE")
    issuer = D11BudgetGrantIssuer(b"test-only-signing-key".ljust(32, b"0"))
    assert read_d11_root_freeze_v3(
        db, issuer, namespace=NS, operation_id="root-op") is None
    with pytest.raises(D11RootFreezeV3Hold, match="trusted W01"):
        issue_d11_root_freeze_v3(
            db, issuer, object(), namespace=NS, operation_id="root-op",
            parent_budget_lease_ref="lease",
        )
    assert db.execute("SELECT COUNT(*) FROM runtime_budget_reservations").fetchone() == (0,)
    assert db.execute("SELECT COUNT(*) FROM runtime_d11_d04_root_freezes_v3").fetchone() == (0,)
    db.rollback()
    db.close()


def test_signed_freeze_roundtrips_with_real_budget_ledger_in_software_fixture(monkeypatch) -> None:
    """The W01 read is a test fixture; this is not product Owner acceptance."""
    db = sqlite3.connect(":memory:")
    install_schema(db)
    install_issuer_schema(db)
    db.commit()
    install_d11_root_freeze_v3(db)
    db.execute("BEGIN IMMEDIATE")
    lease = BudgetLease("lease", None, "bot", "persona", "USD",
                        {"thread_cpu_ms": 200}, {}, {}, {}, 1, "active")
    create_budget_lease(db, lease, "create-lease", SHA)
    issuer = D11BudgetGrantIssuer(b"test-only-signing-key".ljust(32, b"0"))
    issuer.issue_budget_grant(db, BudgetLeaseGrant(
        "root-grant", 1, "bot", "persona", "lease", "USD",
        {"thread_cpu_ms": 100}, (ROOT_WORK_KIND_V3,),
        time.time() + 3600, "root-policy",
    ))
    db.commit()
    frozen = _read()
    monkeypatch.setattr(
        GraphCoordinator, "_read_d04_root_freeze_v3_for_d11",
        lambda self, _db, namespace, operation_id: frozen,
        raising=False,
    )
    coordinator = object.__new__(GraphCoordinator)
    db.execute("BEGIN IMMEDIATE")
    original = issue_d11_root_freeze_v3(
        db, issuer, coordinator, namespace=NS, operation_id="root-op",
        parent_budget_lease_ref="lease",
    )
    assert original.grant_signature_digest == canonical_digest(original.grant_signature)
    assert original.quote_ceiling == (("thread_cpu_ms", 100),)
    assert read_d11_root_freeze_v3(
        db, issuer, namespace=NS, operation_id="root-op") == original
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    assert read_d11_root_freeze_v3(
        db, issuer, namespace=NS, operation_id="root-op") == original
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("UPDATE runtime_d11_d04_root_freezes_v3 SET signature='x'")
    db.rollback()
    db.close()
