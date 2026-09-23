"""Authority owner ticket persistence; pending is never a graph grant."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerPrincipalV1, canonical_bytes,
)
from sylanne3.authority_service import v2_owner_ticket_store as ticket_store_module
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "new-persona")
PRINCIPAL = OwnerPrincipalV1("dashboard", "account-17", "incarnation-3")
AUTH_NS = namespace_ref(NS)


def digest(character):
    return "sha256:" + character * 64


class Clock:
    def __init__(self, core, now=None):
        self.core = core
        self.now = now or datetime(2029, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        assert not self.core._lock._is_owned()
        return self.now


def open_core(path, *, initialize=False, v2_only=True):
    def authorize(credential, action, namespace, holder):
        assert namespace == AUTH_NS and not core._lock._is_owned()
        return ((credential == "paired-operator" and action == "owner_pair")
                or (credential == "paired-claimant" and action == "owner_claim"))

    core = AuthorityServiceCore(
        path, authorizer=authorize, deletion_verifier=lambda *_: True,
        execution_verifier=lambda *_: True, effect_verifier=lambda *_: True,
        dispatch_verifier=lambda *_: True, create=initialize,
    )
    if initialize:
        with core._tx() as db:
            db.execute(
                "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (AUTH_NS, "holder", 1, "active", None, None, 0,
                 "deletion", 0, "genesis", "clear", "execution", 0,
                 "genesis", "nonce"),
            )
            if v2_only:
                db.execute(
                    "INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")
    return core


def ticket(core, **changes):
    with core._tx() as db:
        authority_id = core._id(db)
    data = dict(
        authority_id=authority_id, installation_id="installation-a",
        namespace=NS, principal=PRINCIPAL, ticket_id="ticket-a",
        creation_operation_id="create-new-persona-a", creation_digest=digest("a"),
        policy_digest=digest("b"), challenge="C" * 43,
        expires_at_utc="2030-01-01T00:00:00Z",
    )
    data.update(changes)
    return OwnerClaimTicketV1(**data)


def issue(claim, **changes):
    data = dict(
        action="issue", operation_id="issue-a", authority_id=claim.authority_id,
        installation_id=claim.installation_id, namespace=claim.namespace,
        principal=claim.principal, grant_id="grant-a", grant_digest=digest("c"),
        expected_grant_revision=0,
        expected_guard=OwnerAuthorizationGuardV1(
            claim.authority_id, claim.installation_id, claim.namespace,
            0, "genesis", 0, 0),
        ticket=claim,
    )
    data.update(changes)
    return OwnerAuthorizationOperationV1(**data)


def store(core, *, create=False, first=True, claimant=True):
    def verify_first(credential, claim, authority_namespace):
        assert not core._lock._is_owned()
        return (credential == "paired-operator" and authority_namespace == AUTH_NS
                and claim.creation_operation_id == "create-new-persona-a")

    def verify_claimant(credential, operation):
        assert not core._lock._is_owned()
        return credential == "paired-claimant" and operation.principal == PRINCIPAL

    clock = Clock(core)
    subject = AuthorityV2OwnerTicketStore(
        core, utc_clock=clock,
        first_claim_verifier=verify_first if first else None,
        claimant_verifier=verify_claimant if claimant else None,
        create=create,
    )
    return subject, clock


def test_ticket_and_pending_are_durable_and_exact_replays_survive_restart(tmp_path):
    path = tmp_path / "authority.db"
    core = open_core(path, initialize=True)
    try:
        subject, clock = store(core, create=True)
        claim = ticket(core)
        assert subject.register_ticket(
            credential="paired-operator", authority_namespace=AUTH_NS,
            ticket=claim) == claim
        assert subject.register_ticket(
            credential="paired-operator", authority_namespace=AUTH_NS,
            ticket=claim) == claim
        operation = issue(claim)
        pending = subject.reserve_issue(
            credential="paired-claimant", authority_namespace=AUTH_NS,
            operation=operation)
        assert pending.phase == "pending"
        assert pending.grant_revision is None and pending.graph_access_epoch is None
        clock.now = datetime(2031, 1, 1, tzinfo=timezone.utc)
        assert subject.reserve_issue(
            credential="paired-claimant", authority_namespace=AUTH_NS,
            operation=operation) == pending
    finally:
        core.close()

    core = open_core(path)
    try:
        subject, _ = store(core)
        assert subject.get_pending(
            credential="paired-claimant", authority_namespace=AUTH_NS,
            operation_id="issue-a") == pending
        assert subject.reserve_issue(
            credential="paired-claimant", authority_namespace=AUTH_NS,
            operation=operation) == pending
        with core._tx() as db:
            assert db.execute(
                "SELECT issue_operation_id FROM authority_owner_claim_tickets_v1"
            ).fetchone() == ("issue-a",)
            assert db.execute(
                "SELECT count(*) FROM authority_owner_issue_pending_v1"
            ).fetchone() == (1,)
    finally:
        core.close()


def test_registration_is_one_original_binding_and_changed_bytes_fail(tmp_path):
    core = open_core(tmp_path / "authority.db", initialize=True)
    try:
        subject, _ = store(core, create=True)
        claim = ticket(core)
        subject.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                ticket=claim)
        for changed in (
            replace(claim, challenge="D" * 43),
            replace(claim, ticket_id="ticket-b"),
            replace(claim, creation_digest=digest("d")),
        ):
            with pytest.raises(AuthorityUnavailable, match="binding differs"):
                subject.register_ticket(credential="paired-operator",
                                        authority_namespace=AUTH_NS, ticket=changed)
        with pytest.raises(AuthorityUnavailable):
            subject.register_ticket(credential="paired-claimant",
                                    authority_namespace=AUTH_NS, ticket=claim)
    finally:
        core.close()


def test_reserve_rejects_wrong_ticket_binding_and_second_issue(tmp_path):
    core = open_core(tmp_path / "authority.db", initialize=True)
    try:
        subject, _ = store(core, create=True)
        claim = ticket(core)
        subject.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                ticket=claim)
        for changed in (
            replace(claim, creation_digest=digest("d")),
            replace(claim, challenge="D" * 43),
        ):
            with pytest.raises(AuthorityUnavailable, match="absent or already consumed"):
                subject.reserve_issue(credential="paired-claimant",
                                      authority_namespace=AUTH_NS,
                                      operation=issue(changed))
        with pytest.raises(AuthorityUnavailable, match="verification denied"):
            subject.reserve_issue(
                credential="paired-claimant", authority_namespace=AUTH_NS,
                operation=issue(replace(
                    claim, principal=OwnerPrincipalV1(
                        "dashboard", "account-18", "incarnation-3"))),
            )
        with pytest.raises(AuthorityUnavailable, match="namespace binding"):
            subject.reserve_issue(credential="paired-claimant",
                                  authority_namespace=AUTH_NS,
                                  operation=issue(replace(claim, namespace=NamespaceId("bot", "other"))))
        original = issue(claim)
        subject.reserve_issue(credential="paired-claimant", authority_namespace=AUTH_NS,
                              operation=original)
        with pytest.raises(AuthorityUnavailable, match="replay differs"):
            subject.reserve_issue(credential="paired-claimant", authority_namespace=AUTH_NS,
                                  operation=issue(claim, grant_digest=digest("e")))
        with pytest.raises(AuthorityUnavailable, match="already consumed"):
            subject.reserve_issue(credential="paired-claimant", authority_namespace=AUTH_NS,
                                  operation=issue(claim, operation_id="issue-b"))
    finally:
        core.close()


def test_expiry_and_missing_verifier_fail_closed(tmp_path):
    core = open_core(tmp_path / "authority.db", initialize=True)
    try:
        subject, clock = store(core, create=True)
        claim = ticket(core)
        clock.now = datetime(2031, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(AuthorityUnavailable, match="expired"):
            subject.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                    ticket=claim)
        clock.now = datetime(2029, 1, 1, tzinfo=timezone.utc)
        missing, _ = store(core, first=False)
        with pytest.raises(AuthorityUnavailable, match="verifier"):
            missing.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                    ticket=claim)
        subject.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                ticket=claim)
        no_claimant, _ = store(core, claimant=False)
        with pytest.raises(AuthorityUnavailable, match="verifier"):
            no_claimant.reserve_issue(credential="paired-claimant",
                                      authority_namespace=AUTH_NS, operation=issue(claim))
        clock.now = datetime(2031, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(AuthorityUnavailable, match="expired"):
            subject.reserve_issue(credential="paired-claimant", authority_namespace=AUTH_NS,
                                  operation=issue(claim))
        assert subject.get_pending(credential="paired-claimant",
                                   authority_namespace=AUTH_NS, operation_id="issue-a") is None
    finally:
        core.close()


def test_requires_v2_only_mode(tmp_path):
    core = open_core(tmp_path / "authority.db", initialize=True, v2_only=False)
    try:
        with pytest.raises(AuthorityUnavailable, match="v2-only"):
            store(core, create=True)
    finally:
        core.close()


def test_future_owner_table_does_not_hide_durable_pending(tmp_path):
    path = tmp_path / "authority.db"
    core = open_core(path, initialize=True)
    try:
        subject, _ = store(core, create=True)
        claim = ticket(core)
        subject.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                ticket=claim)
        pending = subject.reserve_issue(credential="paired-claimant",
                                        authority_namespace=AUTH_NS, operation=issue(claim))
        with core._tx() as db:
            db.execute("CREATE TABLE authority_owner_future_v1 (id INTEGER PRIMARY KEY) STRICT")
    finally:
        core.close()
    core = open_core(path)
    try:
        subject, _ = store(core)
        assert subject.get_pending(credential="paired-claimant",
                                   authority_namespace=AUTH_NS,
                                   operation_id="issue-a") == pending
    finally:
        core.close()


@pytest.mark.parametrize("target,column,value", [
    ("pending", "request_digest", digest("e")),
    ("pending", "operation_bytes", "changed_operation"),
    ("pending", "receipt_bytes", "changed_receipt"),
    ("ticket", "ticket_bytes", "changed_ticket"),
    ("ticket", "issue_operation_id", None),
])
def test_pending_reads_reject_single_point_corruption(
        tmp_path, target, column, value):
    core = open_core(tmp_path / "authority.db", initialize=True)
    try:
        subject, _ = store(core, create=True)
        claim = ticket(core)
        operation = issue(claim)
        subject.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                ticket=claim)
        receipt = subject.reserve_issue(credential="paired-claimant",
                                        authority_namespace=AUTH_NS, operation=operation)
        changed = {
            "changed_operation": canonical_bytes(replace(
                operation, grant_digest=digest("e"), request_digest=None)),
            "changed_receipt": canonical_bytes(replace(receipt, receipt_ref="changed")),
            "changed_ticket": canonical_bytes(replace(claim, challenge="D" * 43)),
        }
        value = changed.get(value, value) if isinstance(value, str) else value
        table = ("authority_owner_issue_pending_v1" if target == "pending"
                 else "authority_owner_claim_tickets_v1")
        with core._tx() as db:
            db.execute(f"UPDATE {table} SET {column}=?", (value,))
        with pytest.raises(AuthorityUnavailable, match="stored owner issue pending"):
            subject.get_pending(credential="paired-claimant",
                                authority_namespace=AUTH_NS, operation_id="issue-a")
        with pytest.raises(AuthorityUnavailable, match="stored owner issue pending"):
            subject.reserve_issue(credential="paired-claimant",
                                  authority_namespace=AUTH_NS, operation=operation)
    finally:
        core.close()


def test_lock_wait_cannot_reserve_after_ticket_expiry(tmp_path, monkeypatch):
    core = open_core(tmp_path / "authority.db", initialize=True)
    try:
        subject, clock = store(core, create=True)
        claim = ticket(core)
        subject.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                ticket=claim)
        clock.now = datetime(2029, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        elapsed = [0.0]
        monkeypatch.setattr(ticket_store_module, "monotonic", lambda: 100.0 + elapsed[0])
        original_tx = core._tx
        calls = [0]

        @contextmanager
        def delayed_tx():
            calls[0] += 1
            if calls[0] == 2:
                elapsed[0] = 1.0
            with original_tx() as db:
                yield db

        monkeypatch.setattr(core, "_tx", delayed_tx)
        with pytest.raises(AuthorityUnavailable, match="expired"):
            subject.reserve_issue(credential="paired-claimant",
                                  authority_namespace=AUTH_NS, operation=issue(claim))
        with original_tx() as db:
            assert db.execute(
                "SELECT count(*) FROM authority_owner_issue_pending_v1"
            ).fetchone() == (0,)
    finally:
        core.close()


def test_lock_wait_cannot_register_after_ticket_expiry(tmp_path, monkeypatch):
    core = open_core(tmp_path / "authority.db", initialize=True)
    try:
        subject, clock = store(core, create=True)
        claim = ticket(core)
        clock.now = datetime(2029, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        elapsed = [0.0]
        monkeypatch.setattr(ticket_store_module, "monotonic", lambda: 100.0 + elapsed[0])
        original_tx = core._tx
        calls = [0]

        @contextmanager
        def delayed_tx():
            calls[0] += 1
            if calls[0] == 2:
                elapsed[0] = 1.0
            with original_tx() as db:
                yield db

        monkeypatch.setattr(core, "_tx", delayed_tx)
        with pytest.raises(AuthorityUnavailable, match="expired"):
            subject.register_ticket(credential="paired-operator",
                                    authority_namespace=AUTH_NS, ticket=claim)
        with original_tx() as db:
            assert db.execute(
                "SELECT count(*) FROM authority_owner_claim_tickets_v1"
            ).fetchone() == (0,)
    finally:
        core.close()


def test_register_expiry_before_commit_rolls_back_ticket(tmp_path, monkeypatch):
    core = open_core(tmp_path / "authority.db", initialize=True)
    try:
        subject, clock = store(core, create=True)
        claim = ticket(core)
        clock.now = datetime(2029, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        samples = iter((100.0, 100.5, 101.0))
        monkeypatch.setattr(ticket_store_module, "monotonic", lambda: next(samples))
        with pytest.raises(AuthorityUnavailable, match="expired"):
            subject.register_ticket(credential="paired-operator",
                                    authority_namespace=AUTH_NS, ticket=claim)
        with core._tx() as db:
            assert db.execute(
                "SELECT count(*) FROM authority_owner_claim_tickets_v1"
            ).fetchone() == (0,)
    finally:
        core.close()


def test_expiry_before_commit_rolls_back_pending_and_ticket_use(tmp_path, monkeypatch):
    core = open_core(tmp_path / "authority.db", initialize=True)
    try:
        subject, clock = store(core, create=True)
        claim = ticket(core)
        subject.register_ticket(credential="paired-operator", authority_namespace=AUTH_NS,
                                ticket=claim)
        clock.now = datetime(2029, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        samples = iter((100.0, 100.5, 101.0))
        monkeypatch.setattr(ticket_store_module, "monotonic", lambda: next(samples))
        with pytest.raises(AuthorityUnavailable, match="expired"):
            subject.reserve_issue(credential="paired-claimant",
                                  authority_namespace=AUTH_NS, operation=issue(claim))
        with core._tx() as db:
            assert db.execute(
                "SELECT count(*) FROM authority_owner_issue_pending_v1"
            ).fetchone() == (0,)
            assert db.execute(
                "SELECT issue_operation_id FROM authority_owner_claim_tickets_v1"
            ).fetchone() == (None,)
    finally:
        core.close()
