"""First-owner issue commit is durable, exact, and graph-gated."""

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
    canonical_bytes, decode_bytes,
)
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")
AUTH_NS = namespace_ref(NS)
PRINCIPAL = OwnerPrincipalV1("identity", "account", "incarnation")


def digest(char):
    return "sha256:" + char * 64


def open_core(path, create=False):
    core = AuthorityServiceCore(
        path, create=create,
        authorizer=lambda credential, action, namespace, holder:
            credential == "claimant" and action == "owner_claim" and namespace == AUTH_NS
            or credential == "pairer" and action == "owner_pair" and namespace == AUTH_NS,
        deletion_verifier=lambda *_: True, execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True, dispatch_verifier=lambda *_: True,
    )
    if create:
        with core._tx() as db:
            db.execute("INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (AUTH_NS, "holder", 1, "active", None, None, 0,
                        "deletion", 0, "genesis", "clear", "execution", 0,
                        "genesis", "nonce"))
            db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")
        AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    return core


def setup(core, *, create=False, graph_verifier=None):
    def trusted_graph(operation, proof):
        assert not core._lock._is_owned()
        return graph_verifier(operation, proof) if graph_verifier else False

    store = AuthorityV2OwnerTicketStore(
        core, create=create,
        utc_clock=lambda: datetime(2029, 1, 1, tzinfo=timezone.utc),
        first_claim_verifier=lambda *_: True,
        claimant_verifier=lambda credential, _: credential == "claimant",
        graph_commit_verifier=trusted_graph if graph_verifier else None,
    )
    with core._tx() as db:
        authority_id = core._id(db)
    ticket = OwnerClaimTicketV1(
        authority_id, "installation", NS, PRINCIPAL, "ticket", "create",
        digest("a"), digest("b"), "C" * 43, "2030-01-01T00:00:00Z")
    guard = OwnerAuthorizationGuardV1(authority_id, "installation", NS,
                                       0, "genesis", 0, 0)
    operation = OwnerAuthorizationOperationV1(
        "issue", "issue", authority_id, "installation", NS, PRINCIPAL,
        "grant", digest("c"), 0, guard, ticket)
    proof = OwnerGraphCommitProofV1(
        NS, "issue", operation.request_digest, "grant", digest("c"),
        "graph-incarnation", 1, 1, 4, digest("d"))
    return store, ticket, operation, proof


def reserve(store, ticket, operation):
    store.register_ticket(credential="pairer", authority_namespace=AUTH_NS,
                          ticket=ticket)
    return store.reserve_issue(credential="claimant", authority_namespace=AUTH_NS,
                               operation=operation)


def finalize(store, operation, proof):
    return store.finalize_issue(credential="claimant", authority_namespace=AUTH_NS,
                                operation=operation, proof=proof)


def test_commit_is_canonical_durable_and_exact_replay_after_restart(tmp_path):
    path = tmp_path / "authority.db"
    core = open_core(path, create=True)
    try:
        store, ticket, operation, proof = setup(
            core, create=True, graph_verifier=lambda *_: True)
        pending = reserve(store, ticket, operation)
        assert pending.phase == "pending"
        assert decode_bytes(canonical_bytes(proof)) == proof
        committed = finalize(store, operation, proof)
        assert committed.phase == "committed"
        assert committed.guard.authorization_revision == 1
        assert committed.grant_revision == 1
        assert store.get_current_guard(credential="claimant",
                                       authority_namespace=AUTH_NS) == committed.guard
        assert finalize(store, operation, proof) == committed
    finally:
        core.close()
    core = open_core(path)
    try:
        # Exact replay is an Authority record read, independent of graph liveness.
        store, _, operation, proof = setup(core, graph_verifier=lambda *_: False)
        assert finalize(store, operation, proof) == committed
        assert store.get_pending(credential="claimant", authority_namespace=AUTH_NS,
                                 operation_id="issue") == pending
        with pytest.raises(AuthorityUnavailable, match="replay differs"):
            finalize(store, operation, replace(proof, graph_epoch=5))
    finally:
        core.close()


def test_missing_denied_or_mismatched_graph_proof_keeps_pending(tmp_path):
    core = open_core(tmp_path / "authority.db", create=True)
    try:
        store, ticket, operation, proof = setup(core, create=True)
        reserve(store, ticket, operation)
        with pytest.raises(AuthorityUnavailable, match="verifier"):
            finalize(store, operation, proof)
        denied, _, _, _ = setup(core, graph_verifier=lambda *_: False)
        with pytest.raises(AuthorityUnavailable, match="denied"):
            finalize(denied, operation, proof)
        accepted, _, _, _ = setup(core, graph_verifier=lambda *_: True)
        with pytest.raises(ValueError):
            replace(proof, graph_access_epoch=True)
        with pytest.raises(AuthorityUnavailable, match="proof differs"):
            finalize(accepted, operation, replace(proof, grant_digest=digest("e")))
        assert accepted.get_current_guard(credential="claimant",
                                          authority_namespace=AUTH_NS) is None
        assert finalize(accepted, operation, proof).phase == "committed"
    finally:
        core.close()


def test_live_fence_blocks_commit_without_losing_pending(tmp_path):
    core = open_core(tmp_path / "authority.db", create=True)
    try:
        store, ticket, operation, proof = setup(
            core, create=True, graph_verifier=lambda *_: True)
        reserve(store, ticket, operation)
        with core._tx() as db:
            db.execute("INSERT INTO authority_v2_epochs VALUES(?,1)", (AUTH_NS,))
            db.execute(
                "INSERT INTO authority_v2_fences"
                "(operation_id,namespace,subject,token,fence_epoch,revision,state,permit) "
                "VALUES(?,?,?,?,1,0,'active',?)",
                ("write-op", AUTH_NS, "subject", "token", b"permit"),
            )
        with pytest.raises(AuthorityUnavailable, match="live v2 fence"):
            finalize(store, operation, proof)
        assert store.get_pending(credential="claimant", authority_namespace=AUTH_NS,
                                 operation_id="issue").phase == "pending"
        with core._tx() as db:
            db.execute("UPDATE authority_v2_fences SET state='finished',"
                       "finish_request_id='finish',finish_request_digest=?",
                       (digest("f"),))
        assert finalize(store, operation, proof).phase == "committed"
    finally:
        core.close()
