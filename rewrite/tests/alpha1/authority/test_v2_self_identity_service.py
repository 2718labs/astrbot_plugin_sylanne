"""Real Authority database/fence regressions for administrator self mapping."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.current_self_identity_graph_verifier import (
    PinnedCurrentSelfIdentityGraphVerifier,
)
from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.authority_service.v2_self_identity_contract import (
    SelfIdentityCurrentRequestV1, SelfIdentityMutationV1,
)
from sylanne3.authority_service.v2_self_identity_service import AuthorityV2SelfIdentityService
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot-a", "persona-a")
SUBJECT = "mtls:sha256:" + "a" * 64


def _case(tmp_path, monkeypatch):
    fences, core, _, deletion, guard_journal, execution, _ = installed(tmp_path)
    anchor = fences.current_anchor(credential="ok", subject=SUBJECT)
    tickets = object.__new__(AuthorityV2OwnerTicketStore)
    tickets._core = core
    guard = OwnerAuthorizationGuardV1(
        anchor.authority_id, "installation-a", NS, 1, "sha256:" + "b" * 64, 0, 0)
    monkeypatch.setattr(tickets, "_checked_current_head", lambda db, ns: guard)
    graph_path = tmp_path / "graph.db"
    graph_path.touch()
    graph = PinnedCurrentSelfIdentityGraphVerifier(graph_path)
    monkeypatch.setattr(graph, "current", lambda *_: (
        "graph-incarnation-a", "role-a@1", 3, 3))
    service = AuthorityV2SelfIdentityService(
        core=core, fences=fences, owner_tickets=tickets, graph=graph,
        namespace_id=NS,
        installation_id="installation-a", manifest_digest="c" * 64,
        read_subject=SUBJECT, holder="holder-a",
        administrator_authorizer=lambda credential, action, ns, installation:
            credential == "admin" and action == "self_identity_mutate"
            and ns == "ns-a" and installation == "installation-a",
        create=True)
    mutation = SelfIdentityMutationV1(
        anchor.authority_id, "ns-a", NS, "installation-a", "c" * 64,
        "entity:role-a", "set", "register-a", 0)
    return service, mutation, anchor, core, deletion, guard_journal, execution


def _close(core, deletion, guard, execution):
    core.close(); deletion.close(); guard.close(); execution.close()


def test_real_store_admin_registration_replay_replacement_and_revocation(tmp_path, monkeypatch):
    service, mutation, anchor, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        with pytest.raises(AuthorityUnavailable, match="authorization denied"):
            service.mutate(credential="reader", subject=SUBJECT, mutation=mutation)
        first = service.mutate(credential="admin", subject=SUBJECT, mutation=mutation)
        assert (first.revision, first.revocation_epoch, first.state) == (1, 0, "active")
        assert service.mutate(credential="admin", subject=SUBJECT, mutation=mutation) == first
        with core._tx() as db:
            assert db.execute(
                "SELECT registration_subject FROM authority_self_identity_heads_v1 "
                "WHERE authority_namespace='ns-a'").fetchone() == (SUBJECT,)
            assert db.execute(
                "SELECT administrator_subject FROM authority_self_identity_operations_v1 "
                "WHERE operation_id='register-a'").fetchone() == (SUBJECT,)
        with pytest.raises(AuthorityUnavailable, match="replay differs"):
            service.mutate(credential="admin", subject="different-admin", mutation=mutation)
        with pytest.raises(AuthorityUnavailable, match="replay differs"):
            service.mutate(credential="admin", subject=SUBJECT,
                           mutation=replace(mutation, self_entity_ref="entity:other"))
        with pytest.raises(AuthorityUnavailable, match="revision changed"):
            service.mutate(credential="admin", subject=SUBJECT,
                           mutation=replace(mutation, operation_id="stale", expected_revision=0))
        replacement = replace(mutation, self_entity_ref="entity:role-b",
                              operation_id="replace-a", expected_revision=1)
        second = service.mutate(credential="admin", subject=SUBJECT, mutation=replacement)
        assert (second.revision, second.revocation_epoch, second.state) == (2, 1, "active")
        assert second.mapping_id != first.mapping_id
        revoke = replace(replacement, action="revoke", operation_id="revoke-a",
                         expected_revision=2)
        last = service.mutate(credential="admin", subject=SUBJECT, mutation=revoke)
        assert (last.revision, last.revocation_epoch, last.state) == (3, 2, "revoked")
        assert last.mapping_id == second.mapping_id
        assert service.mutate(credential="admin", subject=SUBJECT, mutation=revoke) == last
    finally:
        _close(core, deletion, guard, execution)


def test_active_read_fence_excludes_admin_change_and_current_is_fence_bound(tmp_path, monkeypatch):
    service, mutation, anchor, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        service.mutate(credential="admin", subject=SUBJECT, mutation=mutation)
        permit = service._fences.begin_fence(
            credential="ok", subject=SUBJECT, holder="holder-a",
            operation="read", operation_id="read-self-a", expected_anchor=anchor)
        assert service.mutate(credential="admin", subject=SUBJECT,
                              mutation=mutation).operation_id == mutation.operation_id
        request = SelfIdentityCurrentRequestV1(
            anchor.authority_id, "ns-a", NS, "installation-a", "c" * 64,
            "d03-self-perspective-a", permit)
        current = service.current(credential="ok", subject=SUBJECT, request=request)
        assert current is not None
        assert (current.graph_revision, current.graph_epoch) == (3, 3)
        assert (current.self_entity_ref, current.registration_operation_id,
                current.registration_digest, current.permit) == (
                    "entity:role-a", mutation.operation_id, mutation.request_digest, permit)
        with pytest.raises(AuthorityUnavailable, match="waits for v2 namespace work"):
            service.mutate(credential="admin", subject=SUBJECT,
                           mutation=replace(mutation, operation_id="replace-a",
                                            self_entity_ref="entity:role-b",
                                            expected_revision=1))
        with pytest.raises(AuthorityUnavailable, match="reader installation differs"):
            service.current(credential="ok", subject="other-reader", request=request)
        service._fences.finish_fence(
            credential="ok", subject=SUBJECT, permit=permit,
            request_id="finish-read-self-a", request_digest="sha256:" + "d" * 64)
        with pytest.raises(AuthorityUnavailable, match="no longer current"):
            service.current(credential="ok", subject=SUBJECT, request=request)
    finally:
        _close(core, deletion, guard, execution)


def test_graph_failure_and_registration_change_during_read_fail_closed(tmp_path, monkeypatch):
    service, mutation, anchor, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        service.mutate(credential="admin", subject=SUBJECT, mutation=mutation)
        permit = service._fences.begin_fence(
            credential="ok", subject=SUBJECT, holder="holder-a",
            operation="read", operation_id="read-self-a", expected_anchor=anchor)
        request = SelfIdentityCurrentRequestV1(
            anchor.authority_id, "ns-a", NS, "installation-a", "c" * 64,
            "d03-self-perspective-a", permit)
        monkeypatch.setattr(service._graph, "current", lambda *_: None)
        with pytest.raises(AuthorityUnavailable, match="current D01"):
            service.current(credential="ok", subject=SUBJECT, request=request)
        assert service._fences.fences._row(core._db, permit.operation_id)[6] == "active"
    finally:
        _close(core, deletion, guard, execution)
