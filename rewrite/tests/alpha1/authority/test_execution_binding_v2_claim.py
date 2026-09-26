"""V2 admission binding is preserved across the claimed Authority append."""

from dataclasses import replace
import asyncio
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_contract import (
    DispatchGraphClaimReceiptV1, DispatchHandoffContextV1,
    ExecutionBindingV1, ExecutionBindingV2, OwnerDispatchWitnessV1,
    canonical_digest,
    from_wire, to_wire,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
)
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.authority_service.mtls_server import AuthorityRpcServer
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_journal import RecoveryConstraintFootprint
from sylanne3.host.mtls_transport import MtlsAuthorityTransport


GRAPH_NS = NamespaceId("bot", "persona")
AUTH_NS = namespace_ref(GRAPH_NS)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _binding_v2(origin: ExecutionBindingV1, **changes: object) -> ExecutionBindingV2:
    fields = dict(
        origin=origin, graph_namespace="/".join(GRAPH_NS.as_tuple),
        graph_incarnation="graph-incarnation-a",
        admission_receipt_digest=_digest("1"),
        admission_graph_version="graph-version-a",
        admission_graph_epoch=3, admission_access_epoch=2,
        admission_deletion_epoch=0,
        action_intent_digest=_digest("2"),
        action_intent_schema_version="d08.action-intent.v1",
        action_schema_digest=_digest("3"),
        action_schema_version="d08.action-schema.v1",
        required_checks_digest=_digest("4"),
        required_checks_schema_version="d08.required-checks.v1",
        initial_check_evidence_digest=_digest("5"),
        utc_deadline="2029-01-01T00:00:00Z",
        clock_policy_ref="clock-policy-a", clock_policy_digest=_digest("6"),
    )
    fields.update(changes)
    return ExecutionBindingV2(**fields)


def _service(tmp_path, *, create=True, final_authorizer=None, final_issuer=None,
             with_owner=False):
    deletion_journal = DeletionJournal(tmp_path / "deletion.db", create=create)
    deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    head = deletion_journal.latest_head()
    deletion_head = JournalHead(head.journal_id, head.seq, head.chain_digest)
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=AUTH_NS, journal_id="execution-a",
        create=create)
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=create,
        authorizer=lambda credential, *_: credential == "ok",
        deletion_verifier=lambda ns, previous, current, phase:
            current == deletion_head and phase == "clear",
        execution_verifier=lambda ns, previous, current, phase:
            journal.verified_head() == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    if create:
        core.register_namespace("ok", AUTH_NS, "holder-a", deletion_head,
                                JournalHead("execution-a", 0, "genesis"))
        core.seal_v2_only("ok")
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    owner_tickets = None
    if with_owner:
        owner_tickets = AuthorityV2OwnerTicketStore(
            core, create=create,
            utc_clock=lambda: datetime(2029, 1, 1, tzinfo=timezone.utc),
            first_claim_verifier=lambda *_: True,
            claimant_verifier=lambda *_: True,
            graph_commit_verifier=lambda *_: True)
        if create:
            with core._tx() as db:
                authority_id = core._id(db)
            principal = OwnerPrincipalV1("identity", "account", "incarnation")
            ticket = OwnerClaimTicketV1(
                authority_id, "install-a", GRAPH_NS, principal, "ticket-a",
                "create-a", _digest("a"), _digest("b"), "C" * 43,
                "2030-01-01T00:00:00Z")
            operation = OwnerAuthorizationOperationV1(
                "issue", "owner-issue-a", authority_id, "install-a", GRAPH_NS,
                principal, "grant-a", _digest("c"), 0,
                OwnerAuthorizationGuardV1(authority_id, "install-a", GRAPH_NS,
                                          0, "genesis", 0, 0), ticket)
            proof = OwnerGraphCommitProofV1(
                GRAPH_NS, operation.operation_id, operation.request_digest,
                operation.grant_id, operation.grant_digest,
                "graph-incarnation-a", 1, 1, 2, _digest("d"))
            owner_tickets.register_ticket(
                credential="ok", authority_namespace=AUTH_NS, ticket=ticket)
            owner_tickets.reserve_issue(
                credential="ok", authority_namespace=AUTH_NS, operation=operation)
            owner_tickets.finalize_issue(
                credential="ok", authority_namespace=AUTH_NS,
                operation=operation, proof=proof)
    bridge = AuthorityV2ExecutionBridge(
        core=core, fences=fences, journal=journal, namespace=AUTH_NS,
        deletion=deletion, final_handoff_authorizer=final_authorizer,
        final_handoff_issuer_id=final_issuer, owner_tickets=owner_tickets,
        owner_installation_id="install-a" if with_owner else None)
    return core, fences, journal, bridge


def _prepared(core, fences, bridge):
    footprint = RecoveryConstraintFootprint(
        namespace=AUTH_NS, activity_id="activity-a", effect_id="effect-a",
        conflict_keys=("resource-a",))
    with core._tx() as db:
        anchor = core._anchor(db, AUTH_NS, core._row(db, AUTH_NS))
    footprint_digest = "sha256:" + hashlib.sha256(footprint._json().encode()).hexdigest()
    permit = fences.begin_fence(
        subject="subject-a", holder="holder-a", operation="dispatch",
        current_anchor=anchor, operation_id="operation-a", effect_id="effect-a",
        command_digest=_digest("a"), footprint_digest=footprint_digest)
    prepared, _ = bridge.execution_prepare(
        credential="ok", subject="subject-a", permit=permit,
        mutation_id="mutation-a", footprint=footprint)
    origin = ExecutionBindingV1(
        permit=permit, namespace=AUTH_NS, activity_id="activity-a",
        effect_id="effect-a", attempt_id="attempt-a", operation_id="operation-a",
        dispatch_generation=1, activation_generation=permit.generation,
        admission_ref="admission-a", verified_check_refs=("check-a",),
        payload_digest=_digest("b"), platform_capability_ref="capability-a",
        adapter_ref="adapter-a", account_ref="account-a",
        destination_ref="destination-a", worker_fence=1,
        content_fence="content-a", cancel_epoch=0, footprint=footprint)
    return prepared, origin


def test_v2_claim_replay_preserves_original_p0_and_complete_admission(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    prepared, origin = _prepared(core, fences, bridge)
    binding = _binding_v2(origin)
    with pytest.raises(AuthorityUnavailable, match="V1 claim"):
        bridge.execution_claim(
            credential="ok", subject="subject-a",
            prepared_receipt=prepared, binding=binding)
    claimed, updated = bridge.execution_claim_v2(
        credential="ok", subject="subject-a",
        prepared_receipt=prepared, binding=binding)
    assert claimed.pending.binding == binding
    assert claimed.pending.binding.origin.permit == origin.permit
    assert updated.revision == 2
    assert bridge.execution_claim_v2(
        credential="ok", subject="subject-a",
        prepared_receipt=prepared, binding=binding) == (claimed, updated)
    with pytest.raises(AuthorityUnavailable):
        bridge.execution_claim_v2(
            credential="ok", subject="subject-a", prepared_receipt=prepared,
            binding=replace(binding, initial_check_evidence_digest=_digest("7")))
    with pytest.raises(AuthorityUnavailable, match="V1 handoff"):
        bridge.begin_handoff(
            credential="ok", subject="subject-a",
            claimed_receipt=claimed, handoff_id="handoff-a")
    assert journal.verified_head().seq == 2
    core.close()
    journal.close()
    core, _, journal, bridge = _service(tmp_path, create=False)
    assert bridge.execution_claim_v2(
        credential="ok", subject="subject-a",
        prepared_receipt=prepared, binding=binding) == (claimed, updated)
    assert journal.verified_head().seq == 2
    core.close()
    journal.close()


def test_v2_handoff_requires_current_owner_authorization_before_graph_claim(tmp_path):
    calls = []

    def graph_claim(context, binding, claimed, _owner_witness, _snapshot):
        assert type(context) is DispatchHandoffContextV1
        assert type(binding) is ExecutionBindingV2
        assert binding.initial_check_evidence_digest == _digest("5")
        assert context.claimed_receipt_digest == canonical_digest(claimed)
        assert context.binding_digest == canonical_digest(binding)
        calls.append((canonical_digest(claimed), context.handoff_id))
        return DispatchGraphClaimReceiptV1(
            context_digest=canonical_digest(context),
            graph_namespace=binding.graph_namespace,
            graph_incarnation=binding.graph_incarnation,
            graph_version="graph-version-b",
            graph_epoch=binding.admission_graph_epoch + 1,
            graph_access_epoch=binding.admission_access_epoch,
            graph_deletion_epoch=binding.admission_deletion_epoch,
            graph_claim_ref="graph-claim-a",
            graph_claim_digest=_digest("8"), issuer_id="graph-issuer-a")

    core, fences, journal, bridge = _service(
        tmp_path, final_authorizer=graph_claim, final_issuer="graph-issuer-a")
    prepared, origin = _prepared(core, fences, bridge)
    claimed, _ = bridge.execution_claim_v2(
        credential="ok", subject="subject-a", prepared_receipt=prepared,
        binding=_binding_v2(origin))
    bridge._final_handoff_authorizer = None
    with pytest.raises(AuthorityUnavailable, match="final handoff authorizer"):
        bridge.begin_handoff_v2(
            credential="ok", subject="subject-a",
            claimed_receipt=claimed, handoff_id="handoff-a")
    bridge._final_handoff_authorizer = graph_claim
    bridge._final_handoff_issuer_id = None
    with pytest.raises(AuthorityUnavailable, match="final handoff authorizer"):
        bridge.begin_handoff_v2(
            credential="ok", subject="subject-a",
            claimed_receipt=claimed, handoff_id="handoff-a")
    bridge._final_handoff_issuer_id = "graph-issuer-a"
    bridge._final_handoff_authorizer = graph_claim
    with pytest.raises(AuthorityUnavailable, match="Owner dispatch authorization"):
        bridge.begin_handoff_v2(
            credential="ok", subject="subject-a",
            claimed_receipt=claimed, handoff_id="handoff-a")
    assert not calls
    assert core._db.execute(
        "SELECT COUNT(*) FROM authority_execution_handoff_starts_v1").fetchone() == (0,)
    core.close()
    journal.close()


def test_v2_owner_witness_pre_post_and_replay(tmp_path):
    observed = []

    def graph_claim(context, binding, claimed, witness, snapshot):
        assert type(witness) is OwnerDispatchWitnessV1
        assert witness.context_digest == canonical_digest(context)
        assert witness.authority_namespace == AUTH_NS
        assert witness.graph_namespace == "/".join(GRAPH_NS.as_tuple)
        assert witness.guard.installation_id == "install-a"
        assert witness.grant_id == "grant-a"
        assert witness.grant_digest == _digest("c")
        assert canonical_digest(claimed) == context.claimed_receipt_digest
        assert snapshot.context_digest == canonical_digest(context)
        assert snapshot.owner_witness_digest == canonical_digest(witness)
        assert snapshot.pending_mutation_ids == ()
        assert tuple(effect.effect_id for effect in snapshot.unresolved_effects) == ("effect-a",)
        assert snapshot.unresolved_effects[0].footprint == binding.origin.footprint
        assert from_wire(to_wire(snapshot)) == snapshot
        observed.append(witness)
        return DispatchGraphClaimReceiptV1(
            canonical_digest(context), binding.graph_namespace,
            binding.graph_incarnation, "graph-version-b", 4, 2, 0,
            "graph-claim-a", _digest("8"), "graph-issuer-a")

    core, fences, journal, bridge = _service(
        tmp_path, with_owner=True, final_authorizer=graph_claim,
        final_issuer="graph-issuer-a")
    prepared, origin = _prepared(core, fences, bridge)
    claimed, _ = bridge.execution_claim_v2(
        credential="ok", subject="subject-a", prepared_receipt=prepared,
        binding=_binding_v2(origin))
    bridge._owner_installation_id = "other-installation"
    with pytest.raises(AuthorityUnavailable, match="Owner authorization"):
        bridge.begin_handoff_v2(
            credential="ok", subject="subject-a", claimed_receipt=claimed,
            handoff_id="handoff-a")
    assert not observed
    bridge._owner_installation_id = "install-a"
    start = bridge.begin_handoff_v2(
        credential="ok", subject="subject-a", claimed_receipt=claimed,
        handoff_id="handoff-a")
    assert start.replay is False
    assert bridge.begin_handoff_v2(
        credential="ok", subject="subject-a", claimed_receipt=claimed,
        handoff_id="handoff-a").replay is True
    assert len(observed) == 1
    assert from_wire(to_wire(observed[0])) == observed[0]
    with pytest.raises(ValueError, match="active grant"):
        replace(observed[0], guard=replace(
            observed[0].guard, namespace=NamespaceId("bot/other", "persona")))
    core.close()
    journal.close()


def test_v2_owner_head_change_during_graph_callback_cannot_write_start(tmp_path):
    core_ref = []

    def graph_claim(context, binding, _claimed, witness, _snapshot):
        assert witness.guard.authorization_revision == 1
        with core_ref[0]._tx() as db:
            db.execute(
                "UPDATE authority_owner_authorization_heads_v1 SET state='revoked' "
                "WHERE authority_namespace=?", (AUTH_NS,))
        return DispatchGraphClaimReceiptV1(
            canonical_digest(context), binding.graph_namespace,
            binding.graph_incarnation, "graph-version-b", 4, 2, 0,
            "graph-claim-a", _digest("8"), "graph-issuer-a")

    core, fences, journal, bridge = _service(
        tmp_path, with_owner=True, final_authorizer=graph_claim,
        final_issuer="graph-issuer-a")
    core_ref.append(core)
    prepared, origin = _prepared(core, fences, bridge)
    claimed, _ = bridge.execution_claim_v2(
        credential="ok", subject="subject-a", prepared_receipt=prepared,
        binding=_binding_v2(origin))
    with pytest.raises(AuthorityUnavailable, match="owner current head differs"):
        bridge.begin_handoff_v2(
            credential="ok", subject="subject-a", claimed_receipt=claimed,
            handoff_id="handoff-a")
    assert core._db.execute(
        "SELECT COUNT(*) FROM authority_execution_handoff_starts_v1").fetchone() == (0,)
    core.close()
    journal.close()


def test_v2_handoff_rejects_unindexed_second_unresolved_effect(tmp_path):
    called = []

    def graph_claim(*args):
        called.append(args)
        raise AssertionError("incomplete Authority effect set reached graph callback")

    core, fences, journal, bridge = _service(
        tmp_path, with_owner=True, final_authorizer=graph_claim,
        final_issuer="graph-issuer-a")
    try:
        prepared, origin = _prepared(core, fences, bridge)
        claimed, _ = bridge.execution_claim_v2(
            credential="ok", subject="subject-a", prepared_receipt=prepared,
            binding=_binding_v2(origin))
        with core._tx() as db:
            db.execute(
                "INSERT INTO authority_effects(namespace,effect_id,state,"
                "conflict_keys_json,execution_seq) VALUES(?,?,?,?,?)",
                (AUTH_NS, "effect-b", "unresolved", '["resource-b"]', 1))
        with pytest.raises(AuthorityUnavailable, match="unresolved effect index is incomplete"):
            bridge.begin_handoff_v2(
                credential="ok", subject="subject-a", claimed_receipt=claimed,
                handoff_id="handoff-a")
        assert not called
        assert core._db.execute(
            "SELECT COUNT(*) FROM authority_execution_handoff_starts_v1").fetchone() == (0,)
    finally:
        core.close()
        journal.close()


def test_v2_handoff_rejects_other_authority_write_during_graph_claim(tmp_path):
    core_ref = []

    def graph_claim(context, binding, _claimed, witness, snapshot):
        assert snapshot.owner_witness_digest == canonical_digest(witness)
        with core_ref[0]._tx() as db:
            db.execute(
                "INSERT INTO authority_meta(key,value) VALUES('admission_probe','changed')")
        return DispatchGraphClaimReceiptV1(
            canonical_digest(context), binding.graph_namespace,
            binding.graph_incarnation, "graph-version-b", 4, 2, 0,
            "graph-claim-a", _digest("8"), "graph-issuer-a")

    core, fences, journal, bridge = _service(
        tmp_path, with_owner=True, final_authorizer=graph_claim,
        final_issuer="graph-issuer-a")
    core_ref.append(core)
    try:
        prepared, origin = _prepared(core, fences, bridge)
        claimed, _ = bridge.execution_claim_v2(
            credential="ok", subject="subject-a", prepared_receipt=prepared,
            binding=_binding_v2(origin))
        with pytest.raises(AuthorityUnavailable, match="Authority admission changed"):
            bridge.begin_handoff_v2(
                credential="ok", subject="subject-a", claimed_receipt=claimed,
                handoff_id="handoff-a")
        assert core._db.execute(
            "SELECT COUNT(*) FROM authority_execution_handoff_starts_v1").fetchone() == (0,)
    finally:
        core.close()
        journal.close()


def test_v2_wire_rejects_missing_admission_and_retyped_origin(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    _, origin = _prepared(core, fences, bridge)
    binding = _binding_v2(origin)
    wire = to_wire(binding)
    for field in ("admission_receipt_digest", "initial_check_evidence_digest",
                  "utc_deadline", "clock_policy_digest"):
        incomplete = dict(wire)
        del incomplete[field]
        with pytest.raises(ValueError, match="execution binding v2"):
            from_wire(incomplete)
    with pytest.raises(ValueError, match="V2 origin"):
        from_wire({**wire, "origin": wire})
    core.close()
    journal.close()


def test_v2_claim_rpc_rejects_v1_and_forged_claim_response(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    prepared, origin = _prepared(core, fences, bridge)
    binding = _binding_v2(origin)
    claimed, updated = bridge.execution_claim_v2(
        credential="ok", subject="subject-a", prepared_receipt=prepared,
        binding=binding)
    transport = object.__new__(MtlsAuthorityTransport)
    handshake = SimpleNamespace(
        channel_binding_sha256="channel-a",
        installation_identity_ref="subject-a",
        installation_authority_id=updated.authority_id)
    methods = []

    async def rpc(_request, _handshake, method, command, *, protocol):
        methods.append(method)
        assert command["binding"]["kind"] == "execution_binding_v2"
        return {"receipt": to_wire(claimed), "permit": to_wire(updated),
                "channel_binding_sha256": "channel-a"}

    transport._content_rpc = rpc

    async def check():
        with pytest.raises(TypeError, match="execution binding"):
            await transport.v2_execution_claim_v2(
                None, handshake, prepared_receipt=prepared, binding=origin)
        assert await transport.v2_execution_claim_v2(
            None, handshake, prepared_receipt=prepared,
            binding=binding) == (claimed, updated)
        transport._content_rpc = forged_rpc
        with pytest.raises(RuntimeError, match="claim binding"):
            await transport.v2_execution_claim_v2(
                None, handshake, prepared_receipt=prepared,
                binding=binding)

    async def forged_rpc(_request, _handshake, method, command, *, protocol):
        altered = replace(binding, clock_policy_digest=_digest("7"))
        forged = replace(claimed, pending=replace(claimed.pending, binding=altered))
        return {"receipt": to_wire(forged), "permit": to_wire(updated),
                "channel_binding_sha256": "channel-a"}

    asyncio.run(check())
    assert methods == ["execution_claim_v2"]
    core.close()
    journal.close()


def test_server_v2_rpc_rejects_partial_and_v1_binding_before_claim(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    prepared, origin = _prepared(core, fences, bridge)
    server = object.__new__(AuthorityRpcServer)
    peer = SimpleNamespace(certificate_sha256="a" * 64)
    complete = to_wire(_binding_v2(origin))
    incomplete = dict(complete)
    del incomplete["initial_check_evidence_digest"]
    for binding_wire in (incomplete, to_wire(origin)):
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command(
                "execution_claim_v2", peer, "profile-a", "manifest-a",
                {"prepared_receipt": to_wire(prepared), "binding": binding_wire})
    assert journal.verified_head().seq == 1
    core.close()
    journal.close()
