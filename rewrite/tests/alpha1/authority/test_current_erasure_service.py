"""The current erasure entry must not turn a pending intent into success."""

import pytest
from dataclasses import replace

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.current_erasure_service import (
    CurrentErasureAuthority,
    GraphBarrierAttestationV1,
)
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_contract import (
    DeletionEvidenceV1, DeletionPendingV1, deletion_scope_digest,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_deletion_migration import AuthorityV2DeletionMigration
from sylanne3.authority_service.v2_deletion_recovery_service import (
    AuthorityV2DeletionPendingRecovery,
)
from sylanne3.authority_service.v2_deletion_tail_migration import (
    AuthorityV2DeletionTailMigration,
)
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_scoped_erasure_store import (
    AuthorityV2ScopedErasureStore, VerifiedGraphAppliedHeadV2,
)
from sylanne3.memory_types import source_key
from sylanne3.runtime.c09_erasure_barrier_store_v1 import C09GraphBarrierReceiptV1
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


def _prepare_storage_fixture_pending(
        erasure, *, credential, subject, holder, installation_id, owner_actor_id,
        owner_session_token, owner_session_request, deletion_operation_id,
        closure_roots, deletion_epoch, policy_ref):
    """Fixture-only pending storage; no Graph plan or product admission claim."""
    from dataclasses import asdict
    from hashlib import sha256
    from sylanne3.authority_service.contract import identifier
    from sylanne3.authority_service.v2_contract import FencePermitV2

    service, _, _, _, installed_id, scoped = erasure._prepare
    namespace = erasure._recovery.namespace
    for name, value in (
            ("subject", subject), ("holder", holder),
            ("installation_id", installation_id), ("owner_actor_id", owner_actor_id),
            ("deletion_operation_id", deletion_operation_id), ("policy_ref", policy_ref)):
        identifier(value, name)
    if (scoped is None or installation_id != installed_id
            or closure_roots != tuple(sorted(set(closure_roots)))
            or len(closure_roots) != 1):
        raise AuthorityUnavailable("fixture requires one canonical scoped storage root")
    service.core._require(credential, "deletion", namespace, holder)
    protocol = lambda kind: erasure._protocol_id(namespace, deletion_operation_id, kind)
    issuer = "storage-fixture-owner-session-v1"
    mutation_id = protocol("mutation")
    prior_receipt = None
    with service._frozen() as (db, deletion_head, execution_head, history):
        prior = service.fences.mutation_locked(db, mutation_id)
        if prior is not None:
            kind, pending, prior_receipt, _ = service.fences._decode_mutation_row(prior)
            if (kind != "deletion" or pending.permit.subject != subject
                    or pending.permit.holder != holder
                    or pending.deletion_operation_id != deletion_operation_id
                    or pending.closure_roots != closure_roots
                    or pending.deletion_epoch != deletion_epoch
                    or pending.policy_ref != policy_ref
                    or pending.evidence.issuer_id != issuer):
                raise AuthorityUnavailable("fixture deletion request replay differs")
        else:
            request, session, guard, _, _ = erasure._current_plan_owner_locked_v1(
                db, token=owner_session_token, request=owner_session_request,
                actor=owner_actor_id)
            anchor = service._current_locked(
                db, deletion_head, execution_head, holder=holder)
            if anchor.authority_id != request.authority_id:
                raise AuthorityUnavailable("fixture Owner Authority differs")
            permit = service.fences.begin_fence_locked(
                db, subject=subject, holder=holder, operation="delete",
                current_anchor=anchor, operation_id=protocol("fence"))
            identity = dict(
                schema="sylanne3.scoped-erasure-request.v2", namespace=namespace,
                operation_id=deletion_operation_id, scope_kind="one_source",
                roots=closure_roots, epoch=deletion_epoch,
                policy_ref=policy_ref, policy_version=1)
            request_digest = "sha256:" + canonical_digest(identity)
            proof = dict(
                request_digest=request_digest, owner_head=asdict(guard),
                actor_id=owner_actor_id, session=asdict(session),
                token_digest="sha256:" + sha256(owner_session_token.encode()).hexdigest(),
                anchor=asdict(anchor))
            evidence = DeletionEvidenceV1(
                authority_id=anchor.authority_id, namespace=namespace,
                deletion_operation_id=deletion_operation_id, kind="request_authorized",
                issuer_id=issuer, evidence_id=protocol("evidence"),
                bound_anchor=anchor, request_digest=request_digest,
                scope_digest=deletion_scope_digest(
                    closure_roots, deletion_epoch, policy_ref),
                proof_digest="sha256:" + canonical_digest(proof))
            draft = DeletionPendingV1(
                permit=permit, mutation_id=mutation_id, request_digest=request_digest,
                deletion_operation_id=deletion_operation_id,
                source_phase="absent", target_phase="pending",
                closure_roots=closure_roots, deletion_epoch=deletion_epoch,
                policy_ref=policy_ref, before_anchor=anchor, evidence=evidence,
                expected_append_id=protocol("append"),
                expected_append_digest="sha256:" + "0" * 64)
            pending = replace(
                draft, expected_append_digest=service.deletion.expected_digest(draft))
            scoped.reserve_locked(db, pending)
            service.fences.record_deletion_pending_locked(
                db, pending, subject=subject, current_anchor=anchor, core=service.core)
    if prior_receipt is None:
        service.deletion.append_pending(pending, core=service.core, fences=service.fences)
    receipt = erasure._recovery.recover(
        credential=credential, subject=subject, mutation_id=mutation_id)
    kind, saved, committed, updated = service.fences.get_mutation(
        mutation_id, subject=subject, namespace=namespace)
    if (receipt is None or receipt.pending != pending or kind != "deletion"
            or saved != pending or committed != receipt
            or type(updated) is not FencePermitV2
            or updated.pinned_anchor != receipt.after_anchor
            or updated.revision != receipt.updated_revision):
        raise AuthorityUnavailable("fixture pending storage recovery incomplete")
    return receipt, updated


def _apply_storage_fixture_head(scoped, *, credential, subject, receipt):
    """Exercise the real scoped CAS; this synthetic DTO grants no Graph proof."""
    from sylanne3.authority_service.contract import identifier

    if type(receipt) is not VerifiedGraphAppliedHeadV2:
        raise AuthorityUnavailable("typed fixture cumulative Graph claim required")
    identifier(subject, "subject")
    if receipt.namespace != scoped.namespace:
        raise AuthorityUnavailable("fixture Graph application crosses namespace")
    scoped.core._require(credential, "deletion", scoped.namespace)
    with scoped.deletion.freeze_writes():
        with scoped.execution.freeze_writes():
            head = scoped.deletion.verified_head()
            execution_head = scoped.execution.verified_head()
            with scoped.core._tx() as db:
                return scoped._apply_verified_head_locked_v1(
                    db, head, execution_head, subject, receipt)


def test_current_entry_requires_real_recovery_service():
    with pytest.raises(AuthorityUnavailable, match="real deletion pending recovery"):
        CurrentErasureAuthority(object())


@pytest.mark.parametrize("method,phase,argument", [
    (CurrentErasureAuthority.accept, "accepted", "barrier"),
])
def test_unimplemented_transitions_hold_without_invoking_input(method, phase, argument):
    class Poison:
        def __getattribute__(self, name):
            raise AssertionError("caller-supplied evidence must not be inspected")

    with pytest.raises(AuthorityUnavailable, match=phase):
        method(**{argument: Poison()})


def test_bare_cleanup_claim_is_not_a_current_cleanup_operation():
    # Product close accepts only its operation_id and actual installed verifier.
    # Caller supplied cleanup claims are rejected by the actual method signature.
    with pytest.raises(TypeError, match="cleanup"):
        CurrentErasureAuthority.close(None, cleanup=object())


def test_owner_signed_storage_fixture_does_not_grant_released_generation(tmp_path):
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from sylanne3.authority_service.v2_owner_contract import OwnerActorBindingV1
    from sylanne3.authority_service.v2_owner_proof import (
        AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
    )
    from sylanne3.authority_service.v2_owner_session import (
        AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
    )
    from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
    from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
    from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
    from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
        _installed, _owner_issue, ADMIN, AUTH_NS, CLAIMANT, PEER, ROLE, SUBJECT, WORKER,
    )
    from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import policy_for

    coordinator, bootstrap, service, compose, expected, principal, authority_id, resources = (
        _installed(tmp_path))
    core = resources[1]
    # The shared Owner fixture seals v2 using a separate seed namespace.
    # Delete only that fixture genesis before exercising the single-namespace
    # deletion-tail migration; the real Owner issue below remains untouched.
    with core._tx() as db:
        db.execute("DELETE FROM authority_namespaces WHERE namespace='seed'")
    original_authorizer = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        (namespace == AUTH_NS and (
            credential == ADMIN and action == "owner_identity_pair"
            or credential == PEER and action == "owner_pair"
            or credential == CLAIMANT and action == "owner_session"
            or credential == WORKER and (
                action == "migrate_deletion"
                or action == "deletion" and holder in {None, "administrator"})))
        or original_authorizer(credential, action, namespace, holder))
    try:
        policy = replace(policy_for(resources[0]), expected_authority_id=authority_id,
                         authority_namespace=AUTH_NS)
        creation = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="owner-creation")
        expected.update(operation_id=creation.operation_id,
                        digest="sha256:" + creation.input_digest)
        _, original_tickets = compose()
        ticket, operation, value = _owner_issue(creation, authority_id, principal)
        original_tickets.register_ticket(
            credential=ADMIN, authority_namespace=AUTH_NS, ticket=ticket)
        original_tickets.reserve_issue(
            credential=CLAIMANT, authority_namespace=AUTH_NS, operation=operation)
        proof = coordinator.commit_first_owner_grant_v2(
            bootstrap, namespace=ROLE, operation_id=operation.operation_id,
            grant_value=value)
        original_tickets.finalize_issue(
            credential=CLAIMANT, authority_namespace=AUTH_NS,
            operation=operation, proof=proof)
        AuthorityV2DeletionMigration(
            core=core, fences=service.fences, deletion=service.deletion,
            execution=service.execution, namespace=AUTH_NS).run(credential=WORKER)
        AuthorityV2DeletionTailMigration(
            core=core, fences=service.fences, deletion=service.deletion,
            execution=service.execution, namespace=AUTH_NS).run(credential=WORKER)
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=service.fences, deletion=service.deletion,
            execution=service.execution, namespace=AUTH_NS)
        assert scoped.migrate_zero_history(credential=WORKER).aggregate_phase == "clear"
        with core._tx() as db:
            assert db.execute("SELECT COUNT(*) FROM authority_owner_issue_committed_v1"
                              ).fetchone() == (1,)

        now = datetime(2029, 1, 1, tzinfo=timezone.utc)
        pairing = AuthorityOwnerPairingSource(
            core, utc_clock=lambda: now, create=True)
        key = Ed25519PrivateKey.generate()
        registration = OwnerCredentialRegistrationV1(
            authority_id, AUTH_NS, "installation", principal, "owner-key", 1,
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "enroll")
        pairing.pair_credential(
            administrator_credential=ADMIN, registration=registration,
            client_certificate_sha256="a" * 64,
            valid_until_utc=now + timedelta(days=365))
        pairing.pair_actor(
            administrator_credential=ADMIN,
            binding=OwnerActorBindingV1(
                authority_id, "installation", ROLE, "owner-actor", principal, 1))
        deployment = OwnerDeploymentVerifier(pairing, lambda: now)
        proofs = AuthorityV2OwnerProofStore(
            core, utc_clock=lambda: now,
            pairing_verifier=deployment.pair_credential, create=True)
        proofs.register_credential(
            transport_credential=PEER, registration=registration)
        sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=lambda: now,
            current_pairing_source=pairing, create=True)
        login = OwnerSessionLoginRequestV1(
            authority_id, AUTH_NS, "installation", principal,
            "owner-key", 1, "owner", "http://localhost:6185")
        challenge = sessions.begin_login(
            transport_credential=CLAIMANT, request=login)
        token = sessions.accept_login(
            transport_credential=CLAIMANT, challenge=challenge,
            signature=key.sign(challenge.signed_bytes()))
        tickets = AuthorityV2OwnerTicketStore(core, owner_sessions=sessions)
        recovery = AuthorityV2DeletionPendingRecovery(
            core=core, fences=service.fences, deletion=service.deletion,
            execution=service.execution, namespace=AUTH_NS,
            scoped_store=scoped)
        erasure = CurrentErasureAuthority(
            recovery, fence_service=service, owner_sessions=sessions,
            owner_tickets=tickets, installation_id="installation",
            scoped_store=scoped)
        args = dict(
            credential=WORKER, subject=SUBJECT, holder="administrator",
            installation_id="installation", owner_actor_id="owner-actor",
            owner_session_token=token, owner_session_request=login,
            deletion_operation_id="erase-root-a", closure_roots=("root-a",),
            deletion_epoch=1, policy_ref="installed-policy-a")
        with pytest.raises(AuthorityUnavailable, match="actor"):
            _prepare_storage_fixture_pending(erasure, **{
                **args, "owner_actor_id": "imposter"})
        with service.deletion.freeze_writes():
            assert service.deletion.latest_phases().get((AUTH_NS, "erase-root-a")) is None
        with pytest.raises(AuthorityUnavailable, match="plan reader"):
            erasure.prepare_request(**{
                key: value for key, value in args.items()
                if key not in {"closure_roots", "deletion_epoch", "policy_ref"}
            }, source_id="root-a")
        receipt, updated = _prepare_storage_fixture_pending(erasure, **args)
        assert receipt.pending.evidence.kind == "request_authorized"
        assert receipt.pending.closure_roots == ("root-a",)
        assert updated.pinned_anchor == receipt.after_anchor
        assert updated.revision == receipt.updated_revision
        assert _prepare_storage_fixture_pending(erasure, **args) == (receipt, updated)
        with pytest.raises(AuthorityUnavailable):
            _prepare_storage_fixture_pending(erasure, **{
                **args, "deletion_operation_id": "overlapping-erase",
                "closure_roots": ("root-b",)})

        # Authority storage mechanics only: W01 has no cumulative Graph
        # application or cleanup verifier yet. Synthetic later-phase evidence
        # here must never be used to open public accepted/closed.
        permit = updated
        for ordinal, (source, target) in enumerate(
                (("pending", "accepted"), ("accepted", "closed")), start=2):
            anchor = permit.pinned_anchor
            evidence = DeletionEvidenceV1(
                authority_id=authority_id, namespace=AUTH_NS,
                deletion_operation_id="erase-root-a",
                kind="barrier_installed" if target == "accepted"
                else "cleanup_complete", issuer_id="controlled-storage-test",
                evidence_id=f"controlled-evidence-{ordinal}",
                bound_anchor=anchor, request_digest=receipt.pending.request_digest,
                scope_digest=receipt.pending.evidence.scope_digest,
                proof_digest="sha256:" + "e" * 64,
                graph_version="controlled-graph", incarnation="controlled-incarnation",
                access_epoch=1, deletion_epoch=1,
                barrier_scope_digest="sha256:" + "f" * 64,
                cleanup_digest="sha256:" + "d" * 64 if target == "closed" else None)
            draft = DeletionPendingV1(
                permit=permit, mutation_id=f"controlled-mutation-{ordinal}",
                request_digest=receipt.pending.request_digest,
                deletion_operation_id="erase-root-a",
                source_phase=source, target_phase=target,
                closure_roots=("root-a",), deletion_epoch=1,
                policy_ref="installed-policy-a", before_anchor=anchor,
                evidence=evidence, expected_append_id=f"controlled-append-{ordinal}",
                expected_append_digest="sha256:" + "0" * 64)
            phase = replace(
                draft, expected_append_digest=service.deletion.expected_digest(draft))
            with core._tx() as db:
                service.fences.record_deletion_pending_locked(
                    db, phase, subject=SUBJECT, current_anchor=anchor)
            service.deletion.append_transition(
                phase, core=core, fences=service.fences)
            phase_receipt = recovery.recover(
                credential=WORKER, subject=SUBJECT, mutation_id=phase.mutation_id)
            assert phase_receipt is not None
            _, _, _, permit = service.fences.get_mutation(
                phase.mutation_id, subject=SUBJECT, namespace=AUTH_NS)
        assert phase_receipt.pending.target_phase == "closed"
        with core._tx() as db:
            assert scoped.state_locked(db).aggregate_phase == "accepted"
        applied = VerifiedGraphAppliedHeadV2(
            AUTH_NS, "erase-root-a", phase_receipt.after_anchor.deletion_seq,
            phase_receipt.after_anchor.deletion_digest, 1,
            "sha256:" + "c" * 64)
        with pytest.raises(AuthorityUnavailable, match="pinned cumulative Graph"):
            scoped.apply_verified_head(
                credential=WORKER, subject=SUBJECT, operation_id=applied.deletion_operation_id)
        assert _apply_storage_fixture_head(scoped,
            credential=WORKER, subject=SUBJECT,
            receipt=applied).aggregate_phase == "clear"
        # Synthetic storage completion does not install a verified RELEASED
        # generation. A later business deletion still requires that real gate.
        with pytest.raises(AuthorityUnavailable,
                           match="installed current C09 storage verifier unavailable"):
            _prepare_storage_fixture_pending(erasure, **{
                **args, "deletion_operation_id": "erase-root-b",
                "closure_roots": ("root-b",), "deletion_epoch": 2})
        with service.deletion.freeze_writes():
            assert service.deletion.latest_phases().get(
                (AUTH_NS, "erase-root-b")) is None
        with core._tx() as db:
            assert service.fences.mutation_locked(
                db, erasure._protocol_id(AUTH_NS, "erase-root-b", "mutation")) is None
        assert scoped.read_ancestor_receipt(
            credential=WORKER, subject=SUBJECT,
            mutation_id=receipt.pending.mutation_id) == receipt
        with pytest.raises(AuthorityUnavailable, match="replay differs"):
            _prepare_storage_fixture_pending(erasure, **{
                **args, "closure_roots": ("different-root",)})
        with pytest.raises(AuthorityUnavailable, match="accepted phase remains HOLD"):
            erasure.accept()
    finally:
        for resource in resources:
            resource.close()


def test_legacy_owner_graph_fixture_requires_current_c09_installation(tmp_path):
    """A real Owner and legacy plan cannot replace installed V2 resources.

    Positive prepare/barrier/accepted coverage requires the genuine installed
    daemon and paged capture resources; this engineering fixture has neither.
    """
    from uuid import uuid4

    from rewrite.tests.alpha1.integration.test_owner_signed_chain import (
        PEER, ROLE, _real_owner_chain,
    )
    from rewrite.tests.alpha1.authority.test_local_owner_round_trip import (
        ADMIN, SUBJECT, WORKER,
    )
    from sylanne3.contracts import Event, Scope
    from sylanne3.domains.d06 import D06DomainProvider
    from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
    from sylanne3.graph_store import GraphStore, ProductionGraphStore, TypeRegistry
    from sylanne3.graph_types import GraphCandidate, GraphWrite, owner_grant_spec
    from sylanne3.memory_types import SourceRecord, access_key
    from sylanne3.authority_service.v2_deletion_graph_read import (
        AuthorityV2DeletionGraphReadService,
    )

    chain = _real_owner_chain(
        tmp_path, extra_purpose="context",
        extra_capability="workbench.erase",
        extra_specs=D06DomainProvider.type_specs())
    graph = None
    try:
        core = chain.resources[1]
        with core._tx() as db:
            db.execute("DELETE FROM authority_namespaces WHERE namespace='seed'")
        old_authorizer = core._authorize_callback
        core._authorize_callback = lambda credential, action, namespace, holder: (
            namespace == chain.service.namespace and (
                credential == WORKER
                and action in {"migrate_deletion", "deletion", "delete"}
                and holder in {None, "administrator"}
                or credential == ADMIN
                and action == "erasure_closure_install")
        ) or old_authorizer(credential, action, namespace, holder)
        AuthorityV2DeletionMigration(
            core=core, fences=chain.service.fences,
            deletion=chain.service.deletion, execution=chain.service.execution,
            namespace=chain.service.namespace).run(credential=WORKER)
        AuthorityV2DeletionTailMigration(
            core=core, fences=chain.service.fences,
            deletion=chain.service.deletion, execution=chain.service.execution,
            namespace=chain.service.namespace).run(credential=WORKER)
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=chain.service.fences,
            deletion=chain.service.deletion, execution=chain.service.execution,
            namespace=chain.service.namespace)
        assert scoped.migrate_zero_history(credential=WORKER).aggregate_phase == "clear"


        registry = TypeRegistry()
        registry.register(owner_grant_spec())
        for spec in D06DomainProvider.type_specs():
            registry.register(spec)
        graph = ProductionGraphStore(tmp_path / "business.db", registry)
        coordinator = GraphCoordinator(
            graph, chain.bootstrap, holder="administrator",
            content_fence_v2=chain.port,
            owner_principal_resolver=chain.current_principal)
        provider = D06DomainProvider()
        coordinator.register_provider(
            chain.bootstrap, "d06", provider, "d06.contract.v1",
            provider.descriptor.request_schema_hash)
        source = source_key(*ROLE.as_tuple, "source-c09")
        access = access_key(*ROLE.as_tuple, "source-c09")
        record = SourceRecord(
            "source-c09", "private", "speaker", "reported", "reported",
            1.0, 2.0, "family", ("owner",), ("context",))
        snapshot = GraphStore.graph_snapshot(
            graph, (source, access), _capability=graph._coordinator_capability)
        GraphStore.graph_commit(
            graph, GraphCandidate(
                Event(Scope(*ROLE.as_tuple, "seed"), "seed-c09-source", 2.0,
                      "seed", {}), snapshot.versions,
                (GraphWrite(source, record.to_dict()),
                 GraphWrite(access, {
                     "source_id": "source-c09", "audiences": ["owner"],
                     "purposes": ["context"], "status": "active",
                     "recorded_at": 2.0}, (source,))), snapshot.epochs),
            _capability=graph._coordinator_capability)
        login = replace(chain.issue_request, audience="owner")
        challenge = chain.sessions.begin_login(
            transport_credential=PEER, request=login)
        token = chain.sessions.accept_login(
            transport_credential=PEER, challenge=challenge,
            signature=chain.key.sign(challenge.signed_bytes()))
        authority, lease, _ = coordinator.grant_current_owner(
            chain.bootstrap, actor="owner-actor", namespace=ROLE,
            domains=("d06",), purpose="context", audience="owner",
            activation_generation=1, owner_session_token=token,
            owner_session_request=login)
        try:
            operation_id = str(uuid4())
            with pytest.raises(UnavailableGuard,
                               match="installed C09 Owner paged plan unavailable"):
                coordinator.issue_current_c09_erasure_plan_v2(
                    authority, lease, operation_id=operation_id,
                    source_ref=source.token)
            plan = coordinator.issue_current_c09_erasure_plan_v1(
                authority, lease, operation_id=operation_id,
                source_ref=source.token)
            recovery = AuthorityV2DeletionPendingRecovery(
                core=core, fences=chain.service.fences,
                deletion=chain.service.deletion,
                execution=chain.service.execution,
                namespace=chain.service.namespace, scoped_store=scoped)
            tickets = chain.server._v2_owner_tickets
            pending_reader = AuthorityV2DeletionGraphReadService(
                fence_service=chain.service, owner_tickets=tickets)

            def read_pending_for_graph(*, namespace, authority_namespace,
                                       deletion_operation_id, permit):
                assert namespace == ROLE
                assert authority_namespace == chain.service.namespace
                return pending_reader.get_pending_deletion_for_graph_write(
                    credential=WORKER, subject=SUBJECT,
                    installation_id="installation",
                    deletion_operation_id=deletion_operation_id, permit=permit)

            chain.port.get_pending_deletion_for_graph_write = read_pending_for_graph
            erasure = CurrentErasureAuthority(
                recovery, fence_service=chain.service,
                owner_sessions=chain.sessions,
                owner_tickets=tickets,
                installation_id="installation", scoped_store=scoped,
                plan_graph_coordinator=coordinator,
                graph_db_path=tmp_path / "business.db",
                graph_coordinator=coordinator, graph_bootstrap=chain.bootstrap,
                namespace_id=ROLE, pending_graph_reader=pending_reader)
            args = dict(
                credential=WORKER, subject=SUBJECT, holder="administrator",
                installation_id="installation", owner_actor_id="owner-actor",
                owner_session_token=token, owner_session_request=login,
                deletion_operation_id=operation_id,
                source_id=plan.source_id)
            with pytest.raises(AuthorityUnavailable, match="Graph plan unavailable"):
                erasure.prepare_request(**{
                    **args, "source_id": "different-source"})
            with chain.service.deletion.freeze_writes():
                assert chain.service.deletion.latest_phases().get(
                    (chain.service.namespace, operation_id)) is None
            with core._tx() as db:
                assert db.execute(
                    "SELECT count(*) FROM authority_v2_fences WHERE namespace=? "
                    "AND state='active'", (chain.service.namespace,)).fetchone() == (0,)
                assert db.execute(
                    "SELECT count(*) FROM authority_v2_mutations WHERE namespace=? "
                    "AND mutation_kind='deletion'",
                    (chain.service.namespace,)).fetchone() == (0,)
            # No plan table or selected storage identity is fabricated here.
            with pytest.raises(AuthorityUnavailable,
                               match="current pinned C09 Graph plan unavailable"):
                erasure.prepare_request(**args)
            with chain.service.deletion.freeze_writes():
                assert chain.service.deletion.latest_phases().get(
                    (chain.service.namespace, operation_id)) is None
            with core._tx() as db:
                assert db.execute(
                    "SELECT count(*) FROM authority_v2_fences WHERE namespace=? "
                    "AND state='active'", (chain.service.namespace,)).fetchone() == (0,)
                assert db.execute(
                    "SELECT count(*) FROM authority_v2_mutations WHERE namespace=? "
                    "AND mutation_kind='deletion'",
                    (chain.service.namespace,)).fetchone() == (0,)
        finally:
            coordinator.release_current_owner_lease(chain.bootstrap, lease)
    finally:
        if graph is not None:
            graph.close()
        for resource in chain.resources:
            resource.close()


def _open_ledger(path, *, create=False):
    """Local storage fixture; it makes no Owner or graph proof claim."""
    journal = DeletionJournal(path / "deletion.db", create=create)
    guard = AuthorityV2DeletionGuard(path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        path / "execution.db", namespace="ns-a", journal_id="execution-a",
        create=create)
    head = journal.latest_head()
    core = AuthorityServiceCore(
        path / "authority.db", create=create,
        authorizer=lambda credential, action, namespace, holder: credential == "ok",
        deletion_verifier=lambda ns, before, current, phase: (
            (current.journal_id, current.seq, current.digest)
            == (head.journal_id, head.seq, head.chain_digest) and phase == "clear"),
        execution_verifier=lambda ns, before, current, phase: (
            current == JournalHead("execution-a", 0, "genesis")),
        effect_verifier=lambda *args: False,
        dispatch_verifier=lambda *args: False)
    if create:
        core.register_namespace(
            "ok", "ns-a", "holder-a",
            JournalHead(head.journal_id, head.seq, head.chain_digest),
            JournalHead("execution-a", 0, "genesis"))
        core.seal_v2_only("ok")
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    if create:
        AuthorityV2DeletionMigration(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace="ns-a").run(credential="ok")
        AuthorityV2DeletionTailMigration(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace="ns-a").run(credential="ok")
    return core, fences, journal, guard, execution


def _close_ledger(parts):
    parts[0].close()
    parts[2].close()
    parts[3].close()
    parts[4].close()


def _phase(parts, permit, source, target, *, ordinal, roots=("root-a",)):
    anchor = permit.pinned_anchor
    operation = "deletion-a"
    request_digest = "sha256:" + "a" * 64
    kind = {"pending": "request_authorized", "accepted": "barrier_installed",
            "closed": "cleanup_complete"}[target]
    extra = {}
    if target != "pending":
        extra.update(graph_version="graph-a", incarnation="graph-incarnation-a",
                     access_epoch=1, deletion_epoch=1,
                     barrier_scope_digest="sha256:" + "b" * 64)
    if target == "closed":
        extra["cleanup_digest"] = "sha256:" + "c" * 64
    evidence = DeletionEvidenceV1(
        authority_id=permit.authority_id, namespace="ns-a",
        deletion_operation_id=operation, kind=kind, issuer_id="ledger-fixture",
        evidence_id=f"evidence-{ordinal}", bound_anchor=anchor,
        request_digest=request_digest,
        scope_digest=deletion_scope_digest(roots, 1, "policy-a"),
        proof_digest="sha256:" + "d" * 64, **extra)
    draft = DeletionPendingV1(
        permit=permit, mutation_id=f"mutation-{ordinal}",
        request_digest=request_digest, deletion_operation_id=operation,
        source_phase=source, target_phase=target, closure_roots=roots,
        deletion_epoch=1, policy_ref="policy-a", before_anchor=anchor,
        evidence=evidence, expected_append_id=f"append-{ordinal}",
        expected_append_digest="sha256:" + "0" * 64)
    return replace(draft, expected_append_digest=parts[3].expected_digest(draft))


def test_scoped_migration_preserves_legacy_pending_as_hold(tmp_path):
    parts = _open_ledger(tmp_path, create=True)
    try:
        core, fences, _, deletion, execution = parts
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="delete", operation_id="legacy-fence",
            expected_anchor=anchor)
        pending = _phase(parts, permit, "absent", "pending", ordinal=1)
        with core._tx() as db:
            fences.record_deletion_pending_locked(
                db, pending, subject="subject-a", current_anchor=anchor)
        deletion.append_pending(pending, core=core, fences=fences)
        recovery = AuthorityV2DeletionPendingRecovery(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        assert recovery.recover(
            credential="ok", subject="subject-a",
            mutation_id=pending.mutation_id) is not None
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        with pytest.raises(AuthorityUnavailable, match="legacy deletion history"):
            scoped.migrate_zero_history(credential="ok")
        with core._tx() as db:
            assert "hold_legacy_history" in db.execute(
                "SELECT value FROM authority_meta "
                "WHERE key='scoped_erasure_v2_migration'").fetchone()[0]
            assert db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='authority_scoped_erasure_v2'"
            ).fetchone() is None
    finally:
        _close_ledger(parts)


def test_scoped_reserved_pending_cold_reopen_uses_same_original(tmp_path):
    parts = _open_ledger(tmp_path, create=True)
    try:
        core, fences, _, deletion, execution = parts
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        scoped.migrate_zero_history(credential="ok")
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="delete", operation_id="scoped-fence",
            expected_anchor=anchor)
        pending = _phase(parts, permit, "absent", "pending", ordinal=1)
        with core._tx() as db:
            scoped.reserve_locked(db, pending)
            fences.record_deletion_pending_locked(
                db, pending, subject="subject-a", current_anchor=anchor)
        _close_ledger(parts)
        parts = _open_ledger(tmp_path)
        core, fences, _, deletion, execution = parts
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        recovery = AuthorityV2DeletionPendingRecovery(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a", scoped_store=scoped)
        assert recovery.recover(
            credential="ok", subject="subject-a",
            mutation_id=pending.mutation_id) is None
        deletion.append_pending(pending, core=core, fences=fences)
        _close_ledger(parts)
        parts = _open_ledger(tmp_path)
        core, fences, _, deletion, execution = parts
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        recovery = AuthorityV2DeletionPendingRecovery(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a", scoped_store=scoped)
        receipt = recovery.recover(
            credential="ok", subject="subject-a",
            mutation_id=pending.mutation_id)
        assert receipt.pending == pending
        assert receipt.after_anchor.deletion_seq == 1
    finally:
        _close_ledger(parts)


def test_internal_phase_ledger_replays_each_head_after_cold_open(tmp_path):
    """Storage mechanics only: synthetic evidence never opens the public entry."""
    parts = _open_ledger(tmp_path, create=True)
    try:
        core, fences, _, guard, execution = parts
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace="ns-a")
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="delete", operation_id="fence-a", expected_anchor=anchor)
        recovery = AuthorityV2DeletionPendingRecovery(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace="ns-a")
        prior_receipt = None
        for ordinal, (source, target) in enumerate(
                (("absent", "pending"), ("pending", "accepted"),
                 ("accepted", "closed")), start=1):
            pending = _phase(parts, permit, source, target, ordinal=ordinal)
            if ordinal == 2:
                graph_namespace = NamespaceId("bot-a", "persona-a")
                roots = (source_key("bot-a", "persona-a", "root-a").token,)
                graph_claim = C09GraphBarrierReceiptV1(
                    graph_namespace, pending.deletion_operation_id,
                    pending.request_digest.removeprefix("sha256:"),
                    canonical_digest(prior_receipt),
                    deletion_scope_digest(
                        pending.closure_roots, pending.deletion_epoch,
                        pending.policy_ref).removeprefix("sha256:"),
                    roots, roots, "graph-incarnation-a", 0, 1, 0, 1, 0, 1,
                    "graph-erasure", "a" * 64, "b" * 64)
                barrier = GraphBarrierAttestationV1(prior_receipt, graph_claim)
                with pytest.raises(AuthorityUnavailable, match="accepted phase remains HOLD"):
                    CurrentErasureAuthority.accept(barrier=barrier)
                with pytest.raises(ValueError, match="pending original"):
                    GraphBarrierAttestationV1(
                        prior_receipt,
                        replace(graph_claim, closure_digest="f" * 64))
                with pytest.raises(AuthorityUnavailable, match="installed C09 graph reader"):
                    CurrentErasureAuthority(recovery).read_graph_barrier_candidate(
                        credential="ok", subject="subject-a",
                        pending_mutation_id=prior_receipt.pending.mutation_id)
            if ordinal == 3:
                with pytest.raises(TypeError, match="cleanup"):
                    CurrentErasureAuthority.close(None, cleanup=object())
            with core._tx() as db:
                fences.record_deletion_pending_locked(
                    db, pending, subject="subject-a", current_anchor=anchor)
            if ordinal == 2:
                changed_scope = _phase(
                    parts, permit, source, target, ordinal=99, roots=("other-root",))
                with core._tx() as db:
                    with pytest.raises(AuthorityUnavailable, match="prior original"):
                        fences.require_prior_deletion_transition_locked(db, changed_scope)
                changed_epoch = replace(
                    pending, evidence=replace(pending.evidence, deletion_epoch=2))
                with core._tx() as db:
                    with pytest.raises(AuthorityUnavailable, match="deletion epoch"):
                        fences.require_prior_deletion_transition_locked(db, changed_epoch)
            if ordinal == 3:
                changed_barrier = replace(
                    pending, evidence=replace(
                        pending.evidence,
                        barrier_scope_digest="sha256:" + "e" * 64))
                with core._tx() as db:
                    with pytest.raises(AuthorityUnavailable, match="accepted graph barrier"):
                        fences.require_prior_deletion_transition_locked(db, changed_barrier)
            if ordinal == 1:
                guard.append_pending(pending, core=core, fences=fences)
            else:
                guard.append_transition(pending, core=core, fences=fences)
            _close_ledger(parts)
            parts = _open_ledger(tmp_path)
            core, fences, _, guard, execution = parts
            recovery = AuthorityV2DeletionPendingRecovery(
                core=core, fences=fences, deletion=guard, execution=execution,
                namespace="ns-a")
            receipt = recovery.recover(
                credential="ok", subject="subject-a", mutation_id=pending.mutation_id)
            assert receipt is not None and receipt.pending == pending
            assert receipt.after_anchor.deletion_seq == ordinal
            assert receipt.after_anchor.deletion_digest == pending.expected_append_digest
            assert receipt.after_anchor.revocation_epoch == anchor.revocation_epoch + 1
            _close_ledger(parts)
            parts = _open_ledger(tmp_path)
            core, fences, _, guard, execution = parts
            recovery = AuthorityV2DeletionPendingRecovery(
                core=core, fences=fences, deletion=guard, execution=execution,
                namespace="ns-a")
            assert recovery.recover(
                credential="ok", subject="subject-a", mutation_id=pending.mutation_id
            ) == receipt
            kind, saved, saved_receipt, permit = fences.get_mutation(
                pending.mutation_id, subject="subject-a", namespace="ns-a")
            assert kind == "deletion" and saved == pending and saved_receipt == receipt
            prior_receipt = receipt
            anchor = receipt.after_anchor
            with guard.freeze_writes():
                assert guard.verified_head().seq == ordinal
                assert guard.latest_phases()[("ns-a", "deletion-a")] == target
            with core._tx() as db:
                assert core._row(db, "ns-a")[9] == target
    finally:
        _close_ledger(parts)
