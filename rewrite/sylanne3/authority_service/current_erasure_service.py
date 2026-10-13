"""Authority-local deletion pending entry; public erasure remains HOLD.

A paired Owner service can durably prepare a diagnostic pending original.
There is no installed D12 plan verification, cumulative Graph application
proof, or cleanup certification, so no public deletion success is exposed.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import re
import uuid

from ..memory_types import source_key
from ..runtime.c09_erasure_barrier_store_v1 import C09GraphBarrierReceiptV1
from ..runtime.c09_erasure_plan_original_v1 import C09ErasurePlanOriginalV1
from ..runtime.c09_source_plan_barrier_v2 import C09SourcePlanCaptureV2,C09GraphBarrierReceiptV2,authority_c09_plan_request_identity_v2
from ..runtime_contracts import NamespaceId, canonical_digest
from .contract import AuthorityUnavailable, identifier
from .v2_contract import (
    DeletionEvidenceV1, DeletionMutationReceiptV1, DeletionPendingV1,
    FencePermitV2, deletion_scope_digest,
)
from .v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
from .v2_fence_service import AuthorityV2FenceService
from .v2_owner_session import AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REQUIRED_CLEANUP_SURFACES = frozenset({
    "graph_current_history", "graph_dependency_history",
    "source_derived_caches", "retrieval_indexes", "process_local_caches",
    "model_prompt_caches", "jobs_drafts", "experiments_diagnostics",
    "imports_exports", "execution_journal_payloads", "sqlite_wal_free_pages",
    "controlled_backups",
})


@dataclass(frozen=True, slots=True)
class GraphBarrierAttestationV1:
    """Bound pair of originals; the source reader determines its authority."""

    pending_receipt: DeletionMutationReceiptV1
    graph_receipt: C09GraphBarrierReceiptV1

    def __post_init__(self) -> None:
        if type(self.pending_receipt) is not DeletionMutationReceiptV1:
            raise TypeError("durable Authority pending receipt required")
        pending = self.pending_receipt.pending
        if pending.target_phase != "pending" or pending.source_phase != "absent":
            raise ValueError("barrier requires the original pending receipt")
        graph = self.graph_receipt
        if type(graph) is not C09GraphBarrierReceiptV1:
            raise TypeError("durable graph barrier receipt required")
        expected_roots = tuple(sorted(
            source_key(*graph.namespace.as_tuple, source_id).token
            for source_id in pending.closure_roots))
        if (graph.operation_id != pending.deletion_operation_id
                or graph.request_digest != pending.request_digest.removeprefix("sha256:")
                or graph.pending_receipt_digest != canonical_digest(self.pending_receipt)
                or graph.closure_digest != deletion_scope_digest(
                    pending.closure_roots, pending.deletion_epoch,
                    pending.policy_ref).removeprefix("sha256:")
                or graph.root_source_refs != expected_roots
                or graph.delete_epoch_after != pending.deletion_epoch):
            raise ValueError("graph barrier differs from pending original")


@dataclass(frozen=True, slots=True)
class GraphBarrierAttestationV2:
    """Bound actual Core pending and complete multi-page Source withdrawal."""
    pending_receipt: DeletionMutationReceiptV1
    graph_receipt: C09GraphBarrierReceiptV2

    def __post_init__(self):
        if type(self.pending_receipt) is not DeletionMutationReceiptV1 or type(self.graph_receipt) is not C09GraphBarrierReceiptV2:
            raise TypeError('actual Core pending and V2 Source barrier required')
        pending=self.pending_receipt.pending;graph=self.graph_receipt
        if ((pending.source_phase,pending.target_phase)!=('absent','pending') or len(pending.closure_roots)!=1
                or graph.operation_id!=pending.deletion_operation_id
                or graph.request_digest!=pending.request_digest.removeprefix('sha256:')
                or graph.pending_receipt_digest!=canonical_digest(self.pending_receipt)
                or graph.closure_digest!=deletion_scope_digest(pending.closure_roots,pending.deletion_epoch,pending.policy_ref).removeprefix('sha256:')
                or graph.root_source_refs!=(source_key(*graph.namespace.as_tuple,pending.closure_roots[0]).token,)
                or graph.delete_epoch_after!=pending.deletion_epoch):
            raise ValueError('complete paged Source barrier differs from actual pending')


@dataclass(frozen=True, slots=True)
class CleanupSurfaceReceiptV1:
    """One non-content surface claim; its issuer still needs live verification."""

    surface: str
    operation_id: str
    scope_digest: str
    status: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if self.surface not in REQUIRED_CLEANUP_SURFACES:
            raise ValueError("unknown cleanup surface")
        identifier(self.operation_id, "operation_id")
        if (self.status not in {"purged", "sanitized", "reset", "not_applicable"}
                or type(self.scope_digest) is not str
                or _DIGEST.fullmatch(self.scope_digest) is None
                or type(self.receipt_digest) is not str
                or _DIGEST.fullmatch(self.receipt_digest) is None):
            raise ValueError("invalid cleanup surface claim")


@dataclass(frozen=True, slots=True)
class CleanupAttestationV1:
    """Complete claim set for future verification; not a closure receipt."""

    accepted_receipt: DeletionMutationReceiptV1
    surface_receipts: tuple[CleanupSurfaceReceiptV1, ...]
    evidence: DeletionEvidenceV1

    def __post_init__(self) -> None:
        if type(self.accepted_receipt) is not DeletionMutationReceiptV1:
            raise TypeError("durable accepted receipt required")
        pending = self.accepted_receipt.pending
        if (pending.source_phase, pending.target_phase) != ("pending", "accepted"):
            raise ValueError("cleanup requires accepted phase original")
        if (type(self.surface_receipts) is not tuple
                or any(type(item) is not CleanupSurfaceReceiptV1
                       for item in self.surface_receipts)
                or {item.surface for item in self.surface_receipts}
                   != REQUIRED_CLEANUP_SURFACES
                or len(self.surface_receipts) != len(REQUIRED_CLEANUP_SURFACES)):
            raise ValueError("all unique cleanup surfaces need receipts")
        scope = deletion_scope_digest(
            pending.closure_roots, pending.deletion_epoch, pending.policy_ref)
        if any((item.operation_id, item.scope_digest)
               != (pending.deletion_operation_id, scope)
               for item in self.surface_receipts):
            raise ValueError("cleanup surface differs from deletion original")
        evidence = self.evidence
        if (type(evidence) is not DeletionEvidenceV1
                or evidence.kind != "cleanup_complete"
                or evidence.bound_anchor != self.accepted_receipt.after_anchor
                or evidence.authority_id != pending.permit.authority_id
                or evidence.namespace != pending.permit.namespace
                or evidence.deletion_operation_id != pending.deletion_operation_id
                or evidence.request_digest != pending.request_digest
                or evidence.scope_digest != scope
                or evidence.deletion_epoch != pending.deletion_epoch):
            raise ValueError("cleanup claim differs from accepted original")


MISSING_PORTS = (
    "product D12 admission for the pinned Owner erasure plan",
    "pinned cumulative C09 Graph application verifier and product admission",
    "issuer-owned inventory and independently verified receipts for every cleanup surface",
    "ScopedErasureV2 content readiness and historical migration qualification",
)


class CurrentErasureAuthority:
    """Internal consumer of an original pending recovery, never a success facade."""

    def __init__(self, recovery: AuthorityV2DeletionPendingRecovery, *,
                 graph_coordinator=None, graph_bootstrap=None,
                 namespace_id: NamespaceId | None = None,
                 pending_graph_reader=None, installation_id: str | None = None,
                 fence_service: AuthorityV2FenceService | None = None,
                 owner_sessions: AuthorityV2OwnerSessionStore | None = None,
                 owner_tickets: AuthorityV2OwnerTicketStore | None = None,
                 scoped_store: AuthorityV2ScopedErasureStore | None = None,
                 plan_graph_coordinator=None, graph_db_path=None):
        if type(recovery) is not AuthorityV2DeletionPendingRecovery:
            raise AuthorityUnavailable("real deletion pending recovery service required")
        self._recovery = recovery
        self._current_cleanup_v1 = None
        self._graph_reader = None
        self._prepare = None
        self._plan_graph_coordinator = None
        self._plan_graph_verifier = None
        self._owner_storage_reader_v1 = None
        if graph_db_path is not None:
            from .current_erasure_plan_graph_verifier import PinnedCurrentErasurePlanGraphVerifier
            self._plan_graph_verifier = PinnedCurrentErasurePlanGraphVerifier(graph_db_path)
        if plan_graph_coordinator is not None:
            from ..graph_coordinator import GraphCoordinator
            if type(plan_graph_coordinator) is not GraphCoordinator:
                raise AuthorityUnavailable("installed C09 plan coordinator required")
            self._plan_graph_coordinator = plan_graph_coordinator
        if any(item is not None for item in (fence_service, owner_sessions,
                                              owner_tickets, scoped_store)):
            from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource

            pairing = (owner_sessions._current_pairing_source
                       if type(owner_sessions) is AuthorityV2OwnerSessionStore else None)
            if (type(fence_service) is not AuthorityV2FenceService
                    or type(owner_sessions) is not AuthorityV2OwnerSessionStore
                    or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                    or type(pairing) is not AuthorityOwnerPairingSource
                    or fence_service.core is not recovery.core
                    or fence_service.fences is not recovery.fences
                    or fence_service.deletion is not recovery.deletion
                    or fence_service.execution is not recovery.execution
                    or fence_service.namespace != recovery.namespace
                    or owner_sessions._core is not recovery.core
                    or pairing._core is not recovery.core
                    or owner_tickets._core is not recovery.core
                    or owner_tickets._owner_sessions is not owner_sessions
                    or scoped_store is not recovery.scoped_store
                    or type(installation_id) is not str):
                raise AuthorityUnavailable("paired Owner deletion preparation services required")
            identifier(installation_id, "installation_id")
            self._prepare = (fence_service, owner_sessions, owner_tickets,
                             pairing, installation_id, scoped_store)
        configured = (graph_coordinator, graph_bootstrap, namespace_id,
                      pending_graph_reader, installation_id)
        if any(item is not None for item in configured[:-1]):
            from ..graph_coordinator import GraphCoordinator
            from .v2_deletion_graph_read import AuthorityV2DeletionGraphReadService

            if (type(graph_coordinator) is not GraphCoordinator
                    or graph_bootstrap is None
                    or type(namespace_id) is not NamespaceId
                    or type(pending_graph_reader) is not AuthorityV2DeletionGraphReadService
                    or type(installation_id) is not str
                    or pending_graph_reader._service.core is not recovery.core
                    or pending_graph_reader._service.fences is not recovery.fences
                    or pending_graph_reader._service.namespace != recovery.namespace):
                raise AuthorityUnavailable("paired installed C09 graph reader required")
            identifier(installation_id, "installation_id")
            self._graph_reader = (graph_coordinator, graph_bootstrap,
                                  namespace_id, pending_graph_reader, installation_id)

    def install_current_owner_storage_reader_v1(self, reader):
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        if (type(reader) is not InstalledD12OwnerStorageAdmissionServiceV1
                or self._prepare is None or self._plan_graph_verifier is None
                or reader.fences is not self._prepare[0]
                or reader.tickets is not self._prepare[2]
                or reader.installation_id != self._prepare[4]
                or reader.graph_path != self._plan_graph_verifier._path
                or self._owner_storage_reader_v1 not in (None, reader)):
            raise AuthorityUnavailable("actual paired C09 Owner storage reader required")
        self._owner_storage_reader_v1 = reader

    def _current_plan_owner_locked_v1(self, db, *, token, request, actor):
        _, sessions, tickets, pairing, installed_id, _ = self._prepare
        namespace = self._recovery.namespace
        if request is None:
            request = sessions.describe_current_in_tx(
                db, token=token, namespace=namespace, installation_id=installed_id)
        session = sessions.require_current_in_tx(db, token=token, request=request)
        pairing.require_current_actor_in_tx(db, authority_namespace=namespace,
            installation_id=installed_id, actor_id=actor, principal=session.principal)
        guard = tickets._checked_current_head(db, namespace)
        head = db.execute("SELECT issue_operation_id FROM authority_owner_authorization_heads_v1 "
                          "WHERE authority_namespace=?", (namespace,)).fetchone()
        origin = tickets._checked_pending(db, namespace, head[0]) if head else None
        committed = tickets._checked_committed(db, namespace, head[0]) if head else None
        if (guard is None or guard.pending_revoke_operation_id is not None
                or guard.installation_id != installed_id
                or guard.authority_id != request.authority_id
                or guard.authorization_revision < 1
                or origin is None or origin[0].principal != session.principal
                or committed is None):
            raise AuthorityUnavailable("current Owner deletion authorization unavailable")
        return request, session, guard, origin, committed

    @contextmanager
    def _observe_current_plan_v1(self, *, credential, subject, holder, actor,
                                 token, request, operation, source, mutation_id,
                                 enabled):
        """Keep a real read fence active across SQL-free Graph/storage reads.

        Only this private context issues an observation. Its caller consumes the
        exact permit into the delete fence in one Core transaction. No external
        DTO or previously closed read can substitute for that handoff.
        """
        if not enabled:
            yield None
            return
        service, _, _, _, installed_id, scoped = self._prepare
        from .d12_lifecycle_gate_v1 import require_lifecycle_exclusion_in_tx_v1
        from ..graph_coordinator import namespace_ref
        permit = None
        try:
            with service._frozen() as (db, deletion, execution, history):
                prior = service.fences.mutation_locked(db, mutation_id)
                if prior is None:
                    service.core._require(credential, "read", service.namespace, holder)
                    owner = self._current_plan_owner_locked_v1(
                        db, token=token, request=request, actor=actor)
                    request, session, guard, origin, committed = owner
                    graph_namespace = committed[0].namespace
                    if (namespace_ref(graph_namespace) != service.namespace
                            or origin[0].namespace != graph_namespace):
                        raise AuthorityUnavailable("committed Owner Graph namespace differs")
                    anchor = service._current_locked(db, deletion, execution, holder=holder)
                    if history:
                        service.core.require_current_content_ready_locked(db, namespace=service.namespace)
                    state = scoped.state_locked(db)
                    lifecycle = require_lifecycle_exclusion_in_tx_v1(db, service.namespace, operation="delete")
                    if state.aggregate_phase != "clear" or state.active_operation_id is not None:
                        raise AuthorityUnavailable("C09 scope is not ready for a new plan")
                    active = db.execute("SELECT operation_id FROM authority_v2_fences "
                        "WHERE namespace=? AND state='active'", (service.namespace,)).fetchone()
                    if active is not None:
                        saved = service.fences._permit(service.fences._row(db, active[0]))
                        expected = self._protocol_id(service.namespace, operation, "plan-read-" + str(saved.fence_epoch))
                        if (saved.operation_id != expected or saved.operation != "read"
                                or saved.subject != subject or saved.holder != holder):
                            raise AuthorityUnavailable("another current fence blocks C09 plan observation")
                        permit = service.fences.validate_fence_locked(db, saved, subject=subject, current_anchor=anchor)
                    else:
                        last = db.execute("SELECT last_epoch FROM authority_v2_epochs WHERE namespace=?", (service.namespace,)).fetchone()
                        epoch = (last[0] if last else 0) + 1
                        permit = service.fences.begin_fence_locked(db, subject=subject, holder=holder,
                            operation="read", current_anchor=anchor,
                            operation_id=self._protocol_id(service.namespace, operation, "plan-read-" + str(epoch)))
            if prior is not None:
                yield None
                return
            admission = None
            if self._owner_storage_reader_v1 is not None:
                current, observed = self._owner_storage_reader_v1.get_current_owner_authority_for_fence_v1(
                    credential=credential, subject=subject, permit=permit, actor=actor,
                    session_token=token, session_request=request)
                if observed != permit or current.guard != guard or current.target_admission is not None:
                    raise AuthorityUnavailable("C09 Owner storage observer differs")
                admission = current.storage_admission
            plan = self._plan_graph_verifier.verify(namespace=graph_namespace, operation_id=operation,
                source_id=source, anchor=anchor, grant_digest=committed[0].grant_digest,
                installation_id=installed_id, principal=session.principal,
                applied_epoch=state.applied_epoch, storage_admission=admission,
                owner_proof=committed[0], owner_guard=guard, holder=holder)
            commitment = canonical_digest(dict(schema="c09.current-plan-observation.v1",
                graph_path=str(self._plan_graph_verifier._path), installation_id=installed_id,
                subject=subject, holder=holder, operation_id=operation, source_id=source,
                permit=asdict(permit), owner_guard=asdict(guard), issue_proof=asdict(committed[0]),
                session=asdict(session), scoped_state=asdict(state),
                lifecycle=None if lifecycle is None else asdict(lifecycle), plan=plan.to_wire(),
                storage_admission_digest=None if admission is None else admission.original_digest))
            yield dict(permit=permit, owner=owner, state=state, lifecycle=lifecycle,
                       plan=plan, admission=admission, commitment=commitment)
        finally:
            if permit is not None:
                # A failed precondition has no deletion effect. Close only this
                # exact still-unconsumed read permit; pending recovery owns any
                # already-committed delete permit.
                with service._frozen() as (db, deletion, execution, _):
                    row = service.fences._row(db, permit.operation_id)
                    if row is not None and row[6] == "active" and service.fences._permit(row) == permit:
                        anchor = service._current_locked(db, deletion, execution, holder=holder)
                        service.fences.finish_fence_locked(db, permit, subject=subject,
                            current_anchor=anchor, request_id=permit.operation_id + ":abandoned",
                            request_digest="sha256:" + canonical_digest((operation, source, "unconsumed")))

    def read_graph_barrier_candidate(self, *, credential, subject: str,
                                     pending_mutation_id: str) -> GraphBarrierAttestationV1:
        """Read two live originals; return a claim only, never acceptance."""
        if self._graph_reader is None:
            raise AuthorityUnavailable("installed C09 graph reader unavailable")
        identifier(subject, "subject")
        identifier(pending_mutation_id, "pending_mutation_id")
        coordinator, bootstrap, namespace_id, reader, installation_id = self._graph_reader
        kind, pending, receipt, permit = self._recovery.fences.get_mutation(
            pending_mutation_id, subject=subject, namespace=self._recovery.namespace)
        if (kind != "deletion" or type(receipt) is not DeletionMutationReceiptV1
                or pending.source_phase != "absent" or pending.target_phase != "pending"
                or pending.permit.subject != subject or permit is None
                or permit.pinned_anchor != receipt.after_anchor):
            raise AuthorityUnavailable("current original pending receipt required")
        arguments = dict(credential=credential, subject=subject,
                         installation_id=installation_id,
                         deletion_operation_id=pending.deletion_operation_id,
                         permit=permit)
        if reader.get_pending_deletion_for_graph_write(**arguments) != receipt:
            raise AuthorityUnavailable("Owner-fenced pending original changed")
        graph = coordinator.read_current_c09_graph_barrier_versioned_v2(
            bootstrap, namespace=namespace_id,
            deletion_operation_id=pending.deletion_operation_id, permit=permit)
        if reader.get_pending_deletion_for_graph_write(**arguments) != receipt:
            raise AuthorityUnavailable("Owner-fenced pending original changed after graph read")
        return GraphBarrierAttestationV2(receipt,graph) if type(graph) is C09GraphBarrierReceiptV2 else GraphBarrierAttestationV1(receipt,graph)

    def recover_prepared_pending(self, *, credential, subject: str,
                                 mutation_id: str) -> DeletionMutationReceiptV1 | None:
        """Commit/read only a previously durable original; None means HOLD.

        The underlying service verifies the exact independent journal event,
        current Authority head, live holder, credential, and original mutation.
        This receipt attests to pending and revocation watermarks only.
        """
        identifier(subject, "subject")
        identifier(mutation_id, "mutation_id")
        receipt = self._recovery.recover(
            credential=credential, subject=subject, mutation_id=mutation_id)
        if receipt is not None and (
                type(receipt) is not DeletionMutationReceiptV1
                or receipt.pending.mutation_id != mutation_id
                or receipt.pending.permit.namespace != self._recovery.namespace
                or receipt.pending.target_phase != "pending"):
            raise AuthorityUnavailable("original pending recovery result differs")
        return receipt

    def prepare_request(self, *, credential, subject: str, holder: str,
                        installation_id: str, owner_actor_id: str,
                        owner_session_token: str,
                        deletion_operation_id: str, source_id: str,
                        owner_session_request: OwnerSessionLoginRequestV1 | None = None,
                        ) -> tuple[DeletionMutationReceiptV1, FencePermitV2]:
        """Bind a current durable Graph plan before preparing Authority pending.

        An exact replay reads the existing Authority original without requiring
        the old Owner session or a now-stale Graph read lease.
        """
        if self._prepare is None or self._plan_graph_verifier is None:
            raise AuthorityUnavailable("installed C09 erasure plan reader required")
        _, _, _, _, _, scoped = self._prepare
        if scoped is None:
            raise AuthorityUnavailable("ScopedErasureV2 plan binding required")
        identifier(source_id, "source_id")
        return self._prepare_bound_request(
            credential=credential, subject=subject, holder=holder,
            installation_id=installation_id, owner_actor_id=owner_actor_id,
            owner_session_token=owner_session_token,
            owner_session_request=owner_session_request,
            deletion_operation_id=deletion_operation_id,
            closure_roots=(source_id,), deletion_epoch=None,
            policy_ref=None, plan=None,
            replay_issuer="authority-owner-graph-plan-v2")

    @staticmethod
    def _protocol_id(namespace: str, operation_id: str, kind: str) -> str:
        return "c09-" + kind + "-" + uuid.uuid5(
            uuid.NAMESPACE_URL, namespace + ":" + operation_id + ":" + kind).hex

    def _prepare_unbound_for_storage_test(self, **kwargs):
        """Controlled storage mechanics only; this is never product admission."""
        return self._prepare_bound_request(
            **kwargs, plan=None, replay_issuer="authority-owner-session-v1")

    def _prepare_bound_request(self, *, credential, subject: str, holder: str,
                               installation_id: str, owner_actor_id: str,
                               owner_session_token: str,
                               owner_session_request: OwnerSessionLoginRequestV1 | None,
                               deletion_operation_id: str,
                               closure_roots: tuple[str, ...], deletion_epoch: int | None,
                               policy_ref: str | None,
                               plan: C09ErasurePlanOriginalV1 | C09SourcePlanCaptureV2 | None,
                               replay_issuer: str,
                               ) -> tuple[DeletionMutationReceiptV1, FencePermitV2]:
        if self._prepare is None:
            raise AuthorityUnavailable("current deletion request prepare port unavailable")
        service, sessions, tickets, pairing, installed_id, scoped = self._prepare
        namespace = self._recovery.namespace
        for name, value in (("subject", subject), ("holder", holder),
                            ("installation_id", installation_id),
                            ("owner_actor_id", owner_actor_id),
                            ("deletion_operation_id", deletion_operation_id)):
            identifier(value, name)
        if policy_ref is not None:
            identifier(policy_ref, "policy_ref")
        if (installation_id != installed_id
                or type(owner_session_token) is not str or not owner_session_token
                or (owner_session_request is not None and (
                    type(owner_session_request) is not OwnerSessionLoginRequestV1
                    or owner_session_request.authority_namespace != namespace
                    or owner_session_request.installation_id != installed_id
                    or owner_session_request.audience != "owner"))
                or type(closure_roots) is not tuple
                or closure_roots != tuple(sorted(set(closure_roots)))):
            raise AuthorityUnavailable("canonical installed Owner deletion request required")
        if scoped is not None and len(closure_roots) != 1:
            raise AuthorityUnavailable("ScopedErasureV2 initial scope requires one source")
        def protocol_id(kind: str) -> str:
            return self._protocol_id(namespace, deletion_operation_id, kind)

        mutation_id = protocol_id("mutation")
        service.core._require(credential, "deletion", namespace, holder)
        pending = None
        prior_receipt = None
        with self._observe_current_plan_v1(credential=credential, subject=subject,
                holder=holder, actor=owner_actor_id, token=owner_session_token,
                request=owner_session_request, operation=deletion_operation_id,
                source=closure_roots[0] if closure_roots else "",
                mutation_id=mutation_id,
                enabled=replay_issuer == "authority-owner-graph-plan-v2") as observed:
            with service._frozen() as (db, deletion_head, execution_head, history):
                prior = service.fences.mutation_locked(db, mutation_id)
                if prior is not None:
                    kind, pending, prior_receipt, _ = service.fences._decode_mutation_row(prior)
                    if (kind != "deletion" or pending.permit.subject != subject
                            or pending.permit.holder != holder
                            or pending.deletion_operation_id != deletion_operation_id
                            or pending.closure_roots != closure_roots
                            or (deletion_epoch is not None
                                and pending.deletion_epoch != deletion_epoch)
                            or (policy_ref is not None
                                and pending.policy_ref != policy_ref)
                            or pending.evidence.issuer_id != replay_issuer):
                        raise AuthorityUnavailable("deletion request replay differs")
                else:
                    owner = self._current_plan_owner_locked_v1(
                        db, token=owner_session_token, request=owner_session_request,
                        actor=owner_actor_id)
                    owner_session_request, session, guard, origin, committed = owner
                    anchor = service._current_locked(
                        db, deletion_head, execution_head, holder=holder)
                    if (scoped is None and history
                            or anchor.authority_id != owner_session_request.authority_id):
                        raise AuthorityUnavailable("deletion namespace already has history")
                    if replay_issuer == "authority-owner-graph-plan-v2":
                        from .d12_lifecycle_gate_v1 import require_lifecycle_exclusion_in_tx_v1
                        if observed is None or observed['owner'] != owner:
                            raise AuthorityUnavailable("C09 current Owner observation changed")
                        read_permit = observed['permit']
                        service.fences.validate_fence_locked(db, read_permit,
                            subject=subject, current_anchor=anchor)
                        if (scoped.state_locked(db) != observed['state']
                                or require_lifecycle_exclusion_in_tx_v1(db, namespace, operation="delete") != observed['lifecycle']
                                or db.execute("SELECT last_epoch FROM authority_v2_epochs WHERE namespace=?", (namespace,)).fetchone() != (read_permit.fence_epoch,)):
                            raise AuthorityUnavailable("C09 observed scope or admission epoch changed")
                        plan = observed['plan']
                        service.fences.finish_fence_locked(db, read_permit,
                            subject=subject, current_anchor=anchor,
                            request_id=read_permit.operation_id + ":consumed",
                            request_digest="sha256:" + observed['commitment'])
                        deletion_epoch = plan.delete_epoch + 1
                        policy_ref = plan.policy_ref
                    permit = service.fences.begin_fence_locked(
                        db, subject=subject, holder=holder, operation="delete",
                        current_anchor=anchor, operation_id=protocol_id("fence"))
                    if deletion_epoch is None or policy_ref is None:
                        raise AuthorityUnavailable("deletion scope requires a plan")
                    scope_digest = deletion_scope_digest(
                        closure_roots, deletion_epoch, policy_ref)
                    identity = dict(
                        schema=("sylanne3.scoped-erasure-request.v2" if scoped is not None
                                else "sylanne3.owner-deletion-request.v1"),
                        namespace=namespace, operation_id=deletion_operation_id,
                        scope_kind="one_source" if scoped is not None else "legacy",
                        roots=closure_roots, epoch=deletion_epoch,
                        policy_ref=policy_ref,
                        policy_version=1 if scoped is not None else 0)
                    if plan is not None:
                        from ..runtime.c09_erasure_plan_original_v1 import authority_c09_plan_request_identity_v1
                        identity = authority_c09_plan_request_identity_v2(namespace,plan) if type(plan) is C09SourcePlanCaptureV2 else authority_c09_plan_request_identity_v1(namespace,plan)
                    if scoped is None:
                        identity.update(installation_id=installed_id,
                                        owner_actor_id=owner_actor_id,
                                        owner_session_request=asdict(owner_session_request))
                    request_digest = "sha256:" + hashlib.sha256(json.dumps(
                        identity, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True).encode()).hexdigest()
                    proof = dict(request_digest=request_digest,
                                 owner_head=asdict(guard), actor_id=owner_actor_id,
                                 session=asdict(session),
                                 token_digest="sha256:" + hashlib.sha256(
                                     owner_session_token.encode()).hexdigest(),
                                 anchor=asdict(anchor))
                    if observed is not None:
                        proof.update(plan_observation_digest=observed['commitment'],
                            owner_storage_admission_digest=(None if observed['admission'] is None
                                else observed['admission'].original_digest))
                    evidence = DeletionEvidenceV1(
                        authority_id=anchor.authority_id, namespace=namespace,
                        deletion_operation_id=deletion_operation_id,
                        kind="request_authorized",
                        issuer_id=replay_issuer,
                        evidence_id=protocol_id("evidence"), bound_anchor=anchor,
                        request_digest=request_digest, scope_digest=scope_digest,
                        proof_digest="sha256:" + hashlib.sha256(json.dumps(
                            proof, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode()).hexdigest())
                    pending = DeletionPendingV1(
                        permit=permit, mutation_id=mutation_id,
                        request_digest=request_digest,
                        deletion_operation_id=deletion_operation_id,
                        source_phase="absent", target_phase="pending",
                        closure_roots=closure_roots, deletion_epoch=deletion_epoch,
                        policy_ref=policy_ref, before_anchor=anchor,
                        evidence=evidence, expected_append_id=protocol_id("append"),
                        expected_append_digest="sha256:" + "0" * 64)
                    pending = replace(
                        pending, expected_append_digest=service.deletion.expected_digest(pending))
                    if scoped is not None:
                        scoped.reserve_locked(db, pending)
                    service.fences.record_deletion_pending_locked(
                        db, pending, subject=subject, current_anchor=anchor, core=service.core)
        if pending is None:
            raise AuthorityUnavailable("deletion request was not prepared")
        if prior_receipt is None:
            service.deletion.append_pending(
                pending, core=service.core, fences=service.fences)
        receipt = self._recovery.recover(
            credential=credential, subject=subject, mutation_id=mutation_id)
        if receipt is None or receipt.pending != pending:
            raise AuthorityUnavailable("deletion pending commit remains unresolved")
        kind, saved, committed, updated = service.fences.get_mutation(
            mutation_id, subject=subject, namespace=namespace)
        if (kind != "deletion" or saved != pending or committed != receipt
                or type(updated) is not FencePermitV2
                or updated.pinned_anchor != receipt.after_anchor
                or updated.revision != receipt.updated_revision):
            raise AuthorityUnavailable("updated deletion permit is unavailable")
        return receipt, updated

    def accept_verified_graph_barrier(
            self, *, credential, subject: str, pending_mutation_id: str,
    ) -> tuple[DeletionMutationReceiptV1, FencePermitV2]:
        """Advance only the original pending after an installed pinned W01 read.

        This internal phase records graph access withdrawal. It says nothing
        about cleanup or cumulative Graph application of a closed head.
        """
        if (self._prepare is None or self._graph_reader is None
                or self._plan_graph_coordinator is not self._graph_reader[0]):
            raise AuthorityUnavailable("paired C09 graph barrier reader required")
        service, _, _, _, _, scoped = self._prepare
        if scoped is None:
            raise AuthorityUnavailable("ScopedErasureV2 accepted state required")
        identifier(subject, "subject")
        identifier(pending_mutation_id, "pending_mutation_id")
        namespace = self._recovery.namespace
        kind, original, pending_receipt, live_permit = service.fences.get_mutation(
            pending_mutation_id, subject=subject, namespace=namespace)
        if (kind != "deletion" or type(pending_receipt) is not DeletionMutationReceiptV1
                or original != pending_receipt.pending
                or original.source_phase != "absent"
                or original.target_phase != "pending"
                or original.evidence.issuer_id != "authority-owner-graph-plan-v2"
                or type(live_permit) is not FencePermitV2):
            raise AuthorityUnavailable("plan-bound pending original required")
        operation_id = original.deletion_operation_id
        mutation_id = self._protocol_id(namespace, operation_id, "accepted-mutation")
        with service._frozen() as (db, _, _, _):
            prior_row = service.fences.mutation_locked(db, mutation_id)
        if prior_row is None:
            barrier = self.read_graph_barrier_candidate(
                credential=credential, subject=subject,
                pending_mutation_id=pending_mutation_id)
            if barrier.pending_receipt != pending_receipt:
                raise AuthorityUnavailable("pinned graph barrier pending differs")
            graph = barrier.graph_receipt
            if (graph.namespace != self._graph_reader[2]
                    or graph.operation_id != operation_id
                    or graph.request_digest != original.request_digest.removeprefix("sha256:")
                    or graph.delete_epoch_after != original.deletion_epoch):
                raise AuthorityUnavailable("pinned graph barrier identity differs")
            evidence = DeletionEvidenceV1(
                authority_id=live_permit.authority_id, namespace=namespace,
                deletion_operation_id=operation_id, kind="barrier_installed",
                issuer_id=("authority-pinned-graph-barrier-v2" if type(graph) is C09GraphBarrierReceiptV2 else "authority-pinned-graph-barrier-v1"),
                evidence_id=self._protocol_id(namespace, operation_id,
                                              "accepted-evidence"),
                bound_anchor=pending_receipt.after_anchor,
                request_digest=original.request_digest,
                scope_digest=original.evidence.scope_digest,
                proof_digest="sha256:" + canonical_digest(graph),
                graph_version=f"graph-epoch-{graph.graph_epoch_after}",
                incarnation=graph.graph_incarnation,
                access_epoch=graph.access_epoch_after,
                deletion_epoch=graph.delete_epoch_after,
                barrier_scope_digest="sha256:" + graph.closure_digest)
            draft = DeletionPendingV1(
                permit=live_permit, mutation_id=mutation_id,
                request_digest=original.request_digest,
                deletion_operation_id=operation_id,
                source_phase="pending", target_phase="accepted",
                closure_roots=original.closure_roots,
                deletion_epoch=original.deletion_epoch,
                policy_ref=original.policy_ref,
                before_anchor=pending_receipt.after_anchor,
                evidence=evidence,
                expected_append_id=self._protocol_id(
                    namespace, operation_id, "accepted-append"),
                expected_append_digest="sha256:" + "0" * 64)
            candidate = replace(
                draft, expected_append_digest=service.deletion.expected_digest(draft))
            with service._frozen() as (db, deletion_head, execution_head, _):
                row = service.fences.mutation_locked(db, mutation_id)
                if row is None:
                    current = service._current_locked(
                        db, deletion_head, execution_head,
                        holder=live_permit.holder, require_clear=False)
                    service.fences.validate_fence_locked(
                        db, live_permit, subject=subject, current_anchor=current)
                    if current != pending_receipt.after_anchor:
                        raise AuthorityUnavailable("pending head changed after graph read")
                    service.fences.record_deletion_pending_locked(
                        db, candidate, subject=subject, current_anchor=current, core=service.core)
                    prior_row = service.fences.mutation_locked(db, mutation_id)
                else:
                    prior_row = row
        if prior_row is None:
            raise AuthorityUnavailable("accepted original was not recorded")
        prior_kind, pending, prior_receipt, _ = service.fences._decode_mutation_row(
            prior_row)
        if (prior_kind != "deletion" or pending.source_phase != "pending"
                or pending.target_phase != "accepted"
                or pending.deletion_operation_id != operation_id
                or pending.request_digest != original.request_digest
                or pending.closure_roots != original.closure_roots
                or pending.deletion_epoch != original.deletion_epoch
                or pending.policy_ref != original.policy_ref
                or pending.before_anchor != pending_receipt.after_anchor
                or pending.evidence.issuer_id not in {"authority-pinned-graph-barrier-v1","authority-pinned-graph-barrier-v2"}):
            raise AuthorityUnavailable("accepted original replay differs")
        if prior_receipt is None:
            service.deletion.append_transition(
                pending, core=service.core, fences=service.fences)
        receipt = self._recovery.recover(
            credential=credential, subject=subject, mutation_id=mutation_id)
        if receipt is None or receipt.pending != pending:
            raise AuthorityUnavailable("accepted phase commit remains unresolved")
        saved_kind, saved, committed, updated = service.fences.get_mutation(
            mutation_id, subject=subject, namespace=namespace)
        if (saved_kind != "deletion" or saved != pending or committed != receipt
                or type(updated) is not FencePermitV2
                or updated.pinned_anchor != receipt.after_anchor
                or updated.revision != receipt.updated_revision):
            raise AuthorityUnavailable("accepted phase updated permit unavailable")
        return receipt, updated

    @staticmethod
    def accept(*, barrier: GraphBarrierAttestationV1 | None = None):
        raise AuthorityUnavailable(
            "deletion accepted phase remains HOLD: pinned graph barrier verifier unavailable")

    def install_current_cleanup_v1(self, service):
        from .c09_close_apply_v1 import InstalledC09CloseApplyV1
        if (type(service) is not InstalledC09CloseApplyV1 or service.recovery is not self._recovery
                or self._current_cleanup_v1 is not None):
            raise AuthorityUnavailable("installed C09 cleanup consumer differs")
        self._current_cleanup_v1 = service

    def close(self, *, operation_id: str):
        if self._current_cleanup_v1 is None:
            raise AuthorityUnavailable("deletion closed phase needs installed surface/application verifiers")
        return self._current_cleanup_v1.close_verified_cleanup_v1(operation_id=operation_id)


__all__ = [
    "CurrentErasureAuthority", "GraphBarrierAttestationV1",
    "CleanupSurfaceReceiptV1", "CleanupAttestationV1",
    "REQUIRED_CLEANUP_SURFACES", "MISSING_PORTS",
]
