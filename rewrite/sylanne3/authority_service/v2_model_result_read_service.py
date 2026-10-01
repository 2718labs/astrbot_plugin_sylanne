"""Authority-local Owner result release from the original terminal egress ledger."""

from __future__ import annotations

from dataclasses import asdict

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, identifier
from .current_model_result_read_graph_verifier import PinnedCurrentModelResultReadGraphVerifier
from .v2_fence_service import AuthorityV2FenceService
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_model_result_read_contract import ModelResultReadRequestV1, ModelResultReadV1
from .v2_owner_session import AuthorityV2OwnerSessionStore
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore


class AuthorityV2ModelResultReadService:
    """Release one completed result after fresh Authority and graph checks.

    The constructor takes only administrator-composed single-writer services.
    The caller's request names a result and a fixed read scope; it supplies no
    observation, terminal receipt, graph proof, or Authority guard.
    """

    def __init__(self, *, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService,
                 owner_tickets: AuthorityV2OwnerTicketStore,
                 owner_sessions: AuthorityV2OwnerSessionStore,
                 graph_verifier: PinnedCurrentModelResultReadGraphVerifier,
                 installation_id: str, read_subject: str, holder: str,
                 source_purpose: str):
        identifier(installation_id, "installation_id")
        identifier(read_subject, "read_subject")
        identifier(holder, "holder")
        # The host pairing adapter imports local composition; delay this type
        # check until construction to keep the Authority modules acyclic.
        from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
        if (type(source_purpose) is not str
                or source_purpose not in {"context", "expression", "consolidation", "audit"}):
            raise ValueError("administrator-pinned source purpose is required")
        core = fences.core if type(fences) is AuthorityV2FenceService else None
        if (type(store) is not AuthorityV2ModelEgressStore
                or core is None or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or type(owner_sessions) is not AuthorityV2OwnerSessionStore
                or type(graph_verifier) is not PinnedCurrentModelResultReadGraphVerifier
                or store._db is not core._db or store._lock is not core._lock
                or owner_tickets._core is not core or owner_sessions._core is not core
                or owner_tickets._owner_sessions is not owner_sessions
                or type(owner_sessions._current_pairing_source)
                   is not AuthorityOwnerPairingSource
                or owner_sessions._current_pairing_source._core is not core):
            raise AuthorityUnavailable("result read requires one trusted Authority composition")
        self._store = store
        self._fences = fences
        self._tickets = owner_tickets
        self._sessions = owner_sessions
        self._graph = graph_verifier
        self._installation_id = installation_id
        self._read_subject = read_subject
        self._holder = holder
        self._source_purpose = source_purpose

    def _current_guard(self, credential, request, token, permit):
        guard = self._tickets.get_current_guard(
            credential=credential,
            authority_namespace=request.authority_namespace,
            installation_id=request.installation_id,
            subject=self._read_subject, permit=permit,
            owner_actor_id=request.owner_actor_id,
            owner_session_token=token,
            owner_session_request=request.owner_session_request)
        if guard is None or guard.pending_revoke_operation_id is not None:
            raise AuthorityUnavailable("current Owner grant is unavailable")
        return guard

    def _terminal_in_frozen(self, request, token, permit, guard, *, content):
        fences = self._fences
        with fences._frozen() as (db, deletion_head, execution_head, history):
            anchor = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=permit.generation)
            if anchor != permit.pinned_anchor:
                raise AuthorityUnavailable("result read Authority anchor changed")
            fences.fences.validate_fence_locked(
                db, permit, subject=self._read_subject, current_anchor=anchor)
            session = self._sessions.require_current_in_tx(
                db, token=token, request=request.owner_session_request)
            self._sessions._current_pairing_source.require_current_actor_in_tx(
                db, authority_namespace=request.authority_namespace,
                installation_id=request.installation_id,
                actor_id=request.owner_actor_id, principal=session.principal)
            if self._tickets._checked_current_head(db, request.authority_namespace) != guard:
                raise AuthorityUnavailable("Owner authorization changed during result read")

            record = self._store._read(db, request.call_id)
            if (record is None or record.state != "observed" or record.content_erased
                    or (record.intent.authority_id, record.intent.namespace,
                        record.intent.call_id,
                        record.intent.authority_activation_generation) !=
                       (request.authority_id, request.authority_namespace,
                        request.call_id, anchor.activation_generation)):
                raise AuthorityUnavailable("completed original result is unavailable")
            intent = record.intent
            admission, report_digest, receipt = self._store.read_admission_locked(db, intent)
            original_row = fences.fences._row(db, intent.operation_id)
            if original_row is None:
                raise AuthorityUnavailable("original terminal model fence is absent")
            original_permit = fences.fences._permit(original_row)
            if (receipt is None or receipt.admission_id != admission.admission_id
                    or report_digest != receipt.report_digest
                    or original_row[6] != "finished" or original_row[10] is not None
                    or original_row[8:10] != (intent.call_id, receipt.finish_digest)
                    or original_permit.operation != "model_egress"
                    or (original_permit.authority_id, original_permit.namespace,
                        original_permit.subject, original_permit.operation_id) !=
                       (intent.authority_id, intent.namespace, intent.subject,
                        intent.operation_id)
                    or (original_permit.token, original_permit.fence_epoch,
                        original_permit.revision) !=
                       (intent.fence_token, intent.fence_epoch,
                        intent.fence_revision)
                    or not self._store.is_fence_bound_locked(db, intent)
                    or admission.installation_id != request.installation_id
                    or receipt.installation_id != request.installation_id
                    or receipt.observation_digest != record.observation_digest
                    or receipt.finish_digest !=
                       fences.fences.model_terminal_finish_digest(
                           intent, original_permit, "completed",
                           record.observation_digest)):
                raise AuthorityUnavailable("original admission or terminal receipt differs")
            if not content:
                return intent, receipt, None
            observation = self._store._read_observation_locked(db, intent)
            if observation.digest != receipt.observation_digest:
                raise AuthorityUnavailable("original completed body differs from terminal")
            return intent, receipt, observation

    def read_completed(self, *, credential: object, owner_session_token: str,
                       request: ModelResultReadRequestV1) -> ModelResultReadV1:
        if (type(request) is not ModelResultReadRequestV1
                or type(owner_session_token) is not str or not owner_session_token
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id
                or request.source_purpose != self._source_purpose):
            raise AuthorityUnavailable("typed installation-bound Owner read required")
        anchor = self._fences.current_anchor(
            credential=credential, subject=self._read_subject)
        if anchor.authority_id != request.authority_id:
            raise AuthorityUnavailable("result read Authority identity differs")
        permit = self._fences.begin_fence(
            credential=credential, subject=self._read_subject,
            holder=self._holder, operation="read",
            operation_id=request.read_operation_id,
            expected_anchor=anchor)
        failure = None
        try:
            self._fences.validate_fence(
                credential=credential, subject=self._read_subject, permit=permit)
            guard = self._current_guard(
                credential, request, owner_session_token, permit)
            intent, first_receipt, _ = self._terminal_in_frozen(
                request, owner_session_token, permit, guard, content=False)
            if self._graph.current(request, intent, guard, permit) is not True:
                raise AuthorityUnavailable("current Owner result graph is unavailable")
            self._fences.validate_fence(
                credential=credential, subject=self._read_subject, permit=permit)
            second_guard = self._current_guard(
                credential, request, owner_session_token, permit)
            if second_guard != guard:
                raise AuthorityUnavailable("Owner authorization changed during result read")
            _, receipt, observation = self._terminal_in_frozen(
                request, owner_session_token, permit, guard, content=True)
            if receipt != first_receipt:
                raise AuthorityUnavailable("terminal receipt changed during result read")
            result = ModelResultReadV1(request.call_id, observation, receipt)
            # Existing GraphCoordinator read flows compare the business graph
            # again after copying under a read fence. Do the same here so any
            # writer outside the expected fenced path is caught before return.
            if self._graph.current(request, intent, guard, permit) is not True:
                raise AuthorityUnavailable("Owner result graph changed during copy")
            self._fences.validate_fence(
                credential=credential, subject=self._read_subject, permit=permit)
            if self._current_guard(
                    credential, request, owner_session_token, permit) != guard:
                raise AuthorityUnavailable("Owner authorization changed after result copy")
        except BaseException as exc:
            failure = exc
            raise
        finally:
            try:
                self._finish(credential, request, permit)
            except Exception:
                if failure is None:
                    raise
        return result

    def _finish(self, credential, request, permit) -> None:
        """Stable finish identity allows an uncertain response to be retried."""
        self._fences.finish_fence(
            credential=credential, subject=self._read_subject, permit=permit,
            request_id="result-read-finish:" + canonical_digest({
                "operation_id": request.read_operation_id,
                "permit_token": permit.token,
            }),
            request_digest="sha256:" + canonical_digest({
                "action": "finish_model_result_read",
                "request": asdict(request), "permit_token": permit.token,
            }))

    def recover_finish(self, *, credential: object,
                       request: ModelResultReadRequestV1) -> None:
        """Close an active read fence after an uncertain finish, without content."""
        if (type(request) is not ModelResultReadRequestV1
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id
                or request.source_purpose != self._source_purpose):
            raise AuthorityUnavailable("typed installation-bound read recovery required")
        permit, state = self._fences.get_fence_operation(
            credential=credential, subject=self._read_subject,
            operation_id=request.read_operation_id)
        if (permit.operation != "read" or permit.authority_id != request.authority_id
                or state not in {"active", "finished"}):
            raise AuthorityUnavailable("original read fence is unavailable")
        self._finish(credential, request, permit)


__all__ = ("AuthorityV2ModelResultReadService",)
