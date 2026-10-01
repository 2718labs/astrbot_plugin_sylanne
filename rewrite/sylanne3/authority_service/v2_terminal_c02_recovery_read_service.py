"""Fenced, single-attempt handoff of an original completed C02 result."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import threading

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, identifier
from .current_worker_model_result_graph_verifier import PinnedTerminalRecoveryGraphVerifierV1
from .v2_contract import FencePermitV2
from .v2_fence_service import AuthorityV2FenceService
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_terminal_c02_recovery_attempts import AuthorityV2TerminalC02RecoveryAttempts
from .v2_terminal_c02_recovery_contract import TerminalRecoveryReadRequestV1


@dataclass(frozen=True, slots=True)
class TerminalC02RecoveryDeliveryV1:
    request: TerminalRecoveryReadRequestV1
    observation: object
    permit: FencePermitV2

    @property
    def handoff_digest(self) -> str:
        return canonical_digest({"request": asdict(self.request),
                                 "observation": asdict(self.observation)})


class AuthorityV2TerminalC02RecoveryReadService:
    """Trusted Authority composition; finish only after transport drain."""

    def __init__(self, *, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService,
                 attempts: AuthorityV2TerminalC02RecoveryAttempts,
                 graph_verifier: PinnedTerminalRecoveryGraphVerifierV1,
                 installation_id: str, read_subject: str, holder: str):
        for value, name in ((installation_id, "installation_id"),
                            (read_subject, "read_subject"), (holder, "holder")):
            identifier(value, name)
        core = fences.core if type(fences) is AuthorityV2FenceService else None
        if (type(store) is not AuthorityV2ModelEgressStore or core is None
                or type(attempts) is not AuthorityV2TerminalC02RecoveryAttempts
                or type(graph_verifier) is not PinnedTerminalRecoveryGraphVerifierV1
                or store._db is not core._db or store._lock is not core._lock
                or attempts._db is not core._db or attempts._lock is not core._lock):
            raise AuthorityUnavailable("terminal C02 recovery composition unavailable")
        self._store, self._fences, self._attempts = store, fences, attempts
        self._graph = graph_verifier
        self._installation_id = installation_id
        self._read_subject = read_subject
        self._holder = holder
        self._delivery_lock = threading.RLock()
        self._inflight: dict[str, FencePermitV2 | None] = {}

    def _require(self, credential, request):
        key = request.original_key if type(request) is TerminalRecoveryReadRequestV1 else None
        if (key is None or key.authority_namespace != self._fences.namespace
                or key.installation_id != self._installation_id):
            raise AuthorityUnavailable("installed terminal C02 recovery reader required")
        self._fences.core._require(
            credential, "read", key.authority_namespace, self._holder)

    def _original_locked(self, db, request, anchor, *, content):
        key = request.original_key
        record = self._store._read(db, key.call_id)
        if (record is None or record.state != "observed" or record.content_erased
                or record.observation_digest != key.observation_digest):
            raise AuthorityUnavailable("original completed C02 content unavailable")
        intent = record.intent
        if (canonical_digest(asdict(intent)) != key.original_intent_digest
                or (intent.authority_id, intent.namespace, intent.call_id,
                    intent.job_id, intent.operation_id,
                    intent.budget_reservation_operation_id, intent.request_digest,
                    intent.authority_activation_generation,
                    intent.authority_revocation_epoch,
                    intent.authority_deletion_seq,
                    intent.authority_execution_seq) !=
                   (key.authority_id, key.authority_namespace, key.call_id,
                    key.job_id, key.acquire_operation_id,
                    key.original_operation_id, key.model_request_digest,
                    anchor.activation_generation, anchor.revocation_epoch,
                    anchor.deletion_seq, anchor.execution_seq)):
            raise AuthorityUnavailable("original C02 model identity differs")
        admission, report_digest, receipt = self._store.read_admission_locked(db, intent)
        row = self._fences.fences._row(db, intent.operation_id)
        original_permit = self._fences.fences._permit(row) if row is not None else None
        if (receipt is None or original_permit is None
                or receipt.admission_id != admission.admission_id
                or report_digest != receipt.report_digest
                or receipt.installation_id != key.installation_id
                or canonical_digest(asdict(receipt)) != key.terminal_receipt_digest
                or receipt.observation_digest != record.observation_digest
                or row[6] != "finished" or row[10] is not None
                or row[8:10] != (intent.call_id, receipt.finish_digest)
                or original_permit.operation != "model_egress"
                or (original_permit.authority_id, original_permit.namespace,
                    original_permit.subject, original_permit.operation_id) !=
                   (intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id)
                or (original_permit.token, original_permit.fence_epoch,
                    original_permit.revision) !=
                   (intent.fence_token, intent.fence_epoch, intent.fence_revision)
                or not self._store.is_fence_bound_locked(db, intent)
                or receipt.finish_digest !=
                   self._fences.fences.model_terminal_finish_digest(
                       intent, original_permit, "completed", record.observation_digest)):
            raise AuthorityUnavailable("original C02 terminal receipt differs")
        if not content:
            return intent, None
        observation = self._store._read_observation_locked(db, intent)
        if observation.digest != key.observation_digest or observation.status != "completed":
            raise AuthorityUnavailable("original C02 body differs")
        return intent, observation

    def query(self, *, credential, request: TerminalRecoveryReadRequestV1):
        """Unknown response recovery returns only exact durable attempt state."""
        self._require(credential, request)
        return self._attempts.read(request)

    def prepare(self, *, credential, request: TerminalRecoveryReadRequestV1):
        self._require(credential, request)
        attempt_id = request.read_attempt_id
        with self._delivery_lock:
            if attempt_id in self._inflight:
                raise AuthorityUnavailable("terminal C02 handoff already in progress")
            self._inflight[attempt_id] = None
        try:
            delivery = self._prepare_inner(credential, request)
            with self._delivery_lock:
                self._inflight[attempt_id] = delivery.permit
            return delivery
        except BaseException:
            with self._delivery_lock:
                self._inflight.pop(attempt_id, None)
            raise

    def _prepare_inner(self, credential, request):
        fences = self._fences
        with fences._frozen() as (db, deletion_head, execution_head, history):
            anchor = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder)
            if anchor.authority_id != request.original_key.authority_id:
                raise AuthorityUnavailable("terminal C02 recovery anchor unavailable")
            intent, _ = self._original_locked(db, request, anchor, content=False)
        candidate = FencePermitV2(
            anchor.authority_id, anchor.namespace, self._read_subject,
            self._holder, anchor.activation_generation, "read",
            request.read_attempt_id, "p" * 32, 1, 0, anchor)
        if self._graph.current(request, intent, candidate) is not True:
            raise AuthorityUnavailable("terminal C02 recovery graph unavailable")
        with fences._frozen() as (db, deletion_head, execution_head, history):
            current = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=anchor.activation_generation)
            if current != anchor:
                raise AuthorityUnavailable("terminal C02 recovery anchor changed")
            original, _ = self._original_locked(db, request, current, content=False)
            if original != intent:
                raise AuthorityUnavailable("original C02 intent changed")
            prior_fence = fences.fences._row(db, request.read_attempt_id)
            prior_attempt, _ = self._attempts._read_locked(db, request.read_attempt_id)
            if (prior_fence is None) != (prior_attempt is None):
                raise AuthorityUnavailable("terminal C02 attempt/fence pair differs")
            permit = fences.fences.begin_fence_locked(
                db, subject=self._read_subject, holder=self._holder,
                operation="read", current_anchor=current,
                operation_id=request.read_attempt_id)
            self._attempts.begin_locked(db, request, permit=permit)
        if self._graph.current(request, intent, permit) is not True:
            raise AuthorityUnavailable("terminal C02 recovery graph changed")
        with fences._frozen() as (db, deletion_head, execution_head, history):
            current = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=permit.generation)
            if current != permit.pinned_anchor:
                raise AuthorityUnavailable("terminal C02 recovery anchor changed")
            fences.fences.validate_fence_locked(
                db, permit, subject=self._read_subject, current_anchor=current)
            original, observation = self._original_locked(db, request, current, content=True)
            if original != intent:
                raise AuthorityUnavailable("original C02 intent changed")
        if self._graph.current(request, intent, permit) is not True:
            raise AuthorityUnavailable("terminal C02 graph changed after copy")
        fences.validate_fence(
            credential=credential, subject=self._read_subject, permit=permit)
        return TerminalC02RecoveryDeliveryV1(request, observation, permit)

    def finish_delivery(self, *, credential, delivery: TerminalC02RecoveryDeliveryV1):
        if type(delivery) is not TerminalC02RecoveryDeliveryV1:
            raise AuthorityUnavailable("typed terminal C02 delivery required")
        request, permit = delivery.request, delivery.permit
        with self._delivery_lock:
            if self._inflight.get(request.read_attempt_id) != permit:
                raise AuthorityUnavailable("terminal C02 delivery is not active")
            try:
                self._require(credential, request)
                if (permit.operation != "read" or permit.subject != self._read_subject
                        or permit.holder != self._holder
                        or permit.operation_id != request.read_attempt_id):
                    raise AuthorityUnavailable("terminal C02 recovery permit differs")
                request_id = "terminal-c02-read-finish:" + canonical_digest({
                    "request": asdict(request), "permit": asdict(permit)})
                request_digest = "sha256:" + canonical_digest({
                    "action": "finish_terminal_c02_recovery_read",
                    "request": asdict(request), "permit": asdict(permit)})
                fences = self._fences
                with fences._frozen() as (db, deletion_head, execution_head, history):
                    anchor = fences._current_locked(
                        db, deletion_head, execution_head, holder=self._holder,
                        generation=permit.generation)
                    if anchor != permit.pinned_anchor:
                        raise AuthorityUnavailable("terminal C02 recovery anchor changed")
                    intent, _ = self._original_locked(db, request, anchor, content=False)
                if self._graph.current(request, intent, permit) is not True:
                    raise AuthorityUnavailable("terminal C02 graph changed before handoff fact")
                with fences._frozen() as (db, deletion_head, execution_head, history):
                    anchor = fences._current_locked(
                        db, deletion_head, execution_head, holder=self._holder,
                        generation=permit.generation)
                    if anchor != permit.pinned_anchor:
                        raise AuthorityUnavailable("terminal C02 recovery anchor changed")
                    row = fences.fences._row(db, request.read_attempt_id)
                    if row is None or fences.fences._permit(row) != permit:
                        raise AuthorityUnavailable("terminal C02 recovery fence differs")
                    fences.fences.finish_fence_locked(
                        db, permit, subject=self._read_subject, current_anchor=anchor,
                        request_id=request_id, request_digest=request_digest)
                    return self._attempts.finish_locked(
                        db, request, permit=permit,
                        handoff_digest=delivery.handoff_digest)
            finally:
                self._inflight.pop(request.read_attempt_id, None)

    def abandon_delivery(self, *, delivery: TerminalC02RecoveryDeliveryV1):
        if type(delivery) is not TerminalC02RecoveryDeliveryV1:
            raise AuthorityUnavailable("typed terminal C02 delivery required")
        with self._delivery_lock:
            if self._inflight.get(delivery.request.read_attempt_id) != delivery.permit:
                raise AuthorityUnavailable("terminal C02 delivery is not active")
            self._inflight.pop(delivery.request.read_attempt_id, None)


__all__ = ("AuthorityV2TerminalC02RecoveryReadService",
           "TerminalC02RecoveryDeliveryV1")
