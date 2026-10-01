"""Authority-local release of one original model result to its current worker.

The returned delivery retains an active read fence until the authenticated
transport has serialized and drained the response. It grants no C02 commit.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import threading

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, identifier
from .current_worker_model_result_graph_verifier import (
    PinnedCurrentWorkerModelResultGraphVerifier,
)
from .current_reply_worker_model_result_graph_verifier import (
    PinnedCurrentReplyWorkerModelResultGraphVerifier,
)
from .v2_contract import FencePermitV2
from .v2_fence_service import AuthorityV2FenceService
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_worker_model_result_attempts import AuthorityV2WorkerModelResultAttempts
from .v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1,
    first_ingress_read_attempt_id_v1, d13_paid_read_attempt_id_v1,
)
from .v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, ReplyWorkerModelResultReadV1,
    reply_worker_read_attempt_id_v1,
)


@dataclass(frozen=True, slots=True)
class WorkerResultDeliveryV1:
    result: WorkerModelResultReadV1 | ReplyWorkerModelResultReadV1
    permit: FencePermitV2

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self.result))


class AuthorityV2WorkerModelResultReadService:
    def __init__(self, *, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService,
                 attempts: AuthorityV2WorkerModelResultAttempts,
                 graph_verifier: PinnedCurrentWorkerModelResultGraphVerifier,
                 reply_graph_verifier: PinnedCurrentReplyWorkerModelResultGraphVerifier | None = None,
                 installation_id: str, read_subject: str, holder: str):
        for value, name in ((installation_id, "installation_id"),
                            (read_subject, "read_subject"), (holder, "holder")):
            identifier(value, name)
        core = fences.core if type(fences) is AuthorityV2FenceService else None
        if (type(store) is not AuthorityV2ModelEgressStore or core is None
                or type(attempts) is not AuthorityV2WorkerModelResultAttempts
                or type(graph_verifier) is not PinnedCurrentWorkerModelResultGraphVerifier
                or (reply_graph_verifier is not None and type(reply_graph_verifier)
                    is not PinnedCurrentReplyWorkerModelResultGraphVerifier)
                or store._db is not core._db or store._lock is not core._lock
                or attempts._db is not core._db or attempts._lock is not core._lock):
            raise AuthorityUnavailable("worker result requires one trusted Authority composition")
        self._store, self._fences, self._attempts = store, fences, attempts
        self._graph = graph_verifier
        self._reply_graph = reply_graph_verifier
        self._installation_id = installation_id
        self._read_subject = read_subject
        self._holder = holder
        # Process-local handoff exclusion. A restarted process has no live TLS
        # writer; the durable attempt/fence remains available for recovery.
        self._delivery_lock = threading.RLock()
        self._inflight_deliveries: dict[str, FencePermitV2 | None] = {}

    def _require(self, credential, request):
        if (type(request) not in {WorkerModelResultReadRequestV1,
                                 ReplyWorkerModelResultReadRequestV1}
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id
                or (type(request) is ReplyWorkerModelResultReadRequestV1
                    and self._reply_graph is None)):
            raise AuthorityUnavailable("installed typed worker read required")
        self._fences.core._require(
            credential, "read", request.authority_namespace, self._holder)

    def _terminal_locked(self, db, request, anchor, *, content):
        record = self._store._read(db, request.call_id)
        if (record is None or record.state != "observed" or record.content_erased
                or (record.intent.authority_id, record.intent.namespace,
                    record.intent.call_id, record.intent.job_id,
                    record.intent.request_digest,
                    record.intent.authority_activation_generation) !=
                   (request.authority_id, request.authority_namespace,
                    request.call_id, request.job_id, request.model_request_digest,
                    anchor.activation_generation)):
            raise AuthorityUnavailable("original completed model call unavailable")
        intent = record.intent
        if (intent.subject != self._read_subject
                or intent.operation_id != request.acquire_operation_id
                or intent.budget_reservation_operation_id != request.original_operation_id):
            raise AuthorityUnavailable("original worker model identity differs")
        admission, report_digest, receipt = self._store.read_admission_locked(db, intent)
        original_row = self._fences.fences._row(db, intent.operation_id)
        if original_row is None:
            raise AuthorityUnavailable("original model fence absent")
        original_permit = self._fences.fences._permit(original_row)
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
                   (intent.fence_token, intent.fence_epoch, intent.fence_revision)
                or not self._store.is_fence_bound_locked(db, intent)
                or admission.installation_id != request.installation_id
                or receipt.installation_id != request.installation_id
                or receipt.observation_digest != record.observation_digest
                or receipt.finish_digest !=
                   self._fences.fences.model_terminal_finish_digest(
                       intent, original_permit, "completed", record.observation_digest)):
            raise AuthorityUnavailable("original admission or terminal receipt differs")
        if not content:
            return intent, receipt, None
        observation = self._store._read_observation_locked(db, intent)
        if observation.digest != receipt.observation_digest:
            raise AuthorityUnavailable("original model body differs")
        result = (ReplyWorkerModelResultReadV1(request, observation, receipt)
                  if type(request) is ReplyWorkerModelResultReadRequestV1 else
                  WorkerModelResultReadV1(request, observation, receipt))
        result.require_original_intent(intent)
        return intent, receipt, result

    def _preflight(self, request):
        fences = self._fences
        with fences._frozen() as (db, deletion_head, execution_head, history):
            anchor = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder)
            if anchor.authority_id != request.authority_id:
                raise AuthorityUnavailable("worker read Authority anchor unavailable")
            intent, _, _ = self._terminal_locked(db, request, anchor, content=False)
        candidate = FencePermitV2(
            anchor.authority_id, anchor.namespace, self._read_subject,
            self._holder, anchor.activation_generation, "read",
            request.read_attempt_id, "p" * 32, 1, 0, anchor)
        graph = (self._reply_graph if type(request) is ReplyWorkerModelResultReadRequestV1
                 else self._graph)
        if graph.current(request, intent, candidate) is not True:
            raise AuthorityUnavailable("current worker graph qualification unavailable")
        return anchor, intent

    def select_attempt(self, *, credential,
                       first_request: WorkerModelResultReadRequestV1 |
                                      ReplyWorkerModelResultReadRequestV1):
        """Select the original active read or the next read after a finished one.

        Selection is content-free and advisory. ``prepare`` rechecks the graph
        and binds the selected attempt under its own current Authority fence.
        """
        self._require(credential, first_request)
        consumer = first_request.consumer_operation_id
        attempt_id = (reply_worker_read_attempt_id_v1
                      if type(first_request) is ReplyWorkerModelResultReadRequestV1
                      else d13_paid_read_attempt_id_v1
                      if first_request.purpose == "d13_precompress_paid"
                      else first_ingress_read_attempt_id_v1)
        if first_request.read_attempt_id != attempt_id(consumer, 1):
            raise AuthorityUnavailable("canonical first worker read required")
        with self._attempts._tx() as db:
            rows = db.execute(
                "SELECT read_attempt_id FROM authority_worker_result_read_attempts_v1 "
                "WHERE consumer_operation_id=? LIMIT 65", (consumer,)
            ).fetchall()
            if len(rows) > 64:
                raise AuthorityUnavailable("worker read attempt limit reached")
            actual = {row[0] for row in rows}
            latest = None
            for attempt in range(1, len(rows) + 1):
                expected = replace(
                    first_request, read_attempt_id=(
                        attempt_id(consumer, attempt)))
                record = self._attempts._read_locked(db, expected.read_attempt_id)
                if (expected.read_attempt_id not in actual or record is None
                        or record.request != expected
                        or attempt < len(rows) and record.state != "finished"):
                    raise AuthorityUnavailable("worker read sequence differs")
                latest = record
            if len(actual) != len(rows):
                raise AuthorityUnavailable("worker read sequence differs")
            if latest is not None and latest.state == "active":
                selected = latest.request
            else:
                next_attempt = len(rows) + 1
                if next_attempt > 64:
                    raise AuthorityUnavailable("worker read attempt limit reached")
                selected = replace(first_request, read_attempt_id=(
                    attempt_id(consumer, next_attempt)))
        self._preflight(selected)
        return selected

    def prepare(self, *, credential,
                request: WorkerModelResultReadRequestV1 |
                         ReplyWorkerModelResultReadRequestV1
                ) -> WorkerResultDeliveryV1:
        """Prepare one body; caller must drain transport before finish_delivery."""
        self._require(credential, request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("worker read attempt already being delivered")
            self._inflight_deliveries[request.read_attempt_id] = None
        try:
            delivery = self._prepare_inner(credential, request)
            with self._delivery_lock:
                self._inflight_deliveries[request.read_attempt_id] = delivery.permit
            return delivery
        except BaseException:
            with self._delivery_lock:
                self._inflight_deliveries.pop(request.read_attempt_id, None)
            raise

    def _prepare_inner(self, credential, request) -> WorkerResultDeliveryV1:
        expected_anchor, original_intent = self._preflight(request)
        fences = self._fences
        with fences._frozen() as (db, deletion_head, execution_head, history):
            anchor = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor:
                raise AuthorityUnavailable("worker read anchor changed")
            intent, _, _ = self._terminal_locked(db, request, anchor, content=False)
            if intent != original_intent:
                raise AuthorityUnavailable("original model intent changed")
            prior_fence = fences.fences._row(db, request.read_attempt_id)
            prior_attempt = self._attempts._read_locked(db, request.read_attempt_id)
            if (prior_fence is None) != (prior_attempt is None):
                raise AuthorityUnavailable("worker result attempt/fence pair differs")
            permit = fences.fences.begin_fence_locked(
                db, subject=self._read_subject, holder=self._holder,
                operation="read", current_anchor=anchor,
                operation_id=request.read_attempt_id)
            self._attempts.begin_locked(db, request, permit=permit)
        graph = (self._reply_graph if type(request) is ReplyWorkerModelResultReadRequestV1
                 else self._graph)
        if graph.current(request, original_intent, permit) is not True:
            raise AuthorityUnavailable("current worker graph changed; read fence retained")
        with fences._frozen() as (db, deletion_head, execution_head, history):
            anchor = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=permit.generation)
            if anchor != permit.pinned_anchor:
                raise AuthorityUnavailable("worker read anchor changed")
            fences.fences.validate_fence_locked(
                db, permit, subject=self._read_subject, current_anchor=anchor)
            intent, _, result = self._terminal_locked(db, request, anchor, content=True)
            if intent != original_intent:
                raise AuthorityUnavailable("original model intent changed")
        if graph.current(request, original_intent, permit) is not True:
            raise AuthorityUnavailable("current worker graph changed after result copy")
        fences.validate_fence(
            credential=credential, subject=self._read_subject, permit=permit)
        return WorkerResultDeliveryV1(result, permit)

    @staticmethod
    def _finish_identity(request, permit):
        return (
            "worker-result-finish:" + canonical_digest({
                "request": asdict(request), "permit": asdict(permit)}),
            "sha256:" + canonical_digest({
                "action": "finish_worker_result_read",
                "request": asdict(request), "permit": asdict(permit)}),
        )

    def _finish(self, credential, request, permit, result_digest):
        self._require(credential, request)
        if (type(permit) is not FencePermitV2
                or permit.operation != "read"
                or permit.subject != self._read_subject
                or permit.holder != self._holder
                or permit.namespace != request.authority_namespace
                or permit.operation_id != request.read_attempt_id):
            raise AuthorityUnavailable("worker read permit differs")
        request_id, request_digest = self._finish_identity(request, permit)
        fences = self._fences
        with fences._frozen() as (db, deletion_head, execution_head, history):
            anchor = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=permit.generation)
            if anchor != permit.pinned_anchor:
                raise AuthorityUnavailable("worker read anchor changed before finish")
            row = fences.fences._row(db, request.read_attempt_id)
            if row is None or fences.fences._permit(row) != permit:
                raise AuthorityUnavailable("original worker read fence differs")
            fences.fences.finish_fence_locked(
                db, permit, subject=self._read_subject, current_anchor=anchor,
                request_id=request_id, request_digest=request_digest)
            self._attempts.finish_locked(
                db, request, permit=permit, result_digest=result_digest)

    def finish_delivery(self, *, credential, delivery: WorkerResultDeliveryV1) -> None:
        if type(delivery) is not WorkerResultDeliveryV1:
            raise AuthorityUnavailable("typed worker delivery required")
        with self._delivery_lock:
            attempt_id = delivery.result.request.read_attempt_id
            if self._inflight_deliveries.get(attempt_id) != delivery.permit:
                raise AuthorityUnavailable("worker delivery is not the active handoff")
            try:
                self._finish(credential, delivery.result.request,
                             delivery.permit, delivery.digest)
            finally:
                self._inflight_deliveries.pop(attempt_id, None)

    def abandon_delivery(self, *, delivery: WorkerResultDeliveryV1) -> None:
        """Release only process-local handoff exclusion after transport failure."""
        if type(delivery) is not WorkerResultDeliveryV1:
            raise AuthorityUnavailable("typed worker delivery required")
        with self._delivery_lock:
            attempt_id = delivery.result.request.read_attempt_id
            if self._inflight_deliveries.get(attempt_id) != delivery.permit:
                raise AuthorityUnavailable("worker delivery is not the active handoff")
            self._inflight_deliveries.pop(attempt_id, None)

    def recover_finish(self, *, credential,
                       request: WorkerModelResultReadRequestV1 |
                                ReplyWorkerModelResultReadRequestV1) -> None:
        """Authenticated content-free close of an uncertain original attempt."""
        self._require(credential, request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("worker delivery is still in progress")
            # Hold exclusion across the exact finish so another prepare cannot
            # begin while recovery closes the original active fence.
            return self._recover_finish_locked(credential, request)

    def _recover_finish_locked(self, credential, request):
        fences = self._fences
        with fences._frozen() as (db, deletion_head, execution_head, history):
            anchor = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder)
            if anchor.authority_id != request.authority_id:
                raise AuthorityUnavailable("worker read recovery anchor unavailable")
            row = fences.fences._row(db, request.read_attempt_id)
            if row is None:
                raise AuthorityUnavailable("original worker read fence absent")
            permit = fences.fences._permit(row)
            attempt = self._attempts._read_locked(db, request.read_attempt_id)
            if (permit.operation != "read" or permit.subject != self._read_subject
                    or permit.holder != self._holder
                    or permit.pinned_anchor != anchor or attempt is None
                    or attempt.request != request
                    or attempt.permit_digest != canonical_digest(asdict(permit))):
                raise AuthorityUnavailable("original worker read attempt differs")
            if attempt.state == "finished":
                request_id, request_digest = self._finish_identity(request, permit)
                if row[6] != "finished" or row[8:10] != (request_id, request_digest):
                    raise AuthorityUnavailable("worker read finish record differs")
                return
            intent, _, result = self._terminal_locked(db, request, anchor, content=True)
            result.require_original_intent(intent)
            digest = canonical_digest(asdict(result))
        self._finish(credential, request, permit, digest)


__all__ = ("AuthorityV2WorkerModelResultReadService", "WorkerResultDeliveryV1")
