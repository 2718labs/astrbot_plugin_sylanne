"""Authority-local paid context reply result read under an original read fence.

Only a history-free V2 request can pass this version. D13 history requires its
current-window consumption barrier in the same graph read before release.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import threading
from typing import Callable

from ..model_broker.context_reply import parse_context_reply_output_v1
from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, identifier
from .current_context_reply_original_verifier import (
    PinnedCurrentContextReplyOriginalVerifier,
)
from .v2_context_reply_result_contract import (
    ContextReplyPaidResultReadV2, ContextReplyResultReadRequestV1,
    context_reply_read_attempt_id_v1,
)
from .v2_fence_service import AuthorityV2FenceService
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_contract import FencePermitV2


@dataclass(frozen=True, slots=True)
class ContextReplyResultDeliveryV2:
    result: ContextReplyPaidResultReadV2
    permit: FencePermitV2


class AuthorityV2ContextReplyResultReadService:
    """Read a paid terminal from the Authority ledger, never a host body."""

    def __init__(self, *, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService,
                 graph_verifier: PinnedCurrentContextReplyOriginalVerifier,
                 installation_id: str,
                 read_subject: str, holder: str,
                 trusted_now_utc: Callable[[], float]):
        for value, name in ((installation_id, "installation_id"),
                            (read_subject, "read_subject"), (holder, "holder")):
            identifier(value, name)
        core = fences.core if type(fences) is AuthorityV2FenceService else None
        if (type(store) is not AuthorityV2ModelEgressStore or core is None
                or type(graph_verifier) is not PinnedCurrentContextReplyOriginalVerifier
                or store._db is not core._db or store._lock is not core._lock
                or not callable(trusted_now_utc)):
            raise AuthorityUnavailable("context reply result needs one pinned Authority")
        self._store, self._fences, self._graph = store, fences, graph_verifier
        self._installation_id = installation_id
        self._read_subject = read_subject
        self._holder = holder
        self._clock = trusted_now_utc
        self._delivery_lock = threading.RLock()
        self._inflight_deliveries: dict[str, FencePermitV2 | None] = {}

    def _terminal_locked(self, db, request, anchor, *, content: bool):
        record = self._store._read(db, request.call_id)
        if (record is None or record.state != "observed" or record.content_erased
                or (record.intent.authority_id, record.intent.namespace,
                    record.intent.call_id, record.intent.job_id,
                    record.intent.authority_activation_generation) !=
                   (request.authority_id, request.authority_namespace,
                    request.call_id, request.job_id, anchor.activation_generation)):
            raise AuthorityUnavailable("original context reply terminal unavailable")
        intent = record.intent
        if (intent.subject != self._read_subject
                or intent.operation_id != request.acquire_operation_id
                or intent.budget_reservation_operation_id != request.original_operation_id):
            raise AuthorityUnavailable("original context reply intent differs")
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
                       intent, original_permit, "completed",
                       record.observation_digest)):
            raise AuthorityUnavailable("original admission or terminal differs")
        if not content:
            return intent, receipt, None
        observation = self._store._read_observation_locked(db, intent)
        if (observation.status != "completed"
                or observation.digest != receipt.observation_digest):
            raise AuthorityUnavailable("completed original body differs")
        return intent, receipt, observation

    def _read_original(self, request, anchor, *, content: bool):
        fences = self._fences
        with fences._frozen() as (db, deletion_head, execution_head, history):
            current = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=anchor.activation_generation)
            if current != anchor:
                raise AuthorityUnavailable("context reply read anchor changed")
            return self._terminal_locked(db, request, anchor, content=content)

    def prepare(self, *, credential: object,
                request: ContextReplyResultReadRequestV1,
                now_utc: float) -> ContextReplyResultDeliveryV2:
        """Retain the read fence until the authenticated response has drained."""
        if (type(request) is not ContextReplyResultReadRequestV1
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id
                or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
            raise AuthorityUnavailable("installed context reply read required")
        ordinal = next((index for index in range(1, 65)
                        if request.read_attempt_id == context_reply_read_attempt_id_v1(
                            request.original_operation_id, index)), None)
        if ordinal is None:
            raise AuthorityUnavailable("bounded original read attempt required")
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("context reply read already being delivered")
            self._inflight_deliveries[request.read_attempt_id] = None
        try:
            delivery = self._prepare_inner(credential, request, ordinal)
            with self._delivery_lock:
                self._inflight_deliveries[request.read_attempt_id] = delivery.permit
            return delivery
        except BaseException:
            with self._delivery_lock:
                self._inflight_deliveries.pop(request.read_attempt_id, None)
            try:
                self.recover_finish(credential=credential, request=request)
            except Exception:
                # The original read operation remains durably recoverable.
                pass
            raise

    def _prepare_inner(self, credential, request, ordinal):
        fences = self._fences
        fences.core._require(
            credential, "read", request.authority_namespace, self._holder)
        trusted_now = self._clock()
        if type(trusted_now) not in (int, float) or not math.isfinite(trusted_now):
            raise AuthorityUnavailable("trusted context reply clock unavailable")
        anchor = fences.current_anchor(
            credential=credential, subject=self._read_subject)
        if anchor.authority_id != request.authority_id:
            raise AuthorityUnavailable("context reply Authority identity differs")
        intent, receipt, _ = self._read_original(request, anchor, content=False)
        current = self._graph.paid_call_current(
            request, intent, receipt, now_utc=float(trusted_now))
        if current is None:
            raise AuthorityUnavailable("original paid context reply graph unavailable")
        frozen = current.frozen_request
        if frozen.input.history or frozen.input.stable_history:
            # D13 current-window consumer is not yet installed.
            raise AuthorityUnavailable("D13 history consumption barrier unavailable")
        permit = fences.begin_fence(
            credential=credential, subject=self._read_subject,
            holder=self._holder, operation="read",
            operation_id=request.read_attempt_id,
            expected_anchor=anchor)
        fences.validate_fence(
            credential=credential, subject=self._read_subject, permit=permit)
        second_intent, second_receipt, observation = self._read_original(
            request, anchor, content=True)
        if second_intent != intent or second_receipt != receipt:
            raise AuthorityUnavailable("original context reply terminal changed")
        after = self._graph.paid_call_current(
            request, intent, receipt, now_utc=float(self._clock()))
        if after != current:
            raise AuthorityUnavailable("current context reply graph changed")
        provider_result = json.loads(observation.result_json)
        if (type(provider_result) is not dict
                or set(provider_result) != {"text"}
                or type(provider_result["text"]) is not str):
            raise AuthorityUnavailable("context reply provider result shape differs")
        parsed = parse_context_reply_output_v1(
            provider_result["text"], frozen)
        result = ContextReplyPaidResultReadV2(
            current.original.seal, frozen, request.read_attempt_id,
            ordinal, permit.operation_id, canonical_digest(asdict(permit)),
            current.model_call_request_digest, receipt, observation,
            current.original.current_read_versions,
            current.original.current_guard_digest,
            parsed.canonical_output, parsed.output_digest,
            "no_reply_hold" if parsed.status == "no_reply_hold"
            else "paid_current_source_verified_hold")
        fences.validate_fence(
            credential=credential, subject=self._read_subject, permit=permit)
        if self._graph.paid_call_current(
                request, intent, receipt,
                now_utc=float(self._clock())) != current:
            raise AuthorityUnavailable("current context reply graph changed after copy")
        return ContextReplyResultDeliveryV2(result, permit)

    def finish_delivery(self, *, credential: object,
                        delivery: ContextReplyResultDeliveryV2) -> None:
        if type(delivery) is not ContextReplyResultDeliveryV2:
            raise AuthorityUnavailable("typed context reply delivery required")
        request_id = delivery.result.read_attempt_id
        with self._delivery_lock:
            if self._inflight_deliveries.get(request_id) != delivery.permit:
                raise AuthorityUnavailable("context reply delivery is not active")
            try:
                self._finish(credential, request_id, delivery.permit)
            finally:
                self._inflight_deliveries.pop(request_id, None)

    def _finish(self, credential, read_attempt_id: str,
                permit: FencePermitV2) -> None:
        basis = {"read_attempt_id": read_attempt_id, "permit": asdict(permit)}
        self._fences.finish_fence(
            credential=credential, subject=self._read_subject, permit=permit,
            request_id="context-result-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({
                "action": "finish_context_reply_result_read", **basis}))

    def recover_finish(self, *, credential: object,
                       request: ContextReplyResultReadRequestV1) -> None:
        """Close a lost active read by original ID, never returning content."""
        if (type(request) is not ContextReplyResultReadRequestV1
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id):
            raise AuthorityUnavailable("installed context reply recovery required")
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("context reply delivery still in progress")
        self._fences.core._require(
            credential, "read", request.authority_namespace, self._holder)
        permit, state = self._fences.get_fence_operation(
            credential=credential, subject=self._read_subject,
            operation_id=request.read_attempt_id)
        if (state not in {"active", "finished"} or permit.operation != "read"
                or permit.authority_id != request.authority_id
                or permit.namespace != request.authority_namespace
                or permit.subject != self._read_subject
                or permit.holder != self._holder):
            raise AuthorityUnavailable("original context reply read fence differs")
        self._finish(credential, request.read_attempt_id, permit)

    def abandon_delivery(self, *, delivery: ContextReplyResultDeliveryV2) -> None:
        """Drop only process-local exclusion; recover_finish closes durable fence."""
        if type(delivery) is not ContextReplyResultDeliveryV2:
            raise AuthorityUnavailable("typed context reply delivery required")
        with self._delivery_lock:
            self._inflight_deliveries.pop(delivery.result.read_attempt_id, None)


__all__ = ("AuthorityV2ContextReplyResultReadService", "ContextReplyResultDeliveryV2")
