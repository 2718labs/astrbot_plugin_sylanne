"""Select an original paid generation output digest from Authority-owned facts.

This selector closes the original graph job without releasing model text. A
separate current-source read is required before a review job may see content.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import sqlite3
import threading
from typing import Callable

from ..model_broker.natural_reply_history_v3 import parse_natural_reply_output_current_v1 as parse_natural_reply_output_v2
from ..runtime.jobs import get_job
from ..runtime.model_cost_settlement import (
    OriginalModelCostCommitV1, original_model_cost_operation_id_v1,
)
from ..runtime.natural_reply_job_v2 import (
    NaturalReplyJobHold, read_original_call_binding, read_original_preparation,
)
from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable, identifier
from .v2_contract import FencePermitV2
from .v2_fence_service import AuthorityV2FenceService
from .v2_model_egress_contract import ModelEgressIntentV1, ModelTerminalReceiptV2
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_natural_generation_output_contract import (
    NaturalGenerationOriginalOutputV2, NaturalGenerationOutputReadRequestV2,
)


class PinnedNaturalGenerationOriginalPaidVerifierV2:
    """Independently bind graph original, call, cost and budget to Authority."""

    def __init__(self, graph_db_path: str | Path):
        path = Path(graph_db_path)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("pinned natural graph database required")
        self._path = path.resolve(strict=True)

    def read(self, request: NaturalGenerationOutputReadRequestV2,
             intent: ModelEgressIntentV1,
             receipt: ModelTerminalReceiptV2):
        if (type(request) is not NaturalGenerationOutputReadRequestV2
                or type(intent) is not ModelEgressIntentV1
                or type(receipt) is not ModelTerminalReceiptV2):
            return None
        try:
            with closing(sqlite3.connect(
                    self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    saved = read_original_preparation(
                        db, request.namespace, request.c02_operation_id,
                        "generation")
                    if saved is None or saved.state != "acquired":
                        return None
                    seal = saved.seal
                    binding = read_original_call_binding(db, saved)
                    if binding is None:
                        return None
                    call = binding.request
                    job = get_job(db, seal.job_id)
                    seal_digest = canonical_digest(asdict(seal))
                    binding_digest = canonical_digest({
                        "original_seal_digest": seal_digest,
                        "model_call_request_digest": call.digest,
                        "worker_fence": binding.worker_fence,
                    })
                    if ((seal.namespace, seal.c02_operation_id,
                         seal.source_ref, seal.installation_id, seal.job_id,
                         seal.original_operation_id, seal.acquire_operation_id,
                         seal.call_id) !=
                        (request.namespace, request.c02_operation_id,
                         request.source_ref, request.installation_id,
                         request.job_id, request.original_operation_id,
                         request.acquire_operation_id, request.call_id)
                            or call.digest != request.typed_model_request_digest
                            or binding.typed_request_digest != call.digest
                            or (intent.authority_id, intent.namespace,
                                intent.operation_id, intent.call_id,
                                intent.job_id, intent.request_digest,
                                intent.binding_digest, intent.worker_fence,
                                intent.budget_lease_id,
                                intent.budget_reservation_operation_id) !=
                               (request.authority_id,
                                request.authority_namespace,
                                seal.acquire_operation_id, seal.call_id,
                                seal.job_id, call.digest, binding_digest,
                                binding.worker_fence,
                                seal.parent_budget_lease_id,
                                seal.reservation_operation_id)
                            or (job.work_kind, job.phase, job.job_id,
                                job.operation_id, job.budget_ref, job.fence,
                                job.lease_holder) !=
                               ("natural_generation", "running", seal.job_id,
                                seal.original_operation_id,
                                seal.parent_budget_lease_id,
                                binding.worker_fence, intent.subject)):
                        return None
                    cost_id = original_model_cost_operation_id_v1(
                        request.namespace, seal.call_id)
                    row = db.execute(
                        "SELECT activity_id,commit_seq,receipt_json FROM "
                        "graph_bundle_operations WHERE bot=? AND persona=? "
                        "AND operation_id=?",
                        request.namespace.as_tuple + (cost_id,),
                    ).fetchone()
                    if row is None:
                        return None
                    data = json.loads(row[2])
                    if canonical_serialize(data) != row[2]:
                        return None
                    cost = OriginalModelCostCommitV1(**data["original_model_cost"])
                    intent_digest = canonical_digest(asdict(intent))
                    receipt_digest = canonical_digest(asdict(receipt))
                    if (data.get("original_intent_digest") != intent_digest
                            or data.get("terminal_receipt_digest") != receipt_digest
                            or cost.status != "committed"
                            or cost.operation_id != cost_id
                            or cost.call_id != seal.call_id
                            or cost.terminal_receipt_digest != receipt_digest
                            or cost.commit_seq != row[1]
                            or db.execute(
                                "SELECT 1 FROM graph_events WHERE bot=? AND "
                                "persona=? AND session=? AND event_id=?",
                                request.namespace.as_tuple + (row[0], cost_id),
                            ).fetchone() is None
                            or db.execute(
                                "SELECT 1 FROM graph_atoms WHERE token=? AND valid=1",
                                (cost.cost_ref,),
                            ).fetchone() is None
                            or db.execute(
                                "SELECT 1 FROM runtime_budget_operations WHERE "
                                "bot_id=? AND persona_id=? AND operation_id=? "
                                "AND phase='settle'",
                                request.namespace.as_tuple +
                                (seal.reservation_operation_id,),
                            ).fetchone() is None
                            or db.execute(
                                "SELECT state FROM runtime_budget_reservations "
                                "WHERE lease_id=? AND operation_id=?",
                                (seal.parent_budget_lease_id,
                                 seal.reservation_operation_id),
                            ).fetchone() != ("settled",)):
                        return None
                    return saved, binding, seal_digest, intent_digest, receipt_digest
                finally:
                    db.execute("ROLLBACK")
        except (NaturalReplyJobHold, sqlite3.Error, KeyError, TypeError,
                ValueError, AttributeError):
            return None


@dataclass(frozen=True, slots=True)
class NaturalGenerationOutputDeliveryV2:
    result: NaturalGenerationOriginalOutputV2
    permit: FencePermitV2


class AuthorityV2NaturalGenerationOutputService:
    """Read and parse one paid original observation behind an Authority fence."""

    def __init__(self, *, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService,
                 graph_verifier: PinnedNaturalGenerationOriginalPaidVerifierV2,
                 installation_id: str, read_subject: str, holder: str,
                 trusted_now_utc: Callable[[], float]):
        for value, name in ((installation_id, "installation_id"),
                            (read_subject, "read_subject"), (holder, "holder")):
            identifier(value, name)
        core = fences.core if type(fences) is AuthorityV2FenceService else None
        if (type(store) is not AuthorityV2ModelEgressStore or core is None
                or type(graph_verifier) is not PinnedNaturalGenerationOriginalPaidVerifierV2
                or store._db is not core._db or store._lock is not core._lock
                or not callable(trusted_now_utc)):
            raise AuthorityUnavailable("natural original result needs one pinned Authority")
        self._store, self._fences, self._graph = store, fences, graph_verifier
        self._installation_id, self._read_subject = installation_id, read_subject
        self._holder, self._clock = holder, trusted_now_utc
        self._delivery_lock = threading.RLock()
        self._inflight_deliveries: dict[str, FencePermitV2 | None] = {}

    def _terminal_locked(self, db, request, anchor, *, content: bool):
        record = self._store._read(db, request.call_id)
        if (record is None or record.state != "observed" or record.content_erased
                or (record.intent.authority_id, record.intent.namespace,
                    record.intent.call_id, record.intent.job_id,
                    record.intent.authority_activation_generation) !=
                   (request.authority_id, request.authority_namespace,
                    request.call_id, request.job_id,
                    anchor.activation_generation)):
            raise AuthorityUnavailable("original natural terminal unavailable")
        intent = record.intent
        if (intent.subject != self._read_subject
                or intent.operation_id != request.acquire_operation_id):
            raise AuthorityUnavailable("original natural intent differs")
        admission, report_digest, receipt = self._store.read_admission_locked(
            db, intent)
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
                   (intent.fence_token, intent.fence_epoch,
                    intent.fence_revision)
                or not self._store.is_fence_bound_locked(db, intent)
                or admission.installation_id != request.installation_id
                or receipt.installation_id != request.installation_id
                or receipt.observation_digest != record.observation_digest
                or receipt.finish_digest !=
                   self._fences.fences.model_terminal_finish_digest(
                       intent, original_permit, "completed",
                       record.observation_digest)):
            raise AuthorityUnavailable("original natural admission differs")
        if not content:
            return intent, receipt, None
        observation = self._store._read_observation_locked(db, intent)
        if (observation.status != "completed"
                or observation.digest != receipt.observation_digest):
            raise AuthorityUnavailable("original natural observation differs")
        return intent, receipt, observation

    def _read_original(self, request, anchor, *, content: bool):
        fences = self._fences
        with fences._frozen() as (db, deletion_head, execution_head, history):
            current = fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=anchor.activation_generation)
            if current != anchor:
                raise AuthorityUnavailable("natural result read anchor changed")
            return self._terminal_locked(db, request, anchor, content=content)

    def prepare(self, *, credential: object,
                request: NaturalGenerationOutputReadRequestV2,
                now_utc: float) -> NaturalGenerationOutputDeliveryV2:
        if (type(request) is not NaturalGenerationOutputReadRequestV2
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id
                or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
            raise AuthorityUnavailable("installed natural result read required")
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("natural result read already active")
            self._inflight_deliveries[request.read_attempt_id] = None
        try:
            result = self._prepare_inner(credential, request)
            with self._delivery_lock:
                self._inflight_deliveries[request.read_attempt_id] = result.permit
            return result
        except BaseException:
            with self._delivery_lock:
                self._inflight_deliveries.pop(request.read_attempt_id, None)
            try:
                self.recover_finish(credential=credential, request=request)
            except Exception:
                pass
            raise

    def _prepare_inner(self, credential, request):
        fences = self._fences
        fences.core._require(
            credential, "read", request.authority_namespace, self._holder)
        trusted_now = self._clock()
        if type(trusted_now) not in (int, float) or not math.isfinite(trusted_now):
            raise AuthorityUnavailable("trusted natural result clock unavailable")
        anchor = fences.current_anchor(
            credential=credential, subject=self._read_subject)
        if anchor.authority_id != request.authority_id:
            raise AuthorityUnavailable("natural result Authority identity differs")
        intent, receipt, _ = self._read_original(request, anchor, content=False)
        original = self._graph.read(request, intent, receipt)
        if original is None:
            raise AuthorityUnavailable("natural original paid graph unavailable")
        permit = fences.begin_fence(
            credential=credential, subject=self._read_subject,
            holder=self._holder, operation="read",
            operation_id=request.read_attempt_id,
            expected_anchor=anchor)
        fences.validate_fence(
            credential=credential, subject=self._read_subject, permit=permit)
        second_intent, second_receipt, observation = self._read_original(
            request, anchor, content=True)
        after = self._graph.read(request, second_intent, second_receipt)
        if (second_intent != intent or second_receipt != receipt
                or after != original):
            raise AuthorityUnavailable("natural original changed during read")
        result = observation.result
        if (type(result) is not dict or set(result) != {"text"}
                or type(result["text"]) is not str):
            raise AuthorityUnavailable("natural provider result shape differs")
        parsed = parse_natural_reply_output_v2(result["text"], original[0].frozen)
        output = NaturalGenerationOriginalOutputV2(
            request=request, original_seal_digest=original[2],
            typed_model_request_digest=original[1].typed_request_digest,
            original_intent_digest=original[3],
            terminal_receipt_digest=original[4],
            observation_digest=observation.digest,
            output_digest=parsed.output_digest, status=parsed.status)
        fences.validate_fence(
            credential=credential, subject=self._read_subject, permit=permit)
        if self._graph.read(request, intent, receipt) != original:
            raise AuthorityUnavailable("natural original changed after copy")
        return NaturalGenerationOutputDeliveryV2(output, permit)

    def finish_delivery(self, *, credential: object,
                        delivery: NaturalGenerationOutputDeliveryV2) -> None:
        if type(delivery) is not NaturalGenerationOutputDeliveryV2:
            raise AuthorityUnavailable("typed natural output delivery required")
        request_id = delivery.result.request.read_attempt_id
        with self._delivery_lock:
            if self._inflight_deliveries.get(request_id) != delivery.permit:
                raise AuthorityUnavailable("natural output delivery is not active")
            try:
                self._finish(credential, request_id, delivery.permit)
            finally:
                self._inflight_deliveries.pop(request_id, None)

    def _finish(self, credential, read_attempt_id, permit):
        basis = {"read_attempt_id": read_attempt_id, "permit": asdict(permit)}
        self._fences.finish_fence(
            credential=credential, subject=self._read_subject, permit=permit,
            request_id="natural-output-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({
                "action": "finish_natural_generation_output_read", **basis}))

    def recover_finish(self, *, credential: object,
                       request: NaturalGenerationOutputReadRequestV2) -> None:
        if (type(request) is not NaturalGenerationOutputReadRequestV2
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id):
            raise AuthorityUnavailable("installed natural output recovery required")
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("natural output delivery still in progress")
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
            raise AuthorityUnavailable("natural output read fence differs")
        self._finish(credential, request.read_attempt_id, permit)

    def abandon_delivery(self, *, delivery: NaturalGenerationOutputDeliveryV2) -> None:
        """Drop process-local exclusion; recover_finish closes durable fence."""
        if type(delivery) is not NaturalGenerationOutputDeliveryV2:
            raise AuthorityUnavailable("typed natural output delivery required")
        with self._delivery_lock:
            self._inflight_deliveries.pop(delivery.result.request.read_attempt_id, None)

    def read_original_natural_generation_output_v2(
        self, *, credential: object,
        request: NaturalGenerationOutputReadRequestV2, now_utc: float,
    ) -> NaturalGenerationOriginalOutputV2:
        """Local installed port: finish the metadata read before returning."""
        delivery = self.prepare(
            credential=credential, request=request, now_utc=now_utc)
        self.finish_delivery(credential=credential, delivery=delivery)
        return delivery.result


__all__ = (
    "PinnedNaturalGenerationOriginalPaidVerifierV2",
    "AuthorityV2NaturalGenerationOutputService",
    "NaturalGenerationOutputDeliveryV2",
)
