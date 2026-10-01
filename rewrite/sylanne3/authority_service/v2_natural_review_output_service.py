"""Select a paid natural review verdict from original Authority observations."""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import sqlite3
import threading
from typing import Callable

from ..model_broker.natural_review import parse_natural_reply_review_output_v1
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
from .v2_natural_generation_output_service import (
    AuthorityV2NaturalGenerationOutputService,
)
from .v2_natural_review_output_contract import (
    NaturalReviewOriginalOutputV2, NaturalReviewOutputReadRequestV2,
)


class PinnedNaturalReviewOriginalPaidVerifierV2:
    """Reopen review/generation seals and the original settled review cost."""

    def __init__(self, graph_db_path: str | Path):
        path = Path(graph_db_path)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("pinned natural review graph database required")
        self._path = path.resolve(strict=True)

    def read(self, request: NaturalReviewOutputReadRequestV2,
             intent: ModelEgressIntentV1,
             receipt: ModelTerminalReceiptV2):
        if (type(request) is not NaturalReviewOutputReadRequestV2
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
                        db, request.namespace, request.parent_original_id,
                        "review")
                    generation = read_original_preparation(
                        db, request.namespace, request.parent_original_id,
                        "generation")
                    if (saved is None or saved.state != "acquired"
                            or generation is None
                            or generation.state != "terminal"):
                        return None
                    seal, gen_seal = saved.seal, generation.seal
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
                    if ((seal.namespace, seal.installation_id, seal.job_id,
                         seal.original_operation_id, seal.acquire_operation_id,
                         seal.call_id, seal.generation_original_operation_id,
                         seal.generation_call_id, seal.generation_output_digest)
                        != (request.namespace, request.installation_id,
                            request.job_id, request.original_operation_id,
                            request.acquire_operation_id, request.call_id,
                            request.generation_original_operation_id,
                            request.generation_call_id,
                            request.generation_output_digest)
                            or gen_seal.c02_operation_id !=
                               request.parent_original_id
                            or generation.terminal_output_digest !=
                               request.generation_output_digest
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
                               ("natural_review", "running", seal.job_id,
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
                    return (saved, generation, binding, seal_digest,
                            intent_digest, receipt_digest)
                finally:
                    db.execute("ROLLBACK")
        except (NaturalReplyJobHold, sqlite3.Error, KeyError, TypeError,
                ValueError, AttributeError):
            return None


@dataclass(frozen=True, slots=True)
class NaturalReviewOutputDeliveryV2:
    result: NaturalReviewOriginalOutputV2
    permit: FencePermitV2


class AuthorityV2NaturalReviewOutputService(
        AuthorityV2NaturalGenerationOutputService):
    """Reuse the same Authority ledger check for a distinct review original."""

    def __init__(self, *, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService,
                 graph_verifier: PinnedNaturalReviewOriginalPaidVerifierV2,
                 installation_id: str, read_subject: str, holder: str,
                 trusted_now_utc: Callable[[], float]):
        for value, name in ((installation_id, "installation_id"),
                            (read_subject, "read_subject"), (holder, "holder")):
            identifier(value, name)
        core = fences.core if type(fences) is AuthorityV2FenceService else None
        if (type(store) is not AuthorityV2ModelEgressStore or core is None
                or type(graph_verifier) is not
                   PinnedNaturalReviewOriginalPaidVerifierV2
                or store._db is not core._db or store._lock is not core._lock
                or not callable(trusted_now_utc)):
            raise AuthorityUnavailable("review result needs one pinned Authority")
        self._store, self._fences, self._graph = store, fences, graph_verifier
        self._installation_id, self._read_subject = installation_id, read_subject
        self._holder, self._clock = holder, trusted_now_utc
        self._delivery_lock = threading.RLock()
        self._inflight_deliveries: dict[str, FencePermitV2 | None] = {}

    def prepare(self, *, credential: object,
                request: NaturalReviewOutputReadRequestV2,
                now_utc: float) -> NaturalReviewOutputDeliveryV2:
        if (type(request) is not NaturalReviewOutputReadRequestV2
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id
                or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
            raise AuthorityUnavailable("installed natural review result required")
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("natural review read already active")
            self._inflight_deliveries[request.read_attempt_id] = None
        try:
            delivery = self._prepare_inner(credential, request)
            with self._delivery_lock:
                self._inflight_deliveries[request.read_attempt_id] = delivery.permit
            return delivery
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
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise AuthorityUnavailable("trusted natural review clock unavailable")
        anchor = fences.current_anchor(
            credential=credential, subject=self._read_subject)
        if anchor.authority_id != request.authority_id:
            raise AuthorityUnavailable("natural review Authority identity differs")
        intent, receipt, _ = self._read_original(request, anchor, content=False)
        original = self._graph.read(request, intent, receipt)
        if original is None:
            raise AuthorityUnavailable("review original paid graph unavailable")
        permit = fences.begin_fence(
            credential=credential, subject=self._read_subject,
            holder=self._holder, operation="read",
            operation_id=request.read_attempt_id,
            expected_anchor=anchor)
        fences.validate_fence(
            credential=credential, subject=self._read_subject, permit=permit)
        again_intent, again_receipt, observation = self._read_original(
            request, anchor, content=True)
        after = self._graph.read(request, again_intent, again_receipt)
        if (again_intent != intent or again_receipt != receipt
                or after != original):
            raise AuthorityUnavailable("review original changed during read")
        result = observation.result
        if (type(result) is not dict or set(result) != {"text"}
                or type(result["text"]) is not str):
            raise AuthorityUnavailable("review provider result shape differs")
        saved, generation, binding, seal_digest, intent_digest, receipt_digest = (
            original)
        parsed = parse_natural_reply_review_output_v1(
            result["text"], saved.frozen, generation.seal, saved.seal)
        output = NaturalReviewOriginalOutputV2(
            request, seal_digest, binding.typed_request_digest,
            intent_digest, receipt_digest, observation.digest,
            parsed.output_digest, parsed.verdict)
        fences.validate_fence(
            credential=credential, subject=self._read_subject, permit=permit)
        if self._graph.read(request, intent, receipt) != original:
            raise AuthorityUnavailable("review original changed after copy")
        return NaturalReviewOutputDeliveryV2(output, permit)

    def finish_delivery(self, *, credential: object,
                        delivery: NaturalReviewOutputDeliveryV2) -> None:
        if type(delivery) is not NaturalReviewOutputDeliveryV2:
            raise AuthorityUnavailable("typed review delivery required")
        attempt = delivery.result.request.read_attempt_id
        with self._delivery_lock:
            if self._inflight_deliveries.get(attempt) != delivery.permit:
                raise AuthorityUnavailable("review delivery is not active")
            try:
                self._finish(credential, attempt, delivery.permit)
            finally:
                self._inflight_deliveries.pop(attempt, None)

    def _finish(self, credential, read_attempt_id, permit):
        basis = {"read_attempt_id": read_attempt_id, "permit": asdict(permit)}
        self._fences.finish_fence(
            credential=credential, subject=self._read_subject, permit=permit,
            request_id="natural-review-output-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({
                "action": "finish_natural_review_output_read", **basis}))

    def recover_finish(self, *, credential: object,
                       request: NaturalReviewOutputReadRequestV2) -> None:
        if (type(request) is not NaturalReviewOutputReadRequestV2
                or request.authority_namespace != self._fences.namespace
                or request.installation_id != self._installation_id):
            raise AuthorityUnavailable("installed natural review recovery required")
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("review delivery still in progress")
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
            raise AuthorityUnavailable("review read fence differs")
        self._finish(credential, request.read_attempt_id, permit)

    def abandon_delivery(self, *, delivery: NaturalReviewOutputDeliveryV2) -> None:
        if type(delivery) is not NaturalReviewOutputDeliveryV2:
            raise AuthorityUnavailable("typed review delivery required")
        with self._delivery_lock:
            self._inflight_deliveries.pop(delivery.result.request.read_attempt_id,
                                          None)

    def read_original_natural_review_output_v2(
        self, *, credential: object, request: NaturalReviewOutputReadRequestV2,
        now_utc: float,
    ) -> NaturalReviewOriginalOutputV2:
        delivery = self.prepare(
            credential=credential, request=request, now_utc=now_utc)
        self.finish_delivery(credential=credential, delivery=delivery)
        return delivery.result


__all__ = (
    "PinnedNaturalReviewOriginalPaidVerifierV2",
    "AuthorityV2NaturalReviewOutputService",
    "NaturalReviewOutputDeliveryV2",
)
