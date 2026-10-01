"""Current D04 content delivery from the original independent model journal."""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
import math
from pathlib import Path
import sqlite3
import threading

from .contract import AuthorityUnavailable
from .current_d04_appraisal_v3 import D04AppraisalResultReadRequestV3, D04AppraisalResultReadV3, read_current_d04_appraisal_graph_v3
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_fence_service import AuthorityV2FenceService
from .v2_natural_generation_output_service import AuthorityV2NaturalGenerationOutputService
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime_contracts import canonical_digest


@dataclass(frozen=True, slots=True)
class D04AppraisalDeliveryV3:
    result: D04AppraisalResultReadV3
    permit: object


class AuthorityD04AppraisalResultServiceV3(AuthorityV2NaturalGenerationOutputService):
    """Reuse exact terminal/journal verification, with a distinct D04 selector.

    No natural-reply selector, seal or capability is accepted here. The
    superclass's private terminal reader only verifies the shared C02 ledger.
    """
    def __init__(self, *, store, fences, graph_db_path, d11_issuer, installation_id,
                 read_subject, holder, trusted_now_utc):
        if (type(store) is not AuthorityV2ModelEgressStore or type(fences) is not AuthorityV2FenceService
                or store._db is not fences.core._db or store._lock is not fences.core._lock
                or type(d11_issuer) is not D11BudgetJobIssuer or not callable(trusted_now_utc)):
            raise AuthorityUnavailable("installed D04 result service must share the exact independent journals")
        self._store, self._fences, self._issuer = store, fences, d11_issuer
        self._path = Path(graph_db_path).resolve(strict=True)
        self._installation_id, self._read_subject, self._holder = installation_id, read_subject, holder
        self._clock = trusted_now_utc
        self._delivery_lock, self._inflight_deliveries = threading.RLock(), {}

    def _scope(self, request):
        if (type(request) is not D04AppraisalResultReadRequestV3
                or request.installation_id != self._installation_id
                or request.authority_namespace != self._fences.namespace):
            raise AuthorityUnavailable("D04 installed result request differs")

    def _graph_read(self, request, intent):
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise AuthorityUnavailable("D04 trusted read time unavailable")
        with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            try:
                original, job, frozen = read_current_d04_appraisal_graph_v3(db, intent, self._issuer, now, allow_accounted_result=True)
                if ((request.namespace, request.job_id, request.original_operation_id, request.call_id,
                     request.binding_digest, request.model_request_digest, request.acquire_operation_id) !=
                    (original.namespace, original.job_id, original.operation_id, original.call_id,
                     original.digest, intent.request_digest, intent.acquire_operation_id)):
                    raise AuthorityUnavailable("D04 selector differs from actual original")
                return original, job, frozen
            finally:
                db.rollback()

    def prepare(self, *, credential, request, now_utc=None):
        self._scope(request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("D04 result delivery already active")
            self._inflight_deliveries[request.read_attempt_id] = None
        try:
            fences = self._fences
            fences.core._require(credential, "read", request.authority_namespace, self._holder)
            anchor = fences.current_anchor(credential=credential, subject=self._read_subject)
            if request.authority_id != anchor.authority_id:
                raise AuthorityUnavailable("D04 result Authority identity differs")
            intent, terminal, _ = self._read_original(request, anchor, content=False)
            before = self._graph_read(request, intent)
            permit = fences.begin_fence(credential=credential, subject=self._read_subject,
                holder=self._holder, operation="read", operation_id=request.read_attempt_id, expected_anchor=anchor)
            with self._delivery_lock:
                self._inflight_deliveries[request.read_attempt_id] = permit
            fences.validate_fence(credential=credential, subject=self._read_subject, permit=permit)
            current_intent, current_terminal, observation = self._read_original(request, anchor, content=True)
            if current_intent != intent or current_terminal != terminal or self._graph_read(request, intent) != before:
                raise AuthorityUnavailable("D04 current source or original changed during copy")
            result = D04AppraisalResultReadV3(request, observation, terminal)
            result.require_original(intent, before[0])
            fences.validate_fence(credential=credential, subject=self._read_subject, permit=permit)
            return D04AppraisalDeliveryV3(result, permit)
        except BaseException:
            with self._delivery_lock:
                self._inflight_deliveries.pop(request.read_attempt_id, None)
            try:
                self.recover_finish(credential=credential, request=request)
            except Exception:
                pass
            raise

    def _finish(self, credential, read_attempt_id, permit):
        basis = {"read_attempt_id": read_attempt_id, "permit": asdict(permit)}
        self._fences.finish_fence(credential=credential, subject=self._read_subject, permit=permit,
            request_id="d04-appraisal-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({"action": "finish_d04_appraisal_read_v3", **basis}))

    def finish_delivery(self, *, credential, delivery):
        if type(delivery) is not D04AppraisalDeliveryV3:
            raise AuthorityUnavailable("actual D04 delivery required")
        key = delivery.result.request.read_attempt_id
        with self._delivery_lock:
            if self._inflight_deliveries.get(key) != delivery.permit:
                raise AuthorityUnavailable("D04 delivery is not active")
            try:
                self._finish(credential, key, delivery.permit)
            finally:
                self._inflight_deliveries.pop(key, None)

    def abandon_delivery(self, *, delivery):
        if type(delivery) is not D04AppraisalDeliveryV3:
            raise AuthorityUnavailable("actual D04 delivery required")
        with self._delivery_lock:
            self._inflight_deliveries.pop(delivery.result.request.read_attempt_id, None)

    def recover_finish(self, *, credential, request):
        self._scope(request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("D04 delivery remains active")
        self._fences.core._require(credential, "read", request.authority_namespace, self._holder)
        # A crash can occur after the Graph records the read attempt but before
        # Authority receives it. Confirm exact absence in this authenticated
        # store; an arbitrary RPC exception is never treated as absence.
        with self._fences.core._tx() as db:
            self._fences._require_mode(db)
            if self._fences.fences._row(db, request.read_attempt_id) is None:
                return
        permit, state = self._fences.get_fence_operation(credential=credential, subject=self._read_subject,
                                                       operation_id=request.read_attempt_id)
        if (state not in {"active", "finished"} or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.subject, permit.holder) !=
                   (request.authority_id, request.authority_namespace, self._read_subject, self._holder)):
            raise AuthorityUnavailable("D04 original result fence differs")
        self._finish(credential, request.read_attempt_id, permit)
