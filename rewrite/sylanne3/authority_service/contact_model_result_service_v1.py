"""Actual independent terminal verification and current contact content fence."""
from contextlib import closing
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import threading
from .contract import AuthorityUnavailable
from .contact_model_result_contract_v1 import ContactModelResultReadRequestV1, ContactModelResultReadV1
from .contact_model_graph_v1 import read_current_contact_model_graph_v1, require_contact_policy_current_v1
from .v2_natural_generation_output_service import AuthorityV2NaturalGenerationOutputService
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_fence_service import AuthorityV2FenceService
from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
from .d10_contact_policy_service_v1 import InstalledD10ContactPolicyServiceV1
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime_contracts import canonical_digest


@dataclass(frozen=True, slots=True)
class ContactModelDeliveryV1:
    result: ContactModelResultReadV1
    permit: object


class InstalledContactModelResultServiceV1(AuthorityV2NaturalGenerationOutputService):
    """Only the shared original terminal/fence methods are reused."""
    def __init__(self, *, store, fences, graph_db_path, d11_issuer, installation_id, read_subject,
            holder, trusted_now_utc, source_location, contact_policy_service):
        if (type(store) is not AuthorityV2ModelEgressStore or type(fences) is not AuthorityV2FenceService
                or store._db is not fences.core._db or store._lock is not fences.core._lock
                or type(d11_issuer) is not D11BudgetJobIssuer or not callable(trusted_now_utc)
                or type(source_location) is not InstalledCurrentSourceLocationQualifierV1
                or source_location._fences is not fences or type(contact_policy_service) is not InstalledD10ContactPolicyServiceV1
                or contact_policy_service.core is not fences.core or contact_policy_service.installation_id != installation_id):
            raise AuthorityUnavailable("contact result requires its actual installed journals, current location and Owner policy")
        self._store, self._fences, self._issuer = store, fences, d11_issuer
        self._path = Path(graph_db_path).resolve(strict=True)
        if self._path != source_location._graph_db_path:
            raise AuthorityUnavailable("contact result Graph is outside actual current storage")
        self._installation_id, self._read_subject, self._holder = installation_id, read_subject, holder
        self._clock, self._location, self._policy = trusted_now_utc, source_location, contact_policy_service
        self._delivery_lock, self._inflight_deliveries = threading.RLock(), {}

    def _scope(self, request):
        if (type(request) is not ContactModelResultReadRequestV1 or request.installation_id != self._installation_id
                or request.authority_namespace != self._fences.namespace):
            raise AuthorityUnavailable("contact result installed selector differs")

    def _graph_read(self, request, intent, location):
        with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            try:
                self._location.require_graph_snapshot_v1(db, location, graph_db_path=self._path)
                original, frozen, job, call = read_current_contact_model_graph_v1(db, intent, self._issuer,
                    self._clock(), allow_accounted_result=True, contact_policy_service=self._policy)
                from ..runtime.contact_paid_original_v1 import require_contact_original_v1
                from .contact_model_result_contract_v1 import contact_result_to_wire_v1
                saved, _ = require_contact_original_v1(db, self._issuer, original.namespace, "read_attempt", request.read_attempt_id)
                paid, _ = require_contact_original_v1(db, self._issuer, original.namespace, "paid_cost", original.job_id)
                reservation = db.execute("SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (intent.budget_lease_id, original.prepare_operation_id)).fetchone()
                cost = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (paid["cost_ref"],)).fetchone()
                import json
                if (saved != contact_result_to_wire_v1(request) or paid["unknown_dimensions"]
                        or paid["prepared_digest"] != original.digest or reservation != ("settled",)
                        or cost is None or cost[1] != 1 or json.loads(cost[0]) != paid["cost_value"]):
                    raise AuthorityUnavailable("contact delivery lacks its actual original paid cost and saved selector")
                if ((request.namespace, request.installation_id, request.contact_id, request.phase, request.job_id,
                        request.acquire_operation_id, request.original_operation_id, request.call_id, request.binding_digest, request.model_request_digest) !=
                        (original.namespace, original.installation_id, original.contact_id, original.phase, original.job_id,
                         original.acquire_operation_id, original.prepare_operation_id, original.call_id, original.digest, call.digest)):
                    raise AuthorityUnavailable("contact result selector is not its actual original")
                return original, frozen, job, call
            finally:
                db.rollback()

    def prepare(self, *, credential, request):
        self._scope(request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("contact result delivery already active")
            self._inflight_deliveries[request.read_attempt_id] = None
        try:
            fences = self._fences
            fences.core._require(credential, "read", request.authority_namespace, self._holder)
            anchor = fences.current_anchor(credential=credential, subject=self._read_subject)
            if anchor.authority_id != request.authority_id:
                raise AuthorityUnavailable("contact result Authority identity differs")
            intent, terminal, _ = self._read_original(request, anchor, content=False)
            permit = fences.begin_fence(credential=credential, subject=self._read_subject, holder=self._holder,
                operation="read", operation_id=request.read_attempt_id, expected_anchor=anchor)
            with self._delivery_lock:
                self._inflight_deliveries[request.read_attempt_id] = permit
            location = self._location.observe_business_for_fence_v1(credential=credential, subject=self._read_subject, permit=permit)
            before = self._graph_read(request, intent, location)
            current_intent, current_terminal, observation = self._read_original(request, anchor, content=True)
            if current_intent != intent or current_terminal != terminal or self._graph_read(request, intent, location) != before:
                raise AuthorityUnavailable("contact current Source or exact terminal changed during delivery")
            result = ContactModelResultReadV1(request, observation, terminal, float(self._clock()),
                canonical_digest({"prepared_digest": before[0].digest, "frozen_digest": before[0].frozen_digest,
                                  "policy_digest": before[1].input.adopted_plan.policy_original_digest}))
            result.require_original(intent, before[0])
            with fences.core._tx() as db:
                self._location.require_current_in_tx_v1(db, location)
            fences.validate_fence(credential=credential, subject=self._read_subject, permit=permit)
            return ContactModelDeliveryV1(result, permit)
        except BaseException:
            with self._delivery_lock:
                self._inflight_deliveries.pop(request.read_attempt_id, None)
            self.recover_finish(credential=credential, request=request)
            raise

    def _finish(self, credential, read_attempt_id, permit):
        basis = {"read_attempt_id": read_attempt_id, "permit": asdict(permit)}
        self._fences.finish_fence(credential=credential, subject=self._read_subject, permit=permit,
            request_id="contact-result-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({"action": "finish_contact_result_read_v1", **basis}))

    def finish_delivery(self, *, credential, delivery):
        if type(delivery) is not ContactModelDeliveryV1:
            raise AuthorityUnavailable("actual contact delivery required")
        key = delivery.result.request.read_attempt_id
        with self._delivery_lock:
            if self._inflight_deliveries.get(key) != delivery.permit:
                raise AuthorityUnavailable("contact result delivery is not active")
            try:
                self._finish(credential, key, delivery.permit)
            finally:
                self._inflight_deliveries.pop(key, None)

    def abandon_delivery(self, *, delivery):
        if type(delivery) is not ContactModelDeliveryV1:
            raise AuthorityUnavailable("actual contact delivery required")
        with self._delivery_lock:
            self._inflight_deliveries.pop(delivery.result.request.read_attempt_id, None)

    def recover_finish(self, *, credential, request):
        self._scope(request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("contact result delivery is still active")
        self._fences.core._require(credential, "read", request.authority_namespace, self._holder)
        with self._fences.core._tx() as db:
            if self._fences.fences._row(db, request.read_attempt_id) is None:
                return
        permit, state = self._fences.get_fence_operation(credential=credential, subject=self._read_subject, operation_id=request.read_attempt_id)
        if (state not in {"active", "finished"} or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.subject, permit.holder) !=
                    (request.authority_id, request.authority_namespace, self._read_subject, self._holder)):
            raise AuthorityUnavailable("contact original delivery fence differs")
        self._finish(credential, request.read_attempt_id, permit)
