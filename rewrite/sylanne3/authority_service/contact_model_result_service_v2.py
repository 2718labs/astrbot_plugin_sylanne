"""Actual independent terminal verification and current contact content fence."""
from ..runtime.contact_original_read_v3 import contact_original_point_v3
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import threading
from .contract import AuthorityUnavailable
from .contact_model_result_contract_v2 import ContactModelResultReadRequestV2, ContactModelResultReadV2
from .contact_model_graph_v2 import read_current_contact_model_graph_v2, require_contact_policy_current_v2
from .v2_natural_generation_output_service import AuthorityV2NaturalGenerationOutputService
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_fence_service import AuthorityV2FenceService
from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
from .d10_contact_policy_service_v1 import InstalledD10ContactPolicyServiceV1
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime_contracts import canonical_digest


@dataclass(frozen=True, slots=True)
class ContactModelDeliveryV2:
    result: ContactModelResultReadV2
    permit: object


class InstalledContactModelResultServiceV2(AuthorityV2NaturalGenerationOutputService):
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
        from .current_authority_graph_read_v3 import install_authority_graph_read_controller_v3
        install_authority_graph_read_controller_v3(self,service=self,source_location=source_location)

    def _scope(self, request):
        if (type(request) is not ContactModelResultReadRequestV2 or request.installation_id != self._installation_id
                or request.authority_namespace != self._fences.namespace):
            raise AuthorityUnavailable("contact result installed selector differs")

    def _graph_read(self, request, intent, location, work):
        from .current_authority_graph_read_v3 import read_authority_graph_current_v3
        from .contact_model_work_v3 import observe_contact_current_policy_v3
        def read(db):
            self._location.require_graph_snapshot_v1(db,location,graph_db_path=self._path)
            original, frozen, job, call = read_current_contact_model_graph_v2(db, intent, self._issuer,
                self._clock(), allow_accounted_result=True, contact_policy_service=self._policy)
            from ..runtime.contact_paid_original_v2 import require_contact_original_v2
            from .contact_model_result_contract_v2 import contact_result_to_wire_v2
            saved, _ = require_contact_original_v2(db, self._issuer, original.namespace, "read_attempt", request.read_attempt_id)
            paid, _ = require_contact_original_v2(db, self._issuer, original.namespace, "paid_cost", original.job_id)
            reservation = contact_original_point_v3(db,table='runtime_budget_reservations',columns=('state',),key_columns=('lease_id', 'operation_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1]))((intent.budget_lease_id, original.prepare_operation_id)),legacy_reader=lambda: db.execute("SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (intent.budget_lease_id, original.prepare_operation_id)).fetchone())
            cost = contact_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((paid["cost_ref"],)),legacy_reader=lambda: db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (paid["cost_ref"],)).fetchone())
            import json
            if (saved != contact_result_to_wire_v2(request) or paid["unknown_dimensions"]
                    or paid["prepared_digest"] != original.digest or reservation != ("settled",)
                    or cost is None or cost[1] != 1 or json.loads(cost[0]) != paid["cost_value"]):
                raise AuthorityUnavailable("contact delivery lacks its actual original paid cost and saved selector")
            if ((request.namespace, request.installation_id, request.contact_id, request.phase, request.job_id,
                    request.acquire_operation_id, request.original_operation_id, request.call_id, request.binding_digest, request.model_request_digest) !=
                    (original.namespace, original.installation_id, original.contact_id, original.phase, original.job_id,
                     original.acquire_operation_id, original.prepare_operation_id, original.call_id, original.digest, call.digest)):
                raise AuthorityUnavailable("contact result selector is not its actual original")
            return original, frozen, job, call

        result = read_authority_graph_current_v3(work,read)
        observe_contact_current_policy_v3(work)
        if read_authority_graph_current_v3(work,read) != result:
            raise AuthorityUnavailable('Contact result actual same-Work Source or paid original changed')
        return result

    def prepare(self, *, credential, request):
        self._scope(request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("contact result delivery already active")
            self._inflight_deliveries[request.read_attempt_id] = None
        work = None
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
            from .contact_model_work_v3 import begin_contact_result_work_v3
            work = begin_contact_result_work_v3(self,credential=credential,permit=permit,request=request,intent=intent,location=location)
            before = self._graph_read(request,intent,location,work)
            current_intent, current_terminal, observation = self._read_original(request, anchor, content=True)
            if current_intent != intent or current_terminal != terminal or self._graph_read(request,intent,location,work) != before:
                raise AuthorityUnavailable("contact current Source or exact terminal changed during delivery")
            result = ContactModelResultReadV2(request, observation, terminal, float(self._clock()),
                canonical_digest({"prepared_digest": before[0].digest, "frozen_digest": before[0].frozen_digest,
                                  "policy_digest": before[1].input.adopted_plan.policy_original_digest}))
            result.require_original(intent, before[0])
            with fences.core._tx() as db:
                self._location.require_current_in_tx_v1(db, location)
            fences.validate_fence(credential=credential, subject=self._read_subject, permit=permit)
            return ContactModelDeliveryV2(result, permit)
        except BaseException:
            with self._delivery_lock:
                self._inflight_deliveries.pop(request.read_attempt_id, None)
            self.recover_finish(credential=credential, request=request)
            raise
        finally:
            if work is not None:
                from .current_authority_graph_read_v3 import finish_authority_graph_read_work_v3
                finish_authority_graph_read_work_v3(work)

    def _finish(self, credential, read_attempt_id, permit):
        basis = {"read_attempt_id": read_attempt_id, "permit": asdict(permit)}
        self._fences.finish_fence(credential=credential, subject=self._read_subject, permit=permit,
            request_id="contact-result-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({"action": "finish_contact_result_read_v2", **basis}))

    def finish_delivery(self, *, credential, delivery):
        if type(delivery) is not ContactModelDeliveryV2:
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
        if type(delivery) is not ContactModelDeliveryV2:
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
