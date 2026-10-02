"""Actual independent terminal verification and current Life content content fence."""
from contextlib import closing
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import threading
from .contract import AuthorityUnavailable
from .internal_life_model_result_contract_v2 import InternalLifeModelResultReadRequestV2, InternalLifeModelResultReadV2
from .internal_life_model_graph_v2 import InstalledInternalLifeModelGraphReaderV2
from .v2_natural_generation_output_service import AuthorityV2NaturalGenerationOutputService
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_fence_service import AuthorityV2FenceService
from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime_contracts import canonical_digest


@dataclass(frozen=True, slots=True)
class InternalLifeModelDeliveryV2:
    result: InternalLifeModelResultReadV2
    permit: object


class InstalledInternalLifeModelResultServiceV2(AuthorityV2NaturalGenerationOutputService):
    """Only the shared original terminal/fence methods are reused."""
    def __init__(self, *, store, fences, graph_db_path, d11_issuer, installation_id, read_subject,
            holder, trusted_now_utc, source_location, graph_reader):
        if (type(store) is not AuthorityV2ModelEgressStore or type(fences) is not AuthorityV2FenceService
                or store._db is not fences.core._db or store._lock is not fences.core._lock
                or type(d11_issuer) is not D11BudgetJobIssuer or not callable(trusted_now_utc)
                or type(source_location) is not InstalledCurrentSourceLocationQualifierV1
                or source_location._fences is not fences or type(graph_reader) is not InstalledInternalLifeModelGraphReaderV2
                or graph_reader.owner_storage.fences is not fences or graph_reader.read_subject != read_subject
                or graph_reader.readers.issuer is not d11_issuer
                or graph_reader.owner_storage.installation_id != installation_id):
            raise AuthorityUnavailable("Life content result requires its actual installed journals, current location and Owner policy")
        self._store, self._fences, self._issuer = store, fences, d11_issuer
        self._path = Path(graph_db_path).resolve(strict=True)
        if self._path != source_location._graph_db_path:
            raise AuthorityUnavailable("Life content result Graph is outside actual current storage")
        self._installation_id, self._read_subject, self._holder = installation_id, read_subject, holder
        self._clock, self._location, self._graph_reader = trusted_now_utc, source_location, graph_reader
        self._delivery_lock, self._inflight_deliveries = threading.RLock(), {}

    def _scope(self, request):
        if (type(request) is not InternalLifeModelResultReadRequestV2 or request.installation_id != self._installation_id
                or request.authority_namespace != self._fences.namespace):
            raise AuthorityUnavailable("Life content result installed selector differs")

    def _graph_read(self, request, intent, terminal, location, fact=None):
        from ..runtime.internal_life_paid_result_v2 import read_life_paid_original_v2,read_life_cost_commit_v2
        from .internal_life_model_result_contract_v2 import internal_life_result_to_wire_v2
        with closing(sqlite3.connect(self._path.as_uri()+"?mode=ro",uri=True)) as db:
            db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
            try:
                self._location.require_graph_snapshot_v1(db,location,graph_db_path=self._path)
                current=self._graph_reader.read(db,intent,self._clock(),allow_accounted_result=True)
                p,b,f=current.prepared,current.binding,current.frozen
                saved=read_life_paid_original_v2(db,p.namespace,self._issuer,'read_attempt',request.read_attempt_id)
                if saved!=internal_life_result_to_wire_v2(request):
                    raise AuthorityUnavailable('Life result lacks its actual saved W01 selector')
                cost=read_life_cost_commit_v2(db,namespace=p.namespace,issuer=self._issuer,
                    prepared=p,intent=intent,terminal=terminal,fact=fact)
                expected=(p.namespace,p.installation_id,p.episode_ref,p.occurrence_digest,
                    f.input.cause.occurrence.event.causal_operation_id,p.job_id,p.acquire_operation_id,
                    p.prepare_operation_id,p.call_id,b.digest,p.digest,current.request.digest)
                if (request.namespace,request.installation_id,request.episode_ref,request.occurrence_digest,
                    request.causal_operation_id,request.job_id,request.acquire_operation_id,
                    request.original_operation_id,request.call_id,request.binding_digest,
                    request.prepared_digest,request.model_request_digest)!=expected:
                    raise AuthorityUnavailable('Life result actual worker/occurrence/original binding differs')
                return current,cost
            finally:db.rollback()

    def prepare(self, *, credential, request):
        self._scope(request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("Life content result delivery already active")
            self._inflight_deliveries[request.read_attempt_id] = None
        try:
            fences = self._fences
            fences.core._require(credential, "read", request.authority_namespace, self._holder)
            anchor = fences.current_anchor(credential=credential, subject=self._read_subject)
            if anchor.authority_id != request.authority_id:
                raise AuthorityUnavailable("Life content result Authority identity differs")
            intent, terminal, _ = self._read_original(request, anchor, content=False)
            permit = fences.begin_fence(credential=credential, subject=self._read_subject, holder=self._holder,
                operation="read", operation_id=request.read_attempt_id, expected_anchor=anchor)
            with self._delivery_lock:
                self._inflight_deliveries[request.read_attempt_id] = permit
            location = self._location.observe_business_for_fence_v1(credential=credential, subject=self._read_subject, permit=permit)
            before = self._graph_read(request, intent, terminal, location)
            current_intent, current_terminal, observation = self._read_original(request, anchor, content=True)
            from ..runtime.model_cost_settlement import OriginalModelCostFactV1
            with fences._frozen() as (core_db,deletion,execution,_):
                if fences._current_locked(core_db,deletion,execution)!=anchor:
                    raise AuthorityUnavailable('Life terminal cost observation anchor changed')
                self._terminal_locked(core_db,request,anchor,content=False)
                record=self._store._read(core_db,intent.call_id)
                admission,_,receipt=self._store.read_admission_locked(core_db,intent)
                fact=OriginalModelCostFactV1(intent,record,admission,receipt)
            if current_intent != intent or current_terminal != terminal or self._graph_read(request, intent, terminal, location,fact) != before:
                raise AuthorityUnavailable("Life content current Source or exact terminal changed during delivery")
            result = InternalLifeModelResultReadV2(request,observation,terminal,float(self._clock()),
                before[0].current_scope_digest)
            from datetime import datetime
            current=before[0]
            quote=self._issuer.resource_issuer.original_signed_quote
            with closing(sqlite3.connect(self._path.as_uri()+'?mode=ro',uri=True)) as db:
                db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                try:
                    q=quote(db,current.prepared.quote_id,current.prepared.quote_version)
                    parent=self._issuer.current_budget_grant(db,q.parent_budget_lease_ref)
                    budget_until=min(q.valid_until_utc,parent.valid_until_utc)
                finally:db.rollback()
            if result.read_at_utc>=min(budget_until,current.frozen.input.expires_at_utc,current.binding.deadline_utc,
                    current.request.envelope.deadline_utc,
                    datetime.fromisoformat(current.job.deadline_utc.replace('Z','+00:00')).timestamp(),
                    datetime.fromisoformat(current.job.lease_expires_utc.replace('Z','+00:00')).timestamp()):
                raise AuthorityUnavailable('Life result original deadline expired before body delivery')
            result.require_original(intent,before[0].prepared,before[0].frozen,before[0].binding)
            with fences.core._tx() as db:
                self._location.require_current_in_tx_v1(db, location)
            fences.validate_fence(credential=credential, subject=self._read_subject, permit=permit)
            return InternalLifeModelDeliveryV2(result, permit)
        except BaseException:
            with self._delivery_lock:
                self._inflight_deliveries.pop(request.read_attempt_id, None)
            self.recover_finish(credential=credential, request=request)
            raise

    def _finish(self, credential, read_attempt_id, permit):
        basis = {"read_attempt_id": read_attempt_id, "permit": asdict(permit)}
        self._fences.finish_fence(credential=credential, subject=self._read_subject, permit=permit,
            request_id="life-content-result-finish:" + canonical_digest(basis),
            request_digest="sha256:" + canonical_digest({"action": "finish_internal_life_result_read_v2", **basis}))

    def finish_delivery(self, *, credential, delivery):
        if type(delivery) is not InternalLifeModelDeliveryV2:
            raise AuthorityUnavailable("actual Life content delivery required")
        key = delivery.result.request.read_attempt_id
        with self._delivery_lock:
            if self._inflight_deliveries.get(key) != delivery.permit:
                raise AuthorityUnavailable("Life content result delivery is not active")
            try:
                self._finish(credential, key, delivery.permit)
            finally:
                self._inflight_deliveries.pop(key, None)

    def abandon_delivery(self, *, delivery):
        if type(delivery) is not InternalLifeModelDeliveryV2:
            raise AuthorityUnavailable("actual Life content delivery required")
        with self._delivery_lock:
            self._inflight_deliveries.pop(delivery.result.request.read_attempt_id, None)

    def recover_finish(self, *, credential, request):
        self._scope(request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:
                raise AuthorityUnavailable("Life content result delivery is still active")
        self._fences.core._require(credential, "read", request.authority_namespace, self._holder)
        with self._fences.core._tx() as db:
            if self._fences.fences._row(db, request.read_attempt_id) is None:
                return
        permit, state = self._fences.get_fence_operation(credential=credential, subject=self._read_subject, operation_id=request.read_attempt_id)
        if (state not in {"active", "finished"} or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.subject, permit.holder) !=
                    (request.authority_id, request.authority_namespace, self._read_subject, self._holder)):
            raise AuthorityUnavailable("Life content original delivery fence differs")
        self._finish(credential, request.read_attempt_id, permit)
