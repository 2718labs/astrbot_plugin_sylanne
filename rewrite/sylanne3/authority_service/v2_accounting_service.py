"""Narrow post-deletion accounting fence around original model cost facts."""

from __future__ import annotations

from dataclasses import asdict

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, identifier
from .v2_accounting_contract import (
    AccountingMaintenanceGrantV1, AccountingMaintenanceRequestV1,
)
from .v2_fence_service import AuthorityV2FenceService
from .v2_model_egress_store import AuthorityV2ModelEgressStore


class AuthorityV2AccountingMaintenanceService:
    """Only an installed accounting observer may use this Authority composition.

    The original v2 admission was issued after D11 reservation verification.
    W01 must independently recheck the original reservation and signed quote
    inside its business graph transaction; Authority owns no budget truth.
    """

    def __init__(self, *, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService, subject: str, holder: str):
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (type(store) is not AuthorityV2ModelEgressStore
                or type(fences) is not AuthorityV2FenceService
                or store._db is not fences.core._db
                or store._lock is not fences.core._lock):
            raise AuthorityUnavailable("accounting requires one Authority store and lock")
        self._store, self._fences = store, fences
        self._subject, self._holder = subject, holder

    def _original_locked(self, db, request: AccountingMaintenanceRequestV1):
        intent = request.intent
        record = self._store.read_locked(db, intent)
        if record.state != "observed" or record.observation_digest is None:
            raise AuthorityUnavailable("unresolved model call retains its original fence and budget")
        if not self._store.is_fence_bound_locked(db, intent):
            raise AuthorityUnavailable("original model fence binding is absent")
        admission, report_digest, receipt = self._store.read_admission_locked(db, intent)
        row = self._fences.fences._row(db, intent.operation_id)
        if row is None:
            raise AuthorityUnavailable("original model fence is absent")
        original = self._fences.fences._permit(row)
        if (row[6] != "finished" or row[10] is not None
                or original.operation != "model_egress"
                or (original.authority_id, original.namespace, original.subject,
                    original.operation_id, original.token, original.fence_epoch,
                    original.revision, canonical_digest(asdict(original.pinned_anchor))) !=
                   (intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id, intent.fence_token, intent.fence_epoch,
                    intent.fence_revision, intent.anchor_digest)
                or receipt is None or report_digest != receipt.report_digest
                or (receipt.admission_id, receipt.call_id, receipt.request_digest,
                    receipt.observation_digest, receipt.installation_id,
                    receipt.host_incarnation) !=
                   (admission.admission_id, intent.call_id, intent.request_digest,
                    record.observation_digest, admission.installation_id,
                    admission.host_incarnation)
                or row[8:10] != (intent.call_id, receipt.finish_digest)
                or receipt.finish_digest !=
                   self._fences.fences.model_terminal_finish_digest(
                       intent, original, "completed", record.observation_digest)):
            raise AuthorityUnavailable("original admitted terminal is not complete")
        binding = "sha256:" + canonical_digest({
            "schema": request.schema, "operation_id": request.operation_id,
            "original_intent": asdict(intent),
            "admission_id": admission.admission_id,
            "reservation_digest": intent.budget_reservation_digest,
            "budget_ceiling": intent.budget_ceiling,
            "observation_digest": record.observation_digest,
            "terminal_receipt_digest": canonical_digest(asdict(receipt)),
        })
        return admission, record, receipt, binding

    def _require(self, credential: object, request: AccountingMaintenanceRequestV1) -> None:
        if (type(request) is not AccountingMaintenanceRequestV1
                or request.intent.namespace != self._fences.namespace):
            raise AuthorityUnavailable("typed accounting request for this namespace required")
        self._fences.core._require(
            credential, "accounting", self._fences.namespace, self._holder)

    def _require_closed_deletion_history(self) -> None:
        """Consult the frozen independent journal, not only Core's phase row."""
        phases = self._fences.deletion.latest_phases()
        if any(namespace == self._fences.namespace and phase != "closed"
               for (namespace, _operation), phase in phases.items()):
            raise AuthorityUnavailable("deletion pending or accepted blocks accounting")

    def begin(self, *, credential: object,
              request: AccountingMaintenanceRequestV1) -> AccountingMaintenanceGrantV1:
        self._require(credential, request)
        with self._fences._frozen() as (db, deletion_head, execution_head, _history):
            self._require_closed_deletion_history()
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor:
                raise AuthorityUnavailable("accounting current anchor changed")
            admission, record, receipt, binding = self._original_locked(db, request)
            permit = self._fences.fences.begin_fence_locked(
                db, subject=self._subject, holder=self._holder,
                operation="accounting", current_anchor=anchor,
                operation_id=request.operation_id, command_digest=binding)
            return AccountingMaintenanceGrantV1(
                permit, request.intent.call_id, admission.admission_id,
                request.intent.budget_reservation_digest,
                record.observation_digest,
                canonical_digest(asdict(receipt)))

    def validate(self, *, credential: object,
                 request: AccountingMaintenanceRequestV1,
                 grant: AccountingMaintenanceGrantV1) -> None:
        self._require(credential, request)
        if type(grant) is not AccountingMaintenanceGrantV1:
            raise AuthorityUnavailable("typed accounting grant required")
        with self._fences._frozen() as (db, deletion_head, execution_head, _history):
            self._require_closed_deletion_history()
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor:
                raise AuthorityUnavailable("accounting current anchor changed")
            admission, record, receipt, binding = self._original_locked(db, request)
            if (grant.permit.operation_id != request.operation_id
                    or grant.permit.command_digest != binding
                    or grant != AccountingMaintenanceGrantV1(
                        grant.permit, request.intent.call_id, admission.admission_id,
                        request.intent.budget_reservation_digest,
                        record.observation_digest,
                        canonical_digest(asdict(receipt)))):
                raise AuthorityUnavailable("accounting grant differs from original model")
            self._fences.fences.validate_fence_locked(
                db, grant.permit, subject=self._subject, current_anchor=anchor)

    @staticmethod
    def _finish_identity(request: AccountingMaintenanceRequestV1, permit):
        return (
            "accounting-finish:" + canonical_digest({
                "operation_id": request.operation_id, "token": permit.token}),
            "sha256:" + canonical_digest({
                "action": "finish_accounting_maintenance_v1",
                "request": asdict(request), "token": permit.token}),
        )

    def finish(self, *, credential: object,
               request: AccountingMaintenanceRequestV1,
               grant: AccountingMaintenanceGrantV1) -> None:
        self.validate(credential=credential, request=request, grant=grant)
        with self._fences._frozen() as (db, deletion_head, execution_head, _history):
            self._require_closed_deletion_history()
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor:
                raise AuthorityUnavailable("accounting current anchor changed before finish")
            _, _, _, binding = self._original_locked(db, request)
            if binding != grant.permit.command_digest:
                raise AuthorityUnavailable("original accounting binding changed before finish")
            self._fences.fences.finish_fence_locked(
                db, grant.permit, subject=self._subject, current_anchor=anchor,
                request_id=self._finish_identity(request, grant.permit)[0],
                request_digest=self._finish_identity(request, grant.permit)[1])

    def recover_finish(self, *, credential: object,
                       request: AccountingMaintenanceRequestV1) -> None:
        """A lost finish response repeats the exact original finish identity."""
        self._require(credential, request)
        permit, state, pending = self._fences.fences.get_operation(
            request.operation_id, subject=self._subject,
            namespace=self._fences.namespace)
        if (permit.operation != "accounting" or pending is not None
                or permit.pinned_anchor != request.expected_anchor):
            raise AuthorityUnavailable("accounting recovery identity differs")
        finish_id, finish_digest = self._finish_identity(request, permit)
        if state == "finished":
            with self._fences.core._tx() as db:
                row = self._fences.fences._row(db, request.operation_id)
                if row is None or row[8:10] != (finish_id, finish_digest):
                    raise AuthorityUnavailable("accounting finish recovery differs")
            return
        if state != "active":
            raise AuthorityUnavailable("accounting fence state is unavailable")
        # Rebuild the grant solely from the original Authority terminal; this
        # does not read a result body or accept a caller-supplied digest.
        with self._fences._frozen() as (db, deletion_head, execution_head, _history):
            self._require_closed_deletion_history()
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=self._holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor:
                raise AuthorityUnavailable("accounting recovery anchor changed")
            admission, record, receipt, binding = self._original_locked(db, request)
            if permit.command_digest != binding:
                raise AuthorityUnavailable("accounting recovery binding differs")
            self._fences.fences.finish_fence_locked(
                db, permit, subject=self._subject, current_anchor=anchor,
                request_id=finish_id, request_digest=finish_digest)


    def _no_dispatch_original_locked_v1(self, db, request, model_service):
        from .v2_model_egress_service import AuthorityV2ModelEgressService
        from .v2_model_egress_store import read_model_no_dispatch_witness_locked_v1
        from .v2_accounting_contract import ModelNoDispatchAccountingRequestV1
        if (type(request) is not ModelNoDispatchAccountingRequestV1
                or type(model_service) is not AuthorityV2ModelEgressService
                or model_service._store is not self._store or model_service._fences is not self._fences
                or model_service._graph_verifier is None):
            raise AuthorityUnavailable("actual same Core unsent model/accounting composition required")
        witness = read_model_no_dispatch_witness_locked_v1(self._store, db,
            request=request.witness.request, signer=model_service._graph_verifier._issuer._signer)
        if witness != request.witness:
            raise AuthorityUnavailable("no-dispatch accounting lacks its exact saved Authority witness")
        intent = request.intent
        record = self._store.read_locked(db, intent)
        row = self._fences.fences._row(db, intent.operation_id)
        if (record.state != "prepared" or record.observation_digest is not None
                or row is None or self._fences.fences._permit(row) != witness.original_permit
                or (row[6], row[8], row[9], row[10]) != ("finished", intent.call_id, witness.finish_digest, None)
                or not self._store.is_fence_bound_locked(db, intent)
                or db.execute("SELECT 1 FROM authority_model_admissions_v2 WHERE call_id=?", (intent.call_id,)).fetchone() is not None
                or db.execute("SELECT 1 FROM authority_model_egress_observation_status_v1 WHERE call_id=?", (intent.call_id,)).fetchone() is not None):
            raise AuthorityUnavailable("original model is admitted/dispatched/unknown; zero accounting denied")
        return "sha256:" + canonical_digest((request.schema, request.operation_id,
            asdict(intent), witness.digest, intent.budget_reservation_digest, intent.budget_ceiling, "zero_model_actual_only"))

    def _require_no_dispatch_accounting_v1(self, credential, request):
        from .v2_accounting_contract import ModelNoDispatchAccountingRequestV1
        if (type(request) is not ModelNoDispatchAccountingRequestV1
                or request.intent.namespace != self._fences.namespace or request.intent.subject != self._subject
                or request.witness.request.holder != self._holder):
            raise AuthorityUnavailable("original installed no-dispatch accounting subject/holder required")
        self._fences.core._require(credential, "accounting", self._fences.namespace, self._holder)

    def begin_no_dispatch_v1(self, *, credential, request, model_service):
        from .v2_accounting_contract import ModelNoDispatchAccountingGrantV1
        self._require_no_dispatch_accounting_v1(credential, request)
        with self._fences._frozen() as (db, deletion_head, execution_head, _history):
            self._require_closed_deletion_history()
            anchor = self._fences._current_locked(db, deletion_head, execution_head, holder=self._holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor: raise AuthorityUnavailable("unsent accounting anchor changed")
            binding = self._no_dispatch_original_locked_v1(db, request, model_service)
            permit = self._fences.fences.begin_fence_locked(db, subject=self._subject, holder=self._holder,
                operation="accounting", current_anchor=anchor, operation_id=request.operation_id, command_digest=binding)
            return ModelNoDispatchAccountingGrantV1(permit, request.intent.call_id,
                request.intent.budget_reservation_digest, request.witness.digest)

    def validate_no_dispatch_v1(self, *, credential, request, grant, model_service):
        from .v2_accounting_contract import ModelNoDispatchAccountingGrantV1
        self._require_no_dispatch_accounting_v1(credential, request)
        if type(grant) is not ModelNoDispatchAccountingGrantV1:
            raise AuthorityUnavailable("actual typed no-dispatch accounting grant required")
        with self._fences._frozen() as (db, deletion_head, execution_head, _history):
            self._require_closed_deletion_history()
            anchor = self._fences._current_locked(db, deletion_head, execution_head, holder=self._holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor: raise AuthorityUnavailable("unsent accounting anchor changed")
            binding = self._no_dispatch_original_locked_v1(db, request, model_service)
            if (grant != ModelNoDispatchAccountingGrantV1(grant.permit, request.intent.call_id,
                    request.intent.budget_reservation_digest, request.witness.digest)
                    or grant.permit.operation_id != request.operation_id or grant.permit.command_digest != binding):
                raise AuthorityUnavailable("unsent accounting grant differs from its actual original")
            self._fences.fences.validate_fence_locked(db, grant.permit, subject=self._subject, current_anchor=anchor)

    @staticmethod
    def _no_dispatch_finish_identity_v1(request, permit):
        return ("no-dispatch-accounting-finish:" + canonical_digest((request.operation_id, permit.token)),
            "sha256:" + canonical_digest(("finish_no_dispatch_accounting_v1", asdict(request), permit.token)))

    def finish_no_dispatch_v1(self, *, credential, request, grant, model_service):
        self.validate_no_dispatch_v1(credential=credential, request=request, grant=grant, model_service=model_service)
        with self._fences._frozen() as (db, deletion_head, execution_head, _history):
            self._require_closed_deletion_history()
            anchor = self._fences._current_locked(db, deletion_head, execution_head, holder=self._holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor: raise AuthorityUnavailable("unsent accounting finish anchor changed")
            if self._no_dispatch_original_locked_v1(db, request, model_service) != grant.permit.command_digest:
                raise AuthorityUnavailable("unsent accounting proof changed")
            identity = self._no_dispatch_finish_identity_v1(request, grant.permit)
            self._fences.fences.finish_fence_locked(db, grant.permit, subject=self._subject,
                current_anchor=anchor, request_id=identity[0], request_digest=identity[1])

    def recover_no_dispatch_finish_v1(self, *, credential, request, model_service):
        from .v2_accounting_contract import ModelNoDispatchAccountingGrantV1
        self._require_no_dispatch_accounting_v1(credential, request)
        permit, state, pending = self._fences.fences.get_operation(request.operation_id,
            subject=self._subject, namespace=self._fences.namespace)
        if permit.operation != "accounting" or pending is not None or permit.pinned_anchor != request.expected_anchor:
            raise AuthorityUnavailable("unsent accounting recovery exact identity differs")
        finish = self._no_dispatch_finish_identity_v1(request, permit)
        if state == "finished":
            with self._fences.core._tx() as db:
                self._no_dispatch_original_locked_v1(db, request, model_service)
                row = self._fences.fences._row(db, request.operation_id)
                if row is None or row[8:10] != finish: raise AuthorityUnavailable("unsent accounting finish receipt differs")
            return
        if state != "active": raise AuthorityUnavailable("unsent accounting fence recovery unavailable")
        grant = ModelNoDispatchAccountingGrantV1(permit, request.intent.call_id,
            request.intent.budget_reservation_digest, request.witness.digest)
        self.finish_no_dispatch_v1(credential=credential, request=request, grant=grant, model_service=model_service)



__all__ = ("AuthorityV2AccountingMaintenanceService",)
