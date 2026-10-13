"""Installed finite source-note work: actual claim, staging, measurement and originals."""
import json
from decimal import localcontext
import os
from pathlib import Path
import sqlite3
import threading
import time

from .contract import AuthorityUnavailable
from .c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
from .d11_bounded_execution_lifecycle_v1 import InstalledD11BoundedExecutionLifecycleV1
from .v2_execution_bridge import AuthorityV2ExecutionBridge
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .d11_life_journal_v1 import read_life_rows_locked_v1, append_life_entry_locked_v1, decode_life_row_v1
from ..runtime.d11_life_contract_v1 import (D11LifeExecutionBindingV1, RoleSegmentStartV1, LifeTerminalPayloadV1,
    life_mutation_id_v1, WORK_KIND)
from ..runtime.d11_life_contract_v1 import (LIFE_BINDING_TYPES, LIFE_START_TYPES, D11DraftExecutionBindingV1,
    DraftRoleSegmentStartV1, DraftTerminalPayloadV1)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime.d11_offline_originals_v1 import _utc


class AuthorityD11LifeServiceV1(InstalledD11BoundedExecutionLifecycleV1):
    _read_execution_rows = staticmethod(read_life_rows_locked_v1)
    _append_execution_row = staticmethod(append_life_entry_locked_v1)
    _execution_mutation_id = staticmethod(life_mutation_id_v1)
    _claim_payload_type = RoleSegmentStartV1
    _event_prefix = "d11_life_"
    _first_claim_action = "first_d11_life_claim"

    def __init__(self, *, bridge, owner_tickets, namespace, installation_id, manifest_digest, graph_db_path,
            issuer, resource_issuer, credential, signing_key, trusted_now_utc, owner_service, package_root, body_quote_authority,
            current_source_location=None, draft_inventory_manifest=None,draft_self_identity=None,
            owner_stop_reply_service=None, installed_bundle=None, draft_self_read_credential=None):
        from ..graph_coordinator import namespace_ref
        from ..runtime.issuers import D11BudgetJobIssuer, D02ResourceIssuer
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        if (type(bridge) is not AuthorityV2ExecutionBridge or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or owner_tickets._core is not bridge.core or type(namespace) is not NamespaceId
                or namespace_ref(namespace) != bridge.namespace or type(issuer) is not D11BudgetJobIssuer
                or type(resource_issuer) is not D02ResourceIssuer or type(signing_key) is not bytes or len(signing_key) != 32
                or not callable(trusted_now_utc) or type(owner_service) not in {
                    InstalledD12OwnerStorageAdmissionServiceV1, InstalledD12TargetOwnerAdmissionServiceV1}
                or owner_service.core is not bridge.core or owner_service.installation_id != installation_id):
            raise AuthorityUnavailable("Life requires actual paired installed authorities")
        graph = Path(graph_db_path).resolve(strict=True)
        fences = owner_service.fences
        if (fences.core is not bridge.core or fences.fences is not bridge.fences
                or fences.deletion is not bridge.deletion or fences.execution is not bridge.journal
                or fences.namespace != bridge.namespace or owner_service.graph_path != graph):
            raise AuthorityUnavailable("Life crossed actual installed handles")
        identity = read_process_identity_v1(os.getpid())
        if identity is None:
            raise AuthorityUnavailable("Life actual executor OS birth unavailable")
        self.build = read_installed_d11_life_build_v1(package_root, manifest_digest)
        self.package_root = Path(package_root).resolve(strict=True)
        self.bridge, self.fences, self.owner_tickets = bridge, fences, owner_tickets
        self.namespace, self.installation_id, self.manifest_digest = namespace, installation_id, manifest_digest
        self.graph_path, self.issuer, self.resource_issuer = graph, issuer, resource_issuer
        self.credential, self._key, self._clock = credential, signing_key, trusted_now_utc
        self.owner_service, self.body_authority = owner_service, body_quote_authority
        self._executor, self._subject = canonical_serialize(identity), "d11-life:" + installation_id
        self._execution_lock = threading.RLock()
        self._claim_clock = None
        from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
        if current_source_location is not None and (type(current_source_location) is not InstalledCurrentSourceLocationQualifierV1
                or current_source_location.core is not bridge.core or current_source_location._fences is not fences
                or current_source_location.namespace_id != namespace or current_source_location.installation_id != installation_id
                or current_source_location._graph_db_path != graph):
            raise AuthorityUnavailable("draft current Source qualifier crossed actual installation")
        if draft_inventory_manifest is not None and (type(draft_inventory_manifest) is not InstallationFilesystemManifestV2
                or draft_inventory_manifest.installation_id != installation_id
                or draft_inventory_manifest.namespace != bridge.namespace):
            raise AuthorityUnavailable("draft filesystem inventory crossed actual installation")
        self.current_source_location = current_source_location
        self.draft_inventory_manifest = draft_inventory_manifest
        if installed_bundle is not None:
            from ..host.authority_profile import AdminInstallationBundle
            if (type(installed_bundle) is not AdminInstallationBundle
                    or installed_bundle.installation_policy.namespace != namespace
                    or installed_bundle.installation_policy.installation_id != installation_id
                    or installed_bundle.installation_policy.manifest_digest != manifest_digest):
                raise AuthorityUnavailable("draft installed policy crossed actual installation")
        self.installed_bundle = installed_bundle
        self.draft_self_identity=None
        self.draft_self_read_credential=None
        if draft_self_identity is not None:
            self.install_draft_self_identity_service_v1(draft_self_identity,read_credential=draft_self_read_credential)
        elif draft_self_read_credential is not None:
            raise AuthorityUnavailable("draft Self read credential requires its actual installed Self service")
        self._owner_stop_reply_service_v1 = None
        self._draft_reply_scopes = {}
        if owner_stop_reply_service is not None:
            self.install_owner_stop_reply_service_v1(owner_stop_reply_service)
        self._draft_locations = {}
        self._draft_claim_binding = None
        self.draft_read_attempts = None
        if draft_inventory_manifest is not None:
            from .v2_worker_model_result_attempts import AuthorityV2WorkerModelResultAttempts
            self.draft_read_attempts = AuthorityV2WorkerModelResultAttempts(bridge.core._db, create=False, lock=bridge.core._lock)

    def observe_owner_artifact_for_fence_v1(self, **request):
        from .d12_owner_artifact_read_v1 import observe_owner_artifact_for_fence_v1
        return observe_owner_artifact_for_fence_v1(self, **request)

    def install_draft_self_identity_service_v1(self,service,*,read_credential):
        from .v2_self_identity_service import AuthorityV2SelfIdentityService
        if (type(service) is not AuthorityV2SelfIdentityService or service._core is not self.bridge.core
                or service._fences is not self.fences or service._namespace_id!=self.namespace
                or service._installation_id!=self.installation_id or service._manifest_digest!=self.manifest_digest
                or service._source_location is not self.current_source_location or service._graph._path!=self.graph_path
                or self.draft_self_identity is not None or read_credential is None):
            raise AuthorityUnavailable("draft self identity must be the real shared installed service with an explicit read credential")
        self.bridge.core._require(read_credential,"self_identity_read",self.bridge.namespace,service._holder)
        self.draft_self_identity=service
        self.draft_self_read_credential=read_credential

    def install_owner_stop_reply_service_v1(self, service):
        from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1
        if (type(service) is not InstalledOwnerStopReplyServiceV1
                or service.core is not self.bridge.core or service.issuer is not self.issuer
                or service.namespace_id != self.namespace or service.installation_id != self.installation_id
                or service.status_service._source_graphs[self.installation_id] != self.graph_path
                or self._owner_stop_reply_service_v1 is not None):
            raise AuthorityUnavailable("draft reply barrier requires the actual same installed Core/Graph service")
        self._owner_stop_reply_service_v1 = service

    def _observe_draft_reply_scope_v1(self, binding):
        from ..runtime.d11_life_preparation_v1 import _read
        from ..runtime.d11_artifact_draft_contract_v1 import DraftActivityScopeV1, draft_from_wire_v1
        service = self._owner_stop_reply_service_v1
        if service is None:
            raise AuthorityUnavailable("draft tool admission lacks its actual installed reply barrier")
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            raw = _read(db, issuer=self.issuer, namespace=self.namespace,
                kind="activity_scope", ref=binding.activity_scope_ref)
            if raw is None or canonical_digest(raw[0]) != binding.activity_scope_digest:
                raise AuthorityUnavailable("draft reply scope lacks its exact signed activity original")
            scope = draft_from_wire_v1(raw[0], DraftActivityScopeV1)
            if (scope.activity_id, scope.root_registration_ref, scope.root_registration_digest) != (
                    binding.activity_id, binding.root_registration_ref, binding.root_registration_digest):
                raise AuthorityUnavailable("draft reply activity original crossed its actual binding")
        finally:
            db.close()
        return service.observe_actual_reply_scope_v1(c02_operation_id=scope.c02_original_ref)

    def _binding(self, binding):
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        if type(binding) not in LIFE_BINDING_TYPES:
            raise AuthorityUnavailable("closed installed Life binding required")
        current_build = read_installed_d11_life_build_v1(self.package_root, self.manifest_digest, recipe_id=binding.recipe_id)
        if (binding.namespace != self.namespace
                or binding.authority_namespace != self.bridge.namespace or binding.installation_id != self.installation_id
                or binding.manifest_digest != self.manifest_digest
                or type(binding) is D11LifeExecutionBindingV1 and current_build != self.build
                or any(getattr(binding, name) != value for name, value in current_build.items())):
            raise AuthorityUnavailable("Life selector differs from actual installed recipe/build")

    def _gate_id(self, binding, phase):
        return "d11-life-gate:" + phase + ":" + canonical_digest((binding.authority_namespace, binding.installation_id, binding.execution_id))

    def _prepared(self, binding, *, for_execution=True, permit=None):
        from ..runtime.d11_life_preparation_v1 import read_current_prepared_life_v1
        from ..runtime.d10_offline_tick_execution_v1 import _decode_json
        from ..runtime.clock import CharacterClockMapping
        if permit is None:
            with self._frozen() as (core_db, _deletion, _execution, _history):
                permit, row = self._gate(core_db, binding, "claim")
                if row[6] != "active": raise AuthorityUnavailable("Life admission lacks its real active once gate")
        inventory = self.read_d11_life_execution_inventory_v1(permit=permit,binding=binding)
        if type(binding) is D11DraftExecutionBindingV1:
            self._draft_reply_scopes[binding.execution_id] = (
                self._observe_draft_reply_scope_v1(binding),
                "tool_claim" if for_execution else "content_adoption")
        location = None
        if type(binding) is D11DraftExecutionBindingV1:
            if self.current_source_location is None or self.draft_inventory_manifest is None:
                raise AuthorityUnavailable("actual installed draft Source qualifier/filesystem inventory unavailable")
            claim, _ = self.read_d11_life_original_v1(binding)
            if claim is None:
                location = self.current_source_location.observe_d11_life_claim_for_fence_v1(
                    credential=self.credential, subject=self._subject, permit=permit,service=self,binding=binding)
            else:
                location = self.current_source_location.observe_d11_life_interval_for_fence_v1(
                    credential=self.credential, subject=self._subject, permit=permit, service=self, binding=binding)
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            prepared = read_current_prepared_life_v1(db, binding=binding, issuer=self.issuer,
                resource_issuer=self.resource_issuer, now_utc=self._now(), for_execution=for_execution)
            if location is not None:
                self.current_source_location.require_graph_snapshot_v1(db, location, graph_db_path=self.graph_path)
                from ..runtime.d11_life_preparation_v1 import _read
                from ..runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
                raw = _read(db, issuer=self.issuer, namespace=self.namespace, kind="draft_root_capability", ref=binding.root_registration_ref)
                if raw is None or canonical_digest(raw[0]) != binding.root_registration_digest:
                    raise AuthorityUnavailable("draft original installed root capability absent or changed")
                root = draft_from_wire_v1(raw[0], DraftRootCapabilityV1)
                if (root.installation_id, root.manifest_digest) != (self.installation_id, self.manifest_digest):
                    raise AuthorityUnavailable("draft signed root capability crossed actual installed build")
                if self.installed_bundle is None:
                    raise AuthorityUnavailable("draft execution lacks its actual installed tool policy")
                from ..host.authority_profile import require_installed_artifact_target_v2
                require_installed_artifact_target_v2(self.installed_bundle.artifact_draft, root, prepared.plan.target)
            from ..runtime.d04_life_before_original_v1 import require_life_d04_before_for_claim_v1
            require_life_d04_before_for_claim_v1(db, prepared=prepared, issuer=self.issuer)
            from ..runtime.d08_life_admission_v1 import InstalledLifeAdmissionReaderV1, require_current_life_action_admission_v1
            from ..runtime_contracts import FenceScope
            from ..graph_types import NamespaceEpoch
            scope = FenceScope(binding.namespace, binding.authority_namespace, binding.activation_generation,
                permit.operation, permit.operation_id, permit, permit.pinned_anchor,
                NamespaceEpoch(*binding.namespace.as_tuple, prepared.graph_epoch), prepared.graph_revision)
            admission_reader = InstalledLifeAdmissionReaderV1(issuer=self.issuer, resource_issuer=self.resource_issuer,
                body_quote_authority=self.body_authority, execution_inventory=inventory, scope=scope)
            require_current_life_action_admission_v1(db,prepared=prepared,reader=admission_reader,now_utc=self._now())
            if location is not None:
                self._draft_locations[binding.execution_id] = location
            if for_execution:
                from ..runtime.d08_project_control_v1 import require_prepared_project_control_for_new_work_v1
                require_prepared_project_control_for_new_work_v1(db, prepared=prepared)
                self._claim_clock = _decode_json(prepared.clock_mapping_json, CharacterClockMapping)
            return prepared
        finally:
            db.close()

    def _payload(self, kind, **values):
        if kind in LIFE_START_TYPES:
            mapping = self._claim_clock
            if mapping is None:
                raise AuthorityUnavailable("Life start lacks actual prepared signed role clock")
            with localcontext() as context:
                context.prec = 28
                character_at = str(mapping.character_at(values["claimed_at_utc"]))
            values.update(character_at=character_at, clock_mapping_ref=mapping.mapping_id, clock_mapping_version=mapping.version)
            if kind is DraftRoleSegmentStartV1:
                binding = self._draft_claim_binding
                location = self._draft_locations.get(binding.execution_id)
                if location is None:
                    raise AuthorityUnavailable("draft claim lacks its actual current Source qualification")
                values.update(source_qualification_digest=canonical_digest((location.core_anchor,
                    location.current_graph_metadata, binding.input_digest)), target_scope_digest=binding.target_scope_digest)
        return super()._payload(kind, **values)

    @staticmethod
    def _prepared_anchor_common_v1(prepared, anchor):
        return InstalledD11BoundedExecutionLifecycleV1._prepared_anchor(prepared, anchor)

    def _owner_current(self, db, binding, prepared, observed):
        super()._owner_current(db, binding, prepared, observed)
        if type(binding) is D11DraftExecutionBindingV1:
            self.require_current_draft_source_in_tx_v1(db, binding)
            from .owner_stop_reply_v1 import require_reply_scope_not_stopped_in_tx_v1
            observation = self._draft_reply_scopes.get(binding.execution_id)
            if observation is None:
                raise AuthorityUnavailable("draft once claim lacks its actual reply scope observation")
            require_reply_scope_not_stopped_in_tx_v1(db,
                authority_namespace=self.bridge.namespace, installation_id=self.installation_id,
                activation_generation=binding.activation_generation,
                actual_cycle_identity=observation[0], action=observation[1])

    def require_current_draft_source_in_tx_v1(self, db, binding):
        if type(binding) is not D11DraftExecutionBindingV1 or self.current_source_location is None:
            raise AuthorityUnavailable("actual draft Source authority required")
        location = self._draft_locations.get(binding.execution_id)
        if location is None:
            raise AuthorityUnavailable("draft current Source qualification absent")
        return self.current_source_location.require_current_in_tx_v1(db, location)

    def _claim(self, binding):
        if type(binding) is D11DraftExecutionBindingV1:
            self._draft_reply_scopes[binding.execution_id] = (self._observe_draft_reply_scope_v1(binding), "tool_claim")
            self._draft_claim_binding = binding
            self._claim_payload_type = DraftRoleSegmentStartV1
            try:
                return super()._claim(binding)
            finally:
                self._draft_claim_binding = None
                self._claim_payload_type = RoleSegmentStartV1
        return super()._claim(binding)

    def verify_life_journal_row_v1(self, journal, row):
        from .v2_execution_journal import AuthorityV2ExecutionJournal
        if type(journal) is not AuthorityV2ExecutionJournal or journal.namespace != self.bridge.namespace:
            raise AuthorityUnavailable("Life originals require actual paired journal")
        binding, claim, terminal = decode_life_row_v1(journal, row)
        with self.bridge.core._lock:
            authority_id = self.bridge.core._id(self.bridge.core._db)
        if (binding.namespace != self.namespace or binding.authority_namespace != self.bridge.namespace
                or binding.authority_id != authority_id or binding.installation_id != self.installation_id):
            raise AuthorityUnavailable("Life signed original crossed actual authority")
        self._verify_payload(claim)
        if terminal is not None:
            self._verify_payload(terminal)
        return binding, claim, terminal

    def read_d11_life_execution_inventory_v1(self, *, permit, binding=None):
        from .d11_life_execution_inventory_v1 import read_life_execution_inventory_v1
        return read_life_execution_inventory_v1(self, permit=permit, binding=binding)

    def read_d11_life_original_v1(self, binding):
        from .d11_life_historical_accounting_v1 import _scope
        _scope(self, binding)
        with self.bridge.deletion.freeze_writes():
            with self.bridge.journal.freeze_writes():
                _, claim, terminal, _, _ = read_life_rows_locked_v1(self.bridge.journal, binding)
                if claim is not None:
                    self._verify_payload(claim.payload)
                if terminal is not None:
                    self._verify_payload(terminal.payload)
                return claim, terminal

    def read_d11_life_accounting_prepared_v1(self, binding):
        from .d11_life_historical_accounting_v1 import _scope
        from ..runtime.d11_life_accounting_v1 import read_life_accounting_prepared_v1
        _scope(self, binding)
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            return read_life_accounting_prepared_v1(db, binding=binding, issuer=self.issuer, resource_issuer=self.resource_issuer)
        finally:
            db.close()

    def life_adoption_bridge_v1(self, binding, *, action, gate=None, outcome=None):
        from .d11_life_bridge_v1 import operate_life_adoption_bridge_v1
        return operate_life_adoption_bridge_v1(self, binding, action, gate, outcome)

    def life_historical_accounting_v1(self, binding, *, action, gate=None):
        from .d11_life_historical_accounting_v1 import operate_life_historical_accounting_v1
        return operate_life_historical_accounting_v1(self, binding, action, gate)

    def _draft_observation_selector_v1(self, binding, request):
        from .d11_life_historical_accounting_v1 import _scope
        from ..runtime.d11_artifact_draft_contract_v1 import DraftFileObservationRequestV1, DraftObservationReadRequestV1
        _scope(self, binding)
        if (type(binding) is not D11DraftExecutionBindingV1 or type(request) is not DraftFileObservationRequestV1
                or request.original_effect_id != binding.effect_id or request.original_call_id != binding.execution_call_id
                or request.original_binding_digest != binding.digest or self.draft_read_attempts is None
                or self.draft_read_attempts._db is not self.bridge.core._db):
            raise AuthorityUnavailable("draft observation needs its original effect and installed read-attempt ledger")
        return DraftObservationReadRequestV1(binding.authority_id, binding.authority_namespace,
            binding.namespace, binding.installation_id, request)

    def read_draft_observation_original_v1(self, binding, request, *, outcome=None):
        from ..runtime.d11_artifact_draft_contract_v1 import DraftObservationOutcomeV1
        selector = self._draft_observation_selector_v1(binding, request)
        with self.bridge.core._tx() as db:
            attempt = self.draft_read_attempts._read_locked(db, selector.read_attempt_id)
        if attempt is None:
            return None
        if attempt.request != selector:
            raise AuthorityUnavailable("draft observation call identity was reused")
        cpu, read_bytes = None, None
        if outcome is not None:
            if (type(outcome) is not DraftObservationOutcomeV1 or outcome.call_id != request.call_id
                    or outcome.request_digest != selector.digest or outcome.original_binding_digest != binding.digest
                    or attempt.state != "finished" or attempt.result_digest != canonical_digest(outcome)):
                raise AuthorityUnavailable("caller receipt differs from actual durable observation digest")
            self._verify_payload(outcome)
            cpu, read_bytes = outcome.actual_cpu_ms, outcome.actual_read_bytes
        # A digest is not a durable body or an exact recoverable measurement.
        # Caller-held signed measurements can qualify costs; no file body or
        # matched-identity claim is echoed after access may have changed.
        return self._payload(DraftObservationOutcomeV1, call_id=request.call_id,
            original_effect_id=binding.effect_id, original_binding_digest=binding.digest,
            request_digest=selector.digest, status="unknown", actual_cpu_ms=cpu,
            actual_read_bytes=read_bytes, matched_original_identity=None, observed_at_utc=self._utc_text(self._now()))

    def observe_artifact_draft_v1(self, binding, request):
        from ..runtime.d11_artifact_draft_contract_v1 import (DraftObservationAdmissionV1,
            DraftObservationOutcomeV1, DraftRootCapabilityV1, draft_from_wire_v1)
        from ..runtime.d11_life_preparation_v1 import _read, read_prepared_life_v1
        from ..runtime.d08_life_admission_v1 import rebuild_life_admission_frame_v1
        from ..runtime.d01_production_operations_v1 import CurrentDomainReadV1
        from ..runtime.budget import require_budget_family_admissible
        from .d11_artifact_draft_executor_v1 import _pinned_root, _readback
        selector = self._draft_observation_selector_v1(binding, request)
        self.bridge.core._require(self.credential, "execution", self.bridge.namespace)
        with self._execution_lock:
            prior = self.read_draft_observation_original_v1(binding, request)
            if prior is not None:
                return prior
            if self.current_source_location is None:
                raise AuthorityUnavailable("draft observation current Source qualifier unavailable")
            with self._frozen() as (core_db, deletion, execution, _):
                anchor, _ = self._current(core_db, deletion, execution)
                row = self.bridge.fences._row(core_db, request.current_read_permit_ref)
                if row is None or row[6] != "active":
                    raise AuthorityUnavailable("draft observation current independent read fence absent")
                permit = self.bridge.fences._permit(row)
                if (permit.operation != "read" or canonical_digest(permit) != request.current_read_permit_digest
                        or permit.subject != self._subject):
                    raise AuthorityUnavailable("draft observation read fence scope/digest differs")
                self.bridge.fences.validate_fence_locked(core_db, permit, subject=self._subject, current_anchor=anchor)
            location = self.current_source_location.observe_d11_draft_observation_for_fence_v1(
                credential=self.credential, subject=self._subject, permit=permit,service=self,binding=binding,request=request)
            db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
            try:
                db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
                self.current_source_location.require_graph_snapshot_v1(db, location)
                raw = _read(db, issuer=self.issuer, namespace=self.namespace,
                    kind="draft_observation_admission", ref=request.admission_original_ref)
                if raw is None or canonical_digest(raw[0]) != request.admission_original_digest:
                    raise AuthorityUnavailable("actual signed independently reserved draft observation admission absent")
                admission = draft_from_wire_v1(raw[0], DraftObservationAdmissionV1)
                parameters = dict(plain_v1(request));parameters.pop("admission_original_digest")
                if admission.request_parameters_json != canonical_serialize(parameters):
                    raise AuthorityUnavailable("draft observation frozen parameters changed")
                prepared = read_prepared_life_v1(db, binding=binding, issuer=self.issuer)
                claim, terminal = self.read_d11_life_original_v1(binding)
                if prepared is None or terminal is None or terminal.original_ref != admission.original_terminal_ref:
                    raise AuthorityUnavailable("draft observation actual original terminal/preparation unavailable")
                if canonical_digest(terminal) != admission.original_terminal_digest:
                    raise AuthorityUnavailable("draft observation original terminal digest changed")
                if (prepared.plan.observation_valid_until_utc is None
                        or _utc(request.observation_valid_until_utc) > _utc(prepared.plan.observation_valid_until_utc)):
                    raise AuthorityUnavailable("original execution did not authorize this observation window")
                frame = rebuild_life_admission_frame_v1(db, prepared=prepared,
                    template_json=admission.frame_template_json, now_utc=self._now())
                read = CurrentDomainReadV1(frame);read.check(db)
                read.source_family(db, admission.source_refs)
                intent = read.head(db, request.observation_intent_ref, required=True)
                from ..runtime.d08_life_admission_v1 import _adopted
                _adopted(db, read, intent)
                from ..domains.d08.execution import _decode_intent
                action = _decode_intent(intent.value)
                if (action.action_kind != "artifact_draft_verify_v1" or action.identity.effect_id != binding.effect_id
                        or action.parameters_digest != canonical_digest(parameters)
                        or action.schema_id != "d11.artifact-draft-observation.action.v1"
                        or action.purpose != frame.envelope.authority.purpose
                        or tuple(action.source_refs) != admission.source_refs):
                    raise AuthorityUnavailable("draft observation has no exact adopted readonly ActionIntent")
                quote = self.resource_issuer.original_signed_quote(db, admission.quote_id, admission.quote_version)
                ceiling = {"thread_cpu_ms": request.cpu_ceiling_ms, "read_bytes": request.read_bytes_ceiling}
                if (canonical_digest(quote) != admission.quote_digest or quote.ceiling != ceiling
                        or quote.parent_budget_lease_ref != request.parent_budget_lease_ref
                        or quote.work_kind != "d11.life.artifact_observation.v1" or quote.effect_id != binding.effect_id
                        or quote.activity_id != action.identity.activity_id
                        or quote.operation_id != raw[1]):
                    raise AuthorityUnavailable("draft observation actual signed finite quote differs")
                grant = self.issuer.current_budget_grant(db, request.parent_budget_lease_ref)
                require_budget_family_admissible(db, request.parent_budget_lease_ref)
                reservation = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (request.parent_budget_lease_ref, request.reservation_ref)).fetchone()
                if (reservation != (request.reservation_digest, canonical_serialize(ceiling), "reserved", None)
                        or quote.work_kind not in grant.allowed_work_kinds
                        or any(amount > grant.max_ceiling.get(name, 0) for name, amount in ceiling.items())):
                    raise AuthorityUnavailable("draft observation needs its own actual reserved parent quota")
                deadline = min(_utc(request.original_deadline_utc).timestamp(),
                    _utc(request.observation_valid_until_utc).timestamp(), grant.valid_until_utc,
                    quote.valid_until_utc, frame.envelope.deadline_utc)
                if self._now() >= deadline or _utc(request.original_deadline_utc).timestamp() > grant.valid_until_utc:
                    raise AuthorityUnavailable("draft observation original applicable deadline expired or changed")
                root_row = _read(db, issuer=self.issuer, namespace=self.namespace,
                    kind="draft_root_capability", ref=admission.root_registration_ref)
                if root_row is None or canonical_digest(root_row[0]) != admission.root_registration_digest:
                    raise AuthorityUnavailable("draft observation current root capability absent")
                root_cap = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
                if (prepared.plan.target.filename not in root_cap.filenames or self._now() >= _utc(root_cap.valid_until_utc).timestamp()
                        or root_cap.resource_id != prepared.plan.target.root_resource_id
                        or root_cap.root_identity != prepared.plan.target.root_identity
                        or (root_cap.installation_id, root_cap.manifest_digest) != (self.installation_id, self.manifest_digest)
                        or root_cap.source_ref not in admission.source_refs
                        or (root_cap.owner_grant_ref, root_cap.owner_grant_revision, root_cap.owner_grant_digest) !=
                           (frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest)
                        or self.draft_inventory_manifest.manifest_digest != location.context.manifest["inventory_manifest_digest"]
                        or request.read_bytes_ceiling > root_cap.max_bytes):
                    raise AuthorityUnavailable("draft observation is outside its current finite filename/root scope")
            finally:
                db.close()
            with self._frozen() as (core_db, deletion, execution, _):
                self.current_source_location.require_current_in_tx_v1(core_db, location)
                old = self.draft_read_attempts._read_locked(core_db, selector.read_attempt_id)
                if old is not None:
                    if old.request != selector:raise AuthorityUnavailable("draft observation call identity conflict")
                    return self._payload(DraftObservationOutcomeV1, call_id=request.call_id,
                        original_effect_id=binding.effect_id, original_binding_digest=binding.digest,
                        request_digest=selector.digest,status="unknown",actual_cpu_ms=None,actual_read_bytes=None,
                        matched_original_identity=None,observed_at_utc=self._utc_text(self._now()))
                self.draft_read_attempts.begin_locked(core_db, selector, permit=permit)
            start, meter, matched = time.thread_time_ns(), [0], None
            try:
                resources = tuple(resource for resource in self.draft_inventory_manifest.resources if resource.resource_id == root_cap.resource_id)
                if len(resources) != 1 or resources[0].kind != "export":
                    raise AuthorityUnavailable("draft observation original registered carrier unavailable")
                if terminal.payload.readback is not None and prepared.plan.content.content_length <= request.read_bytes_ceiling:
                    with _pinned_root(resources[0].path, root_cap.root_identity) as (root, directory_fd):
                        _readback(root / prepared.plan.target.filename, expected_length=prepared.plan.content.content_length,
                            expected_digest=prepared.plan.content.content_digest,
                            expected_identity=terminal.payload.readback.file_identity, directory_fd=directory_fd, read_meter=meter)
                    matched = True
            except AuthorityUnavailable:
                # Missing or foreign identity cannot close the old UNKNOWN.
                matched = None
            cpu = (time.thread_time_ns() - start + 999999) // 1000000
            if self._now() >= deadline or cpu > request.cpu_ceiling_ms:
                matched = None
            result = self._payload(DraftObservationOutcomeV1, call_id=request.call_id,
                original_effect_id=binding.effect_id,original_binding_digest=binding.digest,request_digest=selector.digest,
                status="verified" if matched else "unknown",actual_cpu_ms=cpu,actual_read_bytes=meter[0],
                matched_original_identity=matched,observed_at_utc=self._utc_text(self._now()))
            with self._frozen() as (core_db, deletion, execution, _):
                self.current_source_location.require_current_in_tx_v1(core_db, location)
                self.draft_read_attempts.finish_locked(core_db, selector, permit=permit, result_digest=canonical_digest(result))
                self.bridge.fences.finish_fence_locked(core_db, permit, subject=self._subject, current_anchor=permit.pinned_anchor,
                    request_id=request.call_id + ":observed", request_digest="sha256:" + canonical_digest(result))
            return result

    def recover_claimed_d11_life_v1(self, binding):
        with self._execution_lock:
            claim, terminal = self.read_d11_life_original_v1(binding)
            if claim is None:
                raise AuthorityUnavailable("Life closed recovery requires actual consumed claim")
            continuation = self._recover_committed_append(binding)
            if terminal is None:
                identity = json.loads(claim.payload.executor_incarnation)
                if canonical_serialize(identity) != claim.payload.executor_incarnation:
                    raise AuthorityUnavailable("Life executor identity bytes differ")
                try:
                    require_process_retired_v1(identity)
                except AuthorityUnavailable:
                    return claim, None
                kind = DraftTerminalPayloadV1 if type(binding) is D11DraftExecutionBindingV1 else LifeTerminalPayloadV1
                extra = {"handoff_started": None, "readback": None} if kind is DraftTerminalPayloadV1 else {}
                payload = self._payload(kind, binding_digest=binding.digest,
                    prepared_digest=claim.payload.prepared_digest, execution_id=binding.execution_id,
                    claim_sequence=claim.claim_sequence, claim_digest=claim.claim_digest, status="unknown",
                    actual_cpu_ms=None, artifact_ref=None, artifact_digest=None, artifact_length=None,
                    reason_code="executor_quiesced_measurement_lost", completed_at_utc=self._utc_text(self._now()),
                    character_at=None, postcondition_build_digest=binding.postcondition_build_digest, **extra)
                self._terminal(binding, claim, continuation, payload)
            return self.read_d11_life_original_v1(binding)

    def execute_d11_life_v1(self, binding):
        if type(binding) is D11DraftExecutionBindingV1:
            return self._execute_artifact_draft_v1(binding)
        self._binding(binding)
        self.bridge.core._require(self.credential, "execution", self.bridge.namespace)
        with self._execution_lock:
            claim, terminal = self.read_d11_life_original_v1(binding)
            if claim is not None:
                return self.recover_claimed_d11_life_v1(binding)
            try:
                prepared, claim, continuation = self._claim(binding)
            except BaseException:
                self._close_unclaimed_gate(binding)
                raise
            from ..runtime.d11_life_source_note_v1 import generate_source_note_bytes_v1, write_life_artifact_stage_v1, verify_durable_life_artifact_v1
            start = time.thread_time_ns()
            reason, digest, length = None, None, None
            phase = "computation_failed"
            try:
                data = generate_source_note_bytes_v1(prepared)
                phase = "artifact_stage_failed"
                db = sqlite3.connect(self.graph_path, isolation_level=None)
                try:
                    db.execute("BEGIN IMMEDIATE")
                    write_life_artifact_stage_v1(db, prepared, data)
                    db.execute("COMMIT")
                    phase = "postcondition_failed"
                    db.execute("PRAGMA query_only=ON")
                    db.execute("BEGIN")
                    _, digest, length = verify_durable_life_artifact_v1(db, prepared)
                    db.execute("COMMIT")
                finally:
                    db.close()
            except Exception:
                reason = phase
            finally:
                cpu = (time.thread_time_ns() - start + 999999) // 1000000
            end = self._utc_text(self._now())
            if _utc(end) < _utc(claim.payload.claimed_at_utc):
                reason = "clock_sample_inconsistent"
            elif cpu > binding.cpu_ceiling_ms:
                reason = "cpu_ceiling_exceeded"
            elif _utc(end) >= _utc(binding.deadline_utc):
                reason = "deadline_expired"
            elif _utc(end) >= _utc(binding.job_lease_expires_utc):
                reason = "job_lease_expired"
            mapping = self._claim_clock
            character_at = None
            if _utc(mapping.valid_from_utc) <= _utc(end) <= _utc(mapping.valid_until_utc):
                with localcontext() as context:
                    context.prec = 28
                    character_at = str(mapping.character_at(end))
            elif reason is None:
                reason = "deadline_expired"
            payload = self._payload(LifeTerminalPayloadV1, binding_digest=binding.digest, prepared_digest=prepared.digest,
                execution_id=binding.execution_id, claim_sequence=claim.claim_sequence, claim_digest=claim.claim_digest,
                status="completed" if reason is None else "failed", actual_cpu_ms=cpu,
                artifact_ref=binding.artifact_ref if reason is None else None,
                artifact_digest=digest if reason is None else None, artifact_length=length if reason is None else None,
                reason_code=reason, completed_at_utc=end, character_at=character_at,
                postcondition_build_digest=binding.postcondition_build_digest)
            self._terminal(binding, claim, continuation, payload)
            return self.read_d11_life_original_v1(binding)

    def _execute_artifact_draft_v1(self, binding):
        self._binding(binding)
        self.bridge.core._require(self.credential, "execution", self.bridge.namespace)
        from .d11_artifact_draft_executor_v1 import execute_claimed_artifact_draft_v1, DraftFileEffectUncertain
        from ..runtime.d08_life_admission_v1 import rebuild_life_admission_frame_v1
        from ..runtime.d11_life_preparation_v1 import _read
        with self._execution_lock:
            claim, terminal = self.read_d11_life_original_v1(binding)
            if claim is not None:
                return self.recover_claimed_d11_life_v1(binding)
            try:
                prepared, claim, continuation = self._claim(binding)
            except BaseException:
                self._close_unclaimed_gate(binding)
                raise
            handoff, witness, cpu, reason = False, None, 0, None
            started = time.thread_time_ns()
            db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
            try:
                db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
                admission = _read(db, issuer=self.issuer, namespace=self.namespace,
                    kind="action_admission", ref=prepared.admission_ref)
                if admission is None:
                    raise AuthorityUnavailable("draft signed action admission absent after original claim")
                frame = rebuild_life_admission_frame_v1(db, prepared=prepared,
                    template_json=admission[0]["frame_template_json"], now_utc=self._now())
                witness = execute_claimed_artifact_draft_v1(self, prepared=prepared, claim=claim, frame=frame,
                    content_db=db, current_read_permit=continuation, inventory_manifest=self.draft_inventory_manifest)
                handoff, cpu = True, witness.actual_cpu_ms
            except DraftFileEffectUncertain as exc:
                handoff, witness, cpu = exc.handoff_started, exc.readback, exc.actual_cpu_ms
                reason = "draft_effect_unknown" if handoff else "draft_failed_before_handoff"
            except Exception:
                cpu = (time.thread_time_ns() - started + 999999) // 1000000
                reason = "draft_failed_before_handoff"
            finally:
                db.close()
            end = self._utc_text(self._now())
            mapping = self._claim_clock
            character = None
            if _utc(mapping.valid_from_utc) <= _utc(end) <= _utc(mapping.valid_until_utc):
                with localcontext() as context:
                    context.prec = 28
                    character = str(mapping.character_at(end))
            if reason is None and character is None:
                reason = "draft_effect_unknown"
            payload = self._payload(DraftTerminalPayloadV1, binding_digest=binding.digest,
                prepared_digest=prepared.digest, execution_id=binding.execution_id,
                claim_sequence=claim.claim_sequence, claim_digest=claim.claim_digest,
                status="completed" if reason is None else "unknown" if handoff else "failed",
                actual_cpu_ms=cpu, artifact_ref=binding.artifact_ref if reason is None else None,
                artifact_digest=witness.content_digest if reason is None else None,
                artifact_length=witness.content_length if reason is None else None,
                reason_code=reason, completed_at_utc=end, character_at=character,
                postcondition_build_digest=binding.postcondition_build_digest, handoff_started=handoff, readback=witness)
            self._terminal(binding, claim, continuation, payload)
            return self.read_d11_life_original_v1(binding)
