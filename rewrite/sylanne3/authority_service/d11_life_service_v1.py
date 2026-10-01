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
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.d11_offline_originals_v1 import _utc


class AuthorityD11LifeServiceV1(InstalledD11BoundedExecutionLifecycleV1):
    _read_execution_rows = staticmethod(read_life_rows_locked_v1)
    _append_execution_row = staticmethod(append_life_entry_locked_v1)
    _execution_mutation_id = staticmethod(life_mutation_id_v1)
    _claim_payload_type = RoleSegmentStartV1
    _event_prefix = "d11_life_"
    _first_claim_action = "first_d11_life_claim"

    def __init__(self, *, bridge, owner_tickets, namespace, installation_id, manifest_digest, graph_db_path,
            issuer, resource_issuer, credential, signing_key, trusted_now_utc, owner_service, package_root, body_quote_authority):
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

    def _binding(self, binding):
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        current_build = read_installed_d11_life_build_v1(self.package_root, self.manifest_digest)
        if (type(binding) is not D11LifeExecutionBindingV1 or binding.namespace != self.namespace
                or binding.authority_namespace != self.bridge.namespace or binding.installation_id != self.installation_id
                or binding.manifest_digest != self.manifest_digest or current_build != self.build
                or any(getattr(binding, name) != value for name, value in self.build.items())):
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
        inventory = self.read_d11_life_execution_inventory_v1(permit=permit)
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            prepared = read_current_prepared_life_v1(db, binding=binding, issuer=self.issuer,
                resource_issuer=self.resource_issuer, now_utc=self._now(), for_execution=for_execution)
            from ..runtime.d08_life_admission_v1 import InstalledLifeAdmissionReaderV1, require_current_life_action_admission_v1
            from ..runtime_contracts import FenceScope
            from ..graph_types import NamespaceEpoch
            scope = FenceScope(binding.namespace, binding.authority_namespace, binding.activation_generation,
                permit.operation, permit.operation_id, permit, permit.pinned_anchor,
                NamespaceEpoch(*binding.namespace.as_tuple, prepared.graph_epoch), prepared.graph_revision)
            admission_reader = InstalledLifeAdmissionReaderV1(issuer=self.issuer, resource_issuer=self.resource_issuer,
                body_quote_authority=self.body_authority, execution_inventory=inventory, scope=scope)
            require_current_life_action_admission_v1(db,prepared=prepared,reader=admission_reader,now_utc=self._now())
            if for_execution:
                self._claim_clock = _decode_json(prepared.clock_mapping_json, CharacterClockMapping)
            return prepared
        finally:
            db.close()

    def _payload(self, kind, **values):
        if kind is RoleSegmentStartV1:
            mapping = self._claim_clock
            if mapping is None:
                raise AuthorityUnavailable("Life start lacks actual prepared signed role clock")
            with localcontext() as context:
                context.prec = 28
                character_at = str(mapping.character_at(values["claimed_at_utc"]))
            values.update(character_at=character_at, clock_mapping_ref=mapping.mapping_id, clock_mapping_version=mapping.version)
        return super()._payload(kind, **values)

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

    def read_d11_life_execution_inventory_v1(self, *, permit):
        from .d11_life_execution_inventory_v1 import read_life_execution_inventory_v1
        return read_life_execution_inventory_v1(self, permit=permit)

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
                payload = self._payload(LifeTerminalPayloadV1, binding_digest=binding.digest,
                    prepared_digest=claim.payload.prepared_digest, execution_id=binding.execution_id,
                    claim_sequence=claim.claim_sequence, claim_digest=claim.claim_digest, status="unknown",
                    actual_cpu_ms=None, artifact_ref=None, artifact_digest=None, artifact_length=None,
                    reason_code="executor_quiesced_measurement_lost", completed_at_utc=self._utc_text(self._now()),
                    character_at=None, postcondition_build_digest=binding.postcondition_build_digest)
                self._terminal(binding, claim, continuation, payload)
            return self.read_d11_life_original_v1(binding)

    def execute_d11_life_v1(self, binding):
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
