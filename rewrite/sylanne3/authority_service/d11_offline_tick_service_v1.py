"""Installed, once-only finite role-clock computation and independent originals.

The public selector contains no executable, time sample, result or usage. A
claim permanently consumes execution; a lost measurement stays unknown.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime, timezone
from decimal import Context, DivisionByZero, InvalidOperation, Overflow, ROUND_HALF_EVEN, localcontext
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time

from .contract import AuthorityUnavailable, JournalHead
from .c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
from .d11_offline_tick_contract_v1 import (
    D11OfflineTickBindingV1, D11OfflineTickResultV1, D11OfflineTickClaimPayloadV1,
    D11OfflineTickTerminalPayloadV1, offline_tick_mutation_id_v1,
)
from .d11_offline_tick_journal_v1 import (
    read_offline_tick_rows_locked_v1, append_offline_tick_entry_locked_v1,
    decode_offline_tick_row_v1,
)
from .independent_append_guard_v3 import independent_append_core_guard_v3
from .v2_execution_bridge import AuthorityV2ExecutionBridge
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from ..runtime.d11_offline_originals_v1 import _utc
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1


from .d11_bounded_execution_lifecycle_v1 import InstalledD11BoundedExecutionLifecycleV1


class AuthorityD11OfflineTickServiceV1(InstalledD11BoundedExecutionLifecycleV1):
    _read_execution_rows = staticmethod(read_offline_tick_rows_locked_v1)
    _append_execution_row = staticmethod(append_offline_tick_entry_locked_v1)
    _execution_mutation_id = staticmethod(offline_tick_mutation_id_v1)
    _claim_payload_type = D11OfflineTickClaimPayloadV1
    _event_prefix = "d11_offline_"
    _first_claim_action = "first_d11_offline_tick_claim"

    def __init__(self, *, bridge, owner_tickets, namespace, installation_id,
                 manifest_digest, graph_db_path, issuer, resource_issuer,
                 credential, signing_key, trusted_now_utc, owner_service):
        from ..graph_coordinator import namespace_ref
        from ..runtime.issuers import D11BudgetJobIssuer, D02ResourceIssuer
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
        if (type(bridge) is not AuthorityV2ExecutionBridge
                or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or owner_tickets._core is not bridge.core
                or type(namespace) is not NamespaceId or namespace_ref(namespace) != bridge.namespace
                or type(issuer) is not D11BudgetJobIssuer or type(resource_issuer) is not D02ResourceIssuer
                or type(signing_key) is not bytes or len(signing_key) != 32
                or not callable(trusted_now_utc)
                or type(owner_service) not in {InstalledD12OwnerStorageAdmissionServiceV1,
                                              InstalledD12TargetOwnerAdmissionServiceV1}
                or owner_service.core is not bridge.core
                or owner_service.installation_id != installation_id):
            raise AuthorityUnavailable("offline tick needs actual paired installed authorities")
        graph = Path(graph_db_path).resolve(strict=True)
        fences = owner_service.fences
        if (fences.core is not bridge.core or fences.fences is not bridge.fences
                or fences.deletion is not bridge.deletion or fences.execution is not bridge.journal
                or fences.namespace != bridge.namespace or owner_service.graph_path != graph):
            raise AuthorityUnavailable("offline tick crossed installed stores")
        if (type(manifest_digest) is not str or len(manifest_digest) != 64
                or any(c not in "0123456789abcdef" for c in manifest_digest)):
            raise AuthorityUnavailable("exact installed manifest required")
        identity = read_process_identity_v1(os.getpid())
        if identity is None:
            raise AuthorityUnavailable("actual Authority executor birth unavailable")
        self.bridge, self.fences, self.owner_tickets = bridge, fences, owner_tickets
        self.namespace, self.installation_id, self.manifest_digest = namespace, installation_id, manifest_digest
        self.graph_path, self.issuer, self.resource_issuer = graph, issuer, resource_issuer
        self.credential, self._key, self._clock = credential, signing_key, trusted_now_utc
        self.owner_service = owner_service
        self._executor = canonical_serialize(identity)
        self._subject = "d11-offline:" + installation_id
        self._execution_lock = threading.RLock()

    def _binding(self, binding):
        if (type(binding) is not D11OfflineTickBindingV1 or binding.namespace != self.namespace
                or binding.authority_namespace != self.bridge.namespace
                or binding.installation_id != self.installation_id
                or binding.manifest_digest != self.manifest_digest):
            raise AuthorityUnavailable("offline selector differs from installed identity")






    def verify_offline_tick_journal_row_v1(self, journal, row):
        """Authenticate an existing original for passive accounting only.

        This does not require restoring erased source bodies and grants no new
        claim, result adoption or current-code execution. Active entry points
        separately pin the current manifest and requalify every current input.
        """
        from .v2_execution_journal import AuthorityV2ExecutionJournal
        if type(journal) is not AuthorityV2ExecutionJournal or journal.namespace != self.bridge.namespace:
            raise AuthorityUnavailable("actual same-namespace execution journal required")
        binding, claim, terminal = decode_offline_tick_row_v1(journal, row)
        with self.bridge.core._lock:
            authority_id = self.bridge.core._id(self.bridge.core._db)
        if (binding.namespace != self.namespace or binding.authority_namespace != self.bridge.namespace
                or binding.authority_id != authority_id or binding.installation_id != self.installation_id):
            raise AuthorityUnavailable("offline historical original crossed installation authority")
        self._verify_payload(claim)
        if terminal is not None:
            self._verify_payload(terminal)
        return binding, claim, terminal

    def _gate_id(self, binding, phase):
        return "d11-offline-gate:" + phase + ":" + canonical_digest(
            (binding.authority_namespace, binding.installation_id, binding.execution_id))





    def _prepared(self, binding, *, for_execution=True):
        from ..runtime.d10_offline_tick_execution_v1 import read_current_prepared_offline_tick_v1
        if self.graph_path.resolve(strict=True) != self.graph_path:
            raise AuthorityUnavailable("offline selected Graph path changed")
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            return read_current_prepared_offline_tick_v1(db, binding=binding, issuer=self.issuer,
                resource_issuer=self.resource_issuer, now_utc=self._now(), for_execution=for_execution)
        finally:
            db.close()









    def read_d11_offline_tick_original_v1(self, binding):
        self._binding(binding)
        self.bridge.core._require(self.credential, "current", self.bridge.namespace)
        with self.bridge.deletion.freeze_writes():
            with self.bridge.journal.freeze_writes():
                _, claim, terminal, _, _ = read_offline_tick_rows_locked_v1(self.bridge.journal, binding)
                if claim is not None:
                    self._verify_payload(claim.payload)
                if terminal is not None:
                    self._verify_payload(terminal.payload)
                return claim, terminal

    def offline_adoption_bridge_v1(self, binding, *, action, gate=None, outcome=None):
        from .d11_offline_tick_bridge_v1 import operate_offline_adoption_bridge_v1
        return operate_offline_adoption_bridge_v1(self, binding, action, gate, outcome)

    def read_d11_offline_accounting_prepared_v1(self, binding):
        from .d11_offline_historical_accounting_v1 import _scope
        from ..runtime.d11_offline_accounting_v1 import read_offline_accounting_prepared_v1
        _scope(self, binding)
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            return read_offline_accounting_prepared_v1(db, binding=binding, issuer=self.issuer,
                resource_issuer=self.resource_issuer)
        finally:
            db.close()

    def offline_historical_accounting_v1(self, binding, *, action, gate=None):
        from .d11_offline_historical_accounting_v1 import operate_offline_historical_accounting_v1
        return operate_offline_historical_accounting_v1(self, binding, action, gate)

    def read_historical_d11_offline_tick_original_v1(self, binding):
        from .d11_offline_historical_accounting_v1 import _scope
        _scope(self, binding)
        with self.bridge.core._lock:
            if binding.authority_id != self.bridge.core._id(self.bridge.core._db):
                raise AuthorityUnavailable("offline historical selector crossed actual Authority")
        with self.bridge.deletion.freeze_writes():
            with self.bridge.journal.freeze_writes():
                _, claim, terminal, _, _ = read_offline_tick_rows_locked_v1(self.bridge.journal, binding)
                if claim is not None:
                    self._verify_payload(claim.payload)
                if terminal is not None:
                    self._verify_payload(terminal.payload)
                return claim, terminal

    def recover_claimed_d11_offline_tick_v1(self, binding):
        """Reconcile an existing durable claim, never enter first-claim execution."""
        from .d11_offline_historical_accounting_v1 import _scope
        _scope(self, binding)
        with self._execution_lock:
            claim, terminal = self.read_historical_d11_offline_tick_original_v1(binding)
            if claim is None:
                raise AuthorityUnavailable("offline closed recovery requires an actual prior claim")
            continuation = self._recover_committed_append(binding)
            if terminal is None:
                original_process = json.loads(claim.payload.executor_incarnation)
                if canonical_serialize(original_process) != claim.payload.executor_incarnation:
                    raise AuthorityUnavailable("offline executor original is noncanonical")
                try:
                    require_process_retired_v1(original_process)
                except AuthorityUnavailable:
                    return claim, None
                payload = self._payload(D11OfflineTickTerminalPayloadV1,
                    binding_digest=binding.digest, prepared_digest=claim.payload.prepared_digest,
                    execution_id=binding.execution_id, claim_sequence=claim.claim_sequence,
                    claim_digest=claim.claim_digest, status="unknown", actual_cpu_ms=None,
                    result=None, reason_code="executor_quiesced_measurement_lost",
                    completed_at_utc=self._utc_text(self._now()))
                self._terminal(binding, claim, continuation, payload)
            return self.read_historical_d11_offline_tick_original_v1(binding)

    def offline_unstarted_cancellation_v1(self, binding, *, action, gate=None):
        from .d11_offline_unstarted_cancellation_v1 import operate_offline_unstarted_cancellation_v1
        return operate_offline_unstarted_cancellation_v1(self, binding, action, gate)

    def execute_d11_offline_tick_v1(self, binding):
        self._binding(binding)
        self.bridge.core._require(self.credential, "execution", self.bridge.namespace)
        with self._execution_lock:
            claim, terminal = self.read_d11_offline_tick_original_v1(binding)
            if claim is not None:
                continuation = self._recover_committed_append(binding)
                if terminal is None:
                    # Neither a timeout nor another caller proves quiescence.
                    # Only the original OS birth identity being retired allows
                    # content-free unknown closure; no lost CPU is set to zero.
                    original_process = json.loads(claim.payload.executor_incarnation)
                    if canonical_serialize(original_process) != claim.payload.executor_incarnation:
                        raise AuthorityUnavailable("offline executor original is noncanonical")
                    try:
                        require_process_retired_v1(original_process)
                    except AuthorityUnavailable:
                        return claim, None
                    payload = self._payload(D11OfflineTickTerminalPayloadV1,
                        binding_digest=binding.digest, prepared_digest=claim.payload.prepared_digest,
                        execution_id=binding.execution_id, claim_sequence=claim.claim_sequence,
                        claim_digest=claim.claim_digest, status="unknown", actual_cpu_ms=None,
                        result=None, reason_code="executor_quiesced_measurement_lost",
                        completed_at_utc=self._utc_text(self._now()))
                    self._terminal(binding, claim, continuation, payload)
                return self.read_d11_offline_tick_original_v1(binding)
            try:
                prepared, claim, continuation = self._claim(binding)
            except BaseException:
                self._close_unclaimed_gate(binding)
                raise
            start = time.thread_time_ns()
            result = None
            reason = None
            try:
                from ..runtime.clock import CharacterClockMapping
                from ..runtime.d10_offline_tick_execution_v1 import _decode_json
                context = Context(prec=28, rounding=ROUND_HALF_EVEN, Emin=-999999, Emax=999999,
                    capitals=1, clamp=0, traps=[InvalidOperation, DivisionByZero, Overflow])
                with localcontext(context):
                    mapping = _decode_json(prepared.clock_mapping_json, CharacterClockMapping)
                    character_at = str(mapping.character_at(binding.scheduled_at_utc))
                    computed = self._utc_text(self._now())
                    result = D11OfflineTickResultV1(binding.scheduled_at_utc, computed,
                        mapping.mapping_id, mapping.version, character_at)
            except Exception:
                reason = "computation_failed"
            finally:
                actual_cpu = (time.thread_time_ns() - start + 999999) // 1000000
            # Completion follows computation AND result validation. Do not use
            # the earlier mapping timestamp to slip across a deadline boundary.
            completed = self._utc_text(self._now())
            if result is not None and _utc(completed) < _utc(result.computed_at_utc):
                reason = "clock_sample_inconsistent"
            if actual_cpu > binding.cpu_ceiling_ms:
                reason = "cpu_ceiling_exceeded"
            elif _utc(completed) >= _utc(binding.deadline_utc):
                reason = "deadline_expired"
            elif _utc(completed) >= _utc(binding.job_lease_expires_utc):
                reason = "job_lease_expired"
            if reason is not None:
                result = None
            payload = self._payload(D11OfflineTickTerminalPayloadV1,
                binding_digest=binding.digest, prepared_digest=prepared.digest,
                execution_id=binding.execution_id, claim_sequence=claim.claim_sequence,
                claim_digest=claim.claim_digest, status="completed" if result is not None else "failed",
                actual_cpu_ms=actual_cpu, result=result, reason_code=reason,
                completed_at_utc=completed)
            self._terminal(binding, claim, continuation, payload)
            return self.read_d11_offline_tick_original_v1(binding)


__all__ = ["AuthorityD11OfflineTickServiceV1"]
