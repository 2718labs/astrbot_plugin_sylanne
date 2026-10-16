"""Installed chunk rights and durable originals on the shared execution chain."""
from dataclasses import asdict, replace
from datetime import datetime
import hmac
import json
import sqlite3

from .contract import AuthorityUnavailable, JournalHead, identifier
from .d04_numeric_service_v3 import AuthorityD04NumericServiceV3
from .d04_series_contract_v1 import (D04SeriesChunkBindingV1, D04SeriesClaimV1,
    D04SeriesMeasurementV1, D04SeriesTerminalV1, D04SeriesGateV1, to_wire, from_wire,
    mutation_id, gate_id)
from .d04_series_journal_v1 import append_series_entry_locked_v1, read_series_rows_locked_v1
from ..runtime_contracts import canonical_digest, canonical_serialize


class AuthorityD04SeriesServiceV1:
    def __init__(self, *, numeric_service):
        if type(numeric_service) is not AuthorityD04NumericServiceV3:
            raise AuthorityUnavailable("series requires installed numeric authority composition")
        self.numeric = numeric_service
        self.bridge = numeric_service.bridge
        self.installation_id = numeric_service.installation_id
        self.graph_path = numeric_service.graph_path
        self.namespace = numeric_service.namespace
        self._subject = "d04-series:" + self.installation_id

    def _binding(self, binding):
        if type(binding) is not D04SeriesChunkBindingV1:
            raise AuthorityUnavailable("series typed binding required")
        self.numeric._binding(binding.numeric)

    def _claim(self, binding, claim):
        if (type(claim) is not D04SeriesClaimV1 or claim.binding_digest != binding.digest
                or claim.claim_id != mutation_id(binding, "claim")
                or not hmac.compare_digest(claim.signature, self.numeric._sign(claim))):
            raise AuthorityUnavailable("series signed claim differs")

    def _gate_signature(self, gate):
        if not hmac.compare_digest(gate.signature, self.numeric._sign(gate)):
            raise AuthorityUnavailable("series installed gate signature differs")

    def _content_current(self, binding, *, db=None):
        from ..runtime.d04_series_store_v1 import read_d04_series_root_v1, series_own_job_ref_v1
        from ..runtime.d04_appraisal_driver_v3 import D04GraphReadV3, require_current_read_rows_v3
        from ..graph_types import AtomKey
        owned = db is None
        if owned:
            db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            if owned:
                db.execute("BEGIN")
            root = read_d04_series_root_v1(db, self.namespace, binding.root_ref)
            if root is None or root.digest != binding.root_digest:
                raise AuthorityUnavailable("series complete frozen source original unavailable")
            frozen = json.loads(root.prepared.input_payload_json)
            if canonical_digest(frozen) != root.prepared.binding.input_digest:
                raise AuthorityUnavailable("series source original commitment differs")
            require_current_read_rows_v3(db, tuple(D04GraphReadV3(**row) for row in frozen["read_rows"]
                if row["ref"] != series_own_job_ref_v1(root)), self.namespace)
            return root
        finally:
            if owned:
                db.close()

    def _owner_observation(self,permit,binding,original_binding):
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            from .owner_location_read_v3 import prepare_owner_location_for_series_v3
            return prepare_owner_location_for_series_v3(self,permit=permit,binding=binding,original_binding=original_binding)

    def _read(self, binding, *, phase, erased_body=False):
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        from ..runtime.d04_series_store_v1 import read_d04_series_root_v1, read_d04_series_chunk_prepared_v1
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("BEGIN")
            prepared = read_d04_series_chunk_prepared_v1(db, self.namespace, binding.numeric.operation_id)
            if prepared is None and phase != "claim":
                retained = read_d04_original_v3(db, self.namespace, "series_chunk_accounting", binding.numeric.operation_id)
                prepared = None if retained is None else (from_wire(retained[0]["binding"], D04SeriesChunkBindingV1), retained[0], retained[1])
            if prepared is None or prepared[0] != binding:
                raise AuthorityUnavailable("series independently read chunk preparation differs")
            raw = prepared[1]
            quote = self.numeric.resource_issuer.original_signed_quote(db, binding.numeric.quote_id, binding.numeric.quote_version)
            if (canonical_digest(quote) != binding.numeric.quote_digest
                    or dict(quote.ceiling) != {"cpu_ms": binding.numeric.cpu_ceiling_ms}):
                raise AuthorityUnavailable("series original signed CPU quote differs")
            reserve = db.execute("SELECT receipt_json,digest FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
                "AND operation_id=? AND phase='reserve'", (*self.namespace.as_tuple, binding.numeric.reservation_operation_id)).fetchone()
            if reserve != (raw["reserve_receipt_json"], binding.numeric.reservation_digest):
                raise AuthorityUnavailable("series actual CPU reservation differs")
            metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                self.namespace.as_tuple).fetchone()
            if metadata is None:
                raise AuthorityUnavailable("series Graph recovery metadata absent")
            if phase == "claim":
                if metadata != (raw["requirements_json"], raw["graph_revision"]):
                    raise AuthorityUnavailable("another Graph mutation blocks the original series chunk claim")
                root = read_d04_series_root_v1(db, self.namespace, binding.root_ref)
                if root is None or root.digest != binding.root_digest or root.frozen.plan.digest != binding.plan_digest:
                    raise AuthorityUnavailable("series frozen root/plan differs")
                from ..runtime.d04_series_initial_original_v1 import require_d04_series_initial_original_v1
                require_d04_series_initial_original_v1(db, root)
                from ..runtime.jobs import get_job
                job = get_job(db, binding.numeric.job_id)
                now = self.numeric._clock()
                if (job.phase != "running" or asdict(job) != raw["job"] or job.cancel_epoch
                        or now >= datetime.fromisoformat(binding.numeric.deadline_utc.replace("Z", "+00:00")).timestamp()
                        or now >= datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp()):
                    raise AuthorityUnavailable("series original worker/deadline changed")
                if binding.start_step_index:
                    paid = read_d04_original_v3(db, self.namespace, "series_chunk_cost", binding.predecessor_ref)
                    if (paid is None or paid[0]["math_digest"] != binding.predecessor_digest
                            or paid[0]["status"] != "chunk_completed" or paid[0]["authority_ack"] is not True):
                        raise AuthorityUnavailable("series predecessor terminal/accounting ACK absent")
                # Source rows are immutable premises, while own cost/job writes
                # may advance the Graph. No other business mutation is qualified.
                from ..runtime.d04_numeric_artifact_v3 import decode_d04_numeric_prepared_input_v3
                from ..runtime.d04_appraisal_driver_v3 import require_current_read_rows_v3
                from ..graph_types import AtomKey
                original = decode_d04_numeric_prepared_input_v3(root.prepared)
                from ..runtime.d04_series_store_v1 import series_own_job_ref_v1
                require_current_read_rows_v3(db, tuple(row for row in original.evidence_inputs.read_rows
                    if row.ref != series_own_job_ref_v1(root)), self.namespace)
            elif phase == "terminal":
                measured = read_d04_original_v3(db, self.namespace, "series_chunk_measurement", binding.numeric.operation_id)
                if measured is None:
                    raise AuthorityUnavailable("series actual installed measurement absent")
                measurement = from_wire(measured[0]["measurement"], D04SeriesMeasurementV1)
                claim = from_wire(measured[0]["claim"], D04SeriesClaimV1)
                self._claim(binding, claim)
                if measurement.status == "chunk_completed" and phase == "terminal":
                    math = read_d04_original_v3(db, self.namespace, "series_chunk_math", binding.numeric.operation_id)
                    if math is None and not erased_body:
                        saved = read_d04_original_v3(db, self.namespace, "series_chunk_measurement_gate", binding.numeric.operation_id)
                        gate = None if saved is None else from_wire(saved[0], D04SeriesGateV1)
                        if gate is None or gate.binding != binding or gate.retain_math:
                            raise AuthorityUnavailable("series first completed terminal requires its actual native original")
                        self._gate_signature(gate)
                    if math is not None and measured[0]["artifact_payload_digest"] != math[1]:
                        raise AuthorityUnavailable("series measured native artifact absent/changed")
                    if math is not None:
                        from ..runtime.d04_series_codec_v1 import _decode_series_chunk_for_final_verifier_v1
                        chunk = _decode_series_chunk_for_final_verifier_v1(math[0])
                        from ..runtime.d04_series_initial_original_v1 import require_d04_series_initial_original_v1
                        from ..native_runtime.d04_series_math_v1 import verify_d04_series_chunk_math_v1
                        root = read_d04_series_root_v1(db, self.namespace, binding.root_ref)
                        if root is None or root.digest != binding.root_digest:
                            raise AuthorityUnavailable("series completed terminal lost its actual initial original")
                        require_d04_series_initial_original_v1(db, root)
                        verify_d04_series_chunk_math_v1(root.frozen, chunk, root_digest=root.digest)
                        if chunk.invariant_domain is not None:
                            from ..native_runtime.d04_invariant_domain_v1 import require_installed_d04_invariant_verifier_v1
                            require_installed_d04_invariant_verifier_v1(chunk.invariant_domain, binding.numeric.native_manifest_sha256)
                        if (chunk.digest != measurement.chunk_math_digest
                                or canonical_digest(chunk.endpoints) != measurement.endpoint_digest
                                or (chunk.root_digest, chunk.plan_digest, chunk.start_step_index, chunk.end_step_index, chunk.predecessor_digest) !=
                                    (binding.root_digest, binding.plan_digest, binding.start_step_index, binding.end_step_index, binding.predecessor_digest)):
                            raise AuthorityUnavailable("series genuine measured native commitments differ")
                raw = {**raw, "measurement": measurement, "claim": claim}
            return raw, metadata
        finally:
            db.close()

    def _reconcile(self, db, binding, row, head):
        bridge = self.bridge
        current = bridge.core._head(bridge.core._row(db, bridge.namespace), "execution")
        target = JournalHead(bridge.journal.journal_id, row[0], row[6])
        before = JournalHead(bridge.journal.journal_id, row[0] - 1, row[5])
        phase = "claim" if row[1] == mutation_id(binding, "claim") else "measurement"
        stored = bridge.fences._row(db, gate_id(binding, phase))
        if stored is None:
            raise AuthorityUnavailable("series original append gate absent")
        permit = bridge.fences._permit(stored)
        if (permit.pinned_anchor.execution_seq, permit.pinned_anchor.execution_digest) != (before.seq, before.digest):
            raise AuthorityUnavailable("series append did not follow its exact gate")
        if current != head or head.seq < target.seq:
            if current != before or head != target:
                raise AuthorityUnavailable("series Core recovery requires exact next original row")
            bridge.core.require_current_storage_generation_locked(db, namespace=bridge.namespace, action="recovery")
            db.execute("UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,anchor_nonce=? WHERE namespace=?",
                (target.seq, target.digest, bridge.core._new_nonce(), bridge.namespace))
            bridge.core._event(db, bridge.namespace, "d04_series_" + phase,
                bridge.core._row(db, bridge.namespace)[1], (binding.digest, row[1], row[6]))
        bridge.fences.finish_fence_locked(db, permit, subject=permit.subject, current_anchor=permit.pinned_anchor,
            request_id=permit.operation_id + ":consumed", request_digest="sha256:" + canonical_digest((binding.digest, row[6])))

    def inspect(self, binding):
        self._binding(binding)
        self.bridge.core._require(self.numeric.credential, "current", self.bridge.namespace)
        with self.numeric._frozen() as (db, deletion, head):
            _, claim, measured, first, last = read_series_rows_locked_v1(self.bridge.journal, binding)
            if claim is None:
                self.bridge._check_execution_head_locked(db, head)
                return None, None
            self._claim(binding, claim)
            if last is None:
                self._reconcile(db, binding, first, head)
                return claim, None
            self._reconcile(db, binding, last, head)
            self._reconcile(db, binding, first, head)
            value = D04SeriesTerminalV1(binding, claim, measured, mutation_id(binding, "terminal"),
                last[0], last[6].removeprefix("sha256:"), "pending")
            return claim, replace(value, signature=self.numeric._sign(value))

    def _append(self, binding, permit, claim, measurement, metadata, *, owner=None):
        from .independent_append_guard_v3 import independent_append_core_guard_v3
        from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
        with independent_append_core_guard_v3(self.bridge) as (db, deletion):
            with self.bridge.journal.freeze_writes():
                before = self.bridge.journal.verified_head()
                anchor, holder = self.numeric._current_anchor_locked(db, deletion, before,
                    action="business" if measurement is None else "accounting")
                self.bridge.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor)
                require_lifecycle_admission_in_tx_v1(db, self.bridge.namespace,
                    action="first_d04_numeric_claim" if measurement is None else "accounting", original_claimed=measurement is not None)
                if measurement is None:
                    self.numeric._require_owner_locked(db, binding.numeric, owner)
                    if not self.numeric._graph_location_matches(json.loads(metadata[0]), anchor):
                        raise AuthorityUnavailable("series new claim Graph/Authority location differs")
                    if json.loads(metadata[0])["execution_seq"] != before.seq or json.loads(metadata[0])["execution_digest"] != before.digest:
                        raise AuthorityUnavailable("series new claim must follow prior independent accounting ACK")
                    if self.numeric._clock() >= datetime.fromisoformat(binding.numeric.deadline_utc.replace("Z", "+00:00")).timestamp():
                        raise AuthorityUnavailable("series fixed deadline expired before claim")
                row = append_series_entry_locked_v1(self.bridge.journal, binding=binding, claim=claim,
                    measurement=measurement, before_head=before)
            with self.bridge.journal.freeze_writes():
                self._reconcile(db, binding, row, self.bridge.journal.verified_head())
        return row

    def claim(self, binding, executor_incarnation):
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            self._binding(binding)
            identifier(executor_incarnation, "executor_incarnation")
            self.bridge.core._require(self.numeric.credential, "execution", self.bridge.namespace)
            old, terminal = self.inspect(binding)
            if old is not None:
                raise AuthorityUnavailable("series chunk execution already consumed; HOLD/inspect")
            with self.numeric._frozen() as (db, deletion, head):
                anchor, holder = self.numeric._current_anchor_locked(db, deletion, head)
                permit = self.bridge.fences.begin_fence_locked(db,
                    subject=self._subject + ":claim:" + canonical_digest((binding.digest, executor_incarnation)),
                    holder=holder, operation="write", current_anchor=anchor, operation_id=gate_id(binding, "claim"))
            prepared, metadata = self._read(binding, phase="claim")
            # Root's accepting Owner selectors retain their original operation.
            from ..runtime.d04_series_store_v1 import read_d04_series_root_v1
            db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True)
            try:
                root = read_d04_series_root_v1(db, self.namespace, binding.root_ref)
            finally:
                db.close()
            owner = self._owner_observation(permit, binding, root.prepared.binding)
            claim = D04SeriesClaimV1(binding.digest, binding.numeric.execution_id, mutation_id(binding, "claim"),
                head.seq + 1, self.installation_id, executor_incarnation, "pending")
            claim = replace(claim, signature=self.numeric._sign(claim))
            self._append(binding, permit, claim, None, metadata, owner=owner)
            return claim

    def gate(self, binding, phase):
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            self._binding(binding)
            claim, terminal = self.inspect(binding)
            if claim is None or phase in {"settlement", "restore"} and terminal is None:
                raise AuthorityUnavailable("series unknown execution cannot settle or resume")
            _, metadata = self._read(binding, phase="accounting")
            with self.numeric._frozen() as (db, deletion, head):
                anchor, holder = self.numeric._current_anchor_locked(db, deletion, head,
                    action="business" if phase == "restore" else "accounting")
                permit = self.bridge.fences.begin_fence_locked(db, subject=self._subject, holder=holder,
                    operation="write" if phase == "restore" else "accounting", current_anchor=anchor,
                    operation_id=gate_id(binding, phase), command_digest=(None if phase == "restore" else
                        "sha256:" + canonical_digest((binding.digest, phase))))
            retain = False
            if phase in {"measurement", "restore"}:
                try:
                    root = self._content_current(binding)
                    owner = self._owner_observation(permit, binding, root.prepared.binding)
                    with self.numeric._frozen() as (db, deletion, head):
                        anchor, _ = self.numeric._current_anchor_locked(db, deletion, head, action="accounting")
                        self.bridge.fences.validate_fence_locked(db, permit, subject=self._subject, current_anchor=anchor)
                        self.numeric._require_owner_locked(db, root.prepared.binding, owner)
                    retain = True
                except (AuthorityUnavailable, ValueError):
                    if phase == "restore":
                        with self.numeric._frozen() as (db, deletion, head):
                            anchor, _ = self.numeric._current_anchor_locked(db, deletion, head, action="accounting")
                            self.bridge.fences.finish_fence_locked(db, permit, subject=self._subject, current_anchor=anchor,
                                request_id=permit.operation_id + ":uncommitted",
                                request_digest="sha256:" + canonical_digest((binding.digest, "restore-admission-denied")))
                        raise
            gate = D04SeriesGateV1(binding, phase, permit, metadata[0], metadata[1], binding.root_digest, retain, "pending")
            return replace(gate, signature=self.numeric._sign(gate))

    def validate_gate(self, gate):
        self._binding(gate.binding)
        self._gate_signature(gate)
        with self.numeric._frozen() as (db, deletion, head):
            anchor, _ = self.numeric._current_anchor_locked(db, deletion, head,
                action="business" if gate.phase == "restore" else "accounting")
            self.bridge.fences.validate_fence_locked(db, gate.permit, subject=self._subject, current_anchor=anchor)
        return gate

    def terminal(self, binding, claim, measurement):
        self._claim(binding, claim)
        old, terminal = self.inspect(binding)
        if old != claim:
            raise AuthorityUnavailable("series terminal lacks actual signed claim")
        if terminal is not None:
            if terminal.measurement != measurement:
                raise AuthorityUnavailable("series terminal cannot change measurement")
            return terminal
        raw, metadata = self._read(binding, phase="terminal")
        if raw["measurement"] != measurement or raw["claim"] != claim:
            raise AuthorityUnavailable("series submitted measurement differs from actual Graph original")
        with self.numeric._frozen() as (db, deletion, head):
            stored = self.bridge.fences._row(db, gate_id(binding, "measurement"))
            if stored is None:
                raise AuthorityUnavailable("series technical-original gate absent")
            permit = self.bridge.fences._permit(stored)
        self._append(binding, permit, claim, measurement, metadata)
        return self.inspect(binding)[1]

    def finish(self, gate):
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        self._binding(gate.binding)
        self._gate_signature(gate)
        claim, terminal = self.inspect(gate.binding)
        if terminal is None:
            raise AuthorityUnavailable("series accounting ACK requires genuine measured terminal")
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True)
        try:
            db.execute("BEGIN")
            kind = "series_adoption" if gate.phase == "restore" else "series_chunk_cost_commit"
            ref = gate.binding.root_ref if gate.phase == "restore" else gate.binding.numeric.operation_id
            original = read_d04_original_v3(db, self.namespace, kind, ref)
            if original is None or original[0]["gate_digest"] != gate.digest:
                raise AuthorityUnavailable("series finish lacks exact committed Graph receipt")
            from ..runtime.d04_series_accounting_original_v1 import (read_series_accounting_original_v1,
                read_series_cpu_cost_original_v1)
            prepared = read_series_accounting_original_v1(db, self.namespace,
                gate.binding.numeric.operation_id, issuer=self.numeric.resource_issuer)
            cost = read_series_cpu_cost_original_v1(db, self.namespace, gate.binding, terminal)
            if prepared is None or prepared.binding != gate.binding or cost is None or cost["gate_digest"] != gate.digest:
                raise AuthorityUnavailable("series accounting ACK lacks exact signed preparation and actual CPU event")
            if gate.phase == "restore":
                from ..runtime.d04_series_original_v1 import require_series_adopted_original_v1
                verified = require_series_adopted_original_v1(db, self.namespace, original[0]["operation_id"])
                if verified is None or verified[0].digest != gate.root_digest or original[0]["terminal_digest"] != terminal.digest:
                    raise AuthorityUnavailable("series final ACK lacks complete actual prefix/adoption receipt")
        finally:
            db.close()
        with self.numeric._frozen() as (db, deletion, head):
            anchor, _ = self.numeric._current_anchor_locked(db, deletion, head, action="accounting")
            self.bridge.fences.finish_fence_locked(db, gate.permit, subject=self._subject, current_anchor=anchor,
                request_id=gate.permit.operation_id + ":finished", request_digest="sha256:" + gate.digest)
        return True

    def abandon(self, gate):
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        if gate.phase != "restore":
            raise AuthorityUnavailable("only a known uncommitted final adoption can abandon")
        self._gate_signature(gate)
        db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True)
        try:
            rejected = read_d04_original_v3(db, self.namespace, "series_adoption_rejected", gate.binding.root_ref)
            adopted = read_d04_original_v3(db, self.namespace, "series_adoption", gate.binding.root_ref)
            metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                self.namespace.as_tuple).fetchone()
            if (adopted is not None or rejected is None or rejected[0]["gate_digest"] != gate.digest
                    or metadata != (gate.before_requirements_json, gate.before_graph_revision)):
                raise AuthorityUnavailable("series final rejection is not conclusively uncommitted")
        finally:
            db.close()
        with self.numeric._frozen() as (db, deletion, head):
            anchor, _ = self.numeric._current_anchor_locked(db, deletion, head, action="accounting")
            self.bridge.fences.finish_fence_locked(db, gate.permit, subject=self._subject, current_anchor=anchor,
                request_id=gate.permit.operation_id + ":abandoned", request_digest="sha256:" + gate.digest)
        return True

    def restore_bytes(self, binding):
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
            from ..runtime.d04_series_codec_v1 import _decode_series_chunk_for_final_verifier_v1
            import secrets
            self._binding(binding)
            claim, terminal = self.inspect(binding)
            if terminal is None or terminal.measurement.status != "chunk_completed":
                raise AuthorityUnavailable("series restore requires actual completed terminal; no FFI replay")
            with self.numeric._frozen() as (db, deletion, head):
                anchor, holder = self.numeric._current_anchor_locked(db, deletion, head, action="recovery")
                source = self.bridge.fences._permit(self.bridge.fences._row(db, gate_id(binding, "claim")))
                if not self.numeric._same_location_epoch(source.pinned_anchor, anchor):
                    raise AuthorityUnavailable("series restore crossed deletion/storage lineage")
                permit = self.bridge.fences.begin_fence_locked(db, subject=self._subject, holder=holder,
                    operation="read", current_anchor=anchor,
                    operation_id="d04-series-restore:" + binding.digest + ":" + secrets.token_hex(8))
            try:
                db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
                try:
                    db.execute("BEGIN")
                    root = self._content_current(binding, db=db)
                    raw = read_d04_original_v3(db, self.namespace, "series_chunk_math", binding.numeric.operation_id)
                    measured = read_d04_original_v3(db, self.namespace, "series_chunk_measurement", binding.numeric.operation_id)
                    metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                        self.namespace.as_tuple).fetchone()
                    chunk = None if raw is None else _decode_series_chunk_for_final_verifier_v1(raw[0])
                    from ..runtime.d04_series_initial_original_v1 import require_d04_series_initial_original_v1
                    from ..native_runtime.d04_series_math_v1 import verify_d04_series_chunk_math_v1
                    require_d04_series_initial_original_v1(db, root)
                    if chunk is not None:
                        verify_d04_series_chunk_math_v1(root.frozen, chunk, root_digest=root.digest)
                        if chunk.invariant_domain is not None:
                            from ..native_runtime.d04_invariant_domain_v1 import require_installed_d04_invariant_verifier_v1
                            require_installed_d04_invariant_verifier_v1(chunk.invariant_domain, binding.numeric.native_manifest_sha256)
                    if (raw is None or chunk is None or measured is None or metadata is None
                            or measured[0]["claim"] != to_wire(claim) or measured[0]["measurement"] != to_wire(terminal.measurement)
                            or measured[0]["artifact_payload_digest"] != raw[1]
                            or chunk.digest != terminal.measurement.chunk_math_digest
                            or canonical_digest(chunk.endpoints) != terminal.measurement.endpoint_digest
                            or not self.numeric._graph_location_matches(json.loads(metadata[0]), anchor)):
                        raise AuthorityUnavailable("series native restore original/current location differs")
                    packet = canonical_serialize({"terminal": to_wire(terminal), "math": raw[0]}).encode()
                finally:
                    db.close()
                owner = self._owner_observation(permit, binding, root.prepared.binding)
                with self.numeric._frozen() as (db, deletion, head):
                    current, _ = self.numeric._current_anchor_locked(db, deletion, head, action="recovery")
                    self.bridge.fences.validate_fence_locked(db, permit, subject=self._subject, current_anchor=current)
                    self.numeric._require_owner_locked(db, root.prepared.binding, owner)
                return packet
            finally:
                with self.numeric._frozen() as (db, deletion, head):
                    current, _ = self.numeric._current_anchor_locked(db, deletion, head, action="recovery")
                    self.bridge.fences.finish_fence_locked(db, permit, subject=self._subject, current_anchor=current,
                        request_id=permit.operation_id + ":closed",
                        request_digest="sha256:" + canonical_digest((binding.digest, "restore-read", permit.operation_id)))

    def restore_prefix_manifest(self, binding):
        """Authenticate the entire bounded prefix in one current read fence."""
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            import hashlib
            import secrets
            from .d04_series_journal_v1 import decode_series_row_v1
            from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
            from ..runtime.d04_series_store_v1 import read_d04_series_chunk_prepared_v1
            from ..runtime.d04_series_execution_v1 import chunk_operation_v1
            from ..runtime.d04_series_codec_v1 import _decode_series_chunk_for_final_verifier_v1
            from ..runtime.d04_series_initial_original_v1 import (
                require_d04_series_initial_original_v1, d04_series_original_read_scope_v1)
            from ..runtime.d04_series_prefix_manifest_v1 import D04SeriesPrefixPacketV1, D04SeriesPrefixManifestV1
            from ..native_runtime.d04_series_math_v1 import verify_d04_series_chunk_math_v1
            from ..native_runtime.d04_invariant_domain_v1 import require_installed_d04_invariant_verifier_v1
            self._binding(binding)
            _, last_terminal = self.inspect(binding)
            if last_terminal is None or last_terminal.measurement.status != "chunk_completed":
                raise AuthorityUnavailable("series prefix restore requires a genuine final terminal")
            with self.numeric._frozen() as (core_db, deletion, head):
                anchor, holder = self.numeric._current_anchor_locked(core_db, deletion, head, action="recovery")
                source = self.bridge.fences._permit(self.bridge.fences._row(core_db, gate_id(binding, "claim")))
                if not self.numeric._same_location_epoch(source.pinned_anchor, anchor):
                    raise AuthorityUnavailable("series prefix restore crossed deletion/storage lineage")
                permit = self.bridge.fences.begin_fence_locked(core_db, subject=self._subject, holder=holder,
                    operation="read", current_anchor=anchor,
                    operation_id="d04-series-prefix-restore:" + binding.digest + ":" + secrets.token_hex(8))
            try:
                db = sqlite3.connect(self.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
                try:
                    db.execute("BEGIN")
                    with d04_series_original_read_scope_v1(db):
                        root = self._content_current(binding, db=db)
                        if (binding.plan_digest != root.frozen.plan.digest
                                or binding.end_step_index != root.frozen.plan.total_step_count):
                            raise AuthorityUnavailable("series manifest binding is not the actual final planned chunk")
                        require_d04_series_initial_original_v1(db, root)
                        prepared_prefix = []
                        start = 0
                        while start < root.frozen.plan.total_step_count:
                            saved = read_d04_series_chunk_prepared_v1(db, self.namespace, chunk_operation_v1(root, start))
                            end = start + len(root.frozen.plan.chunk(start))
                            if (saved is None or (saved[0].root_ref, saved[0].root_digest, saved[0].plan_digest,
                                    saved[0].start_step_index, saved[0].end_step_index) !=
                                    (root.root_ref, root.digest, root.frozen.plan.digest, start, end)):
                                raise AuthorityUnavailable("series manifest lacks its exact complete prepared prefix")
                            current_binding, prepared, _ = saved
                            self._binding(current_binding)
                            quote = self.numeric.resource_issuer.original_signed_quote(db,
                                current_binding.numeric.quote_id, current_binding.numeric.quote_version)
                            reserve = db.execute("SELECT receipt_json,digest FROM runtime_budget_operations "
                                "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
                                (*self.namespace.as_tuple, current_binding.numeric.reservation_operation_id)).fetchone()
                            if (canonical_digest(quote) != current_binding.numeric.quote_digest
                                    or dict(quote.ceiling) != {"cpu_ms": current_binding.numeric.cpu_ceiling_ms}
                                    or reserve != (prepared["reserve_receipt_json"], current_binding.numeric.reservation_digest)):
                                raise AuthorityUnavailable("series prefix actual signed quote/reservation differs")
                            prepared_prefix.append(current_binding)
                            start = end
                        if prepared_prefix[-1] != binding:
                            raise AuthorityUnavailable("series manifest final prepared binding differs")
                        # One frozen actual mixed chain supplies all originals. The
                        # complete scanner authenticates other families before we
                        # select this root's exact once identities.
                        originals = []
                        with self.numeric._frozen() as (core_db, deletion, head):
                            current, _ = self.numeric._current_anchor_locked(core_db, deletion, head, action="recovery")
                            self.bridge.fences.validate_fence_locked(core_db, permit, subject=self._subject, current_anchor=current)
                            if current != anchor:
                                raise AuthorityUnavailable("series prefix recovery anchor changed")
                            actual_head, rows = self.bridge.journal._scan_locked()
                            if actual_head != head:
                                raise AuthorityUnavailable("series prefix mixed execution head changed")
                            identities = {row[1]: row for row in rows}
                            for current_binding in prepared_prefix:
                                first = identities.get(mutation_id(current_binding, "claim"))
                                last = identities.get(mutation_id(current_binding, "terminal"))
                                if first is None or last is None:
                                    raise AuthorityUnavailable("series prefix actual claim/terminal original absent")
                                observed, claim, empty = decode_series_row_v1(self.bridge.journal, first)
                                terminal_binding, terminal_claim, measured = decode_series_row_v1(self.bridge.journal, last)
                                self._claim(current_binding, claim)
                                source = self.bridge.fences._permit(self.bridge.fences._row(core_db, gate_id(current_binding, "claim")))
                                if (observed != current_binding or terminal_binding != current_binding or terminal_claim != claim
                                        or empty is not None or measured is None
                                        or not self.numeric._same_location_epoch(source.pinned_anchor, anchor)):
                                    raise AuthorityUnavailable("series prefix actual once claim/terminal lineage differs")
                                self._reconcile(core_db, current_binding, last, head)
                                self._reconcile(core_db, current_binding, first, head)
                                terminal = D04SeriesTerminalV1(current_binding, claim, measured,
                                    mutation_id(current_binding, "terminal"), last[0], last[6].removeprefix("sha256:"), "pending")
                                originals.append(replace(terminal, signature=self.numeric._sign(terminal)))
                        packets = []
                        previous = None
                        for current_binding, terminal in zip(prepared_prefix, originals):
                            raw = read_d04_original_v3(db, self.namespace, "series_chunk_math", current_binding.numeric.operation_id)
                            measured = read_d04_original_v3(db, self.namespace, "series_chunk_measurement", current_binding.numeric.operation_id)
                            if (raw is None or measured is None or measured[0]["claim"] != to_wire(terminal.claim)
                                    or measured[0]["measurement"] != to_wire(terminal.measurement)
                                    or measured[0]["artifact_payload_digest"] != raw[1]
                                    or terminal.measurement.status != "chunk_completed"
                                    or terminal.measurement.actual_cpu_ms > current_binding.numeric.cpu_ceiling_ms):
                                raise AuthorityUnavailable("series prefix measured packet/terminal differs")
                            chunk = _decode_series_chunk_for_final_verifier_v1(raw[0])
                            verify_d04_series_chunk_math_v1(root.frozen, chunk, root_digest=root.digest, predecessor=previous)
                            if chunk.invariant_domain is not None:
                                require_installed_d04_invariant_verifier_v1(chunk.invariant_domain, current_binding.numeric.native_manifest_sha256)
                            native = chunk.full.production_binding
                            if ((chunk.root_digest, chunk.plan_digest, chunk.start_step_index,
                                    chunk.end_step_index, chunk.predecessor_digest) != (current_binding.root_digest,
                                    current_binding.plan_digest, current_binding.start_step_index,
                                    current_binding.end_step_index, current_binding.predecessor_digest)
                                    or chunk.digest != terminal.measurement.chunk_math_digest
                                    or canonical_digest(chunk.endpoints) != terminal.measurement.endpoint_digest
                                    or native.manifest_sha256 != current_binding.numeric.native_manifest_sha256
                                    or native.native_sha256 != current_binding.numeric.native_sha256 or native.abi_version != 2):
                                raise AuthorityUnavailable("series prefix exact native/output commitments differ")
                            packet = canonical_serialize({"terminal": to_wire(terminal), "math": raw[0]}).encode("utf-8")
                            packets.append(D04SeriesPrefixPacketV1(terminal, hashlib.sha256(packet).hexdigest(), len(packet)))
                            previous = chunk
                        metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
                            "WHERE bot=? AND persona=?", self.namespace.as_tuple).fetchone()
                        if (originals[-1] != last_terminal or metadata is None
                                or not self.numeric._graph_location_matches(json.loads(metadata[0]), anchor)
                                or self._content_current(binding, db=db) != root):
                            raise AuthorityUnavailable("series prefix current source/location changed")
                        manifest = D04SeriesPrefixManifestV1(root.root_ref, root.digest, root.frozen.plan.digest,
                            root.frozen.plan.total_step_count, root.frozen.plan.chunk_step_limit, len(packets), tuple(packets))
                finally:
                    db.close()
                owner = self._owner_observation(permit, binding, root.prepared.binding)
                with self.numeric._frozen() as (core_db, deletion, head):
                    current, _ = self.numeric._current_anchor_locked(core_db, deletion, head, action="recovery")
                    self.bridge.fences.validate_fence_locked(core_db, permit, subject=self._subject, current_anchor=current)
                    if current != anchor:
                        raise AuthorityUnavailable("series prefix anchor changed after actual Source/Owner read")
                    self.numeric._require_owner_locked(core_db, root.prepared.binding, owner)
                return manifest
            finally:
                with self.numeric._frozen() as (core_db, deletion, head):
                    current, _ = self.numeric._current_anchor_locked(core_db, deletion, head, action="recovery")
                    self.bridge.fences.finish_fence_locked(core_db, permit, subject=self._subject, current_anchor=current,
                        request_id=permit.operation_id + ":closed",
                        request_digest="sha256:" + canonical_digest((binding.digest, "prefix-restore-read", permit.operation_id)))

    def verify_series_journal_row_v1(self, journal, row):
        from .d04_series_journal_v1 import decode_series_row_v1
        if (journal.namespace != self.bridge.namespace or journal.journal_id != self.bridge.journal.journal_id
                or journal.path.resolve() != self.bridge.journal.path.resolve()):
            raise AuthorityUnavailable("series erasure verifier journal differs")
        binding, claim, measurement = decode_series_row_v1(journal, row)
        self._binding(binding)
        self._claim(binding, claim)
        if measurement is None:
            return binding, claim, None
        raw, _ = self._read(binding, phase="terminal", erased_body=True)
        if raw["measurement"] != measurement or raw["claim"] != claim:
            raise AuthorityUnavailable("series erasure durable measurement differs")
        terminal = D04SeriesTerminalV1(binding, claim, measurement, mutation_id(binding, "terminal"),
            row[0], row[6].removeprefix("sha256:"), "pending")
        return binding, claim, replace(terminal, signature=self.numeric._sign(terminal))
