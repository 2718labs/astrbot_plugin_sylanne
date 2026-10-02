"""Complete authenticated series prefix and one atomic final business adoption."""
from dataclasses import asdict, replace
from contextlib import contextmanager
import json
import logging
import time

from ..runtime_contracts import canonical_digest, canonical_serialize
from ..graph_types import AtomKey, GraphWrite, GraphVersion
from ..native_runtime.d04_series_math_v1 import D04SeriesChunkMathV1, verify_d04_series_chunk_math_v1
from ..domains.d04.joint_state_output_v1 import _write_set, joint_checkpoint_payload_v1, joint_state_payload_v1
from ..authority_service.d04_series_contract_v1 import D04SeriesGateV1, from_wire, to_wire
from .d04_series_execution_v1 import chunk_operation_v1, commit_series_writes_v1, stage_series_cpu_settlement_v1
from .d04_series_codec_v1 import decode_series_dto_v1
from .d04_series_store_v1 import read_d04_series_chunk_prepared_v1, require_d04_series_own_progress_v1, series_own_job_ref_v1
from .d04_series_output_v1 import derive_d04_series_final_v1, derive_d04_series_numeric_verification_v1
from .d04_appraisal_driver_v3 import read_d04_original_v3, record_d04_original_in_transaction_v3
from .d04_contribution_consumption_v3 import current_contribution_writes_v3
from .d04_installed_stage_fence_v3 import _D04PhaseTimingsV1
from .d04_semantic_mapping_v3 import require_current_d04_role_clock_v3, joint_evidence_field_v3
from .d04_joint_advance_v2 import (ProductAdvanceEvidenceV2, ProductAdvanceMemberV2, JointNumericOriginalVerificationV1,
    preflight_joint_advance_v2, preflight_joint_numeric_original_v1, record_joint_advance_v2, record_joint_numeric_original_v1)
from .d04_joint_output_original_store_v1 import record_d04_joint_output_original_v1, record_d04_joint_output_closure_v1

_LOG = logging.getLogger(__name__)


class _AdoptionTimings:
    def __init__(self, root):
        self.diagnostics = _D04PhaseTimingsV1(root.root_ref, deadline_utc=root.prepared.binding.deadline_utc)
        self.seconds = dict.fromkeys(("prefix_restore", "final_derive_numeric_verify",
            "authority_gate_validate", "business_transaction"))
        self.phase = "preflight"

    @contextmanager
    def measure(self, phase):
        self.phase = phase
        started = time.perf_counter()
        try:
            with self.diagnostics.measure(phase):
                yield
        finally:
            elapsed = time.perf_counter() - started
            previous = self.seconds.get(phase)
            self.seconds[phase] = elapsed if previous is None else previous + elapsed


def restore_d04_series_prefix_v1(graph, root):
    """Authority rereads every real terminal; no restore path invokes FFI."""
    port, store = graph._GraphCoordinator__c04_authority_port_v3, graph._GraphCoordinator__store
    chunks = []
    bindings = []
    terminals = []
    start = 0
    while start < root.frozen.plan.total_step_count:
        operation = chunk_operation_v1(root, start)
        with store._lock:
            prepared = read_d04_series_chunk_prepared_v1(store._db, root.prepared.binding.namespace, operation)
        if prepared is None:
            raise ValueError("series final adoption lacks complete prepared prefix")
        binding = prepared[0]
        from .d04_series_restore_v1 import read_installed_d04_series_packet_v1
        terminal, payload = read_installed_d04_series_packet_v1(graph, binding)
        chunk = decode_series_dto_v1(D04SeriesChunkMathV1, payload)
        verify_d04_series_chunk_math_v1(root.frozen, chunk, root_digest=root.digest,
            predecessor=None if not chunks else chunks[-1])
        if (terminal.measurement.chunk_math_digest != chunk.digest
                or terminal.measurement.endpoint_digest != canonical_digest(chunk.endpoints)
                or terminal.measurement.actual_cpu_ms > binding.numeric.cpu_ceiling_ms
                or chunk.start_step_index != binding.start_step_index or chunk.end_step_index != binding.end_step_index
                or chunk.predecessor_digest != binding.predecessor_digest):
            raise ValueError("series real terminal differs from exact native chunk original")
        native = chunk.full.production_binding
        if (native.manifest_sha256 != binding.numeric.native_manifest_sha256
                or native.native_sha256 != binding.numeric.native_sha256 or native.abi_version != 2):
            raise ValueError("series native prefix binding changed")
        chunks.append(chunk)
        bindings.append(binding)
        terminals.append(terminal)
        start = chunk.end_step_index
    return tuple(chunks), tuple(bindings), tuple(terminals)


def _evidence(root, decoded, numeric, output, summary, chunks, contributions):
    fields = {name: canonical_digest(json.loads(payload)) for name, payload in decoded.evidence_inputs.field_payloads}
    fields["numeric_input_digest"] = joint_evidence_field_v3("numeric_input_digest",
        {"root_digest": root.digest, "plan_digest": root.frozen.plan.digest, "frozen_model": root.payload["frozen_model"]})[1]
    fields["full_transcript_digest"] = numeric.full_transcript_sha256
    fields["output_write_set_digest"] = output.write_set_digest
    members = []
    predecessors = {member.checkpoint_ref: member for member in decoded.preparation.predecessors.members}
    for member in output.members:
        old = predecessors[member.checkpoint_ref]
        members.append(ProductAdvanceMemberV2(member.checkpoint_ref, old.checkpoint.commit_operation_id,
            old.checkpoint_revision, canonical_digest(joint_checkpoint_payload_v1(old.checkpoint)), old.state_ref,
            old.state_revision, canonical_digest(joint_state_payload_v1(old.state)), old.checkpoint.certificate_digest,
            old.checkpoint.numeric_error_bound, old.checkpoint_revision + 1,
            canonical_digest(joint_checkpoint_payload_v1(member.next_checkpoint)), member.next_checkpoint.numeric_error_bound,
            old.state_ref, old.state_revision + 1, canonical_digest(joint_state_payload_v1(member.next_state))))
    component = decoded.preparation.current.component
    operation_digest = canonical_digest(("d04.series-final-adoption.v1", root.digest,
        tuple(chunk.digest for chunk in chunks), output.original_digest, tuple(contributions)))
    evidence = ProductAdvanceEvidenceV2("d11.product_advance_evidence.v3" if component.root_original_digest else "d11.product_advance_evidence.v2",
        numeric.namespace, output.operation_id, operation_digest, "d04-joint:" + canonical_digest(component.checkpoint_refs),
        root.prepared.binding.execution_id, component.role_start, component.role_end, tuple(members), component.catalogue_hash,
        component.graph_incarnation, numeric.graph_revision, numeric.graph_epoch, component.access_epoch, component.delete_epoch,
        fields["read_versions_digest"], fields["snapshot_stamp_digest"], fields["time_mapping_digest"], fields["closure_digest"],
        fields["source_closure_digest"], fields["absent_reads_digest"], fields["asset_digest"], numeric.native_manifest_sha256,
        numeric.native_sha256, fields["numeric_input_digest"], numeric.full_transcript_sha256, numeric.family_transcripts,
        output.write_set_digest, fields["contribution_consumption_digest"])
    return evidence


def adopt_d04_series_v1(graph, bootstrap, bundle, root):
    timings = _AdoptionTimings(root)
    try:
        result = _adopt_d04_series_v1(graph, bootstrap, bundle, root, timings)
    except BaseException as failure:
        _LOG.error("D04 series final adoption failed root_ref=%s failed_phase=%s elapsed_seconds=%s exception_type=%s reason=%s",
            root.root_ref, timings.phase, timings.seconds,
            type(failure).__module__ + "." + type(failure).__qualname__, str(failure), exc_info=True)
        raise
    _LOG.debug("D04 series final adoption finished root_ref=%s elapsed_seconds=%s", root.root_ref, timings.seconds)
    return result


def _adopt_d04_series_v1(graph, bootstrap, bundle, root, timings):
    graph._admin(bootstrap)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__c04_authority_port_v3
    namespace = root.prepared.binding.namespace
    with store._lock:
        prior = read_d04_original_v3(store._db, namespace, "series_adoption", root.root_ref)
        old_gate = read_d04_original_v3(store._db, namespace, "series_adoption_gate", root.root_ref)
    if prior is not None:
        if old_gate is None:
            raise ValueError("series committed adoption original gate absent")
        gate = from_wire(old_gate[0], D04SeriesGateV1)
        with timings.measure("authority_gate_validate"):
            port.series(gate.binding, "finish", gate=gate)
        with timings.measure("business_transaction"):
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    paid = read_d04_original_v3(db, namespace, "series_chunk_cost_commit", gate.binding.numeric.operation_id)
                    if paid is None:
                        raise ValueError("series adopted final CPU committed original absent")
                    record_d04_original_in_transaction_v3(db, namespace, "series_chunk_cost", gate.binding.numeric.operation_id,
                        {**paid[0], "authority_ack": True})
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
            return prior[0]
    with timings.measure("prefix_restore"):
        from .d04_series_restore_v1 import _collect_installed_d04_series_prefix_for_final_verifier_v1
        prefix = _collect_installed_d04_series_prefix_for_final_verifier_v1(graph, root)
        chunks, bindings, terminals = prefix.chunks, prefix.bindings, prefix.terminals
    binding, terminal = bindings[-1], terminals[-1]
    with timings.measure("final_derive_numeric_verify"):
        with store._lock:
            store._db.execute("BEGIN")
            try:
                metadata, epoch = require_d04_series_own_progress_v1(graph, store._db, root)
            finally:
                store._db.rollback()
        decoded, numeric, output, summary = derive_d04_series_final_v1(root, chunks,
            graph._GraphCoordinator__d04_installed_joint_output_policy,
            adoption_stamp=(metadata.graph_revision, epoch.revision))
        installation = graph._GraphCoordinator__d04_installed_joint_assembly
        with timings.measure("installed_asset_verify"):
            verification = derive_d04_series_numeric_verification_v1(numeric, summary,
                package_root=installation.package_root, available_cpu_features=installation.available_cpu_features)
    with timings.measure("authority_gate_validate"):
        gate = port.series(binding, "gate", phase="restore")
        port.series(binding, "validate", gate=gate)
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                record_d04_original_in_transaction_v3(store._db, namespace, "series_adoption_gate", root.root_ref, to_wire(gate))
                store._db.commit()
            except BaseException:
                store._db.rollback()
                raise
    with timings.measure("business_transaction"):
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                metadata, epoch = require_d04_series_own_progress_v1(graph, db, root)
                if metadata.graph_revision != gate.before_graph_revision or canonical_serialize(asdict(metadata.requirements)) != gate.before_requirements_json:
                    raise ValueError("series final business snapshot changed after current Authority gate")
                if time.time() >= decoded.preparation.envelope.deadline_utc:
                    raise ValueError("series root fixed deadline expired before adoption")
                require_current_d04_role_clock_v3(db, decoded.evidence_inputs.clock)
                for previous_binding, previous_terminal in zip(bindings[:-1], terminals[:-1]):
                    paid = read_d04_original_v3(db, namespace, "series_chunk_cost", previous_binding.numeric.operation_id)
                    if (paid is None or paid[0]["terminal_digest"] != previous_terminal.digest
                            or paid[0]["authority_ack"] is not True or paid[0]["budget_status"] != "settled"):
                        raise ValueError("series final adoption lacks every actual prior CPU settlement ACK")
                # Last CPU and job closure commit with the complete business write
                # set. There is no intermediate cursor/state adoption per chunk.
                paid, runtime_writes = stage_series_cpu_settlement_v1(graph, db, root, binding, terminal, gate, complete=True)
                if paid["budget_status"] != "settled":
                    raise ValueError("series final CPU exceeded its actual signed reservation")
                contribution = current_contribution_writes_v3(db, namespace, decoded.preparation.current.drives,
                    operation_id=output.operation_id, numeric_binding_digest=root.digest, output_original_digest=output.original_digest)
                evidence = _evidence(root, decoded, numeric, output, summary, chunks, contribution)
                joint = preflight_joint_advance_v2(db, evidence, trusted_local_verifier=lambda current_db, value:
                    current_db is db and value == evidence and require_d04_series_own_progress_v1(graph, db, root) == (metadata, epoch))
                numeric_preflight = preflight_joint_numeric_original_v1(db, evidence, numeric, joint_preflight=joint,
                    trusted_local_numeric_verifier=lambda current_db, value, candidate:
                        verification if current_db is db and value == evidence and candidate == numeric else None)
                output_writes = tuple(GraphWrite(AtomKey.from_token(ref), value) for ref, _, value in _write_set(output.members))
                writes = output_writes + contribution + runtime_writes
                reads = {row.key: row.revision for row in decoded.preparation.envelope.version_guard.read_versions
                    if row.key.token != series_own_job_ref_v1(root)}
                for write in writes:
                    if write.key.type_name.startswith("runtime."):
                        reads[write.key] = (db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone() or (0,))[0]
                anchor = gate.permit.pinned_anchor
                target = replace(metadata.requirements, execution_seq=anchor.execution_seq, execution_digest=anchor.execution_digest)
                if not graph._anchor_matches(target, anchor):
                    raise ValueError("series final bridge changes unrelated recovery dimensions")
                receipt = commit_series_writes_v1(graph, db, metadata, epoch, root, event_id=output.operation_id,
                    now=time.time(), writes=writes, reads=tuple(GraphVersion(key, value) for key, value in sorted(reads.items(), key=lambda row: row[0].token)),
                    target=target, operation_digest=evidence.bundle_digest, ledger_refs=tuple(write.key.token for write in contribution))
                paid = {**paid, "event_id": output.operation_id, "graph_receipt_digest": canonical_digest(receipt)}
                record_d04_original_in_transaction_v3(db, namespace, "series_chunk_cost_commit", binding.numeric.operation_id, paid)
                record_joint_advance_v2(db, evidence, preflight=joint)
                record_joint_numeric_original_v1(db, evidence, numeric, preflight=numeric_preflight)
                record_d04_joint_output_original_v1(db, namespace, output.operation_id, evidence.digest, output)
                output_keys = {write.key.token for write in output_writes}
                closure = tuple((row.ref, row.revision, row.valid, canonical_digest(json.loads(row.value_json)))
                    for row in sorted(decoded.evidence_inputs.read_rows, key=lambda row: row.ref)
                    if row.ref not in output_keys and row.ref != series_own_job_ref_v1(root))
                record_d04_joint_output_closure_v1(db, namespace, output.operation_id, evidence.digest, output.component_digest,
                    decoded.preparation.envelope.authority.audience, decoded.preparation.envelope.authority.purpose, closure)
                result = {"schema": "d04.series-adoption.v1", "status": "joint_advance_committed", "root_ref": root.root_ref,
                    "root_digest": root.digest, "operation_id": output.operation_id, "gate_digest": gate.digest,
                    "last_binding_digest": binding.digest, "terminal_digest": terminal.digest,
                    "complete_prefix_digest": summary.transcript_sha256, "output_original_digest": output.original_digest,
                    "numeric_receipt_digest": numeric.receipt_digest, "graph_receipt_digest": canonical_digest(receipt),
                    "total_step_count": root.frozen.plan.total_step_count, "chunk_count": len(chunks),
                    "actual_cpu_ns": sum(value.measurement.actual_cpu_ns for value in terminals),
                    "actual_cpu_ms": sum(value.measurement.actual_cpu_ms for value in terminals)}
                record_d04_original_in_transaction_v3(db, namespace, "series_adoption_gate", root.root_ref, to_wire(gate))
                record_d04_original_in_transaction_v3(db, namespace, "series_adoption", root.root_ref, result)
                record_d04_original_in_transaction_v3(db, namespace, "series_final_native_prefix", output.operation_id,
                    {"root_ref": root.root_ref, "root_digest": root.digest, "math_digest": summary.transcript_sha256,
                        "chunks": [[value.numeric.operation_id, chunk.digest, original.digest] for value, chunk, original in zip(bindings, chunks, terminals)]})
                for value, original in zip(bindings, terminals):
                    record_d04_original_in_transaction_v3(db, namespace, "series_chunk_terminal", value.numeric.operation_id, to_wire(original))
                db.commit()
            except BaseException:
                db.rollback()
                raise
    with timings.measure("authority_gate_validate"):
        port.series(binding, "finish", gate=gate)
    with timings.measure("business_transaction"):
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                record_d04_original_in_transaction_v3(db, namespace, "series_chunk_cost", binding.numeric.operation_id,
                    {**paid, "authority_ack": True})
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return result


def abandon_d04_series_adoption_v1(graph, root):
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__c04_authority_port_v3
    with store._lock:
        db = store._db
        saved = read_d04_original_v3(db, root.prepared.binding.namespace, "series_adoption_gate", root.root_ref)
        if saved is None:
            return
        gate = from_wire(saved[0], D04SeriesGateV1)
        metadata, _ = graph._v2_graph_stamp(root.prepared.binding.namespace)
        if metadata.graph_revision != gate.before_graph_revision or canonical_serialize(asdict(metadata.requirements)) != gate.before_requirements_json:
            raise ValueError("series final adoption outcome unknown; keep original gate HOLD")
        db.execute("BEGIN IMMEDIATE")
        try:
            record_d04_original_in_transaction_v3(db, root.prepared.binding.namespace, "series_adoption_rejected", root.root_ref,
                {"schema": "d04.series-adoption-rejected.v1", "gate_digest": gate.digest, "status": "rejected_no_commit"})
            db.commit()
        except BaseException:
            db.rollback()
            raise
    port.series(gate.binding, "abandon", gate=gate)
