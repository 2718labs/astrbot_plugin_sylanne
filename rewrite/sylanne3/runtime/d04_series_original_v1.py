"""Explicit series original dispatch for subsequent advances and D06 consumers."""

from dataclasses import asdict
import json
from types import SimpleNamespace
from pathlib import Path
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..authority_service.d04_series_contract_v1 import D04SeriesTerminalV1, D04SeriesGateV1, from_wire
from ..domains.d04.joint_state_output_v1 import JointStateOutputPolicyV1, _write_set
from .d04_series_store_v1 import (read_d04_series_root_v1, read_d04_series_chunk_prepared_v1,
    _read_d04_series_chunk_for_final_verifier_v1)
from .d04_series_output_v1 import derive_d04_series_final_v1, derive_d04_series_numeric_verification_v1
from .d04_appraisal_driver_v3 import read_d04_original_v3


def require_series_adopted_original_v1(db, namespace, operation_id):
    """Use one actual read snapshot, or the caller's existing transaction."""
    from .d04_series_initial_original_v1 import d04_series_original_read_scope_v1
    if db.in_transaction:
        with d04_series_original_read_scope_v1(db) as scope:
            return _read_adopted_series_once_v1(db, namespace, operation_id, scope)
    db.execute("BEGIN")
    try:
        with d04_series_original_read_scope_v1(db) as scope:
            return _read_adopted_series_once_v1(db, namespace, operation_id, scope)
    finally:
        db.rollback()


def _read_adopted_series_once_v1(db, namespace, operation_id, scope):
    # SQL history is immutable within this caller-owned read snapshot. Loaded
    # package bytes have a separate boundary and are checked again on reuse.
    memo, visiting = scope[3:5]
    key = (namespace, operation_id)
    if key in memo:
        result = memo[key]
        from ..host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
        read_installed_d04_numeric_identity_v3(Path(__file__).resolve().parents[3],
            result[0].prepared.binding.native_manifest_sha256)
        return result
    if key in visiting:
        raise ValueError("adopted series ancestry is cyclic")
    visiting.add(key)
    try:
        result = _require_series_adopted_original_in_transaction_v1(db, namespace, operation_id)
        if result is not None:
            # Only the final return follows every mathematical, installation,
            # original, event, receipt and completed-job comparison.
            memo[key] = result
        return result
    finally:
        visiting.remove(key)


def _require_series_adopted_original_in_transaction_v1(db, namespace, operation_id):
    """Return None only for a non-series identity; damaged series originals HOLD.

    This is a pure Graph read of the actual packets authenticated by the
    installed Authority before the one final commit. It neither invokes FFI
    nor substitutes an old v3 numeric artifact for a series native original.
    Current content/Owner qualifications remain the caller's fenced duty.
    """
    from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3,background_json_digest_v3
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    prefix = read_d04_original_v3(db, namespace, "series_final_native_prefix", operation_id)
    from .natural_producer_qualification_v1 import (_host_producer_attachment_owner_v3,_series_adoption_refs_v3,_producer_original_many_v3)
    from .domain_background_read_v3 import _active_v3
    if _host_producer_attachment_owner_v3(db)is not None or _active_v3(db)is not None:
        retained=_series_adoption_refs_v3(db,namespace,operation_id)
        roots=_producer_original_many_v3(db,table='graph_d04_originals_v3',columns=('original_ref',),
            key_columns=('bot','persona','kind'),key=(*namespace.as_tuple,'series_root'),order_column='original_ref',legacy_reader=None)
    else:
        retained = db.execute("SELECT original_ref FROM graph_d04_originals_v3 WHERE bot=? AND persona=? AND kind='series_adoption' "
            "AND json_extract(payload_json,'$.operation_id')=?", (*namespace.as_tuple, operation_id)).fetchall()
        roots = db.execute("SELECT original_ref FROM graph_d04_originals_v3 WHERE bot=? AND persona=? AND kind='series_root'",
            namespace.as_tuple).fetchall()
    selected = []
    for (ref,) in roots:
        candidate = read_d04_original_v3(db, namespace, "series_root", ref)
        if candidate[0]["numeric_operation_id"] == operation_id:
            selected.append(ref)
    if not selected:
        if prefix is not None or retained:
            raise ValueError("series committed identity lost its frozen source original")
        return None
    if len(selected) != 1:
        raise ValueError("series operation has ambiguous frozen roots")
    root = read_d04_series_root_v1(db, namespace, selected[0])
    from .d04_series_initial_original_v1 import require_d04_series_initial_original_v1
    require_d04_series_initial_original_v1(db, root)
    adopted = read_d04_original_v3(db, namespace, "series_adoption", root.root_ref)
    if (adopted is None or prefix is None or adopted[0]["root_digest"] != root.digest
            or prefix[0]["root_digest"] != root.digest or prefix[0]["root_ref"] != root.root_ref
            or not prefix[0]["chunks"]):
        raise ValueError("series identity lacks complete committed final prefix")
    chunks = []
    total_cpu = 0
    for operation, digest, terminal_digest in prefix[0]["chunks"]:
        binding = read_d04_series_chunk_prepared_v1(db, namespace, operation)
        chunk = _read_d04_series_chunk_for_final_verifier_v1(db, namespace, operation)
        saved = read_d04_original_v3(db, namespace, "series_chunk_terminal", operation)
        if binding is None or chunk is None or saved is None:
            raise ValueError("series committed native/terminal packet missing")
        terminal = from_wire(saved[0], D04SeriesTerminalV1)
        if (terminal.binding != binding[0] or terminal.digest != terminal_digest or chunk.digest != digest
                or terminal.measurement.status != "chunk_completed"
                or terminal.measurement.actual_cpu_ms > terminal.binding.numeric.cpu_ceiling_ms
                or terminal.measurement.chunk_math_digest != chunk.digest
                or terminal.measurement.endpoint_digest != canonical_digest(chunk.endpoints)
                or terminal.binding.root_digest != root.digest):
            raise ValueError("series committed packet does not match actual terminal")
        # derive_d04_series_final_v1 below verifies the complete prefix once,
        # including every predecessor link. No partially checked result escapes.
        if chunk.invariant_domain is not None:
            from ..native_runtime.d04_invariant_domain_v1 import require_installed_d04_invariant_verifier_v1
            require_installed_d04_invariant_verifier_v1(chunk.invariant_domain, root.prepared.binding.native_manifest_sha256)
        native = chunk.full.production_binding
        if (native.native_sha256 != root.prepared.binding.native_sha256
                or native.manifest_sha256 != root.prepared.binding.native_manifest_sha256 or native.abi_version != 2):
            raise ValueError("series historical prefix native identity differs")
        total_cpu += terminal.measurement.actual_cpu_ns
        chunks.append(chunk)
    policy = dict(root.payload["output_policy"])
    policy["axis_ids"] = tuple(policy["axis_ids"])
    installed = SimpleNamespace(policy=JointStateOutputPolicyV1(**policy),
        manifest_sha256=root.prepared.binding.native_manifest_sha256, policy_sha256=root.payload["output_policy_sha256"])
    saved_gate = read_d04_original_v3(db, namespace, "series_adoption_gate", root.root_ref)
    if saved_gate is None:
        raise ValueError("series adopted prefix has no original current commit gate")
    gate = from_wire(saved_gate[0], D04SeriesGateV1)
    from .d04_root_original_store_v1 import _receipt
    receipt = _receipt(db, namespace, operation_id)
    if (gate.root_digest != root.digest or gate.binding != terminal.binding
            or gate.digest != adopted[0]["gate_digest"] or len(receipt.invalidated_epochs) != 1):
        raise ValueError("series final commit gate/prefix differs")
    decoded, numeric, output, summary = derive_d04_series_final_v1(root, tuple(chunks), installed,
        adoption_stamp=(gate.before_graph_revision, receipt.invalidated_epochs[0].revision - 1))
    from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1
    from .d04_joint_advance_v2 import read_joint_advance_v2, _decode_numeric_candidate
    persisted_output = read_d04_joint_output_original_v1(db, namespace, operation_id)
    numeric_row = _producer_original_point_v3(db, table='graph_d04_joint_numeric_originals_v1', columns=('numeric_receipt_json', 'numeric_receipt_digest', 'verification_json', 'verification_digest', 'evidence_digest'), key_columns=('bot', 'persona', 'operation_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2]))((*namespace.as_tuple, operation_id)), legacy_reader=lambda: db.execute("SELECT numeric_receipt_json,numeric_receipt_digest,verification_json,verification_digest,evidence_digest FROM graph_d04_joint_numeric_originals_v1 WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id)).fetchone())
    evidence = read_joint_advance_v2(db, namespace, operation_id)
    verification = derive_d04_series_numeric_verification_v1(numeric, summary,
        package_root=Path(__file__).resolve().parents[3])
    from ..graph_store import GraphStore
    from ..graph_types import GraphReceipt, NamespaceEpoch, GraphWrite, AtomKey
    event = _producer_original_point_v3(db, table='graph_events', columns=('revisions', 'invalidated', 'epoch_revision'), key_columns=('bot', 'persona', 'session', 'event_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2],_producer_params_v3[3]))((*namespace.as_tuple, receipt.activity_id, operation_id)), legacy_reader=lambda: db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, receipt.activity_id, operation_id)).fetchone())
    actual_receipt = None if event is None else GraphReceipt("committed", GraphStore._version_rows(event[0]),
        GraphStore._version_rows(event[1]), NamespaceEpoch(*namespace.as_tuple, event[2]))
    contributions = []
    for ref in receipt.ledger_refs:
        revision = next((value.revision for value in receipt.write_versions if value.key.token == ref), None)
        row = _producer_original_point_v3(db, table='graph_history', columns=('value', 'valid'), key_columns=('token', 'revision', 'event_bot', 'event_persona', 'event_session', 'event_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2],_producer_params_v3[3],_producer_params_v3[4],_producer_params_v3[5]))((ref, revision, *namespace.as_tuple, receipt.activity_id, operation_id)), legacy_reader=lambda: db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (ref, revision, *namespace.as_tuple, receipt.activity_id, operation_id)).fetchone())
        if row is None or row[1] != 1:
            raise ValueError("series final contribution is not in its actual atomic event")
        contributions.append(GraphWrite(AtomKey.from_token(ref), background_json_loads_v3(row[0])))
    from .d04_series_adoption_v1 import _evidence
    expected_evidence = _evidence(root, decoded, numeric, output, summary, tuple(chunks), tuple(contributions))
    if (persisted_output != output or numeric_row is None or _decode_numeric_candidate(numeric_row[0]) != numeric
            or numeric_row[1] != numeric.receipt_digest
            or not background_json_matches_v3(numeric_row[2],asdict(verification))
            or numeric_row[3] != canonical_digest(asdict(verification))
            or numeric_row[4] != expected_evidence.digest
            or evidence != expected_evidence or evidence.full_transcript_digest != numeric.full_transcript_sha256
            or evidence.family_loo_transcripts != numeric.family_transcripts
            or evidence.output_write_set_digest != output.write_set_digest
            or adopted[0]["complete_prefix_digest"] != summary.transcript_sha256
            or adopted[0]["output_original_digest"] != output.original_digest
            or adopted[0]["numeric_receipt_digest"] != numeric.receipt_digest
            or adopted[0]["actual_cpu_ns"] != total_cpu
            or adopted[0]["actual_cpu_ms"] != sum(from_wire(read_d04_original_v3(db, namespace,
                "series_chunk_terminal", operation)[0], D04SeriesTerminalV1).measurement.actual_cpu_ms
                for operation, _, _ in prefix[0]["chunks"])
            or adopted[0]["chunk_count"] != len(chunks) or adopted[0]["total_step_count"] != root.frozen.plan.total_step_count
            or prefix[0]["math_digest"] != summary.transcript_sha256
            or actual_receipt is None or adopted[0]["graph_receipt_digest"] != canonical_digest(actual_receipt)):
        raise ValueError("series final complete member/readout originals differ from authenticated prefix")
    if receipt.operation_digest != evidence.bundle_digest:
        raise ValueError("series final commit receipt differs")
    from .d04_joint_advance_v2 import _numeric_history
    _numeric_history(db, evidence)
    from .d04_series_store_v1 import series_own_job_ref_v1, series_chunk_cost_ref_v1
    expected_refs = {ref for ref, _, _ in _write_set(output.members)} | set(receipt.ledger_refs)
    expected_refs.update((series_own_job_ref_v1(root), series_chunk_cost_ref_v1(terminal.binding)))
    if {version.key.token for version in receipt.write_versions} != expected_refs:
        raise ValueError("series final atomic event has an unrelated or missing write")
    job_ref = series_own_job_ref_v1(root)
    job_revision = next(version.revision for version in receipt.write_versions if version.key.token == job_ref)
    job = _producer_original_point_v3(db, table='graph_history', columns=('value', 'valid'), key_columns=('token', 'revision', 'event_bot', 'event_persona', 'event_session', 'event_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2],_producer_params_v3[3],_producer_params_v3[4],_producer_params_v3[5]))((job_ref, job_revision, *namespace.as_tuple, receipt.activity_id, operation_id)), legacy_reader=lambda: db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=? AND event_bot=? "
        "AND event_persona=? AND event_session=? AND event_id=?",
        (job_ref, job_revision, *namespace.as_tuple, receipt.activity_id, operation_id)).fetchone())
    if (job is None or job[1] != 1 or background_json_loads_v3(job[0])["phase"] != "completed"
            or background_json_loads_v3(job[0])["usage_digest"] != canonical_digest({"cpu_ms": adopted[0]["actual_cpu_ms"]})
            or background_json_loads_v3(job[0])["result_ref"] != root.root_ref):
        raise ValueError("series final actual worker was not atomically completed with all CPU")
    return root, tuple(chunks), numeric, output, summary
