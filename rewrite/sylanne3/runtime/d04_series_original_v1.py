"""Explicit series original dispatch for subsequent advances and D06 consumers."""

from dataclasses import asdict,dataclass
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
    from .current_life_numeric_native_read_v3 import read_bound_native_nonseries_original_v3
    handled,value=read_bound_native_nonseries_original_v3(db,namespace,operation_id)
    if handled:return value
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


@dataclass(frozen=True,slots=True)
class HistoricalD04SeriesRootMetadataV1:
    root_ref:str
    payload:dict
    digest:str
    binding:object
    frozen:object


def decode_historical_d04_series_root_v1(payload,digest,model):
    from .d04_numeric_artifact_v3 import HistoricalNumericModelMetadataV1
    from .d04_series_codec_v1 import decode_series_dto_v1
    from ..native_runtime.d04_joint_product_math import D04JointCompiledInputsV1
    from ..native_runtime.d04_fixed_trajectory_v2 import exact_d04_series_step_plan_v1
    from .d04_series_initial_original_v1 import require_historical_d04_series_initial_binding_v1
    if type(model)is not HistoricalNumericModelMetadataV1:raise TypeError('actual numeric model metadata required')
    ref='d04-series-root:'+canonical_digest((model.binding.namespace,model.binding.operation_id))[:48]
    if(payload['schema']!='d04.series-root.v1'or payload['root_ref']!=ref or canonical_digest(payload)!=digest
            or payload['numeric_prepared_digest']!=model.prepared_digest
            or payload['numeric_operation_id']!=model.binding.operation_id):
        raise ValueError('historical series root/prepared complete original differs')
    frozen=decode_series_dto_v1(D04JointCompiledInputsV1,payload['frozen_model'])
    expected=exact_d04_series_step_plan_v1(frozen.plan.role_start,frozen.plan.role_end,family_count=len(frozen.family_drives))
    if frozen.plan!=expected or payload['plan_digest']!=expected.digest:
        raise ValueError('historical series absolute-step plan differs')
    root=HistoricalD04SeriesRootMetadataV1(ref,payload,digest,model.binding,frozen)
    require_historical_d04_series_initial_binding_v1(root,model)
    return root


def verify_historical_d04_series_values_v1(root,model,*,prefix,adopted,bindings,chunks,terminals,gate,receipt,
        numeric_row,evidence,persisted_output,contributions,graph_receipt,job):
    """The full historical series formulas over authenticated numeric-only values."""
    from .d04_series_output_v1 import derive_historical_d04_series_final_v1
    from .d04_joint_advance_v2 import ProductAdvanceEvidenceV2,ProductAdvanceMemberV2,_decode_numeric_candidate
    from ..domains.d04.joint_state_output_v1 import joint_checkpoint_payload_v1,joint_state_payload_v1
    from .d04_semantic_mapping_v3 import joint_evidence_field_v3
    if(type(root)is not HistoricalD04SeriesRootMetadataV1 or prefix['root_digest']!=root.digest
            or prefix['root_ref']!=root.root_ref or adopted['root_digest']!=root.digest or not prefix['chunks']
            or len(chunks)!=len(bindings)or len(chunks)!=len(terminals)or len(chunks)!=len(prefix['chunks'])):
        raise ValueError('historical series lacks its exact complete committed prefix')
    total_cpu=0
    for (operation,digest,terminal_digest),binding,chunk,terminal in zip(prefix['chunks'],bindings,chunks,terminals):
        if(terminal.binding!=binding or binding.numeric.operation_id!=operation or terminal.digest!=terminal_digest
                or chunk.digest!=digest or terminal.measurement.status!='chunk_completed'
                or terminal.measurement.actual_cpu_ms>binding.numeric.cpu_ceiling_ms
                or terminal.measurement.chunk_math_digest!=chunk.digest
                or terminal.measurement.endpoint_digest!=canonical_digest(chunk.endpoints)
                or binding.root_digest!=root.digest):
            raise ValueError('historical series packet differs from its actual terminal')
        if chunk.invariant_domain is not None:
            from ..native_runtime.d04_invariant_domain_v1 import require_installed_d04_invariant_verifier_v1
            require_installed_d04_invariant_verifier_v1(chunk.invariant_domain,root.binding.native_manifest_sha256)
        native=chunk.full.production_binding
        if(native.native_sha256!=root.binding.native_sha256
                or native.manifest_sha256!=root.binding.native_manifest_sha256 or native.abi_version!=2):
            raise ValueError('historical series native identity differs')
        total_cpu+=terminal.measurement.actual_cpu_ns
    policy=dict(root.payload['output_policy']);policy['axis_ids']=tuple(policy['axis_ids'])
    installed=SimpleNamespace(policy=JointStateOutputPolicyV1(**policy),manifest_sha256=root.binding.native_manifest_sha256,
        policy_sha256=root.payload['output_policy_sha256'])
    if(gate.root_digest!=root.digest or gate.binding!=terminals[-1].binding or gate.digest!=adopted['gate_digest']
            or len(receipt.invalidated_epochs)!=1):
        raise ValueError('historical series final gate/prefix differs')
    numeric,output,summary=derive_historical_d04_series_final_v1(root,chunks,installed,model,
        adoption_stamp=(gate.before_graph_revision,receipt.invalidated_epochs[0].revision-1))
    verification=derive_d04_series_numeric_verification_v1(numeric,summary,package_root=Path(__file__).resolve().parents[3])
    fields_=dict(model.field_digests)
    fields_['numeric_input_digest']=joint_evidence_field_v3('numeric_input_digest',
        {'root_digest':root.digest,'plan_digest':root.frozen.plan.digest,'frozen_model':root.payload['frozen_model']})[1]
    members=[];predecessors={m.checkpoint_ref:m for m in model.predecessors.members}
    for member in output.members:
        old=predecessors[member.checkpoint_ref]
        members.append(ProductAdvanceMemberV2(member.checkpoint_ref,old.checkpoint.commit_operation_id,
            old.checkpoint_revision,canonical_digest(joint_checkpoint_payload_v1(old.checkpoint)),old.state_ref,
            old.state_revision,canonical_digest(joint_state_payload_v1(old.state)),old.checkpoint.certificate_digest,
            old.checkpoint.numeric_error_bound,old.checkpoint_revision+1,
            canonical_digest(joint_checkpoint_payload_v1(member.next_checkpoint)),member.next_checkpoint.numeric_error_bound,
            old.state_ref,old.state_revision+1,canonical_digest(joint_state_payload_v1(member.next_state))))
    component=model.current.component
    operation_digest=canonical_digest(('d04.series-final-adoption.v1',root.digest,
        tuple(chunk.digest for chunk in chunks),output.original_digest,tuple(contributions)))
    expected=ProductAdvanceEvidenceV2('d11.product_advance_evidence.v3'if component.root_original_digest else'd11.product_advance_evidence.v2',
        numeric.namespace,output.operation_id,operation_digest,'d04-joint:'+canonical_digest(component.checkpoint_refs),
        root.binding.execution_id,component.role_start,component.role_end,tuple(members),component.catalogue_hash,
        component.graph_incarnation,numeric.graph_revision,numeric.graph_epoch,component.access_epoch,component.delete_epoch,
        fields_['read_versions_digest'],fields_['snapshot_stamp_digest'],fields_['time_mapping_digest'],fields_['closure_digest'],
        fields_['source_closure_digest'],fields_['absent_reads_digest'],fields_['asset_digest'],numeric.native_manifest_sha256,
        numeric.native_sha256,fields_['numeric_input_digest'],numeric.full_transcript_sha256,numeric.family_transcripts,
        output.write_set_digest,fields_['contribution_consumption_digest'])
    if(persisted_output!=output or _decode_numeric_candidate(canonical_serialize(numeric_row[0]))!=numeric
            or numeric_row[1]!=numeric.receipt_digest or canonical_serialize(numeric_row[2])!=canonical_serialize(asdict(verification))
            or numeric_row[3]!=canonical_digest(asdict(verification))or numeric_row[4]!=expected.digest
            or evidence!=expected or evidence.full_transcript_digest!=numeric.full_transcript_sha256
            or evidence.family_loo_transcripts!=numeric.family_transcripts
            or evidence.output_write_set_digest!=output.write_set_digest
            or adopted['complete_prefix_digest']!=summary.transcript_sha256 or adopted['output_original_digest']!=output.original_digest
            or adopted['numeric_receipt_digest']!=numeric.receipt_digest or adopted['actual_cpu_ns']!=total_cpu
            or adopted['actual_cpu_ms']!=sum(t.measurement.actual_cpu_ms for t in terminals)
            or adopted['chunk_count']!=len(chunks)or adopted['total_step_count']!=root.frozen.plan.total_step_count
            or prefix['math_digest']!=summary.transcript_sha256 or adopted['graph_receipt_digest']!=canonical_digest(graph_receipt)
            or receipt.operation_digest!=evidence.bundle_digest):
        raise ValueError('historical series complete math/member/readout originals differ')
    from .d11_types import runtime_job_key,runtime_cost_settlement_key
    job_ref=runtime_job_key(*root.binding.namespace.as_tuple,root.binding.activity_id,root.binding.job_id).token
    last=terminals[-1].binding
    cost_id='d04-series-cost:'+canonical_digest((last.root_digest,last.start_step_index))[:48]
    cost_ref=runtime_cost_settlement_key(*last.numeric.namespace.as_tuple,last.numeric.activity_id,cost_id).token
    expected_refs={ref for ref,_,_ in _write_set(output.members)}|set(receipt.ledger_refs)|{job_ref,cost_ref}
    if({v.key.token for v in receipt.write_versions}!=expected_refs or job.get('phase')!='completed'
            or job.get('usage_digest')!=canonical_digest({'cpu_ms':adopted['actual_cpu_ms']})or job.get('result_ref')!=root.root_ref):
        raise ValueError('historical series final atomic worker/output/CPU set differs')
    return root,chunks,numeric,output,summary
