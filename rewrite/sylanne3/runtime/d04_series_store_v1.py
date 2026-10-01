"""Series roots, bounded originals and narrow own-write Graph progression.

Uses graph_d04_originals_v3 and runtime_jobs. No additional state database or
schema is introduced; C09 may erase vector originals while retaining CPU rows.
"""
from dataclasses import asdict, dataclass, replace
import json

from .d04_appraisal_driver_v3 import (read_d04_original_v3, record_d04_original_in_transaction_v3,
    require_current_read_rows_v3)
from .d04_numeric_cost_v3 import read_d04_numeric_prepared_v3, D04NumericPreparedV3
from .d04_installed_numeric_v3 import _ready_from_original_v3, prepare_post_c02_joint_numeric_v3, numeric_ids_v3
from .d04_series_codec_v1 import encode_series_dto_v1, decode_series_dto_v1
from .d04_semantic_mapping_v3 import evidence_payload_v3
from ..authority_service.d04_series_contract_v1 import D04SeriesChunkBindingV1, from_wire, to_wire
from ..native_runtime.d04_joint_product_math import D04JointCompiledInputsV1, compile_d04_joint_product_inputs_v1
from ..native_runtime.d04_series_math_v1 import D04SeriesChunkMathV1, verify_d04_series_chunk_math_v1
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..graph_types import AtomKey


@dataclass(frozen=True, slots=True)
class D04SeriesRootV1:
    root_ref: str
    payload: dict
    digest: str
    prepared: D04NumericPreparedV3
    frozen: D04JointCompiledInputsV1


def series_own_job_ref_v1(root):
    from .d11_types import runtime_job_key
    binding = root.prepared.binding
    return runtime_job_key(*binding.namespace.as_tuple, binding.activity_id, binding.job_id).token


def series_chunk_cost_ref_v1(binding):
    from .d11_types import runtime_cost_settlement_key
    numeric = binding.numeric
    cost_id = "d04-series-cost:" + canonical_digest((binding.root_digest, binding.start_step_index))[:48]
    return runtime_cost_settlement_key(*numeric.namespace.as_tuple, numeric.activity_id, cost_id).token


def read_d04_series_root_v1(db, namespace, root_ref):
    original = read_d04_original_v3(db, namespace, "series_root", root_ref)
    if original is None:
        return None
    payload, digest = original
    prepared = read_d04_numeric_prepared_v3(db, namespace, payload["numeric_operation_id"])
    if (prepared is None or prepared.digest != payload["numeric_prepared_digest"]
            or payload["schema"] != "d04.series-root.v1" or payload["root_ref"] != root_ref):
        raise ValueError("series frozen original/identity changed")
    frozen = decode_series_dto_v1(D04JointCompiledInputsV1, payload["frozen_model"])
    plan = frozen.plan
    from ..native_runtime.d04_fixed_trajectory_v2 import exact_d04_series_step_plan_v1
    expected = exact_d04_series_step_plan_v1(plan.role_start, plan.role_end, family_count=len(frozen.family_drives))
    if plan != expected or payload["plan_digest"] != expected.digest:
        raise ValueError("series compact absolute h policy differs")
    root = D04SeriesRootV1(root_ref, payload, digest, prepared, frozen)
    from .d04_series_initial_original_v1 import require_d04_series_initial_binding_v1
    require_d04_series_initial_binding_v1(root)
    return root


def freeze_post_c02_d04_series_v1(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    graph._admin(bootstrap)
    namespace = bundle.installation_policy.namespace
    identity = numeric_ids_v3(namespace, c02_operation_id)
    root_ref = "d04-series-root:" + canonical_digest((namespace, identity["operation"]))[:48]
    store = graph._GraphCoordinator__store
    with store._lock:
        root = read_d04_series_root_v1(store._db, namespace, root_ref)
        prepared = read_d04_numeric_prepared_v3(store._db, namespace, identity["operation"])
    if root is not None:
        return root
    ready = (_ready_from_original_v3(prepared) if prepared is not None else
        prepare_post_c02_joint_numeric_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id, source_ref=source_ref))
    current = ready.preparation.current
    installation = graph._GraphCoordinator__d04_installed_joint_assembly
    from ..native_runtime.loader import load_production_native
    from ..host.affect_scheme_asset import load_verified_affect_scheme
    policy = bundle.d04_joint_numeric
    handle = load_production_native(installation.package_root,
        trusted_manifest_sha256=installation.installation_policy.manifest_digest)
    scheme = load_verified_affect_scheme(installation.package_root,
        installation.installation_policy.manifest_digest, available_cpu_features=installation.available_cpu_features).scheme
    frozen = compile_d04_joint_product_inputs_v1(handle, installation.package_root, scheme, current.component,
        checkpoints=current.checkpoints, drives=current.drives, families=current.families,
        readout_id=graph._GraphCoordinator__d04_installed_joint_output_policy.policy.readout_id,
        max_iterations=policy.max_iterations, tolerance=policy.tolerance)
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            metadata, epoch = graph._v2_graph_stamp(namespace)
            if (metadata.graph_revision != current.component.graph_revision
                    or epoch.revision != current.component.query_epoch.revision):
                raise ValueError("series model freeze lost its current original Graph stamp")
            require_current_read_rows_v3(db, ready.evidence_inputs.read_rows, namespace)
            # A previously consumed v3 identity cannot be reinterpreted as a
            # series. The service independently enforces this before claiming.
            if any(read_d04_original_v3(db, namespace, kind, identity["operation"]) is not None
                    for kind in ("numeric_claim", "numeric_measurement", "numeric_artifact", "numeric_adoption")):
                raise ValueError("series cannot take over an already consumed numeric-v3 execution")
            payload = {"schema": "d04.series-root.v1", "root_ref": root_ref,
                "numeric_operation_id": ready.prepared.binding.operation_id,
                "numeric_prepared_digest": ready.prepared.digest, "c02_operation_id": c02_operation_id,
                "source_ref": source_ref, "deadline_utc": ready.prepared.binding.deadline_utc,
                "plan_digest": frozen.plan.digest, "frozen_model": encode_series_dto_v1(frozen),
                "output_policy": asdict(graph._GraphCoordinator__d04_installed_joint_output_policy.policy),
                "operator_version": scheme.operator_version,
                "output_policy_sha256": graph._GraphCoordinator__d04_installed_joint_output_policy.policy_sha256,
                "graph_revision": metadata.graph_revision, "graph_epoch": epoch.revision,
                "requirements": asdict(metadata.requirements)}
            record_d04_original_in_transaction_v3(db, namespace, "series_root", root_ref, payload)
            from .d04_series_initial_original_v1 import require_d04_series_initial_original_v1
            require_d04_series_initial_original_v1(db, read_d04_series_root_v1(db, namespace, root_ref))
            db.commit()
        except BaseException:
            db.rollback()
            raise
        return read_d04_series_root_v1(db, namespace, root_ref)


def read_d04_series_chunk_prepared_v1(db, namespace, operation_id):
    saved = read_d04_original_v3(db, namespace, "series_chunk_prepared", operation_id)
    if saved is None:
        return None
    raw, digest = saved
    binding = from_wire(raw["binding"], D04SeriesChunkBindingV1)
    if binding.numeric.namespace != namespace or binding.numeric.operation_id != operation_id:
        raise ValueError("series chunk prepared namespace/operation differs")
    return binding, raw, digest


def read_d04_series_chunk_math_v1(db, namespace, operation_id):
    saved = read_d04_original_v3(db, namespace, "series_chunk_math", operation_id)
    return None if saved is None else decode_series_dto_v1(D04SeriesChunkMathV1, saved[0])


def _read_d04_series_chunk_for_final_verifier_v1(db, namespace, operation_id):
    from .d04_series_codec_v1 import _decode_series_chunk_for_final_verifier_v1
    saved = read_d04_original_v3(db, namespace, "series_chunk_math", operation_id)
    return None if saved is None else _decode_series_chunk_for_final_verifier_v1(saved[0])


def require_d04_series_own_progress_v1(graph, db, root):
    """Only this root's recorded exact job/cost events advance its snapshot.

    Graph revisions, namespace epochs, history values and recovery heads must
    all be explained by the same atomic receipts. Source/deletion/other-domain
    mutations are never widened into a series witness.
    """
    namespace = root.prepared.binding.namespace
    metadata, epoch = graph._v2_graph_stamp(namespace)
    rows = db.execute("SELECT original_ref,payload_json,payload_digest FROM graph_d04_originals_v3 "
        "WHERE bot=? AND persona=? AND kind='series_progress'", namespace.as_tuple).fetchall()
    progress = []
    for ref, _, _ in rows:
        value = read_d04_original_v3(db, namespace, "series_progress", ref)[0]
        if value["root_digest"] == root.digest:
            progress.append(value)
    progress.sort(key=lambda item: item["graph_epoch"])
    expected_revision, expected_epoch = root.payload["graph_revision"], root.payload["graph_epoch"]
    requirements = root.payload["requirements"]
    from .d04_numeric_artifact_v3 import decode_d04_numeric_prepared_input_v3
    original = decode_d04_numeric_prepared_input_v3(root.prepared)
    from .d04_series_initial_original_v1 import require_d04_series_initial_original_v1
    require_d04_series_initial_original_v1(db, root)
    business_rows = tuple(row for row in original.evidence_inputs.read_rows
        if row.ref != series_own_job_ref_v1(root))
    require_current_read_rows_v3(db, business_rows, namespace)
    for item in progress:
        expected_revision += 1
        expected_epoch += 1
        if (item["graph_revision"] != expected_revision or item["graph_epoch"] != expected_epoch
                or item["before_requirements"] != requirements):
            raise ValueError("series own Graph progress is not a contiguous original prefix")
        event = db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            (*namespace.as_tuple, root.prepared.binding.activity_id, item["event_id"])).fetchone()
        prefix = "d04-series-prepare:" if item["event_id"].startswith("d04-series-prepare:") else "d04-series-settle:"
        operation = item["event_id"].removeprefix(prefix)
        prepared = read_d04_series_chunk_prepared_v1(db, namespace, operation)
        if prepared is None or prepared[0].root_digest != root.digest or prepared[0].numeric.job_id != root.prepared.binding.job_id:
            raise ValueError("series progress event is not this root's actual chunk")
        expected_refs = {series_own_job_ref_v1(root)}
        if prefix == "d04-series-settle:":
            expected_refs.add(series_chunk_cost_ref_v1(prepared[0]))
            cost = read_d04_original_v3(db, namespace, "series_chunk_cost_commit", operation)
            terminal = read_d04_original_v3(db, namespace, "series_chunk_terminal", operation)
            from ..authority_service.d04_series_contract_v1 import D04SeriesTerminalV1
            actual = None if terminal is None else from_wire(terminal[0], D04SeriesTerminalV1)
            if (cost is None or actual is None or actual.binding != prepared[0]
                    or cost[0]["terminal_digest"] != actual.digest or cost[0]["binding_digest"] != prepared[0].digest
                    or cost[0]["event_id"] != item["event_id"]):
                raise ValueError("series progress cost lacks its actual binding/terminal")
        if {ref for ref, _ in item["write_versions"]} != expected_refs:
            raise ValueError("series progress changes another runtime job or cost")
        if (event is None or json.loads(event[0]) != item["write_versions"]
                or json.loads(event[1]) != [] or event[2] != expected_epoch):
            raise ValueError("series own event differs from its immutable Graph receipt")
        for ref, revision, digest in item["write_values"]:
            history = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id "
                "FROM graph_history WHERE token=? AND revision=?", (ref, revision)).fetchone()
            if (history is None or history[1:] != (1, *namespace.as_tuple,
                    root.prepared.binding.activity_id, item["event_id"])
                    or canonical_digest(json.loads(history[0])) != digest):
                raise ValueError("series own history is not the exact recorded event")
        target = item["after_requirements"]
        if any(target[name] != requirements[name] for name in requirements
                if name not in {"execution_seq", "execution_digest"}):
            raise ValueError("series progress changes an unrelated recovery dimension")
        requirements = target
    if (metadata.graph_revision != expected_revision or epoch.revision != expected_epoch
            or asdict(metadata.requirements) != requirements):
        raise ValueError("another Graph mutation blocks series business adoption")
    return metadata, epoch


def record_d04_series_progress_v1(graph, db, root, *, before, before_epoch, receipt, event_id, writes):
    metadata, epoch = graph._v2_graph_stamp(root.prepared.binding.namespace)
    if (receipt.status != "committed" or receipt.invalidated or metadata.graph_revision != before.graph_revision + 1
            or epoch.revision != before_epoch.revision + 1):
        raise ValueError("series progression must be one actual uninvalidating Graph event")
    revisions = {version.key.token: version.revision for version in receipt.revisions}
    value = {"schema": "d04.series-own-progress.v1", "root_digest": root.digest,
        "graph_revision": metadata.graph_revision, "graph_epoch": epoch.revision,
        "event_id": event_id, "before_requirements": asdict(before.requirements),
        "after_requirements": asdict(metadata.requirements),
        "write_versions": [[version.key.token, version.revision] for version in receipt.revisions],
        "write_values": [[write.key.token, revisions[write.key.token], canonical_digest(write.value)] for write in writes]}
    return record_d04_original_in_transaction_v3(db, root.prepared.binding.namespace, "series_progress", event_id, value)
