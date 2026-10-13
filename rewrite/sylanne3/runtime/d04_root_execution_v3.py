"""Durable, explicitly Owner-authorized root CPU preparation before native math."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from uuid import UUID
from ..authority_service.d04_root_execution_contract_v3 import D04RootExecutionBindingV3
from ..domains.d04.authored_lineage_v3 import encode_authored_root_candidate_v3
from ..graph_types import owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..host.installed_d04_root_build_v3 import read_installed_d04_root_identity_v3
from ..host.installed_d04_root_resources import load_installed_d04_root_preset_v3
from .budget import get_budget_lease, reserve_budget, require_budget_family_admissible
from .d04_appraisal_driver_v3 import read_d04_original_v3, record_d04_original_in_transaction_v3
from .d04_root_selection_v3 import read_current_root_execution_selection_v3
from .d11_d04_root_freeze_v3 import ROOT_WORK_KIND_V3
from .issuers import ResourceQuote


@dataclass(frozen=True, slots=True)
class D04RootPreparedExecutionV3:
    binding: D04RootExecutionBindingV3
    input_payload_json: str
    quote_payload_json: str
    reserve_receipt_json: str
    parent_budget_original_json: str
    signed_grant_payload_json: str
    signed_grant_signature: str
    schema: str = "d04.authored-root-prepared.v3"

    @property
    def digest(self):
        return canonical_digest(asdict(self))


def root_execution_ids_v3(namespace, operation_id):
    key = canonical_digest(("d04.authored-root-execution.v3", namespace, operation_id))[:48]
    return {name: "d04-root-" + name + ":" + key for name in ("input", "execution", "quote", "reservation", "activity")}


def read_root_prepared_v3(db, namespace, operation_id):
    saved = read_d04_original_v3(db, namespace, "root_prepared", operation_id)
    if saved is None:
        return None
    raw, digest = saved
    if type(raw) is not dict or set(raw) != set(D04RootPreparedExecutionV3.__dataclass_fields__):
        raise ValueError("root CPU preparation fields differ")
    body = raw["binding"]
    binding = D04RootExecutionBindingV3(**{**body, "namespace": NamespaceId(**body["namespace"])})
    original = D04RootPreparedExecutionV3(**{**raw, "binding": binding})
    if (binding.namespace != namespace or binding.operation_id != operation_id or original.digest != digest
            or original.schema != "d04.authored-root-prepared.v3"
            or canonical_digest(json.loads(original.input_payload_json)) != binding.input_digest):
        raise ValueError("root CPU preparation identity differs")
    for text in (original.input_payload_json, original.quote_payload_json, original.reserve_receipt_json,
                 original.parent_budget_original_json, original.signed_grant_payload_json):
        if canonical_serialize(json.loads(text)) != text:
            raise ValueError("root CPU preparation contains noncanonical original bytes")
    return original


def prepare_current_root_execution_v3(graph, authority, lease, *, operation_id, compiled_digest,
        parent_budget_lease_ref, preset):
    parsed = UUID(operation_id)
    if parsed.version != 4 or str(parsed) != operation_id:
        raise ValueError("root CPU requires the original canonical Owner UUID4")
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.installation_policy.namespace != authority.namespace:
        raise ValueError("root CPU actual installation is absent")
    installed = read_installed_d04_root_identity_v3(assembly.package_root, assembly.installation_policy.manifest_digest)
    actual_preset = load_installed_d04_root_preset_v3(assembly.package_root, assembly.installation_policy.manifest_digest)
    if actual_preset != preset:
        raise ValueError("root CPU requested preset differs from installed original")
    namespace, policy = authority.namespace, assembly.installation_policy
    identity = root_execution_ids_v3(namespace, operation_id)
    request_digest = canonical_digest(("d04.root.prepare.v3", namespace, operation_id, compiled_digest,
        parent_budget_lease_ref, authority.actor, installed))
    prepare_operation = "d04-root-prepare:" + operation_id
    def commit(db, metadata, epoch, now, owner, scope):
        prior = read_root_prepared_v3(db, namespace, operation_id)
        if prior is not None:
            if json.loads(prior.input_payload_json)["request_digest"] != request_digest:
                raise ValueError("root execution original request changed")
            return {"operation_id": prepare_operation, "root_operation_id": operation_id,
                "status": "root_cpu_prepared", "prepared_digest": prior.digest, "binding_digest": prior.binding.digest}
        selection = read_current_root_execution_selection_v3(graph, db, authority,
            operation_id=operation_id, compiled_digest=compiled_digest, preset=preset)
        issuer = graph._GraphCoordinator__d11_issuer
        resource = graph._GraphCoordinator__d02_issuer
        budget = get_budget_lease(db, parent_budget_lease_ref)
        grant = issuer.current_budget_grant(db, parent_budget_lease_ref)
        if ((budget.bot_id, budget.persona_id) != namespace.as_tuple
                or (grant.bot_id, grant.persona_id, grant.lease_id, grant.currency) != (*namespace.as_tuple, budget.lease_id, budget.currency)
                or grant.allowed_work_kinds != (ROOT_WORK_KIND_V3,)
                or set(grant.max_ceiling) != {"thread_cpu_ms"} or grant.max_ceiling["thread_cpu_ms"] <= 0
                or budget.state != "active" or grant.valid_until_utc <= now):
            raise ValueError("root execution lacks its actual signed dedicated CPU budget")
        require_budget_family_admissible(db, budget.lease_id)
        signed_grant, grant_signature = issuer.signed_budget_grant_at_version(db, budget.lease_id, grant.version)
        if signed_grant != grant:
            raise ValueError("root execution original grant changed")
        grant_row = db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?",
            (grant.lease_id, grant.version)).fetchone()
        if grant_row is None or grant_row[1] != grant_signature:
            raise ValueError("root execution actual signed grant original is absent")
        deadline = min(now + 300, grant.valid_until_utc)
        snapshot = "d04-root-snapshot:" + canonical_digest((selection.candidate.digest, selection.read_rows, compiled_digest))[:48]
        quote = ResourceQuote(identity["quote"], 1, *namespace.as_tuple, identity["activity"], operation_id, None,
            budget.lease_id, ROOT_WORK_KIND_V3, snapshot, deadline, installed["algorithm_id"], None, (), (),
            dict(grant.max_ceiling), None, deadline)
        resource.issue_quote(db, quote)
        if resource.original_signed_quote(db, quote.quote_id, 1) != quote:
            raise ValueError("root CPU signed quote did not round trip")
        reserve_digest = canonical_digest(("d04.root.execution-reserve.v3", namespace, operation_id,
            canonical_digest(quote), selection.candidate.digest, selection.read_rows))
        reservation = reserve_budget(db, budget.lease_id, identity["reservation"], reserve_digest, quote.ceiling)
        if reservation.status != "reserved":
            raise ValueError("root CPU actual reservation is unavailable")
        reserve = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            (*namespace.as_tuple, identity["reservation"])).fetchone()
        if reserve is None:
            raise ValueError("root CPU original reservation receipt is absent")
        updated = graph._GraphCoordinator__store.cas_graph_recovery_metadata(metadata, metadata.requirements,
            _capability=graph._GraphCoordinator__graph_capability)
        original_owner = asdict(owner)
        for name in ("capabilities", "purposes", "audiences"):
            original_owner[name] = sorted(original_owner[name])
        token, signed_request = graph._GraphCoordinator__owner_session_proofs[lease]
        input_payload = {"schema": "d04.authored-root-input.v3", "namespace": asdict(namespace),
            "operation_id": operation_id, "request_digest": request_digest, "prepare_operation_id": prepare_operation,
            "prepare_attempt_id": scope.operation_id, "prepare_permit_digest": canonical_digest(scope.permit),
            "owner": original_owner, "owner_session_id": signed_request.credential_id,
            "owner_session_binding_digest": canonical_digest((token, signed_request)),
            "owner_session_request_json": canonical_serialize(asdict(signed_request)),
            "compiled_digest": compiled_digest, "new_head": asdict(selection.new_head),
            "field_input_digest": selection.field_input_digest, "root_input_digest": selection.root_input_digest,
            "candidate": encode_authored_root_candidate_v3(selection.candidate), "read_rows": selection.read_rows,
            "requirements": asdict(updated.requirements), "graph_revision": updated.graph_revision,
            "graph_epoch": epoch.revision, "installed_identity": installed}
        owner_ref = owner_grant_key(*namespace.as_tuple).token
        owner_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (owner_ref,)).fetchone()
        if owner_row is None or owner_row[2] != 1:
            raise ValueError("root CPU actual Owner Graph grant absent")
        binding = D04RootExecutionBindingV3(namespace, metadata.requirements.authority_id,
            metadata.requirements.authority_namespace, policy.installation_id, authority.activation_generation,
            owner_ref, owner_row[0], canonical_digest(json.loads(owner_row[1])), operation_id, identity["execution"],
            identity["input"], canonical_digest(input_payload), installed["algorithm_id"], installed["algorithm_build_digest"],
            installed["native_manifest_sha256"], installed["native_sha256"], installed["output_policy_digest"],
            preset.preset_id, preset.digest, selection.candidate.digest, budget.lease_id, quote.quote_id, 1,
            canonical_digest(quote), identity["reservation"], reserve_digest, grant.max_ceiling["thread_cpu_ms"],
            datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace("+00:00", "Z"))
        prepared = D04RootPreparedExecutionV3(binding, canonical_serialize(input_payload), canonical_serialize(quote),
            reserve[0], canonical_serialize(asdict(budget)), grant_row[0], grant_signature)
        record_d04_original_in_transaction_v3(db, namespace, "root_prepared", operation_id, asdict(prepared))
        # No authored coordinate or Owner session secret is needed to reconcile
        # this actual CPU reservation after content retention ends.
        accounting = {"schema": "d04.authored-root-accounting-prepared.v3", "binding": asdict(binding),
             "prepared_digest": prepared.digest, "quote_payload_json": prepared.quote_payload_json,
             "reserve_receipt_json": prepared.reserve_receipt_json,
             "parent_budget_original_json": prepared.parent_budget_original_json,
             "signed_grant_payload_json": prepared.signed_grant_payload_json,
             "signed_grant_signature": prepared.signed_grant_signature}
        from .d04_root_accounting_prepared_v3 import decode_root_accounting_prepared_payload_v3
        decode_root_accounting_prepared_payload_v3(accounting)
        record_d04_original_in_transaction_v3(db, namespace, "root_accounting_prepared", operation_id, accounting)
        return {"operation_id": prepare_operation, "root_operation_id": operation_id,
            "status": "root_cpu_prepared", "prepared_digest": prepared.digest, "binding_digest": binding.digest}
    graph._owner_domain_write_v3(authority, lease, operation_id=prepare_operation, request_digest=request_digest,
        domains=("d04", "d11", "d12"), capability="workbench.activate", commit=commit,
        new_work_admission=lambda db: graph.local_module_admission.require_v1(
            ("d04", "d11", "d12"), "d04-root:prepare"))
    with graph._GraphCoordinator__store._lock:
        prepared = read_root_prepared_v3(graph._GraphCoordinator__store._db, namespace, operation_id)
    if prepared is None:
        raise ValueError("root execution prepare has no committed original")
    return prepared


@dataclass(frozen=True, slots=True)
class D04ExecutedRootV3:
    prepared: D04RootPreparedExecutionV3
    terminal: object | None
    status: str


def _pending_root_measurements_v3(graph):
    pending = getattr(graph, "_GraphCoordinator__pending_root_measurements_v3", None)
    if pending is None:
        pending = {}
        graph._GraphCoordinator__pending_root_measurements_v3 = pending
    return pending


def _flush_root_measurement_v3(graph, prepared, claim, measurement, artifact):
    port, binding = graph._GraphCoordinator__c04_authority_port_v3, prepared.binding
    for _ in range(2):
        try:
            closure = port.root_cost_inspect(binding)
            if closure is not None:
                if closure.claim != claim or closure.measurement != measurement:
                    raise ValueError("root recovered cost closure changes actual measurement")
                _pending_root_measurements_v3(graph).pop(binding.digest, None)
                return D04ExecutedRootV3(prepared, closure, "execution_completed_adoption_not_adopted")
            actual_claim, terminal = port.root_inspect(binding)
            if actual_claim != claim:
                raise ValueError("root measured original lost its independent claim")
            if terminal is None:
                gate = port.root_original_append(binding, claim)
                _persist_root_measurement_v3(graph, prepared, claim, measurement, artifact, gate)
                terminal = port.root_terminal(binding, claim, measurement)
            if terminal.measurement != measurement:
                raise ValueError("root actual terminal changes original CPU/result")
            _pending_root_measurements_v3(graph).pop(binding.digest, None)
            return D04ExecutedRootV3(prepared, terminal,
                "execution_completed_adoption_not_adopted" if getattr(terminal, "adoption_allowed", True) is False else "execution_terminal")
        except (RuntimeError, OSError, TimeoutError):
            continue
    return D04ExecutedRootV3(prepared, None, "measured_local_append_pending")


def _persist_root_measurement_v3(graph, prepared, claim, measurement, artifact, gate):
    """Append only exact technical originals under Authority's retained gate."""
    from ..authority_service.d04_root_execution_contract_v3 import root_execution_to_wire_v3
    from ..authority_service.d04_root_execution_bridge_v3 import D04RootOriginalAppendV3
    if (type(gate) is not D04RootOriginalAppendV3 or gate.binding != prepared.binding
            or gate.claim != claim or gate.prepared_digest != prepared.digest):
        raise ValueError("root measurement requires its actual Authority technical gate")
    port, store = graph._GraphCoordinator__c04_authority_port_v3, graph._GraphCoordinator__store
    port.root_validate_gate(prepared.binding, gate)
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            before = graph._v2_graph_stamp(prepared.binding.namespace)
            row = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                prepared.binding.namespace.as_tuple).fetchone()
            if row != (gate.before_requirements_json,) or before[0].graph_revision != gate.before_graph_revision:
                raise ValueError("root technical append storage/business identity changed")
            if gate.content_artifact_permitted:
                if read_root_prepared_v3(db, prepared.binding.namespace, prepared.binding.operation_id) != prepared:
                    raise ValueError("root prepared original changed before measurement append")
                if artifact is not None:
                    from ..domains.d04.authored_root_recovery_v3 import decode_authored_root_math_artifact_v3
                    decoded = decode_authored_root_math_artifact_v3(artifact)
                    if (decoded.candidate_digest != prepared.binding.candidate_digest
                            or decoded.operation_id != prepared.binding.operation_id
                            or decoded.artifact_digest != measurement.artifact_digest
                            or decoded.initial_box_proof.proof_digest != measurement.initial_box_proof_digest
                            or decoded.output.issuance_digest != measurement.output_issuance_digest
                            or decoded.output.write_set_digest != measurement.output_write_set_digest):
                        raise ValueError("root measured native artifact commitments differ")
                    record_d04_original_in_transaction_v3(db, prepared.binding.namespace,
                        "root_artifact", prepared.binding.operation_id, artifact)
            record_d04_original_in_transaction_v3(db, prepared.binding.namespace,
                "root_claim", prepared.binding.operation_id, root_execution_to_wire_v3(claim))
            record_d04_original_in_transaction_v3(db, prepared.binding.namespace,
                "root_measurement", prepared.binding.operation_id, root_execution_to_wire_v3(measurement))
            if graph._v2_graph_stamp(prepared.binding.namespace) != before:
                raise ValueError("root technical append cannot change the business Graph")
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return bool(gate.content_artifact_permitted and artifact is not None)


def execute_current_root_execution_v3(graph, authority, lease, *, operation_id,
        compiled_digest, parent_budget_lease_ref, preset):
    """Run one acknowledged root claim outside every Graph lock/transaction."""
    import os
    import threading
    from time import thread_time_ns
    from ..authority_service.c09_process_identity_v1 import read_process_identity_v1
    from ..authority_service.d04_root_execution_contract_v3 import (
        D04RootExecutionMeasurementV3, root_execution_from_wire_v3)
    from ..domains.d04.authored_lineage_v3 import decode_authored_root_candidate_v3
    from ..domains.d04.authored_root_recovery_v3 import (
        execute_authored_root_math_once_v3, encode_authored_root_math_artifact_v3)
    from ..host.installed_d04_output_policy import load_installed_d04_output_policy_v1
    from ..host.installed_tanh_readout_asset import load_installed_tanh_readout_candidate
    from ..native_runtime.loader import load_production_native
    from .c04_authority_port_v3 import InstalledC04AuthorityPortV3

    port, store = graph._GraphCoordinator__c04_authority_port_v3, graph._GraphCoordinator__store
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if (type(port) is not InstalledC04AuthorityPortV3 or assembly is None
            or port._bundle is not assembly.admin_bundle):
        raise ValueError("root execution requires the actual installed Authority composition")
    with store._lock:
        prepared = read_root_prepared_v3(store._db, authority.namespace, operation_id)
    if prepared is None:
        prepared = prepare_current_root_execution_v3(graph, authority, lease,
            operation_id=operation_id, compiled_digest=compiled_digest,
            parent_budget_lease_ref=parent_budget_lease_ref, preset=preset)
    binding = prepared.binding
    raw = json.loads(prepared.input_payload_json)
    if (raw["compiled_digest"] != compiled_digest or binding.parent_budget_lease_ref != parent_budget_lease_ref
            or binding.preset_digest != preset.digest or raw["owner"]["actor"] != authority.actor):
        raise ValueError("root retry differs from its original Owner selection")
    closure = port.root_cost_inspect(binding)
    if closure is not None:
        _pending_root_measurements_v3(graph).pop(binding.digest, None)
        return D04ExecutedRootV3(prepared, closure, "execution_completed_adoption_not_adopted")
    claim, terminal = port.root_inspect(binding)
    if terminal is not None:
        _pending_root_measurements_v3(graph).pop(binding.digest, None)
        return D04ExecutedRootV3(prepared, terminal, "execution_terminal")
    if claim is not None:
        live = _pending_root_measurements_v3(graph).get(binding.digest)
        if live is not None:
            if live[:2] != (prepared, claim):
                raise ValueError("root pending actual measurement identity changed")
            return _flush_root_measurement_v3(graph, *live)
        with store._lock:
            recorded = read_d04_original_v3(store._db, binding.namespace, "root_measurement", operation_id)
            artifact = read_d04_original_v3(store._db, binding.namespace, "root_artifact", operation_id)
        if recorded is None:
            return D04ExecutedRootV3(prepared, None, "claimed_execution_unknown")
        measurement = root_execution_from_wire_v3(recorded[0], D04RootExecutionMeasurementV3)
        live = (prepared, claim, measurement, None if artifact is None else artifact[0])
        _pending_root_measurements_v3(graph)[binding.digest] = live
        return _flush_root_measurement_v3(graph, *live)

    graph.local_module_admission.require_v1(("d04", "d11", "d12"), "d04-root:first_execution")
    # Load and verify the selected package before consuming a once-only claim.
    installed = read_installed_d04_root_identity_v3(assembly.package_root, binding.native_manifest_sha256)
    if installed != raw["installed_identity"]:
        raise ValueError("root installed algorithm identity changed before first execution")
    handle = load_production_native(assembly.package_root, trusted_manifest_sha256=binding.native_manifest_sha256)
    output_policy = load_installed_d04_output_policy_v1(assembly.package_root,
        binding.native_manifest_sha256, require_formal=False, require_backend_runtime=True)
    if output_policy != graph._GraphCoordinator__d04_installed_joint_output_policy:
        raise ValueError("root installed output policy changed")
    readout = load_installed_tanh_readout_candidate(assembly.package_root,
        binding.native_manifest_sha256, preset.assets, expected_readout_id=output_policy.policy.readout_id,
        available_cpu_features=assembly.available_cpu_features)
    candidate = decode_authored_root_candidate_v3(raw["candidate"])
    if candidate.digest != binding.candidate_digest:
        raise ValueError("root original candidate commitment differs")
    incarnation = "d04-root-executor:" + canonical_digest(read_process_identity_v1(os.getpid()))
    if _pending_root_measurements_v3(graph):
        raise ValueError("another measured root awaits its original durable append")
    claim = port.root_claim(binding, incarnation)
    if store._db.in_transaction or store._lock._is_owned():
        raise RuntimeError("root native execution cannot retain a Graph lock or transaction")
    start, thread = thread_time_ns(), threading.get_ident()
    artifact = None
    error = None
    try:
        from ..native_runtime.d04_fixed_trajectory_v2 import bounded_d04_native_cpu_v2
        with bounded_d04_native_cpu_v2(binding.cpu_ceiling_ms):
            product = execute_authored_root_math_once_v3(handle, candidate, readout.asset,
                output_policy.policy, operation_id)
            artifact = encode_authored_root_math_artifact_v3(product)
        if threading.get_ident() != thread:
            raise ValueError("root native work left its measured thread")
    except Exception as exc:
        error = exc
        artifact = None
    actual_cpu_ns = thread_time_ns() - start
    measurement = D04RootExecutionMeasurementV3(binding.digest, claim.claim_id,
        "completed" if error is None else "failed", actual_cpu_ns,
        product.artifact_digest if error is None else None,
        product.initial_box_proof.proof_digest if error is None else None,
        product.output.issuance_digest if error is None else None,
        product.output.write_set_digest if error is None else None,
        None if error is None else type(error).__name__)
    live = (prepared, claim, measurement, artifact)
    _pending_root_measurements_v3(graph)[binding.digest] = live
    return _flush_root_measurement_v3(graph, *live)
