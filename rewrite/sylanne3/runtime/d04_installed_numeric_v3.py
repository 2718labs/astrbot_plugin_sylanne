"""Installed W01 numeric work: actual budget/job first, then frozen 72D input.

The SQL Graph CAS remains inside the same prepare transaction. A failed input
freeze rolls back the signed quote, reservation, job and Graph projection.
No CPU claim or native execution happens while SQL or a Graph lock is held.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import time

from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, owner_grant_key
from ..runtime_contracts import (AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch,
    RUNTIME_SCHEMA, VersionGuard, VersionedRef, canonical_digest, canonical_serialize)
from ..authority_service.d04_numeric_contract_v3 import D04NumericBindingV3, WORK_KIND
from ..domains.d04.joint_state_output_v1 import JointStateFrozenPredecessorsV1, JointStatePredecessorV1
from ..host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
from .budget import get_budget_lease, require_budget_family_admissible, reserve_budget
from .c02_bundle_codec import c02_bundle_from_wire
from .d04_appraisal_driver_v3 import record_d04_original_in_transaction_v3
from .d04_current_joint_replay_input_v2 import read_current_joint_replay_input_in_transaction_v2
from .d04_installed_stage_fence_v3 import run_installed_d04_stage_v3, TABLE as STAGE_TABLE
from .d04_joint_product_assembly_v3 import D04JointProductPreparationV3
from .d04_numeric_cost_v3 import D04NumericPreparedV3, build_d04_numeric_input_payload_v3, read_d04_numeric_prepared_v3
from .d04_numeric_policy_v3 import AdminD04JointNumericPolicyV3
from .d04_product_pipeline_v3 import _commit, ids as appraisal_ids
from .d04_semantic_mapping_v3 import D04RoleClockOriginalV3, freeze_current_d04_joint_evidence_inputs_v3, evidence_payload_v3
from .d11_types import job_graph_write, runtime_cost_settlement_key
from .issuers import ResourceQuote
from .jobs import PersistentJob, create_job, acquire_job


@dataclass(frozen=True, slots=True)
class D04PreparedExecutionV3:
    prepared: D04NumericPreparedV3
    preparation: D04JointProductPreparationV3
    evidence_inputs: object
    holder: str
    worker_fence: int


def numeric_ids_v3(namespace, c02_id):
    suffix = canonical_digest(("d04.installed_numeric.v3", namespace, c02_id))[:48]
    return {key: "d04-numeric-" + key + ":" + suffix
        for key in ("operation", "activity", "job", "quote", "execution", "input", "reservation", "worker")}


def _utc(now):
    return datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")


def _drive_original(db, namespace, c02_operation_id):
    operation = "d04-drive:" + appraisal_ids(namespace, c02_operation_id)["operation"]
    row = db.execute(f"SELECT receipt_json FROM {STAGE_TABLE} WHERE bot=? AND persona=? AND operation_id=? AND stage='drive'",
        (*namespace.as_tuple, operation)).fetchone()
    if row is None or row[0] is None:
        raise ValueError("D04 numeric work requires an actually adopted semantic drive")
    raw = json.loads(row[0])
    if raw.get("status") != "drive_adopted":
        raise ValueError("D04 semantic drive is not adopted")
    clock = D04RoleClockOriginalV3(**{**raw["clock"], "member_predecessor_cursors":
        tuple(tuple(pair) for pair in raw["clock"]["member_predecessor_cursors"])})
    return raw, clock


def _advance_numeric_job_observation_v3(graph, db, verifier, before, before_epoch, after, after_epoch, job, receipt, identity):
    """Derive a target-location scope only from this transaction's sole job CAS."""
    from .d04_owner_initialization_v3 import InstalledD04AuthoredTopologyVerifierV3
    from .jobs import get_job
    if type(verifier) is not InstalledD04AuthoredTopologyVerifierV3 or not db.in_transaction:
        raise ValueError("D04 job scope derivation requires the installed verifier and own transaction")
    original = verifier._location_observation
    if original is None:
        raise ValueError("D04 numeric job has no independently observed initial scope")
    scope, observed = original
    write = job_graph_write(job)
    operation = "d04-numeric-running:" + identity["operation"]
    event = db.execute("SELECT reads,epoch_reads,revisions,invalidated,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*scope.namespace.as_tuple, identity["activity"], operation)).fetchone()
    current = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
    history = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=1",
        (write.key.token,)).fetchone()
    if (scope.graph_revision != before.graph_revision or scope.graph_epoch != before_epoch
            or before.requirements != after.requirements or after.graph_revision != before.graph_revision + 1
            or after_epoch.revision != before_epoch.revision + 1 or receipt.epoch != after_epoch
            or receipt.status != "committed" or receipt.revisions != (GraphVersion(write.key, 1),) or receipt.invalidated
            or graph._v2_graph_stamp(scope.namespace) != (after, after_epoch)
            or not graph._anchor_matches(before.requirements, scope.pinned_anchor)
            or event is None or json.loads(event[0]) != [[write.key.token, 0]]
            or json.loads(event[1]) != [[*scope.namespace.as_tuple, before_epoch.revision]]
            or json.loads(event[2]) != [[write.key.token, 1]] or json.loads(event[3]) != [] or event[4] != after_epoch.revision
            or current is None or current[0] != 1 or current[2] != 1 or json.loads(current[1]) != write.value
            or history != (current[1], 1, *scope.namespace.as_tuple, identity["activity"], operation)
            or get_job(db, job.job_id) != job or job.phase != "running" or job.cancel_epoch != 0 or job.fence != 1
            or job.lease_holder != identity["worker"] or job.operation_id != identity["operation"]
            or job.continuation.get("input_original_ref") != identity["input"]):
        raise ValueError("D04 observed target scope cannot be advanced by another Graph mutation")
    derived_scope = replace(scope, graph_revision=after.graph_revision, graph_epoch=after_epoch)
    reader = graph._GraphCoordinator__d04_semantic_mapping_reader
    semantic = reader._fence.get()
    if (semantic is None or semantic[0] != scope or semantic[1] != observed.guard
            or reader._location.get() != observed):
        raise ValueError("D04 numeric job requires the same independently observed semantic location")
    # Both readers consume only this narrowly proven one-job CAS. Their
    # surrounding contexts discard this derived scope on rollback or exit.
    reader._fence.set((derived_scope, semantic[1], semantic[2]))
    verifier._location_observation = (derived_scope, observed)


def _freeze_product(graph, db, bundle, identity, *, metadata, epoch, clock, root_ref,
        qualification, conversation, deadline, job, topology_verifier):
    namespace, policy = bundle.installation_policy.namespace, bundle.installation_policy
    store = graph._GraphCoordinator__store
    rights = graph._deletion_epochs_locked(db, namespace)
    provider = graph._GraphCoordinator__providers.get("d04")
    if provider is None or provider[0]._active_scheme is None:
        raise ValueError("D04 installed current scheme missing")
    current = read_current_joint_replay_input_in_transaction_v2(db, namespace=namespace,
        registry=store._registry, scheme=provider[0]._active_scheme, root_ref=root_ref,
        role_start=clock.role_start, role_end=clock.role_end,
        expected_query_epoch=QueryEpoch(namespace, "all", epoch.revision),
        expected_graph_incarnation=metadata.requirements.graph_incarnation,
        expected_graph_revision=metadata.graph_revision, expected_access_epoch=rights[0],
        expected_delete_epoch=rights[1], audience=(conversation,), purpose="expression",
        authored_topology_verifier=topology_verifier)
    keys = {row.key: row.revision for row in current.component.read_versions}
    from .d04_contribution_consumption_v3 import current_contribution_allocations_v3
    for ledger_key, _allocation in current_contribution_allocations_v3(db, namespace, current.drives):
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (ledger_key.token,)).fetchone():
            raise ValueError("D04 event contribution has already been consumed")
        keys[ledger_key] = 0
    from .d04_numeric_cost_v3 import numeric_cost_operation_v3
    cost_key = runtime_cost_settlement_key(*namespace.as_tuple, identity["activity"], numeric_cost_operation_v3(namespace, identity["operation"]))
    if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (cost_key.token,)).fetchone():
        raise ValueError("D04 numeric actual CPU already has a Graph settlement")
    keys[cost_key] = 0
    projected_job = job_graph_write(job)
    job_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (projected_job.key.token,)).fetchone()
    if job_row is None or job_row[2] != 1 or json.loads(job_row[1]) != projected_job.value:
        raise ValueError("D04 numeric running job projection is missing")
    keys[projected_job.key] = job_row[0]
    atoms = []
    for key, revision in sorted(keys.items(), key=lambda row: row[0].token):
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if (0 if row is None else row[0]) != revision:
            raise ValueError("D04 actual numeric read changed during prepare")
        atoms.append(GraphAtom(key, 0, {}, False) if row is None
            else GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])))
    snapshot = GraphSnapshot(tuple(atoms), (epoch,))
    predecessors = []
    for block, checkpoint in zip(current.component.block_drives, current.checkpoints):
        state = snapshot.get(block.graph_state_version.key)
        if state is None or not state.valid or block.predecessor_receipt_digest is None:
            raise ValueError("D04 actual predecessor state/original is absent")
        value = store._registry.spec(state.key.type_name).validator(state.value)
        predecessors.append(JointStatePredecessorV1(block.checkpoint_ref,
            block.checkpoint_version.revision, checkpoint, state.key.token, state.revision,
            value, block.predecessor_receipt_digest))
    reads = tuple(GraphVersion(atom.key, atom.revision) for atom in snapshot.atoms)
    inputs = tuple(sorted({drive.source_ref for drive in current.drives}))
    from ..graph_coordinator import _operation_capability_ref
    actor = graph._GraphCoordinator__content_fence_v2.installation_grant.subject
    capability = _operation_capability_ref(namespace, actor, "d04", frozenset({"d04", "d11"}),
        metadata.requirements.activation_generation, identity["operation"])
    authority = AuthorityContext(actor,
        "d04", capability, namespace, ("activity", "event", "persona"),
        "expression", (conversation,), "d04.installed_numeric.v3", metadata.requirements.activation_generation, job.fence)
    envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(identity["activity"], None,
        identity["operation"], "joint_advance", identity["operation"], canonical_digest({"input_refs": list(inputs)})),
        authority, VersionGuard(reads, (current.component.query_epoch,), rights[0], rights[1],
            store._registry.catalogue_hash, policy.scheme_version, policy.operator_version, policy.policy_version,
            (), (), (VersionedRef(identity["quote"], 1),)),
        qualification, inputs, job.budget_ref, deadline, time.monotonic() + max(0, deadline - time.time()),
        "d04-role-interval:" + canonical_digest(asdict(clock))[:48], (identity["input"],))
    return D04JointProductPreparationV3(envelope, current,
        JointStateFrozenPredecessorsV1(namespace, identity["operation"], tuple(predecessors)), snapshot)


def prepare_post_c02_joint_numeric_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    policy = bundle.d04_joint_numeric
    if type(policy) is not AdminD04JointNumericPolicyV3:
        raise ValueError("explicit installed D04 joint numeric limits are required")
    namespace, installation = policy.namespace, bundle.installation_policy
    identity = numeric_ids_v3(namespace, c02_operation_id)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    output_policy = graph._GraphCoordinator__d04_installed_joint_output_policy
    reader = graph._GraphCoordinator__d04_semantic_mapping_reader
    installed = read_installed_d04_numeric_identity_v3(assembly.package_root, installation.manifest_digest)
    topology = graph._installed_d04_authored_topology_verifier_v3()
    prepared_result = []
    def commit(db, metadata, epoch, now, guard, role, current):
        if read_d04_numeric_prepared_v3(db, namespace, identity["operation"]) is not None:
            raise ValueError("D04 immutable numeric preparation must be resumed through its original execution")
        drive, clock = _drive_original(db, namespace, c02_operation_id)
        resource = graph._GraphCoordinator__d02_issuer
        grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, policy.lease_id)
        lease = get_budget_lease(db, policy.lease_id)
        if ((policy.namespace, policy.installation_id, policy.grant_id, policy.grant_version) !=
                (installation.namespace, installation.installation_id, grant.grant_id, grant.version)
                or (grant.bot_id, grant.persona_id) != namespace.as_tuple
                or (lease.bot_id, lease.persona_id) != namespace.as_tuple or lease.state != "active"
                or grant.lease_id != lease.lease_id or grant.currency != lease.currency
                or WORK_KIND not in grant.allowed_work_kinds or grant.valid_until_utc <= now
                or policy.cpu_ceiling_ms > grant.max_ceiling.get("cpu_ms", 0)):
            raise ValueError("D04 current numeric CPU authority differs")
        require_budget_family_admissible(db, lease.lease_id)
        deadline = min(now + policy.job_lifetime_seconds, grant.valid_until_utc)
        snapshot_ref = "d04-numeric-input:" + canonical_digest((identity["operation"], source_ref, drive["mapping_digest"], asdict(clock)))[:48]
        continuation = {"schema": "d04.installed-numeric-continuation.v3", "c02_operation_id": c02_operation_id,
            "source_ref": source_ref, "input_original_ref": identity["input"], "execution_id": identity["execution"],
            "mapping_ref": drive["mapping_ref"], "mapping_digest": drive["mapping_digest"]}
        job = PersistentJob(identity["job"], identity["operation"], identity["activity"], None, *namespace.as_tuple,
            snapshot_ref, "queued", WORK_KIND, continuation, None, _utc(deadline), lease.lease_id,
            installed["algorithm_id"], {"algorithm": installed["algorithm_build_digest"], "resource_quote": identity["quote"] + ":1"},
            None, None, 0, 0, {}, None)
        quote = ResourceQuote(identity["quote"], 1, *namespace.as_tuple, identity["activity"], identity["operation"], None,
            lease.lease_id, WORK_KIND, snapshot_ref, deadline, installed["algorithm_id"], job_graph_write(job).key.token,
            (), (), {"cpu_ms": policy.cpu_ceiling_ms}, None, deadline)
        resource.issue_quote(db, quote)
        if resource.original_signed_quote(db, quote.quote_id, 1) != quote:
            raise ValueError("D04 actual signed numeric quote differs")
        db.execute("INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)",
            (*namespace.as_tuple, "resource_lease", quote.quote_id, "1"))
        reserve_digest = canonical_digest(("d04.numeric-reservation.v3", identity, canonical_digest(quote), continuation))
        reserved = reserve_budget(db, lease.lease_id, identity["reservation"], reserve_digest, quote.ceiling)
        if reserved.status != "reserved":
            raise ValueError("D04 actual numeric CPU reservation is unavailable")
        create_job(db, job, identity["operation"], canonical_digest((job, quote)))
        job = acquire_job(db, job.job_id, identity["worker"], now_utc=_utc(now), lease_seconds=policy.job_lifetime_seconds)
        write = job_graph_write(job)
        existing = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if existing is not None:
            raise ValueError("D04 new numeric work already has a Graph job")
        receipt = _commit(graph, db, metadata, epoch, "d04-numeric-running:" + identity["operation"], identity["activity"], now,
            (write,), (GraphVersion(write.key, 0),), "d04.numeric_running_preparation.v3")
        before_metadata, before_epoch = metadata, epoch
        metadata, epoch = graph._v2_graph_stamp(namespace)
        _advance_numeric_job_observation_v3(graph, db, topology, before_metadata, before_epoch,
            metadata, epoch, job, receipt, identity)
        original = db.execute("SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple, c02_operation_id)).fetchone()
        if original is None:
            raise ValueError("D04 numeric source has no actual C02 original")
        qualification = c02_bundle_from_wire(original[0]).envelope.source_qualification
        preparation = _freeze_product(graph, db, bundle, identity, metadata=metadata, epoch=epoch, clock=clock,
            root_ref=drive["root_ref"], qualification=qualification, conversation=current[1].conversation_ref,
            deadline=deadline, job=job, topology_verifier=topology)
        evidence = freeze_current_d04_joint_evidence_inputs_v3(db, preparation, clock=clock,
            installed_output_policy=output_policy, installed_mapping_reader=reader)
        grant_ref = owner_grant_key(*namespace.as_tuple).token
        owner_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (grant_ref,)).fetchone()
        if owner_row is None or owner_row[2] != 1:
            raise ValueError("D04 numeric current Owner Graph grant is missing")
        owner_digest = canonical_digest(json.loads(owner_row[1]))
        payload, _ = build_d04_numeric_input_payload_v3(preparation, evidence,
            installation_id=installation.installation_id, owner_grant_ref=grant_ref,
            owner_grant_revision=owner_row[0], owner_grant_digest=owner_digest, **installed,
            max_iterations=policy.max_iterations, tolerance=policy.tolerance)
        payload["command_envelope"] = evidence_payload_v3(preparation.envelope)
        payload["worker_original"] = {"holder": job.lease_holder, "fence": job.fence,
            "cancel_epoch": job.cancel_epoch, "lease_expires_utc": job.lease_expires_utc, "deadline_utc": job.deadline_utc}
        payload["numeric_policy"] = evidence_payload_v3(policy)
        binding = D04NumericBindingV3(namespace, metadata.requirements.authority_id,
            metadata.requirements.authority_namespace, installation.installation_id,
            metadata.requirements.activation_generation, grant_ref, owner_row[0], owner_digest,
            identity["operation"], identity["execution"], job.job_id, identity["activity"], identity["input"],
            canonical_digest(payload), installed["algorithm_id"], installed["algorithm_build_digest"],
            installed["native_manifest_sha256"], installed["native_sha256"], installed["output_policy_digest"],
            quote.quote_id, quote.version, canonical_digest(quote), lease.lease_id,
            identity["reservation"], reserve_digest, policy.cpu_ceiling_ms,
            tuple(sorted({item.family_id for item in preparation.current.families})), job.deadline_utc)
        reserve = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            (*namespace.as_tuple, identity["reservation"])).fetchone()
        prepared = D04NumericPreparedV3(binding, canonical_serialize(payload), canonical_serialize(quote),
            reserve[0], canonical_serialize(asdict(job)), identity["input"])
        record_d04_original_in_transaction_v3(db, namespace, "numeric_prepared", binding.operation_id, asdict(prepared))
        from .d04_numeric_accounting_prepared_v3 import record_numeric_accounting_prepared_v3
        record_numeric_accounting_prepared_v3(db, prepared)
        prepared_result.append(D04PreparedExecutionV3(prepared, preparation, evidence, job.lease_holder, job.fence))
        return {"status": "numeric_prepared", "operation_id": identity["operation"], "prepared_digest": prepared.digest,
            "binding_digest": binding.digest, "job_id": job.job_id, "worker_fence": job.fence}
    run_installed_d04_stage_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id, source_ref=source_ref,
        operation_id="d04-numeric-prepare:" + identity["operation"], stage="numeric_prepare",
        request_digest=canonical_digest(("d04.numeric-prepare.v3", namespace, c02_operation_id, source_ref, asdict(policy), installed)),
        commit=commit, semantic=True, fence_observer=lambda scope: topology.observe_current_location_for_fence_v3(
            graph._GraphCoordinator__content_fence_v2, scope))
    if len(prepared_result) != 1:
        raise ValueError("D04 numeric original requires current installed original recovery")
    return prepared_result[0]


@dataclass(frozen=True, slots=True)
class D04ExecutedNumericV3:
    prepared: D04NumericPreparedV3
    terminal: object | None
    status: str


@dataclass(frozen=True, slots=True)
class _MeasuredNumericV3:
    ready: D04PreparedExecutionV3
    claim: object
    measurement: object
    artifact: object


def _pending_measured(graph):
    values = getattr(graph, "_GraphCoordinator__pending_numeric_measurements_v3", None)
    if values is None:
        values = {}
        graph._GraphCoordinator__pending_numeric_measurements_v3 = values
    return values


def _flush_actual_measurement_v3(graph, measured):
    """Retry only this already measured claim, never the native executor."""
    authority = graph._GraphCoordinator__c04_authority_port_v3
    ready, claim, measurement, artifact = measured.ready, measured.claim, measured.measurement, measured.artifact
    prepared, binding = ready.prepared, ready.prepared.binding
    for _ in range(2):
        try:
            closure = authority.numeric_cost_inspect(binding)
            if closure is not None:
                if closure.claim != claim or closure.measurement != measurement:
                    raise ValueError("D04 recovered cost closure changes the actual local measurement")
                _pending_measured(graph).pop(binding.digest, None)
                return D04ExecutedNumericV3(prepared, closure, "execution_completed_adoption_not_adopted")
            original_claim, terminal = authority.numeric_inspect(binding)
            if original_claim != claim:
                raise ValueError("D04 pending local measurement lost its actual independent claim")
            if terminal is None:
                gate = authority.numeric_original_append(binding, claim)
                saved = _persist_numeric_measurement_v3(graph, ready, claim, measurement, artifact, gate)
                terminal = (authority.numeric_cost_only(binding, claim, measurement)
                    if measurement.status == "completed" and not saved
                    else authority.numeric_terminal(binding, claim, measurement))
            if terminal.measurement != measurement:
                raise ValueError("D04 actual terminal changes the measured CPU or output")
            _pending_measured(graph).pop(binding.digest, None)
            return D04ExecutedNumericV3(prepared, terminal,
                "execution_completed_adoption_not_adopted" if getattr(terminal, "adoption_allowed", True) is False else "execution_terminal")
        except (RuntimeError, OSError, TimeoutError):
            # The exact live measured object stays bounded to this execution.
            # A later scheduler retry can append it after reconnection; process
            # death before durable measurement still leaves claim-only unknown.
            continue
    return D04ExecutedNumericV3(prepared, None, "measured_local_append_pending")


def _ready_from_original_v3(prepared):
    from .d04_numeric_artifact_v3 import decode_d04_numeric_prepared_input_v3
    value = decode_d04_numeric_prepared_input_v3(prepared)
    return D04PreparedExecutionV3(prepared, value.preparation, value.evidence_inputs, value.holder, value.worker_fence)


def _persist_numeric_measurement_v3(graph, ready, claim, measurement, artifact, gate):
    from ..authority_service.d04_numeric_claim_bridge_v3 import D04NumericOriginalAppendV3
    from .d04_numeric_cost_v3 import record_d04_numeric_claim_in_transaction_v3, record_installed_d04_numeric_measurement_in_transaction_v3
    from .d04_numeric_artifact_v3 import verify_d04_numeric_artifact_commitments_v3, ARTIFACT_KIND
    if (type(gate) is not D04NumericOriginalAppendV3 or gate.binding != ready.prepared.binding
            or gate.claim != claim or gate.prepared_digest != ready.prepared.digest):
        raise ValueError("D04 actual technical append gate differs")
    port = graph._GraphCoordinator__c04_authority_port_v3
    port.numeric_validate_gate(gate.binding, gate)
    store = graph._GraphCoordinator__store
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            metadata, epoch = graph._v2_graph_stamp(gate.binding.namespace)
            current_wire = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                gate.binding.namespace.as_tuple).fetchone()
            if current_wire != (gate.before_requirements_json,) or metadata.graph_revision != gate.before_graph_revision:
                raise ValueError("D04 technical original Graph/storage cohort changed")
            if gate.content_artifact_permitted:
                if read_d04_numeric_prepared_v3(db, gate.binding.namespace, gate.binding.operation_id) != ready.prepared:
                    raise ValueError("D04 original preparation changed before measured append")
                if artifact is not None:
                    verify_d04_numeric_artifact_commitments_v3(ready.prepared, claim, measurement, artifact)
                    record_d04_original_in_transaction_v3(db, gate.binding.namespace, ARTIFACT_KIND, gate.binding.operation_id, artifact)
            record_d04_numeric_claim_in_transaction_v3(db, ready.prepared, claim)
            record_installed_d04_numeric_measurement_in_transaction_v3(db, ready.prepared, claim, measurement)
            if graph._v2_graph_stamp(gate.binding.namespace) != (metadata, epoch):
                raise ValueError("D04 technical append may not mutate the business Graph")
            db.commit()
        except BaseException:
            db.rollback()
            raise
    # The durable terminal append consumes this actual accounting permit.
    # Ordinary finish would expose a race between measurement and terminal.
    return bool(gate.content_artifact_permitted and artifact is not None)


def execute_post_c02_joint_numeric_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    """Execute only a newly acknowledged Authority claim; resume consumes none."""
    import os
    from ..authority_service.c09_process_identity_v1 import read_process_identity_v1
    from ..authority_service.d04_numeric_contract_v3 import D04NumericMeasurementV3, from_wire
    from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from .d04_appraisal_driver_v3 import read_d04_original_v3
    from .d04_numeric_artifact_v3 import encode_d04_numeric_artifact_v3
    from .d04_numeric_cost_v3 import measure_installed_d04_numeric_v3
    from .d04_joint_product_assembly_v3 import run_installed_d04_joint_product_v3
    graph._admin(bootstrap)
    authority = graph._GraphCoordinator__c04_authority_port_v3
    if type(authority) is not InstalledC04AuthorityPortV3 or authority._bundle is not bundle:
        raise ValueError("D04 numeric executor needs the actual installed paired Authority port")
    namespace = bundle.installation_policy.namespace
    identity = numeric_ids_v3(namespace, c02_operation_id)
    store = graph._GraphCoordinator__store
    with store._lock:
        prepared = read_d04_numeric_prepared_v3(store._db, namespace, identity["operation"])
    ready = (prepare_post_c02_joint_numeric_v3(graph, bootstrap, bundle,
        c02_operation_id=c02_operation_id, source_ref=source_ref) if prepared is None else _ready_from_original_v3(prepared))
    prepared, binding = ready.prepared, ready.prepared.binding
    original_job = json.loads(prepared.job_payload_json)
    if (original_job["continuation"].get("c02_operation_id") != c02_operation_id
            or original_job["continuation"].get("source_ref") != source_ref):
        raise ValueError("D04 numeric retry belongs to another original C02 source")
    closure = authority.numeric_cost_inspect(binding)
    if closure is not None:
        _pending_measured(graph).pop(binding.digest, None)
        return D04ExecutedNumericV3(prepared, closure, "execution_completed_adoption_not_adopted")
    claim, terminal = authority.numeric_inspect(binding)
    if terminal is not None:
        _pending_measured(graph).pop(binding.digest, None)
        return D04ExecutedNumericV3(prepared, terminal, "execution_terminal")
    if claim is not None:
        pending = _pending_measured(graph).get(binding.digest)
        if pending is not None:
            if pending.ready.prepared != prepared or pending.claim != claim:
                raise ValueError("D04 pending measured execution identity differs")
            return _flush_actual_measurement_v3(graph, pending)
        with store._lock:
            observed = read_d04_original_v3(store._db, namespace, "numeric_measurement", binding.operation_id)
            artifact = read_d04_original_v3(store._db, namespace, "numeric_artifact", binding.operation_id)
        if observed is None:
            return D04ExecutedNumericV3(prepared, None, "claimed_execution_unknown")
        measurement = from_wire(observed[0]["measurement"], D04NumericMeasurementV3)
        measured = _MeasuredNumericV3(ready, claim, measurement, None if artifact is None else artifact[0])
        _pending_measured(graph)[binding.digest] = measured
        return _flush_actual_measurement_v3(graph, measured)
    # Fail strict wire/DTO incompatibility before consuming any CPU authority.
    if _ready_from_original_v3(prepared) != ready:
        raise ValueError("D04 immutable prepared codec differs from its original installed input")
    if _pending_measured(graph):
        raise ValueError("D04 another actual measured execution is awaiting its durable append")
    executor = "d04-executor:" + canonical_digest(read_process_identity_v1(os.getpid()))
    # A lost claim response exits here. A retry inspects the consumed claim;
    # it must never infer from local absence that native execution is allowed.
    claim = authority.numeric_claim(binding, executor)
    if store._db.in_transaction or store._lock._is_owned():
        raise RuntimeError("D04 native execution may not hold a Graph transaction or lock")
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    policy = bundle.d04_joint_numeric
    product, measurement, error = measure_installed_d04_numeric_v3(prepared, claim,
        lambda _: run_installed_d04_joint_product_v3(ready.preparation, installation=assembly,
            output_policy=graph._GraphCoordinator__d04_installed_joint_output_policy,
            max_iterations=policy.max_iterations, tolerance=policy.tolerance))
    artifact = None
    if error is None:
        try:
            artifact = encode_d04_numeric_artifact_v3(prepared, claim, product)
        except (ValueError, TypeError, OverflowError):
            # The actual completed CPU measurement remains exactly what ran.
            # Missing proof is a cost-only close, never a fabricated failure.
            artifact = None
    measured = _MeasuredNumericV3(ready, claim, measurement, artifact)
    _pending_measured(graph)[binding.digest] = measured
    return _flush_actual_measurement_v3(graph, measured)
