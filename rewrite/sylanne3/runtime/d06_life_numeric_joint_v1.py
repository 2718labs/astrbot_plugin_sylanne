"""Independent Life locator bridge to the real installed D04 CPU protocol.

One current Owner SQL preparation reserves an actual CPU quote, commits the
running job, then freezes the actual root/component. Execution is separately
issued by the existing installed math queue after an actual Authority claim.
No C02 source or message-arrival identity is manufactured. Policies and clocks
are the unchanged installed originals; incomplete native work remains HOLD.
"""
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import time
import weakref

from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, owner_grant_key
from ..runtime_contracts import (AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch,
    RUNTIME_SCHEMA, VersionGuard, VersionedRef, canonical_digest, canonical_serialize)
from ..authority_service.d04_numeric_contract_v3 import D04NumericBindingV3, WORK_KIND
from ..domains.d04.joint_state_output_v1 import JointStateFrozenPredecessorsV1, JointStatePredecessorV1
from ..host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
from .budget import get_budget_lease, require_budget_family_admissible, reserve_budget
from .d04_appraisal_driver_v3 import record_d04_original_in_transaction_v3
from .d04_current_joint_replay_input_v2 import read_current_joint_replay_input_in_transaction_v2
from .d04_installed_numeric_v3 import D04PreparedExecutionV3, _advance_numeric_job_observation_v3
from .d04_joint_product_assembly_v3 import D04JointProductPreparationV3
from .d04_numeric_cost_v3 import D04NumericPreparedV3, build_d04_numeric_input_payload_v3, read_d04_numeric_prepared_v3
from .d04_numeric_policy_v3 import AdminD04JointNumericPolicyV3
from .d04_product_pipeline_v3 import _commit
from .d04_semantic_mapping_v3 import freeze_current_d04_joint_evidence_inputs_v3, evidence_payload_v3
from .d11_types import job_graph_write, runtime_cost_settlement_key
from .issuers import ResourceQuote
from .jobs import PersistentJob, create_job, acquire_job
from .d06_life_numeric_drive_v1 import (PrepareLifeNumericDriveRequestV1,
    read_plan_life_numeric_drive_v1, read_current_life_numeric_drive_v1,
    require_current_life_numeric_drive_v1, OPERATION as DRIVE_OPERATION)

OPERATION = 'prepare_internal_life_numeric_joint'
CONTINUATION_SCHEMA = 'd04.internal-life-numeric-continuation.v1'
_STAGES = {}
_SOURCE_BRIDGES = weakref.WeakValueDictionary()


@dataclass(frozen=True, slots=True)
class PrepareLifeNumericJointRequestV1:
    episode_ref: str
    causal_operation_id: str
    appraisal_ref: str

    def __post_init__(self):
        PrepareLifeNumericDriveRequestV1(self.episode_ref, self.causal_operation_id, self.appraisal_ref)


def life_numeric_joint_ids_v1(namespace, episode_ref, appraisal_ref):
    suffix = canonical_digest((CONTINUATION_SCHEMA, namespace, episode_ref, appraisal_ref))[:48]
    return {key: 'life-joint-' + key + ':' + suffix for key in
        ('operation', 'prepare', 'activity', 'job', 'quote', 'execution', 'input', 'reservation', 'worker')}


def _drive_request(request):
    return PrepareLifeNumericDriveRequestV1(request.episode_ref, request.causal_operation_id, request.appraisal_ref)


def _utc(now):
    return datetime.fromtimestamp(now, timezone.utc).isoformat().replace('+00:00', 'Z')


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifeNumericJointStageV1:
    frame: object
    request: PrepareLifeNumericJointRequestV1
    drive: object
    graph: object
    bundle: object
    topology: object
    metadata: object
    epoch: object
    installed_readers: object


def read_plan_life_numeric_joint_v1(db, *, namespace, activity_id, operation_kind, request):
    if type(request) is not PrepareLifeNumericJointRequestV1 or operation_kind != OPERATION:
        raise TypeError('exact Life joint numerical request required')
    return read_plan_life_numeric_drive_v1(db, namespace=namespace, activity_id=activity_id,
        operation_kind=DRIVE_OPERATION, request=_drive_request(request))


def stage_life_numeric_joint_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(request) is not PrepareLifeNumericJointRequestV1:
        raise TypeError('exact Life joint numerical request required')
    drive = read_current_life_numeric_drive_v1(db, frame=frame, request=_drive_request(request), installed_readers=installed_readers)
    require_current_life_numeric_drive_v1(drive, db=db, frame=frame)
    graph = installed_readers.life_numeric_mapping_reader.graph
    bundle = installed_readers.life_numeric_bundle
    topology = getattr(installed_readers, 'life_numeric_topology', None)
    from .d04_owner_initialization_v3 import InstalledD04AuthoredTopologyVerifierV3
    if (type(topology) is not InstalledD04AuthoredTopologyVerifierV3
            or db is not graph._GraphCoordinator__store._db
            or not graph._GraphCoordinator__store._lock._is_owned()
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
        raise ValueError('Life joint needs its independently observed actual installed topology')
    metadata, epoch = graph._v2_graph_stamp(drive.original.namespace)
    scope = installed_readers.life_numeric_scope
    ids = life_numeric_joint_ids_v1(drive.original.namespace, request.episode_ref, request.appraisal_ref)
    observed = topology._location_observation
    if (frame.envelope.identity.operation_id != ids['prepare'] or frame.envelope.identity.phase != OPERATION
            or frame.envelope.authority.purpose != 'consolidation'
            or observed is None or observed[0] != scope or observed[1].guard != installed_readers.life_numeric_owner_guard
            or scope.graph_revision != metadata.graph_revision or scope.graph_epoch != epoch
            or epoch != frame.snapshot.epochs[0] or not graph._anchor_matches(metadata.requirements, scope.pinned_anchor)):
        raise ValueError('Life joint current Owner/location/command scope differs')
    result = LifeNumericJointStageV1(frame, request, drive, graph, bundle, topology, metadata, epoch, installed_readers)
    identity = id(result); _STAGES[identity] = (weakref.ref(result, lambda _: _STAGES.pop(identity, None)), db)
    return result


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _LifeJointSourceBridgeV1:
    current_drive: object
    frame: object
    stage: object | None
    numeric_witness: object | None


def _require_life_joint_source_bridge_v1(db, bridge):
    """Only the actual same-SQL Life stage or final numeric witness can issue."""
    from .d04_numeric_adoption_v3 import _COMMIT_WITNESSES
    if (type(bridge) is not _LifeJointSourceBridgeV1
            or _SOURCE_BRIDGES.get(id(bridge)) is not bridge or not db.in_transaction):
        raise ValueError('Life joint Source requires its live private issuance')
    if bridge.stage is not None:
        issued = _STAGES.get(id(bridge.stage))
        if (issued is None or issued[0]() is not bridge.stage or issued[1] is not db
                or bridge.numeric_witness is not None
                or bridge.current_drive.original != bridge.stage.drive.original):
            raise ValueError('Life joint Source stage differs from its actual preparation')
    else:
        witness = bridge.numeric_witness
        if witness is None or _COMMIT_WITNESSES.get(id(witness)) is not witness:
            raise ValueError('Life joint Source final numeric witness is no longer active')
        graph = witness.graph
        from .d04_numeric_adoption_v3 import require_current_numeric_commit_witness_v3
        require_current_numeric_commit_witness_v3(graph, db, witness.candidate.bundle, witness)
    require_current_life_numeric_drive_v1(bridge.current_drive, db=db, frame=bridge.frame)
    return bridge.current_drive, bridge.frame


def _issue_life_joint_source_bridge_v1(db, current_drive, frame, *, stage=None, numeric_witness=None):
    bridge = _LifeJointSourceBridgeV1(current_drive, frame, stage, numeric_witness)
    _SOURCE_BRIDGES[id(bridge)] = bridge
    _require_life_joint_source_bridge_v1(db, bridge)
    return bridge


def read_life_joint_signed_lineage_v1(db, prepared, *, issuer, resource_issuer, now_utc):
    """Independent signed-original join; a continuation locator grants nothing.

    The Authority calls this with its own issuers and pinned Graph transaction.
    Final adoption calls it again before full current-Life requalification.
    """
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..memory_types import SourceRecord
    from .d11_life_preparation_v1 import _read, read_prepared_life_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1
    from .d06_life_numeric_drive_v1 import (KIND as DRIVE_KIND,
        decode_life_numeric_drive_original_v1, _require_life_numeric_drive_producer_membership_v1)
    from .d06_life_numeric_context_v1 import (KIND as CONTEXT_KIND, OPERATION as CONTEXT_OPERATION,
        decode_life_numeric_context_original_v1, _writes, require_life_numeric_shared_original_v1)
    from .d06_internal_life_episode_v2 import (PROVENANCE, decode_internal_life_value_v2,
        validate_internal_life_episode_history_v2, internal_life_writes_from_proof_v2)
    from .d04_life_before_original_v1 import read_life_d04_before_original_v1
    from .d06_life_numeric_task_v1 import read_life_numeric_appraisal_acceptance_v1
    from .d04_installed_numeric_v3 import _ready_from_original_v3
    from .domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionOwnerGuardV1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from .c04_encoding_baseline_store_v3 import _receipt
    continuation = json.loads(prepared.job_payload_json)['continuation']
    if continuation.get('schema') != CONTINUATION_SCHEMA:
        if prepared.binding.operation_id.startswith('life-joint-'):
            raise ValueError('Life numerical operation lost its exact continuation schema')
        return None
    ns = prepared.binding.namespace
    request = PrepareLifeNumericJointRequestV1(continuation['episode_ref'],
        continuation['causal_operation_id'], continuation['appraisal_ref'])
    if read_life_numeric_joint_prepared_v1(db, namespace=ns, request=request) != prepared:
        raise ValueError('Life numerical continuation is not its actual immutable preparation')
    saved_drive = _read(db, issuer=issuer, namespace=ns, kind=DRIVE_KIND, ref=continuation['drive_ref'])
    saved_context = _read(db, issuer=issuer, namespace=ns, kind=CONTEXT_KIND, ref=continuation['context_ref'])
    if saved_drive is None or saved_context is None:
        raise ValueError('Life numerical signed drive/context original is absent')
    drive = decode_life_numeric_drive_original_v1(saved_drive[0])
    context = decode_life_numeric_context_original_v1(saved_context[0])
    if (saved_drive[1] != drive.operation_id or saved_context[1] != context.operation_id
            or drive.namespace != ns or context.namespace != ns
            or drive.episode_ref != request.episode_ref or context.episode_ref != request.episode_ref
            or drive.appraisal_ref != request.appraisal_ref
            or (drive.context_ref, drive.context_digest, drive.before_digest, drive.source_ref) !=
                (context.original_ref, context.digest, context.before_digest, context.source_ref)
            or any(continuation[name] != value for name, value in (
                ('drive_digest', drive.digest), ('context_digest', context.digest),
                ('before_digest', context.before_digest), ('source_ref', context.source_ref),
                ('mapping_ref', drive.mapping_ref), ('mapping_digest', drive.mapping_digest)))):
        raise ValueError('Life numerical signed occurrence/context/drive/mapping join differs')
    ready = _ready_from_original_v3(prepared)
    envelope = ready.preparation.envelope
    qualification = envelope.source_qualification
    if (envelope.authority.purpose != 'consolidation'
            or qualification.source_family != 'derived' or qualification.content_reality != 'inference'
            or qualification.evidence_eligibility != 'ineligible'
            or qualification.internal_activity_actuality != 'actual'
            or context.source_ref not in envelope.input_refs):
        raise ValueError('Life numerical Source was promoted or removed from its actual inputs')
    # These rows were frozen by the actual joint reader, never supplied by this
    # caller. Requiring the whole frame also preserves every ancestor negative.
    guard = ProductionOwnerGuardV1(prepared.binding.owner_grant_ref,
        prepared.binding.owner_grant_revision, prepared.binding.owner_grant_digest, context.owner_head_digest)
    frame = CurrentOperationFrameV1(envelope, ready.preparation.snapshot, now_utc,
        guard, prepared.binding.activation_generation, (), (), ())
    read = CurrentDomainReadV1(frame); read.check(db)
    read.source_family(db, (context.source_ref,), purpose='consolidation')
    source_atom = read.head(db, context.source_ref, required=True)
    source = SourceRecord.from_dict(source_atom.value)
    episode = AtomKey.from_token(request.episode_ref)
    proof = decode_internal_life_value_v2(PROVENANCE,
        read.head(db, AtomKey(episode.owner, PROVENANCE, 'record'), required=True).value)
    validate_internal_life_episode_history_v2(db, proof)
    if now_utc < max(source.recorded_at, proof.event.activity.completed_at):
        raise ValueError('Life numerical context precedes its actual occurrence')
    metadata = json.loads(db.execute('SELECT requirements_json FROM graph_recovery_metadata_v2 '
        'WHERE bot=? AND persona=?', ns.as_tuple).fetchone()[0])
    if (proof.episode.episode_ref != request.episode_ref or proof.event.namespace != ns
            or proof.event.causal_operation_id != request.causal_operation_id
            or canonical_digest(plain_v1(proof)) != context.occurrence_digest
            or proof.owner_head_digest != context.owner_head_digest
            or proof.event.activity.source_ref != context.source_ref
            or proof.event.activity.execution_id != context.execution_id
            or proof.event.activity.activity_id != context.interpretation.activity_id
            or (source_atom.revision, canonical_digest(source_atom.value)) !=
                (context.source_revision, context.source_digest)
            or metadata['graph_incarnation'] != context.graph_incarnation
            or metadata['activation_generation'] != context.activation_generation
            or context.activation_generation != prepared.binding.activation_generation):
        raise ValueError('Life numerical actual Episode/current generation/Source differs')
    for row in proof.current_reads:
        atom = read.head(db, row.ref)
        if (atom.revision, canonical_digest(atom.value), atom.valid) != (row.revision, row.digest, row.valid):
            raise ValueError('Life numerical current occurrence dependency changed')
    episode_writes = internal_life_writes_from_proof_v2(proof)
    for write in episode_writes:
        atom = read.head(db, write.key, required=True)
        if atom.revision != 1 or atom.value != write.value:
            raise ValueError('Life numerical Episode projection changed')
    produced = {write.key for write in episode_writes}
    expected_edges = tuple(sorted((dep.token, 1 if dep in produced else next(
        row.revision for row in proof.current_reads if row.ref == dep.token))
        for dep in episode_writes[-1].dependencies))
    if tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies '
            'WHERE dependent_token=? ORDER BY dependency_token', (episode_writes[-1].key.token,))) != expected_edges:
        raise ValueError('Life numerical occurrence invalidation edges changed')
    experience = json.loads(source.text)
    saved = _read(db, issuer=issuer, namespace=ns, kind='experience', ref=experience['actual_provenance_ref'])
    if saved is None: raise ValueError('Life numerical signed actual experience is absent')
    terminal = life_from_wire_v1(saved[0]['terminal'], D11LifeTerminalV1)
    life_prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if (life_prepared is None or terminal.status != 'completed'
            or terminal.binding.namespace != ns or terminal.binding.execution_id != context.execution_id
            or terminal.original_ref != proof.event.activity.terminal_original_ref
            or saved[1] != request.causal_operation_id
            or saved[0]['source_ref'] != context.source_ref
            or saved[0]['source_digest'] != context.source_digest or saved[0]['experience'] != experience):
        raise ValueError('Life numerical actual experience/preparation/terminal join differs')
    from .d11_life_adoption_v1 import _read_signed, _verify_life_adoption_commit_and_original_v1
    from ..authority_service.d11_life_bridge_v1 import life_bridge_from_wire_v1
    bridge = _read_signed(db, ns, 'adoption_bridge', terminal.binding.execution_id, issuer)
    if bridge is None: raise ValueError('Life numerical signed execution adoption bridge is absent')
    gate = life_bridge_from_wire_v1(bridge[1])
    if gate.binding != terminal.binding or gate.terminal != terminal:
        raise ValueError('Life numerical actual execution bridge differs')
    _verify_life_adoption_commit_and_original_v1(db, gate=gate, issuer=issuer,
        resource_issuer=resource_issuer, require_current_metadata=False)
    before = read_life_d04_before_original_v1(db, prepared=life_prepared, issuer=issuer)
    if before.original_ref != context.before_ref or before.digest != context.before_digest:
        raise ValueError('Life numerical signed before original differs')
    context_receipt = _receipt(db, ns, context.operation_id)
    payload = require_life_numeric_shared_original_v1(db, namespace=ns,
        operation_id=context.operation_id, operation_kind=CONTEXT_OPERATION,
        receipt=context_receipt, writes=_writes(context))
    if payload['provenance'].get('context_original') != plain_v1(context):
        raise ValueError('Life numerical context complete producer differs')
    for write in _writes(context):
        atom = read.head(db, write.key, required=True)
        history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1',
            (write.key.token,)).fetchone()
        if (atom.revision != 1 or atom.value != write.value
                or GraphVersion(write.key, 1) not in context_receipt.write_versions
                or history != (canonical_serialize(write.value), 1, context.operation_id)):
            raise ValueError('Life numerical context current projection differs')
    acceptance = read_life_numeric_appraisal_acceptance_v1(db, ns, request.appraisal_ref, issuer)
    appraisal = read.head(db, request.appraisal_ref, required=True)
    if (acceptance is None or acceptance.context_digest != context.digest
            or acceptance.before_digest != before.digest or acceptance.digest != drive.appraisal_acceptance_digest
            or acceptance.operation_id != drive.appraisal_adoption_operation_id
            or appraisal.revision != acceptance.appraisal_revision
            or canonical_serialize(appraisal.value) != acceptance.appraisal_value_json):
        raise ValueError('Life numerical actual paid appraisal/adoption differs')
    adopted = _require_life_numeric_drive_producer_membership_v1(db, drive)
    from .d04_semantic_mapping_v3 import require_current_d04_role_clock_v3
    from ..domains.d04.numeric_drive import decode_sourced_numeric_drive
    require_current_d04_role_clock_v3(db, drive.clock)
    for ref, revision in drive.drive_versions:
        atom = read.head(db, ref, required=True)
        item = decode_sourced_numeric_drive(atom.value)
        history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?',
            (ref, revision)).fetchone()
        if (atom.revision != revision or GraphVersion(atom.key, revision) not in adopted['receipt'].write_versions
                or history != (canonical_serialize(atom.value), 1, drive.operation_id)
                or item.source_ref != context.source_ref or item.source_revision != context.source_revision
                or read.head(db, item.checkpoint_ref, required=True).revision != item.checkpoint_revision):
            raise ValueError('Life numerical actual mapping drive/member changed')
    selected = {version.key.token: version.revision for block in ready.preparation.current.component.block_drives
        for version in block.drive_versions}
    if any(selected.get(ref) != revision for ref, revision in drive.drive_versions):
        raise ValueError('Life numerical frozen component omitted an actual mapped drive')
    return request, context, drive


def _current_life_joint_source_for_commit_v1(graph, db, witness):
    """Requalify only from the actual final numerical witness and current SQL."""
    from .d04_numeric_adoption_v3 import require_current_numeric_commit_witness_v3
    require_current_numeric_commit_witness_v3(graph, db, witness.candidate.bundle, witness)
    lineage = read_life_joint_signed_lineage_v1(db, witness.ready.prepared,
        issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer,
        now_utc=witness.now_utc)
    if lineage is None: return None
    request, context, original = lineage
    from .domain_production_registry_v1 import installed_operation_v1, installed_readers_for_operation_v1
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1, read_current_domain_policy_refs_v1
    from .domain_production_frame_v1 import _materialize_current_domain_frame_v1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionOperationLimitsV1
    binding, envelope = witness.ready.prepared.binding, witness.ready.preparation.envelope
    scope, owner = witness.scope, witness.bridge.owner_authority.guard
    if (db is not graph._GraphCoordinator__store._db or not graph._GraphCoordinator__store._lock._is_owned()
            or scope.namespace != binding.namespace or scope.graph_epoch != witness.before_epoch
            or scope.graph_revision != witness.before_metadata.graph_revision
            or scope.permit != witness.bridge.permit or scope.pinned_anchor != witness.bridge.after_anchor
            or owner.authorization_head.removeprefix('sha256:') != context.owner_head_digest
            or owner.pending_revoke_operation_id or witness.now_utc >= envelope.deadline_utc):
        raise ValueError('Life numerical final actual Owner/fence/deadline differs')
    readers = installed_readers_for_operation_v1(graph, installed_operation_v1(DRIVE_OPERATION),
        scope=scope, owner_guard=owner)
    drive_request = _drive_request(request)
    plan = read_plan_life_numeric_drive_v1(db, namespace=binding.namespace,
        activity_id=context.interpretation.activity_id, operation_kind=DRIVE_OPERATION, request=drive_request)
    originals = read_current_domain_original_refs_v1(db, namespace=binding.namespace, plan=plan, installed_readers=readers)
    policies = read_current_domain_policy_refs_v1(db, namespace=binding.namespace, plan=plan, installed_readers=readers)
    # Only the read frame uses the authenticated occurrence activity. The
    # native execution envelope, grant, reservation and deadline stay intact.
    read_envelope = replace(envelope, identity=replace(envelope.identity,
        activity_id=context.interpretation.activity_id))
    frame = _materialize_current_domain_frame_v1(graph, db, envelope=read_envelope,
        scope=scope, plan=plan, now_utc=witness.now_utc,
        expected_owner_guard=ProductionOwnerGuardV1(binding.owner_grant_ref,
            binding.owner_grant_revision, binding.owner_grant_digest, context.owner_head_digest),
        expected_rights=(envelope.version_guard.access_epoch, envelope.version_guard.delete_epoch),
        observed_originals=originals, installed_policy_refs=policies, limits=ProductionOperationLimitsV1())
    current = read_current_life_numeric_drive_v1(db, frame=frame, request=drive_request, installed_readers=readers)
    if current.original != original:
        raise ValueError('Life numerical current qualification differs from its signed continuation')
    return _issue_life_joint_source_bridge_v1(db, current, frame, numeric_witness=witness)


def _freeze_life_product_v1(graph, db, bundle, identity, *, metadata, epoch, clock, root_ref,
        qualification, audience, deadline, job, topology_verifier, life_source_bridge):
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
        expected_delete_epoch=rights[1], audience=audience, purpose="consolidation",
        authored_topology_verifier=topology_verifier, _life_source_bridge=life_source_bridge)
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
        "consolidation", audience, "d04.installed_life_numeric.v1", metadata.requirements.activation_generation, job.fence)
    envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(identity["activity"], None,
        identity["operation"], "joint_advance", identity["operation"], canonical_digest({"input_refs": list(inputs)})),
        authority, VersionGuard(reads, (current.component.query_epoch,), rights[0], rights[1],
            store._registry.catalogue_hash, policy.scheme_version, policy.operator_version, policy.policy_version,
            (), (), (VersionedRef(identity["quote"], 1),)),
        qualification, inputs, job.budget_ref, deadline, time.monotonic() + max(0, deadline - time.time()),
        "d04-role-interval:" + canonical_digest(asdict(clock))[:48], (identity["input"],))
    return D04JointProductPreparationV3(envelope, current,
        JointStateFrozenPredecessorsV1(namespace, identity["operation"], tuple(predecessors)), snapshot)


def prepare_life_numeric_joint_in_transaction_v1(db, *, stage):
    """Fixed W01 commit callback: exactly one job CAS, with no later Graph CAS.

    The public caller owns the actual Owner write fence and SQL transaction.
    Its outer command receipt/finish may be stored afterwards without advancing
    Graph. Advancing Graph again would correctly invalidate the frozen input.
    """
    issued = _STAGES.get(id(stage))
    if issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction:
        raise ValueError('Life joint requires its actual same-transaction private preparation')
    graph, bundle, frame = stage.graph, stage.bundle, stage.frame
    current_drive = read_current_life_numeric_drive_v1(db, frame=frame,
        request=_drive_request(stage.request), installed_readers=stage.installed_readers)
    if current_drive.original != stage.drive.original or graph._v2_graph_stamp(current_drive.original.namespace) != (stage.metadata, stage.epoch):
        raise ValueError('Life drive or actual Graph changed before numerical preparation')
    drive, context = current_drive.original, current_drive.context
    policy, installation = bundle.d04_joint_numeric, bundle.installation_policy
    namespace, clock, now = drive.namespace, drive.clock, frame.now_utc
    if type(policy) is not AdminD04JointNumericPolicyV3:
        raise ValueError('explicit installed D04 numerical policy required')
    identity = life_numeric_joint_ids_v1(namespace, stage.request.episode_ref, stage.request.appraisal_ref)
    if read_d04_numeric_prepared_v3(db, namespace, identity['operation']) is not None:
        raise ValueError('Life joint already prepared; resume its actual original')
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    installed = read_installed_d04_numeric_identity_v3(assembly.package_root, installation.manifest_digest)
    output_policy = graph._GraphCoordinator__d04_installed_joint_output_policy
    reader = graph._GraphCoordinator__d04_semantic_mapping_reader
    resource = graph._GraphCoordinator__d02_issuer
    grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, policy.lease_id)
    lease = get_budget_lease(db, policy.lease_id)
    if (lease is None or (policy.namespace, policy.installation_id, policy.grant_id, policy.grant_version) !=
            (namespace, installation.installation_id, grant.grant_id, grant.version)
            or (grant.bot_id, grant.persona_id) != namespace.as_tuple
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple or lease.state != 'active'
            or grant.lease_id != lease.lease_id or grant.currency != lease.currency
            or WORK_KIND not in grant.allowed_work_kinds or grant.valid_until_utc <= now
            or policy.cpu_ceiling_ms > grant.max_ceiling.get('cpu_ms', 0)):
        raise ValueError('Life joint current signed CPU authority differs')
    require_budget_family_admissible(db, lease.lease_id)
    deadline = min(now + policy.job_lifetime_seconds, grant.valid_until_utc)
    snapshot_ref = 'life-joint-input:' + canonical_digest((identity['operation'], drive.digest, asdict(clock)))[:48]
    continuation = {'schema': CONTINUATION_SCHEMA, 'episode_ref': stage.request.episode_ref,
        'causal_operation_id': stage.request.causal_operation_id, 'appraisal_ref': stage.request.appraisal_ref,
        'source_ref': drive.source_ref, 'context_ref': drive.context_ref, 'context_digest': drive.context_digest,
        'before_digest': drive.before_digest, 'drive_ref': drive.original_ref, 'drive_digest': drive.digest,
        'input_original_ref': identity['input'], 'execution_id': identity['execution'],
        'mapping_ref': drive.mapping_ref, 'mapping_digest': drive.mapping_digest}
    job = PersistentJob(identity['job'], identity['operation'], identity['activity'], None, *namespace.as_tuple,
        snapshot_ref, 'queued', WORK_KIND, continuation, None, _utc(deadline), lease.lease_id,
        installed['algorithm_id'], {'algorithm': installed['algorithm_build_digest'], 'resource_quote': identity['quote'] + ':1'},
        None, None, 0, 0, {}, None)
    quote = ResourceQuote(identity['quote'], 1, *namespace.as_tuple, identity['activity'], identity['operation'], None,
        lease.lease_id, WORK_KIND, snapshot_ref, deadline, installed['algorithm_id'], job_graph_write(job).key.token,
        (), (), {'cpu_ms': policy.cpu_ceiling_ms}, None, deadline)
    resource.issue_quote(db, quote)
    if resource.original_signed_quote(db, quote.quote_id, 1) != quote:
        raise ValueError('Life joint actual signed CPU quote differs')
    db.execute('INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)',
        (*namespace.as_tuple, 'resource_lease', quote.quote_id, '1'))
    reserve_digest = canonical_digest(('d04.life-numeric-reservation.v1', identity, canonical_digest(quote), continuation))
    reserved = reserve_budget(db, lease.lease_id, identity['reservation'], reserve_digest, quote.ceiling)
    if reserved.status != 'reserved': raise ValueError('Life joint actual CPU reservation unavailable')
    create_job(db, job, identity['operation'], canonical_digest((job, quote)))
    job = acquire_job(db, job.job_id, identity['worker'], now_utc=_utc(now), lease_seconds=policy.job_lifetime_seconds)
    write = job_graph_write(job)
    if db.execute('SELECT 1 FROM graph_atoms WHERE token=?', (write.key.token,)).fetchone():
        raise ValueError('Life new CPU job already has a Graph projection')
    receipt = _commit(graph, db, stage.metadata, stage.epoch, 'd04-numeric-running:' + identity['operation'],
        identity['activity'], now, (write,), (GraphVersion(write.key, 0),), 'd04.numeric_running_preparation.v3')
    metadata, epoch = graph._v2_graph_stamp(namespace)
    _advance_numeric_job_observation_v3(graph, db, stage.topology, stage.metadata, stage.epoch,
        metadata, epoch, job, receipt, identity)
    from .domain_production_inputs_v1 import _post_commit_frame
    post_frame = _post_commit_frame(db, frame, stage.request)
    post_drive = read_current_life_numeric_drive_v1(db, frame=post_frame,
        request=_drive_request(stage.request), installed_readers=stage.installed_readers)
    life_source_bridge = _issue_life_joint_source_bridge_v1(db, post_drive, post_frame, stage=stage)
    preparation = _freeze_life_product_v1(graph, db, bundle, identity, metadata=metadata, epoch=epoch,
        clock=clock, root_ref=drive.root_ref, qualification=context.source_qualification,
        audience=frame.envelope.authority.audience, deadline=deadline, job=job, topology_verifier=stage.topology,
        life_source_bridge=life_source_bridge)
    evidence = freeze_current_d04_joint_evidence_inputs_v3(db, preparation, clock=clock,
        installed_output_policy=output_policy, installed_mapping_reader=reader)
    if set(preparation.current.component.checkpoint_refs) != {m.checkpoint.ref for m in context.before.members}:
        raise ValueError('Life numerical preparation changed the explicit before-root member inventory')
    grant_ref = owner_grant_key(*namespace.as_tuple).token
    owner_row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?', (grant_ref,)).fetchone()
    if owner_row is None or owner_row[2] != 1: raise ValueError('Life joint actual Owner graph grant unavailable')
    owner_digest = canonical_digest(json.loads(owner_row[1]))
    payload, _ = build_d04_numeric_input_payload_v3(preparation, evidence,
        installation_id=installation.installation_id, owner_grant_ref=grant_ref,
        owner_grant_revision=owner_row[0], owner_grant_digest=owner_digest, **installed,
        max_iterations=policy.max_iterations, tolerance=policy.tolerance)
    payload['command_envelope'] = evidence_payload_v3(preparation.envelope)
    payload['worker_original'] = {'holder': job.lease_holder, 'fence': job.fence,
        'cancel_epoch': job.cancel_epoch, 'lease_expires_utc': job.lease_expires_utc, 'deadline_utc': job.deadline_utc}
    payload['numeric_policy'] = evidence_payload_v3(policy)
    binding = D04NumericBindingV3(namespace, metadata.requirements.authority_id,
        metadata.requirements.authority_namespace, installation.installation_id,
        metadata.requirements.activation_generation, grant_ref, owner_row[0], owner_digest,
        identity['operation'], identity['execution'], job.job_id, identity['activity'], identity['input'],
        canonical_digest(payload), installed['algorithm_id'], installed['algorithm_build_digest'],
        installed['native_manifest_sha256'], installed['native_sha256'], installed['output_policy_digest'],
        quote.quote_id, quote.version, canonical_digest(quote), lease.lease_id,
        identity['reservation'], reserve_digest, policy.cpu_ceiling_ms,
        tuple(sorted({item.family_id for item in preparation.current.families})), job.deadline_utc)
    reserve = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace.as_tuple, identity['reservation'])).fetchone()
    if reserve is None: raise ValueError('Life numerical CPU reservation original disappeared')
    prepared = D04NumericPreparedV3(binding, canonical_serialize(payload), canonical_serialize(quote),
        reserve[0], canonical_serialize(asdict(job)), identity['input'])
    record_d04_original_in_transaction_v3(db, namespace, 'numeric_prepared', binding.operation_id, asdict(prepared))
    from .d04_numeric_accounting_prepared_v3 import record_numeric_accounting_prepared_v3
    record_numeric_accounting_prepared_v3(db, prepared)
    ready = D04PreparedExecutionV3(prepared, preparation, evidence, job.lease_holder, job.fence)
    return ready, receipt


def read_life_numeric_joint_prepared_v1(db, *, namespace, request):
    if type(request) is not PrepareLifeNumericJointRequestV1:
        raise TypeError('exact Life joint locator required')
    identity = life_numeric_joint_ids_v1(namespace, request.episode_ref, request.appraisal_ref)
    prepared = read_d04_numeric_prepared_v3(db, namespace, identity['operation'])
    if prepared is None: return None
    continuation = json.loads(prepared.job_payload_json)['continuation']
    payload = json.loads(prepared.input_payload_json)
    if (prepared.binding.operation_id != identity['operation'] or prepared.binding.job_id != identity['job']
            or prepared.binding.execution_id != identity['execution'] or prepared.binding.quote_id != identity['quote']
            or continuation.get('schema') != CONTINUATION_SCHEMA
            or continuation.get('episode_ref') != request.episode_ref
            or continuation.get('causal_operation_id') != request.causal_operation_id
            or continuation.get('appraisal_ref') != request.appraisal_ref
            or continuation.get('mapping_ref') not in payload['mapping_original_refs']
            or payload['command_envelope']['authority']['purpose'] != 'consolidation'
            or continuation.get('source_ref') not in payload['command_envelope']['input_refs']):
        raise ValueError('Life joint original differs from its closed actual occurrence/appraisal locator')
    return prepared


def issue_current_life_numeric_math_ticket_v1(graph, bootstrap, bundle, queue, *, request):
    """Issue only the real installed queue's fresh claim; never run native here."""
    from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from .d04_numeric_math_ticket_v3 import InstalledD04MathQueueV3
    from .d04_installed_numeric_v3 import (D04ExecutedNumericV3, _ready_from_original_v3,
        _MeasuredNumericV3, _pending_measured, _flush_actual_measurement_v3)
    from .d04_appraisal_driver_v3 import read_d04_original_v3
    graph._admin(bootstrap)
    if (type(request) is not PrepareLifeNumericJointRequestV1 or type(queue) is not InstalledD04MathQueueV3
            or getattr(graph, '_GraphCoordinator__d04_math_queue_v3', None) is not queue):
        raise ValueError('Life CPU queue needs its exact installed composition and locator')
    port, store = graph._GraphCoordinator__c04_authority_port_v3, graph._GraphCoordinator__store
    if type(port) is not InstalledC04AuthorityPortV3 or port._bundle is not bundle:
        raise ValueError('Life CPU queue needs its actual paired Authority')
    namespace = bundle.installation_policy.namespace
    identity = life_numeric_joint_ids_v1(namespace, request.episode_ref, request.appraisal_ref)
    if not queue.reserve(graph, identity['operation']):
        returned = queue.completed(graph, identity['operation'])
        return queue.accept(graph, returned) if returned is not None else {
            'status': 'numeric_executor_busy', 'operation_id': identity['operation']}
    try:
        with store._lock:
            prepared = read_life_numeric_joint_prepared_v1(store._db, namespace=namespace, request=request)
        if prepared is None: raise ValueError('Life CPU lacks actual current W01 preparation; HOLD')
        ready = _ready_from_original_v3(prepared)
        binding = prepared.binding
        closure = port.numeric_cost_inspect(binding)
        if closure is not None:
            return D04ExecutedNumericV3(prepared, closure, 'execution_completed_adoption_not_adopted')
        claim, terminal = port.numeric_inspect(binding)
        if terminal is not None: return D04ExecutedNumericV3(prepared, terminal, 'execution_terminal')
        if claim is not None:
            pending = _pending_measured(graph).get(binding.digest)
            if pending is not None:
                if pending.ready.prepared != prepared or pending.claim != claim:
                    raise ValueError('Life pending native measurement belongs to another claim')
                return _flush_actual_measurement_v3(graph, pending)
            from ..authority_service.d04_numeric_contract_v3 import D04NumericMeasurementV3, from_wire
            with store._lock:
                measured = read_d04_original_v3(store._db, namespace, 'numeric_measurement', binding.operation_id)
                artifact = read_d04_original_v3(store._db, namespace, 'numeric_artifact', binding.operation_id)
            if measured is None: return D04ExecutedNumericV3(prepared, None, 'claimed_execution_unknown')
            pending = _MeasuredNumericV3(ready, claim, from_wire(measured[0]['measurement'], D04NumericMeasurementV3),
                None if artifact is None else artifact[0])
            _pending_measured(graph)[binding.digest] = pending
            return _flush_actual_measurement_v3(graph, pending)
        if _pending_measured(graph): raise ValueError('actual prior native measurement must be durably appended first')
        return queue.claim_and_issue(graph, bootstrap, ready, graph._GraphCoordinator__d04_installed_joint_assembly,
            graph._GraphCoordinator__d04_installed_joint_output_policy)
    finally:
        queue.abandon_unissued(identity['operation'])
