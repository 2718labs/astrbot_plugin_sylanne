"""Installed atomic adoption of one independently completed life tick.

The real permit stays pinned to the post-terminal head. Frozen business inputs
retain their original head; a private commit witness admits only this exact
two-row transition and the fixed source/job/cost bundle.
"""
from dataclasses import dataclass, replace
import json
import time

from ..authority_service.d11_life_bridge_v1 import (
    D11LifeAdoptionBridgeV1, life_bridge_from_wire_v1, life_bridge_to_wire_v1,
)
from ..authority_service.v2_contract import to_wire
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot
from ..runtime_contracts import (
    AuthorityContext, CommandEnvelope, DomainBundle, FenceScope, OperationIdentity,
    QueryEpoch, RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_digest, canonical_serialize,
)
from .d11_life_preparation_v1 import (
    read_prepared_life_v1, read_current_prepared_life_v1, life_ids_from_binding_v1,
)
from .d11_life_terminal_v1 import (
    AdoptCurrentLifeRequestV1, InstalledLifeTerminalReadersV1,
    LifeTerminalBundleV1, life_adoption_operation_id_v1,
    observe_current_life_terminal_v1, read_plan_current_life_terminal_v1,
    stage_current_life_terminal_in_transaction_v1,
    record_life_terminal_after_cas_v1, read_adopted_life_original_v1,
)
from .d11_life_preparation_v1 import TABLE, SIGN_KIND, read_prepared_life_by_ref_v1
from .d10_offline_tick_execution_v1 import _decode_json
from .domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionOwnerGuardV1
from .d11_types import cost_settlement_from_runtime, cost_settlement_graph_write, job_graph_write, reconcile_runtime_write
from .first_ingress_v2 import trusted_upper


def _read_signed(db, namespace, kind, ref, issuer):
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone()
    if row is None:
        return None
    raw = json.loads(row[1])
    if canonical_serialize(raw) != row[1] or canonical_digest(raw) != row[2]:
        raise ValueError("life continuation original bytes changed")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, row[2])), row[3])
    return row[0], raw


def _record_signed(db, binding, kind, raw, issuer):
    wire, digest = canonical_serialize(raw), canonical_digest(raw)
    operation_id = life_adoption_operation_id_v1(binding)
    ref = binding.execution_id
    prior = _read_signed(db, binding.namespace, kind, ref, issuer)
    if prior is not None:
        if prior != (operation_id, raw):
            raise ValueError("life continuation original replay conflicts")
        return
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((binding.namespace, kind, ref, digest)))
    db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)",
        (*binding.namespace.as_tuple, kind, ref, operation_id, wire, digest, signature))


def _bundle(staged):
    binding = staged.prepared.binding
    runtime_writes = tuple(write for proposal in staged.runtime_stage.proposals for write in proposal.typed_writes)
    job = next(write for write in runtime_writes if write.key.type_name == "runtime.job")
    cost = next(write for write in runtime_writes if write.key.type_name == "runtime.cost_settlement")
    return DomainBundle(staged.envelope, (*staged.memory_stage.proposals, *staged.runtime_stage.proposals),
        (), (), (), (cost.key.token,),
        (life_adoption_operation_id_v1(binding),), (job.key.token,), ())


@dataclass(frozen=True, slots=True)
class _LifeCommitWitnessV1:
    graph: object
    bridge: D11LifeAdoptionBridgeV1
    frame: CurrentOperationFrameV1
    staged: LifeTerminalBundleV1
    bundle: DomainBundle
    before_metadata: object
    before_epoch: object
    target_requirements: object


_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class D11LifeAdoptionReceiptV1:
    schema: str
    operation_id: str
    binding_digest: str
    terminal_digest: str
    bridge_digest: str
    original_ref: str
    original_digest: str
    graph_receipt_digest: str
    status: str
    source_refs: tuple[str, ...]
    actual_cpu_ms: int | None

    def __post_init__(self):
        from .d11_offline_originals_v1 import _digest, _text
        if (self.schema != "d11.life-tick-adoption-receipt.v1"
                or self.status not in {"completed", "failed", "unknown"}
                or type(self.source_refs) is not tuple
                or len(self.source_refs) != (1 if self.status == "completed" else 0)
                or (self.actual_cpu_ms is None) != (self.status == "unknown")
                or self.actual_cpu_ms is not None and (type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0)):
            raise ValueError("life adoption receipt has another terminal/source/usage variant")
        for value in (self.operation_id, self.original_ref):
            _text(value)
        for value in (self.binding_digest, self.terminal_digest, self.bridge_digest,
                self.original_digest, self.graph_receipt_digest):
            _digest(value)
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("life adoption receipt contains another source type")


def require_life_commit_v1(witness, graph, db, bundle, v2_write):
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from .budget import _settlement_binding
    if (type(witness) is not _LifeCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or witness.bundle != bundle or _bundle(witness.staged) != bundle
            or v2_write is None or v2_write[:2] != (witness.before_metadata, witness.before_epoch)
            or graph._v2_graph_stamp(witness.bridge.binding.namespace) != v2_write[:2]
            or witness.staged.terminal != witness.bridge.terminal
            or witness.staged.prepared.digest != witness.bridge.prepared_digest
            or not graph._anchor_matches(witness.before_metadata.requirements, witness.bridge.before_anchor)
            or not graph._anchor_matches(witness.target_requirements, witness.bridge.after_anchor)
            or witness.bridge.permit.pinned_anchor != witness.bridge.after_anchor
            or v2_write[4] != canonical_serialize(to_wire(witness.bridge.permit))):
        raise ValueError("life installed atomic commit witness differs")
    CurrentDomainReadV1(witness.frame).check(db)
    binding, terminal = witness.bridge.binding, witness.bridge.terminal
    actual = None if terminal.status == "unknown" else {"thread_cpu_ms": terminal.actual_cpu_ms}
    row = db.execute("SELECT digest,lease_id,resolution_binding_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if row != (binding.reservation_digest, binding.parent_budget_lease_ref, _settlement_binding(actual, True)):
        raise ValueError("life actual complete CPU settlement is not in this transaction")
    require_life_job_registration_v1(witness, db)
    return witness


def require_life_job_registration_v1(witness, db):
    """A terminal updates the job registered by its exact preparation bundle."""
    if (type(witness) is not _LifeCommitWitnessV1
            or _ACTIVE.get(id(witness)) is not witness
            or db is not witness.graph._GraphCoordinator__store._db
            or not db.in_transaction):
        raise ValueError("life job update has no active installed commit witness")
    refs = witness.bundle.persistent_job_refs
    if len(refs) != 1:
        raise ValueError("life terminal must update its one original job")
    row = db.execute("SELECT operation_id FROM graph_bundle_refs WHERE bot=? AND persona=? "
        "AND ref_kind='persistent_job' AND ref=?",
        (*witness.bridge.binding.namespace.as_tuple, refs[0])).fetchone()
    if row != (witness.staged.prepared.prepare_operation_id,):
        raise ValueError("life terminal job is not registered to its actual preparation")
    return refs


def life_target_requirements_v1(witness):
    if type(witness) is not _LifeCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness:
        raise ValueError("life target requirements have no active installed witness")
    return witness.target_requirements


def _frame(graph, db, bridge, prepared, scope, authority, owner, observation, now):
    """Fixed finite read plan, including all frozen inputs and absent targets."""
    binding = prepared.binding
    if (scope.permit != bridge.permit or scope.pinned_anchor != bridge.after_anchor
            or scope.graph_revision != bridge.before_graph_revision
            or scope.graph_epoch.revision != bridge.before_graph_epoch):
        raise ValueError("life scope differs from actual bridge permit and frozen business stamp")
    request = AdoptCurrentLifeRequestV1(binding.prepared_original_ref)
    plan = read_plan_current_life_terminal_v1(db, namespace=binding.namespace,
        activity_id=binding.activity_id, operation_kind="adopt_life", request=request)
    keys = {*plan.exact_keys, *(AtomKey.from_token(row.ref) for row in prepared.read_rows)}
    if len(keys) > 1024:
        raise ValueError("life complete adoption read set exceeds installed bound")
    atoms = []
    for key in sorted(keys, key=lambda item: item.token):
        graph._GraphCoordinator__store._registry.spec(key.type_name)
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        atoms.append(GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])) if row else GraphAtom(key, 0, {}, False))
    snapshot = GraphSnapshot(tuple(atoms), (scope.graph_epoch,))
    versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
        "AND ref='current' AND kind IN ('scheme','operator','policy')", binding.namespace.as_tuple))
    if set(versions) != {"scheme", "operator", "policy"}:
        raise ValueError("life current installation policy heads are incomplete")
    if (authority.actor != bridge.owner_actor_id or authority.purpose not in owner.purposes
            or not set(authority.audience) <= owner.audiences
            or owner.authorization_head != bridge.owner_authority.guard.authorization_head
            or owner.authorization_revision != bridge.owner_authority.guard.authorization_revision):
        raise ValueError("life current independently observed Owner does not admit this source")
    inputs = (binding.prepared_original_ref, observation.original.original_ref)
    envelope = CommandEnvelope(RUNTIME_SCHEMA,
        OperationIdentity(activity_id=binding.activity_id, effect_id=binding.effect_id, attempt_id=binding.attempt_id,
            phase="adopt_life", operation_id=life_adoption_operation_id_v1(binding),
            canonical_input_digest=canonical_digest({"input_refs": list(inputs)})), authority,
        VersionGuard(snapshot.versions, (QueryEpoch(binding.namespace, "namespace", scope.graph_epoch.revision),),
            owner.access_epoch, owner.delete_epoch, graph._GraphCoordinator__store._registry.catalogue_hash,
            versions["scheme"], versions["operator"], versions["policy"], (), (), ()),
        SourceQualification((), "derived", None, now, "inference", "ineligible", None, "not_applicable"),
        inputs, binding.parent_budget_lease_ref, now + 60, time.monotonic() + 60,
        "life-terminal:" + binding.execution_id, ())
    frame = CurrentOperationFrameV1(envelope, snapshot, now,
        ProductionOwnerGuardV1(binding.owner_grant_ref, owner.grant_revision,
            owner.grant_digest.removeprefix("sha256:"), owner.authorization_head.removeprefix("sha256:")),
        binding.activation_generation, (), (), (observation.original,))
    from .d08_life_admission_v1 import enrich_life_adoption_frame_v1
    return enrich_life_adoption_frame_v1(db,frame=frame,prepared=prepared,issuer=graph._GraphCoordinator__d11_issuer), request


def adopt_current_life_v1(graph, bootstrap, *, namespace, prepared_original_ref):
    from ..host.v2_fence_port import V2FencePort
    from ..host.d11_life_port_v1 import InstalledD11LifePortV1
    graph._admin(bootstrap)
    port, store = graph._GraphCoordinator__content_fence_v2, graph._GraphCoordinator__store
    life_port = InstalledD11LifePortV1(port)
    issuer, resources = graph._GraphCoordinator__d11_issuer, graph._GraphCoordinator__d02_issuer
    if type(port) is not V2FencePort:
        raise TypeError("life adoption needs the actual installed paired port")
    with store._lock:
        rows = store._db.execute("SELECT original_ref FROM " + TABLE +
            " WHERE bot=? AND persona=? AND kind='adoption_bridge' "
            "AND json_extract(payload_json,'$.binding.prepared_original_ref')=?",
            (*namespace.as_tuple, prepared_original_ref)).fetchall()
        if len(rows) > 1:
            raise ValueError("life preparation has conflicting adoption identities")
        saved_bridge = _read_signed(store._db, namespace, "adoption_bridge", rows[0][0], issuer) if rows else None
        gate = life_bridge_from_wire_v1(saved_bridge[1]) if saved_bridge else None
        if gate is not None:
            binding = gate.binding
            if (binding.namespace != namespace or binding.prepared_original_ref != prepared_original_ref
                    or binding.execution_id != rows[0][0]):
                raise ValueError("life saved bridge differs from requested installed namespace and preparation")
            saved = verify_life_adoption_commit_v1(store._db, gate=gate, issuer=issuer,
                resource_issuer=resources, require_current_metadata=False)
            validate_life_ack_recovery_v1(store._db, gate=gate, issuer=issuer)
        else:
            prepared = read_prepared_life_by_ref_v1(store._db, namespace=namespace, prepared_original_ref=prepared_original_ref, issuer=issuer)
            if prepared is None:
                raise ValueError("actual life preparation unavailable")
            binding = prepared.binding
            if _read_signed(store._db, namespace, "adoption_receipt", binding.execution_id, issuer) is not None:
                raise ValueError("life committed receipt lacks its original bridge")
    if gate is not None:
        # Only the original durable composite is recovered. Current generation,
        # frozen ancestors and result heads must still match; no new work is issued.
        pairing = port.current_owner_actor_binding(namespace=namespace,
            authority_namespace=binding.authority_namespace, actor_id=gate.owner_actor_id)
        if pairing is None or pairing.installation_id != binding.installation_id:
            raise ValueError("life recovery current Owner pairing differs")
        claim, terminal = life_port.read_d11_life_original_v1(binding=binding)
        if terminal != gate.terminal or claim != gate.terminal.claim:
            raise ValueError("life prior composite receipt lost its actual terminal")
        if port.current_owner_actor_binding(namespace=namespace,
                authority_namespace=binding.authority_namespace, actor_id=gate.owner_actor_id) != pairing:
            raise ValueError("life recovery Owner pairing changed before finish")
        with store._lock:
            db = store._db
            if db.in_transaction:
                raise ValueError("life ACK recovery requires an independent readonly snapshot")
            db.execute("BEGIN")
            try:
                final = verify_life_adoption_commit_v1(db, gate=gate, issuer=issuer,
                    resource_issuer=resources, require_current_metadata=False)
                validate_life_ack_recovery_v1(db, gate=gate, issuer=issuer)
                if canonical_serialize(final) != canonical_serialize(saved):
                    raise ValueError("life recovered durable receipt changed before finish")
            finally:
                db.rollback()
        life_port.life_adoption_bridge_v1(binding=binding, action="finish", gate=gate, outcome="committed")
        return saved
    gate = life_port.life_adoption_bridge_v1(binding=binding, action="begin")
    local_lease = None
    committed = False
    witness = None
    try:
        observation = observe_current_life_terminal_v1(life_port, prepared)
        if observation.terminal != gate.terminal:
            raise ValueError("life terminal changed after actual bridge issuance")
        pairing = port.current_owner_actor_binding(namespace=namespace,
            authority_namespace=binding.authority_namespace, actor_id=gate.owner_actor_id)
        if pairing is None or pairing.installation_id != binding.installation_id:
            raise ValueError("life current Owner actor pairing unavailable")
        now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        life_port.life_adoption_bridge_v1(binding=binding, action="validate", gate=gate)
        inventory = life_port.read_d11_life_execution_inventory_v1(namespace=binding.authority_namespace, permit=gate.permit)
        local_lease, capability = graph.grant(bootstrap, actor=gate.owner_actor_id,
            issuer_domain="d10", namespace=namespace, domains=("d08", "d10", "d11"),
            activation_generation=binding.activation_generation,
            operation_id=life_adoption_operation_id_v1(binding))
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                current = read_current_prepared_life_v1(db, binding=binding, issuer=issuer,
                    resource_issuer=resources, now_utc=now, for_execution=False)
                if current != prepared or prepared.digest != gate.prepared_digest:
                    raise ValueError("life current preparation changed")
                before, epoch = graph._v2_graph_stamp(namespace)
                metadata_wire = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 "
                    "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
                if (metadata_wire != (gate.before_requirements_json,) or before.graph_revision != gate.before_graph_revision
                        or epoch.revision != gate.before_graph_epoch
                        or not graph._anchor_matches(before.requirements, gate.before_anchor)):
                    raise ValueError("life final business snapshot changed")
                scope = FenceScope(namespace, binding.authority_namespace, binding.activation_generation, "write",
                    gate.permit.operation_id, gate.permit, gate.after_anchor, epoch, before.graph_revision)
                target = replace(before.requirements, execution_seq=gate.after_anchor.execution_seq,
                    execution_digest=gate.after_anchor.execution_digest)
                if not graph._anchor_matches(target, gate.after_anchor):
                    raise ValueError("life exact bridge cannot change other recovery fields")
                authority = AuthorityContext(gate.owner_actor_id, "d10", capability, namespace,
                    tuple(sorted(graph._GraphCoordinator__leases[local_lease][5])), "consolidation",
                    prepared.plan.audiences, _decode_json(prepared.signed_grant_json,
                        __import__("sylanne3.runtime.issuers", fromlist=["BudgetLeaseGrant"]).BudgetLeaseGrant).policy_ref,
                    binding.activation_generation)
                owner = graph._owner_graph_binding_locked(authority, pairing.principal,
                    target_admission=gate.owner_authority.target_admission,
                    storage_admission=gate.owner_authority.storage_admission, current_guard=gate.owner_authority.guard)
                frame, request = _frame(graph, db, gate, prepared, scope, authority, owner, observation, now)
                from .d08_life_admission_v1 import InstalledLifeAdmissionReaderV1, require_current_life_action_admission_v1
                admission_reader = InstalledLifeAdmissionReaderV1(issuer=issuer, resource_issuer=resources,
                    body_quote_authority=graph._GraphCoordinator__body_quote_authority, execution_inventory=inventory, scope=scope)
                require_current_life_action_admission_v1(db,prepared=prepared,reader=admission_reader,now_utc=now,frame=frame)
                readers = InstalledLifeTerminalReadersV1(issuer=issuer, observation=observation, admission_reader=admission_reader)
                staged = stage_current_life_terminal_in_transaction_v1(db, frame=frame,
                    request=request, installed_readers=readers)
                bundle = _bundle(staged)
                for proposal in staged.runtime_stage.proposals:
                    for write in proposal.typed_writes:
                        if write.key.type_name.startswith("runtime."):
                            reconcile_runtime_write(db, write)
                witness = _LifeCommitWitnessV1(graph, gate, frame, staged, bundle, before, epoch, target)
                _ACTIVE[id(witness)] = witness
                finish_id = gate.permit.operation_id + ":committed"
                finish_digest = "sha256:" + canonical_digest((gate.qualification_digest, "committed"))
                receipt = graph._commit_domain_bundle_fenced(bundle, local_lease, in_transaction=True, now_utc=now,
                    v2_write=(before, epoch, finish_id, finish_digest, canonical_serialize(to_wire(gate.permit))),
                    domain_production_issuance_v1=witness)
                original = record_life_terminal_after_cas_v1(db, issuer=issuer, staged=staged, graph_receipt=receipt)
                result = {"schema": "d11.life-tick-adoption-receipt.v1", "operation_id": receipt.operation_id,
                    "binding_digest": binding.digest, "terminal_digest": canonical_digest(plain_v1(gate.terminal)),
                    "bridge_digest": gate.qualification_digest, "original_ref": original.original_ref,
                    "original_digest": original.original_digest, "graph_receipt_digest": canonical_digest(receipt),
                    "status": gate.terminal.status, "source_refs": list(staged.source_refs),
                    "actual_cpu_ms": gate.terminal.actual_cpu_ms}
                _record_signed(db, binding, "adoption_bridge", life_bridge_to_wire_v1(gate), issuer)
                _record_signed(db, binding, "adoption_receipt", result, issuer)
                db.commit()
                committed = True
            except BaseException:
                if db.in_transaction:
                    db.rollback()
                raise
        life_port.life_adoption_bridge_v1(binding=binding, action="finish", gate=gate, outcome="committed")
        return result
    except (ValueError, TypeError):
        if not committed:
            life_port.life_adoption_bridge_v1(binding=binding, action="finish", gate=gate, outcome="abandoned")
        raise
    finally:
        if witness is not None:
            _ACTIVE.pop(id(witness), None)
        if local_lease is not None:
            graph.release_authority_lease(bootstrap, local_lease)


def validate_life_recovery_heads_v1(db, *, binding, prepared_digest, prepared, adopted):
    """Readonly recovery joins, independent of unrelated same-generation writes.

    Authentication of prepared/adopted originals is performed by the installed
    reader. This structural seam never authorizes a new adoption or execution.
    """
    from ..runtime_contracts import SnapshotRequirementsV2
    from .d11_life_terminal_v1 import read_current_life_job_result_v1
    if (prepared is None or prepared.binding != binding or prepared.digest != prepared_digest
            or adopted is None or adopted["prepared_digest"] != prepared_digest):
        raise ValueError("life recovery preparation/result identity differs")
    metadata = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", binding.namespace.as_tuple).fetchone()
    current_requirements = None if metadata is None else _decode_json(metadata[0], SnapshotRequirementsV2)
    if current_requirements is None or (current_requirements.namespace,current_requirements.authority_id,
            current_requirements.authority_namespace,current_requirements.activation_generation) != (
                binding.namespace,binding.authority_id,binding.authority_namespace,binding.activation_generation):
        raise ValueError("life recovery activation generation differs")
    from .d11_life_fact_provenance_v1 import life_current_fact_reads_v1
    for frozen in life_current_fact_reads_v1(prepared):
        key = AtomKey.from_token(frozen.ref)
        if (key.owner.bot, key.owner.persona) != binding.namespace.as_tuple:
            raise ValueError("life recovery ancestor namespace differs")
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (frozen.ref, *binding.namespace.as_tuple)).fetchone()
        if row != (frozen.revision, frozen.value_json, int(frozen.valid)) and not (frozen.revision == 0 and row is None):
            raise ValueError("life recovery frozen Source/access/Owner ancestor changed or deleted")
    for member in adopted["write_commitments"]:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (member["ref"], *binding.namespace.as_tuple)).fetchone()
        if (row is None or row[0] != member["revision"] or row[2] != 1
                or canonical_digest(json.loads(row[1])) != member["digest"]):
            raise ValueError("life recovery current artifact/job/terminal member changed or deleted")
    from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    if terminal.binding != binding:
        raise ValueError("life recovery terminal binding differs")
    if terminal.status == "completed":
        import hashlib
        row = db.execute("SELECT binding_digest,artifact_ref,artifact_bytes,artifact_digest,artifact_length,adopted_operation_id "
            "FROM graph_d11_life_artifact_stage_v1 WHERE bot=? AND persona=? AND execution_id=?",
            (*binding.namespace.as_tuple,binding.execution_id)).fetchone()
        payload = terminal.payload
        if (row is None or row[0] != binding.digest or row[1] != binding.artifact_ref
                or type(row[2]) is not bytes or hashlib.sha256(row[2]).hexdigest() != payload.artifact_digest
                or (row[3],row[4],len(row[2]),row[5]) != (payload.artifact_digest,payload.artifact_length,
                    payload.artifact_length,life_adoption_operation_id_v1(binding))):
            raise ValueError("life recovery durable artifact bytes/original adoption identity differs")
        job,_ = read_current_life_job_result_v1(db, job_id=binding.job_id, adopted=adopted)
    else:
        from .jobs import get_job, JobConflict
        try:
            job = get_job(db, binding.job_id)
        except JobConflict as exc:
            raise ValueError("life recovery actual terminal job is absent") from exc
        expected_phase = {"failed": "failed", "unknown": "pending_confirmation"}[terminal.status]
        if ((job.bot_id, job.persona_id, job.job_id, job.operation_id, job.activity_id, job.effect_id,
                job.phase, job.fence, job.cancel_epoch, job.result_ref) !=
                (*binding.namespace.as_tuple, binding.job_id, binding.operation_id, binding.activity_id,
                 binding.effect_id, expected_phase, binding.job_fence, binding.job_cancel_epoch, None)):
            raise ValueError("life recovery actual failed/unknown job identity differs")
    projection=job_graph_write(job)
    if db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (projection.key.token,*binding.namespace.as_tuple)).fetchone() != (canonical_serialize(projection.value),1):
        raise ValueError("life recovery actual full SQL job differs from its committed Graph member")
    from .d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1
    require_current_life_fact_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=adopted)
    return adopted


def validate_life_ack_recovery_v1(db, *, gate, issuer):
    """Authenticate existing originals and current heads before old finish ACK."""
    binding = gate.binding
    prepared = read_prepared_life_v1(db, binding=binding, issuer=issuer)
    adopted = read_adopted_life_original_v1(db, namespace=binding.namespace,
        result_ref=binding.artifact_ref, issuer=issuer)
    return validate_life_recovery_heads_v1(db, binding=binding, prepared_digest=gate.prepared_digest,
        prepared=prepared, adopted=adopted)


def verify_life_adoption_commit_v1(db, *, gate, issuer, resource_issuer, require_current_metadata=True):
    """Independent read-only verification before the Authority finishes its gate."""
    from .d11_life_accounting_v1 import read_life_accounting_prepared_v1
    from .budget import _settlement_binding
    from ..runtime_contracts import CommitReceipt, SnapshotRequirementsV2
    from ..graph_store import GraphStore
    from ..graph_types import NamespaceEpoch
    binding, terminal = gate.binding, gate.terminal
    namespace = binding.namespace
    operation_id = life_adoption_operation_id_v1(binding)
    saved = _read_signed(db, namespace, "adoption_bridge", binding.execution_id, issuer)
    result = _read_signed(db, namespace, "adoption_receipt", binding.execution_id, issuer)
    if (saved is None or saved[0] != operation_id or life_bridge_from_wire_v1(saved[1]) != gate
            or result is None or result[0] != operation_id):
        raise ValueError("life final is missing its same-transaction signed bridge/receipt")
    accounting = read_life_accounting_prepared_v1(db, binding=binding, issuer=issuer, resource_issuer=resource_issuer)
    if accounting is None or accounting.prepared_digest != gate.prepared_digest:
        raise ValueError("life final lost the actual signed quote and reserved contract")
    ids = life_ids_from_binding_v1(binding)
    adopted = read_adopted_life_original_v1(db, namespace=namespace, result_ref=ids["result"], issuer=issuer)
    return validate_life_adoption_composite_v1(db, gate=gate, result=result[1], adopted=adopted,
        require_current_metadata=require_current_metadata)


def validate_life_adoption_composite_v1(db, *, gate, result, adopted, require_current_metadata=False):
    """Structural joins for already authenticated originals and C09 inventory.

    Signature and independent Authority authentication stay in the installed
    reader above; inventory never grants permission from these structural joins.
    """
    from .budget import _settlement_binding
    from ..runtime_contracts import CommitReceipt, SnapshotRequirementsV2
    from ..graph_store import GraphStore
    from ..graph_types import NamespaceEpoch
    from .d11_life_terminal_v1 import read_adopted_life_original_v1, validate_adopted_life_member_history_v1
    from .d11_life_contract_v1 import life_from_wire_v1, D11LifeTerminalV1
    binding, terminal = gate.binding, gate.terminal
    namespace = binding.namespace
    operation_id = life_adoption_operation_id_v1(binding)
    ids = life_ids_from_binding_v1(binding)
    if adopted is None or life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1) != terminal or adopted["prepared_digest"] != gate.prepared_digest:
        raise ValueError("life final actual terminal/adopted original differs")
    validate_adopted_life_member_history_v1(db, value=adopted, namespace=namespace,
        result_ref=binding.artifact_ref, producing_operation_id=operation_id)

    receipt = _decode_json(adopted["graph_receipt_json"], CommitReceipt)
    event = db.execute("SELECT reads,revisions,epoch_revision,invalidated FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, binding.activity_id, operation_id)).fetchone()
    fence = db.execute("SELECT permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,"
        "finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id)).fetchone()
    if (event is None or receipt.read_versions != GraphStore._version_rows(event[0])
            or receipt.write_versions != GraphStore._version_rows(event[1])
            or receipt.invalidated_epochs != (NamespaceEpoch(*namespace.as_tuple, event[2]),)
            or json.loads(event[3]) != [] or event[2] != gate.before_graph_epoch + 1
            or fence != (canonical_serialize(to_wire(gate.permit)), gate.before_graph_revision, gate.before_graph_epoch,
                gate.before_graph_revision + 1, gate.before_graph_epoch + 1, gate.permit.operation_id + ":committed",
                "sha256:" + canonical_digest((gate.qualification_digest, "committed")))):
        raise ValueError("life final actual event/fence is not the exact atomic bridge")
    actual = None if terminal.status == "unknown" else {"thread_cpu_ms": terminal.actual_cpu_ms}
    settle = db.execute("SELECT digest,lease_id,resolution_binding_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
        (*namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if settle != (binding.reservation_digest, binding.parent_budget_lease_ref, _settlement_binding(actual, True)):
        raise ValueError("life final usage/revocation does not settle its exact reservation")
    cost = cost_settlement_from_runtime(db, bot_id=namespace.bot_id, persona_id=namespace.persona_id,
        activity_id=binding.activity_id, bundle_operation_id=operation_id, effect_id=binding.effect_id,
        settlement_id=ids["reservation"], lease_id=binding.parent_budget_lease_ref,
        cost_operation_id=binding.reservation_operation_id, budget_operation_id=binding.reservation_operation_id,
        budget_phase="settle", prior_unknown_ref=None, execution_revoked=True)
    cost_write = cost_settlement_graph_write(cost)
    revisions = {version.key.token: version.revision for version in receipt.write_versions}
    row = db.execute("SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?",
        (cost_write.key.token, revisions.get(cost_write.key.token))).fetchone()
    if row != (canonical_serialize(cost_write.value), 1, operation_id):
        raise ValueError("life actual full cost is absent from its composite event")
    expected = {"schema": "d11.life-tick-adoption-receipt.v1", "operation_id": operation_id,
        "binding_digest": binding.digest, "terminal_digest": canonical_digest(plain_v1(terminal)),
        "bridge_digest": gate.qualification_digest, "original_ref": adopted["result_ref"],
        "original_digest": canonical_digest(plain_v1(adopted)), "graph_receipt_digest": canonical_digest(receipt),
        "status": terminal.status, "source_refs": list(tuple(adopted["source_refs"])), "actual_cpu_ms": terminal.actual_cpu_ms}
    _decode_json(canonical_serialize(result), D11LifeAdoptionReceiptV1)
    if canonical_serialize(result) != canonical_serialize(expected):
        raise ValueError("life actual composite receipt commitments differ")
    metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    before = _decode_json(gate.before_requirements_json, SnapshotRequirementsV2)
    target = replace(before, execution_seq=gate.after_anchor.execution_seq, execution_digest=gate.after_anchor.execution_digest)
    if require_current_metadata and (metadata is None or _decode_json(metadata[0], SnapshotRequirementsV2) != target
            or metadata[1] != gate.before_graph_revision + 1):
        raise ValueError("life committed Graph has not reached its exact authenticated current head")
    return expected
