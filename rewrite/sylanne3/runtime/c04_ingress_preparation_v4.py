"""Self C04 fixed Foreground preparation/adoption; one held W01 per command."""
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import json

from ..contracts import Event, Scope, canonical_json
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphAtom, GraphCandidate, GraphSnapshot, GraphVersion, Owner
from ..runtime_contracts import DomainBundle, DomainProposal, DependencySet, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..memory_association import ActivationPolicy
from .c04_self_scope_v4 import PREPARE_OPERATION, PrepareIngressC04RequestV1, ingress_c04_ids_v4, issue_self_c04_scope_v4, collect_self_c04_graph_v4, prepare_self_c04_body_resources_v4
from .c04_direct_seed_v4 import AssociationWorkInputV4, ALGORITHM_ID_V4, AUTHORED_INPUT_SCHEMA_V4, INPUT_SCHEMA_V4
from .c04_v3_contracts import GraphHeadV3, AssociationPageV3, canonical_v3_digest
from .c04_prepare_service_v3 import c04_prepare_job_id_v3
from .c04_frozen_association_original_v3 import record_c04_frozen_association_original_v4, read_c04_frozen_association_original_v4, _verify_current_association_input_heads_common_v3
from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1, read_c04_internal_work_prepared_v1, record_c04_internal_work_prepared_v1
from .c04_product_original_v3 import record_c04_product_request_v3
from .c04_product_lifecycle_v3 import read_original_c04_product_job_v3
from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
from .d01_production_operations_v1 import CurrentDomainReadV1, production_read_plan_v1, MissingProductionOriginalV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1, record_adopted_domain_operation_v1, _receipt_wire
from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1, reobserve_foreground_activity_v1
from .foreground_cycle_v1 import ForegroundWaitV1, foreground_cycle_from_wire_v1, require_current_foreground_responsibility_v1, decode_foreground_job_v1
from .d11_types import job_graph_write, RuntimeOutboxValue, outbox_graph_write
from .jobs import PersistentJob, get_job, create_job, acquire_job, _save_job, _record_operation
from .budget import reserve_budget

ADOPT_OPERATION = "adopt_ingress_c04_v1"
OPERATIONS = frozenset({PREPARE_OPERATION, ADOPT_OPERATION})
_LIVE = {}
_APPLIED = {}


@dataclass(frozen=True, slots=True)
class InstalledSelfC04ReadersV4:
    graph: object
    issued: object
    scope: object
    environment: object

    @property
    def issuer(self):
        return self.graph._GraphCoordinator__d11_issuer

    @property
    def installed_bundle(self):
        return self.graph._GraphCoordinator__d07_execution_service_v1.bundle


@dataclass(frozen=True, slots=True)
class _ObservedSelfC04EnvironmentV4:
    graph: object
    issued: object
    scope: object
    request: PrepareIngressC04RequestV1
    asset: object
    projection_policy: object
    build_digest: str
    proof: object
    verified: object


@contextmanager
def observe_self_c04_environment_v4(graph, *, issued, scope, request, operation_kind):
    from ..domains.d04.projection_issuer_v2 import load_installed_d04_projection_assets_v2
    from ..host.installed_d06_build import verify_d06_algorithm_build
    evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
    if operation_kind not in OPERATIONS or evidence.request.operation_kind != operation_kind:
        raise ValueError("Self C04 observer changed its issued operation")
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    policy, asset = load_installed_d04_projection_assets_v2(assembly.package_root,
        assembly.installation_policy.manifest_digest, assembly.available_cpu_features)
    build = verify_d06_algorithm_build(assembly.package_root, assembly.installation_policy.manifest_digest,
        require_formal=False, require_backend_runtime=True, algorithm_id=ALGORITHM_ID_V4)
    if build["build_digest"] != "sha256:" + str(graph._GraphCoordinator__c04_direct_seed_build_digest):
        raise ValueError("Self C04 loaded V4 build differs from the actual installed Host pin")
    proof = verified = None
    if operation_kind == ADOPT_OPERATION:
        with graph._GraphCoordinator__store._lock:
            db = graph._GraphCoordinator__store._db
            db.execute("BEGIN")
            try:
                selected, original, _ = _selection(db, evidence.request.namespace, request)
                ids = ingress_c04_ids_v4(selected.namespace, selected.c02_operation_id, original["original_digest"])
                prepared = read_c04_internal_work_prepared_v1(db, selected.namespace, ids["prepare"])
                if prepared is None:
                    raise MissingProductionOriginalV1("actual_self_c04_preparation")
            finally:
                db.rollback()
        from .c04_product_lifecycle_v3 import c04_terminal_proof_from_inspection_v3
        port = graph._GraphCoordinator__c04_authority_port_v3
        proof = c04_terminal_proof_from_inspection_v3(port.inspect(prepared.binding))
        verified = port.verify_terminal(proof)
    reobserve_foreground_activity_v1(issued, graph, scope)
    value = _ObservedSelfC04EnvironmentV4(graph, issued, scope, request, asset, policy,
        build["build_digest"], proof, verified)
    _LIVE[id(value)] = value
    try:
        yield value
    finally:
        del _LIVE[id(value)]


def _environment(readers, request):
    value = readers.environment
    if (type(value) is not _ObservedSelfC04EnvironmentV4 or _LIVE.get(id(value)) is not value
            or (value.graph, value.issued, value.scope, value.request) !=
                (readers.graph, readers.issued, readers.scope, request)):
        raise ValueError("Self C04 has no actual outside-transaction installation/terminal observation")
    return value


def _selection(db, namespace, request):
    actual = read_adopted_ingress_c03_selection_v1(db, namespace=namespace, c02_operation_id=request.c02_operation_id)
    if actual is None:
        raise MissingProductionOriginalV1("actual_adopted_c03_selection")
    value, original, bridge = actual
    if (request.c03_selection_ref != "d06-current:" + original["original_digest"][:48]
            or request.c03_selection_digest != canonical_digest(value)
            or value.selected_source_ref is None
            or (value.cycle_job_ref, value.cue_source_ref) != (request.job_ref, request.source_ref)):
        raise ValueError("Self C04 request changed its actual C03 positive selection")
    return actual


def self_c04_anchor_refs_v4(db, namespace):
    focus = AtomKey(Owner("persona", *namespace.as_tuple), "d07.focus.v1", namespace.persona_id)
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (focus.token,)).fetchone()
    moods = db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND valid=1 "
        "AND type_name IN ('d04.mood_field.v1','d04.authored_mood_state.v1') ORDER BY token LIMIT 2", namespace.as_tuple).fetchall()
    if row is None or row[1] != 1 or len(moods) != 1 or json.loads(row[0])["primary_ticket_ref"] is None:
        raise MissingProductionOriginalV1("actual_unique_c04_focus_attention_mood")
    return focus.token, json.loads(row[0])["primary_ticket_ref"], moods[0][0]


def configure_self_c04_envelope_v4(db, *, graph, envelope, request, operation_kind):
    selected, original, _ = _selection(db, envelope.authority.namespace, request)
    ids = ingress_c04_ids_v4(selected.namespace, selected.c02_operation_id, original["original_digest"])
    if envelope.identity.operation_id != ids["prepare" if operation_kind == PREPARE_OPERATION else "adopt"]:
        raise ValueError("Self C04 fixed command identity differs")
    deadline = envelope.deadline_utc
    if operation_kind == PREPARE_OPERATION:
        bundle = graph._GraphCoordinator__d07_execution_service_v1.bundle
        policy = bundle.d06_recall
        cpu = graph._GraphCoordinator__c04_cpu_quote_authority.read_policy(db, selected.namespace, policy.cpu_policy_id, policy.cpu_policy_version)
        body = graph._GraphCoordinator__body_quote_authority.policy(db, selected.namespace, policy.body_policy_id, policy.body_policy_version)
        _, ticket, _ = self_c04_anchor_refs_v4(db, selected.namespace)
        row = db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1", (ticket,)).fetchone()
        deadline = min(deadline, cpu.valid_until_utc, body.valid_until, json.loads(row[0])["valid_until"])
    return replace(envelope, identity=replace(envelope.identity, effect_id=ids["effect"]),
        deadline_utc=deadline, monotonic_deadline=envelope.monotonic_deadline-(envelope.deadline_utc-deadline))


def read_plan_self_c04_v4(db, *, namespace, request, readers, operation_kind):
    selected, original, _ = _selection(db, namespace, request)
    ids = ingress_c04_ids_v4(namespace, selected.c02_operation_id, original["original_digest"])
    keys = [AtomKey.from_token(request.job_ref)]
    roots = [selected.cue_source_ref, selected.selected_source_ref]
    if operation_kind == PREPARE_OPERATION:
        keys.extend(AtomKey.from_token(ref) for ref in self_c04_anchor_refs_v4(db, namespace))
    else:
        prepared = read_c04_internal_work_prepared_v1(db, namespace, ids["prepare"])
        work = read_c04_frozen_association_original_v4(db, namespace, prepared.binding)
        keys.extend(AtomKey.from_token(row.ref) for row in work.reads)
        keys.append(job_graph_write(read_original_c04_product_job_v3(db, namespace, prepared)).key)
        roots.extend(row.ref for row in work.reads if AtomKey.from_token(row.ref).type_name == "memory.source")
    return production_read_plan_v1((), tuple(sorted(set(keys), key=lambda key:key.token)),
        tuple(sorted(set(roots))), (request.c03_selection_ref,))


@dataclass(frozen=True, slots=True)
class SelfC04PreparationStageV4:
    frame: object
    stage: object
    request: PrepareIngressC04RequestV1
    work: AssociationWorkInputV4
    before_parent: PersistentJob


def stage_self_c04_prepare_v4(db, *, frame, request, installed_readers):
    from .c04_current_projection_service_v3 import issue_current_c04_targets_v3
    env = _environment(installed_readers, request)
    graph = installed_readers.graph
    with issue_self_c04_scope_v4(graph, issued=installed_readers.issued, scope=installed_readers.scope,
            frame=frame, request=request, bundle=installed_readers.installed_bundle) as qualified:
        focus, ticket, mood = self_c04_anchor_refs_v4(db, frame.envelope.authority.namespace)
        originals = collect_self_c04_graph_v4(db, scope=qualified, focus_ref=focus,
            attention_ticket_ref=ticket, mood_ref=mood)
        encodings = []
        for row in originals.reads:
            if row.key.type_name != "memory.source" or not row.valid:
                continue
            entries = db.execute("SELECT encoding_operation_id FROM graph_c04_encoding_baselines_v3 "
                "WHERE bot=? AND persona=? AND source_ref=? LIMIT 2", (*qualified.selection.namespace.as_tuple,row.key.token)).fetchall()
            if len(entries) != 1:
                raise MissingProductionOriginalV1("actual_unique_c04_encoding_baseline")
            encodings.append((row.key.token,entries[0][0]))
        mood_head = next(row for row in originals.reads if row.key.token == mood)
        joint = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",
            (mood,mood_head.revision)).fetchone()
        if joint is None:
            raise MissingProductionOriginalV1("actual_c04_mood_joint_original")
        selected = qualified.selection
        targets = issue_current_c04_targets_v3(db, namespace=selected.namespace,
            operation_id=frame.envelope.identity.operation_id, encoding_operations=tuple(sorted(encodings)),
            mood_joint_operation_id=joint[0], mood_ref=mood, audience=frame.envelope.authority.audience[0],
            purpose=frame.envelope.authority.purpose, owner_epoch=qualified.scope.pinned_anchor.revocation_epoch,
            access_epoch=selected.access_epoch, delete_epoch=selected.delete_epoch,
            asset=env.asset, policy=env.projection_policy)
        budget = qualified.budget
        work = AssociationWorkInputV4(namespace=selected.namespace, activity_id=selected.child_activity_id,
            operation_id=frame.envelope.identity.operation_id, cue_source_ref=selected.cue_source_ref,
            focus_ref=focus, attention_ticket_ref=ticket, mood_ref=mood, selection_ticket=selected.selection_ticket,
            selection_ticket_digest=canonical_v3_digest(selected.selection_ticket), audience=selected.audience[0],
            purpose=selected.purpose, context_tags=(),
            reads=tuple(GraphHeadV3(row.key.token,row.revision,row.valid,row.value_json) for row in originals.reads),
            edge_pages=tuple(sorted((AssociationPageV3(q.source_ref,q.hop,q.edge_refs,q.next_after)
                for q in originals.edge_queries),key=lambda q:q.source_ref)), budget=budget,
            policy=ActivationPolicy(.5,.25,budget.max_iterations,budget.max_nodes,1e-6),
            graph_epoch=originals.graph_epoch.revision, owner_epoch=qualified.scope.pinned_anchor.revocation_epoch,
            access_epoch=selected.access_epoch, delete_epoch=selected.delete_epoch, truncated=originals.truncated,
            algorithm_id=ALGORITHM_ID_V4, algorithm_build_digest=env.build_digest, targets=targets,
            schema=AUTHORED_INPUT_SCHEMA_V4 if AtomKey.from_token(mood).type_name=="d04.authored_mood_state.v1" else INPUT_SCHEMA_V4,
            c03_selection_ref=qualified.selection_ref, c03_selection_original_digest=qualified.selection_original_digest,
            c03_selection_json=canonical_json(plain_v1(selected)), self_scope_digest=qualified.identity_digest)
        before = get_job(db,AtomKey.from_token(request.job_ref).name)
        stage = stage_result_v1(frame,"d06",PREPARE_OPERATION,request,provenance={"selection_ref":qualified.selection_ref},
            coverage="deferred",missing=("actual_c04_terminal",))
    return SelfC04PreparationStageV4(frame,stage,request,work,before)


def _running_job(pure, resources, quote):
    ids=ingress_c04_ids_v4(pure.work.namespace,pure.request.c02_operation_id,pure.work.c03_selection_original_digest)
    work,env=pure.work,resources.envelope
    # No predicted final input/binding digest in the stable job continuation.
    job=PersistentJob(c04_prepare_job_id_v3(work.namespace,work.operation_id),work.operation_id,work.activity_id,
        env.identity.effect_id,*work.namespace.as_tuple,quote.snapshot_ref,"queued","d06.c04_internal_cpu.v1",
        {"schema":"c04.prepared-job-continuation.v4","operation_id":work.operation_id,"execution_id":ids["execution"],
         "prepared_ref":"graph_c04_internal_work_prepared_v1/"+work.operation_id,
         "frozen_input_ref":"graph_c04_association_inputs_v3/"+work.operation_id,"algorithm_id":work.algorithm_id,
         "algorithm_build_digest":work.algorithm_build_digest.removeprefix("sha256:"),
         "activation_generation":env.authority.activation_generation,"recovery_policy":"inspect_original_binding_before_execution"},
        None,datetime.fromtimestamp(env.deadline_utc,timezone.utc).isoformat().replace("+00:00","Z"),
        env.parent_budget_lease_ref,quote.resource_ref,{"algorithm":work.algorithm_id,"build":work.algorithm_build_digest.removeprefix("sha256:"),
        "catalogue":env.version_guard.catalogue_version,"operator":env.version_guard.operator_version,
        "policy":env.version_guard.policy_version},None,None,0,0,{},None)
    return job


@dataclass(frozen=True, slots=True)
class _SelfC04CommitV4:
    runtime: object
    graph: object
    scope: object
    issued: object
    frame: object
    operation: object
    request: object
    bundle: object
    stage: object
    before_metadata: object
    before_epoch: object
    first_receipt: object
    resources: object
    child: object
    after_parent: object


def _after_parent(pure,child):
    before=foreground_cycle_from_wire_v1(pure.before_parent.continuation)
    wait=ForegroundWaitV1("d06","c04_terminal",(VersionedRef(job_graph_write(child).key.token,1),),
        QueryEpoch(pure.work.namespace,"foreground:"+pure.before_parent.job_id,pure.work.graph_epoch+2),
        before.wait.consume_cursor if before.wait is not None else 0,None)
    return replace(pure.before_parent,phase="waiting",
        continuation=plain_v1(replace(before,stage="recall",wait=wait)),
        wake_condition=plain_v1(wait),lease_holder=None,lease_expires_utc=None)


def require_self_c04_prepare_commit_v4(witness,graph,db,bundle,v2_write):
    if (type(witness) is not _SelfC04CommitV4 or _LIVE.get(id(witness)) is not witness
            or witness.graph is not graph or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or bundle != witness.bundle or v2_write is None):
        raise ValueError("Self C04 second CAS has no live fixed private witness")
    evidence=require_foreground_activity_issuance_v1(witness.issued,graph,witness.scope)
    before=witness.before_metadata
    metadata,epoch=graph._v2_graph_stamp(bundle.envelope.authority.namespace)
    if (v2_write[:2] != (metadata,epoch) or metadata.requirements != before.requirements
            or metadata.graph_revision != before.graph_revision+1 or epoch.revision != witness.before_epoch.revision+1
            or witness.first_receipt.status!="committed" or witness.first_receipt.epoch!=epoch
            or witness.scope.graph_revision!=before.graph_revision or witness.scope.graph_epoch!=witness.before_epoch
            or bundle.envelope.identity.operation_id!=evidence.request.operation_id
            or bundle.envelope.authority.actor!=evidence.current_self.self_entity_ref
            or get_job(db,witness.stage.before_parent.job_id)!=witness.stage.before_parent
            or get_job(db,witness.child.job_id)!=witness.child):
        raise ValueError("Self C04 own first CAS/parent/worker/issued identity changed")
    body=witness.resources.body.reservation_write
    if witness.first_receipt.revisions!=(GraphVersion(body.key,1),):
        raise ValueError("Self C04 first CAS changed more than its exact Body reservation")
    for version in witness.resources.read_versions:
        row=db.execute("SELECT revision FROM graph_atoms WHERE token=?",(version.key.token,)).fetchone()
        expected=1 if version.key==body.key else version.revision
        if (0 if row is None else row[0])!=expected:
            raise ValueError("Self C04 input changed between its exact two CAS writes")
    if tuple(w for p in bundle.proposals for w in p.typed_writes)!=(job_graph_write(witness.child),job_graph_write(witness.after_parent)):
        raise ValueError("Self C04 second CAS changed its exact child/parent members")
    return witness


def apply_self_c04_prepare_once_v4(witness,graph,db):
    if type(witness) is not _SelfC04CommitV4 or _LIVE.get(id(witness)) is not witness or id(witness) in _APPLIED:
        raise ValueError("Self C04 parent once hook lacks its fixed live witness")
    if get_job(db,witness.stage.before_parent.job_id)!=witness.stage.before_parent:
        raise ValueError("Self C04 parent changed before waiting checkpoint")
    _save_job(db,witness.after_parent)
    _record_operation(db,witness.after_parent,witness.bundle.envelope.identity.operation_id,"checkpoint",
        canonical_digest(plain_v1(witness.after_parent)))
    _APPLIED[id(witness)]=witness
    return True


def require_self_c04_persistent_member_v4(witness,ref):
    if (_LIVE.get(id(witness)) is not witness or _APPLIED.get(id(witness)) is not witness
            or ref not in {job_graph_write(witness.child).key.token,job_graph_write(witness.after_parent).key.token}):
        raise ValueError("Self C04 persistent member lacks its actual two-CAS witness")


def _freeze_after_cas(db,pure,resources,child,after_parent,receipt,graph,environment):
    from ..authority_service.internal_work_contract import InternalWorkBindingV1
    from .c04_interpretation_policy_v3 import record_installed_c04_interpretation_policy_v3
    ns=pure.work.namespace
    metadata,epoch=graph._v2_graph_stamp(ns)
    if (epoch.revision!=pure.work.graph_epoch+2 or receipt.status!="committed"
            or set(receipt.write_versions)!={GraphVersion(job_graph_write(child).key,1),
                next(v for v in receipt.write_versions if v.key==job_graph_write(after_parent).key)}):
        raise ValueError("Self C04 final freeze lacks its exact second CAS receipt")
    work=replace(pure.work,graph_epoch=epoch.revision)
    _verify_current_association_input_heads_common_v3(db,work)
    quote=graph._GraphCoordinator__c04_cpu_quote_authority.read_original_request_quote(db,ns,work.operation_id)[1]
    body=resources.body.body_quote
    if len(body.components)!=1 or body.components[0].duration_rate!=0:
        raise ValueError("Self C04 requires the actual fixed Body component")
    ids=ingress_c04_ids_v4(ns,pure.request.c02_operation_id,work.c03_selection_original_digest)
    from ..graph_coordinator import namespace_ref
    binding=InternalWorkBindingV1(namespace_ref(ns),work.activity_id,work.operation_id,ids["execution"],
        work.input_digest.removeprefix("sha256:"),quote.quote_id,quote.version,canonical_digest(quote),
        body.quote_id,resources.body.body_quote_version,canonical_digest(body),resources.body.reservation_write.key.token,
        body.components[0].component_id,quote.parent_budget_lease_ref,pure.frame.activation_generation,
        work.algorithm_id,quote.snapshot_ref,work.algorithm_build_digest.removeprefix("sha256:"))
    op="c04-internal-budget:"+binding.binding_digest
    reserved=reserve_budget(db,binding.parent_budget_lease_ref,op,binding.binding_digest,quote.ceiling)
    row=db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",(*ns.as_tuple,op)).fetchone()
    if reserved.status!="reserved" or row is None or row[:2]!=(binding.binding_digest,binding.parent_budget_lease_ref):
        raise ValueError("Self C04 final CPU reservation differs")
    reads={v.key.token:v.revision for v in resources.read_versions}
    reads[resources.body.reservation_write.key.token]=1
    for version in receipt.write_versions:
        reads[version.key.token]=version.revision
    owner=pure.frame.owner_guard
    prepared=C04InternalWorkPreparedV1(binding,resources.body_profile_ref,resources.body_profile_revision,
        resources.body_state_ref,resources.body_state_revision,1,owner.grant_ref,owner.grant_revision,owner.grant_digest,
        op,hashlib.sha256(row[2].encode()).hexdigest(),tuple(sorted(reads.items())),metadata.graph_revision,work.access_epoch,work.delete_epoch)
    record_c04_internal_work_prepared_v1(db,ns,prepared)
    record_c04_frozen_association_original_v4(db,ns,binding,work,asset=environment.asset,policy=environment.projection_policy)
    record_c04_product_request_v3(db,envelope=pure.frame.envelope,prepared=prepared,request_digest=pure.stage.request_digest)
    bundle=graph._GraphCoordinator__d07_execution_service_v1.bundle
    record_installed_c04_interpretation_policy_v3(db,ns,prepared,
        installation_id=bundle.installation_policy.installation_id,manifest_digest=bundle.installation_policy.manifest_digest)
    return prepared,work


def commit_self_c04_prepare_v4(runtime,db,*,operation,request,frame,stage,readers,scope,metadata,epoch,process_lease,owner,guard,external_originals):
    from .domain_production_commit_v1 import foreground_domain_finish_digest_v1
    from ..authority_service.v2_contract import to_wire
    graph=runtime.graph;store=graph._GraphCoordinator__store;cap=graph._GraphCoordinator__graph_capability
    environment=_environment(readers,request)
    if stage_self_c04_prepare_v4(db,frame=frame,request=request,installed_readers=readers)!=stage:
        raise ValueError("Self C04 pure preparation changed")
    with issue_self_c04_scope_v4(graph,issued=readers.issued,scope=scope,frame=frame,request=request,bundle=readers.installed_bundle) as qualified:
        self_scope_original=export_self_c04_scope_original_v5(qualified,db,expected_digest=stage.work.self_scope_digest)
        resources=prepare_self_c04_body_resources_v4(db,scope=qualified,work=stage.work)
    quote_ref=resources.envelope.version_guard.resource_lease_versions[0]
    db.execute("INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)",
        (*stage.work.namespace.as_tuple,"resource_lease",quote_ref.ref,str(quote_ref.version)))
    body=resources.body.reservation_write
    first=GraphStore._graph_commit_in_transaction(store,GraphCandidate(
        Event(Scope(*stage.work.namespace.as_tuple,stage.work.activity_id),"c04-prepare:"+stage.work.operation_id,
            frame.now_utc,"c04.self_body_prepared.v4",{"request_digest":stage.stage.request_digest}),
        resources.read_versions,(body,),(epoch,)),_capability=cap)
    if first.status!="committed" or first.epoch.revision!=epoch.revision+1:
        raise ValueError("Self C04 first reservation CAS differs")
    store.cas_graph_recovery_metadata(metadata,metadata.requirements,_capability=cap)
    mid,mid_epoch=graph._v2_graph_stamp(stage.work.namespace)
    quote=graph._GraphCoordinator__c04_cpu_quote_authority.read_original_request_quote(db,stage.work.namespace,stage.work.operation_id)[1]
    if frame.envelope.deadline_utc-frame.now_utc<1:
        raise ValueError("Self C04 has no whole second of original worker lifetime")
    child=_running_job(stage,resources,quote)
    create_job(db,child,"c04-prepare-running:"+canonical_digest((stage.work.namespace,stage.work.operation_id))[:48],canonical_digest(child))
    child=acquire_job(db,child.job_id,graph._GraphCoordinator__holder,
        now_utc=datetime.fromtimestamp(frame.now_utc,timezone.utc).isoformat().replace("+00:00","Z"),
        lease_seconds=min(300,max(1,int(frame.envelope.deadline_utc-frame.now_utc))))
    after=_after_parent(stage,child)
    keys={v.key for v in (*resources.read_versions,*frame.snapshot.versions)}|{job_graph_write(child).key}
    atoms=[]
    for key in sorted(keys,key=lambda key:key.token):
        row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(key.token,)).fetchone()
        atoms.append(GraphAtom(key,row[0],json.loads(row[1]),bool(row[2])) if row else GraphAtom(key,0,{},False))
    snapshot=GraphSnapshot(tuple(atoms),(mid_epoch,))
    envelope=replace(resources.envelope,version_guard=replace(resources.envelope.version_guard,
        read_versions=snapshot.versions,query_epochs=(QueryEpoch(stage.work.namespace,"namespace",mid_epoch.revision),)))
    frame2=replace(frame,envelope=envelope,snapshot=snapshot,query_coverage=())
    registration=graph._GraphCoordinator__providers["d11"]
    proposal=DomainProposal("d11",registration[1],registration[2],envelope,
        (job_graph_write(child),job_graph_write(after)),DependencySet(),(),())
    bundle=DomainBundle(envelope,(proposal,),(),(),(),(),(frame.envelope.identity.operation_id,),
        (job_graph_write(child).key.token,job_graph_write(after).key.token),())
    witness=_SelfC04CommitV4(runtime,graph,scope,readers.issued,frame2,operation,request,bundle,stage,
        metadata,epoch,first,resources,child,after)
    _LIVE[id(witness)]=witness
    try:
        receipt=graph._commit_domain_bundle_fenced(bundle,process_lease,in_transaction=True,now_utc=frame.now_utc,
            v2_write=(mid,mid_epoch,"finish:"+scope.operation_id,
                foreground_domain_finish_digest_v1(readers.issued.evidence.request,scope.permit),canonical_json(to_wire(scope.permit))),
            domain_production_issuance_v1=witness)
        require_self_c04_persistent_member_v4(witness,job_graph_write(child).key.token)
    finally:
        _LIVE.pop(id(witness),None);_APPLIED.pop(id(witness),None)
    prepared,work=_freeze_after_cas(db,stage,resources,child,after,receipt,graph,environment)
    if canonical_digest(json.loads(self_scope_original)["scope_payload"])!=work.self_scope_digest:
        raise ValueError("Self C04 captured preimage differs after the actual preparation CAS")
    provenance={"schema":"c04.self-foreground-preparation.v5","binding_digest":prepared.binding.binding_digest,
        "prepared_digest":prepared.prepared_digest,"selection_ref":request.c03_selection_ref,
        "self_scope_digest":work.self_scope_digest,"initiating_self":frame.envelope.authority.actor,
        "owner_guard":plain_v1(frame.owner_guard),"before_parent":plain_v1(stage.before_parent),
        "after_parent":plain_v1(after),"child_job_ref":job_graph_write(child).key.token,
        "reservation_receipt_digest":canonical_digest(first),"self_scope_original":json.loads(self_scope_original)}
    primary=stage_result_v1(frame,"d06",PREPARE_OPERATION,request,provenance=provenance,
        coverage="deferred",missing=("actual_c04_terminal",),continuation=child.job_id)
    original=record_adopted_domain_operation_v1(db,primary,receipt)
    return {"schema":"sylanne.domain-production-receipt.v1","domain":"d06","operation_kind":PREPARE_OPERATION,
        "operation_id":work.operation_id,"activity_id":work.activity_id,"original_ref":original.original_ref,
        "original_digest":original.original_digest,"receipt":_receipt_wire(receipt),"receipt_digest":canonical_digest(receipt),
        "job_states":[[child.job_id,"running"],[after.job_id,"waiting"]],"coverage":"deferred",
        "missing_inputs":["actual_c04_terminal"],"continuation_ref":child.job_id,"outbox":[],"produced_originals":[]}


def require_current_self_c04_parent_v4(db, *, namespace, binding, work, prepared, installed_bundle, issuer, current_self, now_utc):
    if (type(work) is not AssociationWorkInputV4 or prepared.binding!=binding or namespace!=work.namespace
            or current_self.namespace!=namespace or current_self.activation_generation!=binding.activation_generation):
        raise ValueError("Self C04 parent reader needs exact actual frozen originals")
    original=read_adopted_domain_operation_v1(db,namespace,binding.operation_id)
    if original is None or original["operation_kind"]!=PREPARE_OPERATION:
        raise ValueError("Self C04 actual Foreground preparation receipt is absent")
    p=original["payload"]["provenance"]
    validate_self_c04_provenance_v4("d06",PREPARE_OPERATION,p)
    if (p["binding_digest"]!=binding.binding_digest
            or p["prepared_digest"]!=prepared.prepared_digest or p["self_scope_digest"]!=work.self_scope_digest
            or p["initiating_self"]!=current_self.self_entity_ref):
        raise ValueError("Self C04 preparation provenance/current Self differs")
    before=decode_foreground_job_v1(p["before_parent"]);after=decode_foreground_job_v1(p["after_parent"])
    cycle=get_job(db,after.job_id)
    current=foreground_cycle_from_wire_v1(cycle.continuation)
    old=foreground_cycle_from_wire_v1(before.continuation)
    selected=work.direct_selection
    child=read_original_c04_product_job_v3(db,namespace,prepared)
    if (cycle!=after or cycle.phase!="waiting" or cycle.lease_holder is not None or cycle.cancel_epoch
            or current.stage!="recall" or current.cancel_generation or current.call_plan!=old.call_plan
            or current.c02_operation_id!=selected.c02_operation_id or current.source_ref!=selected.cue_source_ref
            or current.wait is None or current.wait.producer_domain!="d06" or current.wait.event_kind!="c04_terminal"
            or current.wait.observed_versions!=(VersionedRef(job_graph_write(child).key.token,1),)
            or child.phase!="running" or child.fence!=1 or child.cancel_epoch or child.lease_holder is None
            or child.lease_expires_utc is None or now_utc>=min(
                datetime.fromisoformat(child.lease_expires_utc.replace("Z","+00:00")).timestamp(),
                datetime.fromisoformat(child.deadline_utc.replace("Z","+00:00")).timestamp())):
        raise ValueError("Self C04 original waiting parent or acquired child changed")
    for job in (cycle,child):
        row=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(job_graph_write(job).key.token,)).fetchone()
        if row is None or row[1]!=1 or json.loads(row[0])!=job_graph_write(job).value:
            raise ValueError("Self C04 current SQL/Graph job differs")
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    owner=decode_typed_production_value_v1(p["owner_guard"],ProductionOwnerGuardV1)
    responsibility=require_current_foreground_responsibility_v1(db,namespace=namespace,job=cycle,
        installed_bundle=installed_bundle,issuer=issuer,owner_guard=owner,
        purpose=work.purpose,audiences=(work.audience,),now_utc=now_utc)
    if responsibility is None or responsibility.digest!=selected.responsibility_digest:
        raise ValueError("Self C04 actual original parent responsibility changed")
    return cycle


def validate_self_c04_provenance_v4(domain,operation_kind,value):
    from .domain_production_erasure_v1 import _exact,decode_typed_production_value_v1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    if domain!="d06" or operation_kind not in OPERATIONS:
        raise ValueError("Self C04 provenance has another exact writer")
    if operation_kind==PREPARE_OPERATION:
        common={"schema","binding_digest","prepared_digest","selection_ref","self_scope_digest","initiating_self",
            "owner_guard","before_parent","after_parent","child_job_ref","reservation_receipt_digest"}
        if value["schema"]=="c04.self-foreground-preparation.v4":
            _exact(value,common)
        elif value["schema"]=="c04.self-foreground-preparation.v5":
            _exact(value,common|{'self_scope_original'})
            original=value['self_scope_original'];_exact(original,{'schema','scope_payload','current_self_wire'})
            material=original['scope_payload']
            _exact(material,{'schema','request','selection_original_digest','self','owner_guard','authority','identity','deadline',
                'budget','policy','responsibility_digest','c03_metadata_bridge'})
            from ..authority_service.v2_self_identity_contract import from_wire,to_wire,AuthorityCurrentSelfIdentityV1
            current=from_wire(original['current_self_wire'])
            if (original['schema']!='c04.self-preparation-original.v1' or material['schema']!='c04.self-preparation-scope.v4'
                    or type(current) is not AuthorityCurrentSelfIdentityV1 or to_wire(current)!=original['current_self_wire']
                    or canonical_serialize(current)!=canonical_serialize(material['self'])
                    or canonical_digest(material)!=value['self_scope_digest'] or current.self_entity_ref!=value['initiating_self']):
                raise ValueError('Self C04 V5 captured private scope preimage differs')
        else:raise ValueError("Self C04 preparation schema differs")
        decode_typed_production_value_v1(value["owner_guard"],ProductionOwnerGuardV1)
        child=AtomKey.from_token(value["child_job_ref"])
        if child.type_name!="runtime.job":
            raise ValueError("Self C04 child locator differs")
        digest_names=("binding_digest","prepared_digest","self_scope_digest","reservation_receipt_digest")
    else:
        _exact(value,{"schema","binding_digest","prepare_operation_id","adoption_operation_id","plan_digest",
            "proof_digest","before_parent","after_parent"})
        if (value["schema"]!="c04.self-foreground-adoption.v4"
                or value["prepare_operation_id"]==value["adoption_operation_id"]):
            raise ValueError("Self C04 adopted command identity differs")
        digest_names=("binding_digest","proof_digest")
        if not value["plan_digest"].startswith("sha256:"):
            raise ValueError("Self C04 numeric plan digest differs")
    for name in digest_names:
        digest=value[name]
        if type(digest) is not str or len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Self C04 exact provenance commitment differs")
    before=decode_foreground_job_v1(value["before_parent"]);after=decode_foreground_job_v1(value["after_parent"])
    old=foreground_cycle_from_wire_v1(before.continuation);current=foreground_cycle_from_wire_v1(after.continuation)
    if ((before.job_id,before.operation_id,before.activity_id,before.budget_ref,before.deadline_utc,before.cancel_epoch)
            !=(after.job_id,after.operation_id,after.activity_id,after.budget_ref,after.deadline_utc,after.cancel_epoch)
            or old.call_plan!=current.call_plan or after.lease_holder is not None or after.lease_expires_utc is not None):
        raise ValueError("Self C04 changed the actual parent identity or model CallPlan")
    if operation_kind==PREPARE_OPERATION:
        if (before.phase!="running" or after.phase!="waiting" or current.stage!="recall"
                or current.wait is None or current.wait.producer_domain!="d06" or current.wait.event_kind!="c04_terminal"
                or current.wait.observed_versions!=(VersionedRef(child.token,1),)):
            raise ValueError("Self C04 prepared parent wait differs")
    elif before.phase!="waiting" or after.phase!="queued" or current.stage!="revise_plan" or current.wait is not None:
        raise ValueError("Self C04 adopted parent continuation differs")
