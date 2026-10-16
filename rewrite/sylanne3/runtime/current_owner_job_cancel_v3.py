"""Exact acquired Life Numeric job cancellation on its own retained Owner Work."""
from contextlib import contextmanager
from datetime import datetime
from weakref import WeakKeyDictionary
import time

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3)
from ..graph_worker import (GraphStorageStepV3,GraphStorageWorkV3,create_graph_storage_work_v3,
    require_graph_storage_work_admission_v3)
from .current_method_learning_read_v3 import (_READERS,_READING,_MethodLearningReadV3,_MethodPointReadV3,
    _GeneralMethodSourceMetadataEOFV1,_GENERAL_METHOD_SOURCE_ISSUER_V1,_GENERAL_METHOD_SOURCE_TASKS_V1,
    begin_current_method_learning_read_v3,bind_prepared_method_learning_read_v3,
    _prepare_current_general_method_owner_entry_v1,qualify_method_source_metadata_kernel_v1,
    _release_method_registered_payloads_v3,MethodInputNeededV3,_method_active,
    read_bound_method_learning_attachment_v3,method_graph_head_v3)
from .current_life_numeric_metadata_v1 import _metadata,NumericMetadataTaskV1
from .dispatch_current_inventory_v3 import _heap,_freeze_value_v3,_detach_value_v3

CANCEL_WORK_KIND_V3="current_owner_job_cancel_v3"
CANCEL_OPERATION_V3="cancel_current_owner_job_v3"
_CANCEL_WORKS=WeakKeyDictionary()
_CANCEL_RECIPES=WeakKeyDictionary()
_CANCEL_SOURCES=WeakKeyDictionary()
_CANCEL_CAPSULES=WeakKeyDictionary()
_CANCEL_WRITES=WeakKeyDictionary()
_CANCEL_WRITE_AUTHORITIES=WeakKeyDictionary()
_JOB_COLUMNS=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref","phase","work_kind",
    "continuation_json","wake_condition_json","deadline_utc","budget_ref","resource_ref","operator_versions_json",
    "lease_holder","lease_expires_utc","fence","cancel_epoch","usage_json","result_ref")
_JOB_METADATA=("operation_id","activity_id","bot_id","persona_id","phase","work_kind","deadline_utc",
    "budget_ref","resource_ref","lease_holder","lease_expires_utc","fence","cancel_epoch")
_PRIOR_COLUMNS=("digest","job_id","job_json")
_ATTEMPT_COLUMNS=("request_digest","attempt_id","anchor_json","graph_revision","graph_epoch","permit_json","receipt_json")
_ORIGINAL_COLUMNS=("operation_id","original_digest","original_json")
_OWNER_FIELDS=("principal","actor","namespace","purpose","audience","grant_id","scope","issuer_ref","capabilities","purposes","audiences",
    "grant_digest","grant_revision","access_epoch","delete_epoch","graph_incarnation","authorization_head",
    "authorization_revision","revocation_epoch","target_admission","storage_admission")

def _identity(r):
    return (r.graph,r.runtime,r.authority,r.lease,r.fence,r.operation,r.request,r.request_digest,
        r.operation_kind,r.work,r.selection_digest,r.operation_id,r.session_proof)

def require_current_job_cancel_work_v3(r):
    if (type(r)is not _MethodLearningReadV3 or r not in _READERS or r.operation_kind!=CANCEL_OPERATION_V3
            or _CANCEL_WORKS.get(r)!=_identity(r) or type(r.work)is not GraphStorageWorkV3
            or r.work.kind!=CANCEL_WORK_KIND_V3 or r.work.state is not r or r.work.operation is not r.operation
            or r.work.coordinator is not r.graph or r.operation.closed or r.session_proof is None
            or r.runtime is not r.graph._GraphCoordinator__domain_production_runtime_v1
            or r.fence.scope.operation!="read" or any((r.background_followup,r.background_host_lifecycle,r.background_offline))
            or r.authority.purpose!="workbench_user_action" or "workbench.control"not in r.owner_binding.capabilities):
        raise AuthorityUnavailable("D12 cancel requires its private exact Work/current Owner control/session")
    r.work._require_invocation(r.graph)
    return r

def prepare_current_job_cancel_v3(access,authority,lease,*,operation_id,request_digest,command,commit,domains):
    from .lifecycle_operations_v1 import ControlCommandV1
    from .first_ingress_v2 import trusted_upper
    from ..model_broker.internal_life_numeric_v1 import WORK_KIND,TEMPLATE_VERSION
    graph=access.coordinator
    require_graph_storage_work_admission_v3(graph)
    if (type(command)is not ControlCommandV1 or command.control!="cancel_job" or command.config_diff
            or command.test_intent is not None or not command.object_ref.startswith("job:") or not command.object_ref[4:]
            or tuple(domains)!=("d11",)):
        raise AuthorityUnavailable("D12 cancel requires its exact production command selector")
    graph._authorize(lease,authority,frozenset(domains),owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if owner is None or session is None or assembly is None or "workbench.control"not in owner.capabilities:
        raise AuthorityUnavailable("D12 cancel current installed Owner control unavailable")
    bundle=assembly.admin_bundle;workflow=bundle.model_workflows.life_numeric
    if (bundle.installation_policy.namespace!=authority.namespace or authority.purpose!="workbench_user_action"
            or workflow is None or workflow.work_kind!=WORK_KIND or workflow.template_version!=TEMPLATE_VERSION
            or workflow.purpose!="consolidation" or not authority.audience
            or not set(authority.audience)<=set(workflow.audiences)):
        raise AuthorityUnavailable("D12 cancel has no actual registered acquired job recipe")
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,now+60.0)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id,owner_session_proof=session)
            r=begin_current_method_learning_read_v3(graph,operation,fence,runtime=graph._GraphCoordinator__domain_production_runtime_v1,
                authority=authority,lease=lease,operation_kind=CANCEL_OPERATION_V3,request=command,operation_id=operation_id,
                activity_id=operation_id,audience_ref=authority.audience[0],
                parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id,request_digest=request_digest,
                owner_binding=owner,owner_guard=None,session_proof=session,initial_now_utc=now)
            r.initial_monotonic_deadline=time.monotonic()+60.0
            r.background_followup=r.background_host_lifecycle=r.background_offline=None
            r.cancel_access,r.cancel_commit,r.cancel_domains=access,commit,tuple(domains)
            r.cancel_now=now;r.cancel_job=r.cancel_projection=None;r.cancel_updated=None
            r.cancel_attempt=r.cancel_replay=None
        work=create_graph_storage_work_v3(graph,kind=CANCEL_WORK_KIND_V3,operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=r,operation=operation)
        work._require_invocation(graph,initial=True);r.work=work
        _CANCEL_WORKS[r]=_identity(r);work.phase="cancel_owner_eof"
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise

def require_cancel_metadata_selector_v3(r,identity):
    require_current_job_cancel_work_v3(r)
    mode,profile,ref=identity
    job_id=r.request.object_ref[4:]
    if (mode,profile)==("cancel_job","cancel_continuation") and ref==job_id:return
    recipe=_CANCEL_RECIPES.get(r)
    if recipe is not None and identity in recipe["selectors"]:return
    raise AuthorityUnavailable("D12 cancel metadata escaped its registered actual selected job recipe")

def _utc(value):
    return datetime.fromisoformat(value.replace("Z","+00:00")).timestamp()

def _check_deadline(r):
    recipe=_CANCEL_RECIPES.get(r)
    deadline=min(r.operation.deadline_utc,recipe["deadline"] if recipe is not None and "deadline"in recipe else r.operation.deadline_utc)
    if r.cancel_now>=deadline or time.monotonic()>=r.initial_monotonic_deadline:
        raise AuthorityUnavailable("D12 cancel exceeded its original retained job/Work deadline")

def _prepare_cancel_recipe(r):
    from .d06_internal_life_episode_v2 import EPISODE,PROVENANCE
    from .d04_life_before_original_v1 import life_d04_before_ref_v1
    from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1
    from ..model_broker.internal_life_numeric_v1 import InternalLifeNumericIdentityV1,internal_life_numeric_ids_v1,WORK_KIND
    from .d06_life_numeric_worker_v1 import decode_life_numeric_worker_binding_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    from .domain_production_originals_v1 import _receipt
    from .d11_types import runtime_job_key
    from .d01_production_operations_v1 import production_read_plan_v1
    saved=_CANCEL_RECIPES.get(r)
    if saved is not None and saved.get("ready"):
        with runtime_storage_quantum_v3(r.db)as meter:
            for task in saved["tasks"]:task.require_header_v1(meter)
            _require_cancel_acquisition_metadata_v3(r,saved,meter)
        _check_deadline(r);return saved
    continuation,job_task=_metadata(r,"cancel_job","cancel_continuation",r.request.object_ref[4:])
    job=dict(zip(_JOB_METADATA,job_task.metadata))
    if (job["bot_id"],job["persona_id"])!=r.namespace.as_tuple or job["work_kind"]!=WORK_KIND:
        raise AuthorityUnavailable("D12 cancel selected job has no registered actual Numeric recipe")
    episode=AtomKey.from_token(continuation["episode_ref"])
    if episode.type_name!=EPISODE or NamespaceId.from_key(episode)!=r.namespace:
        raise AuthorityUnavailable("D12 cancel job occurrence metadata crossed namespace")
    provenance=AtomKey(episode.owner,PROVENANCE,"record")
    recipe=_CANCEL_RECIPES.setdefault(r,{"selectors":set(),"tasks":(),"roots":(),"expectations":{}})
    recipe["selectors"].add(("graph","episode",provenance.token))
    proof,proof_task=_metadata(r,"graph","episode",provenance.token)
    activity=proof["event"]["activity"]
    if (proof["episode"]["episode_ref"]!=episode.token or NamespaceId(**proof["event"]["namespace"])!=r.namespace
            or proof["event"]["causal_operation_id"]!=continuation["causal_operation_id"]
            or proof["episode"]["source_refs"]!=[activity["source_ref"]]):
        raise AuthorityUnavailable("D12 cancel actual occurrence/cause/Source differs")
    before_ref=life_d04_before_ref_v1(r.namespace,activity["execution_id"])
    context_ref=life_numeric_context_ids_v1(r.namespace,episode.token)["original"]
    recipe["selectors"].update({("life","before",before_ref),("life","context",context_ref)})
    before,before_task=_metadata(r,"life","before",before_ref)
    context,context_task=_metadata(r,"life","context",context_ref)
    if (NamespaceId(**before["namespace"])!=r.namespace or before["original_ref"]!=before_ref
            or before["execution_id"]!=activity["execution_id"] or NamespaceId(**context["namespace"])!=r.namespace
            or context["episode_ref"]!=episode.token or context["execution_id"]!=activity["execution_id"]
            or context["source_ref"]!=activity["source_ref"] or context["before_ref"]!=before_ref
            or context["before_digest"]!=before_task.column.canonical_digest):
        raise AuthorityUnavailable("D12 cancel actual Context/Before Source identity differs")
    identity=InternalLifeNumericIdentityV1(r.namespace,episode.token,context["execution_id"],context["source_ref"],
        context["occurrence_digest"],context["before_digest"],context_task.column.canonical_digest)
    ids=internal_life_numeric_ids_v1(identity)
    if ids["job"]!=r.request.object_ref[4:]:
        raise AuthorityUnavailable("D12 cancel selected job differs from actual registered once identity")
    recipe["selectors"].update(("life",profile,ids["job"])for profile in ("prepared","binding","request","acquire_commit"))
    recipe["selectors"].add(("cancel_prepare","cancel_prepare_commit",ids["prepare"]))
    prepare_commit,prepare_commit_task=_metadata(r,"cancel_prepare","cancel_prepare_commit",ids["prepare"])
    prepared,prepared_task=_metadata(r,"life","prepared",ids["job"])
    binding_raw,binding_task=_metadata(r,"life","binding",ids["job"])
    request,request_task=_metadata(r,"life","request",ids["job"])
    committed,commit_task=_metadata(r,"life","acquire_commit",ids["job"])
    binding=decode_life_numeric_worker_binding_v1(binding_raw)
    acquisition=_receipt(committed["receipt"])
    job_key=runtime_job_key(*r.namespace.as_tuple,activity["activity_id"],ids["job"])
    versions=acquisition.write_versions
    if (acquisition.status!="committed"or acquisition.operation_id!=ids["acquire"]
            or acquisition.activity_id!=activity["activity_id"]or len(versions)!=1
            or versions[0].key!=job_key or versions[0].revision<1
            or committed["receipt_digest"]!=canonical_digest(acquisition)):
        raise AuthorityUnavailable("D12 cancel actual acquisition receipt lost its exact selected job version")
    history_key=(job_key.token,versions[0].revision)
    with runtime_storage_quantum_v3(r.db)as meter:
        acquired=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",("digest","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,ids["acquire"]))
        history=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_history",("event_id","valid","event_bot","event_persona","value_cell_id"),
            "token=? AND revision=?",history_key)
    if (acquired!=(acquisition.operation_digest,acquisition.commit_seq)or history is None
            or history[:4]!=(ids["acquire"],1,*r.namespace.as_tuple)):
        raise AuthorityUnavailable("D12 cancel acquisition job history metadata has no exact actual committed producer")
    port=r.graph._GraphCoordinator__content_fence_v2;grant=port.installation_grant
    if ((prepared["job_id"],prepared["call_id"],prepared["activity_id"],prepared["causal_operation_id"])!=
            (ids["job"],ids["call"],activity["activity_id"],continuation["causal_operation_id"])
            or prepared["frozen"]["identity"]!=plain_v1(identity) or tuple(prepared["audience"])!=tuple(r.authority.audience)
            or (binding.namespace,binding.job_id,binding.call_id,binding.acquire_operation_id)!=
                (r.namespace,ids["job"],ids["call"],ids["acquire"])
            or (binding.installation_id,binding.manifest_digest,binding.worker_subject,binding.installation_grant_digest)!=
                (grant.installation_id,grant.manifest_digest,grant.subject,canonical_digest(grant))
            or binding.owner_principal!=r.owner_binding.principal or binding.owner_actor!=r.owner_binding.actor
            or binding.owner_guard!=r.material_owner_guard or binding.graph_incarnation!=r.owner_binding.graph_incarnation
            or binding.activation_generation!=r.authority.activation_generation
            or prepared_task.metadata[0]!=ids["prepare"]
            or any(task.metadata[0]!=ids["acquire"]for task in (binding_task,request_task,commit_task))
            or binding.prepared_digest!=prepared_task.column.canonical_digest
            or (request["prepared_digest"],request["binding_digest"])!=(binding.prepared_digest,binding.digest)
            or (committed["prepared_digest"],committed["binding_digest"],committed["request_digest"])!=
                (binding.prepared_digest,binding.digest,request["request_digest"])
            or continuation["numeric_input_digest"]!=prepare_commit["provenance"]["numeric_input_digest"]
            or prepare_commit["provenance"]["prepared_digest"]!=prepared_task.column.canonical_digest
            or (job["operation_id"],job["activity_id"])!=(ids["prepare"],prepared["activity_id"])
            or job["phase"]not in {"running","draining","completed","failed","cancelled"} or job["fence"]<1 or job["cancel_epoch"]<0
            or (job["phase"]in {"running","draining"}and job["lease_holder"]!=binding.worker_subject)
            or (job["lease_holder"]is not None and job["lease_holder"]!=binding.worker_subject)
            or job["budget_ref"]!=r.parent_budget_lease_ref):
        raise AuthorityUnavailable("D12 cancel actual acquired job/current Owner/signed preparation binding differs")
    roots={activity["source_ref"],context["source_ref"],*before["source_roots"]};expectations={}
    for row in (*proof["current_reads"],*prepared["read_rows"]):
        key=AtomKey.from_token(row["ref"])
        if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable("D12 cancel prepared current read crossed namespace")
        if key.type_name in {"memory.source","memory.access"}:
            if key.token in expectations and expectations[key.token]!=row["revision"]:
                raise AuthorityUnavailable("D12 cancel signed current version evidence conflicts")
            expectations[key.token]=row["revision"]
            if key.type_name=="memory.source":roots.add(key.token)
    if context["source_ref"]in expectations and expectations[context["source_ref"]]!=context["source_revision"]:
        raise AuthorityUnavailable("D12 cancel actual Context revision differs from signed prepared Source")
    expectations[context["source_ref"]]=context["source_revision"]
    for raw in request_task.column.envelope_metadata["envelope"]["version_guard"]["read_versions"]:
        value=raw["key"];key=AtomKey(Owner(**value["owner"]),value["type_name"],value["name"])
        if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable("D12 cancel signed envelope crossed namespace")
        if key.type_name in {"memory.source","memory.access"}:
            if key.token in expectations and expectations[key.token]!=raw["revision"]:
                raise AuthorityUnavailable("D12 cancel signed envelope current version differs")
            expectations[key.token]=raw["revision"]
            if key.type_name=="memory.source":roots.add(key.token)
    recipe.update(identity=identity,ids=ids,binding=binding,job=job_task.metadata,continuation=continuation,
        history_key=history_key,history=history,acquired=acquired,
        tasks=(job_task,proof_task,before_task,context_task,prepared_task,binding_task,request_task,commit_task,prepare_commit_task),
        roots=tuple(sorted(roots)),expectations=expectations,
        deadline=min(binding.deadline_utc,_utc(job["deadline_utc"]),
            _utc(job["lease_expires_utc"])if job["lease_expires_utc"]is not None else binding.deadline_utc))
    r.selected_plan=production_read_plan_v1((),(),recipe["roots"],())
    recipe["ready"]=True
    r.operation.retain(_heap(recipe)+1024);_check_deadline(r)
    return recipe

def _require_cancel_acquisition_metadata_v3(r,recipe,meter):
    history=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_history",("event_id","valid","event_bot","event_persona","value_cell_id"),
        "token=? AND revision=?",recipe["history_key"])
    acquired=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",("digest","commit_seq"),
        "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,recipe["ids"]["acquire"]))
    if (history,acquired)!=(recipe["history"],recipe["acquired"]):
        raise AuthorityUnavailable("D12 cancel exact actual acquisition metadata changed after preparation")

def require_cancel_source_purposes_v3(r,purposes):
    require_current_job_cancel_work_v3(r)
    recipe=_CANCEL_RECIPES.get(r)
    if recipe is None or not recipe["roots"] or tuple(purposes)!=("context","consolidation"):
        raise AuthorityUnavailable("D12 cancel Source traversal has no complete actual registered purposes")

def _qualify_cancel_sources(r):
    recipe=_CANCEL_RECIPES[r]
    if r.general_owner_entry is None:raise AuthorityUnavailable("D12 cancel requires independent current Owner metadata EOF")
    r.general_owner_entry.require_for_v3(r)
    if r in _CANCEL_SOURCES:return _CANCEL_SOURCES[r]
    records,versions=qualify_method_source_metadata_kernel_v1(r,recipe["roots"],purposes=("context","consolidation"))
    actual={key.token:version.revision for key,version in versions.items()}
    if any(actual.get(ref)!=revision for ref,revision in recipe["expectations"].items()):
        raise AuthorityUnavailable("D12 cancel actual ALLSource versions differ from signed prepared reads")
    proof=(r.work,r.operation,r.selection_digest,r.graph_stamp,recipe["roots"],tuple(records),tuple(versions.values()))
    r.operation.retain(_heap(proof)+1024);_CANCEL_SOURCES[r]=proof
    return proof

def require_cancel_job_body_v3(r,table,key):
    require_current_job_cancel_work_v3(r)
    if table=="graph_atoms":
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        atom=AtomKey.from_token(key[0])
        from ..graph_types import owner_grant_key
        from ..memory_types import source_key
        if atom==owner_grant_key(*r.namespace.as_tuple):return r
        leaf=_GENERAL_METHOD_SOURCE_TASKS_V1.get(r,{}).get(source_key(*r.namespace.as_tuple,atom.owner.subject or "").token)
        if leaf is not None and leaf.complete and atom in {access_key(*r.namespace.as_tuple,atom.owner.subject),
                source_correction_head_key(r.namespace,atom.owner.subject)}:return r
    recipe=_CANCEL_RECIPES.get(r)
    proof=_CANCEL_SOURCES.get(r)
    if (r.inputs_sealed or proof is None or recipe is None
            or proof[:5]!=(r.work,r.operation,r.selection_digest,r.graph_stamp,recipe["roots"])):
        raise AuthorityUnavailable("D12 selected job body requires ALL actual Source/ancestor EOF before WRITE")
    return r

def require_cancel_job_point_v3(r,request):
    require_cancel_job_body_v3(r,request[0],request[3])
    table,columns,key_columns,key=request
    job_id=r.request.object_ref[4:]
    if table=="graph_atoms" and tuple(columns)==("revision","value","valid") and tuple(key_columns)==("token","bot","persona"):
        from .d11_types import runtime_job_key
        recipe=_CANCEL_RECIPES.get(r)
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=r.namespace or tuple(key[1:])!=r.namespace.as_tuple:
            raise AuthorityUnavailable("D12 selected Graph point crossed exact namespace")
        if _CANCEL_SOURCES.get(r)is None:return r
        allowed=recipe is not None and tuple(key)==(runtime_job_key(*r.namespace.as_tuple,dict(zip(_JOB_METADATA,recipe["job"]))["activity_id"],job_id).token,*r.namespace.as_tuple)
    elif table=="runtime_jobs":allowed=(tuple(columns),tuple(key_columns),tuple(key))==(_JOB_COLUMNS,("job_id",),(job_id,))
    elif table=="graph_owner_domain_attempts_v3":allowed=(tuple(columns),tuple(key_columns),tuple(key))==(_ATTEMPT_COLUMNS,
        ("bot","persona","operation_id"),(*r.namespace.as_tuple,r.operation_id))
    elif table=="graph_d12_backend_originals_v1":
        replay=r.cancel_replay
        allowed=(replay is not None and (tuple(columns),tuple(key_columns),tuple(key))==(_ORIGINAL_COLUMNS,
            ("bot","persona","original_ref"),(*r.namespace.as_tuple,replay["original_ref"])))
    elif table=="runtime_job_operations":allowed=(tuple(columns),tuple(key_columns),tuple(key))==(_PRIOR_COLUMNS,
        ("bot_id","persona_id","operation_id","phase"),(*r.namespace.as_tuple,r.operation_id,"cancel"))
    else:allowed=False
    if not allowed:raise AuthorityUnavailable("D12 cancel body escaped its exact selected job/projection/original")
    return r

def _prepare_cancel_original_replay_v3(r):
    from .lifecycle_operations_v1 import decode_original
    _,row=read_bound_method_learning_attachment_v3(r.db,table="graph_owner_domain_attempts_v3",columns=_ATTEMPT_COLUMNS,
        key_columns=("bot","persona","operation_id"),key=(*r.namespace.as_tuple,r.operation_id))
    r.cancel_attempt=row
    if row is None or row[-1]is None:return
    request=("graph_owner_domain_attempts_v3",_ATTEMPT_COLUMNS,("bot","persona","operation_id"),(*r.namespace.as_tuple,r.operation_id))
    raw=r.points[request].values["receipt_json"].json_v3()
    original=decode_original(raw)
    binding=r.cancel_access.owner_binding(r.authority,r.owner_binding)
    if ((original.namespace,original.operation_id,original.request_digest,original.kind,original.result.control,original.result.object_ref)!=
            (r.namespace,r.operation_id,r.request_digest,"control","cancel_job",r.request.object_ref)
            or (original.owner_grant_ref,original.owner_grant_revision,original.owner_grant_digest,original.activation_generation)!=
                (binding.grant_ref,binding.grant_revision,binding.grant_digest,binding.activation_generation)):
        raise AuthorityUnavailable("D12 cancel saved original crossed its exact current qualified Owner/job request")
    r.cancel_replay=raw
    _,durable=read_bound_method_learning_attachment_v3(r.db,table="graph_d12_backend_originals_v1",columns=_ORIGINAL_COLUMNS,
        key_columns=("bot","persona","original_ref"),key=(*r.namespace.as_tuple,original.original_ref))
    original_request=("graph_d12_backend_originals_v1",_ORIGINAL_COLUMNS,("bot","persona","original_ref"),
        (*r.namespace.as_tuple,original.original_ref))
    if (durable is None or durable[:2]!=(r.operation_id,original.original_digest)
            or r.points[original_request].values["original_json"].frozen!=r.points[request].values["receipt_json"].frozen):
        raise AuthorityUnavailable("D12 cancel saved receipt differs from its exact durable current original EOF")

def read_current_cancel_attempt_v3(capsule,db):
    r=require_current_job_cancel_work_v3(capsule.reader)
    seal=_CANCEL_CAPSULES.get(capsule)
    if seal is None or db is not r.db or not r.read_finished or not r.inputs_sealed:
        raise AuthorityUnavailable("D12 cancel attempt requires its sealed actual current READ metadata")
    r.require_current()
    request=("graph_owner_domain_attempts_v3",_ATTEMPT_COLUMNS,("bot","persona","operation_id"),(*r.namespace.as_tuple,r.operation_id))
    with runtime_storage_quantum_v3(db)as meter:
        r.points[request].require_row_v3(meter)
        presence=db.execute("SELECT receipt_json IS NULL,permit_json IS NULL FROM graph_owner_domain_attempts_v3 "
            "WHERE bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,r.operation_id)).fetchone()
        meter.charge_read(16)
    row=seal[16]
    if presence!=(None if row is None else (int(row[-1]is None),int(row[-2]is None))):
        raise AuthorityUnavailable("D12 cancel original attempt state changed after its exact metadata EOF")
    return row

def replay_current_cancel_original_v3(capsule,db,*,permit,state,now):
    from ..authority_service.v2_contract import to_wire
    r=require_current_job_cancel_work_v3(capsule.reader);seal=_CANCEL_CAPSULES.get(capsule)
    row=read_current_cancel_attempt_v3(capsule,db)
    request=("graph_owner_domain_attempts_v3",_ATTEMPT_COLUMNS,("bot","persona","operation_id"),(*r.namespace.as_tuple,r.operation_id))
    prepared_permit=r.points[request].values.get("permit_json")
    if (seal is None or row is None or seal[17]is None or state!="finished"or prepared_permit is None
            or prepared_permit.frozen!=_freeze_value_v3(to_wire(permit))):
        raise AuthorityUnavailable("D12 cancel replay lacks its exact prepared original WRITE finish confirmation")
    r.cancel_now=now;_check_deadline(r)
    return _detach_value_v3(seal[17])

class _JobCancelCapsuleV3:
    def __init__(self,r,job,projection,prior):
        self.reader=r
        seal=(r.work,r.operation,r.selection_digest,r.graph_stamp,r.authority,r.lease,r.owner_binding,r.owner_guard,
            r.request,r.request_digest,r.operation.deadline_utc,_CANCEL_SOURCES[r],canonical_digest(job),job,projection,prior,
            r.cancel_attempt,_freeze_value_v3(r.cancel_replay))
        _CANCEL_CAPSULES[self]=seal;r.operation.retain(_heap(seal)+1024)

    def require_write_v3(self,graph,*,authority,lease,operation_id,request_digest,metadata,epoch,owner,guard,scope,now):
        r=require_current_job_cancel_work_v3(self.reader);seal=_CANCEL_CAPSULES.get(self)
        if (seal is None or seal[:11]!=(r.work,r.operation,r.selection_digest,r.graph_stamp,r.authority,r.lease,
                r.owner_binding,r.owner_guard,r.request,r.request_digest,r.operation.deadline_utc)
                or graph is not r.graph or authority is not r.authority or lease is not r.lease
                or operation_id!=r.operation_id or request_digest!=r.request_digest
                or (metadata,epoch)!=r.graph_stamp or guard!=r.owner_guard or scope.operation!="write" or scope.namespace!=r.namespace
                or seal[11]!=_CANCEL_SOURCES.get(r) or seal[12]!=canonical_digest(r.cancel_job)
                or r not in _CANCEL_WRITE_AUTHORITIES or _CANCEL_WRITE_AUTHORITIES[r][:2]!=(self,scope)
                or tuple(getattr(owner,name)for name in _OWNER_FIELDS)!=tuple(getattr(r.owner_binding,name)for name in _OWNER_FIELDS)
                or "workbench.control"not in owner.capabilities or not r.read_finished or not r.inputs_sealed):
            raise AuthorityUnavailable("D12 cancel fresh WRITE changed exact sealed Owner/job/Source/selection/stamp")
        r.cancel_now=now;_check_deadline(r)
        r.require_current()
        with runtime_storage_quantum_v3(r.db)as meter:
            for task in _CANCEL_RECIPES[r]["tasks"]:task.require_header_v1(meter)
            _require_cancel_acquisition_metadata_v3(r,_CANCEL_RECIPES[r],meter)
            for task in _GENERAL_METHOD_SOURCE_TASKS_V1.get(r,{}).values():task.require_v1(r,meter)
            for point in r.points.values():
                if point.table!="graph_owner_domain_attempts_v3":point.require_row_v3(meter)
            current=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_jobs",_JOB_METADATA,"job_id=?",(r.request.object_ref[4:],))
            if current!=_CANCEL_RECIPES[r]["job"]:raise AuthorityUnavailable("D12 cancel selected current job metadata changed before WRITE")
        _CANCEL_WRITES[r]=(self,scope,owner)
        return self

def observe_current_cancel_owner_write_v3(capsule,graph,authority,lease,scope,expected,session):
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    r=require_current_job_cancel_work_v3(capsule.reader)
    if (capsule not in _CANCEL_CAPSULES or graph is not r.graph or authority is not r.authority
            or lease is not r.lease or session!=r.session_proof or expected!=r.owner_binding
            or r.db.in_transaction or not r.read_finished or not r.inputs_sealed
            or scope.operation!="write"or scope.namespace!=r.namespace
            or graph._current_owner_principal(authority.actor,r.namespace)!=expected.principal):
        raise AuthorityUnavailable("D12 fresh WRITE Authority observation crossed its exact sealed current Owner")
    token,request=session
    current,permit=graph._GraphCoordinator__content_fence_v2.get_current_owner_authority_for_fence_v1(
        namespace=r.namespace,authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=authority.actor,owner_session_token=token,owner_session_request=request)
    if (type(current)is not D12CurrentOwnerAuthorityV1 or permit!=scope.permit or current.guard!=r.owner_guard
            or current.target_admission!=expected.target_admission or current.storage_admission!=expected.storage_admission):
        raise AuthorityUnavailable("D12 fresh WRITE actual signed Owner guard/admission differs from its complete EOF")
    _CANCEL_WRITE_AUTHORITIES[r]=(capsule,scope,current,expected)
    return current.guard,expected

@contextmanager
def bind_current_job_cancel_write_v3(capsule):
    r=capsule.reader
    if capsule not in _CANCEL_CAPSULES:raise AuthorityUnavailable("D12 actual sealed cancel capsule required")
    token=_READING.set(r)
    try:
        with bind_runtime_storage_operation_v3(r.operation,r.db):yield
    finally:_READING.reset(token);_CANCEL_WRITES.pop(r,None);_CANCEL_WRITE_AUTHORITIES.pop(r,None)

def read_bound_current_cancel_job_v3(db,job_id):
    r=_method_active(db)
    if r is None or r.operation_kind!=CANCEL_OPERATION_V3:return False,None
    record=_CANCEL_WRITES.get(r)
    if record is None or job_id!=r.request.object_ref[4:]:raise AuthorityUnavailable("D12 current job has no exact fresh WRITE capsule")
    return True,r.cancel_updated if r.cancel_updated is not None else r.cancel_job

def read_bound_current_cancel_prior_v3(db,job,operation_id,phase,digest):
    r=_method_active(db)
    if r is None or r.operation_kind!=CANCEL_OPERATION_V3:return False,None
    record=_CANCEL_WRITES.get(r)
    if record is None or (job.job_id,operation_id,phase,digest)!=(r.request.object_ref[4:],r.operation_id,"cancel",r.request_digest[7:]):
        raise AuthorityUnavailable("D12 cancel prior original changed exact command identity")
    return True,_CANCEL_CAPSULES[record[0]][15]

def record_current_cancel_job_v3(db,job):
    r=_method_active(db)
    if r is None or r.operation_kind!=CANCEL_OPERATION_V3:return
    if r not in _CANCEL_WRITES or job.job_id!=r.request.object_ref[4:]:
        raise AuthorityUnavailable("D12 cancel result crossed its exact current WRITE")
    r.cancel_updated=job

def current_cancel_projection_v3(db,job_id):
    r=_method_active(db)
    if r is None or r.operation_kind!=CANCEL_OPERATION_V3:return None
    if r not in _CANCEL_WRITES or job_id!=r.request.object_ref[4:]:raise AuthorityUnavailable("D12 projection has no actual selected WRITE")
    return r.cancel_projection

def advance_current_job_cancel_v3(graph,work):
    from .first_ingress_v2 import trusted_upper
    r=require_current_job_cancel_work_v3(work.state)
    if graph is not r.graph or r.read_finished:raise AuthorityUnavailable("D12 cancel advanced outside its original Work")
    with bind_runtime_storage_operation_v3(work.operation,r.db):
        _prepare_current_general_method_owner_entry_v1(r)
        graph._validate_read_fence_v3(r.fence)
        r.cancel_now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        _check_deadline(r)
        if not r.inventory_sealed:
            with r.store._lock:r.advance()
            return GraphStorageStepV3("progress")
        if r.pending_input is not None:
            with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
                r.require_current(meter=meter);r.pending_input.advance(meter)
                if r.pending_input.complete:r.pending_input=None
            return GraphStorageStepV3("progress")
        token=_READING.set(r)
        try:
            with bind_prepared_method_learning_read_v3(r.inventory,graph,r.db),r.store._lock:
                r.db.execute("BEGIN")
                try:
                    _prepare_cancel_recipe(r);_qualify_cancel_sources(r)
                    _,row=read_bound_method_learning_attachment_v3(r.db,table="runtime_jobs",columns=_JOB_COLUMNS,
                        key_columns=("job_id",),key=(r.request.object_ref[4:],))
                    from .jobs import _job_from_row,_job_from_dict
                    from .d11_types import job_graph_write
                    r.cancel_job=_job_from_row(row)
                    if dict(r.cancel_job.continuation)!=_CANCEL_RECIPES[r]["continuation"]:
                        raise AuthorityUnavailable("D12 selected full job continuation differs from its actual metadata EOF")
                    write=job_graph_write(r.cancel_job)
                    r.cancel_projection=method_graph_head_v3(r.db,r.namespace,write.key)
                    if not r.cancel_projection.valid or r.cancel_projection.value!=write.value:
                        raise AuthorityUnavailable("D12 selected job current Graph projection differs from its actual EOF")
                    _,prior_row=read_bound_method_learning_attachment_v3(r.db,table="runtime_job_operations",columns=_PRIOR_COLUMNS,
                        key_columns=("bot_id","persona_id","operation_id","phase"),key=(*r.namespace.as_tuple,r.operation_id,"cancel"))
                    prior=None
                    if prior_row is not None:
                        if prior_row[:2]!=(r.request_digest[7:],r.cancel_job.job_id):raise AuthorityUnavailable("D12 cancel original command identity differs")
                        prior_request=("runtime_job_operations",_PRIOR_COLUMNS,("bot_id","persona_id","operation_id","phase"),
                            (*r.namespace.as_tuple,r.operation_id,"cancel"))
                        prior=_job_from_dict(r.points[prior_request].values["job_json"].json_v3())
                    _prepare_cancel_original_replay_v3(r)
                    capsule=_JobCancelCapsuleV3(r,r.cancel_job,r.cancel_projection,prior)
                    r.inputs_sealed=True
                finally:r.db.rollback()
            graph._validate_read_fence_v3(r.fence);graph._finish_read_fence_v3(r.fence);r.read_finished=True
            with bind_current_job_cancel_write_v3(capsule):
                result=r.cancel_access._execute_prepared_cancel_v3(r,capsule)
            r.business_completed=r.complete=True
            return GraphStorageStepV3("complete",result)
        except MethodInputNeededV3 as needed:
            kind,actual=needed.request
            with r.store._lock,runtime_storage_quantum_v3(r.db):
                if kind=="numeric_owner_metadata":
                    identity=(kind,actual);task=r.attachments.get(identity)
                    if task is None:task=NumericMetadataTaskV1(r,actual);r.attachments[identity]=task
                elif kind=="general_method_source_metadata":
                    tasks=_GENERAL_METHOD_SOURCE_TASKS_V1.setdefault(r,{})
                    task=tasks.get(actual)
                    if task is None:task=_GeneralMethodSourceMetadataEOFV1(_GENERAL_METHOD_SOURCE_ISSUER_V1,r,actual);tasks[actual]=task
                elif kind=="point":
                    require_cancel_job_point_v3(r,actual)
                    task=r.points.get(actual)
                    if task is None:task=_MethodPointReadV3(r,actual);r.points[actual]=task
                else:raise AuthorityUnavailable("D12 cancel has no registered selected metadata/body dependency")
                r.pending_input=task
            return GraphStorageStepV3("progress")
        finally:_READING.reset(token)

def finish_current_job_cancel_v3(graph,work,error):
    r=work.state
    try:
        if not r.read_finished:graph._finish_read_fence_v3(r.fence);r.read_finished=True
    finally:
        _CANCEL_WORKS.pop(r,None);_CANCEL_RECIPES.pop(r,None);_CANCEL_SOURCES.pop(r,None);_CANCEL_WRITES.pop(r,None)
        _CANCEL_WRITE_AUTHORITIES.pop(r,None)
        for capsule in tuple(_CANCEL_CAPSULES):
            if capsule.reader is r:_CANCEL_CAPSULES.pop(capsule,None)
        _release_method_registered_payloads_v3(r)
        if r.inventory is not None:r.inventory.release_payload_v3()
        r.points.clear();r.attachments.clear();r.cancel_job=r.cancel_updated=r.cancel_projection=None
        r.cancel_attempt=r.cancel_replay=None
        r.cancel_commit=None;finish_runtime_storage_operation_v3(work.operation)
