"""Actual D07 Source preparation outputs and fixed same-COMMIT observations."""
from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakKeyDictionary
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .dispatch_current_inventory_v3 import _heap,_freeze_value_v3,_detach_value_v3

_ISSUED=WeakKeyDictionary()
_ISSUED_JOBS=WeakKeyDictionary()
_POSTCAS=ContextVar("sylanne_d07_source_actual_postcas_v3",default=None)
_SOURCE_KINDS=frozenset({"current_d07_source_read_v3","current_d07_simulation_source_read_v3"})

def _source_reader(db):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None or r.work.kind not in _SOURCE_KINDS:return None
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_identity_v3
    require_current_beta1_source_work_identity_v3(r)
    return r

def _source_state(r):
    if r.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import require_d07_source_work_v3
        return require_d07_source_work_v3(r)
    from .current_d07_simulation_source_read_v3 import require_current_d07_simulation_source_work_v3
    return require_current_d07_simulation_source_work_v3(r)

def _write_binding(r):
    if r.operation_kind=="serve_concern":
        from .d07_source_owner_read_v3 import require_d07_source_write_phase_v3
        return require_d07_source_write_phase_v3(r)
    from .current_d07_simulation_source_read_v3 import require_current_d07_simulation_write_phase_v3
    return require_current_d07_simulation_write_phase_v3(r)

def _before_write(r):
    value=_write_binding(r);s=_source_state(r)
    cap=s.source_permission if r.operation_kind=="serve_concern"else s.cap
    if cap is None:raise AuthorityUnavailable("D07 preparation output requires completed independent Source permission")
    cap.require_for_v3(r)
    return value

def _fixed_ids(r):
    from .d07_execution_v1 import d07_execution_ids_v1
    kind="concern"if r.operation_kind=="serve_concern"else"simulation"
    return d07_execution_ids_v1(r.namespace,r.operation_id,kind)

def read_bound_d07_source_preparation_original_v3(db,issuer,namespace,kind,ref):
    from .foreground_command_source_v3 import read_foreground_command_d07_output_v3
    handled,value=read_foreground_command_d07_output_v3(db,issuer,namespace,kind,ref)
    if handled:return True,value
    r=_source_reader(db)
    if r is None:return False,None
    ids=_fixed_ids(r)
    if(kind not in{"prepared","accounting_prepared"}or ref!=ids["job"]):return False,None
    if namespace!=r.namespace or issuer is not r.graph._GraphCoordinator__d11_issuer:
        raise AuthorityUnavailable("D07 fixed preparation prior crossed actual command/namespace/issuer")
    _before_write(r)
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    with runtime_storage_quantum_v3(db)as meter:
        current=_beta1_metadata_row_v3(r,meter,"graph_d07_execution_originals_v1",
            ("payload_digest","signature"),"bot=? AND persona=? AND kind=? AND original_ref=?",
            (*namespace.as_tuple,kind,ref))
    if current is None:return True,None
    issued=_ISSUED.get(r,{}).get((kind,ref))
    if issued is None or current!=issued[:2]or issued[3]is not _write_binding(r)[1]:
        raise AuthorityUnavailable("D07 prior prepared original belongs to another actual WRITE; recover its operation receipt")
    from .d07_execution_v1 import SIGN_KIND
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,kind,ref,current[0])),current[1])
    r.operation.retain(_heap(issued[2])*4+4096)
    return True,(_detach_value_v3(issued[2]),current[0])

def register_d07_source_preparation_original_v3(db,issuer,namespace,kind,ref,wire,digest,signature):
    from .foreground_command_source_v3 import register_foreground_command_d07_output_v3
    if register_foreground_command_d07_output_v3(db,issuer,namespace,kind,ref,wire,digest,signature):return
    r=_source_reader(db)
    if r is None or kind not in{"prepared","accounting_prepared"}:return
    if(namespace!=r.namespace or ref!=_fixed_ids(r)["job"]or issuer is not r.graph._GraphCoordinator__d11_issuer):
        raise AuthorityUnavailable("D07 preparation writer escaped its fixed actual Source command")
    binding=_before_write(r)
    r.operation.retain(16*len(wire)+32768)
    raw=json.loads(wire)
    from .d07_execution_v1 import SIGN_KIND
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,kind,ref,digest)),signature)
    if canonical_digest(raw)!=digest:
        raise AuthorityUnavailable("D07 actual preparation writer changed its signed original")
    frozen=_freeze_value_v3(raw)
    record=(digest,signature,frozen,binding[1],r.work,r.operation,r.selection_digest)
    prior=_ISSUED.setdefault(r,{}).get((kind,ref))
    if prior is not None and prior!=record:
        raise AuthorityUnavailable("D07 actual preparation writer reused its fixed original identity")
    _ISSUED[r][(kind,ref)]=record

def require_d07_trigger_prepared_metadata_v3(task,value):
    from dataclasses import fields
    from ..runtime_contracts import NamespaceId
    from .d07_execution_v1 import (D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3,
        D07IngressRecallPreparedV1,d07_execution_ids_v1)
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
    known={cls.__dataclass_fields__["schema"].default:cls for cls in(
        D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3,
        D07IngressRecallPreparedV1,D07MethodGrowthPreparedV2,D07GeneralGrowthPreparedV1)}
    cls=known.get(value["schema"]);r=task.reader;ref=task.identity[2]
    if(cls is None or task.column.beta1_metadata_fields_seen!={f.name for f in fields(cls)}
            or NamespaceId(**value["namespace"])!=r.namespace or value["job_id"]!=ref
            or d07_execution_ids_v1(r.namespace,value["operation_id"],value["work_kind"])["job"]!=ref):
        raise AuthorityUnavailable("simulation explicit prepared trigger differs from its signed actual identity")
    versions=[]
    for row in value["read_rows"]:
        key=AtomKey.from_token(row["ref"]);revision=row["revision"]
        if NamespaceId.from_key(key)!=r.namespace or type(revision)is not int or revision<0 or type(row["valid"])is not bool:
            raise AuthorityUnavailable("simulation explicit prepared trigger has noncanonical content locators")
        versions.append(GraphVersion(key,revision))
    roots=tuple(sorted({v.key.token for v in versions if v.key.type_name=="memory.source"}))
    return roots,tuple(versions)

def d07_terminal_metadata_spec_v3(r,job_id):
    s=_source_state(r)
    ref=s.terminals.get(job_id)
    if job_id not in s.jobs or not ref:
        raise AuthorityUnavailable("D07 terminal metadata lacks actual current job result selector")
    return("graph_d07_execution_originals_v1","payload_json",("bot","persona","kind","original_ref"),
        (*r.namespace.as_tuple,"execution",ref),("payload_digest","signature"),
        (("terminal_ref",),("operation_id",),("activity_id",),("work_kind",),("source_refs",),("cost_receipt_refs",)),None)

def finish_d07_terminal_metadata_v3(task,value):
    from dataclasses import fields
    from ..runtime_contracts import NamespaceId
    from .d07_current_behavior_v1 import D07ExecutionOriginalV1
    from .d07_execution_v1 import SIGN_KIND,d07_execution_ids_v1
    r=task.reader;s=_source_state(r);job_id=task.identity[1];ref=s.terminals[job_id]
    r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
        canonical_serialize((r.namespace,"execution",ref,task.metadata[0])),task.metadata[1])
    if(task.column.beta1_metadata_fields_seen!={f.name for f in fields(D07ExecutionOriginalV1)}
            or value["terminal_ref"]!=ref or value["activity_id"]!=r.activity_id
            or d07_execution_ids_v1(r.namespace,value["operation_id"],value["work_kind"])["job"]!=job_id):
        raise AuthorityUnavailable("D07 terminal locator differs from its exact actual current signed job")
    from .d07_source_owner_read_v3 import _source_refs
    roots=_source_refs(r,value["source_refs"]);versions=[]
    for token in value["cost_receipt_refs"]:
        key=AtomKey.from_token(token)
        if NamespaceId.from_key(key)!=r.namespace or key.type_name!="runtime.cost_settlement":
            raise AuthorityUnavailable("D07 terminal cost locator is not its actual namespace computation receipt")
        head=r.heads.get(token)
        if head is None or head[1]!=1:
            raise AuthorityUnavailable("D07 actual terminal cost receipt is not current valid")
        versions.append(GraphVersion(key,head[0]))
    return{"roots":roots,"versions":tuple(versions)}

def d07_prepared_metadata_spec_v3(r,job_id):
    s=_source_state(r)
    if job_id not in s.jobs:
        raise AuthorityUnavailable("D07 prepared metadata was not selected by actual current activity job EOF")
    return("graph_d07_execution_originals_v1","payload_json",("bot","persona","kind","original_ref"),
        (*r.namespace.as_tuple,"prepared",job_id),("payload_digest","signature"),
        (("schema",),("namespace",),("job_id",),("operation_id",),("activity_id",),("work_kind",),
         ("purpose",),("audience",),("read_rows",)),None)

def retain_d07_prepared_metadata_path_v3(task,path):
    if not path:return True
    if path[0]=="read_rows":
        if len(path)<3:return True
        return type(path[1])is int and path[2]in{"ref","revision","valid"}
    return path[0]in{"schema","namespace","job_id","operation_id","activity_id","work_kind","purpose","audience"}

def finish_d07_prepared_metadata_v3(task,value):
    from dataclasses import fields
    from ..runtime_contracts import NamespaceId
    from .d07_execution_v1 import (SIGN_KIND,D07PreparedExecutionV1,D07RelationshipPreparedV2,
        D07ReflectionPreparedV3,D07IngressRecallPreparedV1)
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
    r=task.reader;job_id=task.identity[1]
    known={cls.__dataclass_fields__["schema"].default:cls for cls in(
        D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3,
        D07IngressRecallPreparedV1,D07MethodGrowthPreparedV2,D07GeneralGrowthPreparedV1)}
    cls=known.get(value["schema"])
    selected=_source_state(r).tasks[("d07_job"if r.operation_kind=="serve_concern"else"simulation_job",job_id)]
    job_header=dict(zip(selected.header_columns,selected.metadata))
    if(cls is None or task.column.beta1_metadata_fields_seen!={f.name for f in fields(cls)}
            or NamespaceId(**value["namespace"])!=r.namespace or value["job_id"]!=job_id
            or value["operation_id"]!=job_header["operation_id"]or "d07."+value["work_kind"]!=job_header["work_kind"]
            or value["activity_id"]!=r.activity_id or value["purpose"]!="context"
            or not set(r.authority.audience)<=set(value["audience"])):
        raise AuthorityUnavailable("D07 prepared metadata changed its exact registered schema/job/current audience")
    r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
        canonical_serialize((r.namespace,"prepared",job_id,task.metadata[0])),task.metadata[1])
    versions=[]
    for row in value["read_rows"]:
        key=AtomKey.from_token(row["ref"]);revision=row["revision"]
        if(NamespaceId.from_key(key)!=r.namespace or type(revision)is not int or revision<0
                or type(row["valid"])is not bool):
            raise AuthorityUnavailable("D07 prepared locator metadata crossed exact namespace/revision")
        versions.append(GraphVersion(key,revision))
    return{"roots":tuple(v.key.token for v in versions if v.key.type_name=="memory.source"),
        "versions":tuple(versions),"operation_id":value["operation_id"],"job_id":job_id}

@contextmanager
def bind_d07_source_postcas_v3(witness,receipt):
    r=_source_reader(witness.graph._GraphCoordinator__store._db)
    if r is None:
        yield None
        return
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from .d07_execution_v1 import D07PreparationStageV1
    from ..runtime_contracts import CommitReceipt
    value=_write_binding(r)
    prep=witness.stage
    if(type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or type(prep)is not D07PreparationStageV1 or prep.replayed
            or type(receipt)is not CommitReceipt or receipt.status!="committed"
            or witness.scope is not value[1]or witness.runtime is not r.runtime
            or witness.request!=r.request or witness.operation.operation_kind!=r.operation_kind
            or prep.prepared.operation_id!=r.operation_id or prep.prepared.namespace!=r.namespace
            or receipt.operation_id!=prep.prepared.prepare_operation_id
            or receipt.read_versions!=witness.bundle.envelope.version_guard.read_versions
            or not r.db.in_transaction or not r.store._lock._is_owned()):
        raise AuthorityUnavailable("D07 postCAS observer requires its actual same-COMMIT private preparation witness")
    writes=tuple(w for p in witness.bundle.proposals for w in p.typed_writes)
    versions={v.key:v.revision for v in receipt.write_versions}
    if(set(versions)!={w.key for w in writes}
            or any(w.key.type_name not in{"runtime.job"}and not w.key.type_name.startswith(("d02.","d07."))for w in writes)):
        raise AuthorityUnavailable("D07 postCAS observer escaped its actual fixed D02/D07/D11 write members")
    token=_POSTCAS.set((r,witness,receipt,writes,versions))
    try:yield _POSTCAS.get()
    finally:_POSTCAS.reset(token)

def record_bound_d07_source_postcas_v3(db,issuer,preparation,graph_receipt):
    value=_POSTCAS.get()
    if value is None:return False,None
    r,witness,receipt,writes,versions=value
    from .domain_production_commit_v1 import _ACTIVE
    if(db is not r.db or issuer is not r.graph._GraphCoordinator__d11_issuer
            or preparation is not witness.stage or graph_receipt is not receipt
            or _ACTIVE.get(id(witness))is not witness or _write_binding(r)[1]is not witness.scope):
        raise AuthorityUnavailable("D07 postCAS recorder crossed its actual witness/receipt/issuer")
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    from .d07_execution_v1 import D07ExecutionReadV1,SIGN_KIND
    prepared=preparation.prepared;expected={w.key.token:w for w in writes};heads={}
    with runtime_storage_quantum_v3(db)as meter:
        rights=_runtime_bounded_fixed_row_v3(db,meter,"graph_authority_epochs",("access_epoch","delete_epoch"),
            "bot=? AND persona=?",r.namespace.as_tuple)
        if rights!=(r.owner_binding.access_epoch,r.owner_binding.delete_epoch):
            raise AuthorityUnavailable("D07 actual preparation CAS changed Source/Owner control epochs")
        for write in writes:
            head=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(write.key.token,*r.namespace.as_tuple))
            if head is None or head[:2]!=(versions[write.key],1):
                raise AuthorityUnavailable("D07 actual preparation receipt member is absent after its own CAS")
            heads[write.key.token]=head
        rows=[]
        r.operation.retain(_heap((tuple(prepared.read_rows),tuple(w.value for w in writes)))*4+65536)
        for observed in prepared.read_rows:
            head=heads.get(observed.ref)
            if head is None:
                head=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                    "token=? AND bot=? AND persona=?",(observed.ref,*r.namespace.as_tuple))
            write=expected.get(observed.ref)
            if write is not None:
                rows.append(D07ExecutionReadV1(observed.ref,head[0],True,canonical_serialize(write.value)))
            else:
                initial=r.heads.get(observed.ref)
                if head!=initial or(head is None and(observed.revision!=0 or observed.valid)):
                    raise AuthorityUnavailable("D07 unchanged content member changed during actual same-COMMIT observation")
                rows.append(observed)
        query=[]
        for page in preparation.frame.query_coverage:
            if page.type_id.startswith(("runtime.","d02.")):continue
            if page.type_id not in r.selected_plan.fixed_type_ids:
                raise AuthorityUnavailable("D07 postCAS query is outside original fixed selected metadata families")
            after="";members=[]
            while True:
                row=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("token","revision"),
                    "bot=? AND persona=? AND type_name=? AND token>? ORDER BY token",
                    (*r.namespace.as_tuple,page.type_id,after))
                if row is None:break
                members.append(row);after=row[0]
                if len(members)>128:raise AuthorityUnavailable("D07 actual postCAS metadata exceeds original fixed bound")
            r.operation.retain(_heap(members)+1024)
            query.append({"type_id":page.type_id,"rows":members,"complete":page.complete})
        prior=_runtime_bounded_fixed_row_v3(db,meter,"graph_d07_execution_originals_v1",("payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,"prepare_commit",prepared.job_id))
        if prior is not None:
            raise AuthorityUnavailable("D07 preparation commit original already exists outside this first actual CAS")
    from dataclasses import asdict
    payload={"schema":"d07.preparation-commit.v1","prepared_digest":prepared.digest,
        "prepare_operation_id":prepared.prepare_operation_id,"graph_receipt_digest":canonical_digest(receipt),
        "writes_digest":canonical_digest((*preparation.stage.proposal.typed_writes,*preparation.writes)),
        "post_read_rows":[asdict(row)for row in rows],"post_query_inventory_json":canonical_serialize(query)}
    r.operation.retain(_heap(payload)*4+65536)
    wire=canonical_serialize(payload);digest=canonical_digest(payload)
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((r.namespace,"prepare_commit",prepared.job_id,digest)))
    db.execute("INSERT INTO graph_d07_execution_originals_v1(bot,persona,kind,original_ref,payload_json,payload_digest,signature) VALUES(?,?,?,?,?,?,?)",
        (*r.namespace.as_tuple,"prepare_commit",prepared.job_id,wire,digest,signature))
    return True,digest

def prepare_current_d07_source_read_dependencies_v3(r):
    if r.work.kind not in _SOURCE_KINDS:return
    from .current_beta1_source_read_v3 import require_beta1_source_groups_v3
    require_beta1_source_groups_v3(r,r.selected_plan.source_roots)
    s=_source_state(r)
    from .domain_production_registry_v1 import installed_operation_v1,installed_readers_for_operation_v1
    readers=installed_readers_for_operation_v1(r.graph,installed_operation_v1(r.operation_kind),
        scope=r.fence.scope,owner_guard=r.owner_guard,owner_binding=r.owner_binding,
        execution_reader=r.graph._GraphCoordinator__d07_execution_service_v1)
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1
    read_current_domain_original_refs_v1(r.db,namespace=r.namespace,plan=r.selected_plan,
        installed_readers=readers,authenticated_external_originals=r.observed_originals)
    from .jobs import get_job
    from .d07_execution_v1 import read_prepared_d07_execution_v1
    for job_id in sorted(s.jobs):
        get_job(r.db,job_id)
        read_prepared_d07_execution_v1(r.db,readers.issuer,r.namespace,job_id)
        if job_id in s.terminals:
            from .d07_execution_v1 import read_d07_original_v1
            for family in ("prepare_commit","paid_cost","body_cost"):
                read_d07_original_v1(r.db,readers.issuer,r.namespace,family,job_id)
    if r.operation_kind=="run_simulation":
        from .current_d07_simulation_source_read_v3 import read_current_d07_simulation_history_v3
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        for ref,revision in sorted(s.histories):
            read_current_d07_simulation_history_v3(r.db,ref,revision)
        for operation_id in sorted(s.producers):
            read_adopted_domain_operation_v1(r.db,r.namespace,operation_id)

def register_d07_source_preparation_job_v3(db,job):
    r=_source_reader(db)
    if r is None:return
    binding=_before_write(r)
    if(job.job_id!=_fixed_ids(r)["job"]or(job.bot_id,job.persona_id)!=r.namespace.as_tuple
            or job.operation_id!=r.operation_id or job.activity_id!=r.activity_id or job.phase!="queued"
            or job.fence!=0 or job.cancel_epoch!=0 or not db.in_transaction):
        raise AuthorityUnavailable("D07 actual new job escaped its fixed same-Source writer")
    from dataclasses import asdict
    r.operation.retain(_heap(tuple(getattr(job,name)for name in job.__dataclass_fields__))*4+65536)
    frozen=_freeze_value_v3(asdict(job))
    _ISSUED_JOBS[r]=(job.job_id,frozen,canonical_digest(job),binding[1])

def read_bound_d07_source_preparation_job_v3(db,job_id):
    r=_source_reader(db)
    if r is None:return False,None
    issued=_ISSUED_JOBS.get(r)
    if issued is None or issued[0]!=job_id:return False,None
    if issued[3]is not _before_write(r)[1]:
        raise AuthorityUnavailable("D07 concrete new job crossed its actual same-WRITE scope")
    from .jobs import _job_from_dict
    r.operation.retain(_heap(issued[1])*4+4096)
    job=_job_from_dict(_detach_value_v3(issued[1]))
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    columns=("operation_id","activity_id","bot_id","persona_id","phase","work_kind","fence","cancel_epoch",
        "snapshot_ref","budget_ref","resource_ref","deadline_utc")
    with runtime_storage_quantum_v3(db)as meter:
        current=_beta1_metadata_row_v3(r,meter,"runtime_jobs",columns,"job_id=?",(job_id,))
    expected=tuple(getattr(job,name)for name in columns)
    if current!=expected or canonical_digest(job)!=issued[2]:
        raise AuthorityUnavailable("D07 actual new job metadata changed before its fixed preparation CAS")
    return True,job

def release_d07_source_preparation_members_v3(reader):
    _ISSUED.pop(reader,None);_ISSUED_JOBS.pop(reader,None)
