"""Private bounded SQL read points for the actual Artifact receipt inventory Work."""
from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakKeyDictionary
from dataclasses import dataclass
import json,re
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize,NamespaceId
from ..graph_types import AtomKey
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .source_correction_read_v3 import _heap

_ACTIVE=ContextVar("artifact-receipt-read-points",default=None)
_SEALS=WeakKeyDictionary()
_TASKS=WeakKeyDictionary()
_ISSUER=object()
# No SQL from external requests is accepted. These are the existing read-only
# tables reached by the fixed completion validator and its signed originals.
_TABLES=frozenset({"sqlite_master","graph_atoms","graph_history","graph_epochs","graph_authority_epochs",
    "graph_bundle_operations","graph_events","graph_domain_production_originals_v1",
    "graph_domain_production_outbox_v1","graph_d11_life_originals_v1","graph_d07_execution_originals_v1",
    "graph_first_ingress_c02_committed_seals_v2","graph_first_ingress_identity_v1","graph_d03_arrival_issuance_v2",
    "runtime_jobs","runtime_job_operations","runtime_budget_leases","runtime_budget_grants",
    "runtime_budget_operations","runtime_budget_reservations","runtime_budget_debt_blocks","runtime_resource_quotes",
    "graph_guard_versions","graph_runtime_bootstrap_v1","graph_d10_life_originals_v1",
    "graph_d12_domain_candidates_v1","graph_source_correction_originals_v1","graph_source_correction_heads_v1"})
_INTEGRITY={"graph_domain_production_originals_v1":("original_digest","bundle_digest","receipt_digest"),
    "graph_d11_life_originals_v1":("payload_digest","signature","producing_operation_id"),
    "graph_d07_execution_originals_v1":("payload_digest","signature"),
    "graph_bundle_operations":("digest","commit_seq"),"graph_events":("digest","epoch_revision"),
    "runtime_budget_grants":("version","status","signature"),"runtime_resource_quotes":("signature","status"),
    "runtime_jobs":("phase","fence","cancel_epoch","lease_holder","lease_expires_utc"),
    "runtime_budget_leases":("version","state"),"runtime_budget_operations":("digest","lease_id"),
    "runtime_budget_reservations":("digest","state")}
_KEYS={"graph_atoms":("token",),"graph_history":("token","revision")}


class _NeedPoint(Exception):
    def __init__(self,query,key):self.query,self.key=query,key


class _Cursor:
    def __init__(self,rows):self.rows,self.offset=rows,0
    def fetchone(self):
        if self.offset==len(self.rows):return None
        row=self.rows[self.offset];self.offset+=1;return row
    def fetchall(self):
        rows=self.rows[self.offset:];self.offset=len(self.rows);return list(rows)
    def fetchmany(self,size=1):
        end=min(len(self.rows),self.offset+size);rows=self.rows[self.offset:end];self.offset=end;return list(rows)
    def __iter__(self):return iter(self.fetchall())


def _runtime_receipt_graph_cursor_v3(db,sql,parameters):
    """Use the existing typed Graph readers outside the receipt-only FULL Work."""
    from ..runtime_storage_v3 import runtime_storage_v3,read_graph_rows_v3
    if runtime_storage_v3(db)is None:return None
    query=" ".join(sql.split())
    found=re.fullmatch(r"SELECT ([A-Za-z_0-9, ]+) FROM (graph_atoms|graph_history) WHERE (.*?)(?: ORDER BY ([A-Za-z_][A-Za-z_0-9]*(?: *, *[A-Za-z_][A-Za-z_0-9]*)*))?(?: LIMIT ([0-9]+))?",query,re.I)
    if found is None:return None
    columns=tuple(name.strip()for name in found[1].split(','))
    if 'value'not in columns:return None
    table,where=found[2],found[3]
    order=tuple(name.strip()for name in found[4].split(','))if found[4]else()
    limit=int(found[5])if found[5]else None
    def original_rows():
        return read_graph_rows_v3(db,columns,where=where,parameters=parameters,
            history=table=='graph_history',order_by=order,limit=limit)
    # The real background/Authority producer Work already owns and qualifies
    # these full-PK points. Consume its actual EOF column, not raw SQLite value.
    clauses=[re.fullmatch(r"([A-Za-z_0-9]+) *= *(\?|[01])",part.strip())
        for part in re.split(r"\s+AND\s+",where,flags=re.I)]
    keys=[];values=[];index=0
    if all(part is not None for part in clauses):
        for part in clauses:
            keys.append(part[1])
            if part[2]=='?':
                if index>=len(parameters):break
                values.append(parameters[index]);index+=1
            else:values.append(int(part[2]))
    point=(len(values)==len(keys) and index==len(parameters) and 'token'in keys
        and (table=='graph_atoms'or 'revision'in keys) and not order)
    if point:
        from .natural_producer_qualification_v1 import _producer_original_point_v3
        def original_row():
            rows=original_rows()
            return rows[0]if rows else None
        row=_producer_original_point_v3(db,table=table,columns=columns,
            key_columns=tuple(keys),key=tuple(values),legacy_reader=original_row)
        if row is None:return _Cursor(())
        return _Cursor((row,))
    return _Cursor(original_rows())


def artifact_receipt_sql_v1(db,sql,parameters=()):
    task=_ACTIVE.get()
    if task is None:
        graph=_runtime_receipt_graph_cursor_v3(db,sql,tuple(parameters))
        return graph if graph is not None else db.execute(sql,parameters)
    task.require_actual_v1()
    if db is not task.db:raise AuthorityUnavailable("receipt SQL crossed its actual selected connection")
    query=" ".join(sql.split());key=tuple(parameters);point=task.points.get((query,key))
    if point is None:raise _NeedPoint(query,key)
    if not point.complete:raise AuthorityUnavailable("receipt point cannot release partial JSON")
    if task.assembly and point.table=="graph_epochs"and task.graph._v2_graph_stamp(task.owner.namespace)!=task.graph_stamp:
        return db.execute(sql,parameters)
    return _Cursor(point.rows)


@contextmanager
def _bind_v1(task):
    task.require_actual_v1()
    token=_ACTIVE.set(task)
    try:yield
    finally:_ACTIVE.reset(token)


class _Column(DispatchOriginalJSONReadV3):
    def __init__(self,owner,**kwargs):
        super().__init__(owner,**kwargs)
        if self.cell is not None:
            self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=="canonical-json.ascii.v1")


class _ReceiptPointV1:
    def __init__(self,task,query,key):
        self.task,self.owner,self.query,self.key=task,task.owner,query,key
        self.complete=False;self.phase="metadata";self.columns=[];self.index=0
    def advance(self,meter):
        task=self.task;task.require_actual_v1();db=task.db
        if self.phase=="metadata":
            found=re.fullmatch(r"SELECT (.+?) FROM ([A-Za-z_][A-Za-z_0-9]*)(.*)",self.query,re.I)
            if (found is None or found[2]not in _TABLES or ";"in self.query or
                    re.search(r"\b(JOIN|UNION|WITH|ATTACH|PRAGMA)\b",self.query,re.I)or
                    "json_extract("in self.query.lower()):
                raise AuthorityUnavailable("receipt validator requested an unregistered bounded SELECT shape")
            self.table=found[2];self.selection=tuple(v.strip()for v in found[1].split(","));suffix=found[3]
            info=db.execute("PRAGMA table_info("+self.table+")").fetchall()
            meter.charge_read(sum(sum(len(str(v))for v in row)for row in info)+64)
            names={row[1]for row in info}
            physical_graph=self.table in {"graph_atoms","graph_history"} and "value_cell_id" in names
            logical_names=names|({"value"}if physical_graph else set())
            keys=_KEYS.get(self.table,tuple(row[1]for row in sorted(info,key=lambda row:row[5])if row[5]))
            if self.table=="sqlite_master":
                self.metadata_query=self.query;self.metadata=tuple(db.execute(self.query,self.key).fetchmany(129))
                if len(self.metadata)>128:raise AuthorityUnavailable("receipt metadata query exceeded original finite read point")
                meter.charge_read(_heap(self.metadata));self.rows=self.metadata;self.complete=True;return
            if not keys:
                # Actual fixed schema exposes its unique key; no invented row ID.
                raise AuthorityUnavailable("receipt read table has no declared exact primary key")
            if not all(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*",name)and name in logical_names for name in self.selection):
                if self.selection!=("COUNT(*)",)and self.selection!=("1",):
                    raise AuthorityUnavailable("receipt SELECT projection is not exact declared columns")
            self.keys=keys
            json_columns={"graph_events":{"reads","revisions"}}
            jsons=tuple(name for name in self.selection if name=="value"or name.endswith("_json")or name in json_columns.get(self.table,set()))
            projected=[];self.positions=[]
            for name in self.selection:
                self.positions.append(len(projected))
                # The production Graph stores a cell reference. Never issue
                # SELECT value or length(value) against its physical v3 table.
                projected.append("value_cell_id"if physical_graph and name=="value"else
                    "length(CAST("+name+" AS BLOB))"if name in jsons else name)
            self.key_offset=len(projected);projected.extend(keys)
            integrity=tuple(name for name in _INTEGRITY.get(self.table,())if name in names)
            if self.table in {"graph_atoms","graph_history"}:
                integrity=tuple(name for name in("revision","valid","value_cell_id","event_id","event_bot","event_persona")if name in names)
            self.integrity_offset=len(projected);projected.extend(integrity)
            self.integrity_names=integrity
            self.metadata_query="SELECT "+",".join(projected)+" FROM "+self.table+suffix
            if re.search(r"\bLIMIT\b",suffix,re.I)is None:self.metadata_query+=" LIMIT 129"
            self.metadata=tuple(tuple(row)for row in db.execute(self.metadata_query,self.key).fetchmany(129))
            if len(self.metadata)>128:raise AuthorityUnavailable("receipt original query exceeds its finite metadata point bound")
            meter.charge_read(_heap(self.metadata));task.owner.operation.retain(_heap(self.metadata)+4096)
            self.output=[]
            for row in self.metadata:
                current=list(row[:len(self.selection)]);pk=row[self.key_offset:self.key_offset+len(keys)]
                integrity_row=dict(zip(integrity,row[self.integrity_offset:]))
                for position,name in enumerate(self.selection):
                    if name not in jsons or current[position]is None:continue
                    if self.table in {"graph_atoms","graph_history"}:
                        token=dict(zip(keys,pk))["token"]
                        if AtomKey.from_token(token).type_name=="memory.source":
                            if not task.source_roots_qualified:
                                raise AuthorityUnavailable("receipt Source body requires actual metadata rights first")
                            if token not in task.source_family:
                                raise AuthorityUnavailable("receipt Source body escaped its qualified fixed family")
                    cell=integrity_row.get("value_cell_id")if name=="value"else None
                    column=_Column(task.owner,table=self.table,column=name,key_columns=keys,key=pk,cell_id=cell)
                    self.columns.append((len(self.output),position,column))
                self.output.append(current)
            self.phase="bytes";return
        if self.index<len(self.columns):
            row,position,column=self.columns[self.index]
            if not column.advance(meter):return
            value=column.require_v3(task.owner)
            encoded=canonical_serialize(value)
            task.owner.operation.retain(len(encoded.encode("utf-8"))+1024)
            self.output[row][position]=encoded;self.index+=1;return
        self.rows=tuple(tuple(row)for row in self.output);self.complete=True
    def require_current(self,db,meter):
        if not self.complete or db is not self.task.db:raise AuthorityUnavailable("receipt current point has no complete original")
        rows=tuple(tuple(row)for row in db.execute(self.metadata_query,self.key).fetchmany(129))
        meter.charge_read(_heap(rows))
        if rows!=self.metadata:raise AuthorityUnavailable("receipt original metadata changed after its complete read")


class PreparedArtifactReceiptOriginalsV1:
    def __init__(self,issuer,task):
        if issuer is not _ISSUER or not task.complete or task.receipt is None:
            raise TypeError("actual complete receipt original task required")
        self.task=task;self.receipt=task.receipt
        self.actor_ref,self.audiences,self.source_family=task.actor_ref,task.audiences,task.source_family
        self.digest=canonical_digest(("artifact-receipt-current-originals.v1",self.receipt.digest,
            task.graph_stamp,task.owner.authority_epochs,self.actor_ref,self.audiences,tuple(sorted(self.source_family)),tuple((sql,key,point.metadata,
                tuple(column.sha256 for _,_,column in point.columns))for(sql,key),point in task.points.items())))
        _SEALS[self]=(task,self.receipt,self.digest,task.owner.operation,task.owner.fence.scope,task.graph_stamp,self.actor_ref,self.audiences,self.source_family)
    def require_for_v1(self,inventory,db,*,now_utc,owner_guard=None):
        task=self.task;owner=task.owner
        if (_SEALS.get(self)!=(task,self.receipt,self.digest,owner.operation,owner.fence.scope,task.graph_stamp,self.actor_ref,self.audiences,self.source_family)
                or inventory.artifact_receipt_originals is not self or inventory.family!="artifact_receipt"
                or inventory.operation is not owner.operation or inventory.namespace!=owner.namespace
                or inventory.binding!=owner.binding or inventory.graph_stamp!=task.graph_stamp or db is not task.db
                or task.actor_ref!=self.actor_ref or task.audiences!=self.audiences or task.source_family!=self.source_family
                or owner.operation.closed or not task.complete or task.graph._v2_graph_stamp(owner.namespace)!=task.graph_stamp
                or not now_utc<self.receipt.original_deadline_utc
                or owner_guard is not None and owner_guard!=self.receipt.owner_guard):
            raise AuthorityUnavailable("receipt seal crossed its actual original Work/P2/current Owner/deadline")
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        with runtime_storage_quantum_v3(db)as meter:
            for point in task.points.values():point.require_current(db,meter)
        return self.receipt


class ArtifactReceiptOriginalReadTaskV1:
    def __init__(self,owner,now_utc):
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3,ARTIFACT_RECEIPT_FULL_READ_V1
        dispatch=type(owner)is _DispatchInventoryReadV3 and owner.family=="artifact_receipt"
        assembly=type(owner)is _OrdinaryFullReadV3 and owner.contract is ARTIFACT_RECEIPT_FULL_READ_V1
        if not(dispatch or assembly)or not owner.graph_eof:
            raise TypeError("receipt originals require the actual ordinary dispatch inventory Work")
        self.owner,self.db,self.graph=owner,owner.db,owner.graph
        self.graph_stamp=owner.graph_stamp;self.now_utc=now_utc;self.points={};self.pending=None
        self.complete=False;self.receipt=None;self.seal=None
        self.source_roots_qualified=False;self.source_family=frozenset()
        self.assembly=assembly;self.audiences=owner.authority.audience if assembly else owner.admission.admission.audience
        _TASKS[self]=(owner,owner.operation,owner.fence.scope,self.graph_stamp)
    def require_actual_v1(self):
        owner=self.owner
        if (_TASKS.get(self)!=(owner,owner.operation,owner.fence.scope,self.graph_stamp)
                or owner.operation.closed
                or owner.db is not self.db or not self.db.in_transaction):
            raise AuthorityUnavailable("receipt pre-read lost its actual original Work/SQL/fence/stamp")
        if self.graph._v2_graph_stamp(owner.namespace)!=self.graph_stamp:
            if not self.assembly or not owner.complete:
                raise AuthorityUnavailable("receipt actual pre-read graph stamp changed")
            from .current_graph_full_read_v3 import require_bound_graph_full_read_proof_v3,CURRENT_DISPATCH_FAMILY_V3
            active=require_bound_graph_full_read_proof_v3(self.graph,self.db,owner.namespace,
                required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
            if getattr(active,"base",None)is not owner.result:
                raise AuthorityUnavailable("receipt pre-read cannot accept an unrelated graph delta")
    def advance_v1(self,meter):
        self.require_actual_v1();owner=self.owner
        if self.pending is not None:
            self.pending.advance(meter)
            if self.pending.complete:self.pending=None
            return False
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from .artifact_completion_receipt_v1 import receipt_from_wire_v1,read_current_artifact_completion_receipt_by_operation_v1,receipt_ids_v1
        prefix="artifact-receipt-message:";operation=owner.receipt_operation_id if self.assembly else owner.binding.operation_id
        if not operation.startswith(prefix)or len(operation)!=len(prefix)+48:
            raise AuthorityUnavailable("receipt inventory lacks its exact fixed message identity")
        try:
            with _bind_v1(self):
                original=read_adopted_domain_operation_v1(self.db,owner.namespace,
                    "artifact-completion-source:"+operation[len(prefix):])
                if original is None:raise AuthorityUnavailable("receipt inventory lost its actual D06 producer")
                candidate=receipt_from_wire_v1(original["payload"]["provenance"]["artifact_completion_receipt"])
                self.actor_ref=original["payload"]["authority"]["actor"]
                self.candidate_selector=candidate.selector
                if not self.source_roots_qualified:
                    roots=(candidate.source_ref,*(head.key.token for head,_ in candidate.parent_source_heads))
                    self.source_family=frozenset(owner._require_source_roots_v3(roots,"expression",self.audiences))
                    self.source_roots_qualified=True
                bundle=self.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
                receipt=read_current_artifact_completion_receipt_by_operation_v1(self.db,namespace=owner.namespace,
                    operation_id=operation,issuer=self.graph._GraphCoordinator__d11_issuer,installed_bundle=bundle,
                    owner_guard=candidate.owner_guard,now_utc=self.now_utc,audiences=self.audiences)
            from .artifact_receipt_dispatch_v1 import _original_ingress_route_for_receipt_v1,recover_artifact_receipt_dispatch_candidate_in_transaction_v1
            with _bind_v1(self):
                self.route,self.route_binding=_original_ingress_route_for_receipt_v1(self.db,receipt,owner.query,self.now_utc)
                recovered=recover_artifact_receipt_dispatch_candidate_in_transaction_v1(self.db,owner.namespace,operation)
                self.candidate_recovery=recovered
                if self.assembly and recovered is not None:
                    # The same fixed columns consumed by cold recovery are prepared here.
                    artifact_receipt_sql_v1(self.db,"SELECT digest,activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",(*owner.namespace.as_tuple,operation)).fetchone()
                    artifact_receipt_sql_v1(self.db,"SELECT reads,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",(*owner.namespace.as_tuple,receipt_ids_v1(receipt.selector)["activity"],operation)).fetchone()
                if not self.assembly and (recovered is None or recovered.evidence.payload_digest!=owner.request.payload_digest):
                    raise AuthorityUnavailable("receipt originals differ from the actual admitted dispatch payload")
            self.receipt=receipt;self.complete=True;self.seal=PreparedArtifactReceiptOriginalsV1(_ISSUER,self)
            return True
        except _NeedPoint as needed:
            request=(needed.query,needed.key)
            if len(self.points)>=256:raise AuthorityUnavailable("receipt original closure exceeded the retained point bound")
            profile=_receipt_life_index_profile_v1(self,*request)
            self.pending=(_ReceiptPointV1(self,*request)if profile is None else _ReceiptLifeIndexPointV1(self,*request,profile))
            self.points[request]=self.pending
            return False


def require_prepared_artifact_completion_receipt_v1(db,*,namespace,selector,issuer,installed_bundle,
        owner_guard,now_utc,audiences,prepared_inventory):
    from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3
    if type(prepared_inventory)is not PreparedCurrentDispatchInventoryV3:
        raise AuthorityUnavailable("receipt current disclosure requires its actual issued dispatch inventory")
    prepared_inventory.require_current(db,namespace,prepared_inventory.query)
    seal=prepared_inventory.artifact_receipt_originals
    if type(seal)is not PreparedArtifactReceiptOriginalsV1:
        raise AuthorityUnavailable("receipt current disclosure has no actual complete private original seal")
    value=seal.require_for_v1(prepared_inventory,db,now_utc=now_utc,owner_guard=owner_guard)
    if (value.selector!=selector or issuer is not prepared_inventory.graph._GraphCoordinator__d11_issuer
            or installed_bundle is not prepared_inventory.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
            or tuple(audiences)!=prepared_inventory.admission.admission.audience):
        raise AuthorityUnavailable("receipt disclosure crossed its actual namespace/selector/issuer/installation/audience")
    return value


def read_bound_artifact_receipt_point_v1(db,*,table,columns,key_columns,key):
    task=_ACTIVE.get()
    if task is None:return False,None
    task.require_actual_v1()
    if db is not task.db or table not in _TABLES:
        raise AuthorityUnavailable("receipt point escaped its actual Work connection/closed tables")
    names=tuple(columns)+tuple(key_columns)
    if any(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*",name)is None for name in names):
        raise AuthorityUnavailable("receipt point has another exact column/key projection")
    query="SELECT "+",".join(columns)+" FROM "+table+" WHERE "+" AND ".join(name+"=?"for name in key_columns)
    return True,artifact_receipt_sql_v1(db,query,key).fetchone()


@contextmanager
def bind_prepared_artifact_receipt_points_v1(seal,inventory,db,*,now_utc):
    if type(seal)is not PreparedArtifactReceiptOriginalsV1:
        raise AuthorityUnavailable("actual private prepared receipt seal required")
    seal.require_for_v1(inventory,db,now_utc=now_utc)
    with _bind_v1(seal.task):yield seal


_PAYLOAD_BOUND=ContextVar('artifact_receipt_payload_v1',default=None)

@contextmanager
def bind_artifact_receipt_payload_v1(inventory,graph,request,*,now_utc):
    from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3
    if (type(inventory)is not PreparedCurrentDispatchInventoryV3 or inventory.family!="artifact_receipt"
            or inventory.graph is not graph or inventory.request!=request):
        raise AuthorityUnavailable("Artifact payload requires its actual completed current dispatch inventory")
    sealed=inventory.artifact_receipt_originals
    db=graph._GraphCoordinator__store._db
    # Validation occurs on GraphWorker in the resolver's actual transaction.
    token=_PAYLOAD_BOUND.set((inventory,graph,request,now_utc,sealed))
    try:yield
    finally:_PAYLOAD_BOUND.reset(token)


def require_artifact_receipt_payload_inventory_v1(graph,request):
    bound=_PAYLOAD_BOUND.get()
    if (bound is None or bound[1]is not graph or bound[2]!=request
            or bound[0].artifact_receipt_originals is not bound[4]):
        raise AuthorityUnavailable("Artifact payload cannot bypass its actual receipt original inventory")
    inventory,_,_,now,sealed=bound
    sealed.require_for_v1(inventory,graph._GraphCoordinator__store._db,now_utc=now)
    return inventory,now

def actual_bound_artifact_dispatch_inventory_v1(db,namespace,operation_id):
    from .current_graph_full_read_v3 import _BOUND,_DispatchFullReadBindingV3
    active=_BOUND.get()
    if type(active)is not _DispatchFullReadBindingV3:return None
    proof=active.proof
    if(proof.family!="artifact_receipt"or proof.namespace!=namespace or proof.binding.operation_id!=operation_id
            or proof.graph._GraphCoordinator__store._db is not db):return None
    active.require_current(active.graph,db,namespace,required_families=frozenset())
    return proof


def require_artifact_receipt_assembly_original_v1(proof,graph,db,*,now_utc):
    from .current_graph_full_read_v3 import PreparedCurrentGraphFullReadV3,ARTIFACT_RECEIPT_FULL_READ_V1,require_bound_graph_full_read_proof_v3,CURRENT_DISPATCH_FAMILY_V3
    current=require_bound_graph_full_read_proof_v3(graph,db,proof.namespace,
        required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
    base=getattr(current,"base",current)
    if type(base)is not PreparedCurrentGraphFullReadV3 or base is not proof or base.contract is not ARTIFACT_RECEIPT_FULL_READ_V1:
        raise AuthorityUnavailable("Artifact completion original requires its actual originating full-read family")
    base._actual();seal=base.artifact_receipt_originals
    if type(seal)is not PreparedArtifactReceiptOriginalsV1:
        raise AuthorityUnavailable("Artifact full-read did not finish its actual original task")
    task=seal.task;owner=task.owner
    if (_SEALS.get(seal)!=(task,seal.receipt,seal.digest,owner.operation,owner.fence.scope,task.graph_stamp,seal.actor_ref,seal.audiences,seal.source_family)
            or not task.assembly or owner.work is not base.work or owner.operation is not base.operation
            or task.actor_ref!=seal.actor_ref or task.audiences!=seal.audiences or task.source_family!=seal.source_family
            or owner.artifact_receipt_originals is not seal or owner.receipt_operation_id!=seal.receipt.message_operation_id
            or not now_utc<seal.receipt.original_deadline_utc):
        raise AuthorityUnavailable("Artifact actual full-read original seal/operation/deadline differs")
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        for point in task.points.values():
            if current is not base and point.table in {"graph_epochs"}:
                continue
            delta=_ASSEMBLY_BUDGET_DELTA.get()
            actual=None if delta is None or delta[0]is not proof else delta[5].get((point.query,point.key))
            if actual is None:point.require_current(db,meter)
            else:
                rows=tuple(tuple(row)for row in db.execute(point.metadata_query,point.key).fetchmany(129))
                meter.charge_read(_heap(rows))
                if rows!=actual:raise AuthorityUnavailable("receipt own D11 reservation metadata changed after its actual receipt")
    return seal.receipt


@contextmanager
def bind_artifact_receipt_assembly_points_v1(proof,graph,db,*,now_utc):
    value=require_artifact_receipt_assembly_original_v1(proof,graph,db,now_utc=now_utc)
    with _bind_v1(proof.artifact_receipt_originals.task):yield value




_ASSEMBLY_BUDGET_DELTA=ContextVar("artifact-receipt-actual-reservation.v1",default=None)

@contextmanager
def reserve_artifact_receipt_assembly_budget_v1(proof,graph,scope,envelope,quote,*,now_utc):
    from ..runtime_contracts import FenceScope
    from ..graph_coordinator import budget_operation_digest
    from .budget import reserve_budget,BudgetReceipt
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    db=graph._GraphCoordinator__store._db
    value=require_artifact_receipt_assembly_original_v1(proof,graph,db,now_utc=now_utc)
    if(type(scope)is not FenceScope or scope.operation!="write"or scope.namespace!=value.namespace
            or scope.graph_epoch!=proof.graph_stamp[1]or envelope.identity.operation_id!=value.message_operation_id
            or envelope.identity.effect_id!=value.effect_id or quote.operation_id!=value.message_operation_id
            or quote.parent_budget_lease_ref!=envelope.parent_budget_lease_ref):
        raise AuthorityUnavailable("receipt reservation crossed its actual writer/message/quote")
    digest=budget_operation_digest(envelope,envelope.parent_budget_lease_ref,dict(quote.ceiling))
    receipt=reserve_budget(db,envelope.parent_budget_lease_ref,value.message_operation_id,digest,quote.ceiling)
    if(type(receipt)is not BudgetReceipt or receipt.status!="reserved"or receipt.operation_id!=value.message_operation_id
            or receipt.digest!=digest or receipt.lease_id!=envelope.parent_budget_lease_ref):
        raise AuthorityUnavailable("receipt single-message reservation has no actual D11 receipt")
    actual={}
    with runtime_storage_quantum_v3(db)as meter:
        for key,point in proof.artifact_receipt_originals.task.points.items():
            if point.table!="runtime_budget_leases":continue
            # reserve_budget changes only this exact child. Ancestor gates remain
            # actual independent debt/family checks, and all other points must match.
            if quote.parent_budget_lease_ref not in point.key:continue
            rows=tuple(tuple(row)for row in db.execute(point.metadata_query,point.key).fetchmany(129))
            meter.charge_read(_heap(rows));actual[key]=rows
    state=(proof,scope,envelope,quote,receipt,actual)
    token=_ASSEMBLY_BUDGET_DELTA.set(state)
    try:yield receipt
    finally:_ASSEMBLY_BUDGET_DELTA.reset(token)

class _ReceiptIndexColumnV1(DispatchOriginalJSONReadV3):
    """Same complete canonical stream as Core's phase_prepared_index profile."""
    def __init__(self,point,ref):
        from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3,ConditionedMetadataJSONStreamV3
        self.point=point;self.capture=None;self.registered=False
        super().__init__(point.owner,table=point.table,column="payload_json",
            key_columns=("bot","persona","kind","original_ref"),key=(*point.owner.namespace.as_tuple,point.kind,ref))
        self.capture=ConditionedLocatorJSONV3(self)
        self.capture.retain_path_v3=lambda path:not path or path[0]in{"schema","selector","operation_id","call_id"}
        self.parser=ConditionedMetadataJSONStreamV3(self.capture,ensure_ascii=True)
        self._reserve()
    def _runtime_retained_heap_bytes_v3(self):
        return 65536+_heap((self.nodes,self.scalar,self.fragment,self.value,
            None if self.capture is None else self.capture.value))
    def _reserve(self,extra=0):
        if not self.registered:
            self.operation.register_retained_state_v3(self);self.registered=True
        else:self.operation.refresh_retained_state_v3(self)
        if extra:
            self.operation.reserve_retained_state_growth_v3(self,extra)
            self.operation.finish_retained_state_growth_v3(self)
    def _emit(self,event):
        self.capture._emit_v3(event);self.value=self.capture.value
        self._reserve()
    def close_v1(self):
        from .dispatch_initial_source_read_v3 import _COLUMNS
        _COLUMNS.pop(self,None)
        self.operation.unregister_retained_state_v3(self)
        self.capture=self.value=self._frozen_value=None


class _ReceiptLifeIndexPointV1:
    """Actual signed keyset EOF for two closed existing Life lookup profiles."""
    def __init__(self,task,query,key,profile):
        self.task,self.owner,self.query,self.key=task,task.owner,query,key
        self.table="graph_d11_life_originals_v1";self.kind,self.path,self.selection,self.limit=profile
        self.complete=False;self.cursor="";self.count=0
        self.root=canonical_digest(("artifact-receipt-Life-index.v1",self.kind,task.owner.namespace,key))
        self.current_header=None;self.column=None;self.matching=[];self.matching_headers=[]
        self.columns=[];self.metadata=();self.rows=()
    def advance(self,meter):
        self.task.require_actual_v1();db=self.task.db
        from .d11_life_preparation_v1 import SIGN_KIND
        if self.column is None:
            row=meter.read_fixed_row(db,self.table,("original_ref","producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
                (*self.owner.namespace.as_tuple,self.kind,self.cursor))
            if row is None:
                self.metadata=(("complete_signed_keyset_eof",self.kind,self.count,self.root,self.cursor),)
                self.rows=tuple(self.matching if self.limit is None else self.matching[:self.limit])
                self.complete=True;return
            self.current_header=tuple(row);self.cursor=row[0]
            self.column=_ReceiptIndexColumnV1(self,row[0]);return
        if not self.column.advance(meter):return
        ref,operation,digest,signature=self.current_header
        if self.column.sha256!=digest:
            raise AuthorityUnavailable("receipt Life index has no complete actual canonical SHA/EOF")
        self.owner.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((self.owner.namespace,self.kind,ref,digest)),signature)
        raw=self.column.require_v3(self.owner)
        if self.kind=="c4_phase_prepared":
            from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
            if raw["schema"]!="d11.artifact-draft-phase-model-prepared.v2"or raw["operation_id"]!=operation:
                raise AuthorityUnavailable("receipt task preparation index changed its actual typed producer")
            selected=artifact_draft_from_wire_v2(raw["selector"],ArtifactDraftPhaseSelectorV2)
            if selected.task.namespace!=self.owner.namespace:
                raise AuthorityUnavailable("receipt task preparation signed index crossed namespace")
            matches=selected.task.c02_operation_id==self.key[2]
        else:
            if raw["schema"]!="d11.artifact-draft-model-prepared.v1"or raw["operation_id"]!=operation:
                raise AuthorityUnavailable("receipt call index changed its actual typed producer")
            matches=raw["call_id"]==self.key[2]
        self.count+=1
        self.root=canonical_digest((self.root,self.current_header,self.column.sha256,self.column.byte_count,raw))
        if matches:
            item=(operation,)if self.selection==("producing_operation_id",)else(ref,)
            self.matching.append(item);self.matching_headers.append(self.current_header)
            self.owner.operation.retain(_heap((item,self.current_header))+1024)
        self.column.close_v1();self.column=None;self.current_header=None
    def require_current(self,db,meter):
        if not self.complete or db is not self.task.db:
            raise AuthorityUnavailable("receipt Life index is not a complete actual EOF")
        self.task.require_actual_v1()
        # These originals are immutable under the existing put contract. A new
        # phase preparation changes its actual Graph commit stamp and this
        # family's cardinality; neither can cross the originating current Work.
        count=db.execute("SELECT COUNT(*),MAX(original_ref) FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=?",
            (*self.owner.namespace.as_tuple,self.kind)).fetchone()
        meter.charge_read(_heap(count))
        if count!=(self.count,self.cursor or None):
            raise AuthorityUnavailable("receipt complete Life index changed its actual EOF")
        for expected in self.matching_headers:
            row=meter.read_fixed_row(db,self.table,("original_ref","producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*self.owner.namespace.as_tuple,self.kind,expected[0]))
            if row!=expected:raise AuthorityUnavailable("receipt selected signed Life index header changed")


def _receipt_life_index_profile_v1(task,query,key):
    table="graph_d11_life_originals_v1"
    task_query=("SELECT producing_operation_id FROM "+table+" WHERE bot=? AND persona=? AND kind='c4_phase_prepared' "
        "AND json_extract(payload_json,'$.selector.task.c02_operation_id')=?")
    call_query=("SELECT original_ref FROM "+table+" WHERE bot=? AND persona=? AND kind='c4_prepared' "
        "AND json_extract(payload_json,'$.call_id')=? LIMIT 2")
    if query not in {task_query,call_query}:return None
    if len(key)!=3 or key[:2]!=task.owner.namespace.as_tuple:
        raise AuthorityUnavailable("receipt fixed Life lookup crossed its actual namespace")
    if query==task_query:
        if key[2]!=task.candidate_selector.task.c02_operation_id:
            raise AuthorityUnavailable("receipt preparation census crossed its actual original task")
        return "c4_phase_prepared",("selector","task","c02_operation_id"),("producing_operation_id",),None
    return "c4_prepared",("call_id",),("original_ref",),2
