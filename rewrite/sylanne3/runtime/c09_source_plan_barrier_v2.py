"""Current-Graph C09 Source ancestry/descendant capture and atomic barrier pages.

Owner and Core pending authorization are supplied only by the installed Graph
entrypoints. The tables contain structural commitments, never Source bodies.
Unfinished work remains persistent and does not attest an accepted erasure.
"""
from dataclasses import asdict, dataclass
from contextlib import contextmanager
import json
import sqlite3
from time import monotonic_ns

from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..memory_types import source_key, access_key, validate_access
from ..domains.d06 import source_correction_head_key
from ..runtime_contracts import NamespaceId
from .c09_paged_sql_v2 import canonical_digest, canonical_serialize
from .c09_paged_sql_v2 import C09BatchBudgetV2, C09SqlByteMeterV2, C09PagedCaptureHold
from .c09_erasure_plan_original_v1 import C09_SOURCE_ERASURE_POLICY_REF

@contextmanager
def source_plan_metered_quantum_v2(budget):
    """A single installed reserved quantum shared by all actual producer steps."""
    from .c09_paged_sql_v2 import _QUANTUM_METER_V2
    from .c09_paged_capture_contract_v2 import meter_c09_commitments_v2
    if _QUANTUM_METER_V2.get() is not None:raise C09PagedCaptureHold('Source plan cannot nest a second reserved quantum')
    meter=C09SqlByteMeterV2(budget);token=_QUANTUM_METER_V2.set(meter)
    try:
        with meter_c09_commitments_v2(meter):yield meter
    finally:_QUANTUM_METER_V2.reset(token)


def _source_meter_v2(budget):
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    meter=current_c09_sql_meter_v2()
    if meter.budget!=budget:raise C09PagedCaptureHold('Source producer crossed actual reserved quantum')
    return meter


SOURCE_PLAN_BARRIER_DDLS_V2 = {
 "graph_c09_source_work_v2": "CREATE TABLE graph_c09_source_work_v2 (bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL, state_json TEXT NOT NULL, PRIMARY KEY(bot,persona,operation_id))",
 "graph_c09_source_members_v2": "CREATE TABLE graph_c09_source_members_v2 (bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL, source_ref TEXT NOT NULL, source_id TEXT NOT NULL, source_revision INTEGER NOT NULL, source_digest TEXT NOT NULL, access_ref TEXT NOT NULL, access_revision INTEGER NOT NULL, access_digest TEXT NOT NULL, correction_ref TEXT NOT NULL, correction_revision INTEGER NOT NULL, correction_digest TEXT NOT NULL, ancestor INTEGER NOT NULL DEFAULT 0, ancestor_done INTEGER NOT NULL DEFAULT 0, affected INTEGER NOT NULL DEFAULT 0, expanded INTEGER NOT NULL DEFAULT 0, withdrawn_page INTEGER, withdrawn_revision INTEGER, PRIMARY KEY(bot,persona,operation_id,source_ref))",
 "graph_c09_source_ancestry_stack_v2": "CREATE TABLE graph_c09_source_ancestry_stack_v2 (bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL, depth INTEGER NOT NULL, source_ref TEXT NOT NULL, parent_index TEXT NOT NULL, PRIMARY KEY(bot,persona,operation_id,depth))",
 "graph_c09_source_invalidation_v2": "CREATE TABLE graph_c09_source_invalidation_v2 (bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,token TEXT NOT NULL,expanded INTEGER NOT NULL DEFAULT 0,last_child TEXT NOT NULL DEFAULT '',applied INTEGER NOT NULL DEFAULT 0,before_revision INTEGER,after_revision INTEGER,page_index INTEGER,body_digest TEXT,PRIMARY KEY(bot,persona,operation_id,token))",
 "graph_c09_source_edges_v2": "CREATE TABLE graph_c09_source_edges_v2 (bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL, child_ref TEXT NOT NULL, parent_ref TEXT NOT NULL, PRIMARY KEY(bot,persona,operation_id,child_ref,parent_ref))",
 "graph_c09_source_pages_v2": "CREATE TABLE graph_c09_source_pages_v2 (bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL, stream_kind TEXT NOT NULL, page_index INTEGER NOT NULL, descriptor_json TEXT NOT NULL, records_json TEXT NOT NULL, PRIMARY KEY(bot,persona,operation_id,stream_kind,page_index))",
}
SOURCE_PLAN_BARRIER_INDEXES_V2 = (
 "CREATE INDEX graph_c09_source_access_v2 ON graph_c09_source_members_v2(bot,persona,operation_id,affected,access_ref)",
 "CREATE INDEX graph_c09_source_invalidation_pending_v2 ON graph_c09_source_invalidation_v2(bot,persona,operation_id,expanded,applied,token)",
 "CREATE INDEX graph_c09_source_edges_parent_v2 ON graph_c09_source_edges_v2(bot,persona,operation_id,parent_ref,child_ref)",
 "CREATE INDEX graph_c09_source_ancestor_v2 ON graph_c09_source_members_v2(bot,persona,operation_id,ancestor,ancestor_done,source_ref)",
 "CREATE INDEX graph_c09_source_affected_v2 ON graph_c09_source_members_v2(bot,persona,operation_id,affected,expanded,source_ref)",
)
SOURCE_PLAN_BARRIER_TABLES_V2 = frozenset(SOURCE_PLAN_BARRIER_DDLS_V2)


def install_c09_source_plan_barrier_schema_v2(db):
    for ddl in SOURCE_PLAN_BARRIER_DDLS_V2.values():
        db.execute(ddl.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
    for ddl in SOURCE_PLAN_BARRIER_INDEXES_V2:
        db.execute(ddl.replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1))
    for action in ("UPDATE", "DELETE"):
        db.execute("CREATE TRIGGER IF NOT EXISTS graph_c09_source_pages_v2_"+action.lower()+
            "_immutable BEFORE "+action+" ON graph_c09_source_pages_v2 BEGIN SELECT RAISE(ABORT,'C09 Source page immutable'); END")


@dataclass(frozen=True, slots=True)
class C09SourcePlanCaptureV2:
    namespace: NamespaceId
    operation_id: str
    source_id: str
    source_ref: str
    source_revision: int
    source_digest: str
    owner_ref: str
    owner_revision: int
    owner_grant_digest: str
    graph_incarnation: str
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    recovery_basis_digest: str
    source_location_digest: str
    selected_storage_generation: int
    selected_manifest_digest: str
    selected_pointer_version: int
    inventory_count: int
    inventory_root: str
    ancestry_count: int
    ancestry_root: str
    descendant_count: int
    descendant_root: str
    source_page_root: str
    source_page_count: int
    eof_count_digest: str
    request_digest: str
    policy_ref: str = C09_SOURCE_ERASURE_POLICY_REF
    policy_version: int = 1
    scope_kind: str = "one_source"
    schema: str = "sylanne3.graph.c09_source_plan_capture.v2"

    def __post_init__(self):
        from .c09_erasure_plan_original_v1 import C09_SOURCE_ERASURE_POLICY_REF
        if (type(self.namespace) is not NamespaceId or self.source_ref != source_key(*self.namespace.as_tuple,self.source_id).token
                or self.owner_ref != owner_grant_key(*self.namespace.as_tuple).token
                or self.scope_kind != "one_source" or self.policy_version != 1
                or self.policy_ref != C09_SOURCE_ERASURE_POLICY_REF
                or self.schema != "sylanne3.graph.c09_source_plan_capture.v2"):
            raise ValueError("C09 V2 Source plan identity differs")
        if any(type(x) is not int or x<0 for x in (self.source_revision,self.owner_revision,self.graph_epoch,
                self.access_epoch,self.delete_epoch,self.selected_storage_generation,self.selected_pointer_version,self.inventory_count,self.ancestry_count,self.descendant_count,self.source_page_count)):
            raise ValueError("C09 V2 Source plan count/version differs")
        if min(self.source_revision,self.owner_revision,self.ancestry_count,self.descendant_count)<1:
            raise ValueError("C09 V2 Source plan lacks actual root/Owner/closure")
        if self.request_digest != canonical_digest(self.request_basis()):
            raise ValueError("C09 V2 Source plan digest differs")

    @property
    def root_source_ids(self): return (self.source_id,)
    @property
    def digest(self): return canonical_digest(self.to_wire())
    def request_basis(self): return {k:v for k,v in asdict(self).items() if k!='request_digest'}
    def to_wire(self): return asdict(self)
    @classmethod
    def from_wire(cls,raw):
        from dataclasses import fields
        if type(raw) is not dict or set(raw)!={f.name for f in fields(cls)}:
            raise ValueError("C09 V2 Source plan wire fields differ")
        return cls(**{**raw,'namespace':NamespaceId(**raw['namespace'])})


@dataclass(frozen=True, slots=True)
class C09GraphBarrierPageV2:
    namespace: NamespaceId
    operation_id: str
    plan_digest: str
    pending_receipt_digest: str
    permit_digest: str
    page_index: int
    previous_page_digest: str
    record_offset: int
    record_count: int
    records_root: str
    last_source_ref: str
    graph_epoch_before: int
    graph_epoch_after: int
    access_epoch_before: int
    access_epoch_after: int
    delete_epoch_before: int
    delete_epoch_after: int
    event_id: str
    event_digest: str
    graph_receipt_digest: str
    page_digest: str
    schema: str = "sylanne3.graph.c09_source_barrier_page.v2"

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or not 1<=self.record_count<=64
                or self.page_index<0 or self.record_offset<0
                or self.graph_epoch_after!=self.graph_epoch_before+1
                or self.access_epoch_after!=self.access_epoch_before+1
                or self.delete_epoch_after!=self.delete_epoch_before+(1 if self.page_index==0 else 0)
                or self.schema!='sylanne3.graph.c09_source_barrier_page.v2'):
            raise ValueError('C09 V2 barrier page does not describe its actual bounded CAS')
        if self.page_digest!=canonical_digest({k:v for k,v in asdict(self).items() if k!='page_digest'}):
            raise ValueError('C09 V2 barrier page digest differs')
    @classmethod
    def from_wire(cls,raw):
        from dataclasses import fields
        if type(raw) is not dict or set(raw)!={f.name for f in fields(cls)}:
            raise ValueError('C09 V2 original wire fields differ')
        return cls(**{**raw,'namespace':NamespaceId(**raw['namespace'])})


@dataclass(frozen=True, slots=True)
class C09GraphBarrierReceiptV2:
    namespace: NamespaceId
    operation_id: str
    request_digest: str
    pending_receipt_digest: str
    plan_digest: str
    closure_digest: str
    root_source_ref: str
    graph_incarnation: str
    graph_epoch_before: int
    graph_epoch_after: int
    access_epoch_before: int
    access_epoch_after: int
    delete_epoch_before: int
    delete_epoch_after: int
    affected_count: int
    affected_root: str
    withdrawn_count: int
    withdrawn_root: str
    page_count: int
    page_root: str
    eof_count_digest: str
    receipt_digest: str
    schema: str = "sylanne3.graph.c09_erasure_barrier.v2"

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.affected_count<1
                or self.withdrawn_count!=self.affected_count or self.page_count<1
                or self.graph_epoch_after!=self.graph_epoch_before+self.page_count
                or self.access_epoch_after!=self.access_epoch_before+self.page_count
                or self.delete_epoch_after!=self.delete_epoch_before+1
                or self.schema!='sylanne3.graph.c09_erasure_barrier.v2'):
            raise ValueError('C09 V2 barrier has no actual complete withdrawal chain')
        if self.receipt_digest!=canonical_digest({k:v for k,v in asdict(self).items() if k!='receipt_digest'}):
            raise ValueError('C09 V2 barrier receipt digest differs')
    @property
    def root_source_refs(self):return (self.root_source_ref,)
    @property
    def digest(self):return canonical_digest(self)
    @classmethod
    def from_wire(cls,raw):
        from dataclasses import fields
        if type(raw) is not dict or set(raw)!={f.name for f in fields(cls)}:
            raise ValueError('C09 V2 original wire fields differ')
        return cls(**{**raw,'namespace':NamespaceId(**raw['namespace'])})


def _selected_source_plan_location_v2(selection):
    from ..authority_service.c09_source_plan_location_v2 import SelectedSourcePlanLocationV2
    if type(selection) is not SelectedSourcePlanLocationV2:
        raise TypeError('actual protected selected Source-plan location required')
    return {name:getattr(selection,name) for name in ('source_location_digest','selected_storage_generation','selected_manifest_digest','selected_pointer_version')}


def require_c09_source_storage_selection_v2(state,selection):
    # Actual qualifier/require_current runs outside the business SQL lock.
    if state['storage_selection']!=_selected_source_plan_location_v2(selection):
        raise C09PagedCaptureHold('Source plan selected storage or installed location changed')


class C09SourcePlanCellReaderV2:
    """One actual Graph store's current cell; restart re-reads that cell from 0."""
    __slots__=('source','shape','binding','cursor')
    def __init__(self,source):
        from .c09_paged_sql_v2 import read_c09_table_shape_v2
        self.source=source;self.shape=read_c09_table_shape_v2(source,'graph_atoms');self.binding=None;self.cursor=None

    def read_digest(self,namespace,operation_id,phase,token,revision,budget):
        from .c09_paged_sql_v2 import begin_c09_json_cell_commitment_v2,advance_c09_json_cell_commitment_v2
        if not self.source.in_transaction:raise C09PagedCaptureHold('Source cell left actual Graph transaction')
        size=self.source.execute("SELECT length(CAST(value AS BLOB)) FROM graph_atoms WHERE token=? AND bot=? AND persona=? AND revision=? AND valid=1 AND type_name='memory.source'",(token,*namespace.as_tuple,revision)).fetchone()
        if size is None:raise C09PagedCaptureHold('actual current Source cell disappeared')
        binding=(namespace,operation_id,phase,token,revision,size[0])
        if self.binding!=binding:
            self.cursor=begin_c09_json_cell_commitment_v2(self.source,self.shape,(token,),'value',expected_size=size[0],expected_revision=revision)
            self.binding=binding
        result=advance_c09_json_cell_commitment_v2(self.source,self.shape,budget,cursor=self.cursor,meter=_source_meter_v2(budget))
        return result['value_digest'] if result['complete'] else None


_MEMBER_COLUMNS=('source_ref','source_id','source_revision','source_digest','access_ref','access_revision',
    'access_digest','correction_ref','correction_revision','correction_digest')


def _scope(namespace,operation_id):return (*namespace.as_tuple,operation_id)

def read_c09_source_work_v2(db,namespace,operation_id):
    row=db.execute('SELECT state_json FROM graph_c09_source_work_v2 WHERE bot=? AND persona=? AND operation_id=?',_scope(namespace,operation_id)).fetchone()
    return None if row is None else json.loads(row[0])


def _save(db,namespace,operation_id,state,meter):
    wire=canonical_serialize(state);meter.charge_write(len(wire.encode()))
    db.execute('UPDATE graph_c09_source_work_v2 SET state_json=? WHERE bot=? AND persona=? AND operation_id=?',(wire,*_scope(namespace,operation_id)))


def source_plan_current_stamp_v2(db,namespace):
    row=db.execute('SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',namespace.as_tuple).fetchone()
    epoch=db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',namespace.as_tuple).fetchone()
    rights=db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',namespace.as_tuple).fetchone()
    if row is None or epoch is None or rights is None:raise C09PagedCaptureHold('actual C09 Graph storage/rights metadata absent')
    return {'recovery_basis_digest':canonical_digest((row[0],row[1])),'graph_epoch':epoch[0],'access_epoch':rights[0],'delete_epoch':rights[1]}


def require_c09_source_stamp_v2(db,namespace,state):
    if source_plan_current_stamp_v2(db,namespace)!=state['current_stamp']:
        raise C09PagedCaptureHold('C09 Source work saw an unrelated Graph/storage/rights change')
    owner=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(state['owner_ref'],)).fetchone()
    if owner is None or owner[2]!=1 or owner[0]!=state['owner_revision'] or 'sha256:'+canonical_digest(json.loads(owner[1]))!=state['owner_grant_digest']:
        raise C09PagedCaptureHold('C09 Source work current Owner changed')


def begin_c09_source_plan_capture_v2(db,*,namespace,operation_id,source_ref,owner_revision,owner_grant_digest,graph_incarnation,storage_selection,budget):
    """Called in the installed Owner write fence and the actual Graph transaction."""
    if not db.in_transaction or type(budget) is not C09BatchBudgetV2:raise ValueError('actual Owner transaction and reserved quantum required')
    key=AtomKey.from_token(source_ref)
    if key!=source_key(*namespace.as_tuple,key.owner.subject):raise ValueError('C09 Source root crosses its namespace/type')
    prior=read_c09_source_work_v2(db,namespace,operation_id)
    if prior is not None:
        if (prior['source_ref'],prior['owner_grant_digest'])!=(source_ref,owner_grant_digest):raise C09PagedCaptureHold('C09 Source operation original changed')
        require_c09_source_stamp_v2(db,namespace,prior);require_c09_source_storage_selection_v2(prior,storage_selection);return prior
    state={'schema':'sylanne3.graph.c09_source_work.v2','operation_id':operation_id,'source_id':key.owner.subject,'source_ref':source_ref,
        'owner_ref':owner_grant_key(*namespace.as_tuple).token,'owner_revision':owner_revision,'owner_grant_digest':owner_grant_digest,
        'graph_incarnation':graph_incarnation,'storage_selection':_selected_source_plan_location_v2(storage_selection),'initial_stamp':source_plan_current_stamp_v2(db,namespace),
        'current_stamp':source_plan_current_stamp_v2(db,namespace),'quantum_index':0,'phase':'inventory','inventory_last':'','inventory_count':0,
        'inventory_root':canonical_digest(('c09.source-inventory.v2',namespace,operation_id)),'source_page_count':0,
        'source_page_root':canonical_digest(('c09.source-pages.v2',namespace,operation_id)),
        'parent_ref':None,'child_last':'','inventory_parent_ref':None,'inventory_parent_index':0,'ancestry_depth':0,'seal_last':'','ancestry_count':0,'ancestry_root':canonical_digest(('c09.ancestors.v2',namespace,operation_id)),
        'descendant_count':0,'descendant_root':canonical_digest(('c09.descendants.v2',namespace,operation_id)),
        'census_last':'','census_count':0,'census_root':canonical_digest(('c09.source-inventory.v2',namespace,operation_id))}
    require_c09_source_stamp_v2(db,namespace,state)
    wire=canonical_serialize(state);meter=_source_meter_v2(budget);meter.charge_write(len(wire.encode()))
    db.execute('INSERT INTO graph_c09_source_work_v2 VALUES(?,?,?,?)',(*_scope(namespace,operation_id),wire))
    return state


def _source_row(db,namespace,token,meter,*,value_digest=None,operation_id):
    row=meter.read_fixed_row(db,'graph_atoms',('revision','valid','type_name'),'token=? AND bot=? AND persona=?',(token,*namespace.as_tuple))
    if row is None or row[1]!=1 or row[2]!='memory.source':raise C09PagedCaptureHold('C09 Source inventory/current ancestor unavailable')
    key=AtomKey.from_token(token);source_id=key.owner.subject
    # Current valid memory.source heads were admitted through their registered
    # SourceRecord validator. Only fixed structural scalars cross this reader.
    actual_id=db.execute("SELECT json_extract(value,'$.source_id') FROM graph_atoms WHERE token=?",(token,)).fetchone()
    if actual_id!=(source_id,) or key!=source_key(*namespace.as_tuple,source_id):raise C09PagedCaptureHold('C09 actual Source identity differs')
    if value_digest is None:
        captured=_member(db,namespace,operation_id,token)
        if captured is None or captured[2]!=row[0]:raise C09PagedCaptureHold('actual Source version differs from captured cell digest')
        value_digest=captured[3]
    access=access_key(*namespace.as_tuple,source_id);correction=source_correction_head_key(namespace,source_id)
    a=meter.read_fixed_row(db,'graph_atoms',('revision','value','valid'),'token=?',(access.token,))
    c=meter.read_fixed_row(db,'graph_atoms',('revision','value','valid'),'token=?',(correction.token,))
    if a is None or a[2]!=1:raise C09PagedCaptureHold('C09 actual Source access absent')
    av=json.loads(a[1]);validate_access(av)
    if av['source_id']!=source_id:raise C09PagedCaptureHold('C09 Source access identity differs')
    if c is not None and c[2]!=1:raise C09PagedCaptureHold('C09 Source correction head invalid')
    member=(token,source_id,row[0],value_digest,access.token,a[0],canonical_digest(av),
            correction.token,0 if c is None else c[0],canonical_digest(None if c is None else json.loads(c[1])))
    return av,member


def _member(db,namespace,operation_id,token):
    return db.execute('SELECT '+','.join(_MEMBER_COLUMNS)+' FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND source_ref=?',(*_scope(namespace,operation_id),token)).fetchone()


def _page(db,namespace,operation_id,state,kind,records,meter):
    if not records:return
    wire=canonical_serialize(records)
    descriptor={'schema':'sylanne3.graph.c09_source_capture_page.v2','stream_kind':kind,'page_index':state['source_page_count'],
        'previous_page_digest':state['source_page_root'],'record_count':len(records),'payload_digest':canonical_digest(records)}
    descriptor['page_digest']=canonical_digest(descriptor)
    dwire=canonical_serialize(descriptor);meter.charge_write(len(dwire.encode())+len(wire.encode()))
    db.execute('INSERT INTO graph_c09_source_pages_v2 VALUES(?,?,?,?,?,?,?)',(*_scope(namespace,operation_id),kind,state['source_page_count'],dwire,wire))
    state['source_page_count']+=1;state['source_page_root']=descriptor['page_digest']


def advance_c09_source_plan_capture_v2(db,*,namespace,operation_id,cell_reader,storage_selection,budget):
    if not db.in_transaction:raise ValueError('C09 Source quantum requires actual Graph transaction')
    meter=_source_meter_v2(budget);state=read_c09_source_work_v2(db,namespace,operation_id)
    if state is None:raise C09PagedCaptureHold('actual C09 Source work absent')
    require_c09_source_stamp_v2(db,namespace,state);require_c09_source_storage_selection_v2(state,storage_selection)
    if type(cell_reader) is not C09SourcePlanCellReaderV2 or cell_reader.source is not db:raise TypeError('actual Graph Source cell reader required')
    records=[];start=monotonic_ns();scope=_scope(namespace,operation_id);page_kind=state['phase']
    while len(records)<min(64,budget.max_records) and monotonic_ns()-start<budget.max_local_ns and meter.available_bytes>65536:
        phase=state['phase']
        if phase!=page_kind and records:break
        page_kind=phase
        if phase=='inventory':
            if state['inventory_parent_ref'] is not None:
                token=state['inventory_parent_ref'];index=state['inventory_parent_index']
                parent=db.execute("SELECT json_extract(value,?) FROM graph_atoms WHERE token=? AND valid=1",(f'$.parent_source_ids[{index}]',token)).fetchone()
                if parent is None:raise C09PagedCaptureHold('Source parent inventory lost its actual head')
                if parent[0] is None:
                    state['inventory_parent_ref']=None;records.append((token,'parents_eof'));continue
                if type(parent[0]) is not str:raise C09PagedCaptureHold('Source parent structure is not a registered identifier')
                pref=source_key(*namespace.as_tuple,parent[0]).token
                if pref==token:raise C09PagedCaptureHold('C09 Source has a self ancestry cycle')
                meter.charge_read(len(parent[0].encode()));meter.charge_write(len(pref.encode())+len(token.encode()))
                db.execute('INSERT INTO graph_c09_source_edges_v2 VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING',(*scope,token,pref))
                state['inventory_parent_index']=index+1;records.append((token,index,pref));continue
            row=db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='memory.source' AND valid=1 AND token>? ORDER BY token COLLATE BINARY LIMIT 1",(*namespace.as_tuple,state['inventory_last'])).fetchone()
            if row is None:
                if _member(db,namespace,operation_id,state['source_ref']) is None:raise C09PagedCaptureHold('actual requested Source root absent')
                db.execute('UPDATE graph_c09_source_members_v2 SET ancestor=1,affected=1 WHERE bot=? AND persona=? AND operation_id=? AND source_ref=?',(*scope,state['source_ref']))
                db.execute('INSERT INTO graph_c09_source_ancestry_stack_v2 VALUES(?,?,?,?,?,?)',(*scope,0,state['source_ref'],''))
                state['phase']='ancestors';continue
            version=db.execute('SELECT revision FROM graph_atoms WHERE token=? AND valid=1',(row[0],)).fetchone()
            if version is None:raise C09PagedCaptureHold('actual Source head disappeared during cell read')
            digest=cell_reader.read_digest(namespace,operation_id,phase,row[0],version[0],budget)
            if digest is None:break
            _,member=_source_row(db,namespace,row[0],meter,value_digest=digest,operation_id=operation_id)
            meter.charge_write(len(canonical_serialize(member).encode()))
            db.execute('INSERT INTO graph_c09_source_members_v2 ('+'bot,persona,operation_id,'+','.join(_MEMBER_COLUMNS)+') VALUES('+','.join('?' for _ in range(13))+')',(*scope,*member))
            state['inventory_count']+=1;state['inventory_root']=canonical_digest(('c09.source-record.v2',state['inventory_count'],state['inventory_root'],member))
            state['inventory_last']=row[0];state['inventory_parent_ref']=row[0];state['inventory_parent_index']=0;records.append(member)
        elif phase=='ancestors':
            depth=state['ancestry_depth']
            stack=db.execute('SELECT source_ref,parent_index FROM graph_c09_source_ancestry_stack_v2 WHERE bot=? AND persona=? AND operation_id=? AND depth=?',(*scope,depth)).fetchone()
            if stack is None:
                if depth!=0:raise C09PagedCaptureHold('actual ancestry stack has no contiguous predecessor')
                state['phase']='descendants';continue
            token,index=stack
            access,member=_source_row(db,namespace,token,meter,operation_id=operation_id)
            if access['status']!='active' or member!=_member(db,namespace,operation_id,token):raise C09PagedCaptureHold('C09 current authorized ancestry changed/withdrawn')
            parent=db.execute('SELECT parent_ref FROM graph_c09_source_edges_v2 WHERE bot=? AND persona=? AND operation_id=? AND child_ref=? AND parent_ref>? ORDER BY parent_ref LIMIT 1',(*scope,token,index)).fetchone()
            if parent is None:
                db.execute('UPDATE graph_c09_source_members_v2 SET ancestor_done=1 WHERE bot=? AND persona=? AND operation_id=? AND source_ref=?',(*scope,token))
                db.execute('DELETE FROM graph_c09_source_ancestry_stack_v2 WHERE bot=? AND persona=? AND operation_id=? AND depth=?',(*scope,depth))
                state['ancestry_depth']=max(0,depth-1);records.append((token,'ancestor_eof'));continue
            pref=parent[0]
            if _member(db,namespace,operation_id,pref) is None:raise C09PagedCaptureHold('C09 Source ancestry parent absent')
            if db.execute('SELECT 1 FROM graph_c09_source_ancestry_stack_v2 WHERE bot=? AND persona=? AND operation_id=? AND source_ref=? LIMIT 1',(*scope,pref)).fetchone() is not None:
                raise C09PagedCaptureHold('C09 actual Source ancestry has a cycle')
            db.execute('UPDATE graph_c09_source_ancestry_stack_v2 SET parent_index=? WHERE bot=? AND persona=? AND operation_id=? AND depth=?',(pref,*scope,depth))
            done=db.execute('SELECT ancestor_done FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND source_ref=?',(*scope,pref)).fetchone()[0]
            db.execute('UPDATE graph_c09_source_members_v2 SET ancestor=1 WHERE bot=? AND persona=? AND operation_id=? AND source_ref=?',(*scope,pref))
            if not done:
                db.execute('INSERT INTO graph_c09_source_ancestry_stack_v2 VALUES(?,?,?,?,?,?)',(*scope,depth+1,pref,''));state['ancestry_depth']=depth+1
            records.append((token,index,pref))
        elif phase=='descendants':
            if state['parent_ref'] is None:
                row=db.execute('SELECT source_ref FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND affected=1 AND expanded=0 ORDER BY source_ref LIMIT 1',scope).fetchone()
                if row is None:state['phase']='seal';state['seal_last']='';continue
                state['parent_ref']=row[0];state['child_last']=''
            child=db.execute('SELECT child_ref FROM graph_c09_source_edges_v2 WHERE bot=? AND persona=? AND operation_id=? AND parent_ref=? AND child_ref>? ORDER BY child_ref LIMIT 1',(*scope,state['parent_ref'],state['child_last'])).fetchone()
            if child is None:
                db.execute('UPDATE graph_c09_source_members_v2 SET expanded=1 WHERE bot=? AND persona=? AND operation_id=? AND source_ref=?',(*scope,state['parent_ref']));records.append((state['parent_ref'],'expanded'));state['parent_ref']=None;continue
            db.execute('UPDATE graph_c09_source_members_v2 SET affected=1 WHERE bot=? AND persona=? AND operation_id=? AND source_ref=?',(*scope,child[0]));state['child_last']=child[0];records.append((child[0],'affected'))
        elif phase=='seal':
            row=db.execute('SELECT '+','.join(_MEMBER_COLUMNS)+',ancestor,affected FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND source_ref>? ORDER BY source_ref LIMIT 1',(*scope,state['seal_last'])).fetchone()
            if row is None:state['phase']='census';continue
            member=tuple(row[:10]);ordinal=state.get('sealed_count',0)+1;state['sealed_count']=ordinal
            if row[10]:state['ancestry_count']+=1;state['ancestry_root']=canonical_digest(('c09.ancestor-record.v2',state['ancestry_count'],state['ancestry_root'],member))
            if row[11]:state['descendant_count']+=1;state['descendant_root']=canonical_digest(('c09.descendant-record.v2',state['descendant_count'],state['descendant_root'],member))
            state['seal_last']=row[0];records.append(member)
        elif phase=='census':
            row=db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='memory.source' AND valid=1 AND token>? ORDER BY token COLLATE BINARY LIMIT 1",(*namespace.as_tuple,state['census_last'])).fetchone()
            if row is None:
                if state['census_count']!=state['inventory_count'] or state['census_root']!=state['inventory_root']:raise C09PagedCaptureHold('C09 actual EOF independent Source census differs')
                state['phase']='plan_complete';break
            version=db.execute('SELECT revision FROM graph_atoms WHERE token=? AND valid=1',(row[0],)).fetchone()
            if version is None:raise C09PagedCaptureHold('actual Source head disappeared during cell read')
            digest=cell_reader.read_digest(namespace,operation_id,phase,row[0],version[0],budget)
            if digest is None:break
            _,member=_source_row(db,namespace,row[0],meter,value_digest=digest,operation_id=operation_id)
            if member!=_member(db,namespace,operation_id,row[0]):raise C09PagedCaptureHold('C09 Source census differs from captured structure')
            state['census_count']+=1;state['census_root']=canonical_digest(('c09.source-record.v2',state['census_count'],state['census_root'],member));state['census_last']=row[0];records.append(member)
        elif phase=='plan_complete':break
        else:raise C09PagedCaptureHold('C09 Source plan stage cannot resume here')
    state['quantum_index']+=1
    _page(db,namespace,operation_id,state,page_kind,records,meter);_save(db,namespace,operation_id,state,meter)
    return state


def seal_c09_source_plan_v2(db,namespace,operation_id):
    state=read_c09_source_work_v2(db,namespace,operation_id)
    if state is None or state['phase']!='plan_complete':raise C09PagedCaptureHold('C09 Source capture not complete')
    require_c09_source_stamp_v2(db,namespace,state);root=_member(db,namespace,operation_id,state['source_ref']);stamp=state['initial_stamp']
    values=dict(namespace=namespace,operation_id=operation_id,source_id=state['source_id'],source_ref=state['source_ref'],
        source_revision=root[2],source_digest=root[3],owner_ref=state['owner_ref'],owner_revision=state['owner_revision'],owner_grant_digest=state['owner_grant_digest'],
        graph_incarnation=state['graph_incarnation'],**stamp,**state['storage_selection'],inventory_count=state['inventory_count'],inventory_root=state['inventory_root'],
        ancestry_count=state['ancestry_count'],ancestry_root=state['ancestry_root'],descendant_count=state['descendant_count'],descendant_root=state['descendant_root'],
        source_page_root=state['source_page_root'],source_page_count=state['source_page_count'],eof_count_digest=canonical_digest(('c09.source-eof.v2',state['census_count'],state['census_root'])),
        policy_ref=C09_SOURCE_ERASURE_POLICY_REF,
        policy_version=1,scope_kind='one_source',schema='sylanne3.graph.c09_source_plan_capture.v2')
    values['request_digest']=canonical_digest({**values,'namespace':asdict(namespace)})
    return C09SourcePlanCaptureV2(**values)


_BARRIER_SESSION='c09-source-barrier-v2'


def begin_c09_source_barrier_v2(db,*,plan,pending,permit_digest,budget):
    """Only called after the installed Core pending reader and current Owner checks."""
    from ..authority_service.v2_contract import DeletionMutationReceiptV1, deletion_scope_digest
    if (not db.in_transaction or type(plan) is not C09SourcePlanCaptureV2 or type(pending) is not DeletionMutationReceiptV1
            or pending.pending.source_phase!='absent' or pending.pending.target_phase!='pending'
            or pending.pending.deletion_operation_id!=plan.operation_id
            or pending.pending.closure_roots!=plan.root_source_ids
            or pending.pending.policy_ref!=plan.policy_ref
            or pending.pending.deletion_epoch!=plan.delete_epoch+1
            or pending.pending.evidence.issuer_id!='authority-owner-graph-plan-v2'
            or pending.pending.evidence.scope_digest!=deletion_scope_digest(plan.root_source_ids,plan.delete_epoch+1,plan.policy_ref)):
        raise C09PagedCaptureHold('actual Core pending does not authorize this complete one-Source plan')
    state=read_c09_source_work_v2(db,plan.namespace,plan.operation_id)
    if state is None:raise C09PagedCaptureHold('actual persistent Source plan absent')
    require_c09_source_stamp_v2(db,plan.namespace,state)
    digest=canonical_digest(pending)
    if state['phase']!='plan_complete':
        if (state.get('plan_digest'),state.get('pending_digest'),state.get('permit_digest'))!=(plan.digest,digest,permit_digest):
            raise C09PagedCaptureHold('actual pending/plan/permit changed between barrier pages')
        return state
    request=authority_c09_plan_request_identity_v2(pending.pending.before_anchor.namespace,plan)
    import hashlib
    expected='sha256:'+hashlib.sha256(json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    if pending.pending.request_digest!=expected:raise C09PagedCaptureHold('Core pending request does not bind actual V2 plan')
    state.update(phase='barrier',plan_digest=plan.digest,pending_digest=digest,permit_digest=permit_digest,
        pending_request_digest=expected.removeprefix('sha256:'),closure_digest=pending.pending.evidence.scope_digest.removeprefix('sha256:'),
        barrier_last='',barrier_count=0,barrier_pages=0,
        barrier_root=canonical_digest(('c09.withdrawn-records.v2',plan.digest,digest)),
        barrier_page_root=canonical_digest(('c09.barrier-pages.v2',plan.digest,digest)),
        verify_last='',verify_count=0,verify_root=canonical_digest(('c09.withdrawn-records.v2',plan.digest,digest)),
        verify_page_index=0,verify_page_root=canonical_digest(('c09.barrier-pages.v2',plan.digest,digest)),
        verify_chain_count=0,verify_chain_root=canonical_digest(('c09.withdrawn-records.v2',plan.digest,digest)),verify_chain_last='')
    _save(db,plan.namespace,plan.operation_id,state,_source_meter_v2(budget));return state


def authority_c09_plan_request_identity_v2(authority_namespace,plan):
    if type(plan) is not C09SourcePlanCaptureV2:raise TypeError('actual V2 Source plan required')
    return dict(schema='sylanne3.scoped-erasure-plan-request.v3',namespace=authority_namespace,operation_id=plan.operation_id,
        scope_kind='one_source',roots=plan.root_source_ids,epoch=plan.delete_epoch+1,policy_ref=plan.policy_ref,policy_version=1,
        plan_request_digest=plan.request_digest,plan_content_digest=plan.digest,graph_namespace=plan.namespace.as_tuple,
        graph_incarnation=plan.graph_incarnation,graph_epoch=plan.graph_epoch,graph_access_epoch=plan.access_epoch,
        graph_delete_epoch=plan.delete_epoch,owner_grant_digest=plan.owner_grant_digest)


def prepare_c09_source_barrier_page_v2(db,*,namespace,operation_id,budget):
    from ..graph_types import Event,Scope,GraphWrite,GraphCandidate,NamespaceEpoch
    if not db.in_transaction:raise ValueError('actual pending Graph page transaction required')
    state=read_c09_source_work_v2(db,namespace,operation_id);require_c09_source_stamp_v2(db,namespace,state)
    if state['phase']!='barrier':raise C09PagedCaptureHold('Source barrier is not ready for a write page')
    meter=_source_meter_v2(budget);reads=[];writes=[];members=[];last=state['barrier_last'];start=monotonic_ns();page_bytes=0
    owner=owner_grant_key(*namespace.as_tuple);reads.append(GraphVersion(owner,state['owner_revision']))
    while len(writes)<min(64,budget.max_records) and monotonic_ns()-start<budget.max_local_ns and meter.available_bytes>131072:
        row=db.execute('SELECT source_ref FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND affected=1 AND source_ref>? ORDER BY source_ref LIMIT 1',(*_scope(namespace,operation_id),last)).fetchone()
        if row is None:break
        access,member=_source_row(db,namespace,row[0],meter,operation_id=operation_id)
        if member!=_member(db,namespace,operation_id,row[0]) or access['status']!='active':
            raise C09PagedCaptureHold('Source/current access changed outside this barrier')
        record_bytes=len(canonical_serialize((member[0],member[2],member[3],member[4],member[5],member[5]+1,'0'*64,'c09-barrier-page:'+'0'*48)).encode())
        if page_bytes+record_bytes>16384:break
        page_bytes+=record_bytes
        key=AtomKey.from_token(member[4]);a=meter.read_fixed_row(db,'graph_atoms',('value',),'token=?',(key.token,))
        access_value=json.loads(a[0]);validate_access(access_value)
        reads.extend((GraphVersion(AtomKey.from_token(member[0]),member[2]),GraphVersion(key,member[5]),
                      GraphVersion(AtomKey.from_token(member[7]),member[8])))
        writes.append(GraphWrite(key,{**access_value,'status':'withdrawn'}));members.append(member);last=row[0]
    if not writes:return None
    ordinal=state['barrier_pages'];event_id='c09-barrier-page:'+canonical_digest((namespace,operation_id,state['plan_digest'],ordinal))[:48]
    event=Event(Scope(*namespace.as_tuple,_BARRIER_SESSION),event_id,0.0,'source_access_withdrawn',
        {'operation_id':operation_id,'pending_receipt_digest':state['pending_digest'],'plan_digest':state['plan_digest'],
         'page_index':ordinal,'member_commitments':[canonical_digest(m) for m in members]})
    epoch=NamespaceEpoch(*namespace.as_tuple,state['current_stamp']['graph_epoch'])
    return GraphCandidate(event,tuple(sorted({v.key:v for v in reads}.values(),key=lambda x:x.key.token)),tuple(writes),(epoch,)),tuple(members)


def record_c09_source_barrier_page_after_graph_v2(db,*,namespace,operation_id,members,graph_receipt,budget):
    from ..graph_types import GraphReceipt
    state=read_c09_source_work_v2(db,namespace,operation_id);before=state['current_stamp'];scope=_scope(namespace,operation_id)
    if (not db.in_transaction or type(graph_receipt) is not GraphReceipt or graph_receipt.status!='committed'
            or graph_receipt.epoch.revision!=before['graph_epoch']+1 or not 1<=len(members)<=64):
        raise C09PagedCaptureHold('Source page lacks actual committed bounded Graph CAS')
    meter=_source_meter_v2(budget);ordinal=state['barrier_pages'];event_id='c09-barrier-page:'+canonical_digest((namespace,operation_id,state['plan_digest'],ordinal))[:48]
    event=db.execute('SELECT digest,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',(*namespace.as_tuple,_BARRIER_SESSION,event_id)).fetchone()
    expected={AtomKey.from_token(m[4]):m[5]+1 for m in members}
    if event is None or event[2]!=graph_receipt.epoch.revision or {v.key:v.revision for v in graph_receipt.revisions}!=expected:
        raise C09PagedCaptureHold('Source page Graph event/writes differ')
    root=state['barrier_root'];offset=state['barrier_count'];records=[]
    for member in members:
        access=member[4];actual=meter.read_fixed_row(db,'graph_atoms',('revision','value','valid'),'token=?',(access,))
        old=meter.read_fixed_row(db,'graph_history',('value','valid'),'token=? AND revision=?',(access,member[5]))
        current=json.loads(actual[1]);prior=json.loads(old[0])
        if actual[0]!=member[5]+1 or actual[2]!=1 or old[1]!=1 or current!={**prior,'status':'withdrawn'}:
            raise C09PagedCaptureHold('Source page did not exclusively withdraw its exact access originals')
        record=(member[0],member[2],member[3],access,member[5],actual[0],canonical_digest(current),event_id)
        state['barrier_count']+=1;root=canonical_digest(('c09.withdrawn-record.v2',state['barrier_count'],root,record));records.append(record)
        meter.charge_write(len(canonical_serialize(record).encode()))
        db.execute('UPDATE graph_c09_source_members_v2 SET withdrawn_page=?,withdrawn_revision=? WHERE bot=? AND persona=? AND operation_id=? AND source_ref=?',
                   (ordinal,actual[0],*scope,member[0]))
    after={**before,'graph_epoch':before['graph_epoch']+1,'access_epoch':before['access_epoch']+1,
           'delete_epoch':before['delete_epoch']+(1 if ordinal==0 else 0)}
    changed=db.execute('UPDATE graph_authority_epochs SET access_epoch=?,delete_epoch=? WHERE bot=? AND persona=? AND access_epoch=? AND delete_epoch=?',
        (after['access_epoch'],after['delete_epoch'],*namespace.as_tuple,before['access_epoch'],before['delete_epoch'])).rowcount
    if changed!=1:raise C09PagedCaptureHold('Source page exact rights CAS failed')
    values=dict(namespace=namespace,operation_id=operation_id,plan_digest=state['plan_digest'],pending_receipt_digest=state['pending_digest'],
        permit_digest=state['permit_digest'],page_index=ordinal,previous_page_digest=state['barrier_page_root'],record_offset=offset,
        record_count=len(records),records_root=root,last_source_ref=members[-1][0],
        graph_epoch_before=before['graph_epoch'],graph_epoch_after=after['graph_epoch'],access_epoch_before=before['access_epoch'],access_epoch_after=after['access_epoch'],
        delete_epoch_before=before['delete_epoch'],delete_epoch_after=after['delete_epoch'],event_id=event_id,event_digest=event[0],
        graph_receipt_digest=canonical_digest(graph_receipt),schema='sylanne3.graph.c09_source_barrier_page.v2')
    values['page_digest']=canonical_digest({**values,'namespace':asdict(namespace)});page=C09GraphBarrierPageV2(**values)
    descriptor=canonical_serialize(asdict(page));payload=canonical_serialize(records);meter.charge_write(len(descriptor.encode())+len(payload.encode()))
    db.execute('INSERT INTO graph_c09_source_pages_v2 VALUES(?,?,?,?,?,?,?)',(*scope,'barrier',ordinal,descriptor,payload))
    state.update(current_stamp=after,barrier_last=members[-1][0],barrier_root=root,barrier_pages=ordinal+1,barrier_page_root=page.page_digest)
    require_c09_source_stamp_v2(db,namespace,state);_save(db,namespace,operation_id,state,meter);return page


def advance_c09_source_barrier_completion_v2(db,*,namespace,operation_id,plan,budget):
    """Independent withdrawn-history sweep; no caller count or EOF assertions."""
    state=read_c09_source_work_v2(db,namespace,operation_id);require_c09_source_stamp_v2(db,namespace,state)
    if state['phase'] not in ('barrier','verify','verify_chain','barrier_complete'):raise C09PagedCaptureHold('Source barrier completion stage differs')
    if state['phase']=='barrier':
        remaining=db.execute('SELECT source_ref FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND affected=1 AND source_ref>? ORDER BY source_ref LIMIT 1',(*_scope(namespace,operation_id),state['barrier_last'])).fetchone()
        if remaining is not None:return None
        state['phase']='verify'
    meter=_source_meter_v2(budget);start=monotonic_ns();count=0;scope=_scope(namespace,operation_id)
    while state['phase']=='verify' and count<min(64,budget.max_records) and monotonic_ns()-start<budget.max_local_ns and meter.available_bytes>98304:
        row=db.execute('SELECT '+','.join(_MEMBER_COLUMNS)+',withdrawn_page,withdrawn_revision FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND affected=1 AND source_ref>? ORDER BY source_ref LIMIT 1',(*scope,state['verify_last'])).fetchone()
        if row is None:
            if state['verify_count']!=plan.descendant_count or state['verify_count']!=state['barrier_count'] or state['verify_root']!=state['barrier_root']:
                raise C09PagedCaptureHold('Source barrier real EOF/count/root differs')
            state['phase']='verify_chain';break
        if row[10] is None or row[11]!=row[5]+1:raise C09PagedCaptureHold('Source barrier missing actual access page')
        page_row=meter.read_fixed_row(db,'graph_c09_source_pages_v2',('descriptor_json','records_json'),"bot=? AND persona=? AND operation_id=? AND stream_kind='barrier' AND page_index=?",(*scope,row[10]))
        page=C09GraphBarrierPageV2.from_wire(json.loads(page_row[0]));records=json.loads(page_row[1])
        actual=meter.read_fixed_row(db,'graph_atoms',('revision','value','valid'),'token=?',(row[4],))
        event=db.execute('SELECT digest FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',(*namespace.as_tuple,_BARRIER_SESSION,page.event_id)).fetchone()
        history=meter.read_fixed_row(db,'graph_history',('value','valid'),'token=? AND revision=? AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?',(row[4],row[11],*namespace.as_tuple,_BARRIER_SESSION,page.event_id))
        record=(row[0],row[2],row[3],row[4],row[5],row[11],canonical_digest(json.loads(actual[1])),page.event_id)
        if actual[0]!=row[11] or actual[2]!=1 or history!=(actual[1],1) or event!=(page.event_digest,) or list(record) not in records:
            raise C09PagedCaptureHold('Source barrier current withdrawn head lacks exact page/event/history membership')
        state['verify_count']+=1;state['verify_root']=canonical_digest(('c09.withdrawn-record.v2',state['verify_count'],state['verify_root'],record));state['verify_last']=row[0];count+=1
    if state['phase']=='verify_chain' and meter.available_bytes>98304:
        page_row=meter.read_fixed_row(db,'graph_c09_source_pages_v2',('descriptor_json','records_json'),
            "bot=? AND persona=? AND operation_id=? AND stream_kind='barrier' AND page_index=?",(*scope,state['verify_page_index']))
        if page_row is None:
            if (state['verify_page_index']!=state['barrier_pages'] or state['verify_page_root']!=state['barrier_page_root']
                    or state['verify_chain_count']!=state['verify_count'] or state['verify_chain_root']!=state['verify_root']):
                raise C09PagedCaptureHold('independent Source barrier page chain/count/EOF mismatch')
            state['phase']='barrier_complete'
        else:
            page=C09GraphBarrierPageV2.from_wire(json.loads(page_row[0]));records=json.loads(page_row[1])
            initial=state['initial_stamp'];index=state['verify_page_index']
            if (page.page_index!=index or page.previous_page_digest!=state['verify_page_root']
                    or page.record_offset!=state['verify_chain_count'] or page.record_count!=len(records)
                    or page.plan_digest!=state['plan_digest'] or page.pending_receipt_digest!=state['pending_digest']
                    or page.permit_digest!=state['permit_digest']
                    or page.graph_epoch_before!=initial['graph_epoch']+index
                    or page.access_epoch_before!=initial['access_epoch']+index
                    or page.delete_epoch_before!=initial['delete_epoch']+(1 if index else 0)):
                raise C09PagedCaptureHold('actual Source barrier page/epochs do not continue this pending')
            for record in records:
                if type(record) is not list or len(record)!=8 or record[0]<=state['verify_chain_last'] or record[7]!=page.event_id:
                    raise C09PagedCaptureHold('actual Source barrier original member order/identity differs')
                state['verify_chain_count']+=1
                state['verify_chain_root']=canonical_digest(('c09.withdrawn-record.v2',state['verify_chain_count'],state['verify_chain_root'],tuple(record)))
                state['verify_chain_last']=record[0]
            if state['verify_chain_root']!=page.records_root or state['verify_chain_last']!=page.last_source_ref:
                raise C09PagedCaptureHold('actual Source barrier page payload root differs')
            state['verify_page_root']=page.page_digest;state['verify_page_index']+=1
    _save(db,namespace,operation_id,state,meter)
    if state['phase']!='barrier_complete':return None
    initial=state['initial_stamp'];after=state['current_stamp']
    values=dict(namespace=namespace,operation_id=operation_id,request_digest=state['pending_request_digest'],pending_receipt_digest=state['pending_digest'],
        plan_digest=plan.digest,closure_digest=state['closure_digest'],root_source_ref=plan.source_ref,graph_incarnation=plan.graph_incarnation,
        graph_epoch_before=initial['graph_epoch'],graph_epoch_after=after['graph_epoch'],access_epoch_before=initial['access_epoch'],access_epoch_after=after['access_epoch'],
        delete_epoch_before=initial['delete_epoch'],delete_epoch_after=after['delete_epoch'],affected_count=plan.descendant_count,affected_root=plan.descendant_root,
        withdrawn_count=state['verify_count'],withdrawn_root=state['verify_root'],page_count=state['barrier_pages'],page_root=state['barrier_page_root'],
        eof_count_digest=canonical_digest(('c09.withdrawn-eof.v2',state['verify_count'],state['verify_root'])),schema='sylanne3.graph.c09_erasure_barrier.v2')
    values['receipt_digest']=canonical_digest({**values,'namespace':asdict(namespace)});return C09GraphBarrierReceiptV2(**values)


_VIEW_KEY=object()


class C09SourceBarrierVerificationV2:
    """Bounded independent verification continuation, never an authorization."""
    __slots__=('db','receipt','session','page_index','previous_root','ordinal','record_root','last_ref','complete','_key')
    def __init__(self,key,db,receipt,session):
        from ..authority_service.c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
        if key is not _VIEW_KEY or type(session) is not C09PagedCaptureSessionV2:
            raise TypeError('actual installed C09 session and barrier verifier factory required')
        scope=session.require_current()
        if (scope.graph_namespace!=canonical_serialize(receipt.namespace.as_tuple) or scope.operation_id!=receipt.operation_id
                or scope.barrier_digest!=receipt.digest):raise C09PagedCaptureHold('actual C09 session does not bind this Source barrier')
        self.db,self.receipt,self.session,self._key=db,receipt,session,key
        self.page_index=0;self.ordinal=0;self.last_ref='';self.complete=False
        self.previous_root=canonical_digest(('c09.barrier-pages.v2',receipt.plan_digest,receipt.pending_receipt_digest))
        self.record_root=canonical_digest(('c09.withdrawn-records.v2',receipt.plan_digest,receipt.pending_receipt_digest))

    def require_current(self):
        scope=self.session.require_current()
        if (not self.db.in_transaction or scope.barrier_digest!=self.receipt.digest
                or scope.graph_namespace!=canonical_serialize(self.receipt.namespace.as_tuple) or scope.operation_id!=self.receipt.operation_id):
            raise C09PagedCaptureHold('Source barrier view left its current frozen session/read transaction')
        return scope


def begin_verify_c09_source_barrier_v2(db,*,session):
    from .c09_erasure_barrier_store_v1 import read_c09_erasure_barrier_v2
    from ..authority_service.c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    if type(session) is not C09PagedCaptureSessionV2:raise TypeError('actual installed C09 capture session required')
    scope=session.require_current();raw=json.loads(scope.graph_namespace)
    if type(raw) is not list or len(raw)!=2 or canonical_serialize(raw)!=scope.graph_namespace:
        raise C09PagedCaptureHold('actual Source barrier session Graph namespace wire differs')
    namespace=NamespaceId(*raw);receipt=read_c09_erasure_barrier_v2(db,namespace,scope.operation_id)
    if receipt is None:raise C09PagedCaptureHold('actual complete V2 Source barrier absent')
    return C09SourceBarrierVerificationV2(_VIEW_KEY,db,receipt,session)


def advance_verify_c09_source_barrier_v2(view,*,budget):
    """Whole-chain read, yielding after one bounded original page/quantum."""
    if type(view) is not C09SourceBarrierVerificationV2:raise TypeError('actual opaque Source verifier required')
    view.require_current();receipt=view.receipt;db=view.db;scope=_scope(receipt.namespace,receipt.operation_id)
    if view.complete:return view
    meter=_source_meter_v2(budget)
    row=meter.read_fixed_row(db,'graph_c09_source_pages_v2',('descriptor_json','records_json'),
        'bot=? AND persona=? AND operation_id=? AND stream_kind=? AND page_index=?',(*scope,'barrier',view.page_index))
    if row is None:
        if (view.page_index!=receipt.page_count or view.ordinal!=receipt.withdrawn_count
                or view.record_root!=receipt.withdrawn_root or view.previous_root!=receipt.page_root):
            raise C09PagedCaptureHold('V2 Source barrier true EOF/count/root mismatch')
        view.complete=True;return view
    page=C09GraphBarrierPageV2.from_wire(json.loads(row[0]));records=json.loads(row[1])
    if (page.page_index!=view.page_index or page.previous_page_digest!=view.previous_root
            or page.record_offset!=view.ordinal or len(records)!=page.record_count
            or page.plan_digest!=receipt.plan_digest or page.pending_receipt_digest!=receipt.pending_receipt_digest
            or page.graph_epoch_before!=receipt.graph_epoch_before+view.page_index
            or page.access_epoch_before!=receipt.access_epoch_before+view.page_index
            or page.delete_epoch_before!=receipt.delete_epoch_before+(1 if view.page_index else 0)):
        raise C09PagedCaptureHold('V2 Source barrier page continuity changed')
    event=db.execute('SELECT digest FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',
        (*receipt.namespace.as_tuple,_BARRIER_SESSION,page.event_id)).fetchone()
    if event!=(page.event_digest,):raise C09PagedCaptureHold('Source barrier actual Graph event missing')
    ordinal,record_root,last_ref=view.ordinal,view.record_root,view.last_ref
    for record in records:
        if type(record) is not list or len(record)!=8 or record[0]<=last_ref or record[7]!=page.event_id:
            raise C09PagedCaptureHold('Source barrier original member ordering/fields changed')
        source,source_rev,source_digest,access,before_revision,after_revision,digest,event_id=record
        key=AtomKey.from_token(source)
        if key!=source_key(*receipt.namespace.as_tuple,key.owner.subject) or access!=access_key(*receipt.namespace.as_tuple,key.owner.subject).token:
            raise C09PagedCaptureHold('Source barrier member crossed namespace')
        source_head=meter.read_fixed_row(db,'graph_atoms',('revision','valid'),'token=?',(source,))
        if source_head!=(source_rev,1):raise C09PagedCaptureHold('Source barrier root member actual Source head changed')
        atom=meter.read_fixed_row(db,'graph_atoms',('revision','value','valid'),'token=?',(access,))
        old=meter.read_fixed_row(db,'graph_history',('value','valid'),'token=? AND revision=?',(access,before_revision))
        history=meter.read_fixed_row(db,'graph_history',('value','valid'),'token=? AND revision=? AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?',
            (access,after_revision,*receipt.namespace.as_tuple,_BARRIER_SESSION,event_id))
        if (atom is None or atom[0]!=after_revision or atom[2]!=1 or history!=(atom[1],1) or old is None or old[1]!=1
                or json.loads(atom[1])!={**json.loads(old[0]),'status':'withdrawn'} or canonical_digest(json.loads(atom[1]))!=digest):
            raise C09PagedCaptureHold('Source barrier member does not match actual withdrawn history')
        ordinal+=1;record_root=canonical_digest(('c09.withdrawn-record.v2',ordinal,record_root,tuple(record)));last_ref=source
    if record_root!=page.records_root:raise C09PagedCaptureHold('Source barrier page record root differs')
    view.ordinal,view.record_root,view.last_ref=ordinal,record_root,last_ref
    view.previous_root=page.page_digest;view.page_index+=1;return None


def next_c09_barrier_source_member_v2(view,after_source_ref,*,budget):
    """One actual sealed structural member; the locator never grants permission."""
    if type(view) is not C09SourceBarrierVerificationV2 or not view.complete:
        raise C09PagedCaptureHold('complete independently verified Source barrier view required')
    view.require_current();r=view.receipt;meter=_source_meter_v2(budget)
    row=meter.read_fixed_row(view.db,'graph_c09_source_members_v2',('source_ref','source_revision','source_digest','withdrawn_page'),
        'bot=? AND persona=? AND operation_id=? AND affected=1 AND source_ref>? ORDER BY source_ref',(*_scope(r.namespace,r.operation_id),after_source_ref))
    if row is None:return None
    page_row=meter.read_fixed_row(view.db,'graph_c09_source_pages_v2',('descriptor_json','records_json'),
        'bot=? AND persona=? AND operation_id=? AND stream_kind=? AND page_index=?',(*_scope(r.namespace,r.operation_id),'barrier',row[3]))
    page=C09GraphBarrierPageV2.from_wire(json.loads(page_row[0]));records=json.loads(page_row[1]);matches=[(i,x) for i,x in enumerate(records) if x[0]==row[0]]
    if len(matches)!=1 or page.plan_digest!=r.plan_digest or page.pending_receipt_digest!=r.pending_receipt_digest:
        raise C09PagedCaptureHold('Source member locator has no actual verified page membership')
    index,record=matches[0]
    if (record[1],record[2])!=(row[1],row[2]):raise C09PagedCaptureHold('Source member index differs from original')
    return {'source_ref':row[0],'source_revision':row[1],'source_digest':row[2],
            'page_index':page.page_index,'record_ordinal':page.record_offset+index+1,'record_commitment':canonical_digest(tuple(record)),
            'barrier_digest':r.digest,'pending_receipt_digest':r.pending_receipt_digest}


def bind_c09_barrier_recovery_after_v2(db,*,namespace,operation_id,pending,before_metadata,after_metadata,budget):
    """Only the actual final pending-anchor CAS may replace recovery metadata."""
    from dataclasses import replace
    from ..graph_store import GraphStore
    state=read_c09_source_work_v2(db,namespace,operation_id)
    if (state is None or state['phase']!='barrier_complete'
            or state['pending_digest']!=canonical_digest(pending)):
        raise C09PagedCaptureHold('complete same-pending Source barrier required before recovery CAS')
    before=before_metadata.requirements;anchor=pending.after_anchor
    expected=replace(before,deletion_seq=anchor.deletion_seq,deletion_digest=anchor.deletion_digest,revocation_epoch=anchor.revocation_epoch)
    if (after_metadata.requirements!=expected or after_metadata.graph_revision!=before_metadata.graph_revision+1
            or state['current_stamp']['recovery_basis_digest']!=canonical_digest((GraphStore._recovery_payload(before),before_metadata.graph_revision))):
        raise C09PagedCaptureHold('recovery update is not the exact same-pending metadata CAS')
    current=source_plan_current_stamp_v2(db,namespace)
    if any(current[k]!=state['current_stamp'][k] for k in ('graph_epoch','access_epoch','delete_epoch')):
        raise C09PagedCaptureHold('recovery CAS also changed unrelated Source epochs')
    state['current_stamp']=current;state['recovery_closed']=True
    _save(db,namespace,operation_id,state,_source_meter_v2(budget))
    return state


@dataclass(frozen=True,slots=True)
class C09GraphInvalidationPageV2:
    namespace: NamespaceId
    operation_id: str
    plan_digest: str
    pending_receipt_digest: str
    permit_digest: str
    page_index: int
    previous_page_digest: str
    record_offset: int
    record_count: int
    records_root: str
    graph_epoch_before: int
    graph_epoch_after: int
    access_epoch: int
    delete_epoch: int
    event_id: str
    event_digest: str
    graph_receipt_digest: str
    page_digest: str
    schema: str='sylanne3.graph.c09_invalidation_page.v2'

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.schema!='sylanne3.graph.c09_invalidation_page.v2'
                or not 1<=self.record_count<=64 or self.graph_epoch_after!=self.graph_epoch_before+1):
            raise ValueError('actual bounded C09 invalidation Graph page required')
        if self.page_digest!=canonical_digest({k:v for k,v in asdict(self).items() if k!='page_digest'}):
            raise ValueError('C09 invalidation page wire digest differs')

    @classmethod
    def from_wire(cls,raw):
        from dataclasses import fields
        if type(raw) is not dict or set(raw)!={f.name for f in fields(cls)}:raise ValueError('C09 invalidation page wire fields differ')
        return cls(**{**raw,'namespace':NamespaceId(**raw['namespace'])})


def begin_c09_invalidation_frontier_v2(db,*,namespace,operation_id,budget):
    state=read_c09_source_work_v2(db,namespace,operation_id);require_c09_source_stamp_v2(db,namespace,state)
    if state['phase']!='barrier':raise C09PagedCaptureHold('actual Source withdrawal stage required')
    remaining=db.execute('SELECT 1 FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND affected=1 AND withdrawn_page IS NULL LIMIT 1',_scope(namespace,operation_id)).fetchone()
    if remaining is not None:raise C09PagedCaptureHold('all actual access withdrawal pages must precede invalidation')
    state.update(phase='invalidation_seed',invalidation_seed_last='',invalidation_seed_count=0,
        invalidation_frontier_count=0,invalidation_frontier_root=canonical_digest(('c09.invalidation-frontier.v2',state['plan_digest'],state['pending_digest'])),
        invalidation_discovery_count=0,invalidation_discovery_root=canonical_digest(('c09.invalidation-edges.v2',state['plan_digest'],state['pending_digest'])),
        invalidation_pages=0,invalidation_page_root=canonical_digest(('c09.invalidation-pages.v2',state['plan_digest'],state['pending_digest'])),
        invalidation_count=0,invalidation_root=canonical_digest(('c09.invalidation-records.v2',state['plan_digest'],state['pending_digest'])),
        invalidation_verify_last='',invalidation_verify_count=0,invalidation_verify_root=canonical_digest(('c09.invalidation-records.v2',state['plan_digest'],state['pending_digest'])))
    _save(db,namespace,operation_id,state,_source_meter_v2(budget));return state


def _insert_c09_invalidation_frontier_v2(db,namespace,operation_id,state,token,meter):
    key=AtomKey.from_token(token)
    if (key.owner.bot,key.owner.persona)!=namespace.as_tuple:raise C09PagedCaptureHold('actual Graph reverse dependency crossed namespace')
    meter.charge_write(len(token.encode()))
    changed=db.execute('INSERT INTO graph_c09_source_invalidation_v2(bot,persona,operation_id,token) VALUES(?,?,?,?) ON CONFLICT DO NOTHING',(*_scope(namespace,operation_id),token)).rowcount
    if changed:
        state['invalidation_frontier_count']+=1
        state['invalidation_frontier_root']=canonical_digest(('c09.invalidation-frontier-member.v2',state['invalidation_frontier_count'],state['invalidation_frontier_root'],token))


def advance_c09_invalidation_frontier_v2(db,*,namespace,operation_id,budget):
    """One indexed Source seed/reverse-edge at a time, no closure set/fetchall."""
    state=read_c09_source_work_v2(db,namespace,operation_id);require_c09_source_stamp_v2(db,namespace,state)
    if state['phase'] not in ('invalidation_seed','invalidation_expand','invalidation_apply'):
        raise C09PagedCaptureHold('actual invalidation frontier cannot resume in this stage')
    meter=_source_meter_v2(budget);scope=_scope(namespace,operation_id);started=monotonic_ns();records=0
    while records<min(64,budget.max_records) and monotonic_ns()-started<budget.max_local_ns and meter.available_bytes>65536:
        if state['phase']=='invalidation_seed':
            row=meter.read_fixed_row(db,'graph_c09_source_members_v2',('source_ref','access_ref'),
                'bot=? AND persona=? AND operation_id=? AND affected=1 AND source_ref>? ORDER BY source_ref',(*scope,state['invalidation_seed_last']))
            if row is None:
                if state['invalidation_seed_count']!=state['barrier_count']:raise C09PagedCaptureHold('actual invalidation Source seed EOF/count differs')
                state['phase']='invalidation_expand';continue
            _insert_c09_invalidation_frontier_v2(db,namespace,operation_id,state,row[1],meter)
            state['invalidation_seed_last']=row[0];state['invalidation_seed_count']+=1;records+=1
        elif state['phase']=='invalidation_expand':
            parent=meter.read_fixed_row(db,'graph_c09_source_invalidation_v2',('token','last_child'),
                'bot=? AND persona=? AND operation_id=? AND expanded=0 ORDER BY token',scope)
            if parent is None:
                state['phase']='invalidation_apply';break
            edge=meter.read_fixed_row(db,'graph_dependencies',('dependent_token','dependency_revision'),
                'dependency_token=? AND dependent_token>? ORDER BY dependent_token',(parent[0],parent[1]))
            if edge is None:
                meter.charge_write(len(parent[0].encode()))
                db.execute('UPDATE graph_c09_source_invalidation_v2 SET expanded=1 WHERE bot=? AND persona=? AND operation_id=? AND token=?',(*scope,parent[0]));records+=1;continue
            _insert_c09_invalidation_frontier_v2(db,namespace,operation_id,state,edge[0],meter)
            meter.charge_write(len(edge[0].encode()))
            db.execute('UPDATE graph_c09_source_invalidation_v2 SET last_child=? WHERE bot=? AND persona=? AND operation_id=? AND token=?',(edge[0],*scope,parent[0]))
            state['invalidation_discovery_count']+=1
            state['invalidation_discovery_root']=canonical_digest(('c09.invalidation-edge.v2',state['invalidation_discovery_count'],state['invalidation_discovery_root'],parent[0],edge[0],edge[1]))
            records+=1
        else:break
    _save(db,namespace,operation_id,state,meter);return state


def read_c09_next_invalidation_target_v2(db,*,namespace,operation_id,after_token,budget):
    """A fixed locator, never a mutation or a giant history materialization."""
    state=read_c09_source_work_v2(db,namespace,operation_id);require_c09_source_stamp_v2(db,namespace,state)
    if state['phase']!='invalidation_apply':raise C09PagedCaptureHold('actual dependency discovery has not reached EOF')
    meter=_source_meter_v2(budget);scope=_scope(namespace,operation_id)
    row=meter.read_fixed_row(db,'graph_c09_source_invalidation_v2',('token',),
        'bot=? AND persona=? AND operation_id=? AND applied=0 AND token>? ORDER BY token',(*scope,after_token))
    if row is None:return None
    # All planned access writes are replacements, not invalidations, exactly as
    # the old closure-minus-write_tokens semantics of a combined candidate.
    replacement=db.execute('SELECT 1 FROM graph_c09_source_members_v2 WHERE bot=? AND persona=? AND operation_id=? AND affected=1 AND access_ref=? LIMIT 1',(*scope,row[0])).fetchone()
    head=meter.read_fixed_row(db,'graph_atoms',('revision','valid'),'token=?',(row[0],))
    return {'token':row[0],'replacement':replacement is not None,'before_revision':None if head is None else head[0],
        'currently_valid':head is not None and head[1]==1,'plan_digest':state['plan_digest'],'pending_receipt_digest':state['pending_digest']}
