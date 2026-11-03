"""Private current role controls, complete value commitments and fixed Owner WRITE metadata."""
from dataclasses import asdict,dataclass,replace
from threading import get_ident
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphSnapshot,GraphVersion,OWNER_GRANT_TYPE
from ..runtime_contracts import canonical_digest
from .d01_ordinary_origin_stream_v3 import OrdinaryOriginMetadataStreamV3
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
ROLE_ROWS_SCHEMA_V4='d01.role-control-rows-metadata.v4'
_ROWS=WeakKeyDictionary()

@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class RoleControlRowsMetadataV4:
    namespace: object
    head_id: str
    plan_id: str
    plan_version: int
    authorization_revision: int
    rows: tuple
    schema: str = ROLE_ROWS_SCHEMA_V4


def _decode_control_rows_v4(raw):
    from ..graph_types import OWNER_GRANT_TYPE
    from ..runtime_contracts import NamespaceId
    import re
    if (type(raw)is not dict or set(raw)!={'schema','namespace','head_id','plan_id','plan_version','authorization_revision','rows'}
            or raw['schema']!=ROLE_ROWS_SCHEMA_V4 or type(raw['rows'])not in(list,tuple)or len(raw['rows'])!=3
            or type(raw['plan_version'])is not int or raw['plan_version']<1
            or raw['authorization_revision']!=1 or type(raw['authorization_revision'])is not int):
        raise AuthorityUnavailable('role-control rows metadata fields differ')
    namespace=NamespaceId(**raw['namespace'])
    if raw['head_id']!=raw['plan_id']+'@'+str(raw['plan_version']):
        raise AuthorityUnavailable('role-control rows head identity differs')
    for row,kind in zip(raw['rows'],('d01.persona_activation.v1','d01.persona_plan.v1',OWNER_GRANT_TYPE)):
        if (type(row)not in(list,tuple)or len(row)!=5 or type(row[1])is not int or row[1]<1
                or row[2]is not True or type(row[3])is not str or re.fullmatch('[0-9a-f]{64}',row[3])is None
                or type(row[4])is not dict):
            raise AuthorityUnavailable('role-control fixed row commitment differs')
        key=AtomKey.from_token(row[0])
        if key.type_name!=kind or NamespaceId.from_key(key)!=namespace:
            raise AuthorityUnavailable('role-control row family/namespace differs')
        if kind=='d01.persona_plan.v1'and (key.name!=raw['plan_id']or row[4]!={'namespace':asdict(namespace),'plan_id':raw['plan_id'],'version':raw['plan_version']}):
            raise AuthorityUnavailable('role-control plan metadata differs from its head')
    return raw


def role_control_background_plan_profile_v4(owner,table,column,key):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if (type(owner)is not BackgroundReadWorkV3 or owner.kind!='offline' or not owner.role_clocks
            or table!='graph_atoms' or column!='value' or AtomKey.from_token(key[0]).type_name!='d01.persona_plan.v1'):
        return False
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    return True


def current_role_control_rows_v4(reader,db,namespace,guard):
    from .domain_background_read_v3 import _active_v3,background_graph_head_v3,background_json_loads_v3
    from ..domains.d01 import PersonaDomain,_activation_key
    from ..graph_types import owner_grant_key
    owner=_active_v3(db)
    from .d06_ordinary_readout_v3 import _HOST,_AUTHORITY,_bound_life_control_owner_v4
    from ..runtime_storage_v3 import runtime_storage_v3,_operation
    active=_operation(runtime_storage_v3(db))
    life_candidates=tuple(item for item in (*_HOST.values(),*_AUTHORITY.values())if item.db is db and item.operation is active)
    life=_bound_life_control_owner_v4(db,namespace)if life_candidates else None
    registration=None
    if reader._selection_owner.get() is not None:
        registration=_OwnerWriteRoleControlsV4(reader,db,namespace,guard)
        role,epoch,registration_records=registration.complete_v4()
    elif life is not None:
        life.readout.require_current_v3();life.readout.selected_readout
        role=life.control;epoch=reader.graph._v2_graph_stamp(namespace)[1]
        actual=PersonaDomain.resolve_active_role_control_v3(GraphSnapshot(tuple(life.control_atoms),(epoch,)),namespace=namespace,current_guard=guard)
        if (actual.head_id,actual.plan_key,actual.plan_version,actual.authorization_revision)!=(role.head_id,role.plan_key,role.plan_version,role.authorization_revision):
            raise AuthorityUnavailable('Life selected role current Owner differs')
    elif owner is None:
        role,epoch,_activation=reader.graph._active_role_control_state_locked(namespace,guard)
    else:
        if reader not in owner.role_clocks:raise AuthorityUnavailable('role metadata reader differs from actual staged Work')
        activation_key=_activation_key(namespace);grant_key=owner_grant_key(*namespace.as_tuple)
        atoms=[]
        for key in(activation_key,grant_key):
            row=background_graph_head_v3(db,namespace,key)
            if row is None or row[2]!=1:raise AuthorityUnavailable('current role control is absent')
            atoms.append(GraphAtom(key,row[0],background_json_loads_v3(row[1]),True))
        epoch=reader.graph._v2_graph_stamp(namespace)[1]
        role=PersonaDomain.resolve_active_role_control_v3(GraphSnapshot(tuple(atoms),(epoch,)),namespace=namespace,current_guard=guard)
        plan=background_graph_head_v3(db,namespace,role.plan_key)
        value=background_role_plan_controls_v4(plan[1])if plan is not None else None
        if (plan is None or plan[2]!=1 or value.get('namespace')!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}
                or value.get('plan_id')!=role.plan_key.name or value.get('version')!=role.plan_version):
            raise AuthorityUnavailable('role plan control differs from activation')
        role=replace(role,read_versions=(GraphVersion(activation_key,atoms[0].revision),
            GraphVersion(role.plan_key,plan[0]),GraphVersion(grant_key,atoms[1].revision)))
        from .role_control_lineage_metadata_v4 import require_role_control_lineage_metadata_v4
        lineage=require_role_control_lineage_metadata_v4(owner,role)
        if (lineage.current.plan_value_digest!=plan[1].semantic_sha256
                or lineage.current.plan_ref!=role.read_versions[1]
                or lineage.current.activation_ref!=role.read_versions[0]):
            raise AuthorityUnavailable('Background current controls differ from their complete actual history')
    rows=[]
    from .d04_source_work_v3 import _BOUND as d04_bound
    d04=d04_bound.get()
    for version in role.read_versions:
        if registration is not None:
            _header,value,digest=registration_records[version.key]
        elif owner is not None:
            row=background_graph_head_v3(db,namespace,version.key)
            value=background_role_plan_controls_v4(row[1])if version.key==role.plan_key else background_json_loads_v3(row[1])
            digest=row[1].semantic_sha256
        elif life is not None:
            if version.key==role.plan_key:
                value={'namespace':{'bot_id':namespace.bot_id,'persona_id':namespace.persona_id},'plan_id':role.plan_key.name,'version':role.plan_version}
                digest=life.head.plan_value_digest
            else:
                atom=next(item for item in life.control_atoms if item.key==version.key)
                value=atom.value;digest=canonical_digest(value)
        elif d04 is not None:
            if version.key==role.plan_key:
                value={'namespace':{'bot_id':namespace.bot_id,'persona_id':namespace.persona_id},'plan_id':role.plan_key.name,'version':role.plan_version}
                digest=d04.head.plan_value_digest
            else:
                atom=d04.snapshot.get(version.key);value=atom.value;digest=canonical_digest(value)
        else:
            from .current_graph_full_read_v3 import read_bound_graph_full_role_control_v3
            from ..runtime_contracts import QueryEpoch
            full=read_bound_graph_full_role_control_v3(db,namespace,QueryEpoch(namespace,'all',epoch.revision),current_guard=guard)
            if full is None:raise AuthorityUnavailable('actual prepared role-control metadata is unavailable')
            item=next(item for item in full[2]if item.key==version.key)
            value=item.value;digest=item.whole_value_digest
        if version.key==role.plan_key:value={name:value[name]for name in('namespace','plan_id','version')}
        rows.append((version.key.token,version.revision,True,digest,value))
    metadata=RoleControlRowsMetadataV4(namespace,role.head_id,role.plan_key.name,role.plan_version,role.authorization_revision,tuple(rows))
    _ROWS[metadata]=(reader,db,role,_current_role_metadata_context_v4(reader,db),canonical_digest(metadata))
    return role,epoch,metadata


def background_role_plan_controls_v4(column):
    from .domain_background_read_v3 import BackgroundJSONColumnV3
    if (type(column)is not BackgroundJSONColumnV3 or not column.complete
            or not role_control_background_plan_profile_v4(column.owner,column.table,column.column,column.key)):
        raise AuthorityUnavailable('actual role-clock plan-control metadata EOF required')
    column._actual_v3()
    from .dispatch_current_inventory_v3 import _detach_value_v3
    return _detach_value_v3(column.frozen)


def role_control_background_value_commitment_v4(owner,table,column,key):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if (type(owner)is not BackgroundReadWorkV3 or owner.kind!='offline' or not owner.role_clocks
            or table!='graph_atoms' or column!='value'
            or AtomKey.from_token(key[0]).type_name not in {'d01.persona_plan.v1','d01.persona_activation.v1',OWNER_GRANT_TYPE}):
        return False
    require_actual_background_attachment_owner_v3(owner,db=owner.db)
    return True


class _OwnerWriteRoleControlsV4:
    """Fixed metadata on the original explicit Owner registration WRITE."""
    def __init__(self,reader,db,namespace,guard):
        from ..runtime_storage_v3 import runtime_storage_v3,_operation
        from ..host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
        if type(reader)is not InstalledD04SemanticMappingReaderV3:
            raise AuthorityUnavailable('actual installed Owner registration reader required')
        self.reader,self.db,self.namespace=reader,db,namespace
        self.graph=reader.graph;self.store=self.graph._GraphCoordinator__store
        self.scope,self.guard,self.profile=reader._current(db,namespace)
        self.principal=reader._selection_owner.get();self.location=reader._location.get()
        self.operation=_operation(runtime_storage_v3(db));self.thread=get_ident()
        self.stamp=self.graph._v2_graph_stamp(namespace);self.plan_key=None
        if (self.scope.operation!='write' or self.principal is None or self.guard!=guard
                or self.location is None or self.location.guard!=guard):
            raise AuthorityUnavailable('actual same Owner selection WRITE required')
        self.require_v4()
    def require_v4(self):
        from ..runtime_storage_v3 import runtime_storage_v3,_operation
        if (get_ident()!=self.thread or not self.db.in_transaction or not self.store._lock._is_owned()
                or self.reader._fence.get()!=(self.scope,self.guard,self.profile)
                or self.reader._selection_owner.get()!=self.principal or self.reader._location.get()!=self.location
                or self.graph._v2_graph_stamp(self.namespace)!=self.stamp
                or _operation(runtime_storage_v3(self.db))is not self.operation or self.operation.closed):
            raise AuthorityUnavailable('Owner role metadata left its original WRITE/operation/stamp')
    def read_v4(self,key=None):
        from ..domains.d01 import _activation_key
        from ..graph_types import owner_grant_key
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3,runtime_storage_quantum_v3
        self.require_v4();ns=self.namespace
        if key is None:
            table,column,keycols,args,profile='graph_role_init_receipts_v1','receipt_json',('bot','persona'),ns.as_tuple,'activation'
            where='bot=? AND persona=?';header=None
        else:
            if key not in (_activation_key(ns),owner_grant_key(*ns.as_tuple),self.plan_key):
                raise AuthorityUnavailable('Owner role metadata is outside its fixed active control keys')
            table,column,keycols,args='graph_atoms','value',('token','bot','persona'),(key.token,*ns.as_tuple)
            profile='plan'if key==self.plan_key else'activation';where='token=? AND bot=? AND persona=?'
            with runtime_storage_quantum_v3(self.db)as meter:
                header=meter.read_fixed_row(self.db,table,('revision','valid','value_cell_id'),where,args)
                if header is None or header[0]<1 or header[1]!=1:
                    raise AuthorityUnavailable('Owner active control current header is absent')
                cell=begin_runtime_cell_read_v3(self.db,header[2],erasure_owner_ref=key.token)
                if cell.header[0]not in ('canonical-json.ascii.v1','canonical-json.utf8.v1'):
                    raise AuthorityUnavailable('Owner control metadata has no registered canonical JSON codec')
        retained=0
        def reserve(extra=0):
            nonlocal retained
            from .source_correction_read_v3 import _heap
            amount=_heap((stream.nodes,stream.metadata,stream.fields,stream.scalar,stream.active_hashes,stream.commitments))+extra+131072
            if amount>retained:self.operation.retain(amount-retained);retained=amount
        stream=OrdinaryOriginMetadataStreamV3(profile=profile,ensure_ascii=header is None or cell.header[0]=='canonical-json.ascii.v1',reserve=reserve)
        offset=0;total=None
        while True:
            with runtime_storage_quantum_v3(self.db)as meter:
                self.require_v4()
                if header is not None:chunk=cell.read_fragment(meter=meter)
                elif total is None or offset<total:
                    chunk,size,kind=read_legacy_sql_cell_fragment_v2(self.db,table=table,column=column,where=where,
                        parameters=args,start=offset,length=16384 if total is None else min(16384,total-offset),meter=meter)
                    if total is None:total=size
                    if size!=total or kind!='text':raise AuthorityUnavailable('role initialization metadata column changed')
                    offset+=len(chunk)
                else:chunk=None
                if chunk is None or not chunk:break
                stream.advance_fragment_v3(chunk,meter)
        metadata,hashes,_ranges,_fields,parsed=stream.finish_metadata_v3()
        with runtime_storage_quantum_v3(self.db)as meter:
            self.require_v4()
            if header is not None:
                digest=cell.finish(meter=meter)
                if (digest,cell.header[3])!=(parsed.sha256,parsed.byte_count)or meter.read_fixed_row(
                        self.db,table,('revision','valid','value_cell_id'),where,args)!=header:
                    raise AuthorityUnavailable('Owner control origin/current header/canonical EOF changed')
            elif parsed.byte_count!=total:raise AuthorityUnavailable('role initialization metadata EOF changed')
        return header,metadata,hashes[()]
    def complete_v4(self):
        from ..domains.d01 import PersonaDomain,_activation_key
        from ..graph_types import owner_grant_key
        activation_key=_activation_key(self.namespace);grant_key=owner_grant_key(*self.namespace.as_tuple)
        records={}
        for key in (activation_key,grant_key):records[key]=self.read_v4(key)
        epoch=self.stamp[1]
        atoms=tuple(GraphAtom(key,records[key][0][0],records[key][1],True)for key in(activation_key,grant_key))
        role=PersonaDomain.resolve_active_role_control_v3(GraphSnapshot(atoms,(epoch,)),namespace=self.namespace,current_guard=self.guard)
        self.plan_key=role.plan_key;records[role.plan_key]=self.read_v4(role.plan_key)
        header,value,_digest=records[role.plan_key]
        if (value.get('namespace')!=asdict(self.namespace)or value.get('plan_id')!=role.plan_key.name
                or value.get('version')!=role.plan_version or type(value.get('authored'))is not bool):
            raise AuthorityUnavailable('Owner plan control differs from actual activation')
        role=replace(role,read_versions=tuple(GraphVersion(key,records[key][0][0])for key in(activation_key,role.plan_key,grant_key)))
        from .role_control_lineage_metadata_v4 import require_role_control_lineage_metadata_v4
        lineage=require_role_control_lineage_metadata_v4(self,role)
        if (lineage.current.plan_value_digest!=records[role.plan_key][2]
                or lineage.current.activation_value_digest!=records[activation_key][2]
                or lineage.current.plan_ref!=role.read_versions[1]
                or lineage.current.activation_ref!=role.read_versions[0]):
            raise AuthorityUnavailable('Owner current controls differ from their complete actual history')
        self.require_v4()
        return role,epoch,records


def _current_role_metadata_context_v4(reader,db):
    from .domain_background_read_v3 import _active_v3
    owner=_active_v3(db)
    if owner is not None:return ('background',owner,owner.work,owner.operation,owner.graph_stamp)
    from .d04_source_work_v3 import _BOUND as source_bound,require_installed_d04_source_reader_v3
    source=source_bound.get()
    if source is not None:
        require_installed_d04_source_reader_v3(source)
        return ('d04',source,source.work,source.operation,source.graph_stamp)
    from ..runtime_storage_v3 import runtime_storage_v3,_operation
    operation=_operation(runtime_storage_v3(db))
    from .d06_ordinary_readout_v3 import _HOST,_AUTHORITY,_bound_life_control_owner_v4
    candidates=tuple(owner for owner in (*_HOST.values(),*_AUTHORITY.values())if owner.db is db and owner.operation is operation)
    if candidates:
        owner=_bound_life_control_owner_v4(db,reader._fence.get()[0].namespace)
        return ('life',owner,owner.work,owner.operation)
    from .current_graph_full_read_v3 import _BOUND as full_bound
    bound=full_bound.get()
    if bound is not None:
        proof=bound[0];proof._actual()
        return ('full',proof.work,proof.operation,proof.selection_digest)
    scope,guard,_profile=reader._current(db,reader._fence.get()[0].namespace)
    principal=reader._selection_owner.get()
    if scope.operation!='write'or principal is None:
        raise AuthorityUnavailable('role-control metadata lost its actual originating Owner Work')
    return ('owner_write',reader,scope,guard,principal,operation)
