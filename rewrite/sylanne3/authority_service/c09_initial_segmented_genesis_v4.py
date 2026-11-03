"""Signed provenance and private proofs for explicit new empty Root segmented genesis."""
from __future__ import annotations
from pathlib import Path
from contextlib import closing
from weakref import WeakKeyDictionary,ref
import json,os,sqlite3
from .contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..segmented_sql_cell_v1 import LAYOUT_SCHEMA,LAYOUTS,LAYOUT_SCHEMA_DIGEST,DDLS,TRIGGERS

PLAN_SCHEMA_V4='sylanne3.c09.initial-segmented-genesis-plan.v4'
GENESIS_SCHEMA_V4='sylanne3.c09.initial-segmented-genesis.v4'
MANIFEST_SCHEMA_V4='sylanne3.c09.initial-segmented-storage-manifest.v4'
INITIAL_MANIFEST_SCHEMA_V4=MANIFEST_SCHEMA_V4
MANIFEST_SIGNATURE_DOMAIN_V4='sylanne3.c09.initial-segmented-manifest-signature.v4'
ROLES_V4=('core','deletion','execution','graph')
_ISSUER=object()
_PROOFS=WeakKeyDictionary()
_CONTEXTS=WeakKeyDictionary()


def _sha(value,label):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
        raise AuthorityUnavailable('exact initial segmented commitment required: '+label)
    return value


def require_initial_segmented_manifest_v4(manifest):
    fields={'schema','authority_id','installation_id','control_store_id','cohort_namespaces','generation',
        'prior_manifest_digest','members','inventory_manifest_digest','cumulative_tombstone_root','deletion_watermark',
        'segmented_layouts','initial_genesis_plan_digest','initial_genesis_original_digest','empty_business_eof_digest','manifest_digest'}
    from .c09_storage_control_v1 import _MEMBER_FIELDS,digest
    if (type(manifest)is not dict or set(manifest)!=fields or manifest['schema']!=MANIFEST_SCHEMA_V4
            or manifest['generation']!=0 or type(manifest['generation'])is not int
            or manifest['prior_manifest_digest']is not None or len(manifest['cohort_namespaces'])!=1
            or type(manifest['deletion_watermark'])is not int or manifest['deletion_watermark']!=0
            or manifest['manifest_digest']!=digest({k:v for k,v in manifest.items()if k!='manifest_digest'})
            or tuple(item['role']for item in manifest['members'])!=ROLES_V4
            or any(set(item)!=_MEMBER_FIELDS for item in manifest['members'])):
        raise AuthorityUnavailable('closed actual initial segmented manifest required')
    layouts=manifest['segmented_layouts']
    if type(layouts)is not dict or tuple(sorted(layouts))!=ROLES_V4:
        raise AuthorityUnavailable('initial segmented manifest requires its exact four actual layouts')
    for role in ROLES_V4:
        layout=layouts[role]
        if (type(layout)is not dict or set(layout)!={'layout_id','layout_schema_digest','storage_instance_id'}
                or layout['layout_id']!=LAYOUTS[role]or layout['layout_schema_digest']!=LAYOUT_SCHEMA_DIGEST):
            raise AuthorityUnavailable('initial segmented role differs from its actual registered codec')
        _sha(layout['storage_instance_id'],'storage_instance_id')
    for name in ('inventory_manifest_digest','cumulative_tombstone_root','initial_genesis_plan_digest',
            'initial_genesis_original_digest','empty_business_eof_digest','manifest_digest'):
        _sha(manifest[name],name)
    return manifest


class VerifiedInitialSegmentedStorageV4:
    """Cold-verifiable real initial layout, never a selected/PREPARED surrogate."""
    def __init__(self,issuer,*,control,plan,original,manifest):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual initial segmented Control issuer required')
        self.control,self.plan,self.original,self.manifest=control,plan,original,manifest
        self.namespace=NamespaceId(**plan['namespace'])
        self.authority_namespace=plan['authority_namespace']
        self.genesis_digest=original['genesis_digest']
        self.selection_digest=canonical_digest(('sylanne3.c09.initial-segmented-selection.v4',
            self.genesis_digest,manifest['manifest_digest'],0,0,self.namespace,control.authority_id,
            control.installation_id,control.control_store_id))
        from .c09_storage_control_v1 import VerifiedStorageOpenContextV1
        self.context=VerifiedStorageOpenContextV1(str(control.path),0,manifest['manifest_digest'],0,'READY',manifest,None,control,control._capability)
        _PROOFS[self]=(id(control),canonical_digest(plan),canonical_digest(original),canonical_digest(manifest),
            self.namespace,self.authority_namespace,self.genesis_digest,self.selection_digest)
        _CONTEXTS[self]=id(self.context)
    def member(self,role):
        if role not in ROLES_V4:raise AuthorityUnavailable('exact initial segmented role required')
        return next(item for item in self.manifest['members']if item['role']==role)
    def require_current(self,*,meter):
        from .c09_selected_history_v3 import _bounded
        if (_PROOFS.get(self)!=(id(self.control),canonical_digest(self.plan),canonical_digest(self.original),canonical_digest(self.manifest),
                self.namespace,self.authority_namespace,self.genesis_digest,self.selection_digest)
                or _CONTEXTS.get(self)!=id(self.context)):
            raise AuthorityUnavailable('initial segmented private proof changed')
        self.control.lease.require_held()
        require_initial_segmented_manifest_v4(self.manifest)
        self.control.verify_original_v1(self.original,'genesis_digest')
        with self.control._db()as raw:
            db=_bounded(raw,meter)
            chain=self.control._c09_control_chain_proof_v2
            current=chain.require_current(raw,meter)
            row=db.execute('SELECT genesis_digest,plan_digest,manifest_digest FROM c09_initial_segmented_genesis_v4 WHERE installation_id=?',
                (self.control.installation_id,)).fetchone()
            if (row!=(self.genesis_digest,self.plan['plan_digest'],self.manifest['manifest_digest'])
                    or (current['pointer_version'],current['current_manifest_digest'],current['active_operation_id'],current['stage'])!=
                        (0,self.manifest['manifest_digest'],None,'READY')):
                raise AuthorityUnavailable('initial segmented current Control/genesis point changed')
        for role in ROLES_V4:
            self.control.verify_member_v1(self.member(role),prepared=False)
        return self
    def require_layout(self,db,role,*,meter):
        from .c09_selected_history_v3 import _bounded
        member=self.member(role);layout=self.manifest['segmented_layouts'][role]
        source=_bounded(db,meter)
        rows=source.execute('PRAGMA database_list').fetchall()
        if len(rows)!=1 or rows[0][1]!='main'or Path(rows[0][2]).resolve()!=Path(member['resolved_path']).resolve():
            raise AuthorityUnavailable('initial runtime role is not its exact actual selected SQLite file')
        info=Path(member['resolved_path']).stat()
        if (info.st_dev,info.st_ino)!=(member['device'],member['file_id']):
            raise AuthorityUnavailable('initial segmented role file incarnation changed')
        expected=(1,LAYOUT_SCHEMA,layout['storage_instance_id'],role,LAYOUTS[role],LAYOUT_SCHEMA_DIGEST,
            self.control.authority_id,self.authority_namespace,self.control.installation_id,0,self.plan['plan_digest'])
        row=source.execute('SELECT * FROM segmented_storage_layout_v1 WHERE singleton=1').fetchone()
        if tuple(row or ())!=expected:
            raise AuthorityUnavailable('initial segmented role header/origin does not match its signed genesis plan')
        for name,ddl in {**DDLS,**TRIGGERS}.items():
            kind='table'if name in DDLS else'trigger'
            if source.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name)).fetchone()!=(ddl,):
                raise AuthorityUnavailable('initial segmented actual cell schema differs: '+name)
        return self


def _require_plan_v4(plan):
    fields={'schema','genesis_id','creation_nonce','authority_id','installation_id','control_store_id','namespace',
        'authority_namespace','root_startup_original','root_startup_digest','instance_lock_ref','role_paths',
        'role_storage_instance_ids','layout_schema_digest','catalogue_digest','plan_digest'}
    from ..runtime_contracts import namespace_ref
    if (type(plan)is not dict or set(plan)!=fields or plan['schema']!=PLAN_SCHEMA_V4
            or type(plan['namespace'])is not dict or namespace_ref(NamespaceId(**plan['namespace']))!=plan['authority_namespace']
            or plan['layout_schema_digest']!=LAYOUT_SCHEMA_DIGEST
            or plan['root_startup_digest']!=canonical_digest(plan['root_startup_original'])
            or plan['plan_digest']!=canonical_digest({k:v for k,v in plan.items()if k!='plan_digest'})
            or type(plan['role_paths'])is not dict or tuple(sorted(plan['role_paths']))!=ROLES_V4
            or type(plan['role_storage_instance_ids'])is not dict or tuple(sorted(plan['role_storage_instance_ids']))!=ROLES_V4
            or len(set(plan['role_paths'].values()))!=4 or len(set(plan['role_storage_instance_ids'].values()))!=4):
        raise AuthorityUnavailable('closed actual initial segmented genesis plan required')
    for name in ('authority_id','installation_id','control_store_id','genesis_id','creation_nonce','instance_lock_ref'):
        if type(plan[name])is not str or not plan[name]:raise AuthorityUnavailable('initial genesis plan identity is absent')
    for name in ('catalogue_digest','root_startup_digest','plan_digest'):_sha(plan[name],name)
    for role in ROLES_V4:_sha(plan['role_storage_instance_ids'][role],'role_instance')
    return plan


def _read_signed_initial_metadata_v4(control,db,meter):
    from .c09_selected_history_v3 import _bounded
    bounded=_bounded(db,meter)
    row=bounded.execute('SELECT genesis_json,genesis_digest,plan_digest,manifest_digest FROM c09_initial_segmented_genesis_v4 '
        'WHERE installation_id=?',(control.installation_id,)).fetchone()
    if row is None:raise AuthorityUnavailable('actual signed initial segmented genesis original is absent')
    original=json.loads(row[0]);control.verify_original_v1(original,'genesis_digest')
    fields={'schema','genesis_id','authority_id','installation_id','control_store_id','namespace','authority_namespace',
        'plan','plan_digest','initial_origin_scope_digest','role_originals','empty_business_eof','empty_business_eof_digest',
        'core_counter_empty_eof','key_id','genesis_digest','signature'}
    if (type(original)is not dict or set(original)!=fields or original['schema']!=GENESIS_SCHEMA_V4
            or (original['authority_id'],original['installation_id'],original['control_store_id'])!=
                (control.authority_id,control.installation_id,control.control_store_id)
            or original['genesis_digest']!=row[1]or original['plan_digest']!=row[2]
            or original['empty_business_eof_digest']!=canonical_digest(original['empty_business_eof'])):
        raise AuthorityUnavailable('actual initial segmented original has another immutable Control identity')
    plan=_require_plan_v4(original['plan'])
    if (original['plan_digest']!=plan['plan_digest']or original['initial_origin_scope_digest']!=plan['plan_digest']
            or original['genesis_id']!=plan['genesis_id']or original['namespace']!=plan['namespace']
            or original['authority_namespace']!=plan['authority_namespace']):
        raise AuthorityUnavailable('actual signed initial genesis differs from its pre-file origin plan')
    _require_compact_initial_empty_eof_v4(original,plan)
    manifest=control._read_manifest(bounded,row[3]);require_initial_segmented_manifest_v4(manifest)
    if (manifest['initial_genesis_original_digest']!=original['genesis_digest']
            or manifest['initial_genesis_plan_digest']!=plan['plan_digest']
            or manifest['empty_business_eof_digest']!=original['empty_business_eof_digest']
            or (manifest['authority_id'],manifest['installation_id'],manifest['control_store_id'])!=
                (control.authority_id,control.installation_id,control.control_store_id)
            or manifest['cohort_namespaces']!=[plan['authority_namespace']]):
        raise AuthorityUnavailable('actual initial signed manifest differs from its independently signed genesis')
    for role in ROLES_V4:
        member=next(item for item in manifest['members']if item['role']==role)
        if (member['resolved_path']!=plan['role_paths'][role]
                or manifest['segmented_layouts'][role]['storage_instance_id']!=plan['role_storage_instance_ids'][role]
                or original['role_originals'][role]['member']!=member):
            raise AuthorityUnavailable('actual signed initial role differs from its original creation instance')
    return plan,original,manifest


def read_initial_segmented_storage_v4(control,*,meter):
    """Cold read and verify persistent initial provenance; never recreates empty EOF."""
    with control._db()as db:
        current=control._c09_control_chain_proof_v2.require_current(db,meter)
        plan,original,manifest=_read_signed_initial_metadata_v4(control,db,meter)
    if ((current['stage'],current['pointer_version'],current['current_manifest_digest'],current['active_operation_id'])!=
            ('READY',0,manifest['manifest_digest'],None)):
        raise AuthorityUnavailable('ordinary initial storage requires its actual current READY zero point')
    prior=getattr(control,'_initial_segmented_storage_v4',None)
    if prior is not None:
        if (type(prior)is not VerifiedInitialSegmentedStorageV4 or prior.genesis_digest!=original['genesis_digest']
                or prior.manifest!=manifest):
            raise AuthorityUnavailable('initial segmented Control cannot replace its admitted immutable genesis')
        return prior.require_current(meter=meter)
    proof=VerifiedInitialSegmentedStorageV4(_ISSUER,control=control,plan=plan,original=original,manifest=manifest)
    for role in ROLES_V4:
        member=proof.member(role);control.verify_member_v1(member,prepared=False)
        with closing(sqlite3.connect(Path(member['resolved_path']).as_uri()+'?mode=ro',uri=True,isolation_level=None))as source:
            source.execute('PRAGMA query_only=ON');proof.require_layout(source,role,meter=meter)
    control._initial_segmented_storage_v4=proof
    return proof.require_current(meter=meter)


_PHYSICAL_VIEWS=WeakKeyDictionary()
_PHYSICAL_VIEW_CACHE_V4=WeakKeyDictionary()


class VerifiedInitialSegmentedPhysicalMetadataV4:
    def __init__(self,issuer,*,qualification,db,control,plan,original,manifest):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual initial C09 Source metadata issuer required')
        self._qualification,self._db=qualification,db
        self.control,self.plan,self.original,self.manifest=control,plan,original,manifest
        self.role=qualification.role;self.namespace=NamespaceId(**plan['namespace'])
        self.authority_namespace=plan['authority_namespace'];self.genesis_digest=original['genesis_digest']
        self.selection_digest=canonical_digest(('sylanne3.c09.initial-segmented-selection.v4',self.genesis_digest,
            manifest['manifest_digest'],0,0,self.namespace,control.authority_id,control.installation_id,control.control_store_id))
        self._heap=4096+len(canonical_serialize((plan,original,manifest)).encode())*8
        _PHYSICAL_VIEWS[self]=(id(qualification),id(db),id(control),canonical_digest(plan),canonical_digest(original),
            canonical_digest(manifest),self.role,self.genesis_digest,self.selection_digest)
        qualification.scope.arena.add(self)
    @property
    def qualification(self):return self._qualification
    @property
    def db(self):return self._db
    def _source_heap_bytes(self):return self._heap
    def member(self,role):
        if role!=self.role:raise AuthorityUnavailable('actual C09 Source metadata cannot borrow another role')
        return next(item for item in self.manifest['members']if item['role']==role)
    def require_current(self,*,db,meter):
        from .c09_source_physical_read_v3 import InitialPhysicalSourceReadQualificationV3,_INITIAL_PHYSICAL_SOURCE
        q=self.qualification
        if (type(q)is not InitialPhysicalSourceReadQualificationV3 or q not in _INITIAL_PHYSICAL_SOURCE
                or db is not self.db or db is not q.scope.pair.source or not db.in_transaction
                or _PHYSICAL_VIEWS.get(self)!=(id(q),id(db),id(self.control),canonical_digest(self.plan),
                    canonical_digest(self.original),canonical_digest(self.manifest),self.role,self.genesis_digest,self.selection_digest)):
            raise AuthorityUnavailable('initial physical metadata lost its actual same-session Source SQL binding')
        q.require_current(meter=meter)
        control=q.scope.session._control.maintenance.control
        current,intent=q.scope.session._control._current(q.scope.operation_id)
        if (control is not self.control or q.role!=self.role or current.stage!='INTENT'
                or current.pointer_version!=0 or current.storage_generation!=0
                or current.manifest_digest!=self.manifest['manifest_digest']or current.manifest!=self.manifest
                or q.initial_manifest_digest!=current.manifest_digest or q.initial_pointer!=0
                or intent['details']['old_manifest_digest']!=current.manifest_digest):
            raise AuthorityUnavailable('initial C09 physical metadata differs from its actual active INTENT/source selection')
        self.control.verify_original_v1(self.original,'genesis_digest')
        member=self.member(self.role);identity=json.loads(q.source_original.source_identity)
        if ((member['device'],member['file_id'])!=(identity['device'],identity['file_id'])
                or member['resolved_path']!=q.source_original.source_path):
            raise AuthorityUnavailable('actual initial C09 Source role is not its signed genesis file')
        from .c09_selected_history_v3 import _bounded
        bounded=_bounded(db,meter)
        layout=self.manifest['segmented_layouts'][self.role]
        row=bounded.execute('SELECT storage_instance_id,role,layout_id,layout_schema_digest,authority_id,authority_namespace,'
            'installation_id,storage_generation,origin_scope_digest FROM segmented_storage_layout_v1 WHERE singleton=1').fetchone()
        if row!=(layout['storage_instance_id'],self.role,LAYOUTS[self.role],LAYOUT_SCHEMA_DIGEST,
                control.authority_id,self.authority_namespace,control.installation_id,0,self.plan['plan_digest']):
            raise AuthorityUnavailable('actual initial Source layout/origin differs from its signed genesis')
        return self


def require_initial_segmented_physical_metadata_v4(qualification,*,db,meter):
    from .c09_source_physical_read_v3 import InitialPhysicalSourceReadQualificationV3,_INITIAL_PHYSICAL_SOURCE
    if (type(qualification)is not InitialPhysicalSourceReadQualificationV3 or qualification not in _INITIAL_PHYSICAL_SOURCE
            or db is not qualification.scope.pair.source or not db.in_transaction):
        raise AuthorityUnavailable('actual C09 initial physical Source metadata qualification required')
    qualification.require_current(meter=meter)
    saved=_PHYSICAL_VIEW_CACHE_V4.get(qualification)
    view=None if saved is None else saved()
    if view is not None:return view.require_current(db=db,meter=meter)
    control=qualification.scope.session._control.maintenance.control
    with control._db()as control_db:plan,original,manifest=_read_signed_initial_metadata_v4(control,control_db,meter)
    result=VerifiedInitialSegmentedPhysicalMetadataV4(_ISSUER,qualification=qualification,db=db,control=control,
        plan=plan,original=original,manifest=manifest)
    result.require_current(db=db,meter=meter)
    _PHYSICAL_VIEW_CACHE_V4[qualification]=ref(result)
    return result


INITIAL_GENESIS_DDL_V4="""CREATE TABLE c09_initial_segmented_genesis_v4(
 installation_id TEXT PRIMARY KEY,genesis_id TEXT NOT NULL UNIQUE,plan_digest TEXT NOT NULL,
 genesis_digest TEXT NOT NULL UNIQUE,manifest_digest TEXT NOT NULL UNIQUE,genesis_json TEXT NOT NULL) STRICT"""


def require_initial_genesis_control_schema_v4(control,db):
    table='c09_initial_segmented_genesis_v4'
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()!=(INITIAL_GENESIS_DDL_V4,):
        raise AuthorityUnavailable('actual initial genesis Control schema differs')
    for action in ('UPDATE','DELETE'):
        name=table+'_no_'+action.lower()
        if db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(name,)).fetchone()!=(control._immutable_ddl(table,action),):
            raise AuthorityUnavailable('actual initial genesis Control immutable original guard differs')


def has_current_initial_segmented_manifest_v4(control,*,meter):
    from .c09_selected_history_v3 import _bounded
    with control._db()as db:
        current=control._c09_control_chain_proof_v2.require_current(db,meter)
        row=_bounded(db,meter).execute("SELECT json_extract(manifest_json,'$.schema') FROM c09_storage_manifests_v1 "
            'WHERE manifest_digest=?',(current['current_manifest_digest'],)).fetchone()
    return row==(INITIAL_MANIFEST_SCHEMA_V4,)


def read_initial_segmented_context_v4(control,*,meter):
    from .c09_storage_control_v1 import VerifiedStorageOpenContextV1
    with control._db()as db:
        current=control._c09_control_chain_proof_v2.require_current(db,meter)
        _,_,manifest=_read_signed_initial_metadata_v4(control,db,meter)
    if (current['pointer_version']!=0 or current['current_manifest_digest']!=manifest['manifest_digest']):
        raise AuthorityUnavailable('initial metadata context is outside its actual zero storage point')
    if current['stage']=='READY':return read_initial_segmented_storage_v4(control,meter=meter).context
    if current['stage']not in ('INTENT','PREPARED')or not current['active_operation_id']:
        raise AuthorityUnavailable('initial storage metadata requires its exact active capture stage')
    return VerifiedStorageOpenContextV1(str(control.path),0,manifest['manifest_digest'],0,current['stage'],
        manifest,None,control,control._capability)


def require_initial_segmented_context_v4(control,context,*,action):
    from .c09_storage_control_v1 import VerifiedStorageOpenContextV1
    if (type(context)is not VerifiedStorageOpenContextV1 or context._reader is not control
            or context._capability is not control._capability or context.control_path!=str(control.path)
            or action not in ('maintenance','business','accounting','recovery')):
        raise AuthorityUnavailable('actual initial segmented Control context required')
    with control._resource_sql_quantum_v3()as meter:
        actual=read_initial_segmented_context_v4(control,meter=meter)
        if ((actual.pointer_version,actual.manifest_digest,actual.storage_generation,actual.stage)!=
                (context.pointer_version,context.manifest_digest,context.storage_generation,context.stage)
                or context.manifest!=actual.manifest):
            raise AuthorityUnavailable('actual initial segmented metadata context changed')
        if action!='maintenance':
            proof=read_initial_segmented_storage_v4(control,meter=meter)
            if context is not proof.context:raise AuthorityUnavailable('business initial context is not its private admitted READY proof')
    return context


_RETIREMENT_METADATA_V4=WeakKeyDictionary()


class VerifiedInitialSegmentedRetirementMetadataV4:
    """INTENT Graph terminal metadata only; no runtime or SourceBody admission."""
    def __init__(self,issuer,*,maintenance,coverage,quiescence,db,plan,original,manifest,meter):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual quiesced initial retirement metadata issuer required')
        self.maintenance,self.coverage,self.quiescence=maintenance,coverage,dict(quiescence)
        self.control,self.gate=maintenance.control,maintenance.gate
        self._db=db;self.plan,self.original,self.manifest=plan,original,manifest
        self.namespace=NamespaceId(**plan['namespace']);self.authority_namespace=plan['authority_namespace']
        self.genesis_digest=original['genesis_digest'];self.role='graph'
        self.selection_digest=canonical_digest(('sylanne3.c09.initial-segmented-selection.v4',self.genesis_digest,
            manifest['manifest_digest'],0,0,self.namespace,self.control.authority_id,self.control.installation_id,self.control.control_store_id))
        self.gate_identity=(self.gate._operation,self.gate._epoch,self.gate._closing_continuation)
        self.context=read_initial_segmented_context_v4(self.control,meter=meter)
        self.stamp=self._graph_stamp_v4(db,meter);self._sealed=False;self.closed=False
        _RETIREMENT_METADATA_V4[self]=self._identity_v4()
        self.control.register_c09_retained_state_v3(self)
    @property
    def db(self):return self._db
    def _identity_v4(self):
        return (id(self.maintenance),id(self.coverage),canonical_digest(self.quiescence),id(self.control),id(self.gate),
            id(self.db),canonical_digest(self.plan),canonical_digest(self.original),canonical_digest(self.manifest),
            self.genesis_digest,self.selection_digest,self.gate_identity,self.stamp,self._sealed,id(self.context),self.closed)
    def _c09_retained_heap_bytes_v3(self):
        return 4096+len(canonical_serialize((self.plan,self.original,self.manifest,self.quiescence,self.stamp)).encode())*8
    def release_v4(self):
        if self.closed:return
        self.closed=True;_RETIREMENT_METADATA_V4.pop(self,None)
        self.control._c09_retained_states_v3.discard(self)
        self._db=None
    def member(self,role):
        if role!='graph':raise AuthorityUnavailable('retirement metadata has no other role capability')
        return next(item for item in self.manifest['members']if item['role']=='graph')
    def _require_scope_v4(self,meter):
        from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
        from .c09_writer_peer_originals_v3 import _require_gate,VerifiedPeerRetirementCoverageV3,require_writer_quiescence_original_v3
        from .c09_selected_history_v3 import _bounded
        m=self.maintenance
        if (self.closed or type(m)is not InstalledC09MaintenanceV1 or type(self.coverage)is not VerifiedPeerRetirementCoverageV3
                or _RETIREMENT_METADATA_V4.get(self)!=self._identity_v4()
                or self.gate._installed_maintenance_v3 is not m or m.control is not self.control or m.gate is not self.gate
                or self.coverage.progress.control is not self.control or self.coverage.progress.gate is not self.gate
                or (self.gate._operation,self.gate._epoch,self.gate._closing_continuation)!=self.gate_identity
                or self.gate._operation!=self.coverage.operation_id or self.gate._active!=0
                or self.gate._epoch!=self.quiescence['revoked_admission_epoch']):
            raise AuthorityUnavailable('initial retirement metadata lost its actual drained continuous C09 Gate')
        _require_gate(self.control,self.gate);self.control.lease.require_held()
        if self.gate._closing_continuation is not None:
            self.gate.require_final_continuation_v3(self.gate._closing_continuation,operation_id=self.coverage.operation_id,observe=False)
        with self.control._db()as db:
            current=self.control._c09_control_chain_proof_v2.require_current(db,meter)
            row=_bounded(db,meter).execute('SELECT genesis_digest,plan_digest,manifest_digest FROM c09_initial_segmented_genesis_v4 '
                'WHERE installation_id=?',(self.control.installation_id,)).fetchone()
        if ((current['stage'],current['active_operation_id'],current['pointer_version'],current['current_manifest_digest'])!=
                ('INTENT',self.coverage.operation_id,0,self.manifest['manifest_digest'])
                or row!=(self.genesis_digest,self.plan['plan_digest'],self.manifest['manifest_digest'])):
            raise AuthorityUnavailable('initial retirement metadata changed its actual pre-capture INTENT/genesis')
        self.control.verify_original_v1(self.original,'genesis_digest')
        require_writer_quiescence_original_v3(self.control,self.quiescence,meter=meter,operation_id=self.coverage.operation_id)
        self.coverage.require_current(meter=meter)
        m.core._require(m.credential,'delete',m.closure.namespace)
        self.control.verify_member_v1(self.member('graph'),prepared=False)
        return self
    def _graph_stamp_v4(self,db,meter):
        from .c09_selected_history_v3 import _bounded
        b=_bounded(db,meter);ns=self.namespace.as_tuple
        return (b.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',ns).fetchone(),
            b.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',ns).fetchone(),
            b.execute('SELECT graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',ns).fetchone())
    def require_graph(self,db,*,meter):
        from .c09_selected_history_v3 import _bounded
        self._require_scope_v4(meter)
        if db is not self.db or type(db)is not sqlite3.Connection or not db.in_transaction:
            raise AuthorityUnavailable('actual initial retirement Graph metadata READ transaction required')
        b=_bounded(db,meter);member=self.member('graph');layout=self.manifest['segmented_layouts']['graph']
        if b.execute('PRAGMA query_only').fetchone()!=(1,):
            raise AuthorityUnavailable('initial retirement Graph metadata connection is not query-only')
        rows=b.execute('PRAGMA database_list').fetchall()
        if len(rows)!=1 or rows[0][1]!='main'or Path(rows[0][2]).resolve()!=Path(member['resolved_path']).resolve():
            raise AuthorityUnavailable('retirement metadata cannot read another Graph file')
        header=b.execute('SELECT storage_instance_id,role,layout_id,layout_schema_digest,authority_id,authority_namespace,'
            'installation_id,storage_generation,origin_scope_digest FROM segmented_storage_layout_v1 WHERE singleton=1').fetchone()
        if (header!=(layout['storage_instance_id'],'graph',LAYOUTS['graph'],LAYOUT_SCHEMA_DIGEST,self.control.authority_id,
                self.authority_namespace,self.control.installation_id,0,self.plan['plan_digest'])
                or self._graph_stamp_v4(db,meter)!=self.stamp):
            raise AuthorityUnavailable('actual initial retirement Graph layout/stamp changed')
        return self
    def seal_graph_eof_v4(self,db,*,meter):
        self.require_graph(db,meter=meter)
        if self._sealed:raise AuthorityUnavailable('initial retirement Graph metadata EOF was already sealed')
        self._sealed=True;_RETIREMENT_METADATA_V4[self]=self._identity_v4()
        return self
    def require_current(self,*,meter):
        self._require_scope_v4(meter)
        if not self._sealed:raise AuthorityUnavailable('initial retirement metadata has no actual sealed Graph EOF stamp')
        return self


def require_initial_segmented_retirement_metadata_v4(maintenance,*,retirement_coverage,quiescence_original,db,meter):
    from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    from .c09_writer_peer_originals_v3 import VerifiedPeerRetirementCoverageV3
    if (type(maintenance)is not InstalledC09MaintenanceV1 or type(retirement_coverage)is not VerifiedPeerRetirementCoverageV3
            or type(db)is not sqlite3.Connection or not db.in_transaction):
        raise AuthorityUnavailable('actual C09 quiesced initial retirement Graph metadata issuer required')
    with maintenance.control._db()as control_db:
        plan,original,manifest=_read_signed_initial_metadata_v4(maintenance.control,control_db,meter)
    result=VerifiedInitialSegmentedRetirementMetadataV4(_ISSUER,maintenance=maintenance,coverage=retirement_coverage,
        quiescence=quiescence_original,db=db,plan=plan,original=original,manifest=manifest,meter=meter)
    try:return result.require_graph(db,meter=meter)
    except BaseException:
        result.release_v4();raise


def initial_journal_schema_objects_v4(owner,role):
    from .v2_execution_journal import AuthorityV2ExecutionJournal
    from .v2_deletion_guard import AuthorityV2DeletionGuard
    from ..runtime_storage_v3 import runtime_storage_v3
    from .c09_selected_history_v3 import _bounded
    expected={'execution':AuthorityV2ExecutionJournal,'deletion':AuthorityV2DeletionGuard}
    if role not in expected or type(owner)is not expected[role]or not owner._db.in_transaction:
        raise AuthorityUnavailable('actual initial journal guarded metadata transaction required')
    handle=runtime_storage_v3(owner._db)
    if handle is None or handle.source_kind!='initial_segmented_v4'or handle.role!=role:
        raise AuthorityUnavailable('actual initial journal runtime identity required')
    with handle.quantum()as meter:
        initial=handle.initial;initial.require_current(meter=meter);initial.require_layout(owner._db,role,meter=meter)
        rows=tuple(_bounded(owner._db,meter).execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall())
        if canonical_digest(rows)!=initial.member(role)['schema_objects_digest']:
            raise AuthorityUnavailable('initial journal complete actual schema differs from its signed genesis')
        objects={(kind,name):ddl for kind,name,ddl in rows}
        for name,ddl in DDLS.items():
            if objects.pop(('table',name),None)!=ddl:raise AuthorityUnavailable('initial journal cell table differs')
        for name,ddl in TRIGGERS.items():
            if objects.pop(('trigger',name),None)!=ddl:raise AuthorityUnavailable('initial journal cell trigger differs')
        return objects


_STARTUPS_V4=WeakKeyDictionary()
_CREATIONS_V4=WeakKeyDictionary()


def _initial_fixed_bindings_v4(config):
    from .deployment_config import AuthorityDeploymentConfig
    from ..runtime_contracts import namespace_ref
    from .c09_installed_factory_v1 import InstalledC09MaintenanceFactoryV1
    if (type(config)is not AuthorityDeploymentConfig or config.c09_storage_v1 is None
            or config.c09_storage_v2 is not None or type(config.c09_maintenance_factory)is not InstalledC09MaintenanceFactoryV1
            or len(config.execution_journals)!=1):
        raise AuthorityUnavailable('explicit initial genesis needs its actual single-cohort production configuration')
    installed=config.c09_storage_v1;namespace=next(iter(config.execution_journals));factory=config.c09_maintenance_factory
    if namespace!=namespace_ref(factory.namespace)or installed.installation_id!=factory.inventory.installation_id:
        raise AuthorityUnavailable('actual initial Root namespace/installation differs')
    paths={'core':str(Path(config.authority_db).resolve()),'deletion':str(Path(config.deletion_db).resolve()),
        'execution':str(Path(config.execution_journals[namespace].path).resolve()),'graph':str(Path(config.graph_db).resolve())}
    return dict(authority_id=installed.authority_id,installation_id=installed.installation_id,control_store_id=installed.control_store_id,
        namespace=namespace,graph_namespace=dict(bot_id=factory.namespace.bot_id,persona_id=factory.namespace.persona_id),
        role_paths=paths,control_path=str(Path(installed.control_path).resolve()),key_path=str(Path(installed.key_path).resolve()),
        instance_lock_path=str(Path(config.instance_lock).resolve()),inventory_manifest_digest=factory.inventory.manifest_digest)


class _InitialStorageStartupHoldV4:
    def __init__(self,issuer,*,config,lease,channel,original,consumer_mode,root_spec=None):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual Root initial-storage startup issuer required')
        self.config,self.lease,self.channel,self.original=config,lease,channel,original
        self.consumer_mode,self.root_spec=consumer_mode,root_spec
        self.census=None
        import threading
        self.owner_thread=threading.get_ident();self.closed=False;self.bound=None
        self.bindings=_initial_fixed_bindings_v4(config)
        _STARTUPS_V4[self]=self._identity_v4()
    def _identity_v4(self):
        return (id(self.config),id(self.lease),id(self.channel),canonical_digest(self.original),self.consumer_mode,
            id(self.root_spec),self.owner_thread,self.closed,id(self.bound),canonical_digest(self.bindings),id(self.census))
    def require_current(self):
        import threading,select,time
        from .c09_process_identity_v1 import read_process_identity_v1
        if (_STARTUPS_V4.get(self)!=self._identity_v4()or self.closed or threading.get_ident()!=self.owner_thread
                or self.channel.fileno()<0 or select.select([self.channel],[],[],0)[0]
                or self.bindings!=_initial_fixed_bindings_v4(self.config)
                or self.original['bindings']!=self.bindings
                or self.original['authority_process_original']!=read_process_identity_v1(os.getpid())
                or self.original['root_process_original']!=read_process_identity_v1(self.original['root_process_original']['pid'])):
            raise AuthorityUnavailable('actual continuous pre-Control Root initial-storage hold changed')
        self.lease.require_held()
        if str(self.lease.path.resolve())!=self.bindings['instance_lock_path']:
            raise AuthorityUnavailable('actual initial startup instance lease differs')
        if self.consumer_mode=='production_root':
            from .installed_process_supervisor_v1 import verify_process_supervisor_spec_v1
            from .installed_root_lifetime_observer_v3 import read_installed_root_lifetime_spec_v3,read_root_lifetime_resource_approval_v3,SPEC_PATH
            verify_process_supervisor_spec_v1(self.root_spec)
            resource=read_root_lifetime_resource_approval_v3(read_installed_root_lifetime_spec_v3(SPEC_PATH))
            if resource!=self.original['resource_original']:
                raise AuthorityUnavailable('initial startup actual Root resource approval changed')
        elif self.consumer_mode=='controlled_sdk':
            self.census.require_current()
            source=self.original['resource_original']
            if time.monotonic_ns()>=source['run_deadline_monotonic_ns']:
                raise AuthorityUnavailable('actual initial SDK Root resource deadline expired')
            group=source['app_cgroup'];path=Path(group['path']);st=path.stat()
            if ((st.st_dev,st.st_ino)!=(group['device'],group['inode'])
                    or (path/'cgroup.procs').read_text().split()!=[str(os.getpid())]
                    or any(item.is_dir()for item in path.iterdir())):
                raise AuthorityUnavailable('actual initial SDK Root process/resource census changed')
        else:raise AuthorityUnavailable('unknown actual initial startup consumer mode')
        return self
    def close(self):
        if self.closed:return
        self.require_current()
        if self.consumer_mode=='controlled_sdk':self.census.close()
        elif self.bound is not None:self.bound.close()
        else:
            request=dict(command='release_initial_storage_v4',startup_nonce=self.original['startup_nonce'])
            self._exchange_v4(request)
        self.closed=True;_STARTUPS_V4.pop(self,None);self.channel.close()
    def _exchange_v4(self,request):
        self.require_current()
        encoded=canonical_serialize(request).encode()
        self.channel.sendall(encoded+(b'\n'if self.consumer_mode=='production_root'else b''))
        if self.consumer_mode=='production_root':
            from .installed_process_supervisor_v1 import _read_peer_start_packet_v3
            return _read_peer_start_packet_v3(self.channel,limit=262144)
        raw=self.channel.recv(262145)
        if not raw or len(raw)>262144:raise AuthorityUnavailable('bounded actual SDK initial-storage Root reply required')
        return json.loads(raw)


def _initial_creation_owned_v4(creation,role):
    path=Path(creation.plan['role_paths'][role]);st=path.stat()
    if (str(path.resolve())!=str(path)or (st.st_dev,st.st_ino)!=creation.owned[role]):
        raise AuthorityUnavailable('initial genesis role is not this exact O_EXCL creation')
    return path


class _InitialGenesisCreationV4:
    def __init__(self,issuer,*,startup,plan,owned):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual initial genesis creation issuer required')
        self.startup,self.plan,self.owned=startup,plan,dict(owned)
        self.roles=None;self.empty_eof=None;self.counter_eof=None;self.original=None;self.manifest=None
        self.native_connections=();self.role_connections=()
        _CREATIONS_V4[self]=self._identity_v4()
    def _identity_v4(self):
        return (id(self.startup),canonical_digest(self.plan),tuple(sorted(self.owned.items())),
            canonical_digest((self.roles,self.empty_eof,self.counter_eof,self.original,self.manifest)),
            tuple(map(id,self.native_connections)),tuple(map(id,self.role_connections)))
    def require_current(self,control):
        if _CREATIONS_V4.get(self)!=self._identity_v4():raise AuthorityUnavailable('actual initial creation private binding changed')
        self.startup.require_current()
        if (control.lease is not self.startup.lease or (control.authority_id,control.installation_id,control.control_store_id)!=
                tuple(self.plan[key]for key in ('authority_id','installation_id','control_store_id'))
                or str(control.path)!=self.startup.bindings['control_path']):
            raise AuthorityUnavailable('initial creation cannot publish another Control/install')
        for role in ROLES_V4:_initial_creation_owned_v4(self,role)
        return self


def _initial_schema_rows_v4(db):
    return tuple(db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"))


def _initial_empty_business_eof_v4(db,role,plan,config):
    permitted={'core':{'authority_meta','authority_namespaces','authority_events','authority_scoped_erasure_v2','authority_installer_graph_genesis_v1'},
        'deletion':{'deletion_meta','authority_deletion_v2_meta'},'execution':{'authority_v2_execution_meta'},
        'graph':{'graph_type_catalog','graph_type_authority'}}[role]|{'segmented_storage_layout_v1'}
    namespace=plan['authority_namespace']
    if role=='core':
        meta=dict(db.execute('SELECT key,value FROM authority_meta'))
        if (set(meta)!={'authority_id','service_mode','owner_session_boot_id','deletion_v2_migration',
                'deletion_v2_tail_migration','scoped_erasure_v2_migration'}
                or meta['authority_id']!=plan['authority_id']or meta['service_mode']!='v2-only'):
            raise AuthorityUnavailable('initial Core has unexpected bootstrap metadata')
        for name in ('deletion_v2_migration','deletion_v2_tail_migration','scoped_erasure_v2_migration'):
            marker=json.loads(meta[name])
            if marker['namespace']!=namespace or marker['authority_id']!=plan['authority_id']or marker['stage']!='complete':
                raise AuthorityUnavailable('initial Core exact native zero-history migration did not complete')
        if (db.execute('SELECT COUNT(*) FROM authority_namespaces').fetchone()!=(1,)
                or db.execute("SELECT namespace,generation,phase,revocation_epoch,deletion_seq,deletion_phase,execution_seq FROM authority_namespaces").fetchone()!=
                    (namespace,1,'active',0,0,'clear',0)
                or db.execute('SELECT namespace,kind,generation FROM authority_events').fetchall()!=[(namespace,'install',1)]
                or db.execute('SELECT namespace,aggregate_phase,active_operation_id,applied_seq,applied_epoch,cut_seq FROM authority_scoped_erasure_v2').fetchall()!=
                    [(namespace,'clear',None,0,0,0)]):
            raise AuthorityUnavailable('initial Core is not exact empty-business namespace genesis')
        from .installer_genesis_v1 import read_installer_genesis_original_v1_locked
        first_graph=read_installer_genesis_original_v1_locked(db,namespace)
        if (first_graph is None or first_graph.authority_id!=plan['authority_id']
                or first_graph.installation_id!=plan['installation_id']or first_graph.namespace!=NamespaceId(**plan['namespace'])
                or first_graph.catalogue_hash!=config.c09_maintenance_factory.registry.catalogue_hash
                or db.execute('SELECT COUNT(*) FROM authority_installer_graph_genesis_v1').fetchone()!=(1,)):
            raise AuthorityUnavailable('initial Core actual first-Graph genesis source original differs')
    elif role=='deletion':
        meta=dict(db.execute('SELECT key,value FROM authority_deletion_v2_meta'))
        if (set(meta)!={'schema_version','namespace','journal_id','cut_seq','cut_digest'}
                or meta['namespace']!=namespace or meta['schema_version']!='2'or meta['cut_seq']!='0'
                or dict(db.execute('SELECT key,value FROM deletion_meta'))!={'journal_id':meta['journal_id']}):
            raise AuthorityUnavailable('initial deletion journal zero-history metadata differs')
    elif role=='execution':
        if dict(db.execute('SELECT key,value FROM authority_v2_execution_meta'))!={
                'schema_version':'2','namespace':namespace,'journal_id':config.execution_journals[namespace].journal_id}:
            raise AuthorityUnavailable('initial execution journal metadata differs')
    elif role=='graph':
        from ..graph_store import ProductionGraphStore
        registry=config.c09_maintenance_factory.registry
        observed=tuple(db.execute('SELECT name,owner_kinds,storage_role,immutable,schema_version FROM graph_type_catalog ORDER BY name'))
        expected=tuple(ProductionGraphStore._catalog_row(spec)for spec in registry.specs)
        authority=tuple(db.execute('SELECT name,writer_domain,schema_hash FROM graph_type_authority ORDER BY name'))
        if observed!=expected or authority!=tuple((spec.name,spec.writer_domain or '',spec.schema_hash or '')for spec in registry.specs):
            raise AuthorityUnavailable('initial Graph actual complete type catalogue differs')
    from hashlib import sha256
    census=sha256();census.update(b'[');table_count=0;bootstrap=[]
    for (name,)in db.execute("SELECT name FROM sqlite_master WHERE type='table'AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        quoted='"'+name.replace('"','""')+'"'
        count=db.execute('SELECT COUNT(*) FROM '+quoted).fetchone()[0]
        if name not in permitted and count!=0:
            raise AuthorityUnavailable('nonempty business/history/pending table cannot be initial genesis: '+role+'/'+name)
        metadata=tuple(db.execute('SELECT * FROM '+quoted))if name in permitted else ()
        metadata_digest=canonical_digest(metadata)
        record=(name,count,metadata_digest,'bootstrap'if name in permitted else'empty_business')
        if table_count:census.update(b',')
        census.update(canonical_serialize(record).encode());table_count+=1
        if name in permitted:bootstrap.append((name,count,metadata_digest))
    census.update(b']')
    value=dict(schema='sylanne3.c09.initial-empty-business-eof.v4',role=role,namespace=namespace,
        storage_instance_id=plan['role_storage_instance_ids'][role],schema_objects_digest=canonical_digest(_initial_schema_rows_v4(db)),
        table_count=table_count,table_census_root=census.hexdigest(),bootstrap_metadata_root=canonical_digest(tuple(bootstrap)))
    return dict(value,eof_digest=canonical_digest(value))


def _create_initial_native_schemas_v4(creation,config):
    from types import MappingProxyType
    from .core import AuthorityServiceCore,AUTHORITY_META_DDL_V4
    from .deployment_config import AuthorityCoreVerifiers
    from ..runtime.deletion import DeletionJournal
    from .v2_deletion_guard import AuthorityV2DeletionGuard
    from .v2_execution_journal import AuthorityV2ExecutionJournal
    from .v2_fence_store import AuthorityV2FenceStore
    from .v2_deletion_migration import AuthorityV2DeletionMigration
    from .v2_deletion_tail_migration import AuthorityV2DeletionTailMigration
    from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
    from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
    from .v2_owner_proof import AuthorityV2OwnerProofStore
    from .v2_owner_session import AuthorityV2OwnerSessionStore
    from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
    from .v2_model_egress_store import AuthorityV2ModelEgressStore
    from ..graph_store import ProductionGraphStore
    namespace=creation.plan['authority_namespace'];core=None;deletion=None;execution=None;graph=None
    try:
        legacy=DeletionJournal(_initial_creation_owned_v4(creation,'deletion'),create=True);legacy.close()
        deletion=AuthorityV2DeletionGuard(creation.plan['role_paths']['deletion'])
        execution=AuthorityV2ExecutionJournal(_initial_creation_owned_v4(creation,'execution'),namespace=namespace,
            journal_id=config.execution_journals[namespace].journal_id,create=True)
        path=_initial_creation_owned_v4(creation,'core')
        from contextlib import closing
        with closing(sqlite3.connect(path))as seed:
            seed.execute(AUTHORITY_META_DDL_V4)
            seed.execute('INSERT INTO authority_meta(key,value)VALUES(?,?)',('authority_id',creation.plan['authority_id']));seed.commit()
        verifiers=config.core_verifier_factory(deletion,MappingProxyType({namespace:execution}))
        if type(verifiers)is not AuthorityCoreVerifiers:raise AuthorityUnavailable('actual production Core verifier factory required')
        core=AuthorityServiceCore(path,authorizer=config.core_authorizer,deletion_verifier=verifiers.deletion,
            execution_verifier=verifiers.execution,effect_verifier=verifiers.effect,dispatch_verifier=verifiers.dispatch,create=True)
        if core._id(core._db)!=creation.plan['authority_id']:raise AuthorityUnavailable('actual created Core authority identity differs')
        holders={item.administrator_holder for item in config.installations_v2.values()}
        if len(holders)!=1:raise AuthorityUnavailable('initial Core actual installed administrator holder is not unique')
        core.register_namespace(config.local_administrator_credential('install',namespace),namespace,next(iter(holders)),
            deletion.verified_head(),execution.verified_head())
        core.seal_v2_only(config.local_administrator_credential('seal_v2_only',namespace))
        fences=AuthorityV2FenceStore(core._db,create=True,lock=core._lock)
        args=dict(core=core,fences=fences,deletion=deletion,execution=execution,namespace=namespace)
        credential=config.local_administrator_credential('migrate_deletion',namespace)
        AuthorityV2DeletionMigration(**args).run(credential=credential)
        AuthorityV2DeletionTailMigration(**args).run(credential=credential)
        AuthorityV2ScopedErasureStore(**args).migrate_zero_history(credential=credential)
        pairing=AuthorityOwnerPairingSource(core,utc_clock=config.utc_clock,create=True)
        AuthorityV2OwnerProofStore(core,utc_clock=config.utc_clock,current_pairing_source=pairing,create=True)
        sessions=AuthorityV2OwnerSessionStore(core,utc_clock=config.utc_clock,current_pairing_source=pairing,create=True)
        tickets=AuthorityV2OwnerTicketStore(core,utc_clock=config.utc_clock,owner_sessions=sessions,creation_pairing_source=pairing,create=True)
        AuthorityV2ModelEgressStore(core._db,create=True,lock=core._lock)
        from .d13_core_counter_service_v1 import install_initial_d13_counter_original_schema_v1
        from .d13_provider_http_admission_v1 import install_initial_provider_http_binding_schema_v1
        with core._tx()as db:
            install_initial_d13_counter_original_schema_v1(db)
            install_initial_provider_http_binding_schema_v1(db)
        graph=ProductionGraphStore(_initial_creation_owned_v4(creation,'graph'),config.c09_maintenance_factory.registry)
        from .v2_fence_service import AuthorityV2FenceService
        from .v2_self_identity_service import AuthorityV2SelfIdentityService
        from .current_self_identity_graph_verifier import PinnedCurrentSelfIdentityGraphVerifier
        from .v2_worker_model_result_attempts import AuthorityV2WorkerModelResultAttempts
        service=AuthorityV2FenceService(**args)
        for authority_namespace,peer in (config.self_identity_readers_v2 or {}).items():
            installation=config.installations_v2[peer]
            AuthorityV2SelfIdentityService(core=core,fences=service,owner_tickets=tickets,
                graph=PinnedCurrentSelfIdentityGraphVerifier(config.graph_db),namespace_id=config.c09_maintenance_factory.namespace,
                installation_id=installation.installation_id,manifest_digest=installation.manifest_digest,
                read_subject='mtls:sha256:'+peer[0],holder=installation.administrator_holder,
                administrator_authorizer=config.administrator_authorizer,create=True)
        if config.natural_model_authorities_v2:
            AuthorityV2WorkerModelResultAttempts(core._db,create=True,lock=core._lock)
        from .installer_genesis_v1 import record_installer_genesis_original_v1
        record_installer_genesis_original_v1(core=core,config=config,registry=config.c09_maintenance_factory.registry,
            instance_lease=creation.startup.lease,files=creation.plan['role_paths'])
    finally:
        creation.native_connections=tuple(item._db for item in (graph,core,execution,deletion)if item is not None)
        if graph is not None:graph.close()
        if core is not None:core.close()
        if execution is not None:execution.close()
        if deletion is not None:deletion.close()
        _CREATIONS_V4[creation]=creation._identity_v4()


def _create_initial_segmented_roles_v4(creation,config):
    from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3,GRAPH_REF_INDEXES_V3,CORE_REF_DDLS_V2,FACT_REF_DDLS_V3
    from ..runtime_storage_v3 import selected_runtime_catalogue_v3
    from hashlib import sha256
    from contextlib import closing
    plan=creation.plan;roles={};eofs={}
    for role in ROLES_V4:
        creation.startup.require_current();path=_initial_creation_owned_v4(creation,role)
        with closing(sqlite3.connect(path,isolation_level=None))as db:
            creation.role_connections+= (db,)
            db.execute('PRAGMA foreign_keys=OFF');db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            try:
                refs=GRAPH_REF_DDLS_V3 if role=='graph'else {**CORE_REF_DDLS_V2,**FACT_REF_DDLS_V3} if role=='core'else{}
                native_triggers=tuple(db.execute("SELECT sql FROM sqlite_master WHERE type='trigger'AND name IN ('authority_d13_counter_no_update_v1','authority_d13_counter_no_delete_v1','d13_provider_http_no_update_v1','d13_provider_http_no_delete_v1')ORDER BY name"))if role=='core'else()
                if role=='core'and len(native_triggers)!=4:raise AuthorityUnavailable('actual initial Core producer immutable trigger cohort differs')
                indexes=tuple(db.execute("SELECT sql FROM sqlite_master WHERE type='index'AND name IN ('graph_atoms_namespace','graph_atoms_namespace_type_token')ORDER BY name"))if role=='graph'else()
                if role=='graph'and len(indexes)!=2:raise AuthorityUnavailable('actual production initial Graph index cohort differs')
                for name in refs:
                    exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table'AND name=?",(name,)).fetchone()
                    if exists is not None:
                        if db.execute('SELECT 1 FROM "'+name+'" LIMIT 1').fetchone()is not None:
                            raise AuthorityUnavailable('new initial Body reference table is unexpectedly nonempty: '+name)
                        db.execute('DROP TABLE "'+name+'"')
                for ddl in DDLS.values():db.execute(ddl)
                db.execute('INSERT INTO segmented_storage_layout_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    (1,LAYOUT_SCHEMA,plan['role_storage_instance_ids'][role],role,LAYOUTS[role],LAYOUT_SCHEMA_DIGEST,
                     plan['authority_id'],plan['authority_namespace'],plan['installation_id'],0,plan['plan_digest']))
                for ddl in refs.values():db.execute(ddl)
                for (ddl,)in native_triggers:db.execute(ddl)
                if role=='graph':
                    for (ddl,)in indexes:db.execute(ddl)
                    for ddl in GRAPH_REF_INDEXES_V3.values():db.execute(ddl)
                for name,ddl in selected_runtime_catalogue_v3(role).items():
                    existing=db.execute('SELECT sql FROM sqlite_master WHERE name=?',(name,)).fetchone()
                    if existing is None:db.execute(ddl)
                    elif existing!=(ddl,):raise AuthorityUnavailable('initial production runtime catalogue conflicts: '+name)
                for ddl in TRIGGERS.values():db.execute(ddl)
                if db.execute('PRAGMA foreign_key_check').fetchone()is not None:
                    raise AuthorityUnavailable('actual initial segmented role foreign-key catalogue is inconsistent')
                eofs[role]=_initial_empty_business_eof_v4(db,role,plan,config)
                schema=_initial_schema_rows_v4(db)
                if role=='core':
                    header='authority_d13_counter_originals_v1';index='runtime_d13_counter_calls_v3'
                    hd=canonical_digest(db.execute('SELECT sql FROM sqlite_master WHERE name=?',(header,)).fetchone()[0])
                    ix=canonical_digest(db.execute('SELECT sql FROM sqlite_master WHERE name=?',(index,)).fetchone()[0])
                    creation.counter_eof=dict(schema='sylanne3.c09.initial-counter-empty-eof.v4',core_storage_instance_id=plan['role_storage_instance_ids']['core'],
                        namespace=plan['authority_namespace'],header_table=header,header_count=0,header_schema_digest=hd,
                        index_table=index,index_count=0,index_schema_digest=ix,empty_root=canonical_digest((header,hd,0,index,ix,0)))
                db.execute('COMMIT')
            except BaseException:db.execute('ROLLBACK');raise
            if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]!=0:
                raise AuthorityUnavailable('initial role checkpoint did not settle')
        with path.open('rb')as file:
            os.fsync(file.fileno());file_hash=sha256()
            for chunk in iter(lambda:file.read(1048576),b''):file_hash.update(chunk)
        st=path.stat();journal=config.execution_journals[plan['authority_namespace']].journal_id if role=='execution'else plan['role_storage_instance_ids'][role]
        if role=='deletion':
            with closing(sqlite3.connect(f'file:{path.as_posix()}?mode=ro',uri=True))as identity:
                journal=dict(identity.execute('SELECT key,value FROM deletion_meta'))['journal_id']
        resources=config.c09_maintenance_factory.inventory.resources
        owners=[item for item in resources if item.kind=='sqlite_db'and item.path==str(path)]
        if len(owners)!=1:raise AuthorityUnavailable('initial role has no exact installed inventory resource')
        companions=sorted(item.resource_id for item in resources if item.store_id==owners[0].store_id and item.kind in {'sqlite_wal','sqlite_shm'})
        if len(companions)!=2:raise AuthorityUnavailable('initial role lacks its actual registered WAL/SHM resources')
        member=dict(role=role,resolved_path=str(path),store_id=owners[0].store_id,schema_version=LAYOUTS[role],
            namespace=plan['authority_namespace'],storage_generation=0,incarnation_or_journal_id=journal,device=st.st_dev,file_id=st.st_ino,
            prepared_size=st.st_size,prepared_mtime_ns=st.st_mtime_ns,prepared_sha256=file_hash.hexdigest(),logical_data_root=eofs[role]['eof_digest'],
            schema_objects_digest=canonical_digest(schema),cold_read_digest=canonical_digest((role,plan['plan_digest'],eofs[role])),
            wal_policy='checkpointed-no-live-wal',companion_resource_ids=companions)
        roles[role]=dict(member=member,empty_business_eof_digest=canonical_digest(eofs[role]))
    creation.roles,creation.empty_eof=roles,eofs;_CREATIONS_V4[creation]=creation._identity_v4()


def create_initial_segmented_genesis_v4(*,config,startup_hold):
    from uuid import uuid4
    from .c09_storage_control_v1 import C09StorageControlV1,digest
    if type(startup_hold)is not _InitialStorageStartupHoldV4 or startup_hold.config is not config:
        raise AuthorityUnavailable('actual Root startup hold and unchanged production configuration required')
    startup_hold.require_current();bindings=startup_hold.bindings;factory=config.c09_maintenance_factory
    if Path(bindings['control_path']).exists():raise AuthorityUnavailable('explicit initial genesis refuses an existing Control')
    plan=dict(schema=PLAN_SCHEMA_V4,genesis_id=str(uuid4()),creation_nonce=uuid4().hex,
        authority_id=bindings['authority_id'],installation_id=bindings['installation_id'],control_store_id=bindings['control_store_id'],
        namespace=bindings['graph_namespace'],authority_namespace=bindings['namespace'],root_startup_original=startup_hold.original,
        root_startup_digest=canonical_digest(startup_hold.original),instance_lock_ref=canonical_digest((bindings['instance_lock_path'],
            Path(bindings['instance_lock_path']).stat().st_dev,Path(bindings['instance_lock_path']).stat().st_ino)),role_paths=bindings['role_paths'],
        role_storage_instance_ids={role:canonical_digest(('sylanne3.c09.initial-role-instance.v4',uuid4().hex,role))for role in ROLES_V4},
        layout_schema_digest=LAYOUT_SCHEMA_DIGEST,catalogue_digest=factory.registry.catalogue_hash)
    plan['plan_digest']=canonical_digest(plan);_require_plan_v4(plan);owned={}
    for role in ROLES_V4:
        path=Path(plan['role_paths'][role]);fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
        try:st=os.fstat(fd);owned[role]=(st.st_dev,st.st_ino);os.fsync(fd)
        finally:os.close(fd)
    creation=_InitialGenesisCreationV4(_ISSUER,startup=startup_hold,plan=plan,owned=owned)
    _create_initial_native_schemas_v4(creation,config);_create_initial_segmented_roles_v4(creation,config)
    installed=config.c09_storage_v1
    control=C09StorageControlV1(control_path=installed.control_path,key_path=installed.key_path,installation_id=installed.installation_id,
        authority_id=installed.authority_id,control_store_id=installed.control_store_id,key_id=installed.key_id,
        lease=startup_hold.lease,resource_roots=installed.resource_roots)
    original=control.sign_original_v1(GENESIS_SCHEMA_V4,dict(schema=GENESIS_SCHEMA_V4,genesis_id=plan['genesis_id'],
        authority_id=control.authority_id,installation_id=control.installation_id,control_store_id=control.control_store_id,
        namespace=plan['namespace'],authority_namespace=plan['authority_namespace'],plan=plan,plan_digest=plan['plan_digest'],
        initial_origin_scope_digest=plan['plan_digest'],role_originals=creation.roles,empty_business_eof=creation.empty_eof,
        empty_business_eof_digest=canonical_digest(creation.empty_eof),core_counter_empty_eof=creation.counter_eof),'genesis_digest')
    manifest=dict(schema=MANIFEST_SCHEMA_V4,authority_id=control.authority_id,installation_id=control.installation_id,
        control_store_id=control.control_store_id,cohort_namespaces=[plan['authority_namespace']],generation=0,prior_manifest_digest=None,
        members=[creation.roles[role]['member']for role in ROLES_V4],inventory_manifest_digest=bindings['inventory_manifest_digest'],
        cumulative_tombstone_root=canonical_digest(()),deletion_watermark=0,
        segmented_layouts={role:dict(layout_id=LAYOUTS[role],layout_schema_digest=LAYOUT_SCHEMA_DIGEST,
            storage_instance_id=plan['role_storage_instance_ids'][role])for role in ROLES_V4},
        initial_genesis_plan_digest=plan['plan_digest'],initial_genesis_original_digest=original['genesis_digest'],
        empty_business_eof_digest=original['empty_business_eof_digest'])
    manifest['manifest_digest']=digest(manifest);creation.original,creation.manifest=original,manifest
    _CREATIONS_V4[creation]=creation._identity_v4();control.install_selected_producer_config_v3(config)
    initial=control.bootstrap_initial_segmented_storage_v4(creation=creation)
    control._initial_genesis_creation_v4=creation
    return initial



def _require_actual_closed_initial_connections_v4(creation):
    if (_CREATIONS_V4.get(creation)!=creation._identity_v4()or len(creation.native_connections)!=4
            or len(creation.role_connections)!=4):
        raise AuthorityUnavailable('initial genesis has no complete actual native/four-role connection close originals')
    for connection in (*creation.native_connections,*creation.role_connections):
        try:connection.in_transaction
        except sqlite3.ProgrammingError:continue
        raise AuthorityUnavailable('an actual initial native/segmented connection remains open')
    return creation


def require_published_initial_genesis_for_root_v4(*,bindings,startup_original):
    """Root fixed-path metadata verification; no business/Source capability issuance."""
    import hashlib,hmac
    from .c09_storage_control_v1 import canonical,digest,file_observation_v1
    path=Path(bindings['control_path']);key=Path(bindings['key_path']).read_bytes()
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True))as db:
        db.execute('PRAGMA query_only=ON')
        meta=dict(db.execute('SELECT key,value FROM c09_storage_meta_v1'))
        if any(meta[name]!=bindings[name]for name in ('authority_id','installation_id','control_store_id')):
            raise AuthorityUnavailable('Root initial publication has another fixed Control identity')
        row=db.execute('SELECT genesis_json,genesis_digest,plan_digest,manifest_digest FROM c09_initial_segmented_genesis_v4 '
            'WHERE installation_id=?',(bindings['installation_id'],)).fetchone()
        if row is None:raise AuthorityUnavailable('Root initial publication has no actual signed genesis')
        original=json.loads(row[0]);plan=_require_plan_v4(original['plan'])
        if (original['schema']!=GENESIS_SCHEMA_V4 or original['genesis_digest']!=row[1]or original['plan_digest']!=row[2]
                or plan['root_startup_original']!=startup_original or plan['role_paths']!=bindings['role_paths']
                or plan['root_startup_digest']!=canonical_digest(startup_original)):
            raise AuthorityUnavailable('Root initial publication lost the actual continuous startup original')
        unsigned={k:v for k,v in original.items()if k not in {'genesis_digest','signature'}}
        if (original['genesis_digest']!=digest(unsigned)or original['key_id']!=meta['key_id']
                or not hmac.compare_digest(original['signature'],hmac.new(key,(GENESIS_SCHEMA_V4+'\n'+row[1]).encode(),hashlib.sha256).hexdigest())):
            raise AuthorityUnavailable('Root initial genesis Control signature differs')
        stored=db.execute('SELECT manifest_json,key_id,signature FROM c09_storage_manifests_v1 WHERE manifest_digest=?',(row[3],)).fetchone()
        if stored is None:raise AuthorityUnavailable('Root initial published manifest is absent')
        manifest=require_initial_segmented_manifest_v4(json.loads(stored[0]))
        body=dict(schema=MANIFEST_SIGNATURE_DOMAIN_V4,manifest=manifest,issuer_id=bindings['authority_id'],key_id=meta['key_id'])
        if (stored[1]!=meta['key_id']or not hmac.compare_digest(stored[2],hmac.new(key,
                (MANIFEST_SIGNATURE_DOMAIN_V4+'\n'+digest(body)).encode(),hashlib.sha256).hexdigest())
                or manifest['initial_genesis_original_digest']!=original['genesis_digest']
                or db.execute('SELECT pointer_version,current_manifest_digest,active_operation_id,stage,last_event_seq,last_event_digest '
                    'FROM c09_storage_current_v1 WHERE installation_id=?',(bindings['installation_id'],)).fetchone()!=
                    (0,manifest['manifest_digest'],None,'READY',0,'genesis')
                or db.execute('SELECT 1 FROM c09_storage_events_v1 LIMIT 1').fetchone()is not None):
            raise AuthorityUnavailable('Root initial manifest/current-point/signature differs')
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table'AND name='c09_writer_peer_admissions_v3'").fetchone()is not None:
            if db.execute('SELECT 1 FROM c09_writer_peer_admissions_v3 LIMIT 1').fetchone()is not None:
                raise AuthorityUnavailable('initial publication already admitted a business peer')
    for role in ROLES_V4:
        member=next(item for item in manifest['members']if item['role']==role)
        observation=file_observation_v1(member['resolved_path'],exclusive=True)
        if any(observation[name]!=member[name]for name in ('resolved_path','device','file_id','prepared_size','prepared_mtime_ns','prepared_sha256')):
            raise AuthorityUnavailable('Root initial publication actual frozen role differs')
        with closing(sqlite3.connect(Path(member['resolved_path']).as_uri()+'?mode=ro',uri=True))as db:
            db.execute('PRAGMA query_only=ON')
            header=db.execute('SELECT * FROM segmented_storage_layout_v1 WHERE singleton=1').fetchone()
            if (header!=(1,LAYOUT_SCHEMA,plan['role_storage_instance_ids'][role],role,LAYOUTS[role],LAYOUT_SCHEMA_DIGEST,
                    bindings['authority_id'],bindings['namespace'],bindings['installation_id'],0,plan['plan_digest'])
                    or canonical_digest(_initial_schema_rows_v4(db))!=member['schema_objects_digest']):
                raise AuthorityUnavailable('Root initial publication actual role layout/schema differs')
            for name in ('segmented_cells_v1','segmented_cell_segments_v1','segmented_cell_writes_v1'):
                if db.execute('SELECT 1 FROM '+name+' LIMIT 1').fetchone()is not None:
                    raise AuthorityUnavailable('initial runtime cells are not empty before Root bind')
            if role=='core':
                for name in ('authority_d13_cache_use_policy_v2','authority_d13_cache_use_policies_v2','authority_d13_cache_use_installations_v2'):
                    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table'AND name=?",(name,)).fetchone()is not None:
                        if db.execute('SELECT 1 FROM '+name+' LIMIT 1').fetchone()is not None:
                            raise AuthorityUnavailable('initial Root bind cannot follow a business policy installation')
    return dict(schema='sylanne3.c09.initial-storage-bind-ack.v4',startup_digest=canonical_digest(startup_original),
        genesis_digest=original['genesis_digest'],plan_digest=plan['plan_digest'],manifest_digest=manifest['manifest_digest'],
        role_file_identities={role:[item['member']['device'],item['member']['file_id']]for role,item in original['role_originals'].items()})


def hold_controlled_sdk_initial_storage_v4(*,config,lease,root_descriptor):
    from ..host.c09_controlled_sdk_bootstrap_v3 import hold_controlled_sdk_process_census_v3
    factory=config.c09_maintenance_factory
    census=hold_controlled_sdk_process_census_v3(root_descriptor=root_descriptor,config=config,inventory=factory.inventory,peer=factory.peer)
    try:
        request=dict(schema='sylanne.root-controlled-sdk-initial-storage-request.v4',command='initial_storage_hold_v4',
            held_request_digest=census.original['request_digest'],hold_token=census.original['hold_token'])
        census.channel.sendall(canonical_serialize(request).encode());raw=census.channel.recv(262145)
        reply=json.loads(raw)
        fields={'schema','command','consumer_mode','bindings','root_process_original','authority_process_original',
            'resource_original','selection_configuration_digest','startup_nonce'}
        if (len(raw)>262144 or type(reply)is not dict or set(reply)!=fields
                or reply['schema']!='sylanne3.c09.initial-storage-startup-held.v4'or reply['command']!='initial_storage_held_v4'
                or reply['consumer_mode']!='controlled_sdk'or reply['bindings']!=_initial_fixed_bindings_v4(config)
                or reply['resource_original']!=census.original):
            raise AuthorityUnavailable('actual Root fixed initial SDK startup reply differs')
        result=_InitialStorageStartupHoldV4(_ISSUER,config=config,lease=lease,channel=census.channel,
            original=reply,consumer_mode='controlled_sdk')
        result.census=census;_STARTUPS_V4[result]=result._identity_v4()
        return result.require_current()
    except BaseException:
        census.close();raise


def bind_controlled_sdk_initial_genesis_v4(*,initial,startup_hold):
    if (type(startup_hold)is not _InitialStorageStartupHoldV4 or startup_hold.consumer_mode!='controlled_sdk'
            or type(initial)is not VerifiedInitialSegmentedStorageV4 or initial.control.lease is not startup_hold.lease):
        raise AuthorityUnavailable('actual initial SDK genesis/continuous startup hold required')
    startup_hold.require_current()
    request=dict(schema='sylanne.root-controlled-sdk-initial-storage-request.v4',command='bind_initial_genesis_v4',
        held_request_digest=startup_hold.census.original['request_digest'],hold_token=startup_hold.census.original['hold_token'],
        startup_nonce=startup_hold.original['startup_nonce'])
    result=startup_hold._exchange_v4(request)
    expected=require_published_initial_genesis_for_root_v4(bindings=startup_hold.bindings,startup_original=startup_hold.original)
    if result!=expected:raise AuthorityUnavailable('actual Root initial SDK published genesis bind differs')
    startup_hold.bound=result;_STARTUPS_V4[startup_hold]=startup_hold._identity_v4()
    return startup_hold



def initial_fixed_bindings_from_protected_assets_v4(assets,*,inventory_manifest_digest):
    """Closed metadata derivation used by the actual Root producer, never an issuer."""
    installed=assets['c09_storage_v1'];journals=assets['execution_journals'];bindings=assets['namespace_bindings_v2']
    if (assets.get('c09_storage_v2')is not None or len(journals)!=1 or not bindings
            or len({(item['bot_id'],item['persona_id'],item['authority_namespace'])for item in bindings})!=1):
        raise AuthorityUnavailable('Root initial storage requires one actual installed fixed namespace')
    first=bindings[0]
    if journals[0]['namespace']!=first['authority_namespace']:raise AuthorityUnavailable('Root initial journal namespace differs')
    return dict(authority_id=installed['authority_id'],installation_id=installed['installation_id'],control_store_id=installed['control_store_id'],
        namespace=first['authority_namespace'],graph_namespace=dict(bot_id=first['bot_id'],persona_id=first['persona_id']),
        role_paths=dict(core=str(Path(assets['authority_db']).resolve()),deletion=str(Path(assets['deletion_db']).resolve()),
            execution=str(Path(journals[0]['path']).resolve()),graph=str(Path(assets['graph_db']).resolve())),
        control_path=str(Path(installed['control_path']).resolve()),key_path=str(Path(installed['key_path']).resolve()),
        instance_lock_path=str(Path(assets['instance_lock']).resolve()),inventory_manifest_digest=inventory_manifest_digest)


def hold_production_initial_storage_v4(*,config,lease):
    import socket,struct
    from .installed_process_supervisor_v1 import (verify_process_supervisor_spec_v1,_read_selected_invocation,
        _read_peer_start_packet_v3,_require_actual_authority_observation_v4,decode_process_supervisor_observation_v2)
    from .c09_process_identity_v1 import read_process_identity_v1
    census=config.c09_maintenance_factory._peer_registry_census_v3
    if census is None or census.authority_spec_v4 is None:
        raise AuthorityUnavailable('production initial storage needs actual installed Host/Authority Root specs')
    adapter=census.supervisor;spec=census.authority_spec_v4
    verify_process_supervisor_spec_v1(adapter.config);verify_process_supervisor_spec_v1(spec)
    authority_binding=_read_selected_invocation(spec)
    endpoint=Path(adapter.config.control_socket_path);info=endpoint.lstat()
    if not endpoint.is_socket()or info.st_uid!=0 or info.st_mode&0o077:
        raise AuthorityUnavailable('actual protected production Root initial-storage endpoint required')
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        channel.settimeout(max(adapter.config.start_timeout,adapter.config.drain_timeout)+2)
        channel.connect(str(endpoint));pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if pid!=1 or uid!=0 or os.readlink('/proc/1/ns/pid')!=os.readlink('/proc/self/ns/pid'):
            raise AuthorityUnavailable('actual production Root PID1 initial-storage authority required')
        request=dict(verb='initial_storage_hold_v4',service_role='host',expected_invocation_id='',spec_digest=adapter.config.spec_digest)
        channel.sendall(canonical_serialize(request).encode()+b'\n');reply=_read_peer_start_packet_v3(channel,limit=262144)
        fields={'schema','command','consumer_mode','bindings','root_process_original','authority_process_original',
            'resource_original','selection_configuration_digest','startup_nonce','authority_observation','host_observation'}
        if (type(reply)is not dict or set(reply)!=fields or reply['schema']!='sylanne3.c09.initial-storage-startup-held.v4'
                or reply['command']!='initial_storage_held_v4'or reply['consumer_mode']!='production_root'
                or reply['bindings']!=_initial_fixed_bindings_v4(config)):
            raise AuthorityUnavailable('actual Root initial-storage fixed protected reply differs')
        _require_actual_authority_observation_v4(host_spec=adapter.config,authority_spec=spec,
            host_observation=decode_process_supervisor_observation_v2(reply['host_observation']),
            authority_observation=decode_process_supervisor_observation_v2(reply['authority_observation']),authority_binding=authority_binding,
            authority_original=read_process_identity_v1(os.getpid()),launcher_original=read_process_identity_v1(1))
        result=_InitialStorageStartupHoldV4(_ISSUER,config=config,lease=lease,channel=channel,original=reply,
            consumer_mode='production_root',root_spec=spec)
        return result.require_current()
    except BaseException:channel.close();raise


def bind_production_initial_genesis_v4(*,initial,startup_hold):
    from .installed_process_supervisor_v1 import (RootPeerRegistryGenesisHoldV3,_ROOT_GENESIS_HOLD_ISSUER_V3,
        _read_selected_invocation)
    if (type(startup_hold)is not _InitialStorageStartupHoldV4 or startup_hold.consumer_mode!='production_root'
            or type(initial)is not VerifiedInitialSegmentedStorageV4 or initial.control.lease is not startup_hold.lease):
        raise AuthorityUnavailable('actual production initial genesis and continuous startup hold required')
    factory=startup_hold.config.c09_maintenance_factory;census=factory._peer_registry_census_v3
    census.begin(control=initial.control,config=startup_hold.config,context=initial.context)
    request=dict(command='bind_initial_genesis_v4',startup_nonce=startup_hold.original['startup_nonce'],registry_scope=census.scope)
    response=startup_hold._exchange_v4(request)
    if type(response)is not dict or set(response)!={'initial_bind_original','registry_genesis_original'}:
        raise AuthorityUnavailable('Root initial-storage bind did not preserve its actual registry hold')
    expected=require_published_initial_genesis_for_root_v4(bindings=startup_hold.bindings,startup_original=startup_hold.original)
    if response['initial_bind_original']!=expected:raise AuthorityUnavailable('actual production Root initial publication bind differs')
    hold=RootPeerRegistryGenesisHoldV3(_ROOT_GENESIS_HOLD_ISSUER_V3,census.supervisor,startup_hold.channel,
        response['registry_genesis_original'],startup_hold.original['root_process_original'],startup_hold.original['authority_process_original'],
        authority_spec=census.authority_spec_v4,authority_binding=_read_selected_invocation(census.authority_spec_v4))
    hold.require_authority_birth_observation_v4()
    startup_hold.bound=hold;_STARTUPS_V4[startup_hold]=startup_hold._identity_v4()
    census.adopt_initial_genesis_hold_v4(startup_hold,hold)
    return hold


_INITIAL_SDK_ORIGINALS_V4=WeakKeyDictionary()


class VerifiedControlledSDKInitialGenesisOriginalV4:
    """Actual never-listened initial creation closure; distinct from old service closure."""
    def __init__(self,issuer,*,initial,startup,root_descriptor):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual initial SDK creation original issuer required')
        self.initial,self.startup,self.descriptor=initial,startup,root_descriptor
        self.control=initial.control;self.creation=self.control._initial_genesis_creation_v4
        self.authority=startup.original['authority_process_original']
        self.originals=tuple(dict(schema='sylanne3.c09.initial-role-connections-closed.v4',role=role,
            genesis_digest=initial.genesis_digest,member=initial.member(role),startup_digest=canonical_digest(startup.original))for role in ROLES_V4)
        self.root=canonical_digest(('actual_never_started_initial_genesis',self.originals))
        _INITIAL_SDK_ORIGINALS_V4[self]=(id(initial),id(startup),id(root_descriptor),id(self.control),id(self.creation),
            canonical_digest(self.originals),self.root,canonical_digest(self.authority))
    def require_current(self):
        from ..host.c09_controlled_sdk_bootstrap_v3 import _CENSUS_RELEASES_V4
        if _INITIAL_SDK_ORIGINALS_V4.get(self)!=(id(self.initial),id(self.startup),id(self.descriptor),id(self.control),
                id(self.creation),canonical_digest(self.originals),self.root,canonical_digest(self.authority)):
            raise AuthorityUnavailable('actual initial SDK closure private binding changed')
        _require_actual_closed_initial_connections_v4(self.creation)
        census=self.startup.census;census.require_installed_cohort_v3()
        if census.closed:
            if census not in _CENSUS_RELEASES_V4:raise AuthorityUnavailable('initial SDK has no actual Root release acknowledgement')
        else:census.require_current()
        if (self.startup.bound is None or self.startup.bound['genesis_digest']!=self.initial.genesis_digest
                or self.creation.startup is not self.startup or canonical_digest(self.creation.original)!=canonical_digest(self.initial.original)
                or self.startup.config.c09_maintenance_factory._controlled_sdk_registry_assets_v3!=(self.descriptor,self)):
            raise AuthorityUnavailable('actual initial SDK closure lost its bound Root genesis/selected asset contract')
        self.control.lease.require_held()
        return self


def install_controlled_sdk_initial_genesis_original_v4(*,initial,startup_hold,root_descriptor):
    from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKRootDescriptorV3
    if (type(initial)is not VerifiedInitialSegmentedStorageV4 or type(startup_hold)is not _InitialStorageStartupHoldV4
            or startup_hold.consumer_mode!='controlled_sdk'or startup_hold.bound is None
            or type(root_descriptor)is not VerifiedControlledSDKRootDescriptorV3):
        raise AuthorityUnavailable('actual bound initial SDK genesis/Root descriptor required')
    _require_actual_closed_initial_connections_v4(initial.control._initial_genesis_creation_v4)
    factory=startup_hold.config.c09_maintenance_factory
    if factory._controlled_sdk_registry_assets_v3 is not None:
        raise AuthorityUnavailable('actual initial SDK registry assets already installed')
    root_descriptor.require_current(config=startup_hold.config,inventory=factory.inventory,peer=factory.peer)
    original=VerifiedControlledSDKInitialGenesisOriginalV4(_ISSUER,initial=initial,startup=startup_hold,root_descriptor=root_descriptor)
    factory._controlled_sdk_registry_assets_v3=(root_descriptor,original)
    factory._initial_sdk_genesis_census_v4=startup_hold.census
    return original.require_current()


_INITIAL_SDK_CONTRACTS_V4=WeakKeyDictionary()


class VerifiedControlledSDKInitialStorageContractV4:
    """Exact explicit installer request only; no storage/Source/consumer-ready authority."""
    def __init__(self,issuer,*,config,descriptor):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual explicit initial SDK contract issuer required')
        self.config,self.descriptor=config,descriptor
        self.bindings=_initial_fixed_bindings_v4(config)
        _INITIAL_SDK_CONTRACTS_V4[self]=(id(config),id(descriptor),canonical_digest(self.bindings))
    def require_current(self,*,config=None):
        actual=self.config
        if (_INITIAL_SDK_CONTRACTS_V4.get(self)!=(id(actual),id(self.descriptor),canonical_digest(self.bindings))
                or config is not None and config is not actual or self.bindings!=_initial_fixed_bindings_v4(actual)
                or any(Path(path).exists()for path in (*self.bindings['role_paths'].values(),self.bindings['control_path']))):
            raise AuthorityUnavailable('explicit SDK initial-storage request changed or already has durable role files')
        factory=actual.c09_maintenance_factory
        if factory._controlled_sdk_registry_assets_v3!=(self.descriptor,self):
            raise AuthorityUnavailable('explicit SDK initial-storage contract is not the actual installed factory contract')
        self.descriptor.require_current(config=actual,inventory=factory.inventory,peer=factory.peer)
        return self


def install_controlled_sdk_initial_storage_contract_v4(*,config,root_descriptor):
    from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKRootDescriptorV3
    if type(root_descriptor)is not VerifiedControlledSDKRootDescriptorV3:
        raise AuthorityUnavailable('actual Root-protected initial SDK descriptor required')
    factory=config.c09_maintenance_factory
    if factory._controlled_sdk_registry_assets_v3 is not None or factory._peer_registry_census_v3 is not None:
        raise AuthorityUnavailable('initial SDK must explicitly choose its actual untouched factory contract once')
    value=VerifiedControlledSDKInitialStorageContractV4(_ISSUER,config=config,descriptor=root_descriptor)
    factory._controlled_sdk_registry_assets_v3=(root_descriptor,value)
    return value.require_current(config=config)


def prepare_actual_initial_segmented_storage_v4(*,config,lease,fresh_request):
    from ..runtime.d13_consumer_manifest_v3 import _require_fresh_d13_request_v3
    _require_fresh_d13_request_v3(fresh_request,config=config)
    if fresh_request.mode!='prepare':raise AuthorityUnavailable('only the explicit fresh prepare request may create initial storage')
    factory=config.c09_maintenance_factory
    if fresh_request.consumer_mode=='controlled_sdk':
        descriptor,contract=factory._controlled_sdk_registry_assets_v3
        if type(contract)is not VerifiedControlledSDKInitialStorageContractV4:
            raise AuthorityUnavailable('actual explicit SDK initial contract required before O_EXCL creation')
        contract.require_current(config=config)
        startup=hold_controlled_sdk_initial_storage_v4(config=config,lease=lease,root_descriptor=descriptor)
    elif fresh_request.consumer_mode=='production_root':
        startup=hold_production_initial_storage_v4(config=config,lease=lease)
    else:raise AuthorityUnavailable('initial genesis cannot admit an unknown consumer mode')
    try:
        initial=create_initial_segmented_genesis_v4(config=config,startup_hold=startup)
        if startup.consumer_mode=='controlled_sdk':
            bind_controlled_sdk_initial_genesis_v4(initial=initial,startup_hold=startup)
            factory._controlled_sdk_registry_assets_v3=None
            install_controlled_sdk_initial_genesis_original_v4(initial=initial,startup_hold=startup,root_descriptor=descriptor)
        else:bind_production_initial_genesis_v4(initial=initial,startup_hold=startup)
        initial.control._initial_storage_startup_v4=startup
        return initial.control
    except BaseException:
        startup.close();raise


_INITIAL_MAINTENANCE_V4=WeakKeyDictionary()


class VerifiedInitialMaintenanceCompositionV4:
    """Read-only role composition for the actual INTENT/PREPARED initial source."""
    def __init__(self,issuer,*,control,composition,gate,root_census,context,plan,original,manifest):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual initial maintenance composition issuer required')
        self.control,self.composition,self.config,self.gate,self.root_census=control,composition,composition.config,gate,root_census
        self.context,self.plan,self.original,self.manifest=context,plan,original,manifest
        self.operation_id,self.stage=gate._operation,context.stage
        self.gate_identity=(gate._operation,gate._epoch)
        self.namespace=NamespaceId(**plan['namespace']);self.authority_namespace=plan['authority_namespace']
        self.genesis_digest=original['genesis_digest']
        self.selection_digest=canonical_digest(('sylanne3.c09.initial-segmented-selection.v4',self.genesis_digest,
            manifest['manifest_digest'],0,0,self.namespace,control.authority_id,control.installation_id,control.control_store_id))
        self._opened={};self._closed=False
        _INITIAL_MAINTENANCE_V4[self]=self._identity_v4()
    def _identity_v4(self):
        return (id(self.control),id(self.composition),id(self.config),id(self.gate),id(self.root_census),id(self.context),
            canonical_digest((self.plan,self.original,self.manifest)),self.operation_id,self.stage,self.gate_identity,
            self.namespace,self.authority_namespace,self.genesis_digest,self.selection_digest,self._closed,
            tuple(sorted((role,id(db))for role,db in self._opened.items())))
    def member(self,role):
        if role not in ROLES_V4:raise AuthorityUnavailable('exact initial maintenance role required')
        return next(item for item in self.manifest['members']if item['role']==role)
    def require_current(self,*,meter,metadata_only=True):
        from .daemon import _ResolvedStorageCompositionV3
        from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
        from .installed_process_supervisor_v1 import RootPeerStartCoverageHoldV3,RootPeerRegistryGenesisHoldV3
        from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKProcessCensusV3
        from .c09_selected_history_v3 import _bounded
        if (metadata_only is not True or self._closed or _INITIAL_MAINTENANCE_V4.get(self)!=self._identity_v4()
                or type(self.composition)is not _ResolvedStorageCompositionV3 or self.composition.control is not self.control
                or self.composition.config is not self.config or self.composition.context is not self.context
                or self.composition.peer_gate is not self.gate or type(self.gate)is not InstalledC09WriterGateV1
                or self.gate.control is not self.control or self.gate._installed_config_v3 is not self.config
                or self.gate._pending_start_bootstrap_hold_v3 is not self.root_census
                or (self.gate._operation,self.gate._epoch)!=self.gate_identity
                or not self.operation_id or self.gate._active!=0 or self.stage not in {'INTENT','PREPARED'}):
            raise AuthorityUnavailable('actual initial metadata-only maintenance composition/Gate changed')
        self.control.lease.require_held()
        if type(self.root_census)in {RootPeerStartCoverageHoldV3,RootPeerRegistryGenesisHoldV3}:
            self.root_census.require_authority_birth_observation_v4()
        elif type(self.root_census)is VerifiedControlledSDKProcessCensusV3:self.root_census.require_current()
        else:raise AuthorityUnavailable('initial maintenance has no actual same-Root cold bootstrap census')
        if self.gate._closing_continuation is not None:
            self.gate.require_final_continuation_v3(self.gate._closing_continuation,operation_id=self.operation_id,observe=False)
        if _initial_fixed_bindings_v4(self.config)['role_paths']!=self.plan['role_paths']:
            raise AuthorityUnavailable('initial maintenance fixed configured role paths differ')
        with self.control._db()as db:
            current=self.control._c09_control_chain_proof_v2.require_current(db,meter)
            row=_bounded(db,meter).execute('SELECT genesis_digest,plan_digest,manifest_digest FROM c09_initial_segmented_genesis_v4 '
                'WHERE installation_id=?',(self.control.installation_id,)).fetchone()
            if (tuple(row or ())!=(self.genesis_digest,self.plan['plan_digest'],self.manifest['manifest_digest'])
                    or (current['stage'],current['active_operation_id'],current['pointer_version'],current['current_manifest_digest'])!=
                        (self.stage,self.operation_id,0,self.manifest['manifest_digest'])):
                raise AuthorityUnavailable('initial maintenance signed current INTENT/PREPARED source changed')
            if self.stage=='PREPARED':
                from .c09_prepared_storage_v3 import validate_prepared_schema_v3,_read_selected_prepared_payload_v3
                validate_prepared_schema_v3(self.control,db)
                prepared=_bounded(db,meter).execute('SELECT new_manifest_digest FROM c09_storage_operations_v3 '
                    'WHERE operation_id=?',(self.operation_id,)).fetchone()
                if prepared is None:raise AuthorityUnavailable('initial PREPARED metadata composition has no actual signed source transition')
                target=self.control._read_manifest(_bounded(db,meter),prepared[0])
                actual=_read_selected_prepared_payload_v3(self.control,db,target,meter)
                if actual is None or actual['old_manifest_digest']!=self.manifest['manifest_digest']:
                    raise AuthorityUnavailable('initial PREPARED transition has another old source')
        self.control.verify_original_v1(self.original,'genesis_digest')
        for role in ROLES_V4:self.control.verify_member_v1(self.member(role),prepared=False)
        return self
    def require_layout(self,db,role,*,meter):
        self.require_current(meter=meter)
        from .c09_selected_history_v3 import _bounded
        member=self.member(role);layout=self.manifest['segmented_layouts'][role];b=_bounded(db,meter)
        files=b.execute('PRAGMA database_list').fetchall()
        if (len(files)!=1 or files[0][1]!='main'or Path(files[0][2]).resolve()!=Path(member['resolved_path']).resolve()
                or b.execute('SELECT * FROM segmented_storage_layout_v1 WHERE singleton=1').fetchone()!=
                    (1,LAYOUT_SCHEMA,layout['storage_instance_id'],role,LAYOUTS[role],LAYOUT_SCHEMA_DIGEST,
                     self.control.authority_id,self.authority_namespace,self.control.installation_id,0,self.plan['plan_digest'])):
            raise AuthorityUnavailable('actual initial maintenance existing role layout differs')
        for name,ddl in {**DDLS,**TRIGGERS}.items():
            if b.execute('SELECT sql FROM sqlite_master WHERE type=?AND name=?',('table'if name in DDLS else'trigger',name)).fetchone()!=(ddl,):
                raise AuthorityUnavailable('initial maintenance role has a different existing cell schema')
        return self
    def register_role_v4(self,db,role,*,meter):
        self.require_layout(db,role,meter=meter)
        if role in self._opened and self._opened[role]is not db:
            raise AuthorityUnavailable('initial maintenance cannot open a second runtime connection for one role')
        self._opened[role]=db;_INITIAL_MAINTENANCE_V4[self]=self._identity_v4()
        return self
    def close_v4(self):
        self._closed=True;self._opened.clear();_INITIAL_MAINTENANCE_V4.pop(self,None)


def issue_initial_maintenance_composition_v4(control,*,composition,gate,root_census,meter):
    from .daemon import _ResolvedStorageCompositionV3
    if (type(composition)is not _ResolvedStorageCompositionV3 or composition.control is not control
            or composition.peer_gate is not gate or composition.context.stage not in {'INTENT','PREPARED'}):
        raise AuthorityUnavailable('actual initial maintenance cold-bootstrap composition required')
    with control._db()as db:
        plan,original,manifest=_read_signed_initial_metadata_v4(control,db,meter)
    if composition.context.manifest!=manifest:
        raise AuthorityUnavailable('initial maintenance composition does not carry the actual signed initial manifest')
    value=VerifiedInitialMaintenanceCompositionV4(_ISSUER,control=control,composition=composition,gate=gate,
        root_census=root_census,context=composition.context,plan=plan,original=original,manifest=manifest)
    return value.require_current(meter=meter)



def _require_compact_initial_empty_eof_v4(original,plan):
    fields={'schema','role','namespace','storage_instance_id','schema_objects_digest','table_count',
        'table_census_root','bootstrap_metadata_root','eof_digest'}
    values=original['empty_business_eof']
    if type(values)is not dict or tuple(sorted(values))!=ROLES_V4:
        raise AuthorityUnavailable('initial genesis has no complete exact four-role historical empty EOF')
    for role in ROLES_V4:
        value=values[role]
        if (type(value)is not dict or set(value)!=fields or value['schema']!='sylanne3.c09.initial-empty-business-eof.v4'
                or value['role']!=role or value['namespace']!=plan['authority_namespace']
                or value['storage_instance_id']!=plan['role_storage_instance_ids'][role]
                or type(value['table_count'])is not int or value['table_count']<1
                or value['schema_objects_digest']!=original['role_originals'][role]['member']['schema_objects_digest']
                or value['eof_digest']!=canonical_digest({key:item for key,item in value.items()if key!='eof_digest'})):
            raise AuthorityUnavailable('initial historical empty EOF belongs to another actual role/plan/schema')
        for key in ('schema_objects_digest','table_census_root','bootstrap_metadata_root','eof_digest'):_sha(value[key],key)
    return original


_INITIAL_PREPARED_RETIREMENTS_V4=WeakKeyDictionary()


def _initial_prepared_peer_retirement_material_v4(control,gate,context,operation_id,meter):
    from .c09_writer_peer_originals_v3 import (_require_gate,require_writer_quiescence_original_v3,
        require_peer_completion_pending_coverage_v3)
    from .c09_prepared_storage_v3 import validate_prepared_schema_v3,_read_selected_prepared_payload_v3
    from .c09_selected_history_v3 import _bounded
    from .c09_storage_control_v1 import VerifiedStorageOpenContextV1
    _require_gate(control,gate);control.lease.require_held();gate.require_pending_start_bootstrap_scope_v3(meter=meter)
    if (type(context)is not VerifiedStorageOpenContextV1 or context._reader is not control
            or context._capability is not control._capability or context.stage!='PREPARED'
            or context.pointer_version!=0 or context.storage_generation!=0
            or context.manifest['schema']!=INITIAL_MANIFEST_SCHEMA_V4 or gate._operation not in {None,operation_id}
            or gate._active or gate._peers):
        raise AuthorityUnavailable('actual initial PREPARED cold peer retirement metadata source required')
    with control._db()as raw:
        b=_bounded(raw,meter);current=control._c09_control_chain_proof_v2.require_current(raw,meter)
        plan,genesis,manifest=_read_signed_initial_metadata_v4(control,raw,meter)
        if ((current['stage'],current['active_operation_id'],current['pointer_version'],current['current_manifest_digest'])!=
                ('PREPARED',operation_id,0,context.manifest_digest)or manifest!=context.manifest):
            raise AuthorityUnavailable('initial PREPARED metadata source changed its actual signed Control point')
        validate_prepared_schema_v3(control,raw)
        target_row=b.execute('SELECT new_manifest_digest FROM c09_storage_operations_v3 WHERE operation_id=?',(operation_id,)).fetchone()
        if target_row is None:raise AuthorityUnavailable('initial PREPARED has no actual signed compact V3 transition')
        target=control._read_manifest(b,target_row[0]);prepared=_read_selected_prepared_payload_v3(control,raw,target,meter)
        intent_row=b.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=?AND stage='INTENT'",(operation_id,)).fetchone()
        if intent_row is None:raise AuthorityUnavailable('initial PREPARED has no actual original signed INTENT')
        intent=json.loads(intent_row[0]);control.verify_original_v1(intent,'event_digest')
        quiescence=intent['details']['quiescence_original']
        if (prepared is None or prepared['operation_id']!=operation_id or prepared['old_manifest_digest']!=manifest['manifest_digest']
                or prepared['expected_pointer_version']!=0 or target['prior_manifest_digest']!=manifest['manifest_digest']
                or prepared['writer_freeze_digest']!=quiescence['quiescence_digest']):
            raise AuthorityUnavailable('initial PREPARED compact source/quiescence lineage differs')
        completion=require_writer_quiescence_original_v3(control,quiescence,meter=meter,operation_id=operation_id)
        if (completion['manifest_digest']!=manifest['manifest_digest']or completion['pointer_version']!=0
                or completion['storage_generation']!=0 or completion['complete']is not True):
            raise AuthorityUnavailable('initial PREPARED has no signed full old-selection retirement EOF')
        require_peer_completion_pending_coverage_v3(control,completion,meter=meter)
        return completion,prepared['prepared_digest']


def read_initial_prepared_peer_retirement_v4(control,gate,*,operation_id,context,meter):
    from .c09_writer_peer_originals_v3 import VerifiedPreparedPeerRetirementCoverageV3,_VERIFY
    original,prepared_digest=_initial_prepared_peer_retirement_material_v4(control,gate,context,operation_id,meter)
    proof=VerifiedPreparedPeerRetirementCoverageV3(_VERIFY,control,context,original)
    proof.initial_gate_v4=gate
    _INITIAL_PREPARED_RETIREMENTS_V4[proof]=(id(control),id(gate),id(context),canonical_digest(original),prepared_digest)
    return require_initial_prepared_peer_retirement_v4(proof,meter=meter)


def require_initial_prepared_peer_retirement_v4(proof,*,meter):
    from .c09_writer_peer_originals_v3 import VerifiedPreparedPeerRetirementCoverageV3,_VERIFY
    if type(proof)is not VerifiedPreparedPeerRetirementCoverageV3 or proof._issuer is not _VERIFY:
        raise AuthorityUnavailable('actual private initial PREPARED peer retirement proof required')
    binding=_INITIAL_PREPARED_RETIREMENTS_V4.get(proof)
    if binding is None:raise AuthorityUnavailable('initial PREPARED peer retirement has no actual private issuer binding')
    gate=proof.initial_gate_v4
    original,prepared_digest=_initial_prepared_peer_retirement_material_v4(proof.control,gate,proof.context,proof.operation_id,meter)
    if (binding!=(id(proof.control),id(gate),id(proof.context),canonical_digest(original),prepared_digest)
            or proof.original!=original):
        raise AuthorityUnavailable('initial PREPARED retirement changed its actual signed source/Root/EOF')
    return proof
