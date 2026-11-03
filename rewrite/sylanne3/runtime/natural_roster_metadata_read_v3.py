"""Exact no-content Natural roster metadata from committed Core and Graph originals.

A signed Core expected value is compared with the real selected cell header and
origin. Final receipt locators are streamed to canonical EOF; generated batch
text, generation/review frozen bytes and Source Body are never opened here.
"""
from contextlib import contextmanager,closing
from contextvars import ContextVar
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from uuid import uuid4
from weakref import WeakKeyDictionary
import json
import sqlite3

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphReceipt,NamespaceEpoch,Owner
from ..runtime_contracts import canonical_digest
from ..domains.d09.natural_disposition_v1 import (TYPE,natural_disposition_from_wire_v1,natural_disposition_key_v1)

_KEY=object()
_PROOFS=WeakKeyDictionary()
_BOUND=ContextVar('natural_roster_metadata_v3',default=None)
_RETAINED_BOUND_V3=ContextVar('natural_roster_retained_binding_v3',default=None)


class PreparedNaturalRosterMetadataV3:
    def __init__(self,key,service,context,storage,operation,stamp,capsule,head,locators,headers,core_refs,core_facts):
        if key is not _KEY:raise TypeError('actual installed Natural metadata producer required')
        self.service,self.context,self.storage,self.operation=service,context,storage,operation
        self.namespace,self.parent_original_id=capsule.namespace,capsule.parent_original_id
        self.stamp,self.capsule,self.head=stamp,capsule,head
        self.child_locators,self.headers,self.core_refs=locators,headers,core_refs
        self.birth,self.current,self.committed=core_facts
        self.first_locator_metadata=locators.get(capsule.first_operation_id)
        _PROOFS[self]=(service,context,operation,stamp,capsule,head,canonical_digest(locators),tuple(headers),core_refs,self._core_identity_v3())
    def _core_identity_v3(self):
        return tuple(None if value is None else (value.original_ref,value.digest)
            for value in (self.birth,self.current,self.committed))
    def _actual_v3(self):
        if (_PROOFS.get(self)!=(self.service,self.context,self.operation,self.stamp,self.capsule,self.head,
                canonical_digest(self.child_locators),tuple(self.headers),self.core_refs,self._core_identity_v3()) or self.operation.closed):
            raise AuthorityUnavailable('Natural metadata lost its private selected original lifetime')
        self.context.require_current('business')
        return self
    def require_current_v3(self,db,namespace,parent_original_id):
        self._actual_v3()
        if namespace!=self.namespace or parent_original_id!=self.parent_original_id or not db.in_transaction:
            raise AuthorityUnavailable('Natural roster metadata requires its exact current Graph transaction')
        rows=db.execute('PRAGMA database_list').fetchall()
        if len(rows)!=1 or Path(rows[0][2]).resolve(strict=True)!=Path(self.storage['graph_path']).resolve(strict=True):
            raise AuthorityUnavailable('Natural metadata crossed its actual selected Graph file')
        if _stamp_v3(db,namespace)!=self.stamp:
            raise AuthorityUnavailable('Natural metadata Graph revision/epoch changed before consumption')
        for table,columns,where,args,expected in self.headers:
            actual=db.execute('SELECT '+','.join(columns)+' FROM '+table+' WHERE '+where,args).fetchone()
            if actual!=expected:raise AuthorityUnavailable('Natural exact metadata original changed after preparation')
        return self.head
    @contextmanager
    def bind_v3(self,db):
        self.require_current_v3(db,self.namespace,self.parent_original_id)
        token=_BOUND.set((db,self))
        try:yield self
        finally:_BOUND.reset(token)
    def read_child_locator_v3(self,db,operation_id):
        self.require_current_v3(db,self.namespace,self.parent_original_id)
        if operation_id not in {child[1]for child in self.capsule.child_identities}:
            raise AuthorityUnavailable('Natural metadata child is outside the complete actual parent capsule')
        if operation_id not in self.child_locators:
            raise AuthorityUnavailable('Natural child metadata was not prepared before SQL')
        return self.child_locators[operation_id]
    def release_v3(self):
        if self in _PROOFS:
            _PROOFS.pop(self,None)
            self.operation.release()
            self.child_locators.clear();self.headers.clear()
            self.first_locator_metadata=None


def read_bound_natural_roster_metadata_v3(db,namespace,parent_original_id):
    bound=_BOUND.get()
    if bound is None:return False,None
    if bound[0]is not db:raise AuthorityUnavailable('Natural roster metadata binding crossed Graph connection')
    return True,bound[1].require_current_v3(db,namespace,parent_original_id)


def _stamp_v3(db,ns):
    row=db.execute('SELECT graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
    epoch=db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
    if row is None or epoch is None:raise AuthorityUnavailable('Natural metadata Graph stamp unavailable')
    return row[0],epoch[0]


class _RosterMetadataReadV3:
    def __init__(self,service,db,operation,capsule):
        self.service,self.db,self.operation,self.capsule=service,db,operation,capsule
        self.namespace=capsule.namespace
        self.headers=[]
    @contextmanager
    def quantum_v3(self):
        from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3
        with bind_runtime_storage_operation_v3(self.operation,self.db),runtime_storage_quantum_v3(self.db)as meter:
            yield meter
    def fixed_v3(self,table,columns,where,args):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        with self.quantum_v3()as meter:
            row=_runtime_bounded_fixed_row_v3(self.db,meter,table,columns,where,args)
        item=(table,tuple(columns),where,tuple(args),row)
        if item not in self.headers:self.headers.append(item)
        return row
    def cell_v3(self,cell_id,key,expected,producer):
        from ..runtime_storage_v3 import RuntimeCellReadV3,read_runtime_cell_origin_v3
        with self.quantum_v3()as meter:
            cell=RuntimeCellReadV3(self.operation.handle,cell_id,erasure_owner_ref=key.token,meter=meter)
            h=cell.header
            if h[0]not in {'canonical-json.ascii.v1','canonical-json.utf8.v1'}:
                raise AuthorityUnavailable('Natural roster cell has another actual canonical codec')
            wire=json.dumps(expected,sort_keys=True,separators=(',',':'),ensure_ascii=h[0]=='canonical-json.ascii.v1',allow_nan=False).encode('utf8')
            meter.charge_encode(len(wire))
            origin=read_runtime_cell_origin_v3(self.db,cell_id,header=h,meter=meter)
            if ((h[3],h[5])!=(len(wire),sha256(wire).hexdigest())
                    or origin is not None and h[2]!=producer):
                raise AuthorityUnavailable('Natural signed Core metadata differs from selected cell producer/SHA/bytes')
        self.fixed_v3('segmented_cells_v1',('codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
            'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell_id,))
        return h


def _actual_capsule_v3(service,parent,capsule):
    from ..authority_service.d13_cache_use_contract_v2 import (D13NaturalParentInputReceiptV3,
        cache_use_result_from_wire_v3,owner_operation_id_v3)
    from ..authority_service.d13_original_owner_v3 import natural_stage_owner_ref_v3
    from .natural_reply_job_v2 import natural_job_ids_v2
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    ns=service.owner.namespace_id
    ref=natural_stage_owner_ref_v3(ns,natural_job_ids_v2(ns,parent,'review')[0])
    operation=owner_operation_id_v3(ns,ref,'owner_parent_input')
    with service.owner.core._tx()as db,runtime_storage_quantum_v3(db)as meter:
        row=_runtime_bounded_fixed_row_v3(db,meter,'authority_d13_cache_use_operations_v2',
            ('action','request_digest','result_json'),'namespace=? AND operation_id=?',(service.owner.namespace,operation))
    if row is None:raise AuthorityUnavailable('Natural parent has no actual input identity capsule; legacy remains unknown')
    actual=cache_use_result_from_wire_v3(json.loads(row[2]))
    if (type(actual)is not D13NaturalParentInputReceiptV3 or row[:2]!=('owner_parent_input',actual.request_digest)
            or actual.namespace!=ns or actual.authority_namespace!=service.owner.namespace
            or actual.installation_id!=service.owner.installation_id or actual.parent_original_id!=parent
            or actual.owner_ref!=ref or actual.operation_id!=operation or capsule is not None and actual!=capsule):
        raise AuthorityUnavailable('Natural input capsule differs from its exact immutable Core producer')
    return actual


def _core_roster_v3(service,capsule):
    from ..authority_service.natural_disposition_maintenance_v1 import ORIGINAL_TABLE,natural_disposition_original_ref_v1
    from ..authority_service.v2_contract import from_wire
    parent=capsule.parent_original_id
    with service.owner.core._tx()as db:
        rows=db.execute('SELECT payload_json,payload_digest,signature FROM '+ORIGINAL_TABLE+
            " WHERE authority_namespace=? AND installation_id=? AND kind='roster_prepared' "
            "AND json_extract(payload_json,'$.parent_original_id')=? LIMIT 2",
            (service.owner.namespace,service.owner.installation_id,parent)).fetchall()
        if len(rows)>1:raise AuthorityUnavailable('Natural actual Core birth is ambiguous')
        birth=None if not rows else service.originals._decode(rows[0])
    latest=service.originals.latest_committed(parent)
    if birth is None:
        if latest is not None:raise AuthorityUnavailable('Natural latest committed roster has no actual signed birth')
        return None,None,(),(None,None,None)
    if latest is None:raise AuthorityUnavailable('Natural roster birth has no committed/finished terminal; HOLD')
    current=service.originals.read(latest.payload['prepared_original_ref'])
    if current is None:raise AuthorityUnavailable('Natural latest roster has no signed expected payload')
    born=natural_disposition_from_wire_v1(birth.payload['expected_next_value'])
    value=natural_disposition_from_wire_v1(current.payload['expected_next_value'])
    head=(natural_disposition_key_v1(value),value.revision,value)
    service._require_committed_head_v1(head)
    if ((value.parent_original_id,value.generation_original_operation_id,value.review_original_operation_id,
            value.generation_original_digest,value.review_original_digest,value.whole_output_digest,
            value.creation_operation_id)!=(parent,capsule.generation_original_id,capsule.review_original_id,
            capsule.generation_original_digest,capsule.review_original_digest,capsule.whole_output_digest,capsule.first_operation_id)
            or tuple((c.index,c.operation_id,c.effect_id)for c in value.children)!=capsule.child_identities):
        raise AuthorityUnavailable('Natural roster differs from its actual registered parent input capsule')
    for prepared in (birth,current):
        kind='roster_committed'if prepared.kind=='roster_prepared'else'maintenance_committed'
        committed=service.originals.read(natural_disposition_original_ref_v1(service.owner.namespace,
            service.owner.installation_id,parent,kind,prepared.operation_id))
        if committed is None or committed.payload['permit']!=prepared.payload['permit']:
            raise AuthorityUnavailable('Natural committed terminal changed its original prepared permit')
        permit=from_wire(committed.payload['permit'])
        with service.owner.core._tx()as db:
            row=db.execute('SELECT namespace,subject,state,permit FROM authority_v2_fences WHERE operation_id=?',(permit.operation_id,)).fetchone()
        from ..authority_service.v2_contract import decode_bytes
        if (row is None or row[:3]!=(permit.namespace,permit.subject,'finished')
                or decode_bytes(row[3])!=permit):
            raise AuthorityUnavailable('Natural signed committed roster lacks its actual finished Core fence')
    return born,value,(birth.original_ref,birth.digest,current.original_ref,current.digest,latest.original_ref,latest.digest),(birth,current,latest)


def _locator_v3(reader,operation_id,expected_child,born):
    from .natural_dispatch_locator_metadata_v1 import (NaturalDispatchLocatorMetadataColumnV1,
        _OBJECT_FIELDS_V1,_META_KEYS_V1,_RECIPE_KEYS_V1)
    from .owner_material_source_storage_v3 import CanonicalValueStreamV3
    from ..graph_store import GraphStore
    ns=reader.namespace;capsule=reader.capsule
    bundle=reader.fixed_v3('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation_id))
    if bundle is None:
        event=reader.fixed_v3('graph_events',('session','event_id'),
            'bot=? AND persona=? AND event_id=?',(*ns.as_tuple,operation_id))
        admission=reader.fixed_v3('graph_dispatch_admissions',('admission_ref',),
            'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation_id))
        if event is not None or admission is not None:raise AuthorityUnavailable('Natural absent child bundle has partial committed metadata')
        return None
    if bundle[3]<1 or bundle[2]!=expected_child[2]:raise AuthorityUnavailable('Natural child actual bundle/commit identity differs')
    column=NaturalDispatchLocatorMetadataColumnV1(reader,operation_id)
    while not column.complete:
        with reader.quantum_v3()as meter:column.advance(meter)
    raw=column.raw
    if (type(raw)is not dict or set(raw)!=_OBJECT_FIELDS_V1[()] or raw['schema']!='sylanne.natural_dispatch_read_locator.v1'
            or raw['profile_version']!=1 or type(raw['metadata'])is not dict or set(raw['metadata'])!=_META_KEYS_V1):
        raise AuthorityUnavailable('Natural actual final receipt has no complete versioned locator')
    metadata=raw['metadata'];stream=CanonicalValueStreamV3(metadata)
    while not stream.complete:
        with reader.quantum_v3()as meter:stream.read_fragment(meter)
    if (stream.hash.hexdigest(),stream.offset)!=(raw['metadata_sha256'],raw['metadata_byte_count']):
        raise AuthorityUnavailable('Natural locator metadata canonical SHA/bytes differ from actual receipt')
    recipe=metadata['recipe']
    if (metadata['namespace']!=asdict(ns) or metadata['schema']!=raw['schema'] or metadata['profile_version']!=1
            or (metadata['operation_id'],metadata['activity_id'],metadata['effect_id'],metadata['bundle_digest'])
                !=(operation_id,bundle[1],bundle[2],bundle[0])
            or type(recipe)is not dict or set(recipe)!=_RECIPE_KEYS_V1
            or recipe['schema']!='sylanne.natural_dispatch_read_locator_recipe.v1'
            or recipe['kind']!='unsealed_producer_metadata_recipe' or recipe['namespace']!=asdict(ns)
            or recipe['generation_parent_original_id']!=capsule.parent_original_id
            or recipe['generation_original_operation_id']!=capsule.generation_original_id
            or metadata['generation_seal_digest']!=capsule.generation_original_digest
            or metadata['review_seal_digest']!=capsule.review_original_digest):
        raise AuthorityUnavailable('Natural locator is outside its actual capsule/namespace/producer')
    selection=recipe['committed_selection'];paid=recipe['batch']['paid_review'];child=recipe['semantic_child']
    if (selection['operation_id']!=operation_id or selection['activity_id']!=bundle[1]
            or selection['effect_id']!=bundle[2] or selection['admission_ref']!=metadata['admission_ref']
            or (paid['generation_original_operation_id'],paid['review_original_operation_id'],paid['generation_output_digest'])
                !=(capsule.generation_original_id,capsule.review_original_id,capsule.whole_output_digest)
            or child is None or child['selected_index']!=expected_child[0]
            or child['generation_output_digest']!=capsule.whole_output_digest
            or child['plan_ref']!={'ref':capsule.plan_ref,'version':capsule.plan_revision}
            or tuple((c['position'],c['operation_id'],c['effect_id'])for c in child['roster'])!=capsule.child_identities
            or recipe['batch']['payload_digest']!=child['roster'][expected_child[0]]['payload_digest']):
        raise AuthorityUnavailable('Natural locator first-batch/complete child metadata lineage differs')
    if born is not None:
        actual=born.children[expected_child[0]]
        if (recipe['batch']['segment_id'],recipe['batch']['payload_digest'])!=(actual.segment_id,actual.payload_digest):
            raise AuthorityUnavailable('Natural actual batch segment differs from signed Core birth')
    admission=reader.fixed_v3('graph_dispatch_admissions',
        ('operation_id','effect_id','admission_digest','graph_revision','graph_epoch','receipt_digest'),
        'bot=? AND persona=? AND admission_ref=?',(*ns.as_tuple,metadata['admission_ref']))
    if admission!=(operation_id,bundle[2],metadata['admission_digest'],metadata['graph_revision'],metadata['graph_epoch'],metadata['admission_receipt_digest']):
        raise AuthorityUnavailable('Natural locator actual admission commitment differs')
    event=reader.fixed_v3('graph_events',('revisions','invalidated','epoch_revision'),
        'bot=? AND persona=? AND session=? AND event_id=?',(*ns.as_tuple,bundle[1],operation_id))
    if event is None or event[2]!=metadata['graph_epoch']:raise AuthorityUnavailable('Natural locator actual Graph event absent')
    receipt=GraphReceipt('committed',GraphStore._version_rows(event[0]),GraphStore._version_rows(event[1]),NamespaceEpoch(*ns.as_tuple,event[2]))
    if canonical_digest(receipt)!=metadata['graph_receipt_commitment']:
        raise AuthorityUnavailable('Natural actual event differs from locator Graph receipt commitment')
    revisions={v.key.token:v.revision for v in receipt.revisions}
    writes=selection['candidate_writes']
    if type(writes)is not list or len(writes)!=4:raise AuthorityUnavailable('Natural locator complete candidate footprint differs')
    for ref in writes:
        if revisions.get(ref['ref'])!=ref['version']:raise AuthorityUnavailable('Natural locator candidate ref differs from actual event')
        history=reader.fixed_v3('graph_history',('event_bot','event_persona','event_session','event_id','valid','value_cell_id'),
            'token=? AND revision=?',(ref['ref'],ref['version']))
        if history is None or history[:5]!=(*ns.as_tuple,bundle[1],operation_id,1) or history[5]is None:
            raise AuthorityUnavailable('Natural candidate metadata lacks its actual selected history cell')
    batch=AtomKey.from_token(writes[3]['ref'])
    if batch.type_name not in {'d09.natural_verified_segment_batch.v2','d09.natural_verified_segment_batch.v3'}:
        raise AuthorityUnavailable('Natural locator fourth candidate is not its actual batch')
    return metadata


def prepare_authority_natural_roster_metadata_v3(maintenance,*,parent_original_id,capsule=None):
    from ..authority_service.natural_disposition_maintenance_v1 import InstalledNaturalDispositionMaintenanceServiceV1
    from ..runtime_storage_v3 import (bind_runtime_database_from_control_v3,begin_runtime_storage_operation_v3,
        bind_runtime_storage_operation_v3)
    if type(maintenance)is not InstalledNaturalDispositionMaintenanceServiceV1:
        raise AuthorityUnavailable('Natural roster metadata requires its actual installed maintenance service')
    actual=_actual_capsule_v3(maintenance,parent_original_id,capsule)
    born,value,core_refs,core_facts=_core_roster_v3(maintenance,actual)
    context,storage,member=maintenance.owner._storage()
    operation=handle=None
    try:
        with closing(sqlite3.connect(Path(storage['graph_path']).as_uri()+'?mode=ro',uri=True))as db:
            db.execute('PRAGMA query_only=ON')
            handle=bind_runtime_database_from_control_v3(db,control=maintenance.owner.control,role='graph')
            if handle is None:raise AuthorityUnavailable('Natural roster metadata requires actual selected segmented Graph')
            operation=begin_runtime_storage_operation_v3(db,'natural-roster-metadata:'+uuid4().hex,None)
            reader=_RosterMetadataReadV3(maintenance,db,operation,actual)
            db.execute('BEGIN')
            with bind_runtime_storage_operation_v3(operation,db):
                stamp=_stamp_v3(db,actual.namespace)
                plan=AtomKey.from_token(actual.plan_ref)
                key=AtomKey(Owner('activity',*actual.namespace.as_tuple,plan.owner.subject),TYPE,
                    'natural-batch:'+canonical_digest((actual.namespace,parent_original_id))[:40])
                row=reader.fixed_v3('graph_atoms',('revision','valid','value_cell_id'),
                    'token=? AND bot=? AND persona=?',(key.token,*actual.namespace.as_tuple))
                locators={}
                for child in actual.child_identities:
                    locators[child[1]]=_locator_v3(reader,child[1],child,born)
                if value is None:
                    if row is not None or any(v is not None for v in locators.values()):
                        raise AuthorityUnavailable('Natural missing signed birth cannot hide actual Graph projection/child commit')
                    head=None
                else:
                    if natural_disposition_key_v1(value)!=key or row is None or row[:2]!=(value.revision,1)or row[2]is None:
                        raise AuthorityUnavailable('Natural signed Core latest differs from exact selected Graph head')
                    current=core_facts[1]
                    reader.cell_v3(row[2],key,value.to_wire(),current.operation_id)
                    history=reader.fixed_v3('graph_history',('event_id','valid','value_cell_id'),
                        'token=? AND revision=?',(key.token,1))
                    if history is None or history[:2]!=(value.creation_operation_id,1)or history[2]is None:
                        raise AuthorityUnavailable('Natural roster has no actual selected birth history')
                    reader.cell_v3(history[2],key,born.to_wire(),value.creation_operation_id)
                    if locators[actual.first_operation_id]is None:
                        raise AuthorityUnavailable('Natural roster birth has no actual verified first final receipt locator')
                    head=(key,value.revision,value)
                if _stamp_v3(db,actual.namespace)!=stamp:raise AuthorityUnavailable('Natural metadata changed during preparation')
                proof=PreparedNaturalRosterMetadataV3(_KEY,maintenance,context,storage,operation,stamp,actual,head,
                    locators,reader.headers,core_refs,core_facts)
            # Only detached verified metadata survives this independent read.
            # The retained pool lease owns those metadata bytes until release.
            handle.close();handle=None
        maintenance.owner.control.verify_member_v1(member,prepared=False)
        context.require_current('business')
        return proof
    except BaseException:
        if operation is not None:operation.release()
        raise
    finally:
        if handle is not None:handle.close()


# A closed metadata wire: selectors are numbered producer recipes, never SQL
# supplied by a Host, arbitrary DTO or a Source/body permission.
_RPC_SCHEMA_V3='sylanne3.natural-roster-selected-metadata.v3'
_HEADER_RECIPES_V3=(
    ('graph_atoms',('revision','valid','value_cell_id'),'token=? AND bot=? AND persona=?'),
    ('segmented_cells_v1',('codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
        'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?'),
    ('graph_history',('event_id','valid','value_cell_id'),'token=? AND revision=?'),
    ('graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),'bot=? AND persona=? AND operation_id=?'),
    ('graph_events',('session','event_id'),'bot=? AND persona=? AND event_id=?'),
    ('graph_dispatch_admissions',('admission_ref',),'bot=? AND persona=? AND operation_id=?'),
    ('graph_dispatch_admissions',('operation_id','effect_id','admission_digest','graph_revision','graph_epoch','receipt_digest'),
        'bot=? AND persona=? AND admission_ref=?'),
    ('graph_events',('revisions','invalidated','epoch_revision'),'bot=? AND persona=? AND session=? AND event_id=?'),
    ('graph_history',('event_bot','event_persona','event_session','event_id','valid','value_cell_id'),'token=? AND revision=?'),
)
_RPC_FIELDS_V3=frozenset(('schema','namespace','authority_namespace','installation_id','selection_digest',
    'stamp','capsule','head','core_facts','headers','child_locators'))


def natural_roster_metadata_to_wire_v3(prepared):
    if type(prepared)is not PreparedNaturalRosterMetadataV3:
        raise AuthorityUnavailable('actual Authority selected metadata producer required')
    prepared._actual_v3()
    from ..authority_service.d13_cache_use_contract_v2 import cache_use_to_wire_v2
    return dict(schema=_RPC_SCHEMA_V3,namespace=asdict(prepared.namespace),
        authority_namespace=prepared.service.owner.namespace,
        installation_id=prepared.service.owner.installation_id,
        selection_digest=prepared.operation.selection_digest,stamp=list(prepared.stamp),
        capsule=cache_use_to_wire_v2(prepared.capsule),
        head=None if prepared.head is None else prepared.head[2].to_wire(),
        core_facts=[None if value is None else value.to_wire()
            for value in (prepared.birth,prepared.current,prepared.committed)],
        headers=[dict(recipe=_HEADER_RECIPES_V3.index((table,columns,where)),args=list(args),
            expected=None if expected is None else list(expected))
            for table,columns,where,args,expected in prepared.headers],
        child_locators=prepared.child_locators)


def _decode_roster_metadata_rpc_v3(raw,*,namespace,authority_namespace,installation_id,parent_original_id):
    from ..authority_service.d13_cache_use_contract_v2 import D13NaturalParentInputReceiptV3,cache_use_from_wire_v2
    from ..authority_service.natural_disposition_maintenance_v1 import core_original_from_wire_v1
    if (type(raw)is not dict or set(raw)!=_RPC_FIELDS_V3 or raw['schema']!=_RPC_SCHEMA_V3
            or raw['namespace']!=asdict(namespace) or raw['authority_namespace']!=authority_namespace
            or raw['installation_id']!=installation_id):
        raise AuthorityUnavailable('Natural selected metadata RPC differs from its exact paired namespace')
    capsule=cache_use_from_wire_v2(raw['capsule'],D13NaturalParentInputReceiptV3)
    if ((capsule.namespace,capsule.authority_namespace,capsule.installation_id,capsule.parent_original_id)
            !=(namespace,authority_namespace,installation_id,parent_original_id)):
        raise AuthorityUnavailable('Natural metadata RPC lost its actual registered parent capsule')
    stamp=raw['stamp']
    if type(stamp)is not list or len(stamp)!=2 or any(type(v)is not int or v<0 for v in stamp):
        raise AuthorityUnavailable('Natural metadata RPC has no exact Graph revision/epoch')
    if (type(raw['selection_digest'])is not str or len(raw['selection_digest'])!=64
            or type(raw['core_facts'])is not list or len(raw['core_facts'])!=3):
        raise AuthorityUnavailable('Natural metadata RPC selection/Core facts differ')
    facts=tuple(None if value is None else core_original_from_wire_v1(value)for value in raw['core_facts'])
    for value in facts:
        if value is not None and ((value.authority_namespace,value.installation_id,value.parent_original_id)
                !=(authority_namespace,installation_id,parent_original_id)):
            raise AuthorityUnavailable('Natural metadata RPC crossed its actual signed Core original')
    if raw['head']is None:
        if facts!=(None,None,None):raise AuthorityUnavailable('Natural absent head has an actual signed Core roster')
        head=None;core_refs=()
    else:
        value=natural_disposition_from_wire_v1(raw['head'])
        if (any(v is None for v in facts)or facts[0].kind!='roster_prepared'
                or facts[2].kind not in {'roster_committed','maintenance_committed'}
                or facts[1].payload['expected_next_value']!=raw['head']
                or (value.namespace,value.installation_id,value.parent_original_id)
                    !=(namespace,installation_id,parent_original_id)):
            raise AuthorityUnavailable('Natural metadata RPC head differs from its signed committed Core expected value')
        head=(natural_disposition_key_v1(value),value.revision,value)
        core_refs=tuple(item for fact in facts for item in (fact.original_ref,fact.digest))
    locators=raw['child_locators']
    if type(locators)is not dict or set(locators)!={c[1]for c in capsule.child_identities}:
        raise AuthorityUnavailable('Natural metadata RPC lacks its complete exact child locator census')
    if head is None and any(v is not None for v in locators.values()):
        raise AuthorityUnavailable('Natural metadata RPC absence hid a committed child locator')
    if head is not None and locators[capsule.first_operation_id]is None:
        raise AuthorityUnavailable('Natural metadata RPC roster lacks its actual first final locator')
    headers=[]
    if type(raw['headers'])is not list:raise AuthorityUnavailable('Natural metadata RPC header recipes differ')
    for item in raw['headers']:
        if (type(item)is not dict or set(item)!={'recipe','args','expected'}
                or type(item['recipe'])is not int or not 0<=item['recipe']<len(_HEADER_RECIPES_V3)):
            raise AuthorityUnavailable('Natural metadata RPC contains an unregistered metadata selector')
        table,columns,where=_HEADER_RECIPES_V3[item['recipe']]
        if (type(item['args'])is not list or len(item['args'])!=where.count('?')
                or item['expected']is not None and
                    (type(item['expected'])is not list or len(item['expected'])!=len(columns))):
            raise AuthorityUnavailable('Natural metadata RPC fixed metadata row differs')
        headers.append((table,columns,where,tuple(item['args']),
            None if item['expected']is None else tuple(item['expected'])))
    return capsule,head,dict(locators),headers,core_refs,facts,tuple(stamp),raw['selection_digest']


class _HostNaturalRosterMetadataV3(PreparedNaturalRosterMetadataV3):
    def __init__(self,reader,work,port,rpc_result,decoded):
        capsule,head,locators,headers,core_refs,facts,stamp,selection=decoded
        self.reader,self.work,self.port,self.rpc_result=reader,work,port,rpc_result
        self.selection_digest=selection
        path=reader.db.execute('PRAGMA database_list').fetchall()[0][2]
        super().__init__(_KEY,port,reader.operation.handle.context,{'graph_path':path},
            reader.operation,stamp,capsule,head,locators,headers,core_refs,facts)
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.rpc_result.raw,self.child_locators,self.headers,self.core_refs,
            tuple(None if v is None else v.to_wire()for v in (self.birth,self.current,self.committed)),
            asdict(self.capsule),None if self.head is None else self.head[2].to_wire()))
    def _actual_v3(self):
        from .d13_natural_original_use_v3 import _actual_work_v3
        from ..host.v2_fence_port import require_natural_roster_metadata_rpc_v3
        retained=_RETAINED_BOUND_V3.get()
        if retained is None or retained[0]is not self:
            work=_actual_work_v3(self.reader)
        else:
            from .dispatch_initial_source_read_v3 import require_host_natural_roster_retained_binding_v3
            work,operation,scope=require_host_natural_roster_retained_binding_v3(
                retained[2],retained[3],retained[1],self)
            if operation is not self.operation or scope is not self.reader.fence.scope:
                raise AuthorityUnavailable('Natural retained metadata changed its original operation/Source scope')
        if (work is not self.work or self.work.operation is not self.operation
                or self.operation.selection_digest!=self.selection_digest):
            raise AuthorityUnavailable('Natural metadata lost its original same-Work/selected retention')
        require_natural_roster_metadata_rpc_v3(self.rpc_result,port=self.port)
        return super()._actual_v3()
    def require_current_v3(self,db,namespace,parent_original_id):
        retained=_RETAINED_BOUND_V3.get()
        if retained is not None and retained[0]is self:
            if not db.in_transaction:
                raise AuthorityUnavailable('Natural retained metadata consumption requires actual Graph SQL')
            prepared=retained[3]
            from .current_graph_full_read_v3 import PreparedCurrentGraphFullReadV3,SOURCE_METADATA_FAMILY_V3
            if type(prepared)is PreparedCurrentGraphFullReadV3:
                prepared.require_current(self.reader.graph,db,namespace,
                    required_families=frozenset({SOURCE_METADATA_FAMILY_V3}))
            else:prepared.require_current(db,namespace,prepared.query,prepared.projection)
        return super().require_current_v3(db,namespace,parent_original_id)
    def release_v3(self):
        if self in _PROOFS:
            _PROOFS.pop(self,None)
            self.operation.unregister_retained_state_v3(self)
            self.child_locators.clear();self.headers.clear()
            self.first_locator_metadata=None
            self.rpc_result=None


def prepare_host_natural_roster_metadata_v3(reader,rpc_result):
    """Consume the actual paired RPC outside SQL and retain it in this Source Work."""
    from .d13_natural_original_use_v3 import _actual_work_v3
    from ..host.v2_fence_port import require_natural_roster_metadata_rpc_v3
    work=_actual_work_v3(reader)
    if reader.db.in_transaction:raise AuthorityUnavailable('Natural selected metadata RPC must finish outside Graph SQL')
    port=reader.graph._GraphCoordinator__content_fence_v2
    # The installed fence port is the actual sender of this authenticated result.
    raw,actual_port,namespace,authority_namespace,installation_id,parent=require_natural_roster_metadata_rpc_v3(rpc_result)
    if (actual_port is not port or namespace!=reader.namespace
            or authority_namespace!=reader.fence.scope.permit.namespace):
        raise AuthorityUnavailable('Natural metadata RPC belongs to another actual Source Work/paired fence port')
    decoded=_decode_roster_metadata_rpc_v3(raw,namespace=namespace,authority_namespace=authority_namespace,
        installation_id=installation_id,parent_original_id=parent)
    if decoded[-1]!=reader.operation.selection_digest:
        raise AuthorityUnavailable('Natural metadata RPC crossed the original selected storage basis')
    return _HostNaturalRosterMetadataV3(reader,work,actual_port,rpc_result,decoded)


@contextmanager
def _bind_retained_natural_roster_metadata_v3(proof,db,*,reader,prepared):
    """Only the actual FULL/P2 result Binder may retain this private metadata."""
    from .dispatch_initial_source_read_v3 import require_host_natural_roster_retained_binding_v3
    if type(proof)is not _HostNaturalRosterMetadataV3 or proof.reader is not reader:
        raise AuthorityUnavailable('actual originating Host retained metadata proof required')
    work,operation,scope=require_host_natural_roster_retained_binding_v3(reader,prepared,db,proof)
    if (work is not proof.work or operation is not proof.operation or scope is not reader.fence.scope
            or operation.closed or proof.selection_digest!=operation.selection_digest):
        raise AuthorityUnavailable('Natural retained metadata Binder changed its original Work/retention')
    retained_token=_RETAINED_BOUND_V3.set((proof,db,reader,prepared))
    try:
        proof._actual_v3()
        token=_BOUND.set((db,proof))
        try:yield proof
        finally:_BOUND.reset(token)
    finally:_RETAINED_BOUND_V3.reset(retained_token)
