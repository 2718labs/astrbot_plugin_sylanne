"""C09's content-free join from a durable D11 effect to its Source roots."""
from __future__ import annotations

import json
from weakref import WeakSet

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_serialize
from ..runtime.dispatch_graph_claim import DispatchGraphClaimValueV1, dispatch_claim_key
from .contract import AuthorityUnavailable
from .v2_contract import DispatchGraphClaimReceiptV1, from_wire


_ADOPTION_COLUMNS=('bot','persona','final_operation_id','observation_digest','source_ref','slot_ref','batch_ref',
    'observation_json','original_json','original_digest')


def read_d13_outbound_lineage_v3(columns,row,*,authority_namespace):
    from ..runtime_contracts import canonical_digest
    from .observation_refinement_contract_v3 import (from_wire as decode_observation,
        observation_claimed_receipt_v3,observation_original_dispatch_permit_v3,observation_platform_observation_v3)
    from ..memory_types import source_key
    if tuple(columns)!=_ADOPTION_COLUMNS or len(row)!=len(_ADOPTION_COLUMNS):
        raise AuthorityUnavailable('D13 outbound adoption exact columns differ')
    namespace=NamespaceId(row[0],row[1])
    if '/'.join(namespace.as_tuple)!=authority_namespace:
        raise AuthorityUnavailable('D13 outbound adoption crossed its actual Authority namespace')
    try:
        observation_wire=json.loads(row[7]);original=json.loads(row[8])
        if (canonical_serialize(observation_wire)!=row[7] or canonical_serialize(original)!=row[8]
                or canonical_digest(original)!=row[9]):
            raise ValueError('adoption original canonical digest differs')
        observed=decode_observation(observation_wire);claimed=observation_claimed_receipt_v3(observed)
        permit=observation_original_dispatch_permit_v3(observed);platform=observation_platform_observation_v3(observed)
        base={'schema','operation_id','source_ref','slot_ref','batch_ref','pre_epoch','pre_revision','permit',
            'finish_digest','graph_receipt_digest','observation_digest'}
        actual=frozenset(original)
        if actual not in {frozenset(base),frozenset(base|{'trusted_latest_utc','trusted_clock_digest'})}:
            raise ValueError('closed D13 adoption fields differ')
        if (original['schema']!='d13.outbound_adoption.v1' or original['source_ref']!=row[4]
                or original['slot_ref']!=row[5] or original['batch_ref']!=row[6]
                or original['observation_digest']!=row[3] or row[3]!=canonical_digest(observed)
                or type(original['pre_epoch']) is not int or original['pre_epoch']<0
                or type(original['pre_revision']) is not int or original['pre_revision']<0
                or type(original['finish_digest']) is not str or len(original['finish_digest'])!=71
                or not original['finish_digest'].startswith('sha256:')
                or type(original['graph_receipt_digest']) is not str or len(original['graph_receipt_digest'])!=64
                or any(c not in '0123456789abcdef' for c in original['graph_receipt_digest'])):
            raise ValueError('D13 adoption row/source/observation receipt identity differs')
        if actual==frozenset(base|{'trusted_latest_utc','trusted_clock_digest'}):
            import math
            latest=original['trusted_latest_utc'];clock=original['trusted_clock_digest']
            if (type(latest) not in (int,float) or not math.isfinite(latest) or latest<0
                    or type(clock) is not str or len(clock)!=64
                    or any(c not in '0123456789abcdef' for c in clock)):
                raise ValueError('D13 adoption trusted clock original differs')
        expected_source=source_key(*namespace.as_tuple,'outbound:'+canonical_digest((namespace,row[2]))[:48]).token
        expected_operation='d13-outbound:'+canonical_digest((namespace,row[2],row[3]))[:48]
        if (expected_source!=row[4] or original['operation_id']!=expected_operation
                or platform.binding.origin.operation_id!=row[2]
                or platform.binding.origin.namespace!=authority_namespace
                or permit.operation!='dispatch' or permit.operation_id!=row[2]
                or permit.effect_id!=platform.binding.origin.effect_id
                or (claimed.pending.permit.operation_id,claimed.pending.permit.effect_id)!=(row[2],permit.effect_id)
                or platform.binding.graph_namespace!='/'.join(namespace.as_tuple)):
            raise ValueError('D13 outbound dispatch/source lineage differs')
        from .v2_contract import FencePermitV2
        adoption_permit=from_wire(original['permit'])
        if (type(adoption_permit) is not FencePermitV2 or adoption_permit.operation!='write'
                or adoption_permit.operation_id!=expected_operation
                or (adoption_permit.authority_id,adoption_permit.namespace,adoption_permit.subject,
                    adoption_permit.holder,adoption_permit.generation)!=(permit.authority_id,
                    permit.namespace,permit.subject,permit.holder,permit.generation)
                or original['finish_digest']!='sha256:'+canonical_digest((expected_operation,
                    adoption_permit.token,row[3]))):
            raise ValueError('D13 adoption WRITE differs from its separate dispatch causal identity')
        return dict(namespace=authority_namespace,operation_id=row[2],effect_id=permit.effect_id,
            observation_digest=row[3],source_ref=row[4],source_refs=(row[4],),slot_ref=row[5],batch_ref=row[6],
            original_digest=row[9],observation=observed,claim=claimed,dispatch_permit=permit,adoption_permit=adoption_permit)
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,UnicodeError) as exc:
        raise AuthorityUnavailable('D13 outbound adoption lineage cannot be classified') from exc


def _actual_reserved_meter_v3():
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2,require_c09_reserved_meter_v3
    meter=current_c09_sql_meter_v2()
    if require_c09_reserved_meter_v3(meter.budget) is not meter:
        raise AuthorityUnavailable('actual original reserved C09 quantum required')
    return meter


def require_independent_inspection_member_v3(build,member,*,meter):
    """Authenticate this member only; an unrelated retired operation is unnecessary."""
    from ..runtime.c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
    from ..runtime.source_inspection_migration_v1 import SESSION,validate_member_admission_v1
    from ..runtime_contracts import canonical_digest
    if type(build) is not InstalledGraphRebaseBuildV2:
        raise AuthorityUnavailable('actual frozen Graph builder required for inspection membership')
    build.require_current();root=_actual_reserved_meter_v3()
    ns=tuple(json.loads(build.scope.graph_namespace));original=member['original']
    producer=member['producer_operation_id']
    event=root.read_fixed_row(build.pair.source,'graph_events',('digest','epoch_revision','reads','revisions','invalidated'),
        'bot=? AND persona=? AND session=? AND event_id=?',(*ns,SESSION,producer))
    if (event is None or event[0]!=member['receipt']['event_digest']
            or event[1]!=original['after_stamp'][2] or json.loads(event[2])!=original['reads']
            or json.loads(event[3])!=original['writes'] or json.loads(event[4])!=[]):
        raise AuthorityUnavailable('inspection member lacks its actual independent metadata-only event')
    admission=member['admission']
    if admission is None:return
    admission=validate_member_admission_v1(admission)
    control=build.session._control.maintenance.control
    control.verify_original_v1(admission,'admission_digest')
    if (admission['authority_id']!=build.scope.authority_id
            or admission['authority_namespace']!=build.scope.authority_namespace
            or admission['installation_id']!=build.scope.installation_id
            or admission['control_store_id']!=control.control_store_id):
        raise AuthorityUnavailable('independent member certificate crossed its actual Authority installation')
    target=admission['target_ref'];revision=admission['target_revision']
    old=original['target_original'];cell_id=old['target_head'][2]
    history=root.read_fixed_row(build.pair.source,'graph_history',('valid','value_cell_id'),
        'token=? AND revision=? AND event_bot=? AND event_persona=?',(target,revision,*ns))
    if history!=(1,cell_id):
        raise AuthorityUnavailable('signed inspection target is not its actual frozen historical cell')
    physical=build.session.begin_source_physical_read_v3(build.pair,meter=root)
    header=physical.read_cell_header_v3(cell_id,meter=root)
    if tuple(header[1:])!=tuple(old['target_header']) or canonical_digest(tuple(header[1:]))!=admission['target_header_digest']:
        raise AuthorityUnavailable('signed inspection target header differs from the actual qualified Source')
    metadata=root.read_fixed_row(build.pair.source,'graph_history',('valid','value_cell_id','dependencies'),
        'token=? AND revision=? AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?',
        (admission['metadata_ref'],1,*ns,SESSION,producer))
    if metadata is None or metadata[0]!=1 or json.loads(metadata[2])!=[[target,revision]]:
        raise AuthorityUnavailable('inspection metadata lacks its exact target dependency/current producer history')
    output=physical.read_cell_header_v3(metadata[1],meter=root)
    if output[2]!=admission['metadata_ref'] or output[3]!=producer:
        raise AuthorityUnavailable('inspection metadata physical producer differs from its signed member')
    from hashlib import sha256
    from ..contracts import canonical_json
    from ..domains.d06.inspection_metadata_v1 import SOURCE_TYPE,INTERPRETATION_TYPE
    from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
    key=AtomKey.from_token(target)
    value=dict(schema=SOURCE_TYPE if key.type_name=='memory.source' else INTERPRETATION_TYPE,
        target_ref=target,target_revision=revision,target_codec=old['target_header'][0],
        target_sha256=old['target_header'][5],target_bytes=old['target_header'][3],
        target_semantic_digest=old['semantic_digest'],producer_operation_id=producer,metadata=old['metadata'])
    upper=c09_canonical_json_size_v3(value,ascii=True,exact=True)
    root.require_available(upper*2)
    encoded=canonical_json(value).encode('ascii');root.charge_encode(len(encoded)*2)
    if output[4]!=len(encoded) or output[6]!=sha256(encoded).hexdigest():
        raise AuthorityUnavailable('actual metadata payload differs from its signed fixed nontext projection')
    build.require_current()


def read_frozen_terminal_inspection_resolution_v3(transform,operation_id,*,meter):
    """Read only the same-scope frozen Core; never reopen the installed live Core."""
    from .c09_authority_storage_rebase_v2 import _AuthorityRowTransformV2
    from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
    from .source_inspection_workflow_v1 import TABLE,COLUMNS,validate_inspection_workflow_core_row_v1
    from .source_inspection_held_reconciliation_v1 import (ACCEPT_SCHEMA,LINK_SCHEMA,
        validate_resolution_v1,hold_snapshot_digest_v1)
    if (type(transform) is not _AuthorityRowTransformV2 or type(transform.pair) is not InstalledC09RolePairV2
            or transform.pair.source_original.role!='core'
            or transform.pair._producer.session is not transform.basis.session
            or transform.pair.source_original.scope_digest!=transform.scope.scope_digest):
        raise AuthorityUnavailable('terminal recovery needs its actual frozen Core pair')
    transform.basis.require_current();transform.pair.require_current();root=_actual_reserved_meter_v3()
    db=transform.pair.source;namespace=transform.scope.authority_namespace
    control=transform.basis.session._control.maintenance.control
    def checked_row(identity):
        row=root.read_fixed_row(db,TABLE,COLUMNS,'namespace=? AND operation_id=?',(namespace,identity))
        if row is None:raise AuthorityUnavailable('frozen recovery resolution lost its actual parent row')
        value=validate_inspection_workflow_core_row_v1(COLUMNS,row,authority_namespace=namespace)
        accepted=value['accepted_original'];control.verify_original_v1(accepted,'accepted_digest')
        if accepted['installation_id']!=transform.scope.installation_id:
            raise AuthorityUnavailable('frozen recovery crossed installation')
        return row,accepted
    current=operation_id;seen=set()
    while current not in seen:
        seen.add(current);root.require_available(4096)
        where=("namespace=? AND json_extract(accepted_json,'$.schema')=? AND progress_json IS NOT NULL "
            "AND (json_extract(input_json,'$.parent_workflow_operation_id')=? "
            "OR json_extract(progress_json,'$.parent_child_operation_id')=?)")
        args=(namespace,ACCEPT_SCHEMA,current,current)
        first=root.read_fixed_row(db,TABLE,('operation_id',),where+' ORDER BY operation_id COLLATE BINARY',args)
        if first is None:return None
        second=root.read_fixed_row(db,TABLE,('operation_id',),
            where+' AND operation_id COLLATE BINARY>? ORDER BY operation_id COLLATE BINARY',(*args,first[0]))
        if second is not None:raise AuthorityUnavailable('multiple frozen signed recoveries replace one operation')
        row,accepted=checked_row(first[0]);link=validate_resolution_v1(json.loads(row[9]),accepted)
        control.verify_original_v1(link,'resolution_digest')
        parent,parent_original=checked_row(link['parent_workflow_operation_id'])
        if (parent[6]!='held' or parent[4]!=link['parent_accepted_digest']
                or hold_snapshot_digest_v1(parent)!=link['parent_hold_digest']
                or current not in {parent[1],link['parent_child_operation_id']}):
            raise AuthorityUnavailable('frozen signed resolution differs from its immutable held parent')
        if link['kind']=='resolution':
            if row[6]!='completed':raise AuthorityUnavailable('frozen recovery resolution is not terminal')
            return dict(replaced_operation_id=operation_id,terminal_recovery_operation_id=row[1],resolution=link)
        current=row[1]
    raise AuthorityUnavailable('frozen inspection recovery chain has a cycle')


def require_inspection_core_graph_join_v3(transform,columns,row,*,meter):
    """The independent final Core phase owns OPS/accepted joins."""
    from .c09_authority_storage_rebase_v2 import _AuthorityRowTransformV2
    from .source_inspection_migration_v1 import (COLUMNS as CORE_COLUMNS,
        validate_source_inspection_migration_core_row_v1)
    from .source_inspection_workflow_v1 import (TABLE as WORKFLOWS,COLUMNS as WORKFLOW_COLUMNS,
        validate_inspection_workflow_core_row_v1)
    from ..runtime.source_inspection_migration_v1 import (OPERATIONS,COLUMNS as GRAPH_COLUMNS,
        validate_source_inspection_migration_row_v1)
    if type(transform) is not _AuthorityRowTransformV2 or columns!=CORE_COLUMNS:
        raise AuthorityUnavailable('actual final Core migration row/transform required')
    transform.pair.require_current();transform.basis.require_current();root=_actual_reserved_meter_v3()
    namespace=transform.scope.authority_namespace
    accepted=validate_source_inspection_migration_core_row_v1(columns,row,authority_namespace=namespace)
    control=transform.basis.session._control.maintenance.control
    control.verify_original_v1(accepted['accepted_original'],'accepted_digest')
    graph=transform.basis.session.require_actual_post_mirror_graph_v3();graph.require_current()
    ns=tuple(json.loads(transform.scope.graph_namespace))
    graph_row=root.read_fixed_row(graph.pair.source,OPERATIONS,GRAPH_COLUMNS[OPERATIONS],
        'bot=? AND persona=? AND operation_id=?',(*ns,accepted['operation_id']))
    if graph_row is None:
        if accepted['state']=='completed' or read_frozen_terminal_inspection_resolution_v3(
                transform,accepted['operation_id'],meter=meter) is None:
            raise AuthorityUnavailable('Core migration lacks Graph original or a signed no-child terminal resolution')
    else:
        actual=validate_source_inspection_migration_row_v1(OPERATIONS,GRAPH_COLUMNS[OPERATIONS],graph_row,
            authority_namespace=namespace)
        if (actual['accepted_digest']!=accepted['accepted_digest'] or actual['request']!=accepted['request']
                or actual['request_digest']!=accepted['request_digest']):
            raise AuthorityUnavailable('frozen Graph/Core migration originals differ')
    digest=accepted['accepted_original'].get('workflow_accepted_digest')
    if digest is not None:
        where='namespace=? AND accepted_digest=?'
        args=(namespace,digest)
        first=root.read_fixed_row(transform.pair.source,WORKFLOWS,('operation_id',),
            where+' ORDER BY operation_id COLLATE BINARY',args)
        if first is None or root.read_fixed_row(transform.pair.source,WORKFLOWS,('operation_id',),
                where+' AND operation_id COLLATE BINARY>? ORDER BY operation_id COLLATE BINARY',(*args,first[0])) is not None:
            raise AuthorityUnavailable('child migration lacks one exact frozen accepted-digest workflow')
        parent_row=root.read_fixed_row(transform.pair.source,WORKFLOWS,WORKFLOW_COLUMNS,
            'namespace=? AND operation_id=?',(namespace,first[0]))
        parent=validate_inspection_workflow_core_row_v1(WORKFLOW_COLUMNS,parent_row,authority_namespace=namespace)
        original=parent['accepted_original'];control.verify_original_v1(original,'accepted_digest')
        if (original.get('source_request')!=accepted['request']
                or original['owner_head']!=accepted['owner_head'] or parent['accepted_digest']!=digest):
            raise AuthorityUnavailable('actual workflow does not authorize this distinct migration child')
    transform.pair.require_current();graph.require_current()

class _InspectionCoreReverseReadV3:
    """Independent exact-PK Graph OPS EOF against the final frozen Core."""
    def __init__(self,issuer,builder):
        if issuer is not _INSPECTION_REVERSE_ISSUER_V3:
            raise AuthorityUnavailable('actual inspection reverse issuer required')
        from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
        if type(builder) is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role!='core':
            raise AuthorityUnavailable('actual final Core role builder required')
        builder.require_current()
        self.builder=builder;self.graph=builder.session.require_actual_post_mirror_graph_v3()
        self.graph.require_current();self.after=None;self.count=0;self.complete=False
        from ..runtime_contracts import canonical_digest
        self.root=canonical_digest(('sylanne3.c09.inspection-core-reverse.v3',builder.scope.scope_digest,
            builder.pair.source_original.role_source_digest,self.graph.pair.source_original.role_source_digest))
        _INSPECTION_REVERSE_READERS_V3.add(self)
        builder.session._control.maintenance.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        return 4096+(0 if self.after is None else len(self.after.encode('utf-8')))

    def require_complete_v3(self,builder):
        if (self not in _INSPECTION_REVERSE_READERS_V3 or self.builder is not builder or not self.complete
                or self.graph is not builder.session.require_actual_post_mirror_graph_v3()):
            raise AuthorityUnavailable('complete independent inspection Core/Graph reverse EOF required')
        builder.require_current();self.graph.require_current()
        return self.root,self.count

    def advance_v3(self):
        from copy import copy
        from . import c09_authority_storage_rebase as legacy
        from .source_inspection_migration_v1 import TABLE as CORE,COLUMNS as CORE_COLUMNS
        from ..runtime.source_inspection_migration_v1 import OPERATIONS,COLUMNS as GRAPH_COLUMNS
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
        from ..runtime_contracts import canonical_digest
        if self not in _INSPECTION_REVERSE_READERS_V3:
            raise AuthorityUnavailable('actual inspection reverse Source cursor required')
        self.builder.require_current();self.graph.require_current();meter=_actual_reserved_meter_v3()
        result=copy(self);_INSPECTION_REVERSE_READERS_V3.add(result)
        self.builder.session._control.maintenance.control.register_c09_retained_state_v3(result)
        ns=tuple(json.loads(self.builder.scope.graph_namespace))
        with legacy_cell_read_transaction_v2(self.graph.pair.source),legacy_cell_read_transaction_v2(self.builder.pair.source):
            exists=meter.read_fixed_row(self.graph.pair.source,'sqlite_master',('name',),
                'type=? AND name=?',('table',OPERATIONS))
            if exists is None:
                result.complete=True
                return result
            identity=meter.read_fixed_row(self.graph.pair.source,OPERATIONS,('operation_id',),
                'bot=? AND persona=? AND operation_id COLLATE BINARY>? ORDER BY operation_id COLLATE BINARY',
                (*ns,'' if self.after is None else self.after))
            if identity is None:
                result.complete=True
                return result
            operation=identity[0]
            old=meter.read_fixed_row(self.graph.pair.source,OPERATIONS,GRAPH_COLUMNS[OPERATIONS],
                'bot=? AND persona=? AND operation_id=?',(*ns,operation))
            row=meter.read_fixed_row(self.builder.pair.source,CORE,CORE_COLUMNS,
                'namespace=? AND operation_id=?',(self.builder.scope.authority_namespace,operation))
            if row is None:raise AuthorityUnavailable('orphan frozen Graph inspection OPS lacks actual Core acceptance')
            require_inspection_core_graph_join_v3(self.builder.transform,CORE_COLUMNS,row,meter=meter)
            if row[7]!='completed' and read_frozen_terminal_inspection_resolution_v3(
                    self.builder.transform,operation,meter=meter) is None:
                raise AuthorityUnavailable('unfinished Graph inspection OPS has no actual frozen terminal replacement')
            graph_commitment=legacy._row_commitment(OPERATIONS,GRAPH_COLUMNS[OPERATIONS],old)
            core_commitment=legacy._row_commitment(CORE,CORE_COLUMNS,row)
            meter.charge_encode(len(legacy._canonical((OPERATIONS,GRAPH_COLUMNS[OPERATIONS],
                tuple(legacy._cell(value) for value in old)))))
            meter.charge_encode(len(legacy._canonical((CORE,CORE_COLUMNS,tuple(legacy._cell(value) for value in row)))))
            result.count+=1;result.after=operation
            result.root=canonical_digest(('sylanne3.c09.inspection-core-reverse-member.v3',
                self.root,result.count,operation,graph_commitment,core_commitment))
        self.builder.require_current();self.graph.require_current()
        return result


_INSPECTION_REVERSE_ISSUER_V3=object()
_INSPECTION_REVERSE_READERS_V3=WeakSet()


def advance_inspection_core_reverse_v3(builder):
    state=builder.inspection_core_reverse_v3
    if state is None:state=_InspectionCoreReverseReadV3(_INSPECTION_REVERSE_ISSUER_V3,builder)
    builder._pending_inspection_core_reverse_v3=state.advance_v3()
    return builder._pending_inspection_core_reverse_v3.complete


def require_inspection_core_reverse_v3(builder):
    state=builder.inspection_core_reverse_v3
    if type(state) is not _InspectionCoreReverseReadV3:
        raise AuthorityUnavailable('actual inspection reverse Core proof required')
    return state.require_complete_v3(builder)


class _LineageJSONReadV3:
    """The registered C09 JSON stream; fixed metadata and hashes only."""
    def __init__(self,owner,tag,table,column,keys,key,*,paths=((),),omit_text=False):
        from .c09_owner_reply_disposition_v3 import _OwnerReplyJSONReadV3
        self.owner,self.tag=owner,tag
        self.inner=_OwnerReplyJSONReadV3(owner,table,column,keys,key,paths=paths)
        self.omit_text=omit_text
        self.starts={};self.spans={};self.top_fields=set()
        self.complete=False
        self.scalar_digests={};self.scalar_chars={};self.opaque={}

    def _source_heap_bytes(self):
        from .c09_owner_reply_disposition_v3 import _metadata_heap_v3
        return 8192+_metadata_heap_v3((self.inner.values,self.inner.nodes,self.inner.scalar,
            self.inner.starts,self.inner.spans,self.starts,self.spans,self.top_fields,self.scalar_digests,self.scalar_chars))

    def advance_v3(self,meter):
        from .c09_owner_reply_disposition_v3 import _OwnerReplyJSONReadV3
        from .c09_paged_recovery_facts_v2 import _C09ReadonlyPointMeterV3
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        from ..runtime_contracts import canonical_digest
        from copy import copy
        root=_actual_reserved_meter_v3();point=_C09ReadonlyPointMeterV3(root)
        self.owner.require_current_v3()
        self.owner.control.require_c09_retained_arena_v3(meter=root,additional_bytes=self._source_heap_bytes()+65536)
        result=copy(self);result.starts=dict(self.starts);result.spans=dict(self.spans);result.top_fields=set(self.top_fields)
        result.scalar_digests=dict(self.scalar_digests);result.scalar_chars=dict(self.scalar_chars)
        result.opaque={}
        import codecs
        for path,(hasher,decoder,count,high) in self.opaque.items():
            clone=codecs.getincrementaldecoder('unicode_escape')()
            clone.setstate(decoder.getstate())
            result.opaque[path]=(hasher.copy(),clone,count,high)
        inner=self.inner.copy();result.inner=inner
        def event(value):
            path=value.path
            tracked=(len(path)==1 or path in {('segment','body'),('segments',0,'body'),('approved_literal',)})
            if tracked and value.kind in {'object_start','array_start','scalar_start'}:
                result.starts[path]=value.start_offset
                if len(path)==1:result.top_fields.add(path[0])
            elif tracked and value.kind in {'object_end','array_end','scalar_end'}:
                result.spans[path]=(result.starts.pop(path),value.end_offset)
            if result.omit_text and path[:2]==('semantic_manifest','generation_output'):return
            if result.omit_text and any(part in {'body','text','approved_literal','semantic_scope','deliverable_literal'} for part in path):
                if value.kind=='scalar_start':
                    if value.scalar_kind!='string':raise AuthorityUnavailable('opaque producer text is not an actual string')
                    from hashlib import sha256
                    result.opaque[path]=(sha256(),codecs.getincrementaldecoder('unicode_escape')(),0,False)
                elif value.kind=='scalar_chunk':
                    hasher,decoder,count,high=result.opaque[path];hasher.update(value.raw)
                    for char in decoder.decode(value.raw):
                        code=ord(char)
                        if not (high and 0xdc00<=code<=0xdfff):count+=1
                        high=0xd800<=code<=0xdbff
                    result.opaque[path]=(hasher,decoder,count,high)
                elif value.kind=='scalar_end':
                    hasher,decoder,count,high=result.opaque.pop(path)
                    if decoder.decode(b'',final=True):raise AuthorityUnavailable('opaque text escape EOF differs')
                    result.scalar_digests[path]=hasher.hexdigest();result.scalar_chars[path]=count-2
                return
            _OwnerReplyJSONReadV3._event(inner,value)
        graph=self.owner.builder.pair.source
        if inner.length is None:
            shape=read_c09_table_shape_v2(graph,inner.table,meter=point)
            if inner.column=='value' and 'value_cell_id' in shape.columns:
                row=root.read_fixed_row(graph,inner.table,('value_cell_id',),inner.where,inner.key)
                if row is None:raise AuthorityUnavailable('actual lineage Source cell disappeared')
                inner.physical=self.owner.builder.session.begin_source_physical_read_v3(self.owner.builder.pair,meter=root)
                inner.header=inner.physical.read_cell_header_v3(row[0],meter=root)
                if inner.header[1]!='canonical-json.ascii.v1' or inner.header[2]!=inner.key[0]:
                    raise AuthorityUnavailable('lineage Source physical codec/owner differs')
                inner.length=inner.header[4]
                inner.physical_root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',inner.header[0]))
            else:inner._read(0,0,point)
        elif inner.offset<inner.length:
            amount=min(1024,inner.length-inner.offset)
            if inner.header is None:raw=inner._read(inner.offset,amount,point)
            else:
                segment=inner.physical.read_cell_segment_v3(inner.header[0],inner.physical_ordinal,meter=root)
                if segment is None or segment[0]!=inner.offset:
                    raise AuthorityUnavailable('lineage Source physical segment order differs')
                raw=segment[1];amount=len(raw)
                inner.physical_root=canonical_digest(('sylanne3.segmented-cell-link.v1',inner.physical_root,
                    inner.header[0],inner.physical_ordinal,inner.offset,amount,segment[2]))
                inner.physical_ordinal+=1
            inner.parser.feed(raw,event);inner.parser._emit_callback=None;inner.offset+=amount
        else:
            eof=inner.parser.finish()
            if eof.byte_count!=inner.length or result.starts or result.opaque:
                raise AuthorityUnavailable('lineage Source did not reach exact canonical EOF')
            if inner.header is not None:
                inner.physical.require_cell_eof_v3(inner.header[0],inner.physical_ordinal,meter=root)
                if (inner.physical_ordinal,inner.offset,eof.sha256,inner.physical_root)!=(
                        inner.header[5],inner.header[4],inner.header[6],inner.header[7]):
                    raise AuthorityUnavailable('lineage Source EOF/hash/ordered root differs')
            inner.digest=eof.sha256;inner.complete=True;result.complete=True
        self.owner.require_current_v3()
        self.owner.control.require_c09_retained_arena_v3(meter=root)
        return result

    def value_v3(self,path=()):
        if not self.complete:raise AuthorityUnavailable('complete Source metadata EOF required')
        return self.inner.values[path]


class _LineageSpanHashV3:
    def __init__(self,owner,column,pieces):
        from hashlib import sha256
        self.owner,self.column,self.pieces=owner,column,tuple(pieces)
        self.index=0;self.offset=0;self.hash=sha256();self.complete=False;self.digest=None

    def _source_heap_bytes(self):return 4096+sum(len(x) if type(x) is bytes else 64 for x in self.pieces)

    def advance_v3(self,meter):
        from copy import copy
        from .c09_paged_recovery_facts_v2 import _C09ReadonlyPointMeterV3
        self.owner.require_current_v3();root=_actual_reserved_meter_v3()
        result=copy(self);result.hash=self.hash.copy()
        if result.index==len(result.pieces):
            result.complete=True;result.digest=result.hash.hexdigest();return result
        part=result.pieces[result.index]
        if type(part) is bytes:
            root.require_available(len(part));root.charge_encode(len(part));result.hash.update(part)
            result.index+=1;result.offset=0
        else:
            left,right=result.column.spans[part];amount=min(1024,right-left-result.offset)
            if amount:
                raw=result.column.inner._read(left+result.offset,amount,_C09ReadonlyPointMeterV3(root))
                result.hash.update(raw);result.offset+=amount
            else:result.index+=1;result.offset=0
        self.owner.require_current_v3()
        return result


_GRAPH_LINEAGE_ISSUER_V3=object()
_GRAPH_LINEAGE_READERS_V3=WeakSet()


class _GraphDispatchSourceLineageReadV3:
    """Graph-only dependency evidence. It does not authenticate a Core fact."""
    def __init__(self,issuer,build,shape,key):
        from ..runtime.c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        from ..runtime.c09_paged_sql_v2 import c09_row_commitment_v2
        if issuer is not _GRAPH_LINEAGE_ISSUER_V3 or type(build) not in (InstalledGraphRebaseBuildV2,_FinalGraphSourceLineageScopeV3):
            raise AuthorityUnavailable('actual frozen Graph Source lineage issuer required')
        build.require_current()
        self.builder=self.verified=build
        self.control=build.session._control.maintenance.control
        self.namespace=NamespaceId(*json.loads(build.scope.graph_namespace))
        self.shape,self.key=shape,tuple(key)
        self.phase='claim';self.column=None;self.columns={};self.hash_read=None;self.hashes={}
        self.claim=None;self.bundle=None;self.event=None;self.candidate=None;self.refs=()
        self.member_index=0;self.members=[];self.queue=[];self.family=None
        self.roots=();self.complete=False;self.original=None;self.receipt_original=None
        self.named_use=None;self.named_scope=None;self.source_proofs=[];self.after_hash_phase=None
        self.proof_parents={};self.census_versions={};self.census_heads={}
        self.admission_write_index=0;self.census_head_count=0;self.snapshot_profile=None
        _GRAPH_LINEAGE_READERS_V3.add(self);self.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from .c09_owner_reply_disposition_v3 import _metadata_heap_v3
        return 16384+_metadata_heap_v3((self.key,self.claim,self.bundle,self.event,self.candidate,self.refs,
            self.members,self.queue,self.original,self.receipt_original,self.named_use,self.named_scope,
            self.source_proofs,self.hashes,self.proof_parents,self.census_versions,self.census_heads,getattr(self,'action',None),getattr(self,'schema',None),getattr(self,'grant',None)))+sum(x._source_heap_bytes() for x in self.columns.values())+(
                0 if self.column is None else self.column._source_heap_bytes())+(
                0 if self.hash_read is None else self.hash_read._source_heap_bytes())

    def require_current_v3(self):
        if self not in _GRAPH_LINEAGE_READERS_V3 or self.verified is not self.builder:
            raise AuthorityUnavailable('private actual Graph dependency Source reader required')
        self.builder.require_current()
        if self.builder.scope.scope_digest!=self.builder.pair.source_original.scope_digest:
            raise AuthorityUnavailable('Graph dependency proof crossed its frozen scope')
        return self

    def _begin(self,tag,table,column,keys,key,*,paths=((),),omit_text=False):
        self.column=_LineageJSONReadV3(self,tag,table,column,keys,key,paths=paths,omit_text=omit_text)

    def _history(self,tag,ref,revision,root,*,same_event=False,paths=((),),omit_text=False):
        key=AtomKey.from_token(ref)
        if NamespaceId.from_key(key)!=self.namespace or type(revision) is not int or revision<1:
            raise AuthorityUnavailable('producer history crossed namespace/version')
        where='token=? AND revision=? AND event_bot=? AND event_persona=?'
        args=(ref,revision,*self.namespace.as_tuple)
        row=root.read_fixed_row(self.builder.pair.source,'graph_history',('valid','event_session','event_id'),where,args)
        if row is None or row[0]!=1 or same_event and row[1:]!=(self.claim.activity_id,self.claim.operation_id):
            raise AuthorityUnavailable('producer member lost its exact historical W01 origin')
        self._begin(tag,'graph_history','value',('token','revision'),(ref,revision),paths=paths,omit_text=omit_text)

    def _batch_hash(self):
        from ..runtime_contracts import canonical_serialize
        column=self.columns['member:3'];pieces=[b'{']
        for index,name in enumerate(sorted(column.top_fields-{'batch_digest'})):
            if index:pieces.append(b',')
            pieces.extend((canonical_serialize(name).encode('ascii')+b':',(name,)))
        pieces.append(b'}');self.hash_read=_LineageSpanHashV3(self,column,pieces)
        self.phase='batch_hash'

    def advance_v3(self,meter):
        from ..graph_types import GraphVersion
        from ..runtime_contracts import canonical_digest,canonical_serialize
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
        self.require_current_v3();root=_actual_reserved_meter_v3()
        self.control.require_c09_retained_arena_v3(meter=root,additional_bytes=65536)
        if self.complete:return True
        if self.column is not None:
            self.column=self.column.advance_v3(root)
            if self.column.complete:self.columns[self.column.tag]=self.column;self.column=None
            return False
        if self.hash_read is not None:
            self.hash_read=self.hash_read.advance_v3(root)
            if self.hash_read.complete:
                self.hashes[self.phase]=self.hash_read.digest;self.hash_read=None
                self.phase=self.after_hash_phase or {'batch_hash':'payload_hash_prepare','payload_hash':'identity'}.get(self.phase)
                self.after_hash_phase=None
                if self.phase is None:raise AuthorityUnavailable('unknown registered lineage hash phase')
            return False
        db=self.builder.pair.source;ns=self.namespace.as_tuple
        if self.phase=='claim':
            if 'claim' not in self.columns:
                self._begin('claim',self.shape.table,'value',self.shape.primary_key_columns,self.key);return False
            self.claim=DispatchGraphClaimValueV1(**self.columns['claim'].value_v3())
            key=AtomKey.from_token(self.key[0])
            if self.shape.table=='graph_atoms':
                head=root.read_fixed_row(db,'graph_atoms',('revision','valid'),'token=?',(key.token,))
                if head!=(1,1):raise AuthorityUnavailable('immutable dispatch claim current head is not its authenticated birth')
            if (self.claim.authority_namespace!=self.builder.scope.authority_namespace
                    or key!=dispatch_claim_key(self.namespace,self.claim.effect_id)
                    or (self.claim.bot_id,self.claim.persona_id)!=ns):
                raise AuthorityUnavailable('actual Graph claim differs from effect/namespace key')
            history=root.read_fixed_row(db,'graph_history',('valid','event_session','event_id'),
                'token=? AND revision=? AND event_bot=? AND event_persona=?',(key.token,1,*ns))
            if history!=(1,self.claim.activity_id,'dispatch-claim:'+self.claim.effect_id):
                raise AuthorityUnavailable('Graph claim is not its actual immutable birth member')
            self.phase='bundle'
        elif self.phase=='bundle':
            self.bundle=root.read_fixed_row(db,'graph_bundle_operations',('activity_id','effect_id','digest','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*ns,self.claim.operation_id))
            if self.bundle is None or self.bundle[:2]!=(self.claim.activity_id,self.claim.effect_id):
                raise AuthorityUnavailable('effect does not belong to its exact final bundle')
            self._begin('receipt','graph_bundle_operations','receipt_json',('bot','persona','operation_id'),
                (*ns,self.claim.operation_id),paths=(('natural_dispatch_candidate',),('dispatch_candidate',)))
            self.phase='event'
        elif self.phase=='event':
            value=self.columns['receipt'].inner.values
            natural=value.get(('natural_dispatch_candidate',));generic=value.get(('dispatch_candidate',))
            if (natural is None)==(generic is None):raise AuthorityUnavailable('exactly one registered producer candidate required')
            self.family='natural' if natural is not None else 'generic';self.candidate=natural if natural is not None else generic
            self.event=root.read_fixed_row(db,'graph_events',('digest','epoch_revision'),
                'bot=? AND persona=? AND session=? AND event_id=?',(*ns,self.claim.activity_id,self.claim.operation_id))
            if self.event is None or self.event[1]!=self.candidate.get('graph_epoch'):
                raise AuthorityUnavailable('producer bundle lacks its exact actual final event')
            self.queue=['reads','revisions','invalidated'];self.phase='event_columns'
        elif self.phase=='event_columns':
            if self.queue:
                name=self.queue.pop(0);self._begin(name,'graph_events',name,('bot','persona','session','event_id'),
                    (*ns,self.claim.activity_id,self.claim.operation_id));return False
            candidate=self.candidate
            expected='sylanne.d11.natural_dispatch_candidate.v2' if self.family=='natural' else 'sylanne.d11.dispatch_candidate.v1'
            status='natural_paid_review_current_hold' if self.family=='natural' else 'source_qualified'
            refs=candidate.get('refs')
            if (candidate.get('schema')!=expected or candidate.get('status')!=status
                    or type(refs) is not list or len(refs)!=4):
                raise AuthorityUnavailable('registered final candidate closed shape/status differs')
            writes=self.columns['revisions'].value_v3();reads=self.columns['reads'].value_v3()
            def versions(value):
                if type(value) is not list or any(type(x)is not list or len(x)!=2 or type(x[0])is not str
                        or type(x[1])is not int or x[1]<0 for x in value) or len({x[0] for x in value})!=len(value):
                    raise AuthorityUnavailable('complete event versions have invalid shape/duplicates')
                for ref,rev in value:
                    if NamespaceId.from_key(AtomKey.from_token(ref))!=self.namespace:
                        raise AuthorityUnavailable('event version crossed namespace')
                return dict(value)
            versions(reads);revision_map=versions(writes)
            versions(self.columns['invalidated'].value_v3())
            types=('d08.action_intent.v1','d08.action_schema.v1','d08.communication_intent_grant.v1')
            if len({x[0] for x in refs if type(x)is list and len(x)==2})!=4:
                raise AuthorityUnavailable('candidate repeats or omits a member')
            for index,item in enumerate(refs):
                if (type(item)is not list or len(item)!=2 or type(item[0])is not str
                        or type(item[1])is not int or item[1]<1 or revision_map.get(item[0])!=item[1]):
                    raise AuthorityUnavailable('candidate member is outside exact actual writes')
                atom=AtomKey.from_token(item[0])
                allowed={types[index]} if index<3 else ({'d09.natural_verified_segment_batch.v2','d09.natural_verified_segment_batch.v3'}
                    if self.family=='natural' else {'d09.verified_segment_batch.v1'})
                if (atom.type_name not in allowed or NamespaceId.from_key(atom)!=self.namespace
                        or atom.owner.kind!='activity' or atom.owner.subject!=self.claim.activity_id):
                    raise AuthorityUnavailable('candidate member ordered type/owner differs')
            self.refs=tuple(tuple(x) for x in refs);self.phase='members'
        elif self.phase=='members':
            if self.member_index<4:
                index=self.member_index;ref,revision=self.refs[index]
                self._history('member:'+str(index),ref,revision,root,same_event=True,omit_text=index==3)
                self.member_index+=1;return False
            self._batch_hash()
        elif self.phase=='payload_hash_prepare':
            batch=self.columns['member:3'].value_v3()
            natural=self.family=='natural'
            segment=batch['segment'] if natural else batch['segments'][0]
            if (not natural and len(batch['segments'])!=1 or segment.get('media_refs')!=[]
                    or type(segment.get('claim_uses'))is not list):
                raise AuthorityUnavailable('registered producer must have one immutable text segment')
            uses=sorted(segment['claim_uses'],key=lambda x:(x['start'],x['end']))
            path=('segment','body') if natural else ('segments',0,'body')
            pieces=(b'{"body":',path,b',"claim_uses":',canonical_serialize(uses).encode('ascii'),b',"media_refs":[]}')
            self.hash_read=_LineageSpanHashV3(self,self.columns['member:3'],pieces);self.phase='payload_hash'
        elif self.phase=='identity':
            self._identity_v3(root)
        elif self.phase in {'artifact','named','proof_versions'}:
            self._specific_v3(root)
        elif self.phase=='seal':
            self._begin('admission','graph_dispatch_admissions','admission_json',
                ('bot','persona','admission_ref'),(*ns,self.claim.admission_ref))
            self.phase='admission'
        elif self.phase=='admission':
            from ..runtime.dispatch_admission import _admission_value_from_parsed_v3
            admission=_admission_value_from_parsed_v3(self.columns['admission'].value_v3())
            fixed=root.read_fixed_row(db,'graph_dispatch_admissions',
                ('operation_id','effect_id','admission_digest','graph_revision','graph_epoch','receipt_digest'),
                'bot=? AND persona=? AND admission_ref=?',(*ns,self.claim.admission_ref))
            segment=self.columns['member:3'].value_v3()
            segment=segment['segment'] if self.family=='natural' else segment['segments'][0]
            if (fixed is None or fixed[:3]!=(self.claim.operation_id,self.claim.effect_id,admission.digest)
                    or (admission.namespace,admission.activity_id,admission.operation_id,admission.effect_id,
                        admission.admission_ref,admission.graph_incarnation,admission.candidate_digest)!=
                       (self.claim.authority_namespace,self.claim.activity_id,self.claim.operation_id,
                        self.claim.effect_id,self.claim.admission_ref,self.claim.graph_incarnation,self.candidate['digest'])
                    or admission.action_intent_digest!=canonical_digest(self.action)
                    or admission.action_schema_digest!=canonical_digest(self.schema)
                    or admission.grant_digest!=canonical_digest(self.grant)
                    or admission.batch_digest!=self.columns['member:3'].value_v3()['batch_digest']
                    or admission.payload_digest!=segment['payload_digest']
                    or tuple(admission.audience)!=self.grant.audiences
                    or fixed[4]!=self.event[1] or admission.query_epoch!=self.event[1]
                    or self.candidate['query_epoch']+1!=self.event[1]
                    or self.candidate['graph_revision']is not None and fixed[3]!=self.candidate['graph_revision']
                    or fixed[5]!=canonical_digest({'admission_digest':admission.digest,
                        'graph_revision':fixed[3],'graph_epoch':fixed[4]})):
                raise AuthorityUnavailable('actual complete admission differs from Graph producer/candidate/claim')
            frozen=root.read_fixed_row(db,'graph_epochs',('revision',),'bot=? AND persona=?',ns)
            if frozen is None or frozen[0]<self.event[1]:
                raise AuthorityUnavailable('admission final event exceeds its actual frozen Graph epoch')
            self.frozen_graph_epoch=frozen[0];self.admission=admission
            self.admission_write_index=0
            self.admission_write_root=canonical_digest(('sylanne3.c09.same-event-write-eof.v3',
                self.builder.scope.scope_digest,self.claim.operation_id,self.event))
            self.phase='admission_writes'
        elif self.phase in {'admission_writes','admission_census','admission_census_heads','admission_request'}:
            self._admission_post_versions_v3(root)
        else:raise AuthorityUnavailable('unregistered Graph dependency lineage phase')
        self.require_current_v3();self.control.require_c09_retained_arena_v3(meter=root)
        return self.complete

    def _identity_v3(self,root):
        from ..domains.d08 import GoalExecutionProvider,ActionSchema,ActionSchemaRecord
        from ..runtime_contracts import canonical_digest
        from ..memory_types import access_key,source_key
        from ..graph_types import GraphVersion
        from ..runtime.dispatch_candidate import NaturalDispatchCandidateEvidenceV2,DispatchCandidateEvidenceV1
        types={spec.name:spec for spec in GoalExecutionProvider().register_types()}
        self.action=types['d08.action_intent.v1'].validator(self.columns['member:0'].value_v3())
        self.schema=types['d08.action_schema.v1'].validator(self.columns['member:1'].value_v3())
        self.grant=types['d08.communication_intent_grant.v1'].validator(self.columns['member:2'].value_v3())
        action,schema,grant=self.action,self.schema,self.grant
        batch=self.columns['member:3'].value_v3();candidate=self.candidate
        roots=tuple(candidate.get('source_refs',()))
        if (not roots or len(roots)>256 or len(set(roots))!=len(roots) or roots!=action.source_refs
                or (action.identity.operation_id,action.identity.activity_id,action.identity.effect_id)!=
                    (self.claim.operation_id,self.claim.activity_id,self.claim.effect_id)
                or ActionSchemaRecord.bind(action,ActionSchema(schema.schema_id,schema.action_kind,schema.proactive,schema.required_checks))!=schema
                or self.hashes['batch_hash']!=batch['batch_digest']):
            raise AuthorityUnavailable('actual action/schema/source roots or complete batch commitment differs')
        reads=dict(self.columns['reads'].value_v3())
        for ref in roots:
            key=AtomKey.from_token(ref)
            if key!=source_key(*self.namespace.as_tuple,key.owner.subject or '') or reads.get(ref,0)<1 or reads.get(
                    access_key(*self.namespace.as_tuple,key.owner.subject or '').token,0)<1:
                raise AuthorityUnavailable('producer Source roots lack exact Source/Access causal reads')
        for index,name in enumerate(('action_id','schema_ref','grant_id')):
            value=(action.action_id,schema.schema_ref,grant.grant_id)[index]
            if AtomKey.from_token(self.refs[index][0]).name!=value:raise AuthorityUnavailable('candidate key/name differs')
        if (AtomKey.from_token(self.refs[3][0]).name!=batch['batch_id'] or grant.action_id!=action.action_id
                or grant.intent_revision!=action.revision or grant.target_ref!=action.target_ref or grant.purpose!='expression'
                or batch['action_id']!=action.action_id or batch['intent_ref']!=grant.intent_ref
                or batch['grant_id']!=grant.grant_id or batch['grant_digest']!=canonical_digest(grant)
                or batch['required_check_refs']!=list(grant.required_check_refs)):
            raise AuthorityUnavailable('final grant/batch exact action linkage differs')
        segment=batch['segment'] if self.family=='natural' else batch['segments'][0]
        if segment['effect_id']!=self.claim.effect_id or segment['payload_digest']!=self.hashes['payload_hash']:
            raise AuthorityUnavailable('complete immutable final payload/effect differs')
        epochs=tuple(candidate.get(name) for name in ('access_epoch','delete_epoch','query_epoch'))
        if any(type(x)is not int or x<0 for x in epochs):raise AuthorityUnavailable('producer authority epochs differ')
        from ..domains.d09 import _VERIFIED_BATCH_FIELDS
        from ..domains.d09.natural_batch import _FIELDS as NATURAL_FIELDS
        fields=(NATURAL_FIELDS|({'semantic_manifest'}if batch['schema']=='d09.natural_verified_segment_batch.v3'else set())) if self.family=='natural' else _VERIFIED_BATCH_FIELDS
        if self.columns['member:3'].top_fields!=fields:
            raise AuthorityUnavailable('registered final batch closed schema differs')
        if self.family=='natural':
            paid=batch['paid_review'];current=tuple(GraphVersion(AtomKey.from_token(x['ref']),x['version']) for x in batch['current_reads'])
            if (batch['source_ref']['ref'] not in roots or reads.get(batch['source_ref']['ref'])!=batch['source_ref']['version']
                    or len({v.key for v in current})!=len(current) or any(reads.get(v.key.token)!=v.revision for v in current)
                    or batch['operation_id']!=self.claim.operation_id or batch['activity_id']!=self.claim.activity_id
                    or batch['effect_id']!=self.claim.effect_id or grant.audiences!=(batch['audience_id'],)
                    or grant.route_binding_digest!=batch['route_binding_digest'] or len(grant.segment_grants)!=1
                    or (grant.segment_grants[0].segment_id,grant.segment_grants[0].effect_id,grant.segment_grants[0].payload_digest)!=
                       (segment['segment_id'],segment['effect_id'],segment['payload_digest'])
                    or batch['segment_authorization_ref']!=grant.segment_authorization_ref(segment['segment_id'])):
                raise AuthorityUnavailable('natural current Source/paid/grant/segment causal metadata differs')
            evidence=NaturalDispatchCandidateEvidenceV2(self.claim.operation_id,self.claim.effect_id,
                *(x[0] for x in self.refs),canonical_digest(action),canonical_digest(schema),canonical_digest(grant),
                batch['batch_digest'],segment['segment_id'],segment['payload_digest'],paid['receipt_digest'],
                paid['generation_original_operation_id'],paid['review_original_operation_id'],roots,current,*epochs)
            if evidence.digest!=candidate['digest']:raise AuthorityUnavailable('reconstructed natural candidate digest differs')
            self.roots=roots;self.phase='seal'
        else:
            if (batch['intent_revision']!=action.revision or batch['target_ref']!=action.target_ref
                    or grant.intent_ref!=action.action_id or batch['communication_action_id']!=grant.communication_action_id
                    or batch['contact_id']!=grant.contact_id or batch['batch_revision']!=grant.batch_revision
                    or batch['grant_manifest_digest']!=grant.segment_manifest_digest
                    or batch['audiences']!=list(grant.audiences) or batch['purpose']!=grant.purpose
                    or batch['cancellation_epoch']!=grant.cancellation_epoch or batch['valid_until']!=grant.valid_until
                    or len(grant.segment_grants)!=1
                    or (segment['segment_id'],segment['effect_id'],segment['position'],segment['payload_digest'],segment['segment_authorization_ref'])!=
                       (grant.segment_grants[0].segment_id,grant.segment_grants[0].effect_id,grant.segment_grants[0].position,
                        grant.segment_grants[0].payload_digest,grant.segment_authorization_ref(grant.segment_grants[0].segment_id))):
                raise AuthorityUnavailable('generic final exact action/grant/finite segment metadata differs')
            versions=tuple((ref,reads[ref]) for ref in roots)
            accesses=tuple((access_key(*self.namespace.as_tuple,AtomKey.from_token(ref).owner.subject or '').token,
                reads[access_key(*self.namespace.as_tuple,AtomKey.from_token(ref).owner.subject or '').token]) for ref in roots)
            evidence=DispatchCandidateEvidenceV1(self.claim.operation_id,*(x[0] for x in self.refs),
                canonical_digest(action),canonical_digest(schema),canonical_digest(grant),batch['batch_digest'],roots,
                versions,accesses,*epochs,status='source_qualified',source_audience=tuple(candidate['source_audience']),
                source_proof_versions=tuple(tuple(x) for x in candidate['source_proof_versions']),
                source_proof_digest=candidate['source_proof_digest'])
            if evidence.digest!=candidate['digest']:raise AuthorityUnavailable('reconstructed generic candidate digest differs')
            self.evidence=evidence
            self.roots=roots;self.family=('artifact' if self.claim.operation_id.startswith('artifact-receipt-message:')
                else 'named' if action.identity.phase=='commitment_literal_v1' else None)
            if self.family is None:raise AuthorityUnavailable('unregistered generic final producer family')
            self.phase=self.family;self.specific_stage=0

    def _specific_v3(self,root):
        from ..runtime_contracts import canonical_digest
        from ..memory_types import access_key
        from ..domains.d01.production_operations_v1 import plain_v1
        ns=self.namespace.as_tuple;db=self.builder.pair.source
        if self.phase=='proof_versions':
            proofs=self.candidate['source_proof_versions']
            if self.specific_stage<len(proofs):
                item=proofs[self.specific_stage]
                if (type(item)is not list or len(item)!=2 or type(item[0])is not str or type(item[1])is not int
                        or item[1]<1 or item not in self.columns['reads'].value_v3()):
                    raise AuthorityUnavailable('qualified Source proof lacks its exact actual causal read')
                key=AtomKey.from_token(item[0])
                if NamespaceId.from_key(key)!=self.namespace or key.type_name not in {'memory.source','memory.access'}:
                    raise AuthorityUnavailable('qualified proof contains a foreign Source/Access type')
                tag='proof:'+str(self.specific_stage)
                if tag not in self.columns:
                    self._history(tag,item[0],item[1],root,paths=(
                        (('source_id',),('parent_source_ids',)) if key.type_name=='memory.source' else ()));return
                if key.type_name=='memory.source':
                    metadata=self.columns[tag].inner.values
                    parents=metadata.get(('parent_source_ids',))
                    if (metadata.get(('source_id',))!=key.owner.subject or type(parents)is not list
                            or any(type(parent)is not str or not parent for parent in parents)
                            or len(set(parents))!=len(parents)):
                        raise AuthorityUnavailable('qualified Source proof has another actual parent/id grammar')
                    self.proof_parents[item[0]]=tuple(parents)
                self.source_proofs.append((item[0],item[1],self.columns[tag].inner.digest))
                self.specific_stage+=1;return
            if (not self.source_proofs or not set((*self.evidence.source_read_versions,*self.evidence.access_read_versions))<=set((x[0],x[1])for x in self.source_proofs) or len({(x[0],x[1]) for x in self.source_proofs})!=len(self.source_proofs)
                    or canonical_digest(self.source_proofs)!=self.candidate['source_proof_digest']):
                raise AuthorityUnavailable('complete actual Source proof content digest differs')
            self.phase='seal';return
        if self.phase=='named':
            self._named_v3(root);return
        from ..runtime.artifact_completion_receipt_v1 import (OPERATION,receipt_from_wire_v1,
            DeriveArtifactCompletionReceiptRequestV1)
        from ..runtime.domain_production_originals_v1 import _receipt
        if self.specific_stage==0:
            if len(self.roots)!=1:raise AuthorityUnavailable('Artifact effect must name its single actual receipt Source')
            self.artifact_producer='artifact-completion-source:'+self.claim.operation_id.removeprefix('artifact-receipt-message:')
            self.artifact_header=root.read_fixed_row(db,'graph_domain_production_originals_v1',
                ('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
                'bot=? AND persona=? AND operation_id=?',(*ns,self.artifact_producer))
            if self.artifact_header is None or self.artifact_header[:2]!=('d06',OPERATION):
                raise AuthorityUnavailable('Artifact prefix is not an actual registered D06 receipt producer')
            paths=(('namespace',),('identity','operation_id'),('request',),('coverage',),('now_utc',),
                ('owner_guard',),('provenance','artifact_completion_receipt'))
            self._begin('artifact_original','graph_domain_production_originals_v1','original_payload_json',
                ('bot','persona','operation_id'),(*ns,self.artifact_producer),paths=paths)
            self.specific_stage=1;return
        if self.specific_stage==1:
            source=self.columns['artifact_original'];metadata=source.inner.values
            value=receipt_from_wire_v1(metadata[('provenance','artifact_completion_receipt')])
            if (source.inner.digest!=self.artifact_header[2] or value.namespace!=self.namespace
                    or metadata[('namespace',)]!=plain_v1(self.namespace)
                    or metadata[('identity','operation_id')]!=self.artifact_producer
                    or value.producer_operation_id!=self.artifact_producer
                    or value.message_operation_id!=self.claim.operation_id or value.effect_id!=self.claim.effect_id
                    or value.source_ref!=self.roots[0] or metadata[('coverage',)]!='complete'
                    or metadata[('now_utc',)]!=value.recorded_at_utc
                    or metadata[('owner_guard',)]!=plain_v1(value.owner_guard)
                    or metadata[('request',)]!=plain_v1(DeriveArtifactCompletionReceiptRequestV1(value.selector))):
                raise AuthorityUnavailable('Artifact actual D06 original/Owner/task/message/Source differs')
            self.receipt_original=value
            self._begin('artifact_receipt','graph_domain_production_originals_v1','receipt_json',
                ('bot','persona','operation_id'),(*ns,self.artifact_producer))
            self.specific_stage=2;return
        if self.specific_stage==2:
            receipt=_receipt(self.columns['artifact_receipt'].value_v3())
            bundle=root.read_fixed_row(db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*ns,self.artifact_producer))
            if (receipt.status!='committed' or receipt.operation_id!=self.artifact_producer
                    or canonical_digest(receipt)!=self.artifact_header[4]
                    or receipt.operation_digest!=self.artifact_header[3]
                    or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
                raise AuthorityUnavailable('Artifact original lacks its actual committed producer receipt')
            self.artifact_receipt=receipt
            self._begin('artifact_reads','graph_domain_production_originals_v1','read_versions_json',
                ('bot','persona','operation_id'),(*ns,self.artifact_producer))
            self.specific_stage=3;return
        if self.specific_stage==3:
            value=self.receipt_original;source_key=AtomKey.from_token(value.source_ref)
            from ..runtime.artifact_completion_receipt_v1 import receipt_ids_v1
            if self.claim.activity_id!=receipt_ids_v1(value.selector)['activity']:raise AuthorityUnavailable('Artifact actual activity differs')
            batch=self.columns['member:3'];segment=batch.value_v3()['segments'][0]
            if (batch.scalar_digests.get(('segments',0,'body'))!=canonical_digest(value.text)
                    or batch.scalar_chars.get(('segments',0,'body'))!=len(value.text)
                    or segment['effect_id']!=value.effect_id
                    ):
                raise AuthorityUnavailable('Artifact actual immutable receipt template/effect/activity differs')
            access=access_key(*ns,source_key.owner.subject)
            from ..graph_types import GraphVersion
            from ..domains.d06.inspection_metadata_v1 import inspection_key_v1
            expected={GraphVersion(source_key,1),GraphVersion(access,1)}
            projection=GraphVersion(inspection_key_v1(source_key,1),1)
            actual=set(self.artifact_receipt.write_versions)
            if projection in actual:expected.add(projection)
            if actual!=expected or len(actual)!=len(self.artifact_receipt.write_versions):
                raise AuthorityUnavailable('Artifact D06 producer has another exact Source/Access projection write set')
            self.artifact_queue=[(value.source_ref,1,value.source_digest,'source'),
                (access.token,1,value.source_access_digest,'access')]+[
                (head.key.token,head.revision,digest,'parent') for head,digest in value.parent_source_heads]
            if projection in actual:self.artifact_queue.append((projection.key.token,1,None,'inspection'))
            reads=self.columns['artifact_reads'].value_v3()
            if any([head.key.token,head.revision] not in reads for head,_ in value.parent_source_heads):
                raise AuthorityUnavailable('Artifact D06 original omitted a real parent Source head')
            self.artifact_index=0;self.specific_stage=4;return
        if self.specific_stage==4:
            if self.artifact_index<len(self.artifact_queue):
                ref,rev,digest,kind=self.artifact_queue[self.artifact_index];tag='artifact-history:'+str(self.artifact_index)
                if tag not in self.columns:
                    paths=(('source_id',),('source_kind',),('assertion_status',),('provenance_root',),('parent_source_ids',)) if kind=='source' else (
                        ((),) if kind=='inspection' else ())
                    self._history(tag,ref,rev,root,paths=paths)
                    return
                column=self.columns[tag]
                if digest is not None and column.inner.digest!=digest:
                    raise AuthorityUnavailable('Artifact actual Source/Access/parent full EOF digest differs')
                if kind in {'source','access','inspection'}:
                    origin=root.read_fixed_row(db,'graph_history',('event_id',),
                        'token=? AND revision=? AND event_bot=? AND event_persona=?',(ref,rev,*ns))
                    if origin!=(self.artifact_producer,):
                        raise AuthorityUnavailable('Artifact Source/Access/inspection lacks its exact D06 birth')
                if kind=='source':
                    meta=column.inner.values;value=self.receipt_original
                    if (meta[('source_id',)]!=AtomKey.from_token(ref).owner.subject
                            or meta[('source_kind',)]!='internal' or meta[('assertion_status',)]!='confirmed'
                            or meta[('provenance_root',)]!=value.receipt_id
                            or meta[('parent_source_ids',)]!=[head.key.owner.subject for head,_ in value.parent_source_heads]):
                        raise AuthorityUnavailable('Artifact actual Source parent/kind/provenance metadata differs')
                if kind=='inspection':
                    from ..domains.d06.inspection_metadata_v1 import validate_inspection_metadata_v1
                    metadata=column.value_v3();validate_inspection_metadata_v1(metadata,source=True)
                    if (metadata['target_ref']!=self.receipt_original.source_ref or metadata['target_revision']!=1
                            or metadata['producer_operation_id']!=self.artifact_producer
                            or metadata['target_semantic_digest']!=self.receipt_original.source_digest):
                        raise AuthorityUnavailable('Artifact same-producer inspection projection differs')
                self.artifact_index+=1;return
            self.phase='proof_versions';self.specific_stage=0
            return
        raise AuthorityUnavailable('unknown Artifact Source lineage phase')


    def _admission_post_versions_v3(self,root):
        """Replay the same final event and a complete metadata history census."""
        from ..runtime_contracts import canonical_digest,canonical_serialize
        from ..runtime.dispatch_admission import _request_from_parsed_v3,_request_matches
        from .c09_paged_recovery_facts_v2 import _read_one
        db=self.builder.pair.source;ns=self.namespace.as_tuple
        if self.phase=='admission_writes':
            writes=self.columns['revisions'].value_v3()
            if self.admission_write_index<len(writes):
                ref,revision=writes[self.admission_write_index]
                tag='admission-write:'+str(self.admission_write_index)
                if tag not in self.columns:
                    self._history(tag,ref,revision,root,same_event=True,paths=());return
                column=self.columns[tag]
                self.admission_write_root=canonical_digest((self.admission_write_root,
                    self.admission_write_index,ref,revision,column.inner.digest,column.inner.length))
                self.admission_write_index+=1;return
            self.census_after=('',0);self.census_token=None;self.census_revision=0
            self.census_last_epoch=-1;self.census_selected=None;self.census_latest_valid=None
            self.census_versions={};self.census_heads={};self.census_head_after=''
            self.census_root=canonical_digest(('sylanne3.c09.final-admission-history-census.v3',
                self.builder.scope.scope_digest,self.builder.pair.source_original.role_source_digest,
                self.claim.operation_id,self.event,self.admission_write_root))
            self.census_count=0;self.phase='admission_census';return
        if self.phase=='admission_census':
            row=_read_one(db,'SELECT token,revision,valid,event_session,event_id FROM graph_history '
                'WHERE event_bot=? AND event_persona=? AND (token COLLATE BINARY>? OR '
                '(token=? AND revision>?)) ORDER BY token COLLATE BINARY,revision LIMIT 1',
                (*ns,self.census_after[0],*self.census_after),root)
            if row is None:
                self._finish_census_token_v3()
                self.phase='admission_census_heads';return
            token,revision,valid,session,event=row
            atom=AtomKey.from_token(token)
            if (NamespaceId.from_key(atom)!=self.namespace or type(revision)is not int or revision<1
                    or type(valid)is not int or valid not in (0,1)):
                raise AuthorityUnavailable('actual historical census key/revision/namespace differs')
            if token!=self.census_token:
                self._finish_census_token_v3()
                self.census_token=token;self.census_revision=0;self.census_last_epoch=-1;self.census_selected=None
            if revision!=self.census_revision+1:
                raise AuthorityUnavailable('historical census has a missing or duplicate actual revision')
            birth=root.read_fixed_row(db,'graph_events',('epoch_revision','digest'),
                'bot=? AND persona=? AND session=? AND event_id=?',(*ns,session,event))
            if (birth is None or type(birth[0])is not int or birth[0]<self.census_last_epoch
                    or birth[0]>self.frozen_graph_epoch):
                raise AuthorityUnavailable('historical census has no actual ordered birth event')
            self.census_revision=revision;self.census_last_epoch=birth[0];self.census_latest_valid=valid
            if birth[0]<=self.event[1]:self.census_selected=revision
            self.census_after=(token,revision)
            self.census_root=canonical_digest((self.census_root,self.census_count,row,birth))
            self.census_count+=1;return
        if self.phase=='admission_census_heads':
            row=_read_one(db,'SELECT token,revision,valid FROM graph_atoms WHERE bot=? AND persona=? '
                'AND token COLLATE BINARY>? ORDER BY token COLLATE BINARY LIMIT 1',(*ns,self.census_head_after),root)
            if row is None:
                if self.census_head_count!=len(self.census_heads):
                    raise AuthorityUnavailable('complete census contains history without its actual current head')
                self._require_admission_census_v3(root)
                self._begin('admission-request','graph_dispatch_admissions','request_json',
                    ('bot','persona','admission_ref'),(*ns,self.claim.admission_ref))
                self.phase='admission_request';return
            if self.census_heads.get(row[0])!=row[1:]:
                raise AuthorityUnavailable('actual frozen head differs from complete historical census')
            self.census_root=canonical_digest((self.census_root,'current_head',row))
            self.census_head_after=row[0];self.census_head_count+=1;return
        if self.phase=='admission_request':
            request=_request_from_parsed_v3(self.columns['admission-request'].value_v3())
            if not _request_matches(self.admission,request) or canonical_digest(request)!=self.admission.request_digest:
                raise AuthorityUnavailable('actual complete dispatch request/admission commitment differs')
            self.complete=True;self.phase='complete';return
        raise AuthorityUnavailable('unknown actual postwrite admission proof phase')

    def _finish_census_token_v3(self):
        if self.census_token is None:return
        self.census_heads[self.census_token]=(self.census_revision,self.census_latest_valid)
        if self.census_selected is not None:self.census_versions[self.census_token]=self.census_selected

    def _require_admission_census_v3(self,root):
        from ..runtime_contracts import canonical_digest
        actual=dict(self.admission.graph_reads)
        if len(actual)!=len(self.admission.graph_reads):
            raise AuthorityUnavailable('actual admission repeats a historical snapshot head')
        # A write replaces the same token's pre-CAS value. Old and new versions
        # are never accepted as interchangeable members of a union.
        post=dict(self.columns['reads'].value_v3())
        post.update(dict(self.columns['revisions'].value_v3()))
        for token,revision in actual.items():
            if token in post and revision!=post[token]:
                raise AuthorityUnavailable('admission snapshot contradicts exact same-event postwrite CAS')
            if self.census_versions.get(token)!=revision:
                raise AuthorityUnavailable('admission head is not current at its actual final event epoch')
        profile=None
        if actual==self.census_versions:profile='namespace_all_heads_v1'
        if self.family=='artifact':
            from ..runtime.current_graph_full_read_v3 import _FAMILIES,ARTIFACT_RECEIPT_FULL_READ_V1
            types=frozenset().union(*(_FAMILIES[name]for name in ARTIFACT_RECEIPT_FULL_READ_V1.families))-{'memory.source'}
            family=set();queue=list(self.candidate['source_refs'])
            from ..memory_types import source_key
            while queue:
                ref=queue.pop()
                if ref in family:continue
                if ref not in self.proof_parents:
                    raise AuthorityUnavailable('Artifact snapshot Source family lacks its complete Source metadata EOF')
                family.add(ref)
                queue.extend(source_key(*self.namespace.as_tuple,parent).token for parent in self.proof_parents[ref])
                if len(family)>len(self.proof_parents):
                    raise AuthorityUnavailable('Artifact Source closure exceeds its authenticated proof members')
            if family!=set(self.proof_parents):
                raise AuthorityUnavailable('Artifact qualified Source proof contains another historical family')
            fixed={token:revision for token,revision in self.census_versions.items()
                if AtomKey.from_token(token).type_name in types or token in family}
            if actual==fixed:profile='artifact_fixed_families_and_source_closure_v1'
        if profile is None:
            raise AuthorityUnavailable('complete actual producer snapshot/census profile differs')
        self.snapshot_profile=profile
        self.census_root=canonical_digest((self.census_root,'complete',self.census_count,
            self.census_head_count,profile,tuple(sorted(actual.items()))))

    def _named_v3(self,root):
        from dataclasses import fields
        from ..graph_types import GraphVersion
        from ..runtime_contracts import canonical_digest,canonical_serialize
        from ..domains.d08.commitment_communication_v1 import (
            USE_TYPES,CommitmentCommunicationIntentV1,CommitmentTermsCommunicationIntentV2,
            decode_communication_use_v1,promise_use_key_v1)
        from ..domains.d08.execution import Commitment
        from ..domains.d08.commitment_fulfillment_v1 import (
            CommitmentFulfillmentTermsV1,CommitmentTermsAcceptanceV1)
        from ..domains.d01.production_operations_v1 import plain_v1
        reads=dict(self.columns['reads'].value_v3());ns=self.namespace.as_tuple
        if self.specific_stage==0:
            uses=[(ref,rev) for ref,rev in self.columns['revisions'].value_v3()
                if AtomKey.from_token(ref).type_name in USE_TYPES]
            if len(uses)!=1 or uses[0][1]!=1:raise AuthorityUnavailable('named final needs exactly one immutable same-event PromiseUse')
            self.named_use_version=uses[0]
            self._history('named-use',*uses[0],root,same_event=True)
            self.specific_stage=1;return
        if self.specific_stage==1:
            use=decode_communication_use_v1(self.columns['named-use'].value_v3())
            if (use.namespace!=self.namespace or promise_use_key_v1(self.namespace,self.claim.activity_id,use).token!=self.named_use_version[0]
                    or reads.get(use.scope.key.token)!=use.scope.revision
                    or reads.get(use.commitment.key.token)!=use.commitment.revision):
                raise AuthorityUnavailable('actual Use scope/commitment/key differs from final causal reads')
            self.named_use=use
            self._history('named-scope',use.scope.key.token,use.scope.revision,root,omit_text=True)
            self.specific_stage=2;return
        if self.specific_stage==2:
            use=self.named_use;column=self.columns['named-scope'];scope=column.value_v3()
            cls=CommitmentTermsCommunicationIntentV2 if scope.get('schema')=='d08.commitment_communication_intent.v2' else CommitmentCommunicationIntentV1
            if column.top_fields!={f.name for f in fields(cls)}:
                raise AuthorityUnavailable('Scope metadata/opaque literal closed fields differ')
            self.named_scope=scope;self.named_scope_class=cls
            self.hash_read=_LineageSpanHashV3(self,column,_typed_opaque_pieces_v3(cls,column,{'approved_literal'}))
            self.phase='named_scope_hash';self.after_hash_phase='named';self.specific_stage=3;return
        if self.specific_stage==3:
            use=self.named_use;scope=self.named_scope
            self._history('named-commitment',use.commitment.key.token,use.commitment.revision,root,omit_text=True)
            self.specific_stage=4;return
        if self.specific_stage==4:
            column=self.columns['named-commitment']
            if column.top_fields!={f.name for f in fields(Commitment)}:
                raise AuthorityUnavailable('Commitment closed metadata/opaque semantic scope differs')
            self.hash_read=_LineageSpanHashV3(self,column,_typed_opaque_pieces_v3(Commitment,column,{'semantic_scope'}))
            self.phase='named_commitment_hash';self.after_hash_phase='named';self.specific_stage=5;return
        if self.specific_stage==5:
            use=self.named_use;scope=self.named_scope;commitment=self.columns['named-commitment'].value_v3()
            batch=self.columns['member:3'].value_v3();segment=batch['segments'][0];body=('segments',0,'body')
            scope_column=self.columns['named-scope'];batch_column=self.columns['member:3']
            expected_segment='segment:'+canonical_digest((use.scope_digest,self.action.identity))[:48]
            claim_id='commitment-literal:'+canonical_digest((use.scope_digest,self.action.identity,self.action.action_id))[:48]
            from ..domains.d09 import ClaimKind,ClaimUse
            expected_use=ClaimUse(claim_id,0,use.end,ClaimKind.INTERNAL_ACTIVITY)
            claim_metadata={'claim_id':claim_id,'kind':'internal_activity','source_refs':list(use.source_refs),
                'allowed_audiences':[use.audience_ref],'eligibility':['expression'],
                'disclosure_ref':scope.get('route_source_ref',scope['source_refs'][0])}
            # The body is compared only by the canonical string's actual EOF hash.
            claims=batch['claims']
            if (self.hashes['named_scope_hash']!=use.scope_digest
                    or self.hashes['named_commitment_hash']!=scope['commitment_digest']
                    or plain_v1(use.namespace)!=scope['namespace'] or plain_v1(use.commitment)!=scope['commitment']
                    or scope['terms_digest']!=use.terms_digest
                    or commitment['commitment_id'] not in self.action.commitment_refs
                    or self.action.commitment_refs!=(commitment['commitment_id'],)
                    or (use.operation_id,use.action_id,use.effect_id,use.target_ref,use.source_refs)!=
                       (self.claim.operation_id,self.action.action_id,self.claim.effect_id,self.action.target_ref,self.roots)
                    or (scope['target_ref'],scope['conversation_ref'],tuple(scope['source_refs']))!=
                       (use.target_ref,use.audience_ref,use.source_refs)
                    or (segment['segment_id'],segment['effect_id'],segment['payload_digest'])!=
                       (use.segment_id,use.effect_id,use.payload_digest)
                    or use.segment_id!=expected_segment or use.start!=0
                    or scope_column.scalar_chars[('approved_literal',)]!=use.end
                    or batch_column.scalar_chars[body]!=use.end
                    or scope_column.scalar_digests[('approved_literal',)]!=use.literal_digest
                    or batch_column.scalar_digests[body]!=use.literal_digest
                    or segment['claim_uses']!=plain_v1((expected_use,))
                    or segment['source_refs']!=list(use.source_refs) or segment['audiences']!=[use.audience_ref]
                    or self.grant.promise_grants!=(use.scope.key.token,)
                    or self.grant.audiences!=(use.audience_ref,)
                    or self.action.parameters_digest!=canonical_digest({
                        'schema':'d08.commitment-literal-parameters.v1','scope':use.scope,
                        'scope_digest':use.scope_digest,'promise_use':use,'payload_digest':use.payload_digest})
                    or batch['scene_ref']!=scope['scene_ref'] or batch['target_ref']!=scope['target_ref']
                    or batch['audiences']!=[use.audience_ref]
                    or len(claims)!=1 or claims[0]!=claim_metadata
                    or batch_column.scalar_digests.get(('claims',0,'text'))!=use.literal_digest):
                raise AuthorityUnavailable('named actual Scope/Use/Commitment/literal/route/claims linkage differs')
            self.hash_read=_LineageSpanHashV3(self,scope_column,(b'{"body":',('approved_literal',),
                b',"scope":'+canonical_serialize(use.scope).encode('ascii')+b',"speech_act":"promise"}'))
            self.phase='named_output_hash';self.after_hash_phase='named';self.specific_stage=6;return
        if self.specific_stage==6:
            if self.hashes['named_output_hash']!=self.named_use.output_digest:
                raise AuthorityUnavailable('named immutable output commitment differs')
            if self.named_scope_class is CommitmentCommunicationIntentV1:
                value=self.columns['named-commitment'].value_v3()
                names=('commitment_id','revision','subject_ref','counterparty_ref','semantic_scope','establishment_kind','deadline_ref')
                pieces=[b'[']
                for index,name in enumerate(names):
                    if index:pieces.append(b',')
                    pieces.append((name,) if name=='semantic_scope' else canonical_serialize(value[name]).encode('ascii'))
                pieces.append(b']')
                self.hash_read=_LineageSpanHashV3(self,self.columns['named-commitment'],pieces)
                self.phase='named_v1_terms_hash';self.after_hash_phase='named';self.specific_stage=7;return
            use=self.named_use;scope=self.named_scope
            if (scope['terms_digest']!=scope['fulfillment_terms_digest']
                    or scope['fulfillment_terms']!=plain_v1(use.fulfillment_terms)
                    or scope['role']!=use.role or scope['terms_acceptance']!=plain_v1(use.terms_acceptance)
                    or scope['route_source_ref'] not in self.roots
                    or reads.get(use.fulfillment_terms.key.token)!=use.fulfillment_terms.revision):
                raise AuthorityUnavailable('V2 named immutable terms/role/acceptance/readset differs')
            policy=scope['policy_source_refs'];versions=scope['policy_read_versions']
            if (type(policy)is not list or len(set(policy))!=len(policy)
                    or len(set(policy)|set(self.roots))>32
                    or not scope['policy_audiences'] or len(set(scope['policy_audiences']))!=len(scope['policy_audiences'])
                    or len({x['key'] for x in versions})!=len(versions)):
                raise AuthorityUnavailable('V2 independent policy metadata closed bounds differ')
            for ref in policy:
                atom=AtomKey.from_token(ref)
                if atom.type_name!='memory.source' or NamespaceId.from_key(atom)!=self.namespace:
                    raise AuthorityUnavailable('V2 policy Source crossed namespace/type')
            for version in versions:
                atom=AtomKey.from_token(version['key'])
                if (NamespaceId.from_key(atom)!=self.namespace or version['revision']<1
                        or reads.get(atom.token)!=version['revision']
                        or atom.type_name not in {'d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule'}):
                    raise AuthorityUnavailable('V2 policy selected CAS not in final event')
            birth=root.read_fixed_row(self.builder.pair.source,'graph_history',('dependencies','event_session','event_id'),
                'token=? AND revision=? AND event_bot=? AND event_persona=?',(use.scope.key.token,1,*ns))
            dependencies={x[0] for x in json.loads(birth[0])}
            expected={use.commitment.key.token,use.fulfillment_terms.key.token,*self.roots,*policy,
                *(x['key'] for x in versions)}
            if use.terms_acceptance is not None:expected.add(use.terms_acceptance.key.token)
            if not expected<=dependencies:raise AuthorityUnavailable('V2 Scope birth omitted independent policy/terms causal dependencies')
            self.roots=tuple(dict.fromkeys((*self.roots,*policy)))
            self._history('named-terms',use.fulfillment_terms.key.token,use.fulfillment_terms.revision,root,omit_text=True)
            self.specific_stage=8;return
        if self.specific_stage==7:
            if self.hashes['named_v1_terms_hash']!=self.named_use.terms_digest:
                raise AuthorityUnavailable('V1 commitment original terms digest differs')
            self.phase='proof_versions';self.specific_stage=0;return
        if self.specific_stage==8:
            column=self.columns['named-terms']
            if column.top_fields!={f.name for f in fields(CommitmentFulfillmentTermsV1)}:
                raise AuthorityUnavailable('V2 immutable Terms closed metadata/opaque literal differs')
            self.hash_read=_LineageSpanHashV3(self,column,_typed_opaque_pieces_v3(CommitmentFulfillmentTermsV1,column,{'deliverable_literal'}))
            self.phase='named_terms_hash';self.after_hash_phase='named';self.specific_stage=9;return
        if self.specific_stage==9:
            use=self.named_use;terms=self.columns['named-terms'].value_v3();scope=self.named_scope
            commitment=self.columns['named-commitment'].value_v3()
            if (self.hashes['named_terms_hash']!=use.terms_digest or terms['schema']!='d08.commitment_fulfillment_terms.v1'
                    or terms['namespace']!=plain_v1(self.namespace) or terms['commitment']['key']!=use.commitment.key.token
                    or terms['commitment']['revision']!=1 or terms['counterparty_ref']!=scope['target_ref']
                    or not set(terms['source_refs'])<=set(self.candidate['source_refs'])
                    or terms['semantic_scope_digest']!=self.columns['named-commitment'].scalar_digests[('semantic_scope',)]):
                raise AuthorityUnavailable('V2 actual immutable Terms/Commitment/Source semantic linkage differs')
            if terms['fulfillment_kind'] not in {'communicated','recipient_acknowledged'}:
                raise AuthorityUnavailable('unregistered immutable terms predicate')
            obligation=('deliver exactly this text' if terms['fulfillment_kind']=='communicated'
                else "obtain the recipient's exact receipt confirmation for this text")
            prefix=(f"To {terms['counterparty_ref']}: {obligation}. Deadline UTC: "
                +str(terms['deadline_utc'] if terms['deadline_utc'] is not None else 'none')+". Text:\n")
            from copy import copy
            column=copy(self.columns['named-terms']);column.spans=dict(column.spans)
            self.columns['named-terms']=column
            left,right=column.spans[('deliverable_literal',)]
            column.spans[('deliverable_inner',)]=(left+1,right-1)
            self.hash_read=_LineageSpanHashV3(self,column,(
                canonical_serialize(prefix).encode('ascii')[:-1],('deliverable_inner',),b'"'))
            self.phase='named_semantic_hash';self.after_hash_phase='named';self.specific_stage=10;return
        if self.specific_stage==10:
            use=self.named_use;terms=self.columns['named-terms'].value_v3()
            if self.hashes['named_semantic_hash']!=terms['semantic_scope_digest']:
                raise AuthorityUnavailable('Terms literal/structured semantic scope differs from actual Commitment')
            cid=use.commitment.key.name;digest=use.terms_digest
            if use.role=='offer':
                obligation=('deliver exactly this text' if terms['fulfillment_kind']=='communicated'
                    else "obtain the recipient's exact receipt confirmation for this text")
                prefix=("SYLANNE-COMMITMENT/1 OFFER\n"+f"To {terms['counterparty_ref']}: {obligation}. Deadline UTC: "
                    +str(terms['deadline_utc'] if terms['deadline_utc'] is not None else 'none')+". Text:\n")
                suffix=f"\nCommitment: {cid}\nTerms: {digest}\nTo accept, reply exactly:\nSYLANNE-COMMITMENT/1 ACCEPT {cid} {digest}"
            else:
                prefix=f"SYLANNE-COMMITMENT/1 PERFORMANCE {cid} {digest}\n";suffix=''
                if terms['fulfillment_kind']=='recipient_acknowledged':
                    suffix=f"\nEffect: {use.effect_id}\nTo confirm receipt, reply exactly:\nSYLANNE-COMMITMENT/1 RECEIVED {cid} {digest} {use.effect_id}"
            self.hash_read=_LineageSpanHashV3(self,self.columns['named-terms'],(
                canonical_serialize(prefix).encode('ascii')[:-1],('deliverable_inner',),
                canonical_serialize(suffix).encode('ascii')[1:]))
            self.phase='named_render_hash';self.after_hash_phase='named';self.specific_stage=11;return
        if self.specific_stage==11:
            use=self.named_use;commitment=self.columns['named-commitment'].value_v3()
            if self.hashes['named_render_hash']!=use.literal_digest:
                raise AuthorityUnavailable('actual Scope literal differs from registered terms renderer commitment')
            if commitment['establishment_kind']=='bilateral' and use.role=='performance' and use.terms_acceptance is None:
                raise AuthorityUnavailable('bilateral performance has no actual causal terms acceptance')
            if use.terms_acceptance is not None:
                if reads.get(use.terms_acceptance.key.token)!=use.terms_acceptance.revision:
                    raise AuthorityUnavailable('actual final does not causally read its terms acceptance')
                self._history('named-acceptance',use.terms_acceptance.key.token,use.terms_acceptance.revision,root)
                self.specific_stage=12;return
            self.phase='proof_versions';self.specific_stage=0;return
        if self.specific_stage==12:
            from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
            acceptance=decode_typed_production_value_v1(self.columns['named-acceptance'].value_v3(),CommitmentTermsAcceptanceV1)
            use=self.named_use
            if (acceptance.namespace!=self.namespace or acceptance.terms!=use.fulfillment_terms
                    or acceptance.terms_digest!=use.terms_digest
                    or acceptance.resulting_commitment!=use.commitment
                    or acceptance.inbound_source_ref not in self.candidate['source_refs']):
                raise AuthorityUnavailable('V2 acceptance does not bind actual terms/inbound/commitment')
            self.phase='proof_versions';self.specific_stage=0;return
        raise AuthorityUnavailable('unregistered named metadata proof phase')


def _typed_metadata_value_v3(cls,value):
    """Closed canonical type encoding, without constructing a text-bearing DTO."""
    from dataclasses import fields,is_dataclass
    from typing import get_type_hints,get_origin,get_args,Union
    from types import UnionType
    from ..graph_types import AtomKey
    from ..runtime_contracts import _canonical_value
    origin=get_origin(cls);args=get_args(cls)
    if cls is AtomKey:return _canonical_value(AtomKey.from_token(value),set())
    if origin in (Union,UnionType):
        if value is None and type(None) in args:return None
        variants=[x for x in args if x is not type(None)]
        if len(variants)!=1:raise AuthorityUnavailable('ambiguous canonical metadata union')
        return _typed_metadata_value_v3(variants[0],value)
    if origin in (tuple,list):
        if type(value)is not list:raise AuthorityUnavailable('typed metadata array differs')
        kinds=(args[:1]*len(value)) if len(args)==2 and args[1] is Ellipsis else args
        if len(kinds)!=len(value):raise AuthorityUnavailable('typed metadata tuple arity differs')
        return [_typed_metadata_value_v3(kind,item) for kind,item in zip(kinds,value,strict=True)]
    if is_dataclass(cls):
        if type(value)is not dict or set(value)!={f.name for f in fields(cls)}:
            raise AuthorityUnavailable('typed metadata dataclass closed fields differ')
        hints=get_type_hints(cls)
        return {'$type':cls.__module__+'.'+cls.__qualname__,**{
            field.name:_typed_metadata_value_v3(hints[field.name],value[field.name]) for field in fields(cls)}}
    if cls is float and type(value)in(int,float):return value
    if cls in (str,int,float,bool,type(None)):
        if type(value)is not cls:raise AuthorityUnavailable('typed canonical metadata scalar differs')
        return value
    from enum import Enum
    if isinstance(cls,type) and issubclass(cls,Enum):return cls(value).value
    raise AuthorityUnavailable('unregistered canonical metadata field type')


def _typed_opaque_pieces_v3(cls,column,opaque):
    from dataclasses import fields
    from typing import get_type_hints
    from ..runtime_contracts import canonical_serialize
    value=column.value_v3();hints=get_type_hints(cls);pieces=[b'{']
    names=sorted({'$type',*(f.name for f in fields(cls))})
    for index,name in enumerate(names):
        if index:pieces.append(b',')
        pieces.append(canonical_serialize(name).encode('ascii')+b':')
        if name in opaque:pieces.append((name,))
        else:
            item=cls.__module__+'.'+cls.__qualname__ if name=='$type' else _typed_metadata_value_v3(hints[name],value[name])
            pieces.append(canonical_serialize(item).encode('ascii'))
    pieces.append(b'}')
    return pieces


def _copy_graph_lineage_v3(reader):
    from copy import copy
    result=copy(reader)
    for name in ('columns','hashes','proof_parents','census_versions','census_heads'):
        setattr(result,name,dict(getattr(reader,name)))
    for name in ('members','queue','source_proofs'):
        setattr(result,name,list(getattr(reader,name)))
    if reader.column is not None:
        result.column=copy(reader.column);result.column.owner=result
    if reader.hash_read is not None:
        result.hash_read=copy(reader.hash_read);result.hash_read.owner=result
    _GRAPH_LINEAGE_READERS_V3.add(result)
    result.control.register_c09_retained_state_v3(result)
    return result


def prepare_dispatch_source_lineage_v3(build,shape,key,meter):
    """One bounded frozen Graph quantum; the caller adopts only after reserve exits."""
    if shape.table not in {'graph_atoms','graph_history'}:return True
    atom=AtomKey.from_token(key[0])
    if (atom.type_name!='d11.dispatch_claim.v1'
            or NamespaceId.from_key(atom).as_tuple!=tuple(json.loads(build.scope.graph_namespace))):return True
    from ..runtime.c09_graph_rebase_candidate_v2 import _actual_erased_graph_marker_v3
    if _actual_erased_graph_marker_v3(build,shape,key,meter):return True
    if shape.table=='graph_history' and key[1]!=1:
        raise AuthorityUnavailable('immutable dispatch claim has another historical revision')
    prior=build.platform_lineage_reader_v3
    if prior is not None and prior.shape==shape and prior.key==tuple(key):
        prior.require_current_v3()
        if prior.complete:return True
        reader=_copy_graph_lineage_v3(prior)
    else:reader=_GraphDispatchSourceLineageReadV3(_GRAPH_LINEAGE_ISSUER_V3,build,shape,key)
    reader.advance_v3(meter)
    build.platform_lineage_pending_v3=reader
    return False


def require_dispatch_source_roots_v3(build,namespace,claim,meter):
    """Only completed actual Graph lineage; Core/fact disposition is a later phase."""
    reader=build.platform_lineage_reader_v3
    if (type(reader) is not _GraphDispatchSourceLineageReadV3 or reader.builder is not build
            or not reader.complete or reader.namespace!=namespace or reader.claim!=claim):
        raise AuthorityUnavailable('complete actual frozen producer/Source dependency proof required')
    reader.require_current_v3()
    _actual_reserved_meter_v3()
    return reader.roots

class _FinalGraphSourceLineageScopeV3:
    """Exact frozen Graph Source custody owned by the final Authority builder."""
    def __init__(self,authority_builder):
        from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
        from ..runtime.c09_graph_rebase_candidate_v2 import VerifiedGraphRebaseColdV2
        if type(authority_builder)is not _InstalledAuthorityRoleBuilderV2 or authority_builder.transform.role!='core':
            raise AuthorityUnavailable('actual final Core builder required')
        authority_builder.require_current()
        graph=authority_builder.session.require_actual_post_mirror_graph_v3()
        if type(graph)is not VerifiedGraphRebaseColdV2 or graph.session is not authority_builder.session:
            raise AuthorityUnavailable('actual same-session cold Graph Source required')
        self.authority_builder=authority_builder;self.graph=graph
        self.session=authority_builder.session;self.pair=graph.pair;self.scope=authority_builder.scope
        self.require_current()
    def require_current(self):
        self.authority_builder.require_current()
        if (self.authority_builder.session is not self.session or self.authority_builder.scope!=self.scope
                or self.session.require_actual_post_mirror_graph_v3()is not self.graph
                or self.graph.pair is not self.pair or self.pair.source_original.scope_digest!=self.scope.scope_digest):
            raise AuthorityUnavailable('final Graph Source lineage custody changed')
        self.graph.require_current()
        return self


def begin_final_dispatch_source_lineage_v3(authority_builder,namespace,effect_id,*,meter):
    from ..runtime.dispatch_graph_claim import dispatch_claim_key
    from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
    owner=_FinalGraphSourceLineageScopeV3(authority_builder)
    if namespace.as_tuple!=tuple(json.loads(owner.scope.graph_namespace)):
        raise AuthorityUnavailable('final dispatch Source proof crossed namespace')
    shape=read_c09_table_shape_v2(owner.pair.source,'graph_history',meter=meter)
    return _GraphDispatchSourceLineageReadV3(_GRAPH_LINEAGE_ISSUER_V3,owner,shape,
        (dispatch_claim_key(namespace,effect_id).token,1))


def advance_final_dispatch_source_lineage_v3(reader,meter):
    if type(reader)is not _GraphDispatchSourceLineageReadV3 or type(reader.builder)is not _FinalGraphSourceLineageScopeV3:
        raise AuthorityUnavailable('actual final frozen Graph Source lineage reader required')
    result=_copy_graph_lineage_v3(reader);result.advance_v3(meter)
    return result
