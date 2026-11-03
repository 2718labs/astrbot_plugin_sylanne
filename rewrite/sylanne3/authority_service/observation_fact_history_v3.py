"""Control-authenticated historical Fact membership; never execution permission."""
from __future__ import annotations
from dataclasses import dataclass
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize,NamespaceId
from ..graph_types import AtomKey

KIND='observation_fact_history_v3'
SCHEMA='sylanne3.c09.observation-fact-history.v3'
FIELDS=frozenset(('schema','authority_id','installation_id','control_store_id','namespace','fact_operation_id',
    'mutation_id','subject','request_digest','fact_row_commitment','column_commitments','effect_id','dispatch_operation_id',
    'claim_digest','handoff_digest','graph_claim_digest','predecessor_mutation_id','predecessor_receipt_digest',
    'old_execution_journal_id','old_execution_seq','old_execution_digest','entry_membership','core_source_digest',
    'execution_source_digest','maintenance_operation_id','scope_digest','accepted_receipt_digest','facts_pin_digest',
    'graph_issue_digest','graph_disposition_root','source_disposition_root','source_disposition_count','source_refs',
    'source_versions','target_core_identity','target_storage_instance_id','maintenance_generation','key_id','history_digest','signature'))


def observation_fact_history_body_v3(builder,qualified,*,meter):
    from .c09_authority_storage_rebase_v2 import _PlatformObservationFactDispositionReadV3
    if (type(qualified)is not _PlatformObservationFactDispositionReadV3 or qualified.builder is not builder
            or not qualified.complete or not qualified.quantum_completed or qualified.affected):
        raise AuthorityUnavailable('complete actual unaffected Fact provenance producer required')
    c=qualified.capture;c.require_complete(builder,c.shape,c.key)
    control=builder.session._control.maintenance.control;s=builder.scope;p=qualified.fact
    facts=builder.transform.facts
    facts.require_complete(scope_digest=s.scope_digest,facts_pin_digest=facts._completion.pin_digest)
    body=dict(schema=SCHEMA,authority_id=s.authority_id,installation_id=s.installation_id,
        control_store_id=control.control_store_id,namespace=s.authority_namespace,fact_operation_id=c.key[0],
        mutation_id=p.mutation_id,subject=p.fact_write_permit.subject,request_digest=p.request_digest,
        fact_row_commitment=c.commitment,column_commitments={name:dict(sha256=c.hashes[name],byte_count=c.sizes[name])
            for name in ('pending','receipt','updated_fact_permit')},
        effect_id=p.original_claimed_receipt.pending.permit.effect_id,
        dispatch_operation_id=p.original_claimed_receipt.pending.permit.operation_id,
        claim_digest=qualified.handoff.claim_digest,handoff_digest=qualified.refined_observation.start_digest,
        graph_claim_digest=qualified.handoff.graph_receipt.graph_claim_digest,
        predecessor_mutation_id=p.predecessor_mutation_id,predecessor_receipt_digest=p.predecessor_receipt_digest,
        old_execution_journal_id=facts._completion.old_journal_id,old_execution_seq=facts._completion.old_seq,
        old_execution_digest=facts._completion.old_digest,
        entry_membership=dict(metadata=list(qualified.fact_journal.small),payload_sha256=qualified.fact_journal.digest.hexdigest()),
        core_source_digest=builder.pair.source_original.role_source_digest,
        execution_source_digest=builder.execution_pair.source_original.role_source_digest,
        maintenance_operation_id=s.operation_id,scope_digest=s.scope_digest,accepted_receipt_digest=s.accepted_receipt_digest,
        facts_pin_digest=facts._completion.pin_digest,graph_issue_digest=builder.basis.graph_issue_digest,
        graph_disposition_root=qualified.graph.candidate.candidate_digest,
        source_disposition_root=qualified.graph_root,source_disposition_count=qualified.graph_count,
        source_refs=sorted(set(qualified.graph_lineage.roots)),source_versions=[list(value)for value in qualified.references],
        target_core_identity=list(builder.pair.target_identity),target_storage_instance_id=builder.segmented_target_v3.storage_instance_id,
        maintenance_generation=s.maintenance_generation)
    return body


def issue_observation_fact_history_v3(builder,qualified,*,meter):
    body=observation_fact_history_body_v3(builder,qualified,meter=meter)
    control=builder.session._control.maintenance.control;s=builder.scope
    meter.require_available(len(canonical_serialize(body).encode('utf8'))*4+32768)
    original=control.sign_original_v1(SCHEMA,body,'history_digest')
    validate_observation_fact_history_v3(control,original,namespace=s.authority_namespace)
    return original


def validate_observation_fact_history_v3(control,original,*,namespace):
    if (type(original)is not dict or set(original)!=FIELDS or original['schema']!=SCHEMA
            or (original['authority_id'],original['installation_id'],original['control_store_id'])!=(
                control.authority_id,control.installation_id,control.control_store_id)
            or original['namespace']!=namespace or original['fact_operation_id']!=original['mutation_id']
            or type(original['maintenance_generation'])is not int or original['maintenance_generation']<0):
        raise AuthorityUnavailable('Fact history closed identity/schema differs')
    control.verify_original_v1(original,'history_digest')
    from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2
    scope=control.read_build_original_v1(operation_id=original['maintenance_operation_id'],kind='capture_scope_v2')
    if scope is None:raise AuthorityUnavailable('Fact history actual signed capture scope is absent')
    actual=C09CaptureScopeV2(**scope['details'])
    if (actual.scope_digest,actual.authority_namespace,actual.accepted_receipt_digest,actual.maintenance_generation)!=(
            original['scope_digest'],namespace,original['accepted_receipt_digest'],original['maintenance_generation']):
        raise AuthorityUnavailable('Fact history capture scope/accepted original differs')
    ns=NamespaceId(*__import__('json').loads(actual.graph_namespace))
    refs=original['source_refs'];versions=original['source_versions']
    if (type(refs)is not list or refs!=sorted(set(refs))or not refs
            or type(versions)is not list or len({tuple(v)for v in versions})!=len(versions)
            or type(original['source_disposition_count'])is not int or original['source_disposition_count']!=len(versions)):
        raise AuthorityUnavailable('Fact history actual Source closure shape differs')
    for token in refs:
        key=AtomKey.from_token(token)
        if NamespaceId.from_key(key)!=ns or key.type_name!='memory.source':
            raise AuthorityUnavailable('Fact history Source root crosses its namespace/family')
    for token,revision in versions:
        key=AtomKey.from_token(token)
        if (NamespaceId.from_key(key)!=ns or key.type_name not in {'memory.source','memory.access'}
                or type(revision)is not int or revision<1):
            raise AuthorityUnavailable('Fact history Source version differs')
    plain_digests=('fact_row_commitment','core_source_digest','execution_source_digest','scope_digest',
        'accepted_receipt_digest','facts_pin_digest','graph_issue_digest','graph_disposition_root',
        'source_disposition_root','target_storage_instance_id','history_digest')
    for name in plain_digests:
        value=original[name]
        if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
            raise AuthorityUnavailable('Fact history named complete SHA commitment differs')
    for name in('request_digest','claim_digest','handoff_digest','graph_claim_digest','predecessor_receipt_digest'):
        value=original[name]
        if(type(value)is not str or len(value)!=71 or not value.startswith('sha256:')
                or any(c not in '0123456789abcdef'for c in value[7:])):
            raise AuthorityUnavailable('Fact history original digest domain differs')
    target=original['target_core_identity'];entry=original['entry_membership']
    if (type(target)not in(tuple,list)or len(target)!=2 or any(type(v)is not int or v<0 for v in target)
            or type(entry)is not dict or set(entry)!={'metadata','payload_sha256'}
            or type(entry['metadata'])not in(tuple,list)or len(entry['metadata'])!=6
            or type(entry['payload_sha256'])is not str or len(entry['payload_sha256'])!=64
            or any(c not in '0123456789abcdef'for c in entry['payload_sha256'])):
        raise AuthorityUnavailable('Fact history target/entry closed metadata differs')
    metadata=entry['metadata']
    if(type(metadata[0])is not int or metadata[0]<1 or type(original['old_execution_seq'])is not int
            or original['old_execution_seq']<metadata[0] or metadata[1]!=original['mutation_id']
            or metadata[2]!=original['request_digest']or metadata[3]!=original['mutation_id']
            or any(type(metadata[i])is not str or not metadata[i]for i in(4,5))):
        raise AuthorityUnavailable('Fact history actual journal membership identity differs')
    commitments=original['column_commitments']
    if type(commitments)is not dict or set(commitments)!={'pending','receipt','updated_fact_permit'}:
        raise AuthorityUnavailable('Fact history requires its three actual canonical column commitments')
    for value in commitments.values():
        if (type(value)is not dict or set(value)!={'sha256','byte_count'} or type(value['byte_count'])is not int
                or value['byte_count']<1 or type(value['sha256'])is not str or len(value['sha256'])!=64
                or any(c not in '0123456789abcdef'for c in value['sha256'])):
            raise AuthorityUnavailable('Fact history complete column SHA/bytes differs')
    return original


@dataclass(frozen=True,slots=True)
class HistoricalObservationFactV3:
    """A historical read result; it carries no live fence or dispatch authority."""
    original:dict
    pending:object
    receipt:object
    updated_fact_permit:object


def read_runtime_observation_fact_history_v3(bridge,db,operation_id):
    """Exact archive PK + installed current Core selection + all three cell EOFs."""
    import json
    from ..runtime_storage_v3 import runtime_storage_v3,runtime_source_identity_v4,runtime_storage_operation_v3
    from .c09_platform_observation_fact_storage_v3 import TABLE,PHYSICAL_DDL,fact_storage_schema_v3,fact_row_runtime_v3,CELL_COLUMNS
    handle=runtime_storage_v3(db)
    if handle is None:return None
    with runtime_storage_operation_v3(db,operation_id=operation_id)as operation:
        with handle.quantum()as meter:
            identity=runtime_source_identity_v4(handle,meter=meter)
            schema=meter.read_fixed_row(db,'sqlite_master',('sql',),"type='table' AND name=?",('authority_c09_originals_archive_v1',))
            if schema is None:return None
            from .c09_originals_archive_v1 import ARCHIVE_DDL
            if schema!=(ARCHIVE_DDL,):raise AuthorityUnavailable('Fact history archive physical schema differs')
            found=meter.read_fixed_row(db,'authority_c09_originals_archive_v1',('original_digest','original_json','maintenance_generation'),
                'namespace=? AND operation_id=? AND original_kind=?',(bridge.namespace,operation_id,KIND))
        if found is None:return None
        with handle.quantum()as meter:
            consumed=meter.read_fixed_row(db,'authority_c09_consumed_execution_v1',('item_id',),
                'namespace=? AND kind=? AND item_id=?',(bridge.namespace,'platform_observation_fact_v3',operation_id))
            if consumed is not None:raise AuthorityUnavailable('historical Fact is already retired')
            meter.require_available(len(found[1].encode('utf8'))*4+32768)
            operation.retain(len(found[1].encode('utf8'))*12+65536)
            original=json.loads(found[1]);validate_observation_fact_history_v3(identity.control,original,namespace=bridge.namespace)
            if (canonical_serialize(original)!=found[1]or original['history_digest']!=found[0]
                    or found[2]!=original['maintenance_generation']
                    or fact_storage_schema_v3(db)!=PHYSICAL_DDL):
                raise AuthorityUnavailable('Fact archive bytes/current Core lineage differs')
            require_runtime_fact_history_ancestor_v3(handle,original,meter=meter)
            row=meter.read_fixed_row(db,TABLE,('namespace','fact_operation_id','mutation_id','subject','request_digest','state',*CELL_COLUMNS),
                'fact_operation_id=?',(operation_id,))
            if row is None or row[:6]!=(bridge.namespace,operation_id,operation_id,original['subject'],original['request_digest'],'committed'):
                raise AuthorityUnavailable('Fact archive lacks its actual current committed physical row')
            for name,cell in zip(('pending','receipt','updated_fact_permit'),row[6:]):
                header=meter.read_fixed_row(db,'segmented_cells_v1',('payload_sha256','total_bytes'),'cell_id=?',(cell,))
                expected=original['column_commitments'][name]
                if header!=(expected['sha256'],expected['byte_count']):
                    raise AuthorityUnavailable('Fact history differs from current physical column bytes/SHA')
        from .observation_refinement_v3 import decode_fact_record_v3
        logical=fact_row_runtime_v3(db,operation_id);p,r,u=decode_fact_record_v3(logical)
        if (p.fact_write_permit.namespace!=bridge.namespace or p.fact_write_permit.subject!=original['subject']
                or p.fact_write_permit.operation_id!=operation_id or p.mutation_id!=original['mutation_id']
                or p.request_digest!=original['request_digest']or p.predecessor_mutation_id!=original['predecessor_mutation_id']
                or p.predecessor_receipt_digest!=original['predecessor_receipt_digest']
                or p.original_claimed_receipt.pending.permit.effect_id!=original['effect_id']
                or p.original_claimed_receipt.pending.permit.operation_id!=original['dispatch_operation_id']
                or r.pending!=p or r.after_anchor.execution_journal_id!=original['old_execution_journal_id']):
            raise AuthorityUnavailable('Fact historical typed receipt/claim identity differs')
        return HistoricalObservationFactV3(original,p,r,u)

def _require_history_target_manifest_v3(control,original,manifest):
    """Called only after the actual selected/frozen history EOF lookup."""
    scope=original['scope_digest']
    complete=control.read_build_original_v1(operation_id=original['maintenance_operation_id'],kind='capture_role_complete_v2_core')
    if complete is None:raise AuthorityUnavailable('Fact history completed Core target original is absent')
    details=complete['details']
    members=tuple(member for member in manifest['members']if member['role']=='core')
    if len(members)!=1:raise AuthorityUnavailable('Fact history ancestor has no unique actual Core member')
    member=members[0]
    if (manifest['generation']!=original['maintenance_generation']
            or tuple(details['target_identity'])[:2]!=tuple(original['target_core_identity'])
            or details['scope_digest']!=scope
            or (member['device'],member['file_id'])!=tuple(original['target_core_identity'])
            or details['target_path']!=member['resolved_path']
            or details['target_schema_digest']!=member['schema_objects_digest']
            or manifest['segmented_layouts']['core']['storage_instance_id']!=original['target_storage_instance_id']
            or manifest['graph_issue_digest']!=original['graph_issue_digest']):
        raise AuthorityUnavailable('Fact history target Core/instance is not its actual completed manifest member')
    return manifest


def require_runtime_fact_history_ancestor_v3(handle,original,*,meter):
    from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    if type(handle.selected)is not VerifiedSelectedHistoryReadV3:
        raise AuthorityUnavailable('Fact historical read requires its actual complete selected history')
    selected=handle.selected;selected.require_current(meter=meter);basis=selected.basis
    if basis.prepared['capture_scope_digest']==original['scope_digest']:
        if basis.prepared['operation_id']!=original['maintenance_operation_id']:
            raise AuthorityUnavailable('Fact history current selected operation differs')
        manifest=basis.manifest
    else:
        with basis.read_database('graph',meter=meter)as db:
            frame=meter.read_fixed_row(db,'c09_recovery_history_frames_v2',
                ('operation_id','prepared_digest','manifest_digest'),'scope_digest=? AND generation=?',
                (selected.scope.scope_digest,original['maintenance_generation']))
            scoped=meter.read_fixed_row(db,'c09_recovery_history_scopes_v2',('generation','operation_id','prepared_digest'),
                'scope_digest=? AND historical_scope_digest=?',(selected.scope.scope_digest,original['scope_digest']))
        if (frame is None or scoped!=(original['maintenance_generation'],original['maintenance_operation_id'],frame[1])
                or frame[0]!=original['maintenance_operation_id']):
            raise AuthorityUnavailable('Fact history target is absent from actual authenticated selected history EOF')
        with basis.control._db()as db:manifest=basis.control._read_manifest(db,frame[2])
    _require_history_target_manifest_v3(basis.control,original,manifest)
    selected.require_current(meter=meter)


def require_frozen_fact_history_ancestor_v3(builder,original,*,meter):
    builder.require_current();facts=builder.transform.facts
    facts.require_complete(scope_digest=builder.scope.scope_digest,facts_pin_digest=facts._completion.pin_digest)
    control=builder.session._control.maintenance.control
    scoped=meter.read_fixed_row(facts._db,'c09_recovery_history_scopes_v2',('generation','operation_id','prepared_digest'),
        'scope_digest=? AND historical_scope_digest=?',(builder.scope.scope_digest,original['scope_digest']))
    frame=meter.read_fixed_row(facts._db,'c09_recovery_history_frames_v2',('operation_id','prepared_digest','manifest_digest'),
        'scope_digest=? AND generation=?',(builder.scope.scope_digest,original['maintenance_generation']))
    if (frame is None or scoped!=(original['maintenance_generation'],original['maintenance_operation_id'],frame[1])
            or frame[0]!=original['maintenance_operation_id']):
        raise AuthorityUnavailable('Fact historical target is not an authenticated ancestor of this actual frozen Core Source')
    with control._db()as db:manifest=control._read_manifest(db,frame[2])
    _require_history_target_manifest_v3(control,original,manifest)
    builder.require_current()

def read_frozen_observation_fact_history_v3(capture,*,meter):
    """Only the complete actual same-Core-Source capture may select this archive."""
    import json
    from .c09_platform_observation_fact_storage_v3 import ActualFactSourceCaptureV3
    from .c09_originals_archive_v1 import ARCHIVE_DDL
    if type(capture)is not ActualFactSourceCaptureV3:
        raise AuthorityUnavailable('actual frozen Fact Source capture required')
    builder=capture.builder;capture.require_complete(builder,capture.shape,capture.key)
    db=builder.pair.source;control=builder.session._control.maintenance.control
    schema=meter.read_fixed_row(db,'sqlite_master',('sql',),"type='table' AND name=?",('authority_c09_originals_archive_v1',))
    if schema is None:return None
    if schema!=(ARCHIVE_DDL,):raise AuthorityUnavailable('Fact history archive exact physical schema differs')
    row=meter.read_fixed_row(db,'authority_c09_originals_archive_v1',
        ('original_digest','original_json','maintenance_generation'),
        'namespace=? AND operation_id=? AND original_kind=?',(builder.scope.authority_namespace,capture.key[0],KIND))
    if row is None:return None
    meter.require_available(len(row[1].encode('utf8'))*4+32768)
    original=json.loads(row[1]);validate_observation_fact_history_v3(control,original,namespace=builder.scope.authority_namespace)
    require_frozen_fact_history_ancestor_v3(builder,original,meter=meter)
    if (row[0]!=original['history_digest']or row[2]!=original['maintenance_generation']
            or canonical_serialize(original)!=row[1]or capture.commitment!=original['fact_row_commitment']
            or capture.identity[:5]!=(original['namespace'],original['fact_operation_id'],original['mutation_id'],
                original['subject'],original['request_digest'])
            or any(original['column_commitments'][name]!={'sha256':capture.hashes[name],'byte_count':capture.sizes[name]}
                for name in ('pending','receipt','updated_fact_permit'))):
        raise AuthorityUnavailable('historical Fact certificate differs from its full same-Source physical/typed row')
    p=capture.typed['pending'];r=capture.typed['receipt']
    if (p.predecessor_mutation_id!=original['predecessor_mutation_id']
            or p.predecessor_receipt_digest!=original['predecessor_receipt_digest']
            or p.original_claimed_receipt.pending.permit.effect_id!=original['effect_id']
            or p.original_claimed_receipt.pending.permit.operation_id!=original['dispatch_operation_id']
            or r.after_anchor.execution_journal_id!=original['old_execution_journal_id']):
        raise AuthorityUnavailable('historical Fact receipt/claim/journal identity differs')
    return original,row[1]
