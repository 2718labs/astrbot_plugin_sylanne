"""Same Original Authority Work catalogue and protected direct-C02 C1 attachments."""
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest

_CATALOGUES=WeakKeyDictionary()
_C1_BINDINGS=WeakKeyDictionary()
_OPERATIONS=frozenset({'prepare_personal_candidate_eligibility_v1','adopt_personal_candidate_eligibility_v1',
    'input:register_artifact_task_text_extent','input:register_artifact_phase_postcondition_policy_v1',
    'prepare_personal_candidates_v1','select_personal_step_v2',
    'input:freeze_artifact_candidate_preparation_v1','input:freeze_values','evaluate_values'})
_C02=('graph_first_ingress_c02_committed_seals_v2',('evidence_json','bundle_digest'),('bot','persona','operation_id'))
_BINDING=('runtime_encoding_call_bindings_v1',('source_id','source_revision','access_revision','budget_lease_id',
    'budget_reservation_operation_id','binding_digest','model_request_digest','call_id','request_json'),('bot','persona','job_id'))


def _work_v3(db):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .original_foreground_source_read_v3 import original_foreground_work_v3
    work=_authority_attachment_owner_v3(db)
    return work if work is not None and original_foreground_work_v3(work)is not None else None


def _current_metadata_v3(work,meter):
    from .original_foreground_source_read_v3 import require_original_foreground_work_v3
    from .original_foreground_owner_location_v3 import _OWNERS
    require_original_foreground_work_v3(work);work.require_current(meter=meter)
    owner=_OWNERS.get(work)
    if owner is None or owner.observed is None:
        raise AuthorityUnavailable('Core task catalogue requires actual same-Work Owner17 EOF')
    owner._actual()


def begin_original_task_choice_catalogue_v3(work):
    from .original_foreground_source_read_v3 import require_original_foreground_work_v3
    require_original_foreground_work_v3(work)
    if work.original_profile!='original-foreground-source.v1'or work.request.operation_kind not in _OPERATIONS:return False
    prior=_CATALOGUES.get(work)
    if prior is not None:return not prior['merged']
    from ..runtime.artifact_task_choice_catalogue_metadata_v3 import ArtifactTaskChoiceCatalogueMetadataV3
    request=work.request
    if request.draft_root_registration_ref is None:
        raise AuthorityUnavailable('Core task catalogue has no exact approved Root locator')
    task=ArtifactTaskChoiceCatalogueMetadataV3(work,root_ref=request.draft_root_registration_ref,
        c02_operation_id=request.c02_operation_id,source_ref=request.cue_source_ref,issuer=work.service.issuer)
    _CATALOGUES[work]={'task':task,'binding':(work.service,work.request,work.operation,work.scope,
        work.selection_digest,work.graph_stamp),'merged':False}
    return True


def _catalogue_v3(work):
    from .original_foreground_source_read_v3 import require_original_foreground_work_v3
    require_original_foreground_work_v3(work)
    saved=_CATALOGUES.get(work)
    if saved is None or saved['binding']!=(work.service,work.request,work.operation,work.scope,work.selection_digest,work.graph_stamp):
        raise AuthorityUnavailable('Core task catalogue changed its actual Original request/Work/stamp')
    return saved


def _merge_v3(work,result):
    from ..runtime.d01_production_operations_v1 import production_read_plan_v1
    metadata=work.original_metadata
    roots=set(result.source_roots);keys=set()
    if result.goal_head is not None:keys.add(result.goal_head.key)
    if result.plan_head is not None:keys.add(result.plan_head.key)
    historical=set()
    for original in result.originals:
        metadata.signed.add((original['kind'],original['ref']))
        metadata.producers.add(original['operation_id'])
        roots.update(original['source_roots'])
        for version in (*original['read_versions'],*original['write_versions']):
            if NamespaceId.from_key(version.key)!=work.namespace:
                raise AuthorityUnavailable('Core task catalogue producer read/write version crossed namespace')
            keys.add(version.key)
            if version.revision and(version.key.token,version.revision)not in metadata.history_heads:
                historical.add((version.key.token,version.revision))
    for root in roots:
        key=AtomKey.from_token(root)
        if key.type_name!='memory.source'or NamespaceId.from_key(key)!=work.namespace:
            raise AuthorityUnavailable('Core task catalogue Source roots escaped its actual namespace')
        keys.add(key)
    prior=metadata.candidate_evidence_plan
    metadata.candidate_evidence_plan=production_read_plan_v1(
        ()if prior is None else prior.fixed_type_ids,
        tuple(sorted(keys|set(()if prior is None else prior.exact_keys),key=lambda k:k.token)),
        tuple(sorted(roots|set(()if prior is None else prior.source_roots))),
        tuple(dict.fromkeys((*(()if prior is None else prior.required_original_refs),*(o['ref']for o in result.originals)))))
    metadata.roots.update(roots)
    for key in keys:
        if key.token not in metadata.exact:metadata.exact.add(key.token);metadata.pending.append(key.token)
    metadata.catalogue_history_pending=list(sorted(historical))
    metadata.complete=False;metadata.phase='selected'
    from .original_foreground_source_read_v3 import _reserve
    _reserve(work,(metadata.catalogue_history_pending,tuple(keys),metadata.candidate_evidence_plan))


def advance_original_task_choice_catalogue_v3(work,meter):
    _current_metadata_v3(work,meter);saved=_catalogue_v3(work)
    if work.phase=='original_catalogue':
        if saved['task'].advance(meter):
            _merge_v3(work,saved['task'].result_v3());work.phase='original_catalogue_metadata'
        return
    if work.phase!='original_catalogue_metadata':raise AuthorityUnavailable('Core task catalogue has no registered phase')
    work.original_metadata.advance(meter)
    if work.original_metadata.complete:saved['merged']=True;work.phase='original_owner'


def read_bound_original_task_choice_catalogue_v3(db,*,kind,task,goal_head,plan_head,method_ref=None):
    work=_work_v3(db)
    if work is None:return False,None
    from .original_foreground_source_read_v3 import require_original_foreground_body_v3
    require_original_foreground_body_v3(work);saved=_catalogue_v3(work)
    if not saved['merged']:raise AuthorityUnavailable('Core task catalogue has not completed actual metadata and Source ALL')
    return True,saved['task'].lookup_v3(kind,task=task,goal_head=goal_head,plan_head=plan_head,method_ref=method_ref)


def bind_original_task_scope_c1_v3(metadata,raw):
    work=metadata.work
    if work.original_profile!='original-foreground-source.v1':return
    from ..runtime.c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    c02=work.request.c02_operation_id
    if(raw.get('c02_operation_id')!=c02 or raw.get('source_ref')!=work.request.cue_source_ref
            or raw.get('c1_intent_ref')!=c1_task_intent_ref_v1(work.namespace,c02)):
        raise AuthorityUnavailable('Core task Scope changed its actual fixed C02/C1 Source locator')
    metadata.signed.add(('c1_task_intent',raw['c1_intent_ref']))


def bind_original_signed_c1_metadata_v3(metadata,identity,header,raw):
    from ..runtime.c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    from ..domains.d01.production_operations_v1 import plain_v1
    work=metadata.work;c02=work.request.c02_operation_id;policy=work.service.installed_bundle.installation_policy
    source=AtomKey.from_token(raw['source_ref'])
    if(work.original_profile!='original-foreground-source.v1'or header[0]!=c02
            or identity[2]!=c1_task_intent_ref_v1(work.namespace,c02)
            or raw.get('schema')!='d11.c1-artifact-task-intent-original.v1'
            or raw.get('namespace')!=plain_v1(work.namespace)or raw.get('c02_operation_id')!=c02
            or raw['source_ref']!=work.request.cue_source_ref or source.type_name!='memory.source'
            or NamespaceId.from_key(source)!=work.namespace or type(raw['source_revision'])is not int or raw['source_revision']<1
            or raw['installation_id']!=policy.installation_id or raw['manifest_digest']!=policy.manifest_digest):
        raise AuthorityUnavailable('Core C1 metadata is not its actual signed direct C02 Source original')
    with runtime_storage_quantum_v3(work.db)as meter:
        bundle=meter.read_fixed_row(work.db,'graph_bundle_operations',('digest','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',(*work.namespace.as_tuple,c02))
    if bundle!=(raw['c02_bundle_digest'],raw['c02_commit_seq'])or type(bundle[1])is not int or bundle[1]<1:
        raise AuthorityUnavailable('Core signed C1 has no actual positive same-C02 W01 bundle')
    metadata.roots.add(source.token)
    metadata.historical_pending.append((source.token,raw['source_revision'],raw['source_digest']))
    if source.token not in metadata.exact:metadata.exact.add(source.token);metadata.pending.append(source.token)


def _c1_metadata_v3(work):
    from ..runtime.c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    c02=work.request.c02_operation_id;ref=c1_task_intent_ref_v1(work.namespace,c02)
    raw=work.original_metadata.originals.get(('life','c1_task_intent',ref))
    if raw is None or raw.get('c02_operation_id')!=c02 or raw.get('source_ref')!=work.request.cue_source_ref:
        raise AuthorityUnavailable('Core C02 attachment has no actual complete signed C1 metadata')
    return c02,ref,raw


def register_task_c1_binding_material_v3(db,*,c02_operation_id,read):
    from ..runtime.foreground_command_source_v3 import register_foreground_command_c1_binding_v3
    if register_foreground_command_c1_binding_v3(db,c02_operation_id=c02_operation_id,read=read):return True
    work=_work_v3(db)
    if work is None:return False
    from .original_foreground_source_read_v3 import require_original_foreground_body_v3
    from ..runtime.d11_life_preparation_v1 import _read
    from ..runtime.foreground_cycle_v1 import _adopted_c02_v1
    from ..runtime.domain_background_read_v3 import background_json_loads_v3
    from ..authority_service.v2_worker_model_result_contract import from_wire,WorkerModelResultReadV1
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime.natural_frozen_original_read_v3 import _canonical_container_bytes_v3
    import json
    proof=require_original_foreground_body_v3(work);c02,ref,metadata=_c1_metadata_v3(work)
    if c02_operation_id!=c02 or type(read)is not WorkerModelResultReadV1:
        raise AuthorityUnavailable('Core C1 binding registration changed its actual typed C02 result')
    saved=_read(db,issuer=work.service.issuer,namespace=work.namespace,kind='c1_task_intent',ref=ref)
    if saved is None or saved[1]!=c02:raise AuthorityUnavailable('Core C1 binding has no actual protected signed Original')
    raw=saved[0];receipt=_adopted_c02_v1(db,work.namespace,c02)
    policy=work.service.installed_bundle.installation_policy
    prior=_C1_BINDINGS.get(work)
    prefix=(work.operation,work.scope,work.selection_digest,work.graph_stamp,ref)
    raw_digest=canonical_digest(raw);read_digest=canonical_digest(read)
    if prior is not None:
        if prior[:5]!=prefix or prior[7:]!=(raw_digest,read_digest):
            raise AuthorityUnavailable('Core C1 protected binding changed in the same Work')
        return True
    wire=json.loads(raw['worker_read_json']);work.operation.retain(_canonical_container_bytes_v3(wire)*2+131072)
    actual=from_wire(wire,WorkerModelResultReadV1);request=actual.request
    source=GraphVersion(AtomKey.from_token(raw['source_ref']),raw['source_revision'])
    if(canonical_digest(actual)!=canonical_digest(read)or raw['namespace']!=plain_v1(work.namespace)
            or raw['c02_operation_id']!=c02 or raw['source_ref']!=metadata['source_ref']
            or raw['source_revision']!=metadata['source_revision']or raw['source_digest']!=metadata['source_digest']
            or raw['installation_id']!=policy.installation_id or raw['manifest_digest']!=policy.manifest_digest
            or(raw['c02_bundle_digest'],raw['c02_receipt_digest'],raw['c02_commit_seq'])!=
                (receipt.operation_digest,canonical_digest(receipt),receipt.commit_seq)
            or source not in(*receipt.read_versions,*receipt.write_versions)
            or source.key.token not in proof.sources or(source.key.token,source.revision)not in work.original_metadata.history_heads
            or request.namespace!=work.namespace or request.consumer_operation_id!=c02
            or request.installation_id!=policy.installation_id or request.purpose!='first_ingress_c02'):
        raise AuthorityUnavailable('Core C1 binding substituted actual result/Source/receipt/call identity')
    _C1_BINDINGS[work]=(*prefix,request,source,raw_digest,read_digest)
    return True


def original_task_c1_attachment_shape_v3(request):
    return request[:3]in{_C02,_BINDING}


def require_original_task_c1_point_v3(work,request):
    if request[0]not in{_C02[0],_BINDING[0]}:return False
    from .original_foreground_source_read_v3 import require_original_foreground_body_v3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    require_original_foreground_body_v3(work);c02,ref,raw=_c1_metadata_v3(work)
    allowed=(*_C02,(*work.namespace.as_tuple,c02))
    binding=None
    if request[0]==_BINDING[0]:
        saved=_C1_BINDINGS.get(work)
        if saved is None or saved[:4]!=(work.operation,work.scope,work.selection_digest,work.graph_stamp)or saved[4]!=ref:
            raise AuthorityUnavailable('Core encoding Body requires actual Source-qualified signed C1 result binding')
        actual,source=saved[5:7]
        allowed=(*_BINDING,(*work.namespace.as_tuple,actual.job_id));binding=(actual,source)
    if request!=allowed:raise AuthorityUnavailable('Core C1 point differs from its exact actual C02/job full key and columns')
    attachment=work.attachments.get(request)
    if attachment is not None and attachment.complete:
        with runtime_storage_quantum_v3(work.db)as meter:row=attachment.require_row_v3(work,meter)
        if row is None:raise AuthorityUnavailable('Core actual C1 body dependency disappeared')
        if binding is None:
            if row[1]!=raw['c02_bundle_digest']:raise AuthorityUnavailable('Core actual C02 evidence changed its signed C1 bundle')
        else:
            from ..memory_types import source_key
            actual,source=binding
            column=attachment.json_columns.get('request_json')
            if(source_key(*work.namespace.as_tuple,row[0])!=source.key or row[1]!=source.revision
                    or(row[4],row[5],row[6],row[7])!=(actual.original_operation_id,actual.binding_digest,actual.model_request_digest,actual.call_id)
                    or column is None or not column.complete or column.sha256!=actual.binding_digest):
                raise AuthorityUnavailable('Core encoding Body changed its actual Source/reservation/binding/call EOF')
    return True


def release_original_task_choice_catalogue_v3(work):
    _C1_BINDINGS.pop(work,None);saved=_CATALOGUES.pop(work,None)
    if saved is not None:
        saved['task'].close_v3()
