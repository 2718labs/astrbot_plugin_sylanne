"""Current source context for already paid/adopted D04 continuations.

A completed foreground Focus is not a source revocation. This fixed reader is
used only by drive, numeric preparation and post-joint encoding context. New
foreground/appraisal work keeps its separate live Focus admission.
"""
import json
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot
from ..memory_types import SourceRecord, access_key, source_key
from ..domains.d06 import source_correction_head_key
from ..runtime_contracts import VersionedRef


def read_current_d04_post_appraisal_context_v3(graph, db, namespace, c02_operation_id, source_ref, now_utc, epoch):
    from ..graph_coordinator import GraphCoordinator
    from ..domains.d03.context import ContextProvider, RoleBindingRequest
    from .dispatch_current_projection import derive_current_domain_reads, read_current_dispatch_projection
    from .reply_entity_route_v2 import read_current_reply_entity_route_binding_v2
    from .reply_model_job import read_settled_c02_reply_source_v1, read_current_reply_route_manifest_v2
    from .c04_encoding_baseline_store_v3 import _receipt
    if (type(graph) is not GraphCoordinator or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError('D04 continuation requires its actual current W01 transaction')
    provider=graph._GraphCoordinator__providers.get('d03')
    if provider is None or type(provider[0]) is not ContextProvider:
        raise ValueError('actual D03 current role/boundary provider is unavailable')
    full,query=graph._dispatch_full_graph_snapshot_locked(namespace)
    if query.revision!=epoch.revision:raise ValueError('D04 current context epoch changed')
    atoms={atom.key:atom for atom in full.atoms}
    pending=[source_ref];seen=set()
    while pending:
        ref=pending.pop()
        if ref in seen:continue
        if len(seen)>=256:raise ValueError('D04 current source ancestry exceeds its bound')
        key=AtomKey.from_token(ref)
        if key!=source_key(*namespace.as_tuple,key.owner.subject or ''):
            raise ValueError('D04 current source has another namespace or type')
        for required in (key,access_key(*namespace.as_tuple,key.owner.subject),source_correction_head_key(namespace,key.owner.subject)):
            row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(required.token,)).fetchone()
            actual=GraphAtom(required,row[0],json.loads(row[1]),bool(row[2])) if row else GraphAtom(required,0,{},False)
            if required in atoms and atoms[required]!=actual:raise ValueError('D04 source read changed')
            atoms[required]=actual
        source,access=atoms[key],atoms[access_key(*namespace.as_tuple,key.owner.subject)]
        correction=atoms[source_correction_head_key(namespace,key.owner.subject)]
        if not source.valid or not access.valid or correction.revision or correction.valid:
            raise ValueError('D04 current source/access/correction no longer qualifies')
        record=SourceRecord.from_dict(source.value)
        if (record.source_id!=key.owner.subject or access.value.get('source_id')!=record.source_id
                or access.value.get('status')!='active' or 'expression' not in record.purposes
                or 'expression' not in access.value.get('purposes',())):
            raise ValueError('D04 current source permission is absent')
        seen.add(ref);pending.extend(source_key(*namespace.as_tuple,parent).token for parent in record.parent_source_ids)
    snapshot=GraphSnapshot(tuple(atoms.values()),full.epochs)
    receipt=_receipt(db,namespace,c02_operation_id)
    inputs=read_settled_c02_reply_source_v1(db,graph._GraphCoordinator__d02_issuer,namespace,receipt,source_ref,snapshot)
    route=read_current_reply_route_manifest_v2(db,namespace,inputs,source_ref)
    for ref in seen:
        record=SourceRecord.from_dict(atoms[AtomKey.from_token(ref)].value)
        access=atoms[access_key(*namespace.as_tuple,record.source_id)]
        if route.conversation_ref not in record.audiences or route.conversation_ref not in access.value['audiences']:
            raise ValueError('D04 current ancestor does not permit the actual original audience')
    binding=read_current_reply_entity_route_binding_v2(db,namespace,route,query,now_utc=now_utc)
    projection=read_current_dispatch_projection(db,namespace,snapshot,query)
    request=RoleBindingRequest('persona:'+namespace.persona_id,binding.target_entity_ref,None,
        route.scene_ref,'expression','reply',now_utc,True)
    role,boundary=derive_current_domain_reads(db,projection,request,provider[0])
    if role.status!='complete' or len(role.matched_bindings)!=1 or projection.coverage!='full' or boundary.coverage!='full':
        raise ValueError('D04 current original route role/boundary is incomplete')
    matched=tuple(atom for atom in projection.role_bindings if atom.key.name==role.matched_bindings[0]
        and atom.value.get('scene_ref')==route.scene_ref)
    if len(matched)!=1:raise ValueError('D04 current original route role is ambiguous')
    scene=VersionedRef(matched[0].key.token,matched[0].revision)
    audience=VersionedRef(binding.binding_version.key.token,binding.binding_version.revision)
    return inputs,route,binding,snapshot,query,role,boundary,scene,audience
