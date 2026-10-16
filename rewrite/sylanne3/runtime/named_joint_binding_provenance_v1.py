"""Closed named Joint registration provenance and C09 structural codec."""
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.current_named_joint_binding_v1 import (OPERATION,named_joint_selector_from_wire_v1,
    named_joint_selector_to_wire_v1,named_joint_current_from_wire_v1,named_joint_current_to_wire_v1)
from ..runtime_contracts import FenceScope,canonical_digest,canonical_serialize
from .domain_production_erasure_v1 import decode_typed_production_value_v1

KEY='named_joint_binding_v1'


def current_named_joint_provenance_v1(reader,issued,frame):
    from .named_joint_binding_issuance_v1 import require_named_joint_issuance_v1
    current=require_named_joint_issuance_v1(issued,reader.graph,reader.write_scope)
    state=reader.inputs;host=state.observed
    if state.semantic_frame is not frame or host is None:
        raise AuthorityUnavailable('Named Joint provenance needs actual same-Work qualified Host frame')
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,note_selector_to_wire_v1,note_current_to_wire_v1
    note=type(reader.selector)is NamedJointSourceNoteSelectorV1
    encode_selector=note_selector_to_wire_v1 if note else named_joint_selector_to_wire_v1
    encode_current=note_current_to_wire_v1 if note else named_joint_current_to_wire_v1
    from .named_joint_source_note_inputs_v1 import named_source_note_original_provenance_v1
    return {'schema':'d10.named-joint-binding-provenance.v1','selector':encode_selector(reader.selector),
        'core_scope':plain_v1(reader.write_scope),'core_current':encode_current(current),
        'host_source':{'schema':'d10.named-joint-host-source.v1','read_scope':plain_v1(reader.fence.scope),
            'write_scope':plain_v1(reader.write_scope),'read_versions':plain_v1(host.read_versions),
            'query_coverage':plain_v1(host.query_coverage),'source_closure':plain_v1(host.source_closure),
            'source_purpose_groups':plain_v1(host.source_purpose_groups),'source_proof_digest':host.source_proof_digest,
            'guard_inventory_digest':host.guard_inventory_digest,'header_eof_digest':reader.namespace_reader.root,
            'original_deadline_utc':current.original_deadline_utc,
            **({'original_source':named_source_note_original_provenance_v1(state)}if note else {})}}


def validate_named_joint_provenance_v1(domain,operation_kind,value):
    note=(domain,operation_kind)==('d08','prepare_selected_source_note_action_v2')
    if(not note and(domain,operation_kind)!=('d10',OPERATION))or type(value)is not dict or set(value)!={'schema','selector','core_scope','core_current','host_source'}or value['schema']!='d10.named-joint-binding-provenance.v1':
        raise ValueError('Named Joint provenance crossed its one actual registration recipe')
    from ..authority_service.current_named_joint_source_note_v1 import note_selector_from_wire_v1,note_current_from_wire_v1,source_note_scope_operation_id_v1
    selector=(note_selector_from_wire_v1 if note else named_joint_selector_from_wire_v1)(value['selector'])
    current=(note_current_from_wire_v1 if note else named_joint_current_from_wire_v1)(value['core_current'])
    expected_scope=source_note_scope_operation_id_v1(selector)if note else selector.operation_id
    scope=decode_typed_production_value_v1(value['core_scope'],FenceScope)
    host=value['host_source']
    fields={'schema','read_scope','write_scope','read_versions','query_coverage','source_closure','source_purpose_groups',
        'source_proof_digest','guard_inventory_digest','header_eof_digest','original_deadline_utc'}
    if note:fields.add('original_source')
    if type(host)is not dict or set(host)!=fields or host['schema']!='d10.named-joint-host-source.v1':
        raise ValueError('Named Joint Host Source provenance exact fields differ')
    read=decode_typed_production_value_v1(host['read_scope'],FenceScope)
    write=decode_typed_production_value_v1(host['write_scope'],FenceScope)
    if(current.request!=selector or scope!=write or scope.operation!='write'or scope.operation_id!=expected_scope
            or scope.permit!=current.permit or read.operation!='read'or read.namespace!=scope.namespace
            or read.graph_epoch!=scope.graph_epoch or read.graph_revision!=scope.graph_revision
            or read.authority_namespace!=scope.authority_namespace
            or host['source_proof_digest']!=current.source_proof_digest
            or host['guard_inventory_digest']!=current.guard_inventory_digest
            or host['source_closure']!=value['core_current']['source_closure']
            or host['source_purpose_groups']!=value['core_current']['source_purpose_groups']
            or host['read_versions']!=value['core_current']['read_versions']
            or host['query_coverage']!=value['core_current']['query_coverage']
            or host['original_deadline_utc']!=current.original_deadline_utc):
        raise ValueError('Named Joint provenance changed its exact selector/Core Scope/Host Source/original TTL')
    for name in('source_proof_digest','guard_inventory_digest','header_eof_digest'):
        digest=host[name]
        if type(digest)is not str or len(digest)!=64 or any(char not in '0123456789abcdef'for char in digest):
            raise ValueError('Named Joint provenance actual complete EOF digest differs')
    roots=tuple(ref for _,_,group in current.source_purpose_groups for ref in group)
    if note:
        original=host['original_source']
        required={'schema','original_evidence_digest','read_versions','source_purpose_groups','source_closure','source_proof_digest'}
        if(type(original)is not dict or set(original)!=required or original['schema']!='d10.named-source-note-original-host-inputs.v1'
                or original['original_evidence_digest']!=canonical_digest(current.original_evidence)):
            raise ValueError('Named SourceNote lost its distinct actual original Host Source evidence')
        from ..graph_types import GraphVersion
        versions=tuple(decode_typed_production_value_v1(v,GraphVersion)for v in original['read_versions'])
        closure=tuple(decode_typed_production_value_v1(v,GraphVersion)for v in original['source_closure'])
        if not set(current.original_evidence.read_versions)<=set(versions)or not set(closure)<=set(versions):raise ValueError('Named SourceNote Host Source evidence omitted actual original inputs')
        digest=original['source_proof_digest']
        if type(digest)is not str or len(digest)!=64 or any(c not in '0123456789abcdef'for c in digest):raise ValueError('Named SourceNote Host Source complete EOF proof differs')
        roots=tuple(set(roots)|{v.key.token for v in versions})
    refs={selector.argument.window_ref,current.long_plan_head.key.token,*roots,
        *(version.key.token for version in current.read_versions)}
    return selector,current,scope,tuple(sorted(refs))
