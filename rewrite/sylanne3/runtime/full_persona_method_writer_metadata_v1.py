"""Actual method and ordinary producer metadata for unchanged full Persona copy."""
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest


def full_writer_graph_metadata_v1(state,key,expected_kinds):
    from .current_full_persona_writer_v1 import _SIGNED_PROFILE
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_method_learning_v1 import VALUE_TYPES
    from ..domains.d01.single_event_growth_v1 import ADOPTION_TYPE
    if key.type_name not in {*VALUE_TYPES,ADOPTION_TYPE,'d07.current_interpretation.v1'}or NamespaceId.from_key(key)!=state.reader.namespace:
        raise AuthorityUnavailable('full writer graph metadata has no exact registered method/SingleEvent family')
    owner=state.origin
    head=owner.fixed_v1('graph_atoms',('revision','valid','value_cell_id'),
        'bot=? AND persona=? AND token=?',(*owner.namespace.as_tuple,key.token))
    if head is None or head[1]!=1:raise AuthorityUnavailable('full writer actual immutable method original is absent')
    history=owner.fixed_v1('graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
        'token=? AND revision=?',(key.token,head[0]))
    if history is None or history[:3]!=(1,*owner.namespace.as_tuple)or history[5]!=head[2]:
        raise AuthorityUnavailable('full writer method current/history metadata origin differs')
    column=owner.column_v1('graph_history','value',('token','revision'),(key.token,head[0]),_SIGNED_PROFILE,cell_id=head[2])
    producer,original,receipt=owner.producer_v1(history[4]);ref=GraphVersion(key,head[0])
    if producer[1]not in expected_kinds or ref not in receipt.write_versions:
        raise AuthorityUnavailable('full writer method metadata has another actual registered producer')
    matches=tuple(i for i,write in enumerate(original.metadata['writes'])if decode_typed_production_value_v1(write['key'],AtomKey)==key)
    if len(matches)!=1 or original.commitments[('writes',matches[0],'value')]!=column.semantic_digest:
        raise AuthorityUnavailable('full writer method metadata differs from actual producing typed write')
    return column.metadata,ref,producer,column.semantic_digest


def prepare_full_persona_method_copy_metadata_v1(state,block,producer):
    from .current_full_persona_writer_v1 import(issue_full_persona_copy_metadata_v1,
        copy_metadata_from_actual_producer_v1)
    if producer[0]=='initial':return issue_full_persona_copy_metadata_v1(state,block,producer,(),())
    from .d01_method_learning_v1 import ADOPT,REVIEW,REGISTER_TRIAL,REGISTER_TRIAL_V2,REGISTER_PROTOCOL,EVALUATE
    if producer[0]!=ADOPT:raise AuthorityUnavailable('ST2 method copy has no actual registered method adopter')
    row,column,receipt=state.origin.producer_v1(producer[1]);p=column.metadata['provenance'];request=column.metadata['request']
    if p['method_outcome_review_ref']!=request['review_ref']:
        raise AuthorityUnavailable('method copied producer changed its actual review reference')
    review,review_ref,_producer,review_digest=full_writer_graph_metadata_v1(state,AtomKey.from_token(request['review_ref']),{REVIEW})
    if review_digest!=p['method_outcome_review_digest']:
        # The profile retains the complete closed review controls; no policy or model prose.
        raise AuthorityUnavailable('method copied producer review commitment differs')
    if review['target_block']!=block.block_id or review['qualification']!='qualified' or review['missing_items']:
        raise AuthorityUnavailable('method copied producer did not adopt a qualified review for this exact block')
    trial,trial_ref,_producer,trial_digest=full_writer_graph_metadata_v1(state,AtomKey.from_token(review['trial_ref']),{REGISTER_TRIAL,REGISTER_TRIAL_V2})
    protocol,protocol_ref,_producer,protocol_digest=full_writer_graph_metadata_v1(state,AtomKey.from_token(review['protocol_ref']),{REGISTER_PROTOCOL})
    if(trial['target_block']!=block.block_id or trial['protocol_ref']!=review['protocol_ref']
            or trial['protocol_digest']!=review['protocol_digest'] or protocol_digest!=review['protocol_digest']):
        raise AuthorityUnavailable('method copied trial/protocol/review lineage differs')
    roots=list(review['source_refs']);roots.extend(trial['source_refs']);roots.extend(protocol['source_refs'])
    refs=[review_ref,trial_ref,protocol_ref]
    for ref in review['evaluation_refs']:
        evaluation,version,_producer,evaluation_digest=full_writer_graph_metadata_v1(state,AtomKey.from_token(ref),{EVALUATE})
        if evaluation['trial_ref']!=review['trial_ref']or evaluation['protocol_digest']!=review['protocol_digest']:
            raise AuthorityUnavailable('method copied evaluation belongs to another actual trial/protocol')
        roots.extend(evaluation['source_refs']);refs.append(version)
    base=copy_metadata_from_actual_producer_v1(state,block,producer)
    if not {version.key for version in refs}<=set(base.dependencies):
        raise AuthorityUnavailable('method copied plan dropped its real review/trial/protocol/evaluation dependencies')
    groups=((state.reader.authority.purpose,tuple(state.reader.authority.audience),tuple(sorted(set(roots)))),)
    return issue_full_persona_copy_metadata_v1(state,block,producer,groups,base.dependencies,row[2])


def finish_full_persona_method_copy_v1(evidence,claim):
    import json
    evidence.require_v1(evidence.state)
    value=json.loads(claim)
    expected='ST0'if evidence.producer[0]=='initial'else'ST2'
    if(set(value)!={'schema','policy_id','strategy_state'}or value['schema']!='d01.method-policy.v1'
            or value['strategy_state']!=expected):
        raise AuthorityUnavailable('method copied full Body changed its actual ST0 initialization/ST2 adoption protocol')
    from .d01_method_learning_v1 import POLICY_ID
    if value['policy_id']!=POLICY_ID:raise AuthorityUnavailable('method copied Body has another registered policy identity')


def prepare_full_persona_ordinary_copy_metadata_v1(state,block,producer):
    from .current_full_persona_writer_v1 import(issue_full_persona_copy_metadata_v1,
        copy_metadata_from_actual_producer_v1)
    from .d01_ordinary_origin_read_v3 import _adoption
    from .d01_ordinary_origin_v3 import validate_ordinary_adoption_v3
    from .role_control_lineage_metadata_v4 import _read_history_member_v4
    kind,operation,head=producer
    before=next(previous for previous,following,_transition in state.history if following.plan_ref==head.plan_ref)
    roots=[]
    if kind in {'adopt_growth','adopt_general_growth_v1','adopt_single_event_growth_v1'}:
        members=tuple(_read_history_member_v4(state.origin,v.key,v.revision)[0]for v in(head.plan_ref,head.activation_ref))
        adopted=_adoption(state.origin,before,head,members)
        selections,_=validate_ordinary_adoption_v3(before,adopted)
        roots.extend(selection.source.key.token for selection in selections)
    elif kind=='adopt_ordinary_deep_growth_v1':
        from ..domains.d01.ordinary_cumulative_growth_v1 import DEEP_ADOPTION_KIND
        from .current_full_persona_writer_v1 import _SIGNED_PROFILE
        row,original,_receipt=state.origin.producer_v1(operation)
        ref='ordinary-deep:'+operation
        header=state.origin.fixed_v1('graph_d01_production_inputs_v1',('kind','producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND original_ref=?',(*state.reader.namespace.as_tuple,ref))
        if header is None or header[:2]!=(DEEP_ADOPTION_KIND,operation):
            raise AuthorityUnavailable('ordinary deep copied block lacks its actual signed same-W01 output original')
        column=state.origin.column_v1('graph_d01_production_inputs_v1','payload_json',('bot','persona','original_ref'),
            (*state.reader.namespace.as_tuple,ref),_SIGNED_PROFILE,signed_header=header)
        if not column.signature_verified or column.semantic_digest!=header[2]:
            raise AuthorityUnavailable('ordinary deep copied block output original has no complete signed EOF')
        roots=tuple(column.metadata['support_source_refs'])
        actual_roots=state.origin.column_v1('graph_d01_production_inputs_v1','source_refs_json',('bot','persona','original_ref'),
            (*state.reader.namespace.as_tuple,ref),'activation').metadata
        if tuple(actual_roots)!=roots:
            raise AuthorityUnavailable('ordinary deep copied output Source roots differ from its signed support original')
        if(header[1]!=operation or column.commitments[('base_head',)]!=canonical_digest(before)
                or column.commitments[('successor_head',)]!=canonical_digest(head)):
            raise AuthorityUnavailable('ordinary deep copied block has another real signed predecessor/successor')
    else:raise AuthorityUnavailable('ordinary copied block has no registered actual adopter')
    base=copy_metadata_from_actual_producer_v1(state,block,producer)
    groups=((state.reader.authority.purpose,tuple(state.reader.authority.audience),tuple(sorted(set(roots)))),)
    return issue_full_persona_copy_metadata_v1(state,block,producer,groups,base.dependencies,base.original_digest)


def full_writer_frozen_graph_metadata_v1(selector,version):
    selector.require_v1();state=selector.state;owner=state.origin
    if version not in selector.allowed_versions or version.revision<1:
        raise AuthorityUnavailable('conditioned full writer metadata escaped the actual producer frozen read set')
    owner.reader.store._registry.spec(version.key.type_name)
    if NamespaceId.from_key(version.key)!=owner.namespace:
        raise AuthorityUnavailable('conditioned full writer frozen metadata crossed namespace')
    from .current_full_persona_writer_v1 import _SIGNED_PROFILE
    history=owner.fixed_v1('graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
        'token=? AND revision=?',(version.key.token,version.revision))
    if history is None or history[:3]!=(1,*owner.namespace.as_tuple):
        raise AuthorityUnavailable('conditioned full writer exact historical metadata original is absent')
    column=owner.column_v1('graph_history','value',('token','revision'),(version.key.token,version.revision),
        _SIGNED_PROFILE,cell_id=history[5])
    from .conditioned_self_operations_v1 import VALUE_TYPES
    if version.key.type_name in {*VALUE_TYPES,'d07.current_interpretation.v1'}:
        row,producer,receipt=owner.producer_v1(history[4])
        if version not in receipt.write_versions:
            raise AuthorityUnavailable('conditioned frozen graph metadata is not an actual producer write')
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        matches=tuple(i for i,write in enumerate(producer.metadata['writes'])if decode_typed_production_value_v1(write['key'],AtomKey)==version.key)
        if len(matches)!=1 or producer.commitments[('writes',matches[0],'value')]!=column.semantic_digest:
            raise AuthorityUnavailable('conditioned frozen graph metadata differs from its exact actual typed-write origin')
    else:
        # Match the original Conditioned history rule: inbound/C02 and other
        # registered graph controls have real events, not DomainOriginal rows.
        event_key=(*owner.namespace.as_tuple,history[3],history[4])
        event=owner.fixed_v1('graph_events',('digest','epoch_revision'),
            'bot=? AND persona=? AND session=? AND event_id=?',event_key)
        revisions=owner.column_v1('graph_events','revisions',('bot','persona','session','event_id'),event_key,'activation')
        from .d01_ordinary_origin_read_v3 import _versions
        if event is None or version not in _versions(revisions.metadata):
            raise AuthorityUnavailable('conditioned frozen registered control lacks its actual event/version metadata origin')
    return column.metadata,version,column.semantic_digest


def full_persona_method_target_v1(state):
    from .d01_method_learning_v1 import ADOPT,REVIEW
    if state.reader.operation_kind!=ADOPT:return None
    value,_version,_producer,_digest=full_writer_graph_metadata_v1(state,AtomKey.from_token(state.request.review_ref),{REVIEW})
    if value['base_persona_head']!=state.current.head_id or value['qualification']!='qualified' or value['missing_items']:
        raise AuthorityUnavailable('full writer method target is not the real qualified review at this actual current base')
    return value['target_block']
