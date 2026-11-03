"""Historical semantic producer metadata for same-Method unchanged Persona copy."""
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest


def prepare_full_persona_semantic_copy_metadata_v1(state,block,producer):
    from .current_full_persona_writer_v1 import(issue_full_persona_copy_metadata_v1,
        copy_metadata_from_actual_producer_v1)
    if producer[0]=='initial':
        if block.claim_protocol is not None:
            raise AuthorityUnavailable('authored semantic copy must retain its actual legacy initialization protocol')
        return issue_full_persona_copy_metadata_v1(state,block,producer,(),())
    kind,operation,head=producer;owner=state.origin
    if kind not in {'migrate_semantic_identity_v3','adopt_growth'}:
        raise AuthorityUnavailable('semantic copy has no registered actual migration or semantic-growth producer')
    row,column,receipt=owner.producer_v1(operation);payload=column.metadata
    refs=payload['observed_originals'];roots=[]
    if kind=='migrate_semantic_identity_v3':
        request=payload['request']
        if(block.block_id not in request['target_block_ids']or request['expected_persona_head_id']!=next(
                before.head_id for before,after,_ in state.history if after.plan_ref==head.plan_ref)):
            raise AuthorityUnavailable('semantic migration actual target/base differs from the complete current lineage')
        ref=request.get('plasticity_policy_ref')
        if ref is not None:
            signed,_original,_header,sources=owner.signed_v1(ref,{'identity_plasticity_policy_v3'},refs)
            value=signed.metadata
            if block.block_id not in value['target_block_ids']:
                raise AuthorityUnavailable('actual signed semantic policy excludes this copied block')
            roots.extend(sources)
    else:
        request=payload['request'];intent,_original,_header,sources=owner.signed_v1(
            request['growth_proposal_ref'],{'growth_proposal'},refs)
        value=intent.metadata
        if value.get('schema')!='d01.growth-intent.v2'or value['target_block']!=block.block_id:
            raise AuthorityUnavailable('semantic copied growth has no actual V2 intent for this exact block')
        roots.extend(sources)
        for ref in request['trial_original_refs']:
            trial,_original,_header,sources=owner.signed_v1(ref,{'growth_trial','growth_trial_v2'},refs)
            if trial.metadata.get('growth_proposal_ref')!=request['growth_proposal_ref']:
                raise AuthorityUnavailable('semantic historical trial has another adopted intent')
            roots.extend(sources)
            start_ref=trial.metadata.get('trial_start_ref')
            if start_ref is not None:
                _start,_original,_header,sources=owner.signed_v1(start_ref,{'identity_trial_start_v3'},refs)
                roots.extend(sources)
        counter,_original,_header,sources=owner.signed_v1(request['counterevidence_query_ref'],{'growth_counterevidence'},refs)
        if counter.metadata.get('growth_proposal_ref')!=request['growth_proposal_ref']:
            raise AuthorityUnavailable('semantic historical counter original has another adopted intent')
        roots.extend(sources)
        from .full_persona_method_writer_metadata_v1 import full_writer_graph_metadata_v1
        continuity_ref=value['continuity_interpretation_ref']
        continuity,_version,_producer,_digest=full_writer_graph_metadata_v1(state,AtomKey.from_token(continuity_ref),{'serve_concern'})
        roots.extend(continuity['source_refs'])
    base=copy_metadata_from_actual_producer_v1(state,block,producer)
    groups=((state.reader.authority.purpose,tuple(state.reader.authority.audience),tuple(sorted(set(roots)))),)
    return issue_full_persona_copy_metadata_v1(state,block,producer,groups,base.dependencies,row[2])


def finish_full_persona_semantic_copy_v1(evidence,claim):
    evidence.require_v1(evidence.state)
    if evidence.producer[0]=='initial':return
    from ..domains.d01.identity_v3 import decode_semantic_identity_v3
    value=decode_semantic_identity_v3(claim)
    if value is None or value.block_id!=evidence.block.block_id:
        raise AuthorityUnavailable('semantic full Body differs from the actual copied dedicated protocol')
    state=evidence.state;row,column,_receipt=state.origin.producer_v1(evidence.producer[1]);payload=column.metadata
    if value.valid_from!=payload['now_utc']:
        raise AuthorityUnavailable('copied semantic revision has another actual historical adoption time')
    if evidence.producer[0]=='adopt_growth':
        request=payload['request'];intent,_original,_header,_sources=state.origin.signed_v1(
            request['growth_proposal_ref'],{'growth_proposal'},payload['observed_originals'])
        if(canonical_digest(value.claim)!=intent.commitments[('replacement_claim',)]
                or tuple(request['trial_original_refs'])!=value.trial_original_refs
                or request['counterevidence_query_ref']!=value.counterevidence_original_ref
                or tuple(intent.metadata['evidence_source_refs'])!=value.support_original_refs
                or intent.metadata['continuity_interpretation_ref']!=value.continuity_original_ref):
            raise AuthorityUnavailable('copied semantic Body lost its actual intent/trials/counter/continuity provenance')
    # This is historical unchanged-copy verification, not a new semantic readout.
    # Preserve the original validity/scope and do not require or extend old trial expiry.


def full_persona_single_event_target_v1(state):
    from .d01_single_event_growth_v1 import(PrepareSingleEventGrowthRequestV1,
        AdoptSingleEventGrowthRequestV1,ReviewSingleEventGrowthRequestV1)
    request=state.request;owner=state.origin;r=state.reader
    from .current_full_persona_writer_v1 import _SIGNED_PROFILE
    if type(request)is PrepareSingleEventGrowthRequestV1:
        policy_header=owner.fixed_v1('graph_d01_production_inputs_v1',('kind','producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND original_ref=?',(*r.namespace.as_tuple,request.policy_ref))
        if policy_header is None or policy_header[0]!='single_event_growth_policy_v1':
            raise AuthorityUnavailable('first single-event preparation requires its actual signed registered policy')
        policy=owner.column_v1('graph_d01_production_inputs_v1','payload_json',('bot','persona','original_ref'),
            (*r.namespace.as_tuple,request.policy_ref),_SIGNED_PROFILE,signed_header=policy_header)
        if not policy.signature_verified or policy.semantic_digest!=policy_header[2]:
            raise AuthorityUnavailable('first single-event policy has no complete signed original EOF')
        policy_producer,registration,_receipt=owner.producer_v1(policy_header[1])
        if(policy_producer[:2]!=('d01','register_single_event_growth_policy_v1')
                or policy.metadata['registration_operation_id']!=policy_header[1]
                or policy.commitments[('terms',)]!=registration.commitments[('request','terms')]):
            raise AuthorityUnavailable('first single-event policy is not its actual registered Owner/W01 terms')
        terms=policy.metadata['terms'];blocks={block.block_id:block for block in state.current.blocks}
        target=blocks.get(terms['target_block'])
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..graph_types import GraphVersion
        if(terms['namespace']!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
                or decode_typed_production_value_v1(terms['expected_persona_head'],GraphVersion)!=state.current.plan_ref
                or terms['persona_head_id']!=state.current.head_id or target is None
                or target.kind!=terms['target_kind'] or target.plasticity!='growth'
                or target.claim_digest!=terms['base_claim_digest']):
            raise AuthorityUnavailable('first single-event policy does not bind the actual current target metadata')
        proposal_ref=request.growth_request.growth_proposal_ref
        header=owner.fixed_v1('graph_d01_production_inputs_v1',('kind','producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND original_ref=?',(*r.namespace.as_tuple,proposal_ref))
        if header is None or header[0]!='growth_proposal':
            raise AuthorityUnavailable('first single-event target proposal is absent')
        proposal=owner.column_v1('graph_d01_production_inputs_v1','payload_json',('bot','persona','original_ref'),
            (*r.namespace.as_tuple,proposal_ref),_SIGNED_PROFILE,signed_header=header)
        if(not proposal.signature_verified or proposal.semantic_digest!=header[2]
                or proposal.metadata['base_head']!=state.current.head_id
                or proposal.metadata['target_block']!=terms['target_block']):
            raise AuthorityUnavailable('first single-event actual signed proposal differs from its registered target')
        return terms['target_block']
    if type(request)is AdoptSingleEventGrowthRequestV1:
        row=owner.fixed_v1('graph_d01_production_inputs_v1',('kind','producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND original_ref=?',(*r.namespace.as_tuple,request.input_ref))
        if row is None or row[0]!='single_event_growth_input_v1':
            raise AuthorityUnavailable('single-event writer target lacks its real signed input')
        column=owner.column_v1('graph_d01_production_inputs_v1','payload_json',('bot','persona','original_ref'),
            (*r.namespace.as_tuple,request.input_ref),_SIGNED_PROFILE,signed_header=row)
        if not column.signature_verified or column.semantic_digest!=row[2]:
            raise AuthorityUnavailable('single-event writer target input has no full signed EOF')
        ref=column.metadata['growth_proposal_ref']
        header=owner.fixed_v1('graph_d01_production_inputs_v1',('kind','producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND original_ref=?',(*r.namespace.as_tuple,ref))
        if header is None or header[0]!='growth_proposal':raise AuthorityUnavailable('single-event signed proposal is absent')
        proposal=owner.column_v1('graph_d01_production_inputs_v1','payload_json',('bot','persona','original_ref'),
            (*r.namespace.as_tuple,ref),_SIGNED_PROFILE,signed_header=header)
        if not proposal.signature_verified or proposal.metadata['base_head']!=state.current.head_id:
            raise AuthorityUnavailable('single-event target proposal changed its current base')
        return proposal.metadata['target_block']
    if type(request)is ReviewSingleEventGrowthRequestV1:
        from .full_persona_method_writer_metadata_v1 import full_writer_graph_metadata_v1
        from ..domains.d01.single_event_growth_v1 import ADOPTION_TYPE
        key=AtomKey.from_token(request.adoption_ref)
        if key.type_name!=ADOPTION_TYPE:
            raise AuthorityUnavailable('single-event review target must come from the real adoption reference')
        value,_ref,_producer,_digest=full_writer_graph_metadata_v1(state,key,{'adopt_single_event_growth_v1'})
        return value['target_block']
    return None
