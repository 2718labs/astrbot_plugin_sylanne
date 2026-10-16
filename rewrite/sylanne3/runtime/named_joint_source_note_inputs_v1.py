"""Additional fixed Host input profile for the unchanged selected SourceNote recipe.

Its upper bound is the actual privately issued original FG/OwnerTask WRITE
readset. It grants no new foreground operation, original family or Root route.
"""
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import canonical_digest
from .current_method_learning_read_v3 import _method_preplan_families_v3

_BODY_TYPES=frozenset({'d02.body_state.v1','d02.body_profile.v1','d02.reservation.v1','memory.source'})
_FAMILIES=_method_preplan_families_v3('prepare_selected_source_note_action_v2')|(_BODY_TYPES-{'memory.source'})|frozenset({
    'd03.role_binding','d05.boundary_rule','d08.commitment.v1','d08.action_intent.v1','d08.action_outcome.v1',
    'd07.current_interpretation.v1','d07.focus.v1','d07.attention_ticket.v1'})

def note_original_profile_v1(state):
    return getattr(state,'note_original_profile',None)

def prepare_named_source_note_original_inputs_v1(reader,issued):
    if type(reader.selector)is not NamedJointSourceNoteSelectorV1:return
    from .named_joint_binding_issuance_v1 import require_named_joint_issuance_v1
    current=require_named_joint_issuance_v1(issued,reader.graph,reader.write_scope)
    original=issued.original_issuance.evidence
    if original!=current.original_evidence:raise AuthorityUnavailable('SourceNote recipe lost the actual original WRITE issuance')
    versions={v.key:v.revision for v in original.read_versions}
    if len(versions)!=len(original.read_versions):raise AuthorityUnavailable('Original SourceNote signed readset duplicates a Graph identity')
    state=reader.inputs
    for key,revision in versions.items():
        head=state.work.heads.get(key.token)
        if (0 if head is None else head[0])!=revision:raise AuthorityUnavailable('Original SourceNote recipe readset changed before Host Source ALL')
    roots=tuple(sorted(key.token for key in versions if key.type_name=='memory.source'))
    if not roots:raise AuthorityUnavailable('Original SourceNote issuer supplied no complete actual Source closure')
    audiences=reader.authority.audience
    groups=tuple((purpose,audience,roots)for purpose in('context','consolidation')for audience in audiences)
    profile={'issued':issued,'original':original,'versions':versions,'groups':groups,'materials':(),
        'future':current.future_identity,'schema_key':None,'source_proof_digest':None}
    profile['originals']={}
    state.note_original_profile=profile
    selector=reader.selector.original_selector
    from ..authority_service.current_foreground_activity_v1 import ForegroundActivityRequestV1
    job_ref=selector.cycle_job_ref if type(selector)is ForegroundActivityRequestV1 else selector.task_job_ref
    key=AtomKey.from_token(job_ref)
    if key not in versions:raise AuthorityUnavailable('Original SourceNote current readset omitted its actual parent task job')
    state.job_ids.add(key.name)
    for actual in state.originals.values():seed_named_source_note_original_refs_v1(state,actual)
    from .named_joint_source_work_v3 import _prepare_materials
    old_groups,old_roots=state.groups,state.roots
    start=len(state.materials)
    try:
        state.groups=groups;_prepare_materials(state)
        profile['materials']=tuple(state.materials[start:])
        for atom in reader.namespace_reader.atoms:
            if atom.key in versions:
                if atom.revision!=versions[atom.key]:raise AuthorityUnavailable('Original SourceNote current Source control differs from its signed readset')
                state.bodies[atom.key]=atom
        profile['source_proof_digest']=canonical_digest(('d10.named-source-note-original-host-inputs.v1',
            reader.selector.original_selector,original,groups,tuple(sorted((ref,w.canonical_semantic_digest)
                for m in profile['materials']for ref,w in m.witnesses.items()))))
    finally:state.groups,state.roots=old_groups,tuple(sorted(set(old_roots)|set(roots)))

def require_named_source_note_original_atom_v1(state,key):
    profile=note_original_profile_v1(state)
    if profile is None:return False
    from .named_joint_binding_issuance_v1 import require_named_joint_issuance_v1
    issued=profile['issued'];require_named_joint_issuance_v1(issued,issued.graph,issued.scope)
    if key in profile['versions']:return True
    future=profile['future'];action=AtomKey.from_token(future.action_ref)
    from ..graph_types import AtomKey as Key
    outputs={action,Key(action.owner,'d08.action_cancellation.v1',action.name)}
    if profile['schema_key']is not None:outputs.add(profile['schema_key'])
    if key in outputs:
        if state.work.heads.get(key.token,(0,))[0]!=0:raise AuthorityUnavailable('Original SourceNote future output identity already exists')
        return True
    selected={state.request.argument.window_ref}
    selected.add(state.observed.long_plan_head.key.token)
    if state.observed.prior_window_head is not None:selected.add(state.observed.prior_window_head.key.token)
    if key.token in selected or key==owner_grant_key(*state.work.namespace.as_tuple):return True
    raise AuthorityUnavailable('Original SourceNote recipe requested a Graph input absent from its actual signed original readset')

def named_source_note_original_family_v1(state,type_id):
    profile=note_original_profile_v1(state)
    if profile is None:return False
    if type_id not in _FAMILIES:raise AuthorityUnavailable('Original SourceNote recipe requested another registered family')
    for ref,head in state.work.heads.items():
        key=AtomKey.from_token(ref)
        if key.type_name==type_id and profile['versions'].get(key)!=head[0]:
            raise AuthorityUnavailable('Original SourceNote signed readset lacks an actual complete recipe family member')
    return True

def named_source_note_original_coverage_v1(state):
    from ..runtime_contracts import QueryEpoch
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    if note_original_profile_v1(state)is None:return ()
    types=tuple(sorted(_FAMILIES))
    for kind in types:named_source_note_original_family_v1(state,kind)
    ns=state.work.namespace
    return tuple(ProductionQueryCoverageV1(QueryEpoch(ns,'namespace',state.work.graph_stamp[0]),kind,
        tuple(GraphVersion(AtomKey.from_token(ref),head[0])for ref,head in state.work.heads.items()if AtomKey.from_token(ref).type_name==kind),True,None)for kind in types)


def named_source_note_original_versions_v1(state):
    profile=note_original_profile_v1(state)
    if profile is None:return ()
    versions=dict(profile['versions'])
    versions.update((key,atom.revision)for key,atom in state.bodies.items())
    for m in profile['materials']:
        for v in m.versions:versions[v.key]=v.revision
    return tuple(GraphVersion(k,v)for k,v in sorted(versions.items(),key=lambda item:item[0].token))

def named_source_note_original_provenance_v1(state):
    profile=note_original_profile_v1(state)
    if profile is None:return None
    from ..domains.d01.production_operations_v1 import plain_v1
    return {'schema':'d10.named-source-note-original-host-inputs.v1','original_evidence_digest':canonical_digest(profile['original']),
        'read_versions':plain_v1(named_source_note_original_versions_v1(state)),
        'source_purpose_groups':plain_v1(tuple((purpose,(audience,),roots)for purpose,audience,roots in profile['groups'])),
        'source_closure':plain_v1(tuple(sorted(set(v for m in profile['materials']for v in m.versions),key=lambda v:v.key.token))),
        'source_proof_digest':profile['source_proof_digest']}


def seed_named_source_note_original_refs_v1(state,actual):
    profile=note_original_profile_v1(state)
    if profile is None or actual['operation_kind']!='prepare_personal_candidates_v1':return
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1
    from .d08_personal_candidate_v1 import personal_candidate_evidence_read_plan_v3
    prepared=decode_typed_production_value_v1(actual['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
    evidences=[(prepared.need.original,prepared.need.read_versions,prepared.need.query_coverage)]
    for candidate in prepared.candidates:
        if candidate.quote_ref is not None:state.quote_keys.add((candidate.quote_ref,1))
        for original in candidate.eligibility.originals:evidences.append((original,candidate.eligibility.read_versions,candidate.eligibility.query_coverage))
        if candidate.price is not None:evidences.append((candidate.price.original,candidate.price.read_versions,candidate.price.query_coverage))
    plan=personal_candidate_evidence_read_plan_v3(read_versions=prepared.read_versions,query_coverage=prepared.query_coverage,
        future_decision_ref=prepared.future_decision_ref,preparation_original_digest=actual['original_digest'],evidences=tuple(evidences))
    if any(key not in profile['versions'] for key in plan.exact_keys if key.token!=prepared.future_decision_ref):
        raise AuthorityUnavailable('Original SourceNote signed current readset omits its ALL candidate evidence closure')
    for original,_,_ in evidences:profile['originals'][original.original_ref]=(original.kind,original.original_digest)
    profile['originals']['d08-current:'+actual['original_digest'][:48]]=('d08.current-prepare_personal_candidates_v1',actual['original_digest'])

def admit_named_source_note_producer_v1(state,operation_id):
    profile=note_original_profile_v1(state)
    if profile is None:return False
    from ..authority_service.named_joint_binding_source_read_v3 import _fixed
    row=_fixed(state.work,'graph_domain_production_originals_v1',('domain','operation_kind','original_digest'),
        'bot=? AND persona=? AND operation_id=?',(*state.work.namespace.as_tuple,operation_id))
    if row is None:return False
    ref=row[0]+'-current:'+row[2][:48]
    if profile['originals'].get(ref)!=(row[0]+'.current-'+row[1],row[2]):return False
    state.producer_ids.add(operation_id)
    return True
