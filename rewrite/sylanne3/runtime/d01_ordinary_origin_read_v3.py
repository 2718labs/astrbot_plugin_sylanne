"""Actual fixed ordinary-persona originals on the consumer's independent READ.

These are metadata originals. No claim Body is retained before the caller has
qualified every selected block's complete current Source closure.
"""
from dataclasses import asdict
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..contracts import Event, Scope
from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch, Owner, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime_storage_v3 import begin_runtime_cell_read_v3
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2, _quote
from .d01_ordinary_origin_stream_v3 import OrdinaryOriginMetadataStreamV3
from .d01_ordinary_origin_v3 import (
    OrdinaryBlockCommitmentV3, OrdinaryHeadCommitmentV3,
    OrdinaryHistoryMemberV3, OrdinaryEventCommitmentV3, OrdinaryInitialCommitmentV3,
    OrdinaryRevisionCommitmentV3, OrdinaryWriteCommitmentV3,
    OrdinaryGrowthProposalCommitmentV3, OrdinaryGrowthRequestCommitmentV3,
    OrdinaryOriginalReferenceV3, OrdinaryTrialCommitmentV3, OrdinaryCounterCommitmentV3,
    OrdinaryGeneralStartCommitmentV3, OrdinaryGeneralIntentCommitmentV3,
    OrdinaryGrowthValueCommitmentV3, OrdinaryAdoptionCommitmentV3, OrdinaryOriginLineageV3)
from .source_correction_read_v3 import _heap

_COLUMNS = WeakKeyDictionary()


def _actual(owner):
    from .current_full_persona_writer_v1 import is_current_full_persona_writer_origin_owner_v1,require_current_full_persona_writer_origin_owner_v1
    if is_current_full_persona_writer_origin_owner_v1(owner):
        return require_current_full_persona_writer_origin_owner_v1(owner)
    from .role_control_lineage_metadata_v4 import role_control_lineage_origin_owner_v4,require_role_control_lineage_origin_owner_v4
    if role_control_lineage_origin_owner_v4(owner):
        return require_role_control_lineage_origin_owner_v4(owner)
    from .d01_ordinary_cumulative_growth_v1 import is_current_ordinary_origin_owner_v1, require_current_ordinary_origin_owner_v1
    if is_current_ordinary_origin_owner_v1(owner):
        return require_current_ordinary_origin_owner_v1(owner)
    from .d06_ordinary_readout_v3 import is_life_ordinary_origin_owner_v3,require_life_ordinary_origin_owner_v3
    if is_life_ordinary_origin_owner_v3(owner):
        return require_life_ordinary_origin_owner_v3(owner)
    from ..authority_service.d04_ordinary_source_v3 import authority_d04_origin_owner_v3,require_authority_d04_origin_owner_v3
    if authority_d04_origin_owner_v3(owner):
        return require_authority_d04_origin_owner_v3(owner)
    from .d04_source_work_v3 import require_installed_d04_source_reader_v3
    return require_installed_d04_source_reader_v3(owner)


def _need(value, reason):
    if not value:
        raise AuthorityUnavailable(reason)


def _fixed(owner, table, columns, where, args):
    _actual(owner)
    from .current_full_persona_writer_v1 import is_current_full_persona_writer_origin_owner_v1,read_full_persona_writer_fixed_metadata_v1
    if is_current_full_persona_writer_origin_owner_v1(owner):
        return read_full_persona_writer_fixed_metadata_v1(owner,table,columns,where,args)
    from .role_control_lineage_metadata_v4 import role_control_lineage_origin_owner_v4,read_role_control_lineage_fixed_v4
    if role_control_lineage_origin_owner_v4(owner):
        return read_role_control_lineage_fixed_v4(owner,table,columns,where,args)
    from .d01_ordinary_cumulative_growth_v1 import is_current_ordinary_origin_owner_v1, read_current_ordinary_fixed_metadata_v1
    if is_current_ordinary_origin_owner_v1(owner):
        return read_current_ordinary_fixed_metadata_v1(owner, table, columns, where, args)
    with owner.quantum_v3() as meter:
        return meter.read_fixed_row(owner.db, table, columns, where, args)


class OrdinaryOriginColumnV3:
    """One actual registered origin column; signatures cover the original bytes."""
    def __init__(self, owner, *, table, column, key_columns, key, profile, cell_id=None,
                 signed_header=None):
        _actual(owner)
        self.owner, self.db = owner, owner.db
        self.table, self.column, self.key_columns, self.key = table, column, key_columns, key
        self.profile, self.signed_header = profile, signed_header
        self.where = ' AND '.join(_quote(name)+'=?' for name in key_columns)
        self.reserved = 0
        self.cell = None
        if cell_id is not None:
            with owner.quantum_v3() as meter:
                self.cell = begin_runtime_cell_read_v3(self.db, cell_id,
                    erasure_owner_ref=key[0] if table in {'graph_history','graph_atoms'} else None)
        ascii_wire = self.cell is None or self.cell.header[0] == 'canonical-json.ascii.v1'
        if profile == "ordinary_model_plan_body":
            from .d01_ordinary_cumulative_growth_v1 import create_current_ordinary_model_body_stream_v1
            self.parser = create_current_ordinary_model_body_stream_v1(owner, key=key, ensure_ascii=ascii_wire, reserve=self.reserve)
        else:
            self.parser = OrdinaryOriginMetadataStreamV3(profile=profile,
                ensure_ascii=ascii_wire, reserve=self.reserve)
        self.position = 0
        self.total = None
        self.fragment = b''
        self.offset = 0
        self.complete = self.signature_verified = False
        self.verifier = None
        _COLUMNS[self] = (owner, table, column, key_columns, key, profile, cell_id, signed_header)
        if signed_header is not None:
            from .d01_production_operations_v1 import SIGN_KIND
            self.signer = owner.origin_signer
            self.verifier = self.signer.begin_original_stream_verification_v3(SIGN_KIND, self)

    def reserve(self, extra=0):
        retained = _heap((self.parser.nodes, self.parser.metadata, self.parser.fields,
            self.parser.scalar, self.parser.active_hashes, self.parser.commitments,
            self.parser.ranges, self.parser.claim_protocols, self.parser._claim_scan,
            self.parser.method_policy_claims, self.parser._method_policy_scan,
            self.fragment)) + extra + 131072
        if retained > self.reserved:
            self.owner.operation.retain(retained-self.reserved)
            self.reserved = retained

    def require_v3(self):
        owner = _actual(self.owner)
        expected = (owner, self.table, self.column, self.key_columns, self.key,
                    self.profile, None if self.cell is None else self.cell.cell_id, self.signed_header)
        saved = _COLUMNS.get(self)
        _need(saved is not None and saved[:6] == expected[:6] and saved[7] == self.signed_header,
              'ordinary origin column left its exact actual READ')
        return self

    def advance(self, meter):
        self.require_v3()
        if self.complete:
            return True
        if self.offset < len(self.fragment):
            end = min(self.offset+1024, len(self.fragment))
            part = self.fragment[self.offset:end]
            self.reserve(len(part)*12+65536)
            self.parser.advance_fragment_v3(part, meter)
            if self.verifier is not None:
                self.verifier.update(part)
            self.offset = end
            return False
        if self.cell is not None:
            chunk = self.cell.read_fragment(meter=meter)
            if chunk is not None:
                self.fragment, self.offset = chunk, 0
                return False
        else:
            if self.total is None or self.position < self.total:
                chunk, total, kind = read_legacy_sql_cell_fragment_v2(self.db,
                    table=self.table, column=self.column, where=self.where, parameters=self.key,
                    start=self.position, length=16384 if self.total is None else min(16384,self.total-self.position), meter=meter)
                if self.total is None:
                    self.total = total
                _need(total == self.total and kind == 'text', 'ordinary origin legacy column changed')
                self.position += len(chunk)
                self.fragment, self.offset = chunk, 0
                if chunk:
                    return False
        self.metadata, self.commitments, self.ranges, self.fields, parsed = self.parser.finish_metadata_v3()
        if self.cell is not None:
            digest = self.cell.finish(meter=meter)
            _need((parsed.sha256, parsed.byte_count) == (digest,self.cell.header[3]),
                  'ordinary origin canonical cell/header/full EOF differs')
        else:
            _need(parsed.byte_count == self.total, 'ordinary origin legacy canonical EOF differs')
        self.sha256, self.byte_count = parsed.sha256, parsed.byte_count
        self.semantic_digest = self.commitments[()]
        self.complete = True
        if self.signed_header is not None:
            from .d01_production_operations_v1 import SIGN_KIND
            self.signer.finish_original_stream_verification_v3(
                SIGN_KIND, self.signed_header[3], self, self.verifier)
            self.signature_verified = True
        self.reserve()
        return True


def require_ordinary_origin_signature_column_v3(column, *, signer, kind,
        signature=None, verifier=None, complete=False):
    from .current_full_persona_writer_v1 import require_full_persona_writer_signature_column_v1
    actual=require_full_persona_writer_signature_column_v1(column,signer=signer,kind=kind,
        signature=signature,verifier=verifier,complete=complete)
    if actual is not None:return actual
    from .d01_production_operations_v1 import SIGN_KIND
    _need(type(column) is OrdinaryOriginColumnV3, 'actual ordinary origin signature column required')
    column.require_v3()
    owner = column.owner
    _need(column.table == 'graph_d01_production_inputs_v1' and column.column == 'payload_json'
          and column.key_columns == ('bot','persona','original_ref')
          and column.key[:2] == owner.namespace.as_tuple
          and column.profile in {'proposal','trial','counter','general_intent','general_start','single_event_policy','single_event_input',
              'single_event_readout_case_metadata_v4',
              'ordinary_cumulative_policy','ordinary_basis_locator','ordinary_basis_body','ordinary_continuity_assessment','ordinary_deep_adoption'}
          and kind == SIGN_KIND and signer is owner.origin_signer
          and column.signed_header is not None,
          'ordinary origin signature recipe differs from its actual producer')
    if complete:
        _need(column.complete and signature == column.signed_header[3]
              and verifier is column.verifier, 'ordinary origin signature requires complete original EOF')
    return column


def _column(owner, table, column, key_columns, key, profile, *, cell_id=None, signed_header=None):
    from .current_full_persona_writer_v1 import is_current_full_persona_writer_origin_owner_v1,read_full_persona_writer_metadata_column_v1
    if is_current_full_persona_writer_origin_owner_v1(owner):
        return read_full_persona_writer_metadata_column_v1(owner,table=table,column=column,key_columns=key_columns,key=key,
            profile=profile,cell_id=cell_id,signed_header=signed_header)
    from .role_control_lineage_metadata_v4 import role_control_lineage_origin_owner_v4,read_role_control_lineage_column_v4
    if role_control_lineage_origin_owner_v4(owner):
        return read_role_control_lineage_column_v4(owner,table=table,column=column,key_columns=key_columns,key=key,
            profile=profile,cell_id=cell_id,signed_header=signed_header)
    from .d01_ordinary_cumulative_growth_v1 import is_current_ordinary_origin_owner_v1, read_current_ordinary_metadata_column_v1
    if is_current_ordinary_origin_owner_v1(owner):
        return read_current_ordinary_metadata_column_v1(owner, table=table, column=column, key_columns=key_columns,
            key=key, profile=profile, cell_id=cell_id, signed_header=signed_header)
    reader = OrdinaryOriginColumnV3(owner, table=table, column=column,
        key_columns=key_columns, key=key, profile=profile, cell_id=cell_id, signed_header=signed_header)
    while not reader.complete:
        with owner.quantum_v3() as meter:
            reader.advance(meter)
    owner.origin_columns.append(reader)
    return reader


def _typed(raw, cls):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, cls)


def _versions(raw):
    return tuple(_typed(v, GraphVersion) for v in raw)


def _references(raw):
    return tuple(OrdinaryOriginalReferenceV3(v['kind'],v['original_ref'],v['original_digest']) for v in raw)


def _history(owner, key, revision, profile):
    _need(NamespaceId.from_key(key) == owner.namespace and type(revision) is int and revision > 0,
          'ordinary origin historical locator crosses namespace or positive revision')
    profiles={'d01.persona_plan.v1':'plan','d01.persona_activation.v1':'activation',
        'd01.persona_revision.v1':'revision','d01.growth_contribution.v1':'growth','runtime.role_resources.v1':'resources',
        'd01.single_event_growth_adoption.v1':'single_event_adoption','d01.single_event_growth_review.v1':'single_event_review',
        'd01.single_event_growth_review.v2':'single_event_review'}
    from .d01_ordinary_cumulative_growth_v1 import is_current_ordinary_origin_owner_v1
    if is_current_ordinary_origin_owner_v1(owner):
        profiles['d01.ordinary_deep_growth_anchor.v1'] = 'ordinary_deep_anchor'
    _need(key.type_name in profiles,'ordinary origin history is outside its exact registered lineage family')
    profile=profiles[key.type_name]
    cached=owner.origin_history.get((key.token,revision))
    if cached is not None:return cached
    header = _fixed(owner,'graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
                    'token=? AND revision=?',(key.token,revision))
    _need(header is not None and header[0] == 1 and header[1:3] == owner.namespace.as_tuple,
          'ordinary origin exact history member unavailable')
    column = _column(owner,'graph_history','value',('token','revision'),
                     (key.token,revision),profile,cell_id=header[5])
    member = OrdinaryHistoryMemberV3(GraphVersion(key,revision),column.semantic_digest,True,
        Scope(*header[1:4]),header[4])
    owner.origin_history[(key.token,revision)]=(member,column)
    return member,column


def _head(owner, plan_version, activation_revision):
    from ..domains.d01 import PersonaActivation
    ns = owner.namespace
    akey = AtomKey(Owner('persona',*ns.as_tuple),'d01.persona_activation.v1','current')
    activation_member, ac = _history(owner,akey,activation_revision,'activation')
    activation = _typed(ac.metadata,PersonaActivation)
    _need(activation.plan_version == plan_version, 'ordinary origin head/activation version gap')
    pkey = AtomKey(Owner('persona',*ns.as_tuple),'d01.persona_plan.v1',activation.plan_id)
    plan_member, pc = _history(owner,pkey,plan_version,'plan')
    _need(plan_member.event_scope == activation_member.event_scope
          and plan_member.event_id == activation_member.event_id,
          'ordinary origin plan/activation did not share its actual commit')
    raw = pc.metadata
    _need(set(pc.fields[()]) == {'plan_id','namespace','version','blocks','values','authored'}
          and raw['namespace'] == asdict(ns)
          and (raw['plan_id'],raw['version']) == (activation.plan_id,plan_version),
          'ordinary origin exact plan schema/head differs')
    blocks = []
    for index, block in enumerate(raw['blocks']):
        path = ('blocks',index)
        _need(pc.fields[path] == {'block_id','kind','claim','plasticity'}
              and path+('claim',) in pc.parser.claim_protocols,
              'ordinary origin block has no complete dedicated-claim classification')
        blocks.append(OrdinaryBlockCommitmentV3(block['block_id'],block['kind'],block['plasticity'],
            pc.commitments[path+('claim',)],pc.parser.claim_protocols[path+('claim',)]))
    head = OrdinaryHeadCommitmentV3(ns,activation.plan_id,plan_version,raw['authored'],
        plan_member.ref,pc.semantic_digest,activation_member.ref,ac.semantic_digest,
        activation,tuple(blocks),pc.commitments[('values',)])
    return head,(plan_member,activation_member)


def _event(owner, event):
    ns = owner.namespace
    header = _fixed(owner,'graph_events',('digest','epoch_revision'),
        'bot=? AND persona=? AND session=? AND event_id=?',
        (*ns.as_tuple,event.scope.session,event.event_id))
    _need(header is not None, 'ordinary origin producer Graph event absent')
    key = (*ns.as_tuple,event.scope.session,event.event_id)
    cols = {name:_column(owner,'graph_events',name,('bot','persona','session','event_id'),
        key,'activation').metadata for name in ('reads','epoch_reads','revisions','invalidated')}
    return OrdinaryEventCommitmentV3(event,header[0],
        tuple(GraphVersion(AtomKey.from_token(ref),rev) for ref,rev in cols['reads']),
        tuple(NamespaceEpoch(*row) for row in cols['epoch_reads']),
        tuple(GraphVersion(AtomKey.from_token(ref),rev) for ref,rev in cols['revisions']),
        tuple(v.key for v in _event_invalidated_versions_v3(owner,event,cols['invalidated'])),header[1])



def _event_invalidated_versions_v3(owner,event,raw=None):
    if raw is None:
        raw = _column(owner,'graph_events','invalidated',('bot','persona','session','event_id'),
            (*owner.namespace.as_tuple,event.scope.session,event.event_id),'activation').metadata
    versions = []
    for value in raw:
        _need(type(value) in {list,tuple} and len(value) == 2
            and type(value[0]) is str and type(value[1]) is int and value[1] > 1,
            'ordinary origin invalidation is not its actual positive new history version')
        key = AtomKey.from_token(value[0])
        _need(NamespaceId.from_key(key) == owner.namespace
            and key not in {v.key for v in versions},
            'ordinary origin invalidation repeats/crosses namespace')
        versions.append(GraphVersion(key,value[1]))
    return tuple(versions)


def _signed(owner, ref, profile, expected_kind, observed):
    ns = owner.namespace
    header = _fixed(owner,'graph_d01_production_inputs_v1',
        ('kind','producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND original_ref=?',(*ns.as_tuple,ref))
    _need(header is not None and header[0] in expected_kind,
          'ordinary origin actual signed producer kind is unavailable')
    column = _column(owner,'graph_d01_production_inputs_v1','payload_json',
        ('bot','persona','original_ref'),(*ns.as_tuple,ref),profile,signed_header=header)
    roots = _column(owner,'graph_d01_production_inputs_v1','source_refs_json',
        ('bot','persona','original_ref'),(*ns.as_tuple,ref),'activation').metadata
    original = OrdinaryOriginalReferenceV3('d01.'+header[0],ref,header[2])
    _need(column.semantic_digest == header[2] and column.signature_verified and original in observed,
          'ordinary origin signed original is not an exact adopted original')
    producer = _fixed(owner,'graph_bundle_operations',('digest','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,header[1]))
    _need(producer is not None and type(producer[1]) is int and producer[1] > 0,
          'ordinary origin signed producer did not actually commit')
    receipt = _column(owner,'graph_bundle_operations','receipt_json',
        ('bot','persona','operation_id'),(*ns.as_tuple,header[1]),'activation').metadata
    _need(receipt.get('commit_seq') == producer[1]
          and receipt.get('status','committed') in {'committed','duplicate'},
          'ordinary origin signed producer original commit differs')
    return column,original,header,tuple(roots)




def _members_for_event(owner,event,expected):
    from .role_control_lineage_metadata_v4 import _require_invalidated_history_v4
    wanted = {v.key:v.revision for v in expected}
    invalidated = _event_invalidated_versions_v3(owner,event)
    _need(len(wanted) == len(expected)
        and not set(wanted).intersection(v.key for v in invalidated),
        'ordinary origin actual write/invalidation vector repeats a key')
    all_members = {**wanted,**{v.key:v.revision for v in invalidated}}
    for version in invalidated:
        _require_invalidated_history_v4(owner,version,event)
    members = []
    cursor = ''
    count = 0
    ns = owner.namespace
    while True:
        row = _fixed(owner,'graph_history',('token','revision'),
            'event_bot=? AND event_persona=? AND event_session=? AND event_id=? AND token>? ORDER BY token',
            (*ns.as_tuple,event.scope.session,event.event_id,cursor))
        if row is None:
            break
        key = AtomKey.from_token(row[0])
        _need(all_members.get(key) == row[1] and count < len(all_members),
              'ordinary origin actual producer history census has an extra/unsupported member')
        if key in wanted:
            member,_ = _history(owner,key,row[1],'activation')
            members.append(member)
        cursor = row[0]
        count += 1
    _need(count == len(all_members) and len(members) == len(wanted),
        'ordinary origin actual producer history census is incomplete')
    return tuple(members)


def _initial(owner):
    ns = owner.namespace
    row = _fixed(owner,'graph_role_init_receipts_v1',('operation_id',),
        'bot=? AND persona=?',ns.as_tuple)
    _need(row is not None, 'ordinary origin actual initialization receipt absent')
    receipt_column = _column(owner,'graph_role_init_receipts_v1','receipt_json',
        ('bot','persona'),ns.as_tuple,'initial_receipt')
    raw = receipt_column.metadata
    _need(raw['operation_id'] == row[0], 'ordinary origin initial operation differs')
    head,members = _head(owner,1,1)
    resources_key = AtomKey(Owner('persona',*ns.as_tuple),'runtime.role_resources.v1',head.plan_id)
    resource,rc = _history(owner,resources_key,1,'resources')
    event = Event(Scope(*ns.as_tuple,'d01-role-initialization'),raw['operation_id'],0,'role_initialized',
        {'input_digest':raw['input_digest'],'owner_grant_id':raw['owner_grant_id'],
         'authorization_head':raw['owner_authorization_head']})
    initial = OrdinaryInitialCommitmentV3(head,raw,receipt_column.semantic_digest,
        GraphVersion(owner_grant_key(*ns.as_tuple),raw['owner_grant_revision']),
        raw['owner_authorization_head'],resource.ref,rc.semantic_digest,
        NamespaceId(rc.metadata['bot_id'],rc.metadata['persona_id']),rc.metadata['operation_id'],
        rc.metadata['plan_id'],rc.metadata['head_id'],_event(owner,event),
        _members_for_event(owner,event,(*[m.ref for m in members],resource.ref)))
    return initial


def _adoption(owner, previous, successor, members):
    ns = owner.namespace
    operation = members[0].event_id
    header = _fixed(owner,'graph_domain_production_originals_v1',
        ('domain','operation_kind','original_digest','bundle_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation))
    _need(header is not None and header[0] == 'd01'
          and header[1] in {'adopt_growth','adopt_general_growth_v1','adopt_single_event_growth_v1'},
          'ordinary origin activation has an unsupported actual producer')
    key = (*ns.as_tuple,operation)
    pc = _column(owner,'graph_domain_production_originals_v1','original_payload_json',
        ('bot','persona','operation_id'),key,'adoption')
    payload = pc.metadata
    _need(pc.semantic_digest == header[2], 'ordinary origin adopted payload digest differs')
    from .domain_production_originals_v1 import _receipt
    receipt = _receipt(_column(owner,'graph_domain_production_originals_v1','receipt_json',
        ('bot','persona','operation_id'),key,'activation').metadata)
    reads = _column(owner,'graph_domain_production_originals_v1','read_versions_json',
        ('bot','persona','operation_id'),key,'activation').metadata
    _need(canonical_digest(receipt) == header[4], 'ordinary origin actual receipt digest differs')
    bundle = _fixed(owner,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',key)
    single_kind = header[1] == 'adopt_single_event_growth_v1'
    general_kind = header[1] in {'adopt_general_growth_v1','adopt_single_event_growth_v1'}
    provenance = payload['provenance']
    provenance_path = ('provenance','growth') if general_kind else ('provenance',)
    selected = provenance['growth'] if general_kind else provenance
    candidate = selected['candidate']
    candidate_path = provenance_path+('candidate',)
    observed = _references(payload['observed_originals'])
    originals = _references(selected['originals'])
    request = payload['request']
    single = None
    single_policy = single_input = None
    if single_kind:
        from ..domains.d01.single_event_growth_v1 import SingleEventGrowthPolicyV1, SingleEventGrowthInputV1
        ic, io, ih, ir = _signed(owner, request['input_ref'], 'single_event_input',
            {'single_event_growth_input_v1'}, observed)
        single_input = _typed(ic.metadata, SingleEventGrowthInputV1)
        sc, so, sh, sr = _signed(owner, single_input.policy_ref, 'single_event_policy',
            {'single_event_growth_policy_v1'}, observed)
        single_policy = _typed(sc.metadata, SingleEventGrowthPolicyV1)
        _need(tuple(sorted(single_input.source_refs)) == ir
              and tuple(sorted(single_policy.source_refs)) == sr,
              'single-event signed input/policy Source membership differs')
        request = {'growth_proposal_ref': single_input.growth_proposal_ref,
            'trigger_original_ref': single_input.trigger_original_ref,
            'trial_original_refs': single_input.trial_original_refs,
            'counterevidence_query_ref': single_input.counterevidence_query_ref,
            'general_growth_intent_ref': single_input.general_growth_intent_ref}
    proposal_column,proposal_original,ph,roots = _signed(owner,request['growth_proposal_ref'],
        'proposal',{'growth_proposal'},observed)
    proposal = proposal_column.metadata
    proposal_commitment = OrdinaryGrowthProposalCommitmentV3(
        proposal_original.original_ref,ph[0],ph[1],ph[2],canonical_digest(ph[3]),roots,
        proposal['proposal_id'],proposal['base_head'],proposal['target_block'],
        proposal_column.commitments[('replacement_claim',)],proposal['change_kind'],
        tuple(proposal['evidence_source_refs']),proposal['trigger_original_ref'],
        tuple(proposal['required_trial_refs']))
    trials = []
    for ref in request['trial_original_refs']:
        tc,to,th,_ = _signed(owner,ref,'trial',
            {'general_growth_trial_v1'} if general_kind else {'growth_trial','growth_trial_v2'},observed)
        tv = tc.metadata
        trials.append(OrdinaryTrialCommitmentV3(to,
            tv['growth_proposal_ref'],
            tuple(tv['evidence_source_refs']),tuple(tv['settled_outcome_refs']),
            tv['completed'],tv['trial_start_ref'] if general_kind else None))
    cc,co,_,_ = _signed(owner,request['counterevidence_query_ref'],'counter',
        {'growth_counterevidence'},observed)
    cv = cc.metadata
    counter = OrdinaryCounterCommitmentV3(co,cv['growth_proposal_ref'],
        tuple(cv['evidence_source_refs']),tuple(cv['counterevidence_source_refs']),
        cv['query_scope_ref'],cv['coverage_complete'])
    general = None
    general_provenance = provenance['general_growth'] if single_kind else provenance
    if general_kind:
        gc,go,_,_ = _signed(owner,request['general_growth_intent_ref'],'general_intent',
            {'general_growth_intent_v1'},observed)
        gv = gc.metadata
        starts = []
        for ref in gv['trial_start_refs']:
            sc,so,_,_ = _signed(owner,ref,'general_start',{'general_growth_trial_start_v1'},observed)
            sv = sc.metadata
            starts.append(OrdinaryGeneralStartCommitmentV3(so,sv['proposal_ref'],sv['proposal_digest'],
                sv['base_persona_head'],_typed(sv['base_persona_version'],GraphVersion),
                sv['target_block'],sv['completed_trial_ref']))
        general = OrdinaryGeneralIntentCommitmentV3(go,gv['schema'],
            pc.commitments[('provenance','general_growth','general_growth_intent') if single_kind else
                ('provenance','general_growth_intent')],gv['proposal_ref'],gv['proposal_digest'],
            tuple(gv['required_trial_refs']),tuple(gv['trial_start_refs']),
            tuple(gv['support_source_refs']),tuple(gv['context_source_refs']),tuple(starts),
            _references(general_provenance['trial_start_originals']),_references(general_provenance['trial_originals']))
    raw_revision = candidate['revision']
    revision_key = AtomKey(Owner('persona',*ns.as_tuple),'d01.persona_revision.v1',raw_revision['revision_id'])
    revision_version = next(v for v in receipt.write_versions if v.key == revision_key)
    revision_member,rc = _history(owner,revision_key,revision_version.revision,'revision')
    rv = rc.metadata
    revision = OrdinaryRevisionCommitmentV3(revision_version,rc.semantic_digest,
        rv['revision_id'],rv['previous_head'],rv['new_head'],successor.blocks,
        tuple(rv['continuity']['retained_blocks']),rv['continuity']['changed_block'],
        tuple(rv['continuity']['source_families']))
    writes = []
    growth = None
    for index, write in enumerate(payload['writes']):
        wkey = _typed(write['key'],AtomKey)
        actual = next(v for v in receipt.write_versions if v.key == wkey)
        member,wc = _history(owner,wkey,actual.revision,
            'plan' if wkey.type_name == 'd01.persona_plan.v1' else
            'growth' if wkey.type_name == 'd01.growth_contribution.v1' else 'revision')
        writes.append(OrdinaryWriteCommitmentV3(wkey,pc.commitments[('writes',index,'value')],
            tuple(_typed(v,AtomKey) for v in write['dependencies'])))
        if wkey.type_name == 'd01.growth_contribution.v1':
            value = wc.metadata
            item = OrdinaryGrowthValueCommitmentV3(wc.semantic_digest,value['proposal_id'],
                value['base_head'],value['target_block'],wc.commitments[('replacement_claim',)],
                tuple(value['source_families']),value['counterevidence_checked'],value['change_kind'],
                value['evidence_reality'])
            _need(growth is None or growth == item, 'ordinary origin contribution originals differ')
            growth = item
    _need(growth is not None, 'ordinary origin actual GrowthProposal contribution absent')
    owner.origin_support_readsets[proposal_original.original_ref] = {
        version.key:version.revision for version in _versions(candidate['read_versions'])
        if version.key.type_name == 'memory.source'}
    if single_kind:
        from .d01_ordinary_origin_v3 import OrdinarySingleEventCommitmentV1
        from ..domains.d01.single_event_growth_v1 import (SingleEventGrowthAdoptionV1,
            SingleEventGrowthReviewV1, SingleEventGrowthReviewV2,
            single_event_adoption_key_v1, single_event_review_key_v1, single_event_review_key_v2)
        ak = single_event_adoption_key_v1(ns, single_policy.terms.policy_ref)
        av = next(v for v in receipt.write_versions if v.key == ak)
        _, ac = _history(owner, ak, av.revision, 'single_event_adoption')
        adopted = _typed(ac.metadata, SingleEventGrowthAdoptionV1)
        rk = AtomKey.from_token(adopted.review_ref)
        if rk == single_event_review_key_v1(ns, single_policy.terms.policy_ref):
            review_type = SingleEventGrowthReviewV1
        elif rk == single_event_review_key_v2(ns, single_policy.terms.policy_ref):
            review_type = SingleEventGrowthReviewV2
        else:
            raise AuthorityUnavailable('single-event adoption has no exact V1/V2 review obligation')
        qv = next(v for v in receipt.write_versions if v.key == rk)
        _, qc = _history(owner, rk, qv.revision, 'single_event_review')
        candidate_writes = tuple(OrdinaryWriteCommitmentV3(_typed(w['key'], AtomKey),
            pc.commitments[candidate_path+('typed_writes', index, 'value')],
            tuple(_typed(k, AtomKey) for k in w['dependencies']))
            for index, w in enumerate(candidate['typed_writes']))
        single = OrdinarySingleEventCommitmentV1(single_policy, so, sh[1], single_input, io,
            adopted, _typed(qc.metadata, review_type),
            av, qv, candidate_writes)
    identity = payload['identity']
    event = Event(Scope(*ns.as_tuple,identity['activity_id']),operation,payload['now_utc'],
        'domain_bundle',{'bundle_digest':header[3]})
    return OrdinaryAdoptionCommitmentV3(ns,header[0],header[1],payload['schema'],operation,
        identity['activity_id'],identity['effect_id'],payload['now_utc'],header[2],header[3],
        payload['coverage'],tuple(payload['missing_inputs']),payload['continuation_ref'],
        OrdinaryGrowthRequestCommitmentV3(request['growth_proposal_ref'],request['trigger_original_ref'],
            tuple(request['trial_original_refs']),request['counterevidence_query_ref'],
            request['general_growth_intent_ref'] if general_kind else None),
        proposal_commitment,tuple(trials),counter,general,observed,originals,
        '.'.join(candidate_path),growth,successor,revision,
        pc.commitments[candidate_path+('revision',)],pc.commitments[candidate_path+('typed_writes',)],
        pc.commitments[('writes',)],candidate['head_id'],_versions(candidate['read_versions']),
        _versions(payload['read_versions']),
        tuple(GraphVersion(AtomKey.from_token(ref),rev) for ref,rev in reads),
        tuple(writes),_members_for_event(owner,event,receipt.write_versions),receipt,bundle,_event(owner,event),single)


def read_current_ordinary_origins_v3(owner, current_control):
    """Reconstruct the unique actual initial->current chain, then exact block origins."""
    _actual(owner)
    initial = _initial(owner)
    lineage = OrdinaryOriginLineageV3(initial)
    current,members = _head(owner,current_control.plan_version,
        next(v.revision for v in current_control.read_versions
             if v.key.type_name == 'd01.persona_activation.v1'))
    _need(current.head_id == current_control.head_id
          and current.plan_ref.key == current_control.plan_key,
          'ordinary origin actual protected current control changed')
    _need(current.version <= 1024, 'ordinary origin activation lineage exceeds its fixed bound')
    from .d01_ordinary_dedicated_origin_v3 import (
        DEDICATED_ORIGIN_KINDS_V3,advance_dedicated_ordinary_origins_v3)
    from ..domains.d01.ordinary_cumulative_growth_v1 import OrdinaryContinuityAnchorV1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    anchor = OrdinaryContinuityAnchorV1('initial',ProductionOriginalRefV1(
        'd01.role_initialization.v1',initial.receipt['operation_id'],initial.receipt_digest),
        initial.head,initial.receipt_digest)
    transitions = []
    previous = initial.head
    for revision in range(2,current.version+1):
        following,member = _head(owner,revision,revision)
        producer = _fixed(owner,'graph_domain_production_originals_v1',('operation_kind',),
            'bot=? AND persona=? AND operation_id=?',(*owner.namespace.as_tuple,member[0].event_id))
        _need(producer is not None,'ordinary origin actual transition producer is absent')
        if producer[0] in DEDICATED_ORIGIN_KINDS_V3:
            anchor,transitions = advance_dedicated_ordinary_origins_v3(
                owner,lineage,previous,following,member,anchor,transitions)
        else:
            adoption = _adoption(owner,previous,following,member)
            lineage.advance_v3(adoption)
            transitions.append((previous,following,adoption.operation_kind,adoption.original_digest,
                canonical_digest(adoption.receipt),adoption.event.recorded_digest))
            if adoption.single_event is not None:
                from .d01_single_event_readout_v4 import retain_single_event_ordinary_origin_v4
                retain_single_event_ordinary_origin_v4(owner,previous,adoption)
        previous = following
    selected = tuple((block.block_id,block.claim_digest) for block in current.blocks
                     if block.kind != 'semantic_identity' and block.claim_protocol is None)
    return current,lineage.finish_v3(current,selected)
