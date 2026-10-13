"""Finite historical C04/draft producer originals; no live observation or grant."""
from copy import copy
from dataclasses import fields,is_dataclass,asdict
from hashlib import sha256
import json
import sys
from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold,_D13PaidRowStreamV3
from ..runtime_contracts import VersionedRef,canonical_digest,canonical_serialize,meter_canonical_outputs


def _heap(value):
    total=sys.getsizeof(value)
    if type(value) is dict:total+=sum(_heap(k)+_heap(v) for k,v in value.items())
    elif type(value) in (tuple,list,set):total+=sum(_heap(v) for v in value)
    elif is_dataclass(value) and not isinstance(value,type):total+=sum(_heap(getattr(value,f.name)) for f in fields(value))
    return total


class _ProducerWitnessRowV4(_D13PaidRowStreamV3):
    """Full Source/disposition commitment, independently shaped target, then value."""
    def __init__(self,parent):
        self.parent=parent;self.capture=parent.capture;self.graph=parent.graph
        self.shape,self.row_key=parent.locator.rows[parent.row_index]
        self.row_where=' AND '.join('"'+name+'"=?' for name in self.shape.primary_key_columns)
        self.json_columns=('value','dependencies','reads','epoch_reads','revisions','invalidated')
        self.decode_names=('value',) if self.shape.table=='graph_history' and self.row_key==(parent.reference.ref,parent.reference.version) else ()
        self.phase='origin';self.small=None;self.target_small=None;self.disposition=None
        self.source_hash=sha256();self.target_hash=sha256();self.column=0;self.offset=0;self.total=None
        self.parser=None;self.buffer=bytearray();self.values={};self.json_source_bytes={};self.complete=False
        self.capture.parser._source_arena.add(self)
    def owned_values(self):return ()
    def advance(self,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_c09_table_shape_v2
        result=self.copy();self.graph.require_current()
        if result.phase=='origin':
            result.disposition=self.capture.builder.basis.read_d13_context_epoch_row_original_v3(self.parent.locator,self.parent.row_index,meter=meter);result.phase='small'
        elif result.phase=='small':
            names=tuple(n for n in result.shape.columns if n not in result.json_columns)
            with legacy_cell_read_transaction_v2(self.graph.pair.source):
                row=meter.read_fixed_row(self.graph.pair.source,result.shape.table,names,result.row_where,result.row_key)
            if row is None:raise C09PagedCaptureHold('producer historical Source witness disappeared')
            result.small=dict(zip(names,row,strict=True));result.phase='source_row'
        elif result.phase=='source_row':result._row_advance(False,meter)
        elif result.phase=='target':
            with legacy_cell_read_transaction_v2(self.graph._read_db):
                shape=read_c09_table_shape_v2(self.graph._read_db,result.shape.table,meter=meter)
                if (shape.primary_key_columns,shape.primary_key_types)!=(result.shape.primary_key_columns,result.shape.primary_key_types):
                    raise C09PagedCaptureHold('producer historical target changed logical primary key')
                names=tuple(n for n in shape.columns if n not in result.json_columns)
                row=meter.read_fixed_row(self.graph._read_db,shape.table,names,result.row_where,result.row_key)
            if result.disposition.disposition=='derived_removed':
                if row is not None:raise C09PagedCaptureHold('removed producer witness survived in target')
                result.phase='fields'
            else:
                if row is None:raise C09PagedCaptureHold('retained producer witness absent in target')
                result.shape=shape;result.target_small=dict(zip(names,row,strict=True));result.phase='target_row'
        elif result.phase=='target_row':result._row_advance(True,meter)
        elif result.phase=='fields':result._read_fields(meter)
        elif result.phase=='identity':result.complete=True
        else:raise C09PagedCaptureHold('unknown producer witness row phase')
        self.capture.parser._require_arena();return result


class NaturalProducerQualificationOriginalReadV4:
    def __init__(self,parent):
        from .c09_authority_storage_rebase_v2 import _D13OutboundAdoptionReadV3
        from ..runtime.natural_producer_qualification_v1 import C04_KIND,DRAFT_KIND
        if (type(parent) is not _D13OutboundAdoptionReadV3 or parent.phase!='natural_producer_qualification_originals'
                or parent.natural_qualification_original is None or not parent.natural_qualification_original.complete):
            raise C09PagedCaptureHold('producer qualification requires actual Source and external-unit originals')
        self.parent=parent;self.capture=parent.capture;self.graph=parent.graph;self.source=parent.natural_reference_facts.source
        self.facts=parent.natural_reference_facts.parser;self.external=parent.natural_source_original
        self.paths=tuple(parent.natural_qualification_original.producer_paths)
        kinds=[self.facts.metadata[path+('d06_claim_kind',)] for path in self.paths]
        if any(kind not in {C04_KIND,DRAFT_KIND} for kind in kinds):
            raise C09PagedCaptureHold('frozen natural scope has an unknown producer family')
        self.epoch=parent.natural_acquires['generation'].acquire['graph_epoch'];self.envelope=parent.natural_requests['generation'].request_envelope
        self.c02_operation_id=parent.natural_preparations['generation'].small['parent_original_id']
        self.guard={};self.guard_index=0;self.phase='guard';self.index=0;self.verified={};self.complete=False
        self.unit=None;self.field_names=();self.field_index=0;self.buffer=bytearray();self.offset=0
        self.members={};self.histories={};self.context_tokens=set();self.pending=[];self.reference=None;self.locator=None;self.row=None;self.row_index=0;self.after_members=None
        self.data={};self.producer=None;self.projection=None;self.roots=();self.walk=[];self.walk_active=set();self.walk_seen=set();self.source_refs={};self.access_refs={};self.correction_refs={}
        self.source.arena.add(self);self.source.require_arena()
    def _source_heap_bytes(self):
        return sys.getsizeof(self.__dict__)+sum(_heap(v) for v in (self.paths,self.guard,self.verified,self.unit,self.buffer,self.members,self.histories,
            self.context_tokens,self.pending,self.reference,self.locator,self.data,self.projection,self.roots,self.walk,self.walk_active,self.walk_seen,
            self.source_refs,self.access_refs,self.correction_refs))+4096
    def copy(self):
        self.source.require_arena(self._source_heap_bytes());result=copy(self)
        for name in ('guard','verified','members','histories','data','source_refs','access_refs','correction_refs'):setattr(result,name,dict(getattr(self,name)))
        result.unit=None if self.unit is None else dict(self.unit);result.buffer=bytearray(self.buffer);result.pending=list(self.pending)
        result.context_tokens=set(self.context_tokens);result.walk=list(self.walk);result.walk_active=set(self.walk_active);result.walk_seen=set(self.walk_seen)
        self.source.arena.add(result);return result
    def _codec(self,meter,size,action):
        meter.require_available(size);self.source.require_arena(size*32+65536)
        with meter_canonical_outputs(meter):return action()
    def _queue(self,token,version=None,*,context=False):
        if version is None:version=self.guard.get(token)
        if type(version) is not int or version<0 or self.guard.get(token)!=version:raise C09PagedCaptureHold('producer member is absent from original generation guard')
        if context:self.context_tokens.add(token)
        ref=VersionedRef(token,version)
        if token in self.members:
            if self.members[token].revision!=version:raise C09PagedCaptureHold('producer member changed guarded revision')
        elif ref not in self.pending:self.pending.append(ref)
    def _guard(self,meter):
        reads=self.envelope.version_guard.read_versions
        if self.guard_index==len(reads):self.phase='unit';return
        row=reads[self.guard_index];owner=row.key.owner
        upper=32+sum(len(v)*12 for v in (owner.kind,owner.bot,owner.persona,owner.subject,row.key.type_name,row.key.name) if v is not None)
        meter.require_available(upper);self.source.require_arena(upper*16+16384);token=row.key.token;meter.charge_encode(len(token))
        if token in self.guard:raise C09PagedCaptureHold('original generation guard repeats member')
        self.guard[token]=row.revision;self.guard_index+=1
    def _unit(self,meter):
        if self.index==len(self.paths):self.complete=True;return
        path=self.paths[self.index];self.source.require_arena((len(self.facts.references)+32)*512)
        self.unit={name:self.facts.metadata[path+(name,)] for name in self.facts._unit_scalars}
        for name in self.facts._unit_ref_arrays:
            refs={p[5]:ref for p,ref in self.facts.references.items() if len(p)==6 and p[:5]==path+(name,)}
            if set(refs)!=set(range(len(refs))):raise C09PagedCaptureHold('producer reference indices incomplete')
            self.unit[name]=[asdict(refs[i]) for i in range(len(refs))]
        ref=self.facts.references.get(path+('qualification_ref',))
        if ref is None or ref.version<1:raise C09PagedCaptureHold('producer unit lacks positive qualification locator')
        self.unit['qualification_ref']=asdict(ref);self.field_names=tuple(sorted({'qualified_text','source_excerpt',*self.facts._unit_tuple_fields}))
        self.field_index=0;self.offset=0;self.buffer.clear();self.phase='unit_fields'
    def _unit_field(self,meter):
        if self.field_index==len(self.field_names):
            ref=VersionedRef(**self.unit['qualification_ref']);self._queue(ref.ref,ref.version,context=True)
            self.after_members='producer_locator';self.phase='members';return
        name=self.field_names[self.field_index];left,right=self.source.evidence.projection_ranges[self.paths[self.index]+(name,)];self.source.require_range(left,right)
        if self.offset==right-left:
            value=self._codec(meter,len(self.buffer),lambda:json.loads(self.buffer))
            self.unit[name]=value;self.buffer.clear();self.offset=0;self.field_index+=1;return
        amount=min(1024,right-left-self.offset);self.source.require_arena((len(self.buffer)+amount)*2+32768)
        self.buffer.extend(self.source._read_fragment(left+self.offset,amount,meter));self.offset+=amount
    def _members(self,meter):
        from ..graph_types import AtomKey,GraphAtom
        if self.reference is None:
            if not self.pending:self.phase=self.after_members;return
            self.reference=self.pending.pop(0);self.locator=self.capture.builder.basis.read_d13_context_epoch_locator_v3(self.reference,self.epoch,meter=meter)
            self.row_index=0;self.row=None;return
        if self.row_index<len(self.locator.rows):
            if self.row is None:self.row=_ProducerWitnessRowV4(self)
            elif not self.row.complete:self.row=self.row.advance(meter)
            else:
                if self.row.shape.table=='graph_history' and self.row.row_key==(self.reference.ref,self.reference.version):
                    if self.row.small['valid']!=1:raise C09PagedCaptureHold('producer historical positive member invalid')
                    self.members[self.reference.ref]=GraphAtom(AtomKey.from_token(self.reference.ref),self.reference.version,self.row.values['value'],True)
                    self.histories[self.reference.ref]=self.row.small['event_id']
                self.row_index+=1;self.row=None
            return
        if self.reference.version==0:
            if not self.locator.absent:raise C09PagedCaptureHold('producer zero revision lacks historical absence')
            self.members[self.reference.ref]=GraphAtom(AtomKey.from_token(self.reference.ref),0,{},False)
        elif self.reference.ref not in self.members:raise C09PagedCaptureHold('producer exact guarded history absent')
        self.reference=None;self.locator=None
    def _source_sql(self,meter,action):
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
        self.source.require_arena(meter.available_bytes*16+65536)
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            with meter_canonical_outputs(meter):return action(_BoundedReadConnectionV2(self.graph.pair.source,meter))
    def _producer_locator(self,meter):
        from ..runtime.natural_producer_qualification_v1 import C04_KIND,read_c04_expression_originals_from_history_v4
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        ref=VersionedRef(**self.unit['qualification_ref']);atom=self.members[ref.ref]
        if self.unit['d06_claim_kind']==C04_KIND:
            raw=self._codec(meter,c09_canonical_json_size_v3(atom.value)*2,lambda:canonical_serialize(atom.value))
            history=(self.histories[ref.ref],raw,1)
            self.data['c04']=self._source_sql(meter,lambda db:read_c04_expression_originals_from_history_v4(db,self.parent.namespace,self.c02_operation_id,ref,atom,history))
            self.data['binding']=self.data['c04'][1].binding;self.phase='journal'
        else:
            from ..runtime.d11_life_fact_provenance_v1 import decode_life_fact_auxiliary_v1,ELIGIBILITY_TYPE
            eligibility=self._codec(meter,c09_canonical_json_size_v3(atom.value)*4,lambda:decode_life_fact_auxiliary_v1(ELIGIBILITY_TYPE,atom.value))
            self.data['eligibility']=eligibility;self._queue(eligibility.provenance_ref,eligibility.provenance_revision,context=True)
            self.after_members='draft_provenance';self.phase='members'
    def _draft_provenance(self,meter):
        from ..runtime.d11_life_fact_provenance_v1 import decode_life_fact_auxiliary_v1,PROVENANCE_TYPE
        from ..runtime.d11_life_contract_v1 import D11DraftExecutionBindingV1,draft_artifact_ref_v1
        from ..runtime.natural_producer_qualification_v1 import _draft_locator
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        eligibility=self.data['eligibility'];atom=self.members[eligibility.provenance_ref]
        proof=self._codec(meter,c09_canonical_json_size_v3(atom.value)*4,lambda:decode_life_fact_auxiliary_v1(PROVENANCE_TYPE,atom.value))
        binding=proof.binding
        if (type(binding) is not D11DraftExecutionBindingV1 or binding.namespace!=self.parent.namespace
                or eligibility.fact_ref!=proof.fact_ref or proof.fact_ref!=binding.artifact_ref
                or self._codec(meter,c09_canonical_json_size_v3(atom.value)*2,lambda:canonical_digest(atom.value))!=eligibility.provenance_digest
                or binding.artifact_ref!=draft_artifact_ref_v1(binding.namespace,binding.effect_id)):
            raise C09PagedCaptureHold('draft qualification lost deterministic actual producer proof')
        self.data['binding']=binding;self.data['draft']=self._source_sql(meter,lambda db:_draft_locator(db,self.parent.namespace,self.c02_operation_id,
            binding.artifact_ref,self.capture.builder.session._control.maintenance._installed_d11_budget_job_issuer_v2));self.phase='journal'
    def _journal(self,meter):
        from .c09_paged_recovery_facts_v2 import begin_installed_c09_recovery_facts_v2
        from ..runtime.natural_producer_qualification_v1 import C04_KIND
        if self.producer is None:self.producer=begin_installed_c09_recovery_facts_v2(self.capture.builder.session,self.graph.pair)
        kind='internal' if self.unit['d06_claim_kind']==C04_KIND else 'life';binding=self.data['binding']
        original=self.producer.read_indexed_producer_original_v4(binding.execution_id,kind,meter=meter,require_arena=self.source.require_arena)
        if kind=='internal':
            proof=original['original']
            if proof.binding!=binding:raise C09PagedCaptureHold('C04 journal crossed actual prepared binding')
            self.data['proof']=proof;self.phase='c04_inputs'
        else:
            saved=original['original'];prepared,terminal,_,_,_=self.data['draft']
            if saved[0]!=binding or saved[1]!=terminal.claim or saved[2]!=terminal or prepared.binding!=binding:
                raise C09PagedCaptureHold('draft signed Graph terminal differs from independent journal')
            self.phase='draft_inputs'
    def _c04_inputs(self,meter):
        from ..runtime.d11_c04_internal_cost import read_c04_cpu_cost_original_v1
        from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1
        from ..runtime.c04_interpretation_policy_v3 import read_installed_c04_interpretation_policy_v3
        from ..runtime.jobs import get_job
        from ..graph_types import AtomKey
        from ..domains.d03.self_perspective import self_mapping_key
        _,prepared,work,_,_,preparation,_=self.data['c04'];p=preparation['payload']['provenance']
        self.data['cpu']=self._source_sql(meter,lambda db:read_c04_cpu_cost_original_v1(db,self.parent.namespace,prepared.binding.operation_id))
        self.data['body']=self._source_sql(meter,lambda db:read_c04_body_cost_original_v1(db,self.parent.namespace,prepared.binding.operation_id))
        self.data['policy']=self._source_sql(meter,lambda db:read_installed_c04_interpretation_policy_v3(db,self.parent.namespace,prepared,
            installation_id=work.direct_selection.installation_id,manifest_digest=work.direct_selection.manifest_digest))[0]
        self.data['child']=self._source_sql(meter,lambda db:get_job(db,AtomKey.from_token(p['child_job_ref']).name))
        self._queue(p['child_job_ref'],context=True);self._queue(self_mapping_key(self.parent.namespace).token,context=True)
        for row in self.data['c04'][4]['interpretation']['source_heads']:self._queue(row['ref'],row['revision'])
        self.after_members='c04_self';self.phase='members'
    def _draft_inputs(self,meter):
        from ..runtime.d11_life_adoption_v1 import _read_signed
        from .d11_life_bridge_v1 import life_bridge_from_wire_v1,D11DraftSelfAdoptionBridgeV2
        from ..runtime.d11_life_fact_provenance_v1 import life_current_fact_reads_v1,life_fact_auxiliary_key_v1,PROVENANCE_TYPE,ELIGIBILITY_TYPE
        from ..runtime.d11_life_graph_types_v1 import life_role_segment_key_v1
        from ..runtime.d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
        from ..domains.d03.self_perspective import self_mapping_key
        from ..graph_types import AtomKey
        prepared,terminal,adopted,_,_=self.data['draft'];issuer=self.capture.builder.session._control.maintenance._installed_d11_budget_job_issuer_v2
        saved=self._source_sql(meter,lambda db:_read_signed(db,self.parent.namespace,'adoption_bridge',terminal.binding.execution_id,issuer))
        if saved is None:raise C09PagedCaptureHold('draft expression has no signed original Self bridge')
        bridge=life_bridge_from_wire_v1(saved[1])
        if type(bridge) is not D11DraftSelfAdoptionBridgeV2 or bridge.binding!=terminal.binding or bridge.terminal!=terminal:
            raise C09PagedCaptureHold('draft Self bridge crossed actual terminal/family')
        self.data['self_bridge']=bridge
        facts=(AtomKey.from_token(terminal.binding.artifact_ref),life_role_segment_key_v1(terminal.binding,'start'),life_role_segment_key_v1(terminal.binding,'end'))
        for fact in facts:
            for key in (fact,life_fact_auxiliary_key_v1(fact,PROVENANCE_TYPE),life_fact_auxiliary_key_v1(fact,ELIGIBILITY_TYPE)):self._queue(key.token,context=True)
        for key in life_outcome_read_keys_v1(terminal.binding,prepared.plan.action_intent.ref):self._queue(key.token,context=True)
        for frozen in life_current_fact_reads_v1(prepared):self._queue(frozen.ref,frozen.revision,context=True)
        self._queue(self_mapping_key(self.parent.namespace).token,context=True);self.after_members='draft_self';self.phase='members'
    def _self_original(self,current,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,c09_canonical_json_size_v3
        from .v2_self_identity_service import SelfIdentityMutationReceiptV1
        from ..domains.d03.self_identity_qualification import self_identity_mapping_from_current
        from ..domains.d03.self_perspective import self_mapping_key
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        core=self.capture.builder.pair.source
        with legacy_cell_read_transaction_v2(core):
            row=_BoundedReadConnectionV2(core,meter).execute('SELECT authority_namespace,request_digest,receipt_json FROM authority_self_identity_operations_v1 WHERE operation_id=?',(current.registration_operation_id,)).fetchone()
            head=_BoundedReadConnectionV2(core,meter).execute('SELECT namespace_json,installation_id,manifest_digest,mapping_id,self_entity_ref,revision,revocation_epoch,state,registration_operation_id,registration_digest FROM authority_self_identity_heads_v1 WHERE authority_namespace=?',(current.authority_namespace,)).fetchone()
        from ..contracts import canonical_json
        namespace_json=self._codec(meter,c09_canonical_json_size_v3(asdict(current.namespace))*2,lambda:canonical_json(asdict(current.namespace)))
        expected=(namespace_json,current.installation_id,current.manifest_digest,current.mapping_id,current.self_entity_ref,
            current.mapping_revision,current.mapping_revocation_epoch,'active',current.registration_operation_id,current.registration_digest)
        if head!=expected or current.mapping_revision!=1 or current.mapping_revocation_epoch!=0:
            raise C09PagedCaptureHold('producer Self immutable registration was replaced or revoked before frozen Source')
        if row is None:raise C09PagedCaptureHold('producer historical Self registration absent')
        receipt=self._codec(meter,len(row[2])*4,lambda:SelfIdentityMutationReceiptV1(**json.loads(row[2])))
        receipt_json=self._codec(meter,len(row[2])*2,lambda:canonical_json(asdict(receipt)))
        if receipt_json!=row[2]:raise C09PagedCaptureHold('producer actual Self registration receipt wire differs')
        if (row[:2]!=(current.authority_namespace,current.registration_digest) or receipt.operation_id!=current.registration_operation_id
                or receipt.authority_namespace!=current.authority_namespace
                or receipt.mapping_id!=current.mapping_id or receipt.request_digest!=current.registration_digest
                or receipt.revision!=current.mapping_revision or receipt.revocation_epoch!=current.mapping_revocation_epoch or receipt.state!='active'
                or current.namespace!=self.parent.namespace or current.authority_id!=self.capture.builder.scope.authority_id
                or current.installation_id!=self.capture.builder.scope.installation_id):
            raise C09PagedCaptureHold('producer historical Self differs from immutable Core registration')
        mapping=self._codec(meter,c09_canonical_json_size_v3(current,typed=True)*3,lambda:self_identity_mapping_from_current(current))
        from ..domains.d01.production_operations_v1 import plain_v1
        atom=self.members[self_mapping_key(self.parent.namespace).token]
        if atom.value!=plain_v1(mapping):raise C09PagedCaptureHold('historical Self mapping differs from actual Core-qualified projection')
        return atom
    def _c04_self(self,meter):
        from .v2_self_identity_contract import from_wire,to_wire,AuthorityCurrentSelfIdentityV1
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3,legacy_cell_read_transaction_v2
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        _,prepared,work,_,_,preparation,_=self.data['c04'];p=preparation['payload']['provenance'];saved=p.get('self_scope_original')
        if type(saved) is not dict or set(saved)!={'schema','scope_payload','current_self_wire'} or saved['schema']!='c04.self-preparation-original.v1':
            raise C09PagedCaptureHold('C04 lacks actual self_scope_original preimage; legacy digest cannot be backfilled')
        current=self._codec(meter,c09_canonical_json_size_v3(saved)*4,lambda:from_wire(saved['current_self_wire']));material=saved['scope_payload']
        if (type(current) is not AuthorityCurrentSelfIdentityV1 or to_wire(current)!=saved['current_self_wire']
                or type(material) is not dict or set(material)!={'schema','request','selection_original_digest','self','owner_guard','authority','identity',
                    'deadline','budget','policy','responsibility_digest','c03_metadata_bridge'} or material['schema']!='c04.self-preparation-scope.v4'
                or preparation['payload']['provenance']['schema']!='c04.self-foreground-preparation.v5'):
            raise C09PagedCaptureHold('C04 captured scope/current Self exact formal inventory differs')
        def untyped(value):
            if type(value) is dict:return {k:untyped(v) for k,v in value.items() if k!='$type'}
            if type(value) is list:return [untyped(v) for v in value]
            return value
        plain={name:untyped(value) for name,value in material.items()};payload=preparation['payload']
        if (any(plain[name]!=payload[name] for name in ('request','owner_guard','authority','identity'))
                or plain['selection_original_digest']!=work.c03_selection_original_digest
                or plain['request']['c02_operation_id']!=self.c02_operation_id
                or plain['request']['c03_selection_ref']!=work.c03_selection_ref
                or plain['request']['source_ref']!=work.cue_source_ref
                or plain['identity']['operation_id']!=prepared.binding.operation_id
                or plain['authority']['actor']!=current.self_entity_ref):
            raise C09PagedCaptureHold('C04 captured scope request/Owner/authority/identity/deadline changed')
        def same():return canonical_digest(material)==p['self_scope_digest']==work.self_scope_digest and json.loads(canonical_serialize(current))==material['self']
        if not self._codec(meter,c09_canonical_json_size_v3(saved)*4,same):raise C09PagedCaptureHold('C04 actual captured Self preimage differs from work or original wire')
        if (current.self_entity_ref!=p['initiating_self'] or current.activation_generation!=prepared.binding.activation_generation
                or current.graph_epoch>=self.epoch or material['selection_original_digest']!=work.c03_selection_original_digest
                or (current.installation_id,current.manifest_digest)!=(work.direct_selection.installation_id,work.direct_selection.manifest_digest)):
            raise C09PagedCaptureHold('C04 captured Self/time/selection differs from original interval')
        with legacy_cell_read_transaction_v2(self.capture.builder.pair.source):
            row=_BoundedReadConnectionV2(self.capture.builder.pair.source,meter).execute('SELECT permit,state FROM authority_v2_fences WHERE operation_id=?',(current.permit.operation_id,)).fetchone()
        from .v2_contract import canonical_bytes
        encoded=self._codec(meter,c09_canonical_json_size_v3(saved)*4,lambda:canonical_bytes(current.permit));meter.charge_encode(len(encoded))
        if row!=(encoded,'finished'):raise C09PagedCaptureHold('C04 historical Self lacks actual finished Core permit')
        from ..runtime.d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
        from ..runtime.jobs import _utc
        actual_c03=self._source_sql(meter,lambda db:read_adopted_ingress_c03_selection_v1(db,namespace=self.parent.namespace,c02_operation_id=self.c02_operation_id))
        if (actual_c03 is None or material['selection_original_digest']!=actual_c03[1]['original_digest']
                or self._codec(meter,c09_canonical_json_size_v3(actual_c03[2],typed=True)*2,lambda:json.loads(canonical_serialize(actual_c03[2])))!=material['c03_metadata_bridge']
                or self._codec(meter,c09_canonical_json_size_v3(work.budget,typed=True)*2,lambda:json.loads(canonical_serialize(work.budget)))!=material['budget']
                or material['responsibility_digest']!=actual_c03[0].responsibility_digest
                or material['policy']!=plain['request']['recall_policy_digest']
                or material['deadline']>_utc(p['before_parent']['deadline_utc'],'deadline').timestamp()
                or material['deadline']<preparation['payload']['now_utc']
                or current.request_operation_id!=prepared.binding.operation_id or current.permit.operation_id!=prepared.binding.operation_id
                or (plain['owner_guard']['grant_ref'],plain['owner_guard']['grant_revision'],plain['owner_guard']['grant_digest'])
                    !=(prepared.owner_grant_ref,prepared.owner_grant_revision,prepared.owner_grant_digest)
                or current.graph_epoch>=work.graph_epoch or work.graph_epoch>=self.epoch):
            raise C09PagedCaptureHold('C04 original Self interval/C03/Owner/responsibility/policy does not close')
        self.data['self_atom']=self._self_original(current,meter);self.phase='c04_projection'

    def _draft_self(self,meter):
        from .c09_life_recovery_originals_v1 import require_original_draft_self_bridge_core_v2
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        bridge=self.data['self_bridge']
        with legacy_cell_read_transaction_v2(self.capture.builder.pair.source):
            with meter_canonical_outputs(meter):require_original_draft_self_bridge_core_v2(_BoundedReadConnectionV2(self.capture.builder.pair.source,meter),gate=bridge)
        self.data['self_atom']=self._self_original(bridge.current_self,meter);self.phase='draft_members';self.data['member_index']=0
    def _draft_members(self,meter):
        from ..runtime.d11_life_fact_provenance_v1 import life_current_fact_reads_v1,life_read_digest_v1
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        prepared,terminal,adopted,_,_=self.data['draft']
        reads=life_current_fact_reads_v1(prepared);position=self.data['member_index']
        if position<len(reads):
            frozen=reads[position];member=self.members[frozen.ref]
            actual=self._codec(meter,c09_canonical_json_size_v3(member.value)*2,lambda:canonical_digest(member.value))
            expected=self._codec(meter,c09_canonical_json_size_v3(frozen,typed=True)*2,lambda:life_read_digest_v1(frozen))
            if member.revision!=frozen.revision or member.valid!=frozen.valid or actual!=expected:
                raise C09PagedCaptureHold('draft producer read changed by original generation epoch')
            self.data['member_index']=position+1;return
        commitments=adopted['write_commitments'];position-=len(reads)
        selected=[row for row in commitments if row['ref'] in self.context_tokens]
        if position==len(selected):self.phase='draft_projection';return
        row=selected[position];member=self.members[row['ref']]
        actual=self._codec(meter,c09_canonical_json_size_v3(member.value)*2,lambda:canonical_digest(member.value))
        if (member.revision!=row['revision'] or not member.valid or actual!=row['digest']
                or self.histories[member.key.token]!=adopted['producing_operation_id']):
            raise C09PagedCaptureHold('draft actual generation fact/proof/eligibility lost signed adoption membership')
        self.data['member_index']+=1
    def _c04_projection(self,meter):
        from ..runtime.natural_producer_qualification_v1 import c04_expression_original_projection_v4
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        atom,prepared,work,plan,provenance,preparation,adopted=self.data['c04']
        for row in provenance['interpretation']['source_heads']:
            member=self.members[row['ref']]
            if (member.revision!=row['revision'] or member.valid!=row['valid'] or
                    self._codec(meter,len(row['value_json'])*2,lambda:canonical_serialize(member.value))!=row['value_json']):
                raise C09PagedCaptureHold('C04 source head differs from original generation history')
        child_ref=preparation['payload']['provenance']['child_job_ref']
        size=sum(c09_canonical_json_size_v3(value,typed=True) for value in (self.data['proof'],work,provenance,atom.value,self.data['cpu'],self.data['body']))*12
        self.projection=self._codec(meter,size,lambda:c04_expression_original_projection_v4(atom=atom,prepared=prepared,work=work,plan=plan,
            provenance=provenance,preparation=preparation,adopted=adopted,proof=self.data['proof'],cpu=self.data['cpu'],body=self.data['body'],
            policy=self.data['policy'],self_atom=self.data['self_atom'],child=self.data['child'],child_atom=self.members[child_ref],
            audience_id=self.unit['audience_ref'],valid_until_utc=self.unit['expires_at_utc']))
        self.phase='begin_closure'
    def _draft_projection(self,meter):
        from ..runtime.natural_producer_qualification_v1 import draft_expression_original_projection_v4
        from ..runtime.d11_life_fact_provenance_v1 import life_fact_auxiliary_key_v1,PROVENANCE_TYPE,ELIGIBILITY_TYPE
        from ..graph_types import AtomKey
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        prepared,terminal,adopted,readback,activity=self.data['draft'];fact_key=AtomKey.from_token(terminal.binding.artifact_ref)
        fact=self.members[fact_key.token];proof=self.members[life_fact_auxiliary_key_v1(fact_key,PROVENANCE_TYPE).token]
        eligibility=self.members[life_fact_auxiliary_key_v1(fact_key,ELIGIBILITY_TYPE).token]
        size=sum(c09_canonical_json_size_v3(value,typed=True) for value in (prepared,terminal,adopted,readback,self.data['self_atom'].value))*6
        self.projection=self._codec(meter,size,lambda:draft_expression_original_projection_v4(prepared=prepared,terminal=terminal,adopted=adopted,
            readback=readback,activity=activity,self_atom=self.data['self_atom'],fact=fact,proof=proof,eligibility=eligibility,
            result_ref=terminal.binding.artifact_ref,audience_id=self.unit['audience_ref'],valid_until_utc=self.unit['expires_at_utc']))
        self.phase='begin_closure'
    def _begin_closure(self,meter):
        self.roots=tuple(self.projection['roots']);self.walk=[(ref,False) for ref in reversed(self.roots)]
        self.walk_active=set();self.walk_seen=set();self.phase='closure'
    def _closure(self,meter):
        from ..graph_types import AtomKey
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        if not self.walk:self.phase='candidate';return
        token,exit_node=self.walk.pop()
        if exit_node:self.walk_active.remove(token);self.walk_seen.add(token);return
        if token in self.walk_active:raise C09PagedCaptureHold('producer historical Source ancestry cyclic')
        if token in self.walk_seen:return
        if len(self.walk_active)+len(self.walk_seen)>=256:raise C09PagedCaptureHold('producer Source closure exceeds formal 256 bound')
        upper=(len(token)+sum(map(len,self.parent.namespace.as_tuple))+128)*48
        meter.require_available(upper);self.source.require_arena(upper*16+16384)
        key=AtomKey.from_token(token);namespace=self.parent.namespace
        if key!=source_key(*namespace.as_tuple,key.owner.subject or ''):
            raise C09PagedCaptureHold('producer Source is not canonical in original namespace')
        access=access_key(*namespace.as_tuple,key.owner.subject).token;correction=source_correction_head_key(namespace,key.owner.subject).token
        meter.charge_encode(len(token)+len(key.token)+len(access)+len(correction))
        record=self.external.sources.get(token);permission=self.external.accesses.get(access)
        if (record is None or permission is None or correction not in self.external.corrections
                or record['source_id']!=key.owner.subject or permission['source_id']!=key.owner.subject
                or permission['status']!='active' or self.unit['audience_ref'] not in record['audiences']
                or self.unit['audience_ref'] not in permission['audiences']
                or 'expression' not in record['purposes'] or 'expression' not in permission['purposes']):
            raise C09PagedCaptureHold('producer Source ancestor lacks verified historical expression permission')
        for name,ref in (('source_refs',token),('access_refs',access),('correction_refs',correction)):
            revision=self.guard.get(ref)
            if type(revision) is not int or (revision!=0 if name=='correction_refs' else revision<1):
                raise C09PagedCaptureHold('producer Source closure absent from original generation guard')
            original=VersionedRef(ref,revision)
            if original not in self.external.references:raise C09PagedCaptureHold('producer Source closure differs from independently verified epoch witness')
            getattr(self,name)[ref]=original
        self.walk_active.add(token);self.walk.append((token,True))
        parents=record['parent_source_ids'];parent_upper=sum((len(p)+sum(map(len,namespace.as_tuple))+128)*24 for p in parents)
        meter.require_available(parent_upper);self.source.require_arena(parent_upper*16+16384)
        parent_tokens=[source_key(*namespace.as_tuple,parent).token for parent in parents]
        meter.charge_encode(sum(map(len,parent_tokens)));self.walk.extend((parent,False) for parent in reversed(parent_tokens))
    def _candidate(self,meter):
        from ..runtime.natural_producer_qualification_v1 import (ProducerExpressionContextV1,C04InterpretationExpressionCandidateV1,
            D11DraftExpressionCandidateV1,C04_KIND,producer_expression_unit_v1)
        from ..domains.d01.production_operations_v1 import plain_v1
        from ..graph_types import AtomKey,GraphVersion
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        groups=tuple(tuple(group[token] for token in sorted(group)) for group in (self.source_refs,self.access_refs,self.correction_refs))
        versions={ref.ref:ref.version for group in groups for ref in group}
        for token in self.context_tokens:versions[token]=self.members[token].revision
        upper=sum(len(token)*2+128 for token in versions);meter.require_available(upper);self.source.require_arena(upper*16+16384)
        reads=tuple(GraphVersion(AtomKey.from_token(token),versions[token]) for token in sorted(versions));meter.charge_encode(sum(len(token) for token in versions))
        guard=self.envelope.version_guard
        context=ProducerExpressionContextV1(self.parent.namespace,self.c02_operation_id,self.unit['audience_ref'],float(self.projection['deadline']),
            guard.access_epoch,guard.delete_epoch,*groups,reads,self.projection['producer_digest'])
        ctor=C04InterpretationExpressionCandidateV1 if self.unit['d06_claim_kind']==C04_KIND else D11DraftExpressionCandidateV1
        candidate=ctor(context,**{name:value for name,value in self.projection.items() if name not in {'roots','deadline','producer_digest'}})
        size=c09_canonical_json_size_v3(candidate,typed=True)*4+c09_canonical_json_size_v3(self.unit)*4
        rebuilt=self._codec(meter,size,lambda:plain_v1(producer_expression_unit_v1(candidate)))
        if rebuilt!=self.unit:raise C09PagedCaptureHold('actual historical producer unit differs from frozen generation qualification')
        self.verified[self.paths[self.index]]=rebuilt['qualification_digest'];self.index+=1;self.phase='unit'
        self.unit=None;self.field_names=();self.buffer.clear();self.members={};self.histories={};self.context_tokens=set();self.pending=[]
        self.reference=None;self.locator=None;self.row=None;self.data={};self.projection=None;self.roots=();self.walk=[]
        self.walk_active=set();self.walk_seen=set();self.source_refs={};self.access_refs={};self.correction_refs={}
    def advance(self,meter):
        self.source.require_current();self.capture.builder.require_current();result=self.copy()
        method={'guard':'_guard','unit':'_unit','unit_fields':'_unit_field','members':'_members','producer_locator':'_producer_locator',
            'draft_provenance':'_draft_provenance','journal':'_journal','c04_inputs':'_c04_inputs','draft_inputs':'_draft_inputs',
            'c04_self':'_c04_self','draft_self':'_draft_self','draft_members':'_draft_members','c04_projection':'_c04_projection','draft_projection':'_draft_projection',
            'begin_closure':'_begin_closure','closure':'_closure','candidate':'_candidate'}.get(result.phase)
        if method is None:raise C09PagedCaptureHold('unknown actual producer qualification phase')
        getattr(result,method)(meter);self.source.require_current();self.source.require_arena();return result
