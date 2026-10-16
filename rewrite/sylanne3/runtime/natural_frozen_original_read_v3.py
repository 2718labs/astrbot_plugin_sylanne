"""Source-only bounded verification of an actual complete natural frozen original."""
from dataclasses import fields
from hashlib import sha256
from weakref import WeakKeyDictionary
from types import MappingProxyType

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import _canonical_value
from .owner_material_source_storage_v3 import CanonicalValueStreamV3

_ISSUER=object()
_ISSUED=WeakKeyDictionary()


def _readonly_v3(value):
    if type(value)is dict:return MappingProxyType({key:_readonly_v3(item)for key,item in value.items()})
    if type(value)is list:return tuple(_readonly_v3(item)for item in value)
    return value


def _unproxy_v3(value):
    if type(value)is MappingProxyType:return {key:_unproxy_v3(item)for key,item in value.items()}
    if type(value)in(list,tuple):return [_unproxy_v3(item)for item in value]
    if type(value)is dict:return {key:_unproxy_v3(item)for key,item in value.items()}
    return value


def _plain_v3(value):
    from dataclasses import is_dataclass,asdict
    if is_dataclass(value):return asdict(value)
    if type(value)is dict:return {key:_plain_v3(item)for key,item in value.items()}
    if type(value)in(list,tuple):return [_plain_v3(item)for item in value]
    return value


def _canonical_container_bytes_v3(value):
    from dataclasses import is_dataclass
    if is_dataclass(value):return 512+len(fields(value))*96+sum(_canonical_container_bytes_v3(getattr(value,item.name))for item in fields(value))
    if type(value)in(dict,MappingProxyType):return 256+len(value)*96+sum(_canonical_container_bytes_v3(item)for item in value.values())
    if type(value)in(list,tuple):return 64+len(value)*16+sum(_canonical_container_bytes_v3(item)for item in value)
    return 0


class _CanonicalComparisonV3:
    def __init__(self,value,target=None,*,operation):
        operation.retain(_canonical_container_bytes_v3(value)*2+65536)
        self.stream=CanonicalValueStreamV3(_canonical_value(_unproxy_v3(value),set()))
        self.target,self.offset,self.complete=target,0,False
    def advance(self,meter):
        fragment=self.stream.read_fragment(meter)
        if fragment:
            if self.target is not None:
                actual=self.target[self.offset:self.offset+len(fragment)].encode('ascii')
                meter.charge_encode(len(actual))
                if actual!=fragment:raise ValueError('natural actual canonical fragment differs')
            self.offset+=len(fragment)
        if self.stream.complete:
            if self.target is not None and self.offset!=len(self.target):raise ValueError('natural actual canonical EOF differs')
            self.complete=True
        return self.complete
    @property
    def digest(self):
        if not self.complete:raise ValueError('natural canonical digest requires complete actual EOF')
        return self.stream.hash.hexdigest()


class _PrefixComparisonV3:
    def __init__(self,messages,installation,target,*,operation):
        self.parts=[b'{"max_output_tokens":'+str(installation.max_output_tokens).encode()+b',"messages":[',
            _CanonicalComparisonV3(_plain_v3(messages[0]),operation=operation),b',',_CanonicalComparisonV3(_plain_v3(messages[1]),operation=operation),b',{"content":']
        self.target,self.offset,self.hash,self.complete=target,0,sha256(),False
    def advance(self,meter):
        if not self.parts:
            if self.offset!=len(self.target):raise ValueError('natural actual prefix EOF differs')
            self.complete=True;return True
        part=self.parts[0]
        if type(part)is bytes:fragment=part;self.parts.pop(0)
        else:
            fragment=part.stream.read_fragment(meter)or b''
            if part.stream.complete:self.parts.pop(0)
        actual=self.target[self.offset:self.offset+len(fragment)].encode('ascii')
        meter.charge_encode(len(actual))
        if actual!=fragment:raise ValueError('natural original stable prefix differs')
        self.hash.update(fragment);self.offset+=len(fragment);return False
    @property
    def digest(self):
        if not self.complete:raise ValueError('natural prefix needs complete actual EOF')
        return self.hash.hexdigest()


class PreparedNaturalFrozenReadV3:
    def __init__(self,issuer,owner,column):
        if issuer is not _ISSUER:raise TypeError('actual Source frozen original issuer required')
        from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3,_container_bytes_v3
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3
        if type(column)is not DispatchOriginalJSONReadV3:
            raise TypeError('actual complete original column required')
        if type(owner)not in (_DispatchInventoryReadV3,_OrdinaryFullReadV3):
            from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
            require_actual_authority_graph_attachment_owner_v3(owner,db=column.db)
        if type(owner)is _OrdinaryFullReadV3:
            if owner.prefinal is None or owner.work.state is not owner or owner.work.operation is not owner.operation:
                raise TypeError('actual prefinal originating FULL Work required')
            owner.prefinal._actual()
        self.owner,self.column=owner,column
        self.raw=column.require_v3(owner)
        if column.table!='graph_natural_generation_preparations_v2'or column.column!='frozen_json':
            raise ValueError('actual natural generation frozen column required')
        from ..model_broker import natural_reply as v2,natural_reply_history_v3 as v3,natural_reply_history_v4 as v4,natural_reply_history_v6 as v6,natural_reply_history_v7 as v7
        self.modules={2:v2,3:v3,4:v4,6:v6,7:v7}
        schema=self.raw.get('schema')
        mapping={None:2,'sylanne.d09.frozen_natural_request.v3':3,'sylanne.d09.frozen_natural_request.v4':4,
            'sylanne.d09.frozen_natural_request.v5':4,'sylanne.d09.frozen_natural_request.v6':6,'sylanne.d09.frozen_natural_request.v7':7}
        if schema not in mapping:raise ValueError('actual frozen natural schema differs')
        self.version=mapping[schema];self.module=self.modules[self.version]
        self.input_type=getattr(self.module,'NaturalReplyInputV'+str(self.version))
        self.frozen_type=getattr(self.module,'FrozenNaturalReplyRequestV'+str(self.version))
        if set(self.raw)!={field.name for field in fields(self.frozen_type)}:raise ValueError('actual frozen fieldset differs')
        self.data=self.raw['input']
        if type(self.data)is not dict or set(self.data)!={field.name for field in fields(self.input_type)}:
            raise ValueError('actual natural input fieldset differs')
        owner.operation.retain(_container_bytes_v3(self.raw)*2+262144)
        self.raw=_readonly_v3(self.raw);self.data=self.raw['input']
        self.parts={'question':[],'units':[],'stable_history':[],'recent_history':[],'detail_history':[],'stable_turns':[]}
        self.queue=[('question',self.data['question'])]
        self.queue += [('units',item)for item in self.data['plan']['units']]
        for name in ('stable_history','recent_history','detail_history','stable_turns'):
            self.queue += [(name,item)for item in self.data.get(name,())]
        self.phase='parts';self.complete=False;self.result=None;self.input=None;self.slice_digest=None
        self.timeline_complete=self.version!=7;self.timeline_block=0;self.timeline_row=0;self.timeline_offset=0;self.timeline_target=0
        self.timeline_piece=None;self.timeline_kind=0;self.comparison=None;self.jobs=[];self.input_digest=None
        _ISSUED[self]=(owner,column,column.sha256,column.byte_count,owner.operation,owner.fence.scope,self.raw,self.version,self.input_type,self.frozen_type)
    def _actual(self):
        from .dispatch_current_inventory_v3 import _SOURCE_ISSUED
        if (_ISSUED.get(self)!=(self.owner,self.column,self.column.sha256,self.column.byte_count,self.owner.operation,self.owner.fence.scope,self.raw,self.version,self.input_type,self.frozen_type)
                or self.column.owner is not self.owner or self.owner.operation.closed):
            raise AuthorityUnavailable('actual immutable Source frozen original changed')
        for source in self.owner.sources.values():
            if source not in _SOURCE_ISSUED or source.scope is not self.owner.fence.scope:
                raise AuthorityUnavailable('actual same-work Source full EOF differs')
    def _part(self):
        from .natural_reply_job_v2 import _part,_unit
        from ..runtime_contracts import CompletedTurnV1,VersionedRef
        from ..model_broker.natural_reply_history_v3 import D13NaturalRawTurnV1
        from ..model_broker.natural_reply_history_v4 import D13NaturalDetailPartV1
        from ..model_broker.natural_reply_history_v7 import D13NaturalStableTurnV7
        if not self.queue:
            if self.version==2:self.phase='input';return
            value={'stable_history':tuple(self.parts['stable_history']),'recent_history':tuple(self.parts['recent_history']),
                'coverage':tuple(tuple(v)for v in self.data['history_selection']['coverage']),'gaps':tuple(tuple(v)for v in self.data['history_selection']['gaps'])}
            if self.version!=3:value['detail_history']=tuple(self.parts['detail_history'])
            self.comparison=_CanonicalComparisonV3(value,operation=self.owner.operation);self.phase='slice';return
        kind,raw=self.queue.pop(0);self.owner.operation.retain(8192)
        if kind=='units':value=_unit(raw)
        elif kind in ('question','stable_history'):value=_part(raw)
        elif kind=='detail_history':value=D13NaturalDetailPartV1(raw['sequence'],VersionedRef(**raw['source_ref']),raw['speaker_ref'],raw['text'],raw['expires_at_utc'])
        elif kind=='stable_turns':value=D13NaturalStableTurnV7(**raw)
        else:
            if type(raw)is not MappingProxyType or set(raw)!={'turn','completion_ref'}:raise ValueError('actual natural raw turn fields differ')
            turn=dict(raw['turn'])
            for name in ('audience_ref','raw_ref','source_ref','access_ref'):turn[name]=VersionedRef(**turn[name])
            value=D13NaturalRawTurnV1(CompletedTurnV1(**turn),VersionedRef(**raw['completion_ref']))
        self.parts[kind].append(value)
    def _timeline(self,meter):
        rows=self.parts['stable_turns'];blocks=self.parts['stable_history']
        if self.timeline_block>=len(blocks):self.timeline_complete=True;self.phase='input';return
        index=self.timeline_block;block=blocks[index].text
        if self.timeline_piece is None:
            if self.timeline_row>=len(rows)or rows[self.timeline_row].block_index!=index:
                if self.timeline_target!=len(block):raise ValueError('V7 stable timeline EOF differs')
                self.timeline_block+=1;self.timeline_target=0;self.timeline_kind=0;return
            row=rows[self.timeline_row]
            self.timeline_piece=((('\n'if self.timeline_kind else '')+f'[{row.sequence} {row.speaker_ref}] ')if self.timeline_kind!=2 else row.text)
            self.timeline_offset=0
        end=min(self.timeline_offset+1024,len(self.timeline_piece));piece=self.timeline_piece[self.timeline_offset:end]
        if block[self.timeline_target:self.timeline_target+len(piece)]!=piece:raise ValueError('V7 exact stable timeline text differs')
        self.timeline_offset=end;self.timeline_target+=len(piece)
        if end==len(self.timeline_piece):
            self.timeline_piece=None
            if self.timeline_kind==2:self.timeline_row+=1;self.timeline_kind=1
            else:self.timeline_kind=2
    def _input(self):
        from ..runtime_contracts import NamespaceId,VersionedRef
        from ..domains.d09.natural_reply import NaturalExpressionPlanV2
        from ..model_broker.natural_reply import NaturalReplyInstallationV2
        p=dict(self.data['plan']);p['namespace']=NamespaceId(**p['namespace'])
        for name in ('plan_ref','scene_ref','audience_ref'):p[name]=VersionedRef(**p[name])
        for name in ('required_slots','allowed_speech_acts'):p[name]=tuple(p[name])
        p['promise_grants']=tuple(VersionedRef(**v)for v in p['promise_grants']);p['units']=tuple(self.parts['units'])
        plan=NaturalExpressionPlanV2(**p)
        if plan.namespace!=self.owner.namespace:raise ValueError('actual natural input namespace differs')
        args=[self.parts['question'][0],plan,tuple(self.parts['stable_history'])]
        if self.version!=2:
            sel=dict(self.data['history_selection'])
            for name in ('scene_ref','audience_ref','block_ref'):
                if name in sel:sel[name]=None if sel[name]is None else VersionedRef(**sel[name])
            for name in ('source_dependencies','read_set','raw_turn_refs','block_refs'):
                if name in sel:sel[name]=tuple(VersionedRef(**v)for v in sel[name])
            for name in ('coverage','gaps','page_cursors'):
                if name in sel:sel[name]=tuple(tuple(v)for v in sel[name])
            selection_type=getattr(self.modules[6]if self.version in(6,7)else self.modules[3],
                'D13NaturalHistorySelectionV2'if self.version in(6,7)else'D13NaturalHistorySelectionV1')
            args += [tuple(self.parts['recent_history']),selection_type(**sel)]
            if self.version!=3:args.append(tuple(self.parts['detail_history']))
        args += [self.data['frozen_at_utc'],self.data['expires_at_utc']]
        kwargs={}
        if self.version!=2:
            args.append(self.data['schema']);kwargs['_prepared_history_eof_v3']=self
        if self.version==7:kwargs['stable_turns']=tuple(self.parts['stable_turns'])
        self.input=self.input_type(*args,**kwargs)
        self.installation=NaturalReplyInstallationV2(**self.raw['installation'])
        self.jobs=[('frozen_input_digest',_CanonicalComparisonV3(self.input,operation=self.owner.operation)),('qualified_units_digest',_CanonicalComparisonV3(self.input.plan.units,operation=self.owner.operation))]
        self.phase='digests'
    def _wire_jobs(self):
        from dataclasses import asdict
        from ..model_broker.natural_reply import NaturalReplyMessageV2
        i=self.input;m=self.module;installation=self.installation
        self.template=m.TEMPLATE_DIGEST;schema=m.INPUT_SCHEMA;system=m.SYSTEM_MESSAGE
        if self.version==4 and i.schema==m.INPUT_SCHEMA_V5:schema=m.INPUT_SCHEMA_V5;system=m.SYSTEM_MESSAGE_V5;self.template=m.TEMPLATE_DIGEST_V5
        scope={'namespace':asdict(i.plan.namespace),'scene_id':i.plan.scene_id,'audience_id':i.plan.audience_id,
            'scene_ref':asdict(i.plan.scene_ref),'audience_ref':asdict(i.plan.audience_ref)}
        if self.version==7:
            projection=m.semantic_model_projection_v7(i,prepared_eof=self)
            self.jobs.append(('semantic_projection_digest',_CanonicalComparisonV3(projection,operation=self.owner.operation)))
            stable={'schema':schema,'stable_history':projection['stable_history']}
            dynamic={'schema':schema,**{key:value for key,value in projection.items()if key not in{'schema','stable_history'}}}
        elif self.version==2:
            stable={'schema':schema,'scope':scope,'stable_history':_plain_v3(i.stable_history)}
            dynamic={'schema':schema,'frozen_at_utc':i.frozen_at_utc,'expires_at_utc':i.expires_at_utc,'question':_plain_v3(i.question),
                'expression_plan':{**scope,'plan_ref':asdict(i.plan.plan_ref),'required_slots':i.plan.required_slots,'allowed_speech_acts':i.plan.allowed_speech_acts,
                    'promise_grants':_plain_v3(i.plan.promise_grants),'valid_until_utc':i.plan.valid_until_utc,'final_activity_id':i.plan.final_activity_id,
                    'final_operation_id':i.plan.final_operation_id,'final_effect_id':i.plan.final_effect_id},'qualified_units':_plain_v3(i.plan.units)}
        else:
            plan=asdict(i.plan);plan.pop('units')
            stable={'schema':schema,'scope':scope,'stable_history':_plain_v3(i.stable_history)}
            dynamic={'schema':schema,'scope':scope,'frozen_at_utc':i.frozen_at_utc,'expires_at_utc':i.expires_at_utc,'question':_plain_v3(i.question),
                'expression_plan':plan,'qualified_units':_plain_v3(i.plan.units),'recent_history':_plain_v3(i.recent_history),'history_selection':_plain_v3(i.history_selection)}
            if self.version!=3:dynamic['detail_history']=_plain_v3(i.detail_history)
        raw_messages=self.raw['messages']
        if len(raw_messages)!=3 or raw_messages[0]!={'role':'system','content':system}or any(set(item)!={'role','content'}for item in raw_messages):
            raise ValueError('actual natural three-message system layout differs')
        if (raw_messages[1]['role'],raw_messages[2]['role'])!=('user','user'):raise ValueError('actual natural user layout differs')
        self.messages=tuple(NaturalReplyMessageV2(**raw)for raw in raw_messages)
        self.jobs += [('stable',_CanonicalComparisonV3(stable,raw_messages[1]['content'],operation=self.owner.operation)),('dynamic',_CanonicalComparisonV3(dynamic,raw_messages[2]['content'],operation=self.owner.operation)),
            ('model_request_digest',_CanonicalComparisonV3({'provider_id':installation.provider_id,'model':installation.model_id,'messages':_plain_v3(self.messages),
                'max_output_tokens':installation.max_output_tokens},self.raw['canonical_wire'],operation=self.owner.operation)),
            ('prefix',_PrefixComparisonV3(self.messages,installation,self.raw['stable_prefix_wire'],operation=self.owner.operation))]
    def _finish(self):
        values={name:self.raw[name]for name in self.raw}
        values.update(input=self.input,installation=self.installation,messages=self.messages)
        if self.version==4:
            expected=(self.module.FROZEN_SCHEMA_V5 if self.input.schema==self.module.INPUT_SCHEMA_V5 else 'sylanne.d09.frozen_natural_request.v4')
            if values['schema']!=expected:raise ValueError('actual V4/V5 input/frozen semantic version differs')
            values['schema']=expected
        self.result=self.frozen_type(**values)
        self.comparison=_CanonicalComparisonV3(_plain_v3(self.result),operation=self.owner.operation);self.phase='complete_digest'
    def advance(self,meter):
        self._actual()
        if self.phase=='parts':self._part()
        elif self.phase=='slice':
            if self.comparison.advance(meter):
                self.slice_digest=self.comparison.digest
                if self.slice_digest!=self.data['history_selection']['selected_slice_digest']:raise ValueError('actual natural selected slice digest differs')
                self.phase='timeline'if self.version==7 else'input'
        elif self.phase=='timeline':self._timeline(meter)
        elif self.phase=='input':self._input()
        elif self.phase=='digests':
            if self.jobs:
                name,job=self.jobs[0]
                if job.advance(meter):
                    digest=job.digest
                    if name not in ('stable','dynamic','prefix')and digest!=self.raw[name]:raise ValueError('actual natural original digest differs: '+name)
                    if name=='frozen_input_digest':self.input_digest=digest
                    if name=='prefix':
                        if self.version==2:
                            value={'template_digest':self.template,'installation_id':self.installation.installation_id,'provider_config_digest':self.installation.provider_config_digest,
                                'provider_id':self.installation.provider_id,'model_id':self.installation.model_id,'stable_prefix_sha256':digest}
                        else:value={'template_digest':self.template,'installation':self.installation,'stable_prefix_sha256':digest}
                        self.jobs.append(('stable_prefix_digest',_CanonicalComparisonV3(value,operation=self.owner.operation)))
                    self.jobs.pop(0)
            elif not hasattr(self,'messages'):self._wire_jobs()
            else:self._finish()
        elif self.phase=='complete_digest':
            if self.comparison.advance(meter):
                if (self.comparison.digest,self.comparison.offset)!=(self.column.sha256,self.column.byte_count):
                    raise ValueError('actual complete typed frozen original canonical SHA/EOF differs')
                self.complete=True
        return self.complete
    def require_for_v3(self,raw):
        self._actual()
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        if not self.complete or _freeze_value_v3(raw)!=self.column._frozen_value:
            raise AuthorityUnavailable('actual complete private frozen original required')
        return self.result


def begin_natural_frozen_original_read_v3(owner,column):
    from ..graph_worker import require_graph_storage_work_admission_v3
    require_graph_storage_work_admission_v3(owner.graph)
    return PreparedNaturalFrozenReadV3(_ISSUER,owner,column)


def require_prepared_history_slice_v3(witness,input):
    from .installed_d13_natural_frame_v7 import _CounterInputEOFV7
    if type(witness)is _CounterInputEOFV7:
        return witness.require_slice_v7(input)
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    if _require_natural_canonical_owner_type_v3(witness)is not witness or witness not in _ISSUED or witness.slice_digest is None:
        raise AuthorityUnavailable('actual complete original history slice EOF required')
    witness._actual()
    value={'stable_history':input.stable_history,'recent_history':input.recent_history,
        'coverage':input.history_selection.coverage,'gaps':input.history_selection.gaps}
    raw={'stable_history':witness.data['stable_history'],'recent_history':witness.data['recent_history'],
        'coverage':witness.data['history_selection']['coverage'],'gaps':witness.data['history_selection']['gaps']}
    if witness.version!=3:value['detail_history']=input.detail_history;raw['detail_history']=witness.data['detail_history']
    if input.plan.namespace!=witness.owner.namespace or _freeze_value_v3(_canonical_value(_plain_v3(value),set()))!=_freeze_value_v3(_unproxy_v3(raw)):
        raise AuthorityUnavailable('actual typed Source history fields changed after complete EOF')
    return witness.slice_digest


def require_prepared_stable_timeline_v3(witness,input):
    from .installed_d13_natural_frame_v7 import _CounterInputEOFV7
    if type(witness)is _CounterInputEOFV7:
        return witness.require_timeline_v7(input)
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    if (_require_natural_canonical_owner_type_v3(witness)is not witness or witness not in _ISSUED or witness.version!=7
            or not witness.timeline_complete or input.stable_turns!=tuple(witness.parts['stable_turns'])
            or input.stable_history!=tuple(witness.parts['stable_history'])):
        raise AuthorityUnavailable('actual V7 stable timeline complete equality required')
    witness._actual()


def require_prepared_semantic_input_digest_v3(witness,input):
    from .installed_d13_natural_frame_v7 import _CounterInputEOFV7
    if type(witness)is _CounterInputEOFV7:
        return witness.require_input_digest_v7(input)
    if (_require_natural_canonical_owner_type_v3(witness)is not witness or witness not in _ISSUED or input is not witness.input
            or witness.input_digest is None):raise AuthorityUnavailable('actual complete typed input digest required')
    witness._actual();return witness.input_digest


def require_prepared_natural_frozen_v3(witness,raw,*,version):
    if _require_natural_canonical_owner_type_v3(witness)is not witness or witness not in _ISSUED or witness.version!=version:
        raise AuthorityUnavailable('actual matching-version private frozen EOF witness required')
    return witness.require_for_v3(raw)


_AUTHORITY_FROZEN_V3=WeakKeyDictionary()


class PreparedAuthorityNaturalFrozenReadV3(PreparedNaturalFrozenReadV3):
    """Canonical value verification in one real Authority Work; no Host grant."""
    def __init__(self,issuer,owner,column):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        require_actual_authority_graph_attachment_owner_v3(owner,db=column.db)
        super().__init__(issuer,owner,column)
        _AUTHORITY_FROZEN_V3[self]=(owner,column,owner.operation,owner.scope)
    def _actual(self):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        require_actual_authority_graph_attachment_owner_v3(self.owner,db=self.column.db)
        if (_AUTHORITY_FROZEN_V3.get(self)!=(self.owner,self.column,self.owner.operation,self.owner.scope)
                or _ISSUED.get(self)!=(self.owner,self.column,self.column.sha256,self.column.byte_count,
                    self.owner.operation,self.owner.fence.scope,self.raw,self.version,self.input_type,self.frozen_type)
                or self.column.owner is not self.owner):
            raise AuthorityUnavailable('actual Authority canonical original changed its Work or full EOF')


def begin_authority_natural_frozen_original_read_v3(owner,column):
    from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
    require_actual_authority_graph_attachment_owner_v3(owner,db=column.db)
    column.require_v3(owner)
    return PreparedAuthorityNaturalFrozenReadV3(_ISSUER,owner,column)


def _require_natural_canonical_owner_type_v3(witness):
    if type(witness)is PreparedNaturalFrozenReadV3:return witness
    if type(witness)is PreparedAuthorityNaturalFrozenReadV3 and witness in _AUTHORITY_FROZEN_V3:
        witness._actual();return witness
    raise AuthorityUnavailable('actual independently issued canonical original required')
