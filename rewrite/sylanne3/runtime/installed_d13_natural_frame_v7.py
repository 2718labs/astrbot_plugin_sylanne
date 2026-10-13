"""V7 candidates from actual current collection and independently paid blocks.

The shared storage collector and derived-block qualifier stay at their original
versions. The new semantic model wire never reuses a V6 count or admission.
"""
from dataclasses import dataclass,replace
from weakref import WeakSet,WeakKeyDictionary
from ..domains.d13.derived_block_metadata_v2 import derived_block_metadata_value_v2
from ..domains.d13.precompression import select_detail_slots
from ..domains.d13.raw_slice import _merge_ranges
from ..graph_types import AtomKey,GraphVersion,GraphWrite
from ..model_broker.context_reply import ContextReplyPartV1
from ..model_broker.natural_reply_history_v3 import D13NaturalRawTurnV1
from ..model_broker.natural_reply_history_v4 import D13NaturalDetailPartV1
from ..model_broker.natural_reply_history_v6 import D13NaturalHistorySelectionV2
from ..model_broker.natural_reply_history_v7 import (NaturalReplyInputV7,FrozenNaturalReplyRequestV7,
    D13NaturalStableTurnV7,freeze_natural_reply_request_v7)
from ..runtime_contracts import VersionedRef,canonical_digest
from .d13_current_collection_v6 import CurrentD13CollectionV6,read_current_d13_collection_v6
from .installed_d13_natural_frame_v6 import _QualifiedDerivedProjectionV6,read_current_derived_blocks_v6

POLICY_REF='d13.natural.current_core_full_wire.v7'

@dataclass(frozen=True,slots=True)
class NaturalHistoryPairV7:
    raw:FrozenNaturalReplyRequestV7
    compressed:FrozenNaturalReplyRequestV7|None
    collection:CurrentD13CollectionV6
    projected_blocks:tuple
    activation_writes:tuple[GraphWrite,...]
    activation_reads:tuple[GraphVersion,...]
    schema:str='d13.natural-history-pair.v7'


def core_collection_binding_digest_v7(collection,*,snapshot_commitment,frozen_at_utc):
    if type(collection) is not CurrentD13CollectionV6:
        raise TypeError('actual current collection required for Core V7 binding')
    return canonical_digest({'schema':'sylanne3.d13.core-collection-binding.v7',
        'snapshot':snapshot_commitment,'window':replace(collection.window,trusted_utc=frozen_at_utc),
        'pages':tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence,
            page.page_status,page.expired_sequences,page.unclosed_sequences) for page in collection.pages)})


def core_paid_block_binding_v7(item,*,metadata=None,metadata_ref=None):
    # Historical metadata comes only from an exact graph_history row followed by actual activation verification.
    metadata=item.metadata if metadata is None else metadata
    metadata_ref=item.ref if metadata_ref is None else metadata_ref
    return {'metadata_ref':metadata_ref.ref,'metadata_revision':metadata_ref.version,
        'metadata_digest':canonical_digest(metadata),'payload_digest':metadata.payload_digest,
        'plan_ref':item.compression_plan.job_ref,'plan_digest':canonical_digest(item.compression_plan),
        'paid_original_ref':metadata.paid_original_operation_id,'paid_original_digest':metadata.paid_original_digest,
        'expires_at_utc':metadata.expires_at_utc,'turn_first':item.block.turns[0].sequence,
        'turn_last':item.block.turns[-1].sequence}


def core_paid_blockset_digest_v7(bindings):
    return canonical_digest({'schema':'sylanne3.d13.core-paid-blockset.v7','bindings':bindings})


def build_natural_frame_v7(*,collection,plan,question,installation,frozen_at_utc,expires_at_utc,
        policy_digest,blocks=(),history_byte_budget=262144):
    """Pure candidates only; actual installed count, budget reservation and W01 adoption are separate."""
    if (type(collection) is not CurrentD13CollectionV6 or type(history_byte_budget) is not int
            or not 1<=history_byte_budget<=262144 or type(blocks) is not tuple or len(blocks)>4
            or any(type(item) is not _QualifiedDerivedProjectionV6 for item in blocks)):
        raise ValueError('v7 frame needs the bounded actual collector and current derived projections')
    window=collection.window
    if (window.namespace!=plan.namespace or window.scene_ref!=plan.scene_ref or window.audience_ref!=plan.audience_ref
            or window.conversation_ref!=plan.audience_id or question.audience_ref!=plan.audience_ref):
        raise ValueError('v7 history and natural plan/current question differ')
    stable,details,refs,selected,covered=[],[],[],[],set()
    used=0
    expiry=min(expires_at_utc,plan.valid_until_utc,question.expires_at_utc)
    for item in blocks:
        block=item.block
        sequences={turn.sequence for turn in block.turns}
        if covered & sequences or question.ref in block.source_dependencies:
            raise ValueError('v7 history duplicates a block turn or current question')
        text='\n'.join(f'[{turn.sequence} {turn.speaker_ref}] {turn.text}' for turn in block.timeline)
        size=len(text.encode('utf-8'))
        if used+size>history_byte_budget:
            continue
        ref=VersionedRef(item.ref.ref,item.ref.version+(item.metadata.status=='standby'))
        expiry=min(expiry,item.metadata.expires_at_utc)
        stable.append(ContextReplyPartV1('d13_history',ref,window.audience_ref,expiry,text,block.source_dependencies))
        refs.append(ref);selected.append(item);covered.update(sequences);used+=size
    turns=[]
    for turn in reversed(window.turns):
        if turn.source_ref==question.ref or turn.sequence in covered:
            continue
        size=len(turn.text.encode('utf-8'))
        if used+size>history_byte_budget:
            break
        if not 0<=frozen_at_utc-turn.trusted_utc<72*3600:
            continue
        turns.append(turn);used+=size;expiry=min(expiry,turn.trusted_utc+72*3600)
    turns.reverse()
    represented=covered|{turn.sequence for turn in turns}
    gaps=_merge_ranges((*window.missing_ranges,*((turn.sequence,turn.sequence) for turn in window.turns
        if turn.source_ref!=question.ref and turn.sequence not in represented),
        *(row for item in selected for row in item.block.omitted_ranges)))
    coverage=_merge_ranges((n,n) for n in sorted(represented) if not any(a<=n<=b for a,b in gaps))
    dependencies=tuple(dict.fromkeys((*tuple(ref for item in selected for ref in item.block.source_dependencies),
        *(ref for turn in turns for ref in (turn.raw_ref,turn.source_ref,turn.access_ref)))))
    raw_sources={turn.source_ref for turn in turns}
    evidence=tuple(dict.fromkeys(ref for unit in plan.units for ref in unit.source_refs))
    for item in selected:
        block=item.block
        selected_keys={chosen.key for chosen in select_detail_slots(block,query_keys=(),detail_byte_budget=max(0,history_byte_budget-used),
            query_text=question.text[:1024],evidence_sources=evidence)}
        speakers={(turn.sequence,turn.source_ref):turn.speaker_ref for turn in block.turns}
        for slot in sorted(block.detail_slots,key=lambda row:(row.sequence,row.key)):
            if slot.key not in selected_keys or slot.source_ref in raw_sources:
                continue
            size=len(slot.text.encode('utf-8'))
            if used+size>history_byte_budget:
                continue
            details.append(D13NaturalDetailPartV1(slot.sequence,slot.source_ref,
                speakers[(slot.sequence,slot.source_ref)],slot.text,expiry))
            used+=size
    details=tuple(sorted(details,key=lambda part:(part.sequence,part.source_ref.ref,part.text)))
    stable=tuple(replace(part,expires_at_utc=expiry) for part in stable)
    raw=tuple(D13NaturalRawTurnV1(turn,turn.raw_ref) for turn in turns)
    read_set=tuple(dict.fromkeys((*window.read_set,*refs)))
    selection=D13NaturalHistorySelectionV2(canonical_digest(replace(window,trusted_utc=frozen_at_utc)),
        window.order_watermark,coverage,gaps,dependencies,read_set,window.scene_ref,window.audience_ref,
        window.conversation_ref,expiry,window.access_epoch,window.delete_epoch,window.activation_epoch,
        tuple(refs),tuple(turn.raw_ref for turn in turns),
        canonical_digest({'stable_history':stable,'recent_history':raw,'detail_history':details, 'coverage':coverage,'gaps':gaps}),
        POLICY_REF,policy_digest,tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence)
            for page in collection.pages),collection.snapshot_commitment)
    return freeze_natural_reply_request_v7(NaturalReplyInputV7(question,plan,stable,raw,selection,details,
        frozen_at_utc,expiry,stable_turns=tuple(D13NaturalStableTurnV7(index,turn.sequence,turn.speaker_ref,turn.text)
            for index,item in enumerate(selected) for turn in item.block.timeline)),installation),tuple(selected)


def prepare_current_natural_history_pair_v7(db,*,namespace,plan,question,installation,now_utc,frozen_at_utc,expires_at_utc,
        activation_generation,paid_verifier,policy_digest,max_slots=256,history_byte_budget=262144):
    if not frozen_at_utc<=now_utc<expires_at_utc or expires_at_utc>min(plan.valid_until_utc,question.expires_at_utc):
        raise ValueError('V7 fixed Core frame time and original absolute lifetime differ')
    collection=read_current_d13_collection_v6(db,namespace,plan.scene_id,plan.audience_id,now_utc,
        expected_activation_generation=activation_generation,max_slots=max_slots)
    projections=() if paid_verifier is None else read_current_derived_blocks_v6(db,collection=collection,question=question,paid_verifier=paid_verifier)
    raw,_=build_natural_frame_v7(collection=collection,plan=plan,question=question,installation=installation,
        frozen_at_utc=frozen_at_utc,expires_at_utc=expires_at_utc,policy_digest=policy_digest,history_byte_budget=history_byte_budget)
    compressed,selected=build_natural_frame_v7(collection=collection,plan=plan,question=question,installation=installation,
        frozen_at_utc=frozen_at_utc,expires_at_utc=expires_at_utc,policy_digest=policy_digest,blocks=projections,
        history_byte_budget=history_byte_budget)
    if not selected:
        return NaturalHistoryPairV7(raw,None,collection,(),(),())
    pair_expiry=min(raw.input.expires_at_utc,compressed.input.expires_at_utc)
    if raw.input.expires_at_utc!=pair_expiry:
        raw=freeze_natural_reply_request_v7(replace(raw.input,expires_at_utc=pair_expiry,
            history_selection=replace(raw.input.history_selection,expires_at_utc=pair_expiry)),installation)
    if compressed.input.expires_at_utc!=pair_expiry:
        compressed=freeze_natural_reply_request_v7(replace(compressed.input,expires_at_utc=pair_expiry,
            history_selection=replace(compressed.input.history_selection,expires_at_utc=pair_expiry)),installation)
    writes,reads=[],[]
    for item in selected:
        if item.metadata.status=='standby':
            key=AtomKey.from_token(item.ref.ref)
            writes.append(GraphWrite(key,derived_block_metadata_value_v2(replace(item.metadata,status='active')),
                tuple(AtomKey.from_token(ref.ref) for ref in item.metadata.source_dependencies)))
            reads.append(GraphVersion(key,item.ref.version))
    return NaturalHistoryPairV7(raw,compressed,collection,selected,tuple(writes),tuple(reads))



@dataclass(frozen=True,slots=True)
class NaturalHistoryDecisionV7:
    selected:str
    token_evidence:str
    activation:str
    policy_digest:str
    wire_digest:str
    proof_digest:str|None=None
    activation_writes:tuple=()
    activation_expected:tuple=()
    budget_state:str='unverified'
    pair:NaturalHistoryPairV7|None=None



def bind_actual_pair_to_core_snapshot_v7(pair,frame):
    """Only an independently signed/count-checked Core original can later select this candidate."""
    if type(pair) is not NaturalHistoryPairV7:
        raise TypeError('actual current V7 pair required')
    def bind(frozen):
        if frozen is None:return None
        selection=replace(frozen.input.history_selection,collection_snapshot_commitment=frame.collection_snapshot_commitment)
        return freeze_natural_reply_request_v7(replace(frozen.input,history_selection=selection),frozen.installation)
    if core_collection_binding_digest_v7(pair.collection,snapshot_commitment=frame.collection_snapshot_commitment,
            frozen_at_utc=frame.frozen_at_utc)!=frame.collection_digest:
        raise ValueError('V7 current Source/window/page facts differ from independently frozen Core collection')
    return replace(pair,raw=bind(pair.raw),compressed=bind(pair.compressed))


def freeze_current_natural_frame_v7(db,*,namespace,plan,question,installation,now_utc,expires_at_utc,
        activation_generation,paid_verifier,installed_wire_port,policy_digest,max_slots=256,original=None,
        frame=None,history_byte_budget=262144):
    """Same current short read; only independent Core signed evidence can select."""
    from ..authority_service.d13_core_counter_contract_v1 import D13CoreFrameIntentHeaderV7
    from ..authority_service.d13_wire_evidence_v7 import InstalledD13WireEvidencePortV7,read_signed_d13_core_wire_original_v1
    if not db.in_transaction or type(installed_wire_port) is not InstalledD13WireEvidencePortV7:
        raise ValueError('V7 current frame requires actual held reader and installed Core evidence port')
    if original is not None:
        if (type(original) is not FrozenNaturalReplyRequestV7 or original!=freeze_natural_reply_request_v7(original.input,original.installation)
                or original.installation!=installation or original.input.plan!=plan or original.input.question!=question):
            raise ValueError('V7 replay cannot replace the complete original input')
    stored=read_signed_d13_core_wire_original_v1(db,namespace=namespace,c02_operation_id=installed_wire_port._parent,
        policy=installed_wire_port._policy)
    if stored is None:raise ValueError('V7 actual Core count original is not yet available')
    actual_frame=stored[1].payload.frame
    if frame is not None and frame!=actual_frame:raise ValueError('V7 caller header differs from independently signed original')
    frame=actual_frame
    if (type(frame) is not D13CoreFrameIntentHeaderV7 or frame.namespace!=namespace or frame.plan_ref!=plan.plan_ref
            or frame.activation_generation!=activation_generation or frame.policy_digest!=policy_digest
            or expires_at_utc<frame.expires_at_utc or not frame.frozen_at_utc<=now_utc<frame.expires_at_utc):
        raise ValueError('V7 original Core frame time/plan/source scope differs')
    if original is not None:
        collection=read_current_d13_collection_v6(db,namespace,plan.scene_id,plan.audience_id,now_utc,
            expected_activation_generation=activation_generation,max_slots=max_slots)
        decision=installed_wire_port.verify_reserved_original_v7(original=original,current_collection=collection,
            now_utc=now_utc,paid_verifier=paid_verifier)
        reads=tuple(GraphVersion(AtomKey.from_token(ref.ref),ref.version) for ref in original.input.history_selection.read_set)
        return original,reads,decision
    pair=prepare_current_natural_history_pair_v7(db,namespace=namespace,plan=plan,question=question,installation=installation,
        now_utc=now_utc,frozen_at_utc=frame.frozen_at_utc,expires_at_utc=frame.expires_at_utc,
        activation_generation=activation_generation,paid_verifier=paid_verifier,policy_digest=policy_digest,
        max_slots=max_slots,history_byte_budget=history_byte_budget)
    pair=bind_actual_pair_to_core_snapshot_v7(pair,frame)
    decision=installed_wire_port.evaluate_natural_pair_v7(pair=pair,now_utc=now_utc)
    if decision is None:raise ValueError('V7 signed independent Core count cannot select original model input')
    selected=pair.raw if decision.selected=='raw' else pair.compressed
    if original is not None and selected!=original:raise ValueError('V7 original cannot change its counted semantic variant')
    actual={ref.key.token:ref for ref in decision.activation_expected}
    reads=tuple(actual.get(ref.ref,GraphVersion(AtomKey.from_token(ref.ref),ref.version)) for ref in selected.input.history_selection.read_set)
    return selected,reads,decision

_AUTHORITY_CURRENT_READERS_V7 = WeakSet()
_AUTHORITY_WIRE_EOFS_V7 = WeakKeyDictionary()


class _ProviderHTTPStreamV7:
    """The registered SDK serializer's ordered UTF-8 fragments, without a full body."""
    def __init__(self, template):
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        from ..model_broker.d13_provider_http_template_v1 import provider_http_body_v1
        import json
        class _OrderedUTF8(CanonicalValueStreamV3):
            @staticmethod
            def _quoted(value, meter_getter=None):
                yield b'"'
                for offset in range(0, len(value), 1024):
                    meter = meter_getter()
                    meter.require_available(1024*36+8192)
                    raw = json.dumps(value[offset:offset+1024], ensure_ascii=False,
                        separators=(',', ':'), allow_nan=False)
                    encoded = raw[1:-1].encode('utf-8')
                    meter.charge_encode(len(raw)*4+len(encoded))
                    yield encoded
                yield b'"'
            @classmethod
            def _value(cls, value, meter_getter=None):
                if type(value) is dict:
                    yield b'{'
                    for index, (key, part) in enumerate(value.items()):
                        if index: yield b','
                        yield from cls._quoted(key, meter_getter)
                        yield b':'
                        yield from cls._value(part, meter_getter)
                    yield b'}'
                else:
                    yield from super()._value(value, meter_getter)
        self.stream = _OrderedUTF8(provider_http_body_v1(template, request_digest='0'*64))
    def advance(self, meter):
        self.stream.read_fragment(meter)
        return self.stream.complete


class _AuthorityCurrentNaturalFrameV7:
    def __init__(self, work, *, issuer, frozen, parent_original_id, now_utc, same_batch_prepared):
        from ..authority_service.current_authority_graph_read_v3 import (
            AuthorityGraphReadWorkV3, require_authority_prepared_generation_v3)
        from ..authority_service.d13_natural_frame_verifier_v7 import InstalledAuthorityD13NaturalFrameVerifierV7
        from ..authority_service.contract import AuthorityUnavailable
        if (type(work) is not AuthorityGraphReadWorkV3
                or type(issuer) is not InstalledAuthorityD13NaturalFrameVerifierV7
                or work.controller.verifier._natural_history is not issuer
                or work.parent_original_id != parent_original_id or work.now_utc != now_utc
                or require_authority_prepared_generation_v3(work,
                    parent_original_id=parent_original_id).frozen is not frozen):
            raise AuthorityUnavailable('actual Authority V7 replay Work/issuer/parent/clock required')
        work._actual()
        original = work.originals[(parent_original_id, 'generation')]
        from .natural_frozen_original_read_v3 import PreparedAuthorityNaturalFrozenReadV3
        eof = original.frozen_eof
        if type(eof) is not PreparedAuthorityNaturalFrozenReadV3 or not eof.complete or eof.result is not frozen:
            raise AuthorityUnavailable('Authority V7 replay requires its full typed frozen EOF')
        eof._actual()
        workflow = issuer._bundle.model_workflows.natural_generation
        from ..model_broker.natural_reply import NaturalReplyInstallationV2
        installed = NaturalReplyInstallationV2(issuer._bundle.installation_policy.installation_id,
            workflow.provider_config_digest, workflow.provider_id, workflow.model_id, workflow.max_output_tokens)
        if installed != frozen.installation or frozen.input.plan.namespace != work.namespace:
            raise ValueError('Authority V7 replay crossed the original installed workflow or namespace')
        self.work, self.issuer, self.frozen = work, issuer, frozen
        self.parent_original_id, self.now_utc, self.same_batch_prepared = parent_original_id, now_utc, same_batch_prepared
        self.frozen_eof, self.frozen_digest = eof, eof.column.sha256
        self.phase, self.complete, self.prepared = 'collection', False, None
        self.collection_reader = self.collection = self.wire = self.paid_reader = None
        self.original_row = self.stream = None
        self.digests, self.http_bytes = {}, None
        self.prefix_baseline_index=0
        self.operation,self.scope=work.operation,work.scope
        self.serializer_pin=issuer._bundle.d13_wire_policy.serializer_fingerprint if issuer._bundle.d13_wire_policy else None
        _AUTHORITY_CURRENT_READERS_V7.add(self)
    def _actual(self):
        from ..authority_service.contract import AuthorityUnavailable
        work = self.work
        if (self not in _AUTHORITY_CURRENT_READERS_V7 or work.history_current_reader is not self
                or work.controller.verifier._natural_history is not self.issuer
                or work.originals[(self.parent_original_id, 'generation')].frozen_eof is not self.frozen_eof
                or self.frozen_eof.result is not self.frozen
                or work.operation is not self.operation or work.scope is not self.scope
                or self.serializer_pin != (self.issuer._bundle.d13_wire_policy.serializer_fingerprint if self.issuer._bundle.d13_wire_policy else None)):
            raise AuthorityUnavailable('Authority V7 replay lost its private same-Work original')
        work._actual(); self.frozen_eof._actual()
    def _canonical(self, value):
        from ..runtime_contracts import _canonical_value
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
        self.work.operation.retain(_canonical_container_bytes_v3(value)*2+65536)
        return CanonicalValueStreamV3(_canonical_value(value, set()))
    def advance(self, *, meter):
        self._actual(); self.work.require_current(meter=meter)
        if self.complete: return self
        work, frozen = self.work, self.frozen
        selection, plan = frozen.input.history_selection, frozen.input.plan
        if self.phase == 'collection':
            if self.collection_reader is None:
                from .d13_current_collection_v6 import begin_authority_d13_collection_read_v6
                self.collection_reader = begin_authority_d13_collection_read_v6(work,
                    scene_ref=plan.scene_id, conversation_ref=plan.audience_id, now_utc=self.now_utc,
                    expected_activation_generation=selection.activation_generation,
                    max_slots=self.issuer._bundle.d13_wire_policy.max_slots if self.issuer._bundle.d13_wire_policy else 256,
                    before_sequence=None if self.same_batch_prepared is None else selection.order_watermark+1)
            self.collection_reader.advance(meter=meter)
            if self.collection_reader.complete:
                self.collection = self.collection_reader.prepared.require_current_v6(work)
                self.phase = 'same_batch' if self.same_batch_prepared is not None else 'wire_original'
            return self
        if self.phase == 'same_batch':
            from .natural_same_batch_history_v7 import prepare_authority_same_batch_prefix_v7
            projected = prepare_authority_same_batch_prefix_v7(self)
            self.stream = self._canonical(projected); self.phase = 'prefix_digest'; return self
        if self.phase == 'wire_original':
            from ..authority_service.d13_wire_evidence_v7 import read_signed_d13_core_wire_original_v1
            policy = self.issuer._bundle.d13_wire_policy
            self.original_row = read_signed_d13_core_wire_original_v1(work.db, namespace=work.namespace,
                c02_operation_id=self.parent_original_id, policy=policy)
            if self.original_row is None: raise ValueError('V7 actual signed Core count original unavailable')
            frame = self.original_row[1].payload.frame
            from ..authority_service.d13_core_counter_contract_v1 import D13CoreFrameIntentHeaderV7
            if (type(frame) is not D13CoreFrameIntentHeaderV7 or frame.namespace != work.namespace
                    or frame.plan_ref != plan.plan_ref or frame.activation_generation != selection.activation_generation
                    or frame.policy_digest != selection.policy_digest
                    or frozen.input.expires_at_utc < frame.expires_at_utc
                    or not frame.frozen_at_utc <= self.now_utc < frame.expires_at_utc):
                raise ValueError('V7 original Core frame time/plan/source scope differs')
            self.stream = self._canonical(replace(self.collection.window, trusted_utc=frozen.input.frozen_at_utc))
            self.phase = 'window_digest'; return self
        if self.phase == 'prefix_baseline':
            if self.prefix_baseline_index < len(selection.read_set):
                ref=selection.read_set[self.prefix_baseline_index]
                if ref.ref!=self.prefix_order_ref.ref:
                    key=AtomKey.from_token(ref.ref)
                    if (key.owner.bot,key.owner.persona)!=work.namespace.as_tuple:
                        raise ValueError('same-batch baseline crossed its original namespace')
                    meter.require_available(len(ref.ref)*4+256)
                    head=work.db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(ref.ref,)).fetchone()
                    meter.charge_read(32)
                    if (ref.version==0 and head is not None or ref.version>0 and head!=(ref.version,1)):
                        raise ValueError('same-batch baseline source, rights, cache or slot changed')
                self.prefix_baseline_index+=1
            else:self.phase='same_batch_verify'
            return self
        if self.phase in ('window_digest', 'collection_digest', 'template_digest', 'prefix_digest'):
            if meter.available_bytes < 196608: return self
            self.stream.read_fragment(meter)
            if not self.stream.complete: return self
            self.digests[self.phase] = self.stream.hash.hexdigest(); self.stream = None
            if self.phase == 'prefix_digest': self.phase = 'prefix_baseline'; return self
            if self.phase == 'window_digest':
                frame = self.original_row[1].payload.frame
                self.stream = self._canonical({'schema':'sylanne3.d13.core-collection-binding.v7',
                    'snapshot':selection.collection_snapshot_commitment,
                    'window':replace(self.collection.window,trusted_utc=frame.frozen_at_utc),
                    'pages':tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence,
                        page.page_status,page.expired_sequences,page.unclosed_sequences) for page in self.collection.pages)})
                self.phase = 'collection_digest'; return self
            if self.phase == 'collection_digest':
                from ..model_broker.d13_provider_http_template_v1 import D13ProviderHTTPTemplateV1
                from dataclasses import asdict
                frame = self.original_row[1].payload.frame
                self.template = D13ProviderHTTPTemplateV1(frozen.installation.model_id,
                    tuple((message.role,message.content) for message in frozen.messages), frozen.installation.max_output_tokens,
                    frame.generation_call_id,frame.billing_contract_digest,self.issuer._bundle.d13_wire_policy.serializer_fingerprint)
                self.stream = self._canonical(asdict(self.template)); self.phase = 'template_digest'; return self
            self.stream = _ProviderHTTPStreamV7(self.template); self.phase = 'http_bytes'; return self
        if self.phase == 'http_bytes':
            if meter.available_bytes < 196608: return self
            if self.stream.advance(meter):
                self.http_bytes = self.stream.stream.offset; self.stream = None; self.phase = 'paid_blocks'
                _AUTHORITY_WIRE_EOFS_V7[self]=(work,self.operation,self.scope,frozen,self.frozen_eof,self.original_row,
                    tuple(sorted(self.digests.items())),self.http_bytes,self.serializer_pin)
            return self
        if self.phase == 'paid_blocks':
            from .installed_d13_natural_frame_v6 import begin_authority_current_derived_blocks_v6
            if self.paid_reader is None:
                self.paid_reader = begin_authority_current_derived_blocks_v6(work,
                    collection_reader=self.collection_reader,question=frozen.input.question,
                    bundle=self.issuer._bundle,resource_issuer=self.issuer._issuer.resource_issuer,
                    budget_issuer=self.issuer._issuer,authority_store=self.issuer._store,now_utc=self.now_utc)
            self.paid_reader.advance(meter=meter)
            if self.paid_reader.complete:self.phase = 'wire_verify'
            return self
        if self.phase == 'wire_verify':
            from .d13_natural_installed_ports_v7 import build_current_natural_d13_ports_v7
            self.wire, paid = build_current_natural_d13_ports_v7(work.db,bundle=self.issuer._bundle,
                resource_issuer=self.issuer._issuer.resource_issuer,budget_issuer=self.issuer._issuer,
                c02_operation_id=self.parent_original_id,plan=plan,now_utc=self.now_utc,
                activation_generation=selection.activation_generation,original=frozen,
                authority_store=self.issuer._store,max_slots=self.collection.max_slots,
                _authority_replay=self)
            from ..authority_service.d13_wire_evidence_v7 import _verify_reserved_original_predicates_v7
            decision = _verify_reserved_original_predicates_v7(self.wire,original=frozen,
                current_collection=self.collection,now_utc=self.now_utc,paid_verifier=paid,_prepared=self)
            if decision.activation_writes or frozen.input.stable_history and decision.budget_state != 'reserved_original':
                raise ValueError('V7 actual saved replay did not retain its original reservation')
            reads = tuple(GraphVersion(AtomKey.from_token(ref.ref),ref.version)for ref in selection.read_set)
            from ..authority_service.d13_natural_frame_verifier_v1 import D13AuthorityNaturalFrameReadV1
            self.prepared = D13AuthorityNaturalFrameReadV1(self.frozen_digest,frozen.model_request_digest,
                reads,decision.budget_state,decision.proof_digest)
        elif self.phase == 'same_batch_verify':
            from .natural_same_batch_history_v7 import verify_same_batch_history_v7
            reads = verify_same_batch_history_v7(work.db,issuer=self.issuer,prepared=self.same_batch_prepared,
                namespace=work.namespace,parent_original_id=self.parent_original_id,frozen=frozen,
                now_utc=self.now_utc,max_slots=self.collection.max_slots,_authority_reader=self)
            from ..authority_service.d13_natural_frame_verifier_v1 import D13AuthorityNaturalFrameReadV1
            self.prepared = D13AuthorityNaturalFrameReadV1(self.frozen_digest,frozen.model_request_digest,reads,
                'original_paid_calls_unchanged',canonical_digest({'schema':'d13.same-batch-original-read.v7',
                    'frozen':self.frozen_digest,'observations':self.same_batch_prepared.observations,'current_reads':reads}))
        else: raise ValueError('unregistered Authority V7 original replay phase')
        self.complete = True; return self
    def require_wire_inputs_v7(self, port, *, original, current_collection, now_utc):
        self._actual()
        if (self.phase != 'wire_verify' or self.wire is not port or port._db is not self.work.db
                or original is not self.frozen or current_collection is not self.collection or now_utc != self.now_utc):
            raise ValueError('V7 wire predicate requires its actual same-Work EOF inputs')
        facts=_AUTHORITY_WIRE_EOFS_V7.get(self)
        if facts!=(self.work,self.operation,self.scope,self.frozen,self.frozen_eof,self.original_row,
                tuple(sorted(self.digests.items())),self.http_bytes,self.serializer_pin):
            raise ValueError('V7 original wire EOF facts changed after actual preparation')
        return dict(facts[6]),facts[7],facts[5]
    def require_current_v7(self, *, issuer, frozen, parent_original_id, now_utc, same_batch_prepared=None):
        self._actual()
        if (not self.complete or issuer is not self.issuer or frozen is not self.frozen
                or parent_original_id != self.parent_original_id or now_utc != self.now_utc
                or same_batch_prepared is not self.same_batch_prepared):
            raise ValueError('V7 current read requires its completed actual original replay')
        return self.prepared
    def release_payload_v3(self):
        _AUTHORITY_CURRENT_READERS_V7.discard(self)
        _AUTHORITY_WIRE_EOFS_V7.pop(self,None)
        if self.paid_reader is not None:self.paid_reader.release_payload_v3()
        self.stream = self.template = self.collection_reader = self.collection = self.paid_reader = None
        self.original_row = self.frozen = self.frozen_eof = self.prepared = None
        self.digests.clear()


def begin_authority_current_natural_frame_v7(work, *, issuer, frozen, parent_original_id, now_utc, same_batch_prepared=None):
    return _AuthorityCurrentNaturalFrameV7(work,issuer=issuer,frozen=frozen,
        parent_original_id=parent_original_id,now_utc=now_utc,same_batch_prepared=same_batch_prepared)

_COUNTER_INITIAL_READERS_V7=WeakSet()
_COUNTER_INPUT_EOFS_V7=WeakKeyDictionary()
_COUNTER_PARTS_EOFS_V7=WeakKeyDictionary()
_COUNTER_TYPED_INPUT_EOFS_V7=WeakKeyDictionary()
_COUNTER_PAIR_EOFS_V7=WeakKeyDictionary()


class _UTF8PartsCountV7:
    def __init__(self,parts):self.parts=tuple(parts);self.position=self.offset=self.size=0;self.complete=False
    def advance(self,meter):
        if self.complete:return self
        if self.position>=len(self.parts):self.complete=True;return self
        part=self.parts[self.position]
        if self.offset<len(part):
            end=min(self.offset+1024,len(part));data=part[self.offset:end].encode('utf-8')
            meter.charge_encode(len(data));self.size+=len(data);self.offset=end;return self
        self.position+=1;self.offset=0;return self


class _CounterFramePartsV7:
    """The original frame selection, with text size and timeline construction split."""
    def __init__(self,owner,blocks):
        self.owner,self.collection,self.blocks=owner,owner.collection,blocks
        scope=owner.counter_scope;self.plan,self.question=scope.plan,scope.question
        window=self.collection.window
        if (type(blocks)is not tuple or len(blocks)>4 or any(type(item)is not _QualifiedDerivedProjectionV6 for item in blocks)
                or window.namespace!=self.plan.namespace or window.scene_ref!=self.plan.scene_ref
                or window.audience_ref!=self.plan.audience_ref or window.conversation_ref!=self.plan.audience_id
                or self.question.audience_ref!=self.plan.audience_ref):
            raise ValueError('initial V7 frame needs actual current scope/qualified block projections')
        self.stable=[];self.details=[];self.refs=[];self.selected=[];self.covered=set();self.turns=[];self.used=0
        self.expiry=min(scope.deadline_utc,self.plan.valid_until_utc,self.question.expires_at_utc)
        self.position=0;self.phase='blocks';self.counter=None;self.detail_reader=None;self.complete=False
        self.timeline=[];self.raw_candidates=tuple(reversed(window.turns));self.active=None;self.parts=None
        owner.work.operation.retain(65536+len(window.turns)*256+len(blocks)*4096)
    def advance(self,meter):
        self.owner._actual();window=self.collection.window;scope=self.owner.counter_scope
        if self.complete:return self
        if self.phase=='blocks':
            if self.position>=len(self.blocks):self.position=0;self.phase='raw';return self
            item=self.blocks[self.position];block=item.block
            sequences={turn.sequence for turn in block.turns}
            if self.covered & sequences or self.question.ref in block.source_dependencies:
                raise ValueError('v7 history duplicates a block turn or current question')
            self.active=item
            self.parts=tuple(value for index,turn in enumerate(block.timeline)
                for value in ((('\n'if index else '')+f'[{turn.sequence} {turn.speaker_ref}] '),turn.text))
            self.counter=_UTF8PartsCountV7(self.parts);self.phase='block_size';return self
        if self.phase=='block_size':
            self.counter.advance(meter)
            if not self.counter.complete:return self
            item=self.active;size=self.counter.size
            if self.used+size<=262144:
                self.owner.work.operation.retain(size*4+1024)
                text=''.join(self.parts)
                ref=VersionedRef(item.ref.ref,item.ref.version+(item.metadata.status=='standby'))
                self.expiry=min(self.expiry,item.metadata.expires_at_utc)
                self.stable.append(ContextReplyPartV1('d13_history',ref,window.audience_ref,self.expiry,text,item.block.source_dependencies))
                self.refs.append(ref);self.selected.append(item);self.covered.update(turn.sequence for turn in item.block.turns);self.used+=size
            self.position+=1;self.counter=self.parts=self.active=None;self.phase='blocks';return self
        if self.phase=='raw':
            if self.position>=len(self.raw_candidates):self.turns.reverse();self.position=0;self.phase='details';return self
            turn=self.raw_candidates[self.position]
            if turn.source_ref==self.question.ref or turn.sequence in self.covered:self.position+=1;return self
            self.active=turn;self.counter=_UTF8PartsCountV7((turn.text,));self.phase='raw_size';return self
        if self.phase=='raw_size':
            self.counter.advance(meter)
            if not self.counter.complete:return self
            turn=self.active;size=self.counter.size
            if self.used+size>262144:
                self.turns.reverse();self.position=0;self.phase='details'
            else:
                if 0<=scope.frozen_at_utc-turn.trusted_utc<72*3600:
                    self.turns.append(turn);self.used+=size;self.expiry=min(self.expiry,turn.trusted_utc+72*3600)
                self.position+=1;self.phase='raw'
            self.counter=self.active=None;return self
        if self.phase=='details':
            if self.position>=len(self.selected):self.phase='final';return self
            item=self.selected[self.position]
            from ..domains.d13.precompression import begin_bounded_detail_selection_v7
            evidence=tuple(dict.fromkeys(ref for unit in self.plan.units for ref in unit.source_refs))
            self.detail_reader=begin_bounded_detail_selection_v7(item.block,query_keys=(),detail_byte_budget=max(0,262144-self.used),
                query_text=self.question.text[:1024],evidence_sources=evidence,operation=self.owner.work.operation)
            self.active=item;self.phase='detail_rank';return self
        if self.phase=='detail_rank':
            self.detail_reader.advance(meter)
            if not self.detail_reader.complete:return self
            selected_keys={slot.key for slot in self.detail_reader.result}
            raw_sources={turn.source_ref for turn in self.turns}
            self.detail_slots=tuple(slot for slot in sorted(self.active.block.detail_slots,key=lambda row:(row.sequence,row.key))
                if slot.key in selected_keys and slot.source_ref not in raw_sources)
            self.detail_position=0;self.phase='detail_values';return self
        if self.phase=='detail_values':
            if self.detail_position>=len(self.detail_slots):
                self.position+=1;self.detail_reader=self.active=None;self.phase='details';return self
            slot=self.detail_slots[self.detail_position]
            if self.counter is None:self.counter=_UTF8PartsCountV7((slot.text,))
            self.counter.advance(meter)
            if not self.counter.complete:return self
            size=self.counter.size
            if self.used+size<=262144:
                speakers={(turn.sequence,turn.source_ref):turn.speaker_ref for turn in self.active.block.turns}
                self.details.append(D13NaturalDetailPartV1(slot.sequence,slot.source_ref,
                    speakers[(slot.sequence,slot.source_ref)],slot.text,self.expiry));self.used+=size
            self.detail_position+=1;self.counter=None;return self
        if self.phase!='final':raise ValueError('unregistered actual V7 frame-parts phase')
        represented=self.covered|{turn.sequence for turn in self.turns}
        self.gaps=_merge_ranges((*window.missing_ranges,*((turn.sequence,turn.sequence)for turn in window.turns
            if turn.source_ref!=self.question.ref and turn.sequence not in represented),
            *(row for item in self.selected for row in item.block.omitted_ranges)))
        self.coverage=_merge_ranges((n,n)for n in sorted(represented)if not any(a<=n<=b for a,b in self.gaps))
        self.dependencies=tuple(dict.fromkeys((*tuple(ref for item in self.selected for ref in item.block.source_dependencies),
            *(ref for turn in self.turns for ref in(turn.raw_ref,turn.source_ref,turn.access_ref)))))
        self.stable=tuple(replace(part,expires_at_utc=self.expiry)for part in self.stable)
        self.recent=tuple(D13NaturalRawTurnV1(turn,turn.raw_ref)for turn in self.turns)
        self.details=tuple(sorted(self.details,key=lambda part:(part.sequence,part.source_ref.ref,part.text)))
        self.read_set=tuple(dict.fromkeys((*window.read_set,*self.refs)))
        self.timeline=tuple(D13NaturalStableTurnV7(index,turn.sequence,turn.speaker_ref,turn.text)
            for index,item in enumerate(self.selected)for turn in item.block.timeline)
        self.selected=tuple(self.selected);self.complete=True
        _COUNTER_PARTS_EOFS_V7[self]=(self.owner,self.owner.work,self.owner.counter_scope,self.collection,
            self.stable,self.recent,self.details,self.timeline,self.coverage,self.gaps,self.dependencies,self.read_set,self.selected)
        return self


class _CounterInputEOFV7:
    def __init__(self,owner,parts,selection):
        if type(owner)is not _AuthorityInitialNaturalHistoryPairV7 or type(parts)is not _CounterFramePartsV7:
            raise ValueError('actual initial Counter input EOF issuer required')
        owner._actual()
        initial_phase=owner.phase=='input'
        normalized_phase=False
        if owner.phase=='draft_normalize_variant'and owner.normalizing:
            from dataclasses import fields
            previous=owner.variants[owner.variant].input.history_selection
            original=owner.original_variants[owner.variant]
            normalized_phase=(owner.original_draft is owner.work.counter_call.draft
                and selection is owner.normalized_selection
                and selection.collection_snapshot_commitment==original['input']['history_selection']['collection_snapshot_commitment']
                and all(getattr(selection,field.name)==getattr(previous,field.name)
                    for field in fields(previous)if field.name!='collection_snapshot_commitment'))
        if (_COUNTER_PARTS_EOFS_V7.get(parts)!=(owner,owner.work,owner.counter_scope,owner.collection,
                parts.stable,parts.recent,parts.details,parts.timeline,parts.coverage,parts.gaps,parts.dependencies,parts.read_set,parts.selected)
                or owner.parts_active is not parts or not(initial_phase or normalized_phase)
                or owner.digests.get('slice')!=selection.selected_slice_digest
                or owner.digests.get('window')!=selection.window_digest):
            raise ValueError('actual complete Counter frame parts/slice/window EOF required')
        self.owner,self.parts,self.selection=owner,parts,selection
        self.slice_digest=selection.selected_slice_digest;self.input=self.input_digest=None
        _COUNTER_INPUT_EOFS_V7[self]=(owner,owner.work,owner.counter_scope,owner.work.operation,owner.work.scope,
            parts,selection,self.slice_digest,parts.stable,parts.recent,parts.details,parts.timeline)
    def _actual(self):
        facts=_COUNTER_INPUT_EOFS_V7.get(self);self.owner._actual()
        if facts!=(self.owner,self.owner.work,self.owner.counter_scope,self.owner.work.operation,self.owner.work.scope,
                self.parts,self.selection,self.slice_digest,self.parts.stable,self.parts.recent,self.parts.details,self.parts.timeline):
            raise ValueError('actual Counter input EOF changed its original private source/work')
        return self
    def require_slice_v7(self,input):
        self._actual()
        if (input.plan is not self.owner.counter_scope.plan or input.question is not self.owner.counter_scope.question
                or input.history_selection is not self.selection or input.stable_history!=self.parts.stable
                or input.recent_history!=self.parts.recent or input.detail_history!=self.parts.details):
            raise ValueError('Counter typed history differs from its full actual slice EOF')
        return self.slice_digest
    def require_timeline_v7(self,input):
        self.require_slice_v7(input)
        if input.stable_turns!=self.parts.timeline:raise ValueError('Counter actual timeline equality differs')
    def require_input_digest_v7(self,input):
        self._actual()
        if (input is not self.input or _COUNTER_TYPED_INPUT_EOFS_V7.get(self)!=(self.owner,self.owner.work,
                self.owner.counter_scope,self.input,self.input_digest)):
            raise ValueError('Counter full typed input EOF required')
        return self.input_digest

class _CounterCanonicalBufferV7:
    def __init__(self,owner,value,*,retain_text=True):
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
        from ..runtime_contracts import _canonical_value
        owner.work.operation.retain(_canonical_container_bytes_v3(value)*2+65536)
        self.owner=owner;self.stream=CanonicalValueStreamV3(_canonical_value(value,set()));self.parts=[]
        self.complete=False;self.text=None;self.retain_text=retain_text
    def advance(self,meter):
        if self.complete:return self
        if meter.available_bytes<196608:return self
        fragment=self.stream.read_fragment(meter)
        if fragment and self.retain_text:self.owner.work.operation.retain(len(fragment)+128);self.parts.append(fragment)
        if self.stream.complete:
            if self.retain_text:
                self.owner.work.operation.retain(self.stream.offset*2+1024)
                self.text=b''.join(self.parts).decode('ascii')
            self.parts=[];self.complete=True
        return self
    @property
    def digest(self):
        if not self.complete:raise ValueError('actual Counter canonical buffer EOF required')
        return self.stream.hash.hexdigest()


_COUNTER_DRAFT_MATERIALS_V7=WeakKeyDictionary()


def _counter_frozen_plain_v7(value):
    from types import MappingProxyType
    if type(value)is dict:return MappingProxyType({key:_counter_frozen_plain_v7(part)for key,part in value.items()})
    if type(value)in(tuple,list):return tuple(_counter_frozen_plain_v7(part)for part in value)
    return value


def _counter_detached_plain_v7(value):
    from collections.abc import Mapping
    if isinstance(value,Mapping):return {key:_counter_detached_plain_v7(part)for key,part in value.items()}
    if type(value)is tuple:return tuple(_counter_detached_plain_v7(part)for part in value)
    return value


def _counter_plain_original_matches_v7(value,sealed):
    from collections.abc import Mapping
    if isinstance(sealed,Mapping):
        return (type(value)is dict and value.keys()==sealed.keys()
            and all(_counter_plain_original_matches_v7(value[key],part)for key,part in sealed.items()))
    if type(sealed)is tuple:
        return (type(value)in(tuple,list)and len(value)==len(sealed)
            and all(_counter_plain_original_matches_v7(left,right)for left,right in zip(value,sealed)))
    if type(sealed)is str:return value is sealed
    return type(value)is type(sealed)and value==sealed


class PreparedAuthorityCounterDraftMaterialV7:
    def __init__(self,owner):
        owner._actual()
        if (type(owner)is not _AuthorityInitialNaturalHistoryPairV7 or owner.phase!='draft_complete'
                or not owner.normalization_complete or owner.complete):
            raise ValueError('only actual completed Counter recipe preparation may issue material')
        self.owner=owner
        self.generation_call_id=owner.generation_call_id
        self.raw_template=owner.http_templates[0]
        self.compressed_template=owner.http_templates[1]if len(owner.http_templates)>1 else None
        self.raw_http_utf8=owner.http_texts[0]
        self.compressed_http_utf8=owner.http_texts[1]if len(owner.http_texts)>1 else None
        self.input_json=owner.material_fields['kernel']
        self.input_digest=owner.material_digests['kernel']
        self.prospective_plan_digest=owner.material_digests['plan']
        self.collection_digest=owner.material_digests['collection']
        self.template_digests=tuple(owner.template_digests)
        from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
        owner.work.operation.retain(_canonical_container_bytes_v3(owner.frozen_values)*2+1024)
        self._frozen_values=tuple(_counter_frozen_plain_v7(value)for value in owner.frozen_values)
        self._draft=owner.original_draft
        self._original_variants=owner.original_variants
        if self._draft is not None and any(not _counter_plain_original_matches_v7(self._draft[name],sealed)
                for name,sealed in zip(('raw','compressed'),self._original_variants)):
            raise ValueError('Counter existing draft changed after its original recipe EOF')
        _COUNTER_DRAFT_MATERIALS_V7[self]=(owner,owner.work,owner.operation,owner.scope,owner.prepared,
            self.generation_call_id,self.raw_template,self.compressed_template,self.raw_http_utf8,
            self.compressed_http_utf8,self.input_json,self.input_digest,self.prospective_plan_digest,
            self.collection_digest,self.template_digests,self._frozen_values,self._draft,self._original_variants)
    def require_current_v7(self,work):
        owner=self.owner;owner._actual()
        if (work is not owner.work or not owner.complete or owner.draft_material is not self
                or _COUNTER_DRAFT_MATERIALS_V7.get(self)!=(owner,work,owner.operation,owner.scope,owner.prepared,
                    self.generation_call_id,self.raw_template,self.compressed_template,self.raw_http_utf8,
                    self.compressed_http_utf8,self.input_json,self.input_digest,self.prospective_plan_digest,
                    self.collection_digest,self.template_digests,self._frozen_values,self._draft,self._original_variants)):
            raise ValueError('actual Counter HTTP/kernel/draft recipe EOF material required')
        return self
    def frozen_values_v7(self,work):
        self.require_current_v7(work)
        from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
        work.operation.retain(_canonical_container_bytes_v3(self.owner.frozen_values)*2+1024)
        return (_counter_detached_plain_v7(self._frozen_values[0]),
            _counter_detached_plain_v7(self._frozen_values[1])if len(self._frozen_values)>1 else None)
    def require_same_source_v7(self,work,draft):
        self.require_current_v7(work)
        if draft is not self._draft or draft is not work.counter_call.draft or draft is None:
            raise ValueError('Counter normalization requires the actual existing draft original')
        # Each full normalized variant was compared against this original at EOF.
        if (not self.owner.normalization_complete or any(not _counter_plain_original_matches_v7(draft[name],sealed)
                for name,sealed in zip(('raw','compressed'),self._original_variants))):
            raise ValueError('Counter existing draft changed its complete normalized recipe original')
        return self
    def release_payload_v3(self):
        _COUNTER_DRAFT_MATERIALS_V7.pop(self,None)
        self.owner=self.raw_template=self.compressed_template=self.raw_http_utf8=self.compressed_http_utf8=None
        self.input_json=self._frozen_values=self._original_variants=self._draft=None


class _CounterHTTPBufferV7:
    def __init__(self,owner,template):
        self.owner=owner;self.stream=_ProviderHTTPStreamV7(template).stream
        self.parts=[];self.complete=False;self.text=None
    def advance(self,meter):
        if self.complete or meter.available_bytes<196608:return self
        fragment=self.stream.read_fragment(meter)
        if fragment:
            self.owner.work.operation.retain(len(fragment)+128);self.parts.append(fragment)
        if self.stream.complete:
            self.owner.work.operation.retain(self.stream.offset*5+1024)
            self.text=b''.join(self.parts).decode('utf-8');self.parts=[];self.complete=True
        return self


class _AuthorityInitialNaturalHistoryPairV7:
    def __init__(self,work,*,counter_scope):
        from ..authority_service.d13_core_counter_source_v1 import PreparedAuthorityCounterMaterialScopeV7
        if type(counter_scope)is not PreparedAuthorityCounterMaterialScopeV7:
            raise ValueError('actual initial Counter material scope required')
        counter_scope.require_current_v7(work)
        self.work,self.counter_scope=work,counter_scope
        self.phase='collection';self.complete=False;self.prepared=None
        self.collection_reader=self.collection=self.paid_reader=None
        self.parts_raw=self.parts_compressed=self.parts_active=None
        self.variant=0;self.variants=[];self.input_witnesses=[];self.buffer=None;self.digests={};self.fields={};self.input_witness=None
        self.operation,self.scope=work.operation,work.scope
        self.original_draft=work.counter_call.draft;self.normalized_selection=None
        self.original_variants=None
        if self.original_draft is not None:
            from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
            raw_variants=tuple(self.original_draft[name]for name in('raw','compressed'))
            work.operation.retain(_canonical_container_bytes_v3(raw_variants)*2+1024)
            self.original_variants=tuple(_counter_frozen_plain_v7(value)for value in raw_variants)
        self.normalizing=False;self.normalization_complete=False;self.draft_material=None
        self.material_fields={};self.material_digests={};self.frozen_values=[]
        self.http_templates=[];self.http_texts=[];self.template_digests=[];self.material_index=0
        _COUNTER_INITIAL_READERS_V7.add(self)
    def _actual(self):
        if (self not in _COUNTER_INITIAL_READERS_V7 or self.work.counter_pair_reader is not self
                or self.work.operation is not self.operation or self.work.scope is not self.scope):
            raise ValueError('actual Counter initial Work/operation/reader required')
        self.counter_scope.require_current_v7(self.work);return self
    def _begin_buffer(self,name,value,next_phase):
        self.buffer=_CounterCanonicalBufferV7(self,value,retain_text=name in('stable','dynamic','wire','system_wire','stable_wire','kernel'));self.buffer_name=name;self.after_buffer=next_phase;self.phase='buffer'
    def advance(self,*,meter):
        self._actual();self.work.require_current(meter=meter)
        if self.complete:return self
        scope=self.counter_scope;work=self.work
        if self.phase=='collection':
            from .d13_current_collection_v6 import begin_authority_d13_collection_read_v6
            if self.collection_reader is None:
                self.collection_reader=begin_authority_d13_collection_read_v6(work,scene_ref=scope.plan.scene_id,
                    conversation_ref=scope.plan.audience_id,now_utc=scope.now_utc,expected_activation_generation=scope.activation_generation,
                    expected_owner_authorization_head=work.counter_current_self.owner_authorization_head,max_slots=scope.max_slots)
            self.collection_reader.advance(meter=meter)
            if self.collection_reader.complete:
                self.collection=self.collection_reader.prepared.require_current_v6(work);self.phase='paid'
            return self
        if self.phase=='paid':
            from .installed_d13_natural_frame_v6 import begin_authority_current_derived_blocks_v6
            if self.paid_reader is None:
                factory=scope.source.paid_verifier_factory
                self.paid_reader=begin_authority_current_derived_blocks_v6(work,collection_reader=self.collection_reader,
                    question=scope.question,bundle=scope.source.observer.installed_bundle,resource_issuer=factory.resource_issuer,
                    budget_issuer=factory.budget_issuer,authority_store=factory.authority_store,now_utc=scope.now_utc,_counter_scope=scope)
            self.paid_reader.advance(meter=meter)
            if self.paid_reader.complete:
                _verifier,blocks=self.paid_reader.require_current_v6(work)
                self.parts_raw=_CounterFramePartsV7(self,());self.parts_compressed=_CounterFramePartsV7(self,blocks)
                self.phase='raw_parts'
            return self
        if self.phase in ('raw_parts','compressed_parts'):
            parts=self.parts_raw if self.phase=='raw_parts'else self.parts_compressed
            parts.advance(meter)
            if parts.complete:
                if self.phase=='raw_parts':self.phase='compressed_parts'
                else:
                    self.pair_expiry=min(self.parts_raw.expiry,self.parts_compressed.expiry)
                    self.parts_active=self.parts_raw;self.phase='window'
            return self
        if self.phase=='buffer':
            self.buffer.advance(meter)
            if self.buffer.complete:
                self.digests[self.buffer_name]=self.buffer.digest;self.fields[self.buffer_name]=self.buffer.text
                if self.buffer_name=='normalized':self.normalized_size=self.buffer.stream.offset
                if self.buffer_name=='original':self.original_size=self.buffer.stream.offset
                self.buffer=None;self.phase=self.after_buffer
                if self.phase.startswith('draft_'):
                    self.material_digests[self.buffer_name]=self.digests[self.buffer_name]
                    self.material_fields[self.buffer_name]=self.fields[self.buffer_name]
            return self
        if self.phase=='window':
            self.digests={};self.fields={}
            self._begin_buffer('window',replace(self.collection.window,trusted_utc=scope.frozen_at_utc),'slice');return self
        if self.phase.startswith('draft_'):
            from dataclasses import asdict
            from ..model_broker.d13_provider_http_template_v1 import D13ProviderHTTPTemplateV1
            if self.phase=='draft_plan':
                self._begin_buffer('plan',scope.prospective.plan,'draft_collection');return self
            if self.phase=='draft_collection':
                self._begin_buffer('collection',{'schema':'sylanne3.d13.core-collection-binding.v7',
                    'snapshot':self.prepared.raw.input.history_selection.collection_snapshot_commitment,
                    'window':replace(self.collection.window,trusted_utc=scope.frozen_at_utc),
                    'pages':tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence,
                        page.page_status,page.expired_sequences,page.unclosed_sequences)for page in self.collection.pages)},
                    'draft_variant');return self
            if self.phase=='draft_variant':
                frozen=self.variants[self.material_index]
                from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
                work.operation.retain(_canonical_container_bytes_v3(frozen)*3+65536)
                self.frozen_values.append(asdict(frozen))
                self._begin_buffer('frozen',self.frozen_values[-1],'draft_template');return self
            if self.phase=='draft_template':
                frozen=self.variants[self.material_index]
                from .natural_reply_job_v2 import natural_job_ids_v2
                self.generation_call_id=natural_job_ids_v2(work.namespace,work.request.c02_operation_id,'generation')[3]
                self.http_templates.append(D13ProviderHTTPTemplateV1(frozen.installation.model_id,
                    tuple((message.role,message.content)for message in frozen.messages),frozen.installation.max_output_tokens,
                    self.generation_call_id,work.counter_call.service.billing_contract_digest,scope.policy.serializer_fingerprint))
                self._begin_buffer('template',asdict(self.http_templates[-1]),'draft_http_begin');return self
            if self.phase=='draft_http_begin':
                self.template_digests.append(self.material_digests['template'])
                self.http_buffer=_CounterHTTPBufferV7(self,self.http_templates[-1]);self.phase='draft_http';return self
            if self.phase=='draft_http':
                self.http_buffer.advance(meter)
                if self.http_buffer.complete:
                    self.http_texts.append(self.http_buffer.text);self.http_buffer=None;self.material_index+=1
                    self.phase='draft_variant'if self.material_index<len(self.variants)else'draft_kernel'
                return self
            if self.phase=='draft_kernel':
                value={'schema':'sylanne3.d13.counter-kernel-input.v1',
                    'raw_http_template_digest':self.template_digests[0],
                    'compressed_http_template_digest':self.template_digests[1]if len(self.template_digests)>1 else None,
                    'raw_http_utf8':self.http_texts[0],
                    'compressed_http_utf8':self.http_texts[1]if len(self.http_texts)>1 else None,
                    **{name:getattr(scope.policy,name)for name in('serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint')}}
                self._begin_buffer('kernel',value,'draft_normalize');return self
            if self.phase=='draft_normalize':
                if self.original_draft is None:
                    self.normalization_complete=True;self.phase='draft_complete';return self
                if self.original_draft is not work.counter_call.draft:
                    raise ValueError('Counter existing draft changed during recipe preparation')
                self.normalizing=True;self.variant=0;self.phase='draft_normalize_variant';return self
            if self.phase=='draft_normalize_variant':
                previous=self.variants[self.variant];name=('raw','compressed')[self.variant]
                original=self.original_variants[self.variant]
                from collections.abc import Mapping
                if not isinstance(original,Mapping):raise ValueError('Counter V7 frame variant changed')
                selection=replace(previous.input.history_selection,
                    collection_snapshot_commitment=original['input']['history_selection']['collection_snapshot_commitment'])
                self.normalized_selection=selection
                self.parts_active=self.parts_raw if self.variant==0 else self.parts_compressed
                self.digests={'window':selection.window_digest,'slice':selection.selected_slice_digest};self.fields={}
                witness=_CounterInputEOFV7(self,self.parts_active,selection);self.input_witnesses.append(witness)
                self.input_witness=witness
                self.input=NaturalReplyInputV7(previous.input.question,previous.input.plan,previous.input.stable_history,
                    previous.input.recent_history,selection,previous.input.detail_history,previous.input.frozen_at_utc,
                    previous.input.expires_at_utc,stable_turns=previous.input.stable_turns,_prepared_history_eof_v3=witness)
                witness.input=self.input;self._begin_buffer('input',self.input,'projection');return self
            if self.phase=='draft_normalized_expected':
                self.normalized_expected=(self.material_digests['normalized'],self.normalized_size)
                from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
                sealed=self.original_variants[self.variant]
                work.operation.retain(_canonical_container_bytes_v3(sealed)*2+1024)
                self._begin_buffer('original',_counter_detached_plain_v7(sealed),'draft_normalized_compare');return self
            if self.phase=='draft_normalized_compare':
                if self.normalized_expected!=(self.material_digests['original'],self.original_size):
                    raise ValueError('Counter V7 frame variant changed')
                self.variant+=1
                if self.variant<len(self.variants):self.phase='draft_normalize_variant'
                else:
                    if len(self.variants)==1 and self.original_variants[1]is not None:
                        raise ValueError('Counter V7 frame variant changed')
                    self.normalization_complete=True;self.phase='draft_complete'
                return self
            if self.phase=='draft_complete':
                self.draft_material=PreparedAuthorityCounterDraftMaterialV7(self);self.complete=True;return self
            raise ValueError('unregistered Counter draft material phase')
        parts=self.parts_active
        if self.phase=='slice':
            self._begin_buffer('slice',{'stable_history':parts.stable,'recent_history':parts.recent,'detail_history':parts.details,
                'coverage':parts.coverage,'gaps':parts.gaps},'input');return self
        if self.phase=='input':
            window=self.collection.window
            selection=D13NaturalHistorySelectionV2(self.digests['window'],window.order_watermark,parts.coverage,parts.gaps,
                parts.dependencies,parts.read_set,window.scene_ref,window.audience_ref,window.conversation_ref,self.pair_expiry,
                window.access_epoch,window.delete_epoch,window.activation_epoch,tuple(parts.refs),tuple(turn.raw_ref for turn in parts.turns),
                self.digests['slice'],POLICY_REF,scope.policy_digest,
                tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence)for page in self.collection.pages),
                self.collection.snapshot_commitment)
            self.input_witness=_CounterInputEOFV7(self,parts,selection)
            self.input_witnesses.append(self.input_witness)
            self.input=NaturalReplyInputV7(scope.question,scope.plan,parts.stable,parts.recent,selection,parts.details,
                scope.frozen_at_utc,self.pair_expiry,stable_turns=parts.timeline,_prepared_history_eof_v3=self.input_witness)
            self.input_witness.input=self.input
            self._begin_buffer('input',self.input,'projection');return self
        if self.phase=='projection':
            self.input_witness.input_digest=self.digests['input']
            _COUNTER_TYPED_INPUT_EOFS_V7[self.input_witness]=(self,work,scope,self.input,self.digests['input'])
            from ..model_broker.natural_reply_history_v7 import semantic_model_projection_v7,_natural_message_values_v7
            self.projection=semantic_model_projection_v7(self.input,prepared_eof=self.input_witness)
            self._begin_buffer('projection',self.projection,'stable');return self
        if self.phase=='stable':
            from ..model_broker.natural_reply_history_v7 import _natural_message_values_v7
            self.stable_value,self.dynamic_value=_natural_message_values_v7(self.projection)
            self._begin_buffer('stable',self.stable_value,'dynamic');return self
        if self.phase=='dynamic':self._begin_buffer('dynamic',self.dynamic_value,'wire');return self
        if self.phase=='wire':
            from ..model_broker.natural_reply_history_v7 import NaturalReplyMessageV2,SYSTEM_MESSAGE,_natural_wire_value_v7
            self.messages=(NaturalReplyMessageV2('system',SYSTEM_MESSAGE),NaturalReplyMessageV2('user',self.fields['stable']),
                NaturalReplyMessageV2('user',self.fields['dynamic']))
            self._begin_buffer('wire',_natural_wire_value_v7(scope.installation,self.messages),'system_wire');return self
        if self.phase=='system_wire':
            from dataclasses import asdict
            self._begin_buffer('system_wire',asdict(self.messages[0]),'stable_wire');return self
        if self.phase=='stable_wire':
            from dataclasses import asdict
            self._begin_buffer('stable_wire',asdict(self.messages[1]),'prefix');return self
        if self.phase=='prefix':
            from ..model_broker.natural_reply_history_v7 import _natural_prefix_parts_v7
            from hashlib import sha256
            self.work.operation.retain((len(self.fields['system_wire'])+len(self.fields['stable_wire']))*2+1024)
            self.prefix=''.join(_natural_prefix_parts_v7(scope.installation,self.fields['system_wire'],self.fields['stable_wire']))
            if not self.fields['wire'].startswith(self.prefix):raise ValueError('V7 stable prefix differs from actual canonical wire')
            self.prefix_offset=0;self.prefix_hash=sha256();self.phase='prefix_hash';return self
        if self.phase=='prefix_hash':
            if self.prefix_offset<len(self.prefix):
                end=min(self.prefix_offset+1024,len(self.prefix));fragment=self.prefix[self.prefix_offset:end].encode('ascii')
                meter.charge_encode(len(fragment));self.prefix_hash.update(fragment);self.prefix_offset=end;return self
            from ..model_broker.natural_reply_history_v7 import TEMPLATE_DIGEST
            self._begin_buffer('prefix_digest',{'template_digest':TEMPLATE_DIGEST,'installation':scope.installation,
                'stable_prefix_sha256':self.prefix_hash.hexdigest()},'units');return self
        if self.phase=='units':self._begin_buffer('units',self.input.plan.units,'variant_done');return self
        if self.phase=='variant_done':
            frozen=FrozenNaturalReplyRequestV7(self.input,scope.installation,self.messages,self.fields['wire'],self.prefix,
                self.digests['prefix_digest'],self.digests['input'],self.digests['units'],self.digests['wire'],self.digests['projection'])
            if self.normalizing:
                from dataclasses import asdict
                self._begin_buffer('normalized',asdict(frozen),'draft_normalized_expected');return self
            self.variants.append(frozen)
            if self.variant==0 and self.parts_compressed.selected:
                self.variant=1;self.parts_active=self.parts_compressed;self.phase='window';return self
            writes=[];reads=[];selected=self.parts_compressed.selected if len(self.variants)>1 else ()
            for item in selected:
                if item.metadata.status=='standby':
                    key=AtomKey.from_token(item.ref.ref)
                    writes.append(GraphWrite(key,derived_block_metadata_value_v2(replace(item.metadata,status='active')),
                        tuple(AtomKey.from_token(ref.ref)for ref in item.metadata.source_dependencies)))
                    reads.append(GraphVersion(key,item.ref.version))
            self.prepared=NaturalHistoryPairV7(self.variants[0],self.variants[1]if len(self.variants)>1 else None,
                self.collection,selected,tuple(writes),tuple(reads));self.phase='draft_plan'
            _COUNTER_PAIR_EOFS_V7[self]=(work,scope,self.operation,self.scope,self.prepared,tuple(self.variants),self.collection,selected)
            return self
        raise ValueError('unregistered actual initial Counter frame phase')
    def require_current_v7(self,work):
        self._actual()
        if (work is not self.work or not self.complete
                or _COUNTER_PAIR_EOFS_V7.get(self)!=(work,self.counter_scope,self.operation,self.scope,self.prepared,
                    tuple(self.variants),self.collection,self.prepared.projected_blocks)):
            raise ValueError('actual initial Counter pair EOF required')
        return self.prepared
    def require_counter_draft_material_v7(self,work):
        self.require_current_v7(work)
        return self.draft_material.require_current_v7(work)
    def release_payload_v3(self):
        if self.draft_material is not None:self.draft_material.release_payload_v3()
        self.draft_material=None;self.http_buffer=None;self.original_draft=None;self.original_variants=None;self.normalized_selection=None
        self.http_templates.clear();self.http_texts.clear();self.frozen_values.clear()
        self.material_fields.clear();self.material_digests.clear();self.template_digests.clear()
        _COUNTER_INITIAL_READERS_V7.discard(self)
        if self.paid_reader is not None:self.paid_reader.release_payload_v3()
        for witness in self.input_witnesses:
            _COUNTER_INPUT_EOFS_V7.pop(witness,None);_COUNTER_TYPED_INPUT_EOFS_V7.pop(witness,None)
        self.input_witnesses.clear()
        for parts in (self.parts_raw,self.parts_compressed):
            if parts is not None:_COUNTER_PARTS_EOFS_V7.pop(parts,None)
        _COUNTER_PAIR_EOFS_V7.pop(self,None)
        self.parts_raw=self.parts_compressed=self.parts_active=self.paid_reader=self.collection_reader=self.collection=None
        self.buffer=self.input=self.input_witness=self.messages=self.projection=self.stable_value=self.dynamic_value=self.prefix=None
        self.prepared=None;self.variants.clear();self.fields.clear();self.digests.clear()


def begin_authority_initial_natural_history_pair_v7(work,*,counter_scope):
    return _AuthorityInitialNaturalHistoryPairV7(work,counter_scope=counter_scope)
