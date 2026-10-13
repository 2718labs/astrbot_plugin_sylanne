"""Actual v6 same-snapshot multi-block read and exact natural wire candidates."""
from dataclasses import dataclass, replace
import json
from weakref import WeakSet

from ..authority_service.d13_derived_paid_block_verifier_v2 import InstalledD13DerivedPaidBlockVerifierV2
from ..domains.d13.derived_block_metadata_v2 import (METADATA_TYPE, decode_derived_block_metadata_v2,
    derived_block_metadata_value_v2)
from ..domains.d13.precompression import _model_candidate_current, select_detail_slots
from ..domains.d13.provider import retirement_reason
from ..domains.d13.raw_slice import _merge_ranges
from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..model_broker.context_reply import ContextReplyPartV1
from ..model_broker.natural_reply_history_v3 import D13NaturalRawTurnV1
from ..model_broker.natural_reply_history_v4 import D13NaturalDetailPartV1
from ..model_broker.natural_reply_history_v6 import (D13NaturalHistorySelectionV2, NaturalReplyInputV6,
    FrozenNaturalReplyRequestV6, freeze_natural_reply_request_v6)
from ..runtime_contracts import VersionedRef, canonical_digest
from .d11_derived_cache_payload_v1 import read_derived_payload_v1
from .d13_current_collection_v6 import CurrentD13CollectionV6, read_current_d13_collection_v6
from .d13_precompression_job import plan_from_precompression_job_v1
from .jobs import get_job

POLICY_REF = 'd13.natural.current_full_wire.v6'
_PROJECTION_KEY = object()

@dataclass(frozen=True,slots=True,init=False)
class _QualifiedDerivedProjectionV6:
    ref: VersionedRef
    metadata: object
    block: object
    compression_plan: object
    def __init__(self,key,*,ref,metadata,block,compression_plan):
        if key is not _PROJECTION_KEY:
            raise TypeError('derived projection comes only from this current paid/source reader')
        for name,value in (('ref',ref),('metadata',metadata),('block',block),('compression_plan',compression_plan)):
            object.__setattr__(self,name,value)

@dataclass(frozen=True, slots=True)
class NaturalHistoryPairV6:
    raw: FrozenNaturalReplyRequestV6
    compressed: FrozenNaturalReplyRequestV6 | None
    collection: CurrentD13CollectionV6
    projected_blocks: tuple
    activation_writes: tuple[GraphWrite, ...]
    activation_reads: tuple[GraphVersion, ...]
    schema: str = 'd13.natural-history-pair.v6'


def _qualify_current_derived_block_v6(db,*,collection,question,paid_verifier,row,occupied,_authority_reader=None):
    """One candidate's unchanged metadata, Source, retirement and paid predicates."""
    window=collection.window
    token,revision,raw=row
    if _authority_reader is None:metadata=decode_derived_block_metadata_v2(json.loads(raw))
    else:
        if type(_authority_reader)is not _AuthorityDerivedBlocksReadV6 or _authority_reader.active_row is not row and _authority_reader.active_row!=row:
            raise ValueError('actual filtered paid candidate original required')
        _authority_reader._actual();metadata=_authority_reader.active_metadata
    key=AtomKey.from_token(token)
    if (metadata.namespace!=window.namespace or key.name!=metadata.block_ref
            or metadata.scene_ref!=window.scene_ref or metadata.audience_ref!=window.audience_ref
            or metadata.conversation_ref!=window.conversation_ref or window.trusted_utc>=metadata.expires_at_utc
            or not set(metadata.source_dependencies)<=set(window.source_dependencies)
            or question.ref in metadata.source_dependencies):
        return None
    covered={turn.sequence for turn in metadata.turn_expiries}
    if occupied & covered:return None
    block=read_derived_payload_v1(db,metadata,now_utc=window.trusted_utc)
    job=get_job(db,metadata.job_ref)
    if (job.bot_id,job.persona_id)!=window.namespace.as_tuple:
        raise ValueError('derived block job crossed its namespace')
    compression_plan=plan_from_precompression_job_v1(job)
    if (retirement_reason(block,compression_plan,window) is not None
            or not _model_candidate_current(block,compression_plan,window,paid_verifier)):
        return None
    return _QualifiedDerivedProjectionV6(_PROJECTION_KEY,ref=VersionedRef(token,revision),
        metadata=metadata,block=block,compression_plan=compression_plan)


def read_current_derived_blocks_v6(db,*,collection,question,paid_verifier):
    if (not db.in_transaction or type(collection) is not CurrentD13CollectionV6
            or type(paid_verifier) is not InstalledD13DerivedPaidBlockVerifierV2):
        raise ValueError('v6 blocks require the actual current collection and new installed paid verifier')
    window=collection.window
    first,last=collection.pages[-1].first_sequence,window.order_watermark
    rows=db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name=? AND owner_kind='persona' AND valid=1 "
        "AND json_extract(value,'$.status') IN ('standby','active') "
        "AND json_extract(value,'$.turn_expiries[0].sequence')>=? "
        "AND json_extract(value,'$.turn_expiries[#-1].sequence')<=? "
        "ORDER BY json_extract(value,'$.turn_expiries[#-1].sequence') DESC,token LIMIT 16",
        (*window.namespace.as_tuple,METADATA_TYPE,first,last)).fetchall()
    selected,occupied=[],set()
    for row in rows:
        item=_qualify_current_derived_block_v6(db,collection=collection,question=question,
            paid_verifier=paid_verifier,row=row,occupied=occupied)
        if item is None:continue
        selected.append(item);occupied.update(turn.sequence for turn in item.metadata.turn_expiries)
        if len(selected)==4:break
    return tuple(sorted(selected,key=lambda item:item.block.turns[0].sequence))


def build_natural_frame_v6(*,collection,plan,question,installation,frozen_at_utc,expires_at_utc,
        policy_digest,blocks=(),history_byte_budget=262144):
    """Pure candidates only; actual installed count, budget reservation and W01 adoption are separate."""
    if (type(collection) is not CurrentD13CollectionV6 or type(history_byte_budget) is not int
            or not 1<=history_byte_budget<=262144 or type(blocks) is not tuple or len(blocks)>4
            or any(type(item) is not _QualifiedDerivedProjectionV6 for item in blocks)):
        raise ValueError('v6 frame needs the bounded actual collector and current derived projections')
    window=collection.window
    if (window.namespace!=plan.namespace or window.scene_ref!=plan.scene_ref or window.audience_ref!=plan.audience_ref
            or window.conversation_ref!=plan.audience_id or question.audience_ref!=plan.audience_ref):
        raise ValueError('v6 history and natural plan/current question differ')
    stable,details,refs,selected,covered=[],[],[],[],set()
    used=0
    expiry=min(expires_at_utc,plan.valid_until_utc,question.expires_at_utc)
    for item in blocks:
        block=item.block
        sequences={turn.sequence for turn in block.turns}
        if covered & sequences or question.ref in block.source_dependencies:
            raise ValueError('v6 history duplicates a block turn or current question')
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
    return freeze_natural_reply_request_v6(NaturalReplyInputV6(question,plan,stable,raw,selection,details,
        frozen_at_utc,expiry),installation),tuple(selected)


def prepare_current_natural_history_pair_v6(db,*,namespace,plan,question,installation,now_utc,expires_at_utc,
        activation_generation,paid_verifier,policy_digest,max_slots=256,history_byte_budget=262144):
    collection=read_current_d13_collection_v6(db,namespace,plan.scene_id,plan.audience_id,now_utc,
        expected_activation_generation=activation_generation,max_slots=max_slots)
    projections=() if paid_verifier is None else read_current_derived_blocks_v6(db,collection=collection,question=question,paid_verifier=paid_verifier)
    raw,_=build_natural_frame_v6(collection=collection,plan=plan,question=question,installation=installation,
        frozen_at_utc=now_utc,expires_at_utc=expires_at_utc,policy_digest=policy_digest,history_byte_budget=history_byte_budget)
    compressed,selected=build_natural_frame_v6(collection=collection,plan=plan,question=question,installation=installation,
        frozen_at_utc=now_utc,expires_at_utc=expires_at_utc,policy_digest=policy_digest,blocks=projections,
        history_byte_budget=history_byte_budget)
    if not selected:
        return NaturalHistoryPairV6(raw,None,collection,(),(),())
    pair_expiry=min(raw.input.expires_at_utc,compressed.input.expires_at_utc)
    if raw.input.expires_at_utc!=pair_expiry:
        raw=freeze_natural_reply_request_v6(replace(raw.input,expires_at_utc=pair_expiry,
            history_selection=replace(raw.input.history_selection,expires_at_utc=pair_expiry)),installation)
    if compressed.input.expires_at_utc!=pair_expiry:
        compressed=freeze_natural_reply_request_v6(replace(compressed.input,expires_at_utc=pair_expiry,
            history_selection=replace(compressed.input.history_selection,expires_at_utc=pair_expiry)),installation)
    writes,reads=[],[]
    for item in selected:
        if item.metadata.status=='standby':
            key=AtomKey.from_token(item.ref.ref)
            writes.append(GraphWrite(key,derived_block_metadata_value_v2(replace(item.metadata,status='active')),
                tuple(AtomKey.from_token(ref.ref) for ref in item.metadata.source_dependencies)))
            reads.append(GraphVersion(key,item.ref.version))
    return NaturalHistoryPairV6(raw,compressed,collection,selected,tuple(writes),tuple(reads))


@dataclass(frozen=True,slots=True)
class NaturalHistoryDecisionV6:
    selected: str
    token_evidence: str
    activation: str
    policy_digest: str
    wire_digest: str
    proof_digest: str | None=None
    activation_writes: tuple=()
    activation_expected: tuple=()
    budget_state: str='unverified'
    pair: NaturalHistoryPairV6 | None=None


def freeze_current_natural_frame_v6(db,*,namespace,plan,question,installation,now_utc,expires_at_utc,
        activation_generation,paid_verifier,installed_wire_port,policy_digest,max_slots=256,original=None,
        preflight=None,preflight_out=None,history_byte_budget=262144):
    from .d13_natural_counter_preflight_v6 import D13NaturalWirePreflightV6
    from ..authority_service.d13_wire_evidence_v6 import (InstalledD13WireEvidencePortV6,
        require_current_v6_collection_for_original_pair)
    if not db.in_transaction:
        raise ValueError('v6 freezing belongs to the actual held current read transaction')
    if original is not None:
        if (type(original) is not FrozenNaturalReplyRequestV6 or original!=freeze_natural_reply_request_v6(original.input,original.installation)
                or original.installation!=installation or original.input.plan!=plan or original.input.question!=question
                or not original.input.frozen_at_utc<=now_utc<original.input.expires_at_utc):
            raise ValueError('v6 original cannot change its exact input/install/deadline')
        collection=read_current_d13_collection_v6(db,namespace,plan.scene_id,plan.audience_id,now_utc,
            expected_activation_generation=activation_generation,max_slots=max_slots)
        if canonical_digest(replace(collection.window,trusted_utc=original.input.frozen_at_utc))!=original.input.history_selection.window_digest:
            raise ValueError('v6 original Source/order/permissions/turn body changed')
        if original.input.stable_history:
            if type(installed_wire_port) is not InstalledD13WireEvidencePortV6:
                raise ValueError('v6 compressed original needs the actual new reserved wire port')
            proof=installed_wire_port.verify_reserved_original_v6(original=original,current_collection=collection,now_utc=now_utc)
        else:
            proof=None
        reads=tuple(GraphVersion(AtomKey.from_token(ref.ref),ref.version) for ref in original.input.history_selection.read_set)
        return original,reads,NaturalHistoryDecisionV6('compressed' if original.input.stable_history else 'raw',
            'token_evidence_unverified' if proof is None else proof.token_evidence,'activation_not_attempted',policy_digest,
            original.model_request_digest,None if proof is None else proof.proof_digest,
            budget_state='unverified' if proof is None else proof.budget_state)
    if preflight is not None:
        if (type(preflight) is not D13NaturalWirePreflightV6 or preflight.installed_policy_digest!=policy_digest
                or preflight.pair.raw.input.plan!=plan or preflight.pair.raw.input.question!=question
                or preflight.pair.raw.installation!=installation):
            raise ValueError('v6 counted preflight is another exact current model/source input')
        pair=preflight.pair
        require_current_v6_collection_for_original_pair(db,installed_wire_port._policy,pair,now_utc)
    else:
        pair=prepare_current_natural_history_pair_v6(db,namespace=namespace,plan=plan,question=question,
            installation=installation,now_utc=now_utc,expires_at_utc=expires_at_utc,activation_generation=activation_generation,
            paid_verifier=paid_verifier,policy_digest=policy_digest,max_slots=max_slots,history_byte_budget=history_byte_budget)
    if preflight_out is not None and pair.compressed is not None and installed_wire_port is not None:
        if preflight is not None or type(preflight_out) is not list or preflight_out:
            raise ValueError('v6 first counter preflight requires its fresh output collector')
        preflight_out.append(D13NaturalWirePreflightV6(pair,policy_digest))
        proof=None;selected=pair.raw
    elif pair.compressed is None:
        proof=None;selected=pair.raw
    else:
        if type(installed_wire_port) is not InstalledD13WireEvidencePortV6:
            raise ValueError('v6 current multi-block selection lacks its installed complete-wire authority')
        proof=installed_wire_port.evaluate_natural_pair_v6(pair=pair,now_utc=now_utc)
        if proof is None or proof.selected=='hold':
            raise ValueError('v6 actual full-wire count/current budget cannot select a model input')
        selected=pair.raw if proof.selected=='raw' else pair.compressed
    activations=pair.activation_writes if proof is not None and proof.selected=='compressed' else ()
    expected=pair.activation_reads if activations else ()
    actual={ref.key.token:ref for ref in expected}
    reads=tuple(actual.get(ref.ref,GraphVersion(AtomKey.from_token(ref.ref),ref.version))
        for ref in selected.input.history_selection.read_set)
    return selected,reads,NaturalHistoryDecisionV6('compressed' if selected.input.stable_history else 'raw',
        'token_evidence_unverified' if proof is None else proof.token_evidence,
        'activation_prepared' if activations else 'activation_not_attempted',policy_digest,selected.model_request_digest,
        None if proof is None else proof.proof_digest,activations,expected,'unverified' if proof is None else proof.budget_state,pair)

_AUTHORITY_DERIVED_READERS_V6=WeakSet()


class _AuthorityDerivedBlocksReadV6:
    def __init__(self,work,*,collection_reader,question,bundle,resource_issuer,budget_issuer,authority_store,now_utc,_counter_scope=None):
        from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
        from .d13_current_collection_v6 import PreparedAuthorityD13CollectionV6
        if type(work)is not AuthorityGraphReadWorkV3 or type(collection_reader.prepared)is not PreparedAuthorityD13CollectionV6:
            raise ValueError('actual Authority paid collection/bundle required')
        if _counter_scope is None:
            if work.controller.verifier._natural_history._bundle is not bundle:
                raise ValueError('actual Authority history bundle required')
        else:
            from ..authority_service.d13_core_counter_source_v1 import PreparedAuthorityCounterMaterialScopeV7
            if type(_counter_scope)is not PreparedAuthorityCounterMaterialScopeV7:
                raise ValueError('actual initial Counter paid input scope required')
            _counter_scope.require_current_v7(work)
            if (_counter_scope.source.observer.installed_bundle is not bundle
                    or _counter_scope.source.paid_verifier_factory.resource_issuer is not resource_issuer
                    or _counter_scope.source.paid_verifier_factory.budget_issuer is not budget_issuer
                    or _counter_scope.source.paid_verifier_factory.authority_store is not authority_store):
                raise ValueError('Counter paid material crossed its actual installed factory')
        self.counter_scope=_counter_scope
        self.work,self.collection_cap=work,collection_reader.prepared
        self.collection=self.collection_cap.require_current_v6(work)
        self.question,self.bundle=question,bundle
        self.resource_issuer,self.budget_issuer,self.authority_store=resource_issuer,budget_issuer,authority_store
        self.now_utc=now_utc;self.phase='candidates';self.complete=False
        self.candidate_reader=self.body_reader=self.request_reader=None
        self.rows=();self.position=0;self.selected=[];self.occupied=set();self.bodies={};self.paid_requests={}
        self.active_row=self.active_metadata=self.active_plan=self.verifier=None
        _AUTHORITY_DERIVED_READERS_V6.add(self)
    def _actual(self):
        work=self.work
        owner=work.history_current_reader if self.counter_scope is None else work.counter_pair_reader
        if self.counter_scope is not None:self.counter_scope.require_current_v7(work)
        if (self not in _AUTHORITY_DERIVED_READERS_V6 or owner is None or owner.paid_reader is not self
                or self.collection_cap.require_current_v6(work)is not self.collection):
            raise ValueError('actual same-Work paid candidate collector required')
        work._actual()
    def advance(self,*,meter):
        self._actual();self.work.require_current(meter=meter)
        if self.complete:return self
        work,window=self.work,self.collection.window
        if self.phase=='candidates':
            from ..authority_service.current_authority_graph_read_v3 import begin_authority_paid_candidate_rows_read_v6
            if self.candidate_reader is None:self.candidate_reader=begin_authority_paid_candidate_rows_read_v6(work,selection=self.collection)
            self.candidate_reader.advance(meter=meter)
            if self.candidate_reader.complete:
                self.rows=self.candidate_reader.require_current_v6(work)
                if type(self.rows)is not tuple or len(self.rows)>16:raise ValueError('actual paid LIMIT16 candidates required')
                from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
                main=self.bundle.model_workflows.reply
                if main is None:raise ValueError('actual installed main model required for paid original read')
                installation=(D13PrecompressionInstallationV1(self.bundle.installation_policy.installation_id,
                    main.provider_id,main.model_id,main.provider_config_digest,main.max_output_tokens)if self.counter_scope is None
                    else self.counter_scope.source.paid_verifier_factory.installation)
                self.verifier=InstalledD13DerivedPaidBlockVerifierV2(work.db,installation=installation,
                    resource_issuer=self.resource_issuer,budget_issuer=self.budget_issuer,
                    namespace=work.namespace,scene_ref=AtomKey.from_token(window.scene_ref.ref).owner.subject,
                    conversation_ref=window.conversation_ref,now_utc=self.now_utc,
                    activation_generation=window.activation_epoch,authority_store=self.authority_store,
                    max_slots=self.collection.max_slots,_authority_collection=(work,self.collection_cap))
                self.phase='candidate'
            return self
        if self.phase=='candidate':
            if self.position>=len(self.rows) or len(self.selected)==4:
                self.complete=True;return self
            self.active_row=self.rows[self.position]
            token,revision,raw=self.active_row
            metadata=decode_derived_block_metadata_v2(raw)
            key=AtomKey.from_token(token)
            if (metadata.namespace!=window.namespace or key.name!=metadata.block_ref
                    or metadata.scene_ref!=window.scene_ref or metadata.audience_ref!=window.audience_ref
                    or metadata.conversation_ref!=window.conversation_ref or window.trusted_utc>=metadata.expires_at_utc
                    or not set(metadata.source_dependencies)<=set(window.source_dependencies)
                    or self.question.ref in metadata.source_dependencies
                    or self.occupied & {turn.sequence for turn in metadata.turn_expiries}):
                self.position+=1;return self
            self.active_metadata=metadata
            from ..authority_service.current_authority_graph_read_v3 import begin_authority_derived_payload_read_v6
            self.body_reader=begin_authority_derived_payload_read_v6(work,selection=self.collection,
                metadata=metadata,metadata_ref=VersionedRef(token,revision))
            self.phase='body';return self
        if self.phase=='body':
            if not self.body_reader.advance(meter):return self
            from .d11_derived_cache_payload_v1 import _qualify_derived_payload_value_v1
            raw=self.body_reader.require_v3(work)
            block=_qualify_derived_payload_value_v1(self.active_metadata,raw,
                payload_digest=self.body_reader.sha256,payload_length=self.body_reader.byte_count)
            self.bodies[self.active_metadata.block_ref]=(self.active_metadata,self.body_reader,block)
            job=get_job(work.db,self.active_metadata.job_ref)
            if (job.bot_id,job.persona_id)!=work.namespace.as_tuple:raise ValueError('derived block job crossed its namespace')
            self.active_plan=plan_from_precompression_job_v1(job)
            from ..authority_service.d13_paid_block_verifier_v1 import begin_authority_d13_paid_request_read_v3
            self.request_reader=begin_authority_d13_paid_request_read_v3(work,verifier=self.verifier,
                plan=self.active_plan,window=window)
            self.phase='originals';return self
        if self.phase=='originals':
            self.request_reader.advance(meter=meter)
            if self.request_reader.complete:
                self.paid_requests[self.active_plan.job_ref]=self.request_reader
                self.phase='qualify'
            return self
        if self.phase!='qualify':raise ValueError('unregistered actual paid candidate phase')
        token,revision,raw=self.active_row
        item=_qualify_current_derived_block_v6(work.db,collection=self.collection,question=self.question,
            paid_verifier=self.verifier,row=(token,revision,raw),occupied=self.occupied,_authority_reader=self)
        if item is not None:
            self.selected.append(item);self.occupied.update(turn.sequence for turn in item.metadata.turn_expiries)
        self.position+=1;self.phase='candidate';self.body_reader=self.request_reader=None
        self.active_row=self.active_metadata=self.active_plan=None
        return self
    def require_current_v6(self,work):
        if work is not self.work:raise ValueError('actual paid qualification has another Work')
        self._actual()
        if not self.complete:raise ValueError('actual full candidate order/qualification EOF required')
        return self.verifier,tuple(sorted(self.selected,key=lambda item:item.block.turns[0].sequence))
    def require_body_v6(self,metadata):
        self._actual()
        item=self.bodies.get(metadata.block_ref)
        if item is None or item[0]!=metadata or not item[1].complete:raise ValueError('actual paid body EOF was not prepared')
        return item[2]
    def release_payload_v3(self):
        _AUTHORITY_DERIVED_READERS_V6.discard(self)
        for proof in self.paid_requests.values():proof.release_payload_v3()
        self.paid_requests.clear();self.bodies.clear();self.selected.clear();self.rows=()
        self.candidate_reader=self.body_reader=self.request_reader=self.verifier=None


def begin_authority_current_derived_blocks_v6(work,*,collection_reader,question,bundle,resource_issuer,budget_issuer,authority_store,now_utc,_counter_scope=None):
    return _AuthorityDerivedBlocksReadV6(work,collection_reader=collection_reader,question=question,bundle=bundle,
        resource_issuer=resource_issuer,budget_issuer=budget_issuer,authority_store=authority_store,now_utc=now_utc,_counter_scope=_counter_scope)


def require_authority_derived_blocks_reader_v6(work):
    owner=work.counter_pair_reader if work.controller.kind=='counter'else work.history_current_reader
    reader=None if owner is None else owner.paid_reader
    if type(reader)is not _AuthorityDerivedBlocksReadV6:raise ValueError('actual same-Work paid reader required')
    reader._actual();return reader
