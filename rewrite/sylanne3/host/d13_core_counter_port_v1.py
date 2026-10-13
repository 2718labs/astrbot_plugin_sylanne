"""Host locator-only client for the independent installed Core counter.

Call only outside Graph locks/transactions. Neither a DTO nor frame header
confers model permission; signed evidence still enters the current W01 gates.
"""
from ..authority_service.d13_core_counter_contract_v1 import (D13CurrentFramePrepareSelectorV7,
    D13CurrentWireCountSelectorV1,D13CoreFrameIntentHeaderV7,InstalledD13WirePolicyV7,
    D13CounterCPUPrepareInstructionV1,D13CounterAwaitingAccountingV1,verify_signed_d13_core_wire_evidence_v1)
from .v2_fence_port import V2FencePort

class InstalledD13CoreCounterPortV1:
    def __init__(self,port,*,policy):
        if type(port) is not V2FencePort or type(policy) is not InstalledD13WirePolicyV7:
            raise TypeError('actual paired private port and installed Core policy required')
        if policy.installation.installation_id!=port.installation_grant.installation_id:
            raise ValueError('Core counter policy crossed actual installed grant')
        self._port,self.policy=port,policy
    def prepare_current_d13_frame_v7(self,selector):
        if type(selector) is not D13CurrentFramePrepareSelectorV7:raise TypeError('exact actual frame selector required')
        frame=self._port.prepare_current_d13_frame_v7(selector)
        if type(frame) is D13CounterCPUPrepareInstructionV1:return frame
        if frame.policy_digest!=self.policy.policy_digest:raise ValueError('actual Core frame policy differs')
        return frame
    def count_current_d13_wire_v1(self,selector,*,frame,now_utc):
        if type(selector) is not D13CurrentWireCountSelectorV1 or type(frame) is not D13CoreFrameIntentHeaderV7:
            raise TypeError('exact original count operation and frame required')
        envelope=self._port.count_current_d13_wire_v1(selector,frame=frame)
        if type(envelope) is D13CounterAwaitingAccountingV1:return envelope
        verify_signed_d13_core_wire_evidence_v1(self.policy,envelope,selector=selector,frame=frame,now_utc=now_utc)
        return envelope

    def count_actual_current_pair_v7(self,*,pair,frame,now_utc):
        """Count only the pair independently reconstructed for this original Core frame."""
        from ..runtime.installed_d13_natural_frame_v7 import (NaturalHistoryPairV7,
            core_collection_binding_digest_v7,core_paid_block_binding_v7,core_paid_blockset_digest_v7)
        from ..model_broker.d13_provider_http_template_v1 import provider_http_template_v1
        if (type(pair) is not NaturalHistoryPairV7 or type(frame) is not D13CoreFrameIntentHeaderV7
                or frame.policy_digest!=self.policy.policy_digest
                or core_collection_binding_digest_v7(pair.collection,
                    snapshot_commitment=pair.raw.input.history_selection.collection_snapshot_commitment,
                    frozen_at_utc=frame.frozen_at_utc)!=frame.collection_digest
                or core_paid_blockset_digest_v7([core_paid_block_binding_v7(item) for item in pair.projected_blocks])!=frame.blockset_digest):
            raise ValueError('actual current pair differs from independent Core frame originals')
        raw=provider_http_template_v1(pair.raw,generation_call_id=frame.generation_call_id,
            billing_contract_digest=frame.billing_contract_digest,serializer_pin=self.policy.serializer_fingerprint)
        compressed=None if pair.compressed is None else provider_http_template_v1(pair.compressed,
            generation_call_id=frame.generation_call_id,billing_contract_digest=frame.billing_contract_digest,
            serializer_pin=self.policy.serializer_fingerprint)
        selector=D13CurrentWireCountSelectorV1(frame.install_id,frame.authority_namespace,
            frame.frame_intent_id,frame.frame_intent_digest,frame.counter_operation_id,
            pair.raw.frozen_input_digest,None if pair.compressed is None else pair.compressed.frozen_input_digest,
            raw.template_digest,None if compressed is None else compressed.template_digest)
        envelope=self.count_current_d13_wire_v1(selector,frame=frame,now_utc=now_utc)
        if type(envelope) is D13CounterAwaitingAccountingV1:return selector,envelope
        if (envelope.payload.raw_http_bytes!=raw.byte_count
                or envelope.payload.compressed_http_bytes!=(None if compressed is None else compressed.byte_count)):
            raise ValueError('independent count original differs from actual pinned SDK serializer length')
        return selector,envelope

    def count_original_header_v7(self,*,frame,now_utc):
        """Use only the Core-frozen pair commitments; no Host body candidate precedes CPU."""
        if type(frame) is not D13CoreFrameIntentHeaderV7 or frame.policy_digest!=self.policy.policy_digest:
            raise ValueError('actual Core frozen header and same installed policy required')
        selector=D13CurrentWireCountSelectorV1(frame.install_id,frame.authority_namespace,
            frame.frame_intent_id,frame.frame_intent_digest,frame.counter_operation_id,
            frame.raw_authority_digest,frame.compressed_authority_digest,
            frame.raw_http_template_digest,frame.compressed_http_template_digest)
        return selector,self.count_current_d13_wire_v1(selector,frame=frame,now_utc=now_utc)
