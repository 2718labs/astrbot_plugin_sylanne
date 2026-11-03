"""Closed observation-fact originals; a fact fence never authorizes dispatch."""
from __future__ import annotations
from dataclasses import dataclass, fields, asdict
import hashlib
import json
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest as original_digest
from .contract import identifier
from .v2_contract import (FencePermitV2,MutationReceiptV2,PlatformObservationV1,
    PlatformObservationV2,to_wire as v2_to_wire,from_wire as v2_from_wire)

SCHEMA='sylanne.authority.platform-observation-refinement.v3'
ENTRY_PREFIX=b'{"observation_refinement_original":'

def _digest(value):
    if type(value) is not str or len(value)!=71 or not value.startswith('sha256:') or any(c not in '0123456789abcdef' for c in value[7:]):
        raise ValueError('observation fact requires exact SHA256 commitment')

@dataclass(frozen=True,slots=True)
class PlatformObservationRefinementPendingV3:
    fact_write_permit:FencePermitV2
    mutation_id:str
    request_digest:str
    before_anchor:RestoreAnchor
    expected_execution_journal_id:str
    expected_execution_seq:int
    expected_append_id:str
    expected_append_digest:str
    original_claimed_receipt:MutationReceiptV2
    predecessor_mutation_id:str
    predecessor_receipt_digest:str
    platform_observation:PlatformObservationV1|PlatformObservationV2
    schema:str=SCHEMA
    def __post_init__(self):
        p=self.fact_write_permit;c=self.original_claimed_receipt;o=self.platform_observation
        if self.schema!=SCHEMA or type(p) is not FencePermitV2 or p.operation!='write' or p.effect_id is not None or p.footprint_digest is not None:
            raise ValueError('fact requires its own exact WRITE fence')
        if type(c) is not MutationReceiptV2 or c.durable_state!='committed' or c.pending.phase!='claimed' or type(o) not in (PlatformObservationV1,PlatformObservationV2) or o.binding!=c.pending.binding:
            raise ValueError('fact requires original committed dispatch claim and observation')
        origin=c.pending.permit
        if (p.authority_id,p.namespace,p.subject,p.holder,p.generation)!=(origin.authority_id,origin.namespace,origin.subject,origin.holder,origin.generation) or p.operation_id==origin.operation_id:
            raise ValueError('fact and historical dispatch identities differ')
        for name in ('mutation_id','expected_execution_journal_id','expected_append_id','predecessor_mutation_id'):
            identifier(getattr(self,name),name)
        for name in ('request_digest','expected_append_digest','predecessor_receipt_digest'):_digest(getattr(self,name))
        if type(self.before_anchor) is not RestoreAnchor or p.pinned_anchor!=self.before_anchor or self.expected_execution_journal_id!=self.before_anchor.execution_journal_id or type(self.expected_execution_seq) is not int or self.expected_execution_seq!=self.before_anchor.execution_seq+1 or self.mutation_id!=p.operation_id or self.expected_append_id!=self.mutation_id:
            raise ValueError('fact append/fence/before anchor identity differs')
        if p.command_digest is not None:
            raise ValueError('fact WRITE fence cannot contain dispatch command authority')
        if p.operation_id!=fact_operation_id_v3(p.namespace,c,o) or self.request_digest!=fact_request_digest_v3(p.operation_id,c,self.predecessor_mutation_id,self.predecessor_receipt_digest,o,self.before_anchor):
            raise ValueError('fact stable identity/request commitment differs')

@dataclass(frozen=True,slots=True)
class PlatformObservationRefinementReceiptV3:
    pending:PlatformObservationRefinementPendingV3
    after_anchor:RestoreAnchor
    updated_revision:int
    durable_state:str='committed'
    schema:str=SCHEMA
    def __post_init__(self):
        if self.schema!=SCHEMA or type(self.pending) is not PlatformObservationRefinementPendingV3 or type(self.after_anchor) is not RestoreAnchor or self.durable_state!='committed' or type(self.updated_revision) is not int or self.updated_revision!=self.pending.fact_write_permit.revision+1:
            raise ValueError('invalid committed observation fact receipt')
        b=self.pending.before_anchor;a=self.after_anchor
        if (a.authority_id,a.namespace,a.activation_generation,a.deletion_journal_id,a.deletion_seq,a.deletion_digest,a.execution_journal_id,a.revocation_epoch)!=(b.authority_id,b.namespace,b.activation_generation,b.deletion_journal_id,b.deletion_seq,b.deletion_digest,b.execution_journal_id,b.revocation_epoch) or (a.execution_seq,a.execution_digest)!=(self.pending.expected_execution_seq,self.pending.expected_append_digest):
            raise ValueError('fact receipt changes unrelated anchor or append')
    @property
    def receipt_digest(self):return canonical_digest(self)

def to_wire(value):
    if type(value) is PlatformObservationRefinementPendingV3:
        return {f.name:(v2_to_wire(getattr(value,f.name)) if f.name in ('fact_write_permit','original_claimed_receipt','platform_observation') else asdict(value.before_anchor) if f.name=='before_anchor' else getattr(value,f.name)) for f in fields(value)}|{'kind':'platform_observation_refinement_pending_v3'}
    if type(value) is PlatformObservationRefinementReceiptV3:
        return {'kind':'platform_observation_refinement_receipt_v3','schema':value.schema,'pending':to_wire(value.pending),'after_anchor':asdict(value.after_anchor),'updated_revision':value.updated_revision,'durable_state':value.durable_state}
    return v2_to_wire(value)

def from_wire(value):
    if type(value) is not dict:raise ValueError('observation original must be an object')
    kind=value.get('kind')
    if kind=='platform_observation_refinement_pending_v3':
        if set(value)!={f.name for f in fields(PlatformObservationRefinementPendingV3)}|{'kind'}:raise ValueError('fact pending fields differ')
        d={k:v for k,v in value.items() if k!='kind'}
        for k in ('fact_write_permit','original_claimed_receipt','platform_observation'):d[k]=v2_from_wire(d[k])
        d['before_anchor']=RestoreAnchor(**d['before_anchor'])
        return PlatformObservationRefinementPendingV3(**d)
    if kind=='platform_observation_refinement_receipt_v3':
        if set(value)!={f.name for f in fields(PlatformObservationRefinementReceiptV3)}|{'kind'}:raise ValueError('fact receipt fields differ')
        d={k:v for k,v in value.items() if k!='kind'}
        d['pending']=from_wire(d['pending']);d['after_anchor']=RestoreAnchor(**d['after_anchor'])
        return PlatformObservationRefinementReceiptV3(**d)
    return v2_from_wire(value)

def canonical_bytes(value):return json.dumps(to_wire(value),sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
def canonical_digest(value):return 'sha256:'+hashlib.sha256(canonical_bytes(value)).hexdigest()

def decode_bytes(value):
    if type(value) is not bytes:raise ValueError('observation original must be bytes')
    result=from_wire(json.loads(value))
    if canonical_bytes(result)!=value:raise ValueError('noncanonical observation original')
    return result

def observation_claimed_receipt_v3(receipt):
    if type(receipt) is PlatformObservationRefinementReceiptV3:return receipt.pending.original_claimed_receipt
    if type(receipt) is MutationReceiptV2 and receipt.pending.phase=='observed':return receipt.pending.claimed_receipt
    raise ValueError('exact committed observation receipt required')
def observation_original_dispatch_permit_v3(receipt):return observation_claimed_receipt_v3(receipt).pending.permit
def observation_platform_observation_v3(receipt):
    observation_claimed_receipt_v3(receipt)
    return receipt.pending.platform_observation
def observation_effect_id_v3(receipt):return observation_original_dispatch_permit_v3(receipt).effect_id
def observation_receipt_digest_v3(receipt):
    observation_claimed_receipt_v3(receipt)
    return original_digest(receipt)

def fact_operation_id_v3(namespace,claimed,observation):
    return 'observation-fact-v3:'+original_digest((namespace,claimed.pending.permit.operation_id,claimed.pending.permit.effect_id,observation.observation_id))

def fact_request_digest_v3(fact_id,claim,predecessor_id,predecessor_digest,observation,before_anchor):
    return 'sha256:'+original_digest(('platform-observation-refinement.v3',fact_id,canonical_digest(claim),predecessor_id,predecessor_digest,observation,before_anchor))

def expected_fact_digest_v3(pending):
    shape=to_wire(pending);shape.pop('expected_append_digest')
    material={'observation_refinement_original':{'journal_id':pending.expected_execution_journal_id,'seq':pending.expected_execution_seq,'previous_digest':pending.before_anchor.execution_digest,'pending':shape}}
    return 'sha256:'+hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
def encode_fact_entry_v3(pending):return json.dumps({'observation_refinement_original':to_wire(pending)},sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
def decode_fact_row_v3(journal,row):
    body=json.loads(row[4])
    if type(body) is not dict or set(body)!={'observation_refinement_original'}:raise ValueError('fact entry envelope differs')
    p=from_wire(body['observation_refinement_original'])
    if type(p) is not PlatformObservationRefinementPendingV3 or row[4]!=encode_fact_entry_v3(p) or (row[0],row[1],row[2],row[3],row[5],row[6])!=(p.expected_execution_seq,p.mutation_id,p.request_digest,p.expected_append_id,p.before_anchor.execution_digest,p.expected_append_digest) or p.fact_write_permit.namespace!=journal.namespace or p.expected_execution_journal_id!=journal.journal_id or expected_fact_digest_v3(p)!=p.expected_append_digest:
        raise ValueError('fact entry commitment differs')
    return p
