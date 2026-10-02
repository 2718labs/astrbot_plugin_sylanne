"""Closed Life-produced D08 outcome companions; no current authority is issued."""
from dataclasses import dataclass
import json

from ..graph_types import AtomKey, GraphWrite, TypeSpec
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize, schema_hash
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import ActionOutcome, _decode_intent
from ..domains.d08.production_operations_v1 import observed_action_outcome_key_v1
from .d11_life_graph_types_v1 import life_role_segment_key_v1
from .d11_life_contract_v1 import life_adoption_operation_id_v1
from .d11_life_fact_provenance_v1 import (
    LifeFactProvenanceV1, PROVENANCE_TYPE as END_PROVENANCE_TYPE,
    ELIGIBILITY_TYPE as END_ELIGIBILITY_TYPE, life_fact_auxiliary_key_v1,
    life_current_fact_reads_v1, life_fact_provenance_v1, _digest,
)

OUTCOME_TYPE='d08.action_outcome.v1'
PROVENANCE_TYPE='d11.life_outcome_provenance.v1'
ELIGIBILITY_TYPE='d11.life_outcome_eligibility.v1'


def life_outcome_key_v1(binding,action_ref):
    action=AtomKey.from_token(action_ref)
    if (action.type_name!='d08.action_intent.v1' or NamespaceId.from_key(action)!=binding.namespace
            or action.owner.kind!='activity' or action.owner.subject!=binding.activity_id):
        raise ValueError('Life outcome actual Action scope differs')
    return AtomKey(action.owner,OUTCOME_TYPE,'outcome:'+canonical_digest(
        (action.owner,action.name,binding.effect_id,binding.attempt_id))[:48])


def life_outcome_auxiliary_key_v1(fact,kind):
    if fact.type_name!=OUTCOME_TYPE or kind not in {PROVENANCE_TYPE,ELIGIBILITY_TYPE}:
        raise ValueError('Life outcome companion family differs')
    return AtomKey(fact.owner,kind,'life-outcome:'+canonical_digest((kind,fact.token)))


def life_outcome_read_keys_v1(binding,action_ref):
    fact=life_outcome_key_v1(binding,action_ref)
    return (fact,*(life_outcome_auxiliary_key_v1(fact,kind) for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE)))


@dataclass(frozen=True,slots=True)
class LifeOutcomeProvenanceV1:
    fact_ref: str
    fact_revision: int
    fact_digest: str
    action_ref: str
    action_revision: int
    action_digest: str
    terminal_provenance_ref: str
    terminal_provenance_revision: int
    terminal_provenance_digest: str
    terminal_provenance: LifeFactProvenanceV1
    schema: str=PROVENANCE_TYPE

    def __post_init__(self):
        proof=self.terminal_provenance
        if type(proof) is not LifeFactProvenanceV1:raise ValueError('Life outcome lacks its actual typed terminal provenance')
        end=life_role_segment_key_v1(proof.binding,'end')
        if (self.schema!=PROVENANCE_TYPE or self.fact_ref!=life_outcome_key_v1(proof.binding,self.action_ref).token
                or type(self.fact_revision) is not int or self.fact_revision!=1
                or type(self.action_revision) is not int or self.action_revision<1
                or proof.fact_ref!=end.token or self.terminal_provenance_ref!=life_fact_auxiliary_key_v1(end,END_PROVENANCE_TYPE).token
                or type(self.terminal_provenance_revision) is not int or self.terminal_provenance_revision!=1
                or self.terminal_provenance_digest!=canonical_digest(plain_v1(proof))
                or not any((row.ref,row.revision,row.value_digest,row.valid)==
                    (self.action_ref,self.action_revision,self.action_digest,True) for row in proof.reads)):
            raise ValueError('Life outcome fact/Action/end provenance identity differs')
        _digest(self.fact_digest);_digest(self.action_digest)


@dataclass(frozen=True,slots=True)
class LifeOutcomeEligibilityV1:
    fact_ref: str
    fact_revision: int
    fact_digest: str
    provenance_ref: str
    provenance_revision: int
    provenance_digest: str
    terminal_eligibility_ref: str
    producing_operation_id: str
    schema: str=ELIGIBILITY_TYPE

    def __post_init__(self):
        fact=AtomKey.from_token(self.fact_ref);end=AtomKey.from_token(self.terminal_eligibility_ref)
        if (self.schema!=ELIGIBILITY_TYPE or fact.type_name!=OUTCOME_TYPE
                or self.provenance_ref!=life_outcome_auxiliary_key_v1(fact,PROVENANCE_TYPE).token
                or end.type_name!=END_ELIGIBILITY_TYPE or end.owner!=fact.owner
                or type(self.fact_revision) is not int or self.fact_revision!=1
                or type(self.provenance_revision) is not int or self.provenance_revision!=1
                or type(self.producing_operation_id) is not str or not self.producing_operation_id.startswith('d11-life-adopt:')):
            raise ValueError('Life outcome eligibility scope differs')
        _digest(self.fact_digest);_digest(self.provenance_digest)


def decode_life_outcome_auxiliary_v1(kind,value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    cls={PROVENANCE_TYPE:LifeOutcomeProvenanceV1,ELIGIBILITY_TYPE:LifeOutcomeEligibilityV1}.get(kind)
    if cls is None:raise ValueError('unknown Life outcome companion family')
    return decode_typed_production_value_v1(value,cls)


def life_outcome_type_specs_v1():
    return tuple(TypeSpec(kind,('activity',),'state' if kind==PROVENANCE_TYPE else 'projection',
        lambda value,kind=kind:decode_life_outcome_auxiliary_v1(kind,value),immutable=kind==PROVENANCE_TYPE,
        schema_version=1,writer_domain='d11',schema_hash=schema_hash({'type':kind,'version':1,
            'closed_fields':tuple(cls.__dataclass_fields__)}))
        for kind,cls in ((PROVENANCE_TYPE,LifeOutcomeProvenanceV1),(ELIGIBILITY_TYPE,LifeOutcomeEligibilityV1)))


def life_outcome_fact_v1(prepared,terminal):
    b=prepared.binding;ref=prepared.plan.action_intent
    row=next((row for row in prepared.read_rows if row.ref==ref.ref),None)
    if row is None or (row.revision,canonical_digest(json.loads(row.value_json)),row.valid)!=(ref.revision,ref.digest,True):
        raise ValueError('Life outcome lacks its actual prepared Action revision/digest')
    action=_decode_intent(json.loads(row.value_json));key=AtomKey.from_token(ref.ref)
    if ((action.identity.activity_id,action.identity.effect_id,action.identity.attempt_id,action.identity.operation_id)!=
            (b.activity_id,b.effect_id,b.attempt_id,b.operation_id) or key.name!=action.action_id
            or terminal.binding!=b or terminal.payload.prepared_digest!=prepared.digest):
        raise ValueError('Life outcome actual Action/terminal identity differs')
    outcome_key=observed_action_outcome_key_v1(key,action)
    if outcome_key!=life_outcome_key_v1(b,ref.ref):raise ValueError('Life outcome key differs from its actual D08 producer')
    from .d11_offline_originals_v1 import _utc
    outcome=ActionOutcome(outcome_key.name,action.action_id,b.effect_id,b.attempt_id,
        {'completed':'completed_verified','failed':'failed_verified','unknown':'unknown'}[terminal.status],
        'installed_artifact_readback' if terminal.status=='completed' else 'actual_execution_terminal',
        (terminal.original_ref,),(b.effect_id,) if terminal.status=='completed' else (),
        (b.effect_id,) if terminal.status=='unknown' else (),'life-settlement:'+canonical_digest((b.namespace,b.effect_id)),
        _utc(terminal.payload.completed_at_utc).timestamp())
    return GraphWrite(outcome_key,plain_v1(outcome))


def life_outcome_qualified_writes_v1(prepared,terminal,life_writes):
    fact=life_outcome_fact_v1(prepared,terminal);b=prepared.binding
    end=life_role_segment_key_v1(b,'end')
    end_fact=next(write for write in life_writes if write.key==end)
    end_proof=life_fact_provenance_v1(prepared,terminal.claim,terminal,end_fact)
    end_proof_key=life_fact_auxiliary_key_v1(end,END_PROVENANCE_TYPE)
    proof=LifeOutcomeProvenanceV1(fact.key.token,1,canonical_digest(fact.value),prepared.plan.action_intent.ref,
        prepared.plan.action_intent.revision,prepared.plan.action_intent.digest,end_proof_key.token,1,
        canonical_digest(plain_v1(end_proof)),end_proof)
    proof_key=life_outcome_auxiliary_key_v1(fact.key,PROVENANCE_TYPE)
    end_elig=life_fact_auxiliary_key_v1(end,END_ELIGIBILITY_TYPE)
    eligibility=LifeOutcomeEligibilityV1(fact.key.token,1,proof.fact_digest,proof_key.token,1,
        canonical_digest(plain_v1(proof)),end_elig.token,life_adoption_operation_id_v1(b))
    dependencies=tuple(dict.fromkeys((fact.key,proof_key,end_elig,
        *(AtomKey.from_token(row.ref) for row in life_current_fact_reads_v1(prepared)))))
    return fact,GraphWrite(proof_key,plain_v1(proof)),GraphWrite(
        life_outcome_auxiliary_key_v1(fact.key,ELIGIBILITY_TYPE),plain_v1(eligibility),dependencies)


def require_current_life_outcome_eligibility_v1(db,*,prepared,terminal,adopted,life_writes):
    if adopted['schema']!='d11.adopted-life-original.v4':raise ValueError('legacy Life outcome lacks authenticated current eligibility')
    members={row['ref']:row for row in adopted['write_commitments']}
    writes=life_outcome_qualified_writes_v1(prepared,terminal,life_writes)
    for write in writes:
        if (db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(write.key.token,)).fetchone()!=
                (1,canonical_serialize(write.value),1) or members.get(write.key.token)!=
                {'ref':write.key.token,'revision':1,'digest':canonical_digest(write.value)}):
            raise ValueError('Life current outcome/provenance/eligibility differs from signed actual members')
    end_elig=AtomKey.from_token(writes[2].value['terminal_eligibility_ref'])
    if db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(end_elig.token,)).fetchone()!=(1,1):
        raise ValueError('Life current outcome terminal eligibility is missing or invalidated')
    expected=tuple(sorted((key.token,1 if key in (writes[0].key,writes[1].key,end_elig) else
        next(row.revision for row in life_current_fact_reads_v1(prepared) if row.ref==key.token)) for key in writes[2].dependencies))
    if tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token',
            (writes[2].key.token,)))!=expected:raise ValueError('Life outcome current invalidation edges differ')
    return writes[0].key


def validate_life_outcome_provenance_history_v1(db,*,prepared,terminal,adopted,receipt,members,life_writes):
    writes=life_outcome_qualified_writes_v1(prepared,terminal,life_writes)
    for write in writes:
        if canonical_serialize(members.get(write.key.token))!=canonical_serialize(write.value):
            raise ValueError('Life historical outcome differs from actual Action/terminal/provenance originals')
        row=db.execute('SELECT dependencies FROM graph_history WHERE token=? AND revision=1 AND event_id=?',
            (write.key.token,receipt.operation_id)).fetchone()
        expected=tuple(sorted((key.token,1 if key in (writes[0].key,writes[1].key,
            AtomKey.from_token(writes[2].value['terminal_eligibility_ref'])) else
            next(row.revision for row in life_current_fact_reads_v1(prepared) if row.ref==key.token)) for key in write.dependencies))
        if row is None or tuple(sorted(tuple(pair) for pair in json.loads(row[0])))!=expected:
            raise ValueError('Life historical outcome immutable/projection edge ownership differs')
    return writes[0].key
