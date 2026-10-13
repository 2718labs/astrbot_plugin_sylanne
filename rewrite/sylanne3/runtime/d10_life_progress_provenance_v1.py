"""Immutable Life progress and its independently invalidating eligibility.

The original progress schema is unchanged. These finite companions bind the
actual Life terminal proof; their decoding never grants current permission.
"""
from dataclasses import dataclass
import json

from ..graph_types import AtomKey,GraphWrite,Owner,TypeSpec
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize,schema_hash
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
from .d11_life_fact_provenance_v1 import (
    LifeFactProvenanceV1,life_fact_auxiliary_key_v1,life_current_fact_reads_v1,
    life_fact_provenance_v1,ELIGIBILITY_TYPE as END_ELIGIBILITY,PROVENANCE_TYPE as END_PROOF,_digest,
)
from .d11_life_graph_types_v1 import life_role_segment_key_v1

PROVENANCE_TYPE='d10.life_progress_provenance.v1'
ELIGIBILITY_TYPE='d10.life_progress_eligibility.v1'


def life_progress_key_v1(binding):
    return AtomKey(Owner('activity',*binding.namespace.as_tuple,binding.activity_id),'d10.life_progress.v1',binding.effect_id)


def life_progress_auxiliary_key_v1(fact,kind):
    if fact.type_name!='d10.life_progress.v1' or kind not in {PROVENANCE_TYPE,ELIGIBILITY_TYPE}:
        raise ValueError('Life progress companion family differs')
    return AtomKey(fact.owner,kind,'life-progress:'+canonical_digest((kind,fact.token)))


def life_progress_read_keys_v1(binding):
    fact=life_progress_key_v1(binding)
    return (fact,*(life_progress_auxiliary_key_v1(fact,kind) for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE)))


@dataclass(frozen=True,slots=True)
class LifeProgressProvenanceV1:
    fact_ref:str
    fact_revision:int
    fact_digest:str
    producing_operation_id:str
    terminal_provenance_ref:str
    terminal_provenance_digest:str
    terminal_provenance:LifeFactProvenanceV1
    schema:str=PROVENANCE_TYPE

    def __post_init__(self):
        p=self.terminal_provenance
        if type(p) is not LifeFactProvenanceV1:raise ValueError('Life progress lacks actual typed terminal provenance')
        end=life_role_segment_key_v1(p.binding,'end')
        if (self.schema!=PROVENANCE_TYPE or self.fact_ref!=life_progress_key_v1(p.binding).token
                or type(self.fact_revision) is not int or self.fact_revision!=1
                or type(self.producing_operation_id) is not str or not self.producing_operation_id
                or p.fact_ref!=end.token or self.terminal_provenance_ref!=life_fact_auxiliary_key_v1(end,END_PROOF).token
                or self.terminal_provenance_digest!=canonical_digest(plain_v1(p))):
            raise ValueError('Life progress exact fact/end proof identity differs')
        _digest(self.fact_digest)


@dataclass(frozen=True,slots=True)
class LifeProgressEligibilityV1:
    fact_ref:str
    fact_revision:int
    fact_digest:str
    provenance_ref:str
    provenance_digest:str
    terminal_eligibility_ref:str
    producing_operation_id:str
    schema:str=ELIGIBILITY_TYPE

    def __post_init__(self):
        fact=AtomKey.from_token(self.fact_ref);end=AtomKey.from_token(self.terminal_eligibility_ref)
        if (self.schema!=ELIGIBILITY_TYPE or type(self.fact_revision) is not int or self.fact_revision!=1
                or self.provenance_ref!=life_progress_auxiliary_key_v1(fact,PROVENANCE_TYPE).token
                or end.type_name!=END_ELIGIBILITY or end.owner!=fact.owner
                or type(self.producing_operation_id) is not str or not self.producing_operation_id):
            raise ValueError('Life progress eligibility scope differs')
        _digest(self.fact_digest);_digest(self.provenance_digest)


def decode_life_progress_auxiliary_v1(kind,value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    cls={PROVENANCE_TYPE:LifeProgressProvenanceV1,ELIGIBILITY_TYPE:LifeProgressEligibilityV1}.get(kind)
    if cls is None:raise ValueError('unknown Life progress companion family')
    return decode_typed_production_value_v1(value,cls)


def life_progress_type_specs_v1():
    return tuple(TypeSpec(kind,('activity',),'state' if kind==PROVENANCE_TYPE else 'projection',
        lambda value,kind=kind:decode_life_progress_auxiliary_v1(kind,value),immutable=kind==PROVENANCE_TYPE,
        writer_domain='d10',schema_version=1,schema_hash=schema_hash({'type':kind,'version':1,
            'closed_fields':tuple(cls.__dataclass_fields__)})) for kind,cls in
        ((PROVENANCE_TYPE,LifeProgressProvenanceV1),(ELIGIBILITY_TYPE,LifeProgressEligibilityV1)))


def life_progress_qualified_writes_v1(prepared,terminal,progress,operation_id):
    from .d11_life_outcome_provenance_v1 import life_outcome_key_v1
    b=prepared.binding
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    roots = tuple(dict.fromkeys((prepared.plan.input_source.ref, *prepared.plan.content.source_refs))) if type(prepared.plan) is RegisteredDraftFilePlanV3 else (prepared.plan.input_source.ref,)
    if (type(progress) is not LifeProgressHeadV1 or terminal.binding!=b or terminal.payload.prepared_digest!=prepared.digest
            or (progress.project_ref,progress.recipe_ref,progress.activity_id,progress.effect_id,progress.artifact_ref,
                progress.terminal_ref,progress.source_refs,progress.receipt_refs,progress.reality,progress.step,
                progress.role_start,progress.role_end)!=
            (prepared.plan.project.ref,prepared.plan.recipe.ref,b.activity_id,b.effect_id,b.artifact_ref,terminal.original_ref,
                roots,(terminal.claim.original_ref,terminal.original_ref,
                    life_outcome_key_v1(b,prepared.plan.action_intent.ref).token),
                'real_execution',prepared.plan.step,float(terminal.claim.payload.character_at),float(terminal.payload.character_at))):
        raise ValueError('Life progress differs from actual prepared plan/terminal/outcome')
    # Provenance derives only the existing terminal fact, without producing
    # another execution/result or reading caller-supplied eligibility flags.
    from .d11_life_contract_v1 import life_to_wire_v1
    end=life_role_segment_key_v1(b,'end')
    end_fact=GraphWrite(end,{'schema':end.type_name,'binding':life_to_wire_v1(b),
        'payload':life_to_wire_v1(terminal.payload),'journal_ref':terminal.original_ref,'journal_digest':terminal.terminal_digest})
    end_proof=life_fact_provenance_v1(prepared,terminal.claim,terminal,end_fact)
    fact=GraphWrite(life_progress_key_v1(b),plain_v1(progress));proof_key=life_progress_auxiliary_key_v1(fact.key,PROVENANCE_TYPE)
    proof=LifeProgressProvenanceV1(fact.key.token,1,canonical_digest(fact.value),operation_id,
        life_fact_auxiliary_key_v1(end,END_PROOF).token,canonical_digest(plain_v1(end_proof)),end_proof)
    end_elig=life_fact_auxiliary_key_v1(end,END_ELIGIBILITY)
    eligibility=LifeProgressEligibilityV1(fact.key.token,1,proof.fact_digest,proof_key.token,
        canonical_digest(plain_v1(proof)),end_elig.token,operation_id)
    deps=tuple(dict.fromkeys((fact.key,proof_key,end_elig,
        *(AtomKey.from_token(row.ref) for row in life_current_fact_reads_v1(prepared)))))
    return fact,GraphWrite(proof_key,plain_v1(proof)),GraphWrite(
        life_progress_auxiliary_key_v1(fact.key,ELIGIBILITY_TYPE),plain_v1(eligibility),deps)


def life_experience_access_dependencies_v1(prepared,source):
    return tuple(dict.fromkeys((source,life_fact_auxiliary_key_v1(
        life_role_segment_key_v1(prepared.binding,'end'),END_ELIGIBILITY),
        *(AtomKey.from_token(row.ref) for row in life_current_fact_reads_v1(prepared)))))


def validate_life_progress_provenance_history_v1(db,*,prepared,terminal,progress,production):
    """Exact historical SQL joins, independent of current revocation/validity."""
    operation=production['receipt'].operation_id;ns=prepared.binding.namespace
    writes=life_progress_qualified_writes_v1(prepared,terminal,progress,operation)
    if (production['domain']!='d10' or production['operation_kind']!='advance_life'
            or canonical_serialize(production['payload']['writes'])!=canonical_serialize(plain_v1(writes))
            or canonical_serialize(production['payload']['provenance']['actual_progress'])!=canonical_serialize(plain_v1(progress))):
        raise ValueError('Life historical progress differs from its actual production payload')
    versions={v.key:v.revision for v in production['receipt'].write_versions}
    proof=writes[1].value
    from .d11_life_contract_v1 import life_adoption_operation_id_v1
    end=db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1',
        (proof['terminal_provenance_ref'],)).fetchone()
    if end!=(canonical_serialize(proof['terminal_provenance']),1,life_adoption_operation_id_v1(prepared.binding)):
        raise ValueError('Life progress lost its actual historical terminal proof')
    current_reads=life_current_fact_reads_v1(prepared)
    produced={writes[0].key,writes[1].key,AtomKey.from_token(writes[2].value['terminal_eligibility_ref'])}
    for write in writes:
        deps=tuple(sorted((key.token,1 if key in produced else next(row.revision for row in current_reads if row.ref==key.token))
            for key in write.dependencies))
        historical=db.execute('SELECT value,valid,event_bot,event_persona,event_id,dependencies FROM graph_history '
            'WHERE token=? AND revision=1',(write.key.token,)).fetchone()
        if (versions.get(write.key)!=1 or historical is None or historical[:5]!=
                (canonical_serialize(write.value),1,*ns.as_tuple,operation)
                or tuple(sorted(tuple(pair) for pair in json.loads(historical[5])))!=deps):
            raise ValueError('Life historical progress member/invalidating edge ownership differs')
    return writes


def life_progress_current_read_inputs_v1(db,namespace,progress_ref):
    """Locate complete reads; these unqualified SQL rows issue no authority."""
    fact=AtomKey.from_token(progress_ref)
    if fact.type_name!='d10.life_progress.v1' or NamespaceId.from_key(fact)!=namespace:
        raise ValueError('Life current progress read scope differs')
    proof_key=life_progress_auxiliary_key_v1(fact,PROVENANCE_TYPE)
    row=db.execute('SELECT value,valid FROM graph_atoms WHERE token=?',(proof_key.token,)).fetchone()
    if row is None or row[1]!=1:raise ValueError('legacy Life progress lacks typed current provenance; HOLD')
    proof=decode_life_progress_auxiliary_v1(PROVENANCE_TYPE,json.loads(row[0]));b=proof.terminal_provenance.binding
    if proof.fact_ref!=progress_ref or b.namespace!=namespace:raise ValueError('Life progress actual proof scope differs')
    from .d11_life_preparation_v1 import TABLE,life_prepared_from_wire_v1
    prepared_row=db.execute('SELECT payload_json FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,'prepared',b.prepared_original_ref)).fetchone()
    if prepared_row is None:raise ValueError('Life progress actual prepared read original is absent')
    prepared=life_prepared_from_wire_v1(json.loads(prepared_row[0]))
    if prepared.binding!=b or prepared.digest!=proof.terminal_provenance.prepared_digest:
        raise ValueError('Life progress typed prepared read scope differs')
    from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
    from .d11_life_contract_v1 import life_mutation_id_v1
    facts=(AtomKey.from_token(b.artifact_ref),life_role_segment_key_v1(b,'start'),life_role_segment_key_v1(b,'end'))
    reads=life_current_fact_reads_v1(prepared)
    keys=(*life_progress_read_keys_v1(b),*facts,*(life_fact_auxiliary_key_v1(fact,kind)
        for fact in facts for kind in (END_PROOF,END_ELIGIBILITY)),*life_outcome_read_keys_v1(b,prepared.plan.action_intent.ref),
        *(AtomKey.from_token(row.ref) for row in reads))
    roots=tuple(row.ref for row in reads if AtomKey.from_token(row.ref).type_name=='memory.source')
    originals=(b.prepared_original_ref,b.plan_original_ref,b.artifact_ref,life_mutation_id_v1(b,'claim'),life_mutation_id_v1(b,'terminal'))
    return tuple(dict.fromkeys(keys)),roots,originals


def require_current_life_progress_v1(db,*,namespace,progress,issuer,read):
    from .d11_life_preparation_v1 import read_prepared_life_v1
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1,life_from_wire_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1
    adopted=read_adopted_life_original_v1(db,namespace=namespace,result_ref=progress.artifact_ref,issuer=issuer)
    if adopted is None:raise ValueError('Life progress lacks its actual signed terminal original')
    terminal=life_from_wire_v1(adopted['terminal'],D11LifeTerminalV1)
    prepared=read_prepared_life_v1(db,binding=terminal.binding,issuer=issuer)
    if prepared is None:raise ValueError('Life progress lacks its actual signed prepared original')
    require_current_life_fact_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=adopted)
    fact=life_progress_key_v1(terminal.binding)
    keys,roots,_=life_progress_current_read_inputs_v1(db,namespace,fact.token)
    read.check(db)
    for key in keys:read.head(db,key,required=False)
    for audience in prepared.plan.audiences:
        for purpose in ('context','consolidation'):read.source_family(db,roots,purpose=purpose,audience=audience)
    row=db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1',(fact.token,)).fetchone()
    if row is None:raise ValueError('Life progress has no actual committed historical fact')
    operation=row[2];production=read_adopted_domain_operation_v1(db,namespace,operation)
    if (production is None or production['domain']!='d10' or production['operation_kind']!='advance_life'
            or canonical_serialize(production['payload']['provenance']['actual_progress'])!=canonical_serialize(plain_v1(progress))):
        raise ValueError('Life progress has no exact actual composite adopted original')
    writes=life_progress_qualified_writes_v1(prepared,terminal,progress,operation)
    validate_life_progress_provenance_history_v1(db,prepared=prepared,terminal=terminal,progress=progress,production=production)
    versions={v.key:v.revision for v in production['receipt'].write_versions}
    for write in writes:
        expected=(1,canonical_serialize(write.value),1)
        if (versions.get(write.key)!=1 or db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',
                (write.key.token,)).fetchone()!=expected or db.execute(
                'SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1',(write.key.token,)).fetchone()!=
                (expected[1],1,operation)):
            raise ValueError('Life current progress/proof/eligibility differs from actual adopted members')
    expected=tuple(sorted((key.token,1 if key in {writes[0].key,writes[1].key,AtomKey.from_token(writes[2].value['terminal_eligibility_ref'])}
        else next(row.revision for row in life_current_fact_reads_v1(prepared) if row.ref==key.token)) for key in writes[2].dependencies))
    if tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token',
            (writes[2].key.token,)))!=expected:raise ValueError('Life progress actual current invalidation edges differ')
    return prepared,terminal,production


def require_life_experience_access_edges_v1(db,*,prepared,source):
    from ..memory_types import access_key
    access=access_key(*prepared.binding.namespace.as_tuple,source.owner.subject)
    deps=life_experience_access_dependencies_v1(prepared,source)
    expected=tuple(sorted((key.token,1 if key in {source,life_fact_auxiliary_key_v1(
        life_role_segment_key_v1(prepared.binding,'end'),END_ELIGIBILITY)} else
        next(row.revision for row in life_current_fact_reads_v1(prepared) if row.ref==key.token)) for key in deps))
    row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(access.token,)).fetchone()
    if (row is None or row[0]!=1 or row[2]!=1 or json.loads(row[1])['status']!='active'
            or tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token',
                (access.token,)))!=expected):
        raise ValueError('Life experience access/current invalidation edges differ')
    return access
