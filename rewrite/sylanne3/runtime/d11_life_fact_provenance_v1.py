"""Immutable Life provenance and mutable current eligibility, issued together.

Historical fact/type bytes remain V1. Invalidating edges belong exclusively
to eligibility. Provenance is a typed deletion/verification commitment, not a
permission source; installed consumers must authenticate the signed prepared
and adopted originals and independently recheck current Source/Owner rights.
"""

from .d11_life_contract_v1 import LIFE_BINDING_TYPES, LIFE_CLAIM_TYPES, LIFE_TERMINAL_TYPES
from dataclasses import dataclass
import json

from ..graph_types import AtomKey, GraphWrite, TypeSpec
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize, schema_hash
from .d11_life_contract_v1 import D11LifeExecutionBindingV1, life_adoption_operation_id_v1
from .d11_life_preparation_v1 import life_read_digest_v1

PROVENANCE_TYPE='d11.life_fact_provenance.v1'
ELIGIBILITY_TYPE='d11.life_fact_eligibility.v1'
FACT_TYPES=frozenset({'d11.life_artifact.v1','d11.role_segment_start.v1','d11.role_segment_end.v1','d11.draft_artifact.v1','d11.draft_segment_start.v1','d11.draft_segment_end.v1'})


def _digest(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Life fact provenance digest differs')


@dataclass(frozen=True,slots=True)
class LifeFactReadCommitmentV1:
    ref: str
    revision: int
    value_digest: str
    valid: bool

    def __post_init__(self):
        AtomKey.from_token(self.ref);_digest(self.value_digest)
        if (type(self.revision) is not int or self.revision<0 or type(self.valid) is not bool
                or self.revision==0 and self.valid):
            raise ValueError('Life provenance read version/type differs')


@dataclass(frozen=True,slots=True)
class LifeFactProvenanceV1:
    binding: D11LifeExecutionBindingV1
    fact_ref: str
    fact_revision: int
    fact_digest: str
    producing_operation_id: str
    prepared_digest: str
    claim_original_ref: str
    claim_digest: str
    terminal_original_ref: str
    terminal_digest: str
    reads: tuple[LifeFactReadCommitmentV1,...]
    source_family_refs: tuple[str,...]
    schema: str=PROVENANCE_TYPE

    def __post_init__(self):
        b=self.binding;key=AtomKey.from_token(self.fact_ref)
        if (type(b) not in LIFE_BINDING_TYPES or self.schema!=PROVENANCE_TYPE
                or key.type_name not in FACT_TYPES or NamespaceId.from_key(key)!=b.namespace
                or type(self.fact_revision) is not int or self.fact_revision!=1
                or self.producing_operation_id!=life_adoption_operation_id_v1(b)
                or type(self.reads) is not tuple or not 1<=len(self.reads)<=1024
                or any(type(row) is not LifeFactReadCommitmentV1 for row in self.reads)
                or tuple(sorted(self.reads,key=lambda row:row.ref))!=self.reads
                or len({row.ref for row in self.reads})!=len(self.reads)
                or any(NamespaceId.from_key(AtomKey.from_token(row.ref))!=b.namespace for row in self.reads)):
            raise ValueError('Life provenance closed fact/read scope differs')
        for value in (self.fact_digest,self.prepared_digest):_digest(value)
        from .d11_life_graph_types_v1 import life_role_segment_key_v1
        exact=(AtomKey.from_token(b.artifact_ref) if key.type_name in {'d11.life_artifact.v1','d11.draft_artifact.v1'}
            else life_role_segment_key_v1(b,'start' if key.type_name in {'d11.role_segment_start.v1','d11.draft_segment_start.v1'} else 'end'))
        if key!=exact:raise ValueError('Life provenance fact key is not its actual bound original')
        for value in (self.claim_digest,self.terminal_digest):
            if type(value) is not str or not value.startswith('sha256:'):raise ValueError('Life provenance journal digest differs')
            _digest(value[7:])
        from .d11_life_contract_v1 import life_mutation_id_v1
        if (self.claim_original_ref!=life_mutation_id_v1(b,'claim')
                or self.terminal_original_ref!=life_mutation_id_v1(b,'terminal')):
            raise ValueError('Life provenance actual execution originals differ')
        actual=tuple(row.ref for row in self.reads if AtomKey.from_token(row.ref).type_name=='memory.source')
        if not actual or self.source_family_refs!=actual:
            raise ValueError('Life provenance complete Source inventory differs')


@dataclass(frozen=True,slots=True)
class LifeFactEligibilityV1:
    fact_ref: str
    fact_revision: int
    fact_digest: str
    provenance_ref: str
    provenance_revision: int
    provenance_digest: str
    producing_operation_id: str
    schema: str=ELIGIBILITY_TYPE

    def __post_init__(self):
        fact,proof=AtomKey.from_token(self.fact_ref),AtomKey.from_token(self.provenance_ref)
        if (self.schema!=ELIGIBILITY_TYPE or fact.type_name not in FACT_TYPES
                or proof!=life_fact_auxiliary_key_v1(fact,PROVENANCE_TYPE)
                or type(self.fact_revision) is not int or self.fact_revision!=1
                or type(self.provenance_revision) is not int or self.provenance_revision!=1
                or type(self.producing_operation_id) is not str or not self.producing_operation_id.startswith('d11-life-adopt:')):
            raise ValueError('Life eligibility fact/provenance identity differs')
        _digest(self.fact_digest);_digest(self.provenance_digest)


def life_fact_auxiliary_key_v1(fact,kind):
    if fact.type_name not in FACT_TYPES or kind not in {PROVENANCE_TYPE,ELIGIBILITY_TYPE}:
        raise ValueError('Life auxiliary key family differs')
    return AtomKey(fact.owner,kind,'life-fact:'+canonical_digest((kind,fact.token)))


def decode_life_fact_auxiliary_v1(kind,value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    cls=LifeFactProvenanceV1 if kind==PROVENANCE_TYPE else LifeFactEligibilityV1 if kind==ELIGIBILITY_TYPE else None
    if cls is None:raise ValueError('unknown Life auxiliary fact family')
    return decode_typed_production_value_v1(value,cls)


def life_fact_auxiliary_type_specs_v1():
    return tuple(TypeSpec(kind,('activity',),'state' if kind==PROVENANCE_TYPE else 'projection',
        lambda value,kind=kind:decode_life_fact_auxiliary_v1(kind,value),immutable=kind==PROVENANCE_TYPE,
        schema_version=1,writer_domain='d11',schema_hash=schema_hash({'type':kind,'version':1,
            'closed_fields':tuple((LifeFactProvenanceV1 if kind==PROVENANCE_TYPE else LifeFactEligibilityV1).__dataclass_fields__)}))
        for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE))


def life_fact_provenance_v1(prepared,claim,terminal,fact):
    from .d11_life_preparation_v1 import life_read_digest_v1
    rows=tuple(sorted((LifeFactReadCommitmentV1(row.ref,row.revision,
        life_read_digest_v1(row),row.valid) for row in prepared.read_rows),key=lambda row:row.ref))
    return LifeFactProvenanceV1(prepared.binding,fact.key.token,1,canonical_digest(fact.value),
        life_adoption_operation_id_v1(prepared.binding),prepared.digest,claim.original_ref,claim.claim_digest,
        terminal.original_ref,terminal.terminal_digest,rows,
        tuple(row.ref for row in rows if AtomKey.from_token(row.ref).type_name=='memory.source'))


# Complete historical reads remain in the immutable proof. Only actual current
# source/permission/plan inputs are invalidating eligibility dependencies.
CURRENT_PERMISSION_TYPES=frozenset({'d01.persona_activation.v1','d01.persona_plan.v1',
    'd03.self_identity_mapping.v1','d03.entity_anchor','d03.role_binding',
    'd05.boundary_rule','d12.active_scheme_head.v1'})
SOURCE_FAMILY_TYPES=frozenset({'memory.source','memory.access','d06.source_correction_head.v1'})


def life_current_fact_reads_v1(prepared):
    from .d11_life_preparation_v1 import D11DraftPreparedV1
    if type(prepared) is D11DraftPreparedV1:
        from ..graph_types import owner_grant_key
        owner = owner_grant_key(*prepared.binding.namespace.as_tuple).token
        selected = tuple(row for row in prepared.read_rows if row.ref == owner or
            AtomKey.from_token(row.ref).type_name in SOURCE_FAMILY_TYPES | CURRENT_PERMISSION_TYPES)
        if owner not in {row.ref for row in selected}:
            raise ValueError("draft current eligibility lost its actual upstream Owner read")
        return selected
    from ..graph_types import owner_grant_key
    from ..memory_types import SourceRecord, source_key, access_key
    from ..domains.d06 import source_correction_head_key
    rows={row.ref:row for row in prepared.read_rows}
    if len(rows)!=len(prepared.read_rows):raise ValueError('Life prepared current reads contain duplicate refs')
    ns=prepared.binding.namespace
    required={owner_grant_key(*ns.as_tuple).token,*(getattr(prepared.plan,name).ref for name in
        ('project','recipe','action_intent','input_source','input_access'))}
    sources={ref:row for ref,row in rows.items() if AtomKey.from_token(ref).type_name=='memory.source'}
    for ref,row in sources.items():
        source=SourceRecord.from_dict(json.loads(row.value_json))
        if ref!=source_key(*ns.as_tuple,source.source_id).token or row.revision<1 or not row.valid:
            raise ValueError('Life current Source family has no genuine valid original')
        parent_refs={source_key(*ns.as_tuple,parent).token for parent in source.parent_source_ids}
        if not parent_refs<=sources.keys():raise ValueError('Life current Source ancestry is incomplete')
        required.update((access_key(*ns.as_tuple,source.source_id).token,source_correction_head_key(ns,source.source_id).token))
    if not required<=rows.keys():raise ValueError('Life current Source/access/correction/Owner/plan closure is incomplete')
    selected=tuple(row for row in prepared.read_rows if row.ref in required or
        AtomKey.from_token(row.ref).type_name in SOURCE_FAMILY_TYPES|CURRENT_PERMISSION_TYPES)
    for row in selected:
        if NamespaceId.from_key(AtomKey.from_token(row.ref))!=ns:raise ValueError('Life current eligibility scope differs')
    return selected


def life_fact_qualified_writes_v1(prepared,claim,terminal,facts):
    from ..domains.d01.production_operations_v1 import plain_v1
    result=[]
    for fact in facts:
        if fact.dependencies:raise ValueError('immutable Life facts retain invalidating edges')
        proof=life_fact_provenance_v1(prepared,claim,terminal,fact)
        key=life_fact_auxiliary_key_v1(fact.key,PROVENANCE_TYPE)
        eligibility_key=life_fact_auxiliary_key_v1(fact.key,ELIGIBILITY_TYPE)
        eligibility=LifeFactEligibilityV1(fact.key.token,1,proof.fact_digest,key.token,1,
            canonical_digest(plain_v1(proof)),proof.producing_operation_id)
        dependencies=tuple(dict.fromkeys((fact.key,key,*(AtomKey.from_token(row.ref) for row in life_current_fact_reads_v1(prepared)))))
        result.extend((fact,GraphWrite(key,plain_v1(proof)),GraphWrite(eligibility_key,plain_v1(eligibility),dependencies)))
    return tuple(result)


def require_current_life_fact_eligibility_v1(db,*,prepared,terminal,adopted):
    """Signed-original callers join every fact, proof and current projection."""
    from .natural_producer_qualification_v1 import _producer_original_many_v3
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .d11_life_graph_types_v1 import validate_life_graph_value_v1, life_role_segment_key_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    b=prepared.binding
    if terminal.binding!=b or adopted['schema']!='d11.adopted-life-original.v4':
        raise ValueError('legacy Life current use lacks authenticated eligibility provenance')
    facts=[life_role_segment_key_v1(b,'start'),life_role_segment_key_v1(b,'end')]
    if terminal.status=='completed':facts.append(AtomKey.from_token(b.artifact_ref))
    commitments={row['ref']:row for row in adopted['write_commitments']}
    current_reads=life_current_fact_reads_v1(prepared)
    for key in facts:
        row=_producer_original_point_v3(db, table='graph_atoms', columns=('revision', 'value', 'valid'), key_columns=('token',), key=(lambda _producer_params_v3: (_producer_params_v3[0],))((key.token,)), legacy_reader=lambda: db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone())
        if row is None or row[0]!=1 or row[2]!=1 or validate_life_graph_value_v1(key.type_name,json.loads(row[1]))!=b:
            raise ValueError('Life current immutable fact is missing or differs')
        fact=GraphWrite(key,json.loads(row[1]))
        proof=life_fact_provenance_v1(prepared,terminal.claim,terminal,fact)
        proof_key=life_fact_auxiliary_key_v1(key,PROVENANCE_TYPE)
        eligibility_key=life_fact_auxiliary_key_v1(key,ELIGIBILITY_TYPE)
        eligibility=LifeFactEligibilityV1(key.token,1,proof.fact_digest,proof_key.token,1,
            canonical_digest(plain_v1(proof)),proof.producing_operation_id)
        for member,value in ((key,fact.value),(proof_key,plain_v1(proof)),(eligibility_key,plain_v1(eligibility))):
            expected=(1,canonical_serialize(value),1)
            if _producer_original_point_v3(db, table='graph_atoms', columns=('revision', 'value', 'valid'), key_columns=('token',), key=(lambda _producer_params_v3: (_producer_params_v3[0],))((member.token,)), legacy_reader=lambda: db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(member.token,)).fetchone())!=expected:
                raise ValueError('Life current fact/provenance/eligibility is missing, changed or invalidated')
            if commitments.get(member.token)!={'ref':member.token,'revision':1,'digest':canonical_digest(value)}:
                raise ValueError('Life eligibility lacks its exact signed adoption membership')
        expected_dependencies=tuple(sorted({(key.token,1),(proof_key.token,1),
            *((row.ref,row.revision) for row in current_reads)}))
        dependencies=_producer_original_many_v3(db,table='graph_dependencies',columns=('dependency_token', 'dependency_revision'),key_columns=('dependent_token',),key=(eligibility_key.token,),order_column='dependency_token',legacy_reader=lambda: tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies '
            'WHERE dependent_token=? ORDER BY dependency_token',(eligibility_key.token,))))
        if dependencies!=expected_dependencies:
            raise ValueError('Life current eligibility invalidation edges differ or are absent')
        for frozen in current_reads:
            actual=_producer_original_point_v3(db, table='graph_atoms', columns=('revision', 'value', 'valid'), key_columns=('token',), key=(lambda _producer_params_v3: (_producer_params_v3[0],))((frozen.ref,)), legacy_reader=lambda: db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(frozen.ref,)).fetchone())
            if frozen.revision==0 and actual is None:continue
            if (actual is None or actual[0]!=frozen.revision or bool(actual[2])!=frozen.valid
                    or canonical_digest(json.loads(actual[1]))!=life_read_digest_v1(frozen)):
                raise ValueError('Life current Source/Access/Correction/plan ancestor changed or deleted')
    from .d11_life_outcome_provenance_v1 import require_current_life_outcome_eligibility_v1
    life_writes=tuple(GraphWrite(key,json.loads(_producer_original_point_v3(db, table='graph_atoms', columns=('value',), key_columns=('token',), key=(lambda _producer_params_v3: (_producer_params_v3[0],))((key.token,)), legacy_reader=lambda: db.execute('SELECT value FROM graph_atoms WHERE token=?',(key.token,)).fetchone())[0])) for key in facts)
    outcome=require_current_life_outcome_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=adopted,life_writes=life_writes)
    return (*facts,outcome)


def validate_life_fact_provenance_history_v1(db,*,terminal,adopted,receipt,members):
    """Authenticate the closed immutable history join, without current rights."""
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .d11_life_graph_types_v1 import life_role_segment_key_v1
    from .d11_life_contract_v1 import life_to_wire_v1
    b=terminal.binding
    from .d11_life_preparation_v1 import TABLE, life_prepared_from_wire_v1
    row=_producer_original_point_v3(db, table='graph_d11_life_originals_v1', columns=('payload_json', 'payload_digest', 'producing_operation_id'), key_columns=('bot', 'persona', 'kind', 'original_ref'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],'prepared',_producer_params_v3[2]))((*b.namespace.as_tuple, b.prepared_original_ref)), legacy_reader=lambda: db.execute('SELECT payload_json,payload_digest,producing_operation_id FROM '+TABLE+
        " WHERE bot=? AND persona=? AND kind='prepared' AND original_ref=?",
        (*b.namespace.as_tuple,b.prepared_original_ref)).fetchone())
    if row is None:raise ValueError('Life historical provenance lacks its actual prepared original')
    raw=json.loads(row[0]);prepared=life_prepared_from_wire_v1(raw)
    if (canonical_serialize(raw)!=row[0] or prepared.digest!=row[1] or row[1]!=adopted['prepared_digest']
            or prepared.binding!=b or row[2]!=b.prepare_operation_id):
        raise ValueError('Life historical provenance actual prepared bytes/digest/scope differs')
    keys=[life_role_segment_key_v1(b,'start'),life_role_segment_key_v1(b,'end')]
    if terminal.status=='completed':keys.append(AtomKey.from_token(b.artifact_ref))
    reads={row.key.token:row.revision for row in receipt.read_versions}
    for fact_key in keys:
        fact=members.get(fact_key.token)
        proof_key=life_fact_auxiliary_key_v1(fact_key,PROVENANCE_TYPE)
        eligibility_key=life_fact_auxiliary_key_v1(fact_key,ELIGIBILITY_TYPE)
        if fact is None or proof_key.token not in members or eligibility_key.token not in members:
            raise ValueError('Life v3 historical fact/provenance/eligibility membership is incomplete')
        proof=decode_life_fact_auxiliary_v1(PROVENANCE_TYPE,members[proof_key.token])
        eligibility=decode_life_fact_auxiliary_v1(ELIGIBILITY_TYPE,members[eligibility_key.token])
        if (proof.binding!=b or proof.fact_ref!=fact_key.token or proof.fact_digest!=canonical_digest(fact)
                or proof.prepared_digest!=adopted['prepared_digest'] or proof.claim_original_ref!=terminal.claim.original_ref
                or proof.claim_digest!=terminal.claim.claim_digest or proof.terminal_original_ref!=terminal.original_ref
                or proof.terminal_digest!=terminal.terminal_digest or proof.producing_operation_id!=receipt.operation_id
                or eligibility.fact_ref!=fact_key.token or eligibility.fact_digest!=proof.fact_digest
                or eligibility.provenance_digest!=canonical_digest(members[proof_key.token])
                or eligibility.producing_operation_id!=receipt.operation_id
                or any(reads.get(row.ref)!=row.revision for row in proof.reads)):
            raise ValueError('Life historical provenance crossed actual originals/read-set identity')
        expected_proof=life_fact_provenance_v1(prepared,terminal.claim,terminal,GraphWrite(fact_key,fact))
        from ..domains.d01.production_operations_v1 import plain_v1
        if canonical_serialize(members[proof_key.token])!=canonical_serialize(plain_v1(expected_proof)):
            raise ValueError('Life historical provenance complete prepared read-set differs')
        for frozen in prepared.read_rows:
            original=_producer_original_point_v3(db, table='graph_history', columns=('value', 'valid'), key_columns=('token', 'revision'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1]))((frozen.ref, frozen.revision)), legacy_reader=lambda: db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
                (frozen.ref,frozen.revision)).fetchone())
            if frozen.revision==0 and original is None:continue
            if (original is None or original[1] != int(frozen.valid)
                    or canonical_digest(json.loads(original[0])) != life_read_digest_v1(frozen)):
                raise ValueError('Life historical Source/Access/Correction/plan revision bytes differ')
        if fact_key.type_name not in {'d11.life_artifact.v1','d11.draft_artifact.v1'}:
            original=terminal.claim if fact_key.type_name in {'d11.role_segment_start.v1','d11.draft_segment_start.v1'} else terminal
            expected={'schema':fact_key.type_name,'binding':life_to_wire_v1(b),'payload':life_to_wire_v1(original.payload),
                'journal_ref':original.original_ref,'journal_digest':original.claim_digest if original is terminal.claim else original.terminal_digest}
            if canonical_serialize(fact)!=canonical_serialize(expected):
                raise ValueError('Life historical role fact differs from its actual journal original')
        expected_dependencies=tuple(sorted({(fact_key.token,1),(proof_key.token,1),
            *((row.ref,row.revision) for row in life_current_fact_reads_v1(prepared))}))
        for key,expected in ((fact_key,()),(proof_key,()),(eligibility_key,expected_dependencies)):
            row=_producer_original_point_v3(db, table='graph_history', columns=('dependencies',), key_columns=('token', 'revision', 'event_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],1,_producer_params_v3[1]))((key.token, receipt.operation_id)), legacy_reader=lambda: db.execute('SELECT dependencies FROM graph_history WHERE token=? AND revision=1 AND event_id=?',
                (key.token,receipt.operation_id)).fetchone())
            dependencies=None if row is None else json.loads(row[0])
            if (type(dependencies) is not list or len(dependencies)!=len(expected)
                    or tuple(sorted(tuple(item) for item in dependencies))!=expected):
                raise ValueError('Life historical immutable/eligibility edge ownership differs')
    if adopted['schema']=='d11.adopted-life-original.v4':
        from .d11_life_outcome_provenance_v1 import validate_life_outcome_provenance_history_v1
        outcome=validate_life_outcome_provenance_history_v1(db,prepared=prepared,terminal=terminal,adopted=adopted,receipt=receipt,
            members=members,life_writes=tuple(GraphWrite(key,members[key.token]) for key in keys))
        keys.append(outcome)
    return tuple(keys)
