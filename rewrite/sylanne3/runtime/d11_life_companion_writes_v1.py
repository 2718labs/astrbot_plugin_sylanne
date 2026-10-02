"""Finite same-proposal Life companion validation; never issues authority."""
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from .d11_life_fact_provenance_v1 import (
    PROVENANCE_TYPE, ELIGIBILITY_TYPE, decode_life_fact_auxiliary_v1,
    life_fact_auxiliary_key_v1,
)
from .d11_life_outcome_provenance_v1 import (
    PROVENANCE_TYPE as OUTCOME_PROOF, ELIGIBILITY_TYPE as OUTCOME_ELIGIBILITY,
    decode_life_outcome_auxiliary_v1, life_outcome_auxiliary_key_v1,
)

COMPANION_TYPES=frozenset({PROVENANCE_TYPE,ELIGIBILITY_TYPE,OUTCOME_PROOF,OUTCOME_ELIGIBILITY})


def validate_life_companion_writes_v1(writes,namespace,*,operation_id,activity_id,effect_id):
    by_key={write.key:write for write in writes}
    if len(by_key)!=len(writes):raise ValueError('duplicate D11 proposal write key')
    decoded={write.key:(decode_life_fact_auxiliary_v1(write.key.type_name,write.value)
        if write.key.type_name in {PROVENANCE_TYPE,ELIGIBILITY_TYPE}
        else decode_life_outcome_auxiliary_v1(write.key.type_name,write.value))
        for write in writes if write.key.type_name in COMPANION_TYPES}
    for key,value in decoded.items():
        if NamespaceId.from_key(key)!=namespace:raise ValueError('Life companion namespace differs from proposal')
        kind=key.type_name;fact=AtomKey.from_token(value.fact_ref)
        expected=(life_fact_auxiliary_key_v1(fact,kind) if kind in {PROVENANCE_TYPE,ELIGIBILITY_TYPE}
            else life_outcome_auxiliary_key_v1(fact,kind))
        if key!=expected:raise ValueError('Life companion write key differs from its bound original')
        if kind in {PROVENANCE_TYPE,OUTCOME_PROOF}:
            proof=value if kind==PROVENANCE_TYPE else value.terminal_provenance
        else:
            proof_key=AtomKey.from_token(value.provenance_ref)
            paired=decoded.get(proof_key)
            if (paired is None or proof_key.type_name!=(PROVENANCE_TYPE if kind==ELIGIBILITY_TYPE else OUTCOME_PROOF)
                    or canonical_digest(by_key[proof_key].value)!=value.provenance_digest
                    or (paired.fact_ref,paired.fact_revision,paired.fact_digest)!=(value.fact_ref,value.fact_revision,value.fact_digest)):
                raise ValueError('Life eligibility lacks its exact same-proposal provenance')
            proof=paired if kind==ELIGIBILITY_TYPE else paired.terminal_provenance
            if value.producing_operation_id!=proof.producing_operation_id:
                raise ValueError('Life eligibility producing operation differs from provenance')
        b=proof.binding
        if ((b.namespace,b.activity_id,b.effect_id,proof.producing_operation_id)!=
                (namespace,activity_id,effect_id,operation_id)):
            raise ValueError('Life companion binding/producing operation differs from proposal')
        if kind==PROVENANCE_TYPE:
            actual=by_key.get(fact)
            if actual is None or canonical_digest(actual.value)!=value.fact_digest:
                raise ValueError('Life provenance lacks its exact same-proposal fact')
        elif kind==OUTCOME_PROOF:
            end_key=AtomKey.from_token(value.terminal_provenance_ref)
            if (end_key not in decoded or end_key.type_name!=PROVENANCE_TYPE
                    or canonical_digest(by_key[end_key].value)!=value.terminal_provenance_digest
                    or canonical_serialize(by_key[end_key].value)!=canonical_serialize(plain_v1(value.terminal_provenance))):
                raise ValueError('Life outcome lacks its exact same-proposal terminal provenance')
        elif kind==OUTCOME_ELIGIBILITY:
            end_key=AtomKey.from_token(value.terminal_eligibility_ref)
            end=decoded.get(end_key)
            if (end is None or end_key.type_name!=ELIGIBILITY_TYPE
                    or end.fact_ref!=proof.fact_ref or end.provenance_ref!=paired.terminal_provenance_ref
                    or end.provenance_digest!=paired.terminal_provenance_digest):
                raise ValueError('Life outcome lacks its exact same-proposal terminal eligibility')
    return frozenset(decoded)
