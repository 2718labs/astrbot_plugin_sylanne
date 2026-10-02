"""Actual finite D11 proposal contract, without permission issuance."""
from copy import deepcopy
from dataclasses import replace

import pytest

from test_d11_life_job_result_binding_v1 import case
from sylanne3.graph_types import AtomKey, GraphWrite
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime.d11_life_contract_v1 import life_adoption_operation_id_v1
from sylanne3.runtime.d11_life_graph_types_v1 import life_fact_writes_v1
from sylanne3.runtime.d11_life_companion_writes_v1 import COMPANION_TYPES
from sylanne3.runtime.d11_types import validate_d11_writes


def proposal(case):
    return tuple(write for write in life_fact_writes_v1(case.prepared,case.terminal.claim,case.terminal,
        (case.data,case.terminal.payload.artifact_digest,len(case.data))) if write.key.type_name!='d08.action_outcome.v1')


def validate(case,writes,**changes):
    args=dict(operation_id=life_adoption_operation_id_v1(case.binding),activity_id=case.binding.activity_id,
        effect_id=case.binding.effect_id)
    namespace=changes.pop('namespace',case.binding.namespace);args.update(changes)
    return validate_d11_writes(writes,namespace,**args)


def test_actual_four_companion_families_validate_same_proposal(case):
    writes=proposal(case)
    assert {write.key.type_name for write in writes}&COMPANION_TYPES==COMPANION_TYPES
    assert validate(case,writes)


@pytest.mark.parametrize('changes',[
    {'operation_id':'different-operation'},{'activity_id':'different-activity'},
    {'effect_id':'effect:different'},{'namespace':NamespaceId('other-bot','persona')},
])
def test_actual_companions_reject_wrong_proposal_identity(case,changes):
    with pytest.raises(ValueError):validate(case,proposal(case),**changes)


@pytest.mark.parametrize('family',sorted(COMPANION_TYPES))
def test_actual_companion_write_key_must_be_canonical(case,family):
    writes=tuple(GraphWrite(AtomKey(write.key.owner,family,'different-name'),write.value,write.dependencies)
        if write.key.type_name==family else write for write in proposal(case))
    with pytest.raises(ValueError):validate(case,writes)


@pytest.mark.parametrize('family',[
    'd11.life_fact_provenance.v1','d11.life_fact_eligibility.v1','d11.life_outcome_provenance.v1',
])
def test_missing_same_proposal_proof_or_terminal_eligibility_rejected(case,family):
    writes=list(proposal(case))
    # Missing end members exercises Outcome pairing even when the other two
    # Life proof/eligibility members remain present and individually valid.
    removed=next(write for write in writes if write.key.type_name==family and
        (family=='d11.life_outcome_provenance.v1' or 'role_segment_end' in str(write.value)))
    writes.remove(removed)
    with pytest.raises(ValueError):validate(case,tuple(writes))


def test_changed_fact_bytes_reject_same_proposal_proof(case):
    writes=[]
    for write in proposal(case):
        if write.key.type_name=='d11.life_artifact.v1':
            value=deepcopy(write.value);value['artifact_digest']='c'*64
            write=replace(write,value=value)
        writes.append(write)
    with pytest.raises(ValueError):validate(case,tuple(writes))


def test_unknown_companion_family_remains_rejected(case):
    writes=proposal(case);first=writes[0]
    with pytest.raises(ValueError):validate(case,(*writes,GraphWrite(
        AtomKey(first.key.owner,'d11.caller_provenance.v1','fake'),{})))
