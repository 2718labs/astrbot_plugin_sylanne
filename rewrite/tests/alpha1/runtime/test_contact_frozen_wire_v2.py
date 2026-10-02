"""New V2 canonical GraphKey wire; public fixtures do not issue model authority."""
from copy import deepcopy
from dataclasses import replace, asdict
import json

import pytest

from test_contact_plan_v2 import proof, D
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d09.natural_reply import NaturalExpressionPlanV2, QualifiedExpressionUnitV2
from sylanne3.domains.d08.contact_plan_v2 import contact_plan_keys_v2
from sylanne3.model_broker.natural_reply import NaturalReplyInstallationV2
from sylanne3.model_broker.contact_expression_v2 import ContactGenerationInputV2, freeze_contact_model_request_v2
from sylanne3.domains.d09 import ClaimKind
from sylanne3.runtime.contact_model_job_v2 import (
    thaw_contact_request_v2, ContactModelPreparedV2, contact_model_ids_v2,
)
from sylanne3.runtime.c09_contact_originals_v2 import validate_contact_payload_v2
from sylanne3.runtime_contracts import VersionedRef, canonical_digest, canonical_serialize


@pytest.fixture
def frozen(proof):
    p=proof.plan
    unit=QualifiedExpressionUnitV2('basis:fixture',ClaimKind.REPORTED_CLAIM,'fixture report',None,
        (p.source_ref,),(),(),p.audience_id,'expression',10.)
    p=replace(p,qualified_units_digest=canonical_digest((unit,)))
    expression=NaturalExpressionPlanV2(p.namespace,VersionedRef(contact_plan_keys_v2(p)[0].token,1),
        p.source_ref,p.source_ref,p.required_slots,p.allowed_speech_acts,(),(unit,),10.,
        p.activity_id,'final-operation','final-effect',p.scene_id,p.audience_id)
    return freeze_contact_model_request_v2(ContactGenerationInputV2(p,expression,1.,10.),
        NaturalReplyInstallationV2('installation',D,'provider','model',128))


def prepared(frozen):
    p=frozen.input.adopted_plan;ids=contact_model_ids_v2(p,frozen.phase)
    return ContactModelPreparedV2(p.namespace,p.contact_id,frozen.phase,p.activity_id,'installation',
        ids['job'],ids['prepare'],ids['acquire'],ids['call'],D,canonical_serialize(plain_v1(frozen)),
        canonical_digest(plain_v1(frozen)),ids['quote'],1,D,D,'provider-config',D,None,None,None)


def test_new_frozen_wire_keeps_canonical_graph_keys_and_roundtrips_original(frozen):
    raw=plain_v1(frozen)
    assert type(raw['input']['adopted_plan']['qualified_read_versions'][0]['key']) is str
    assert type(asdict(frozen)['input']['adopted_plan']['qualified_read_versions'][0]['key']) is dict
    assert thaw_contact_request_v2(raw)==frozen
    provider=json.loads(frozen.messages[1].content)
    assert provider['scope']==raw['input']['adopted_plan']
    assert provider['expression_plan']==raw['input']['expression_plan']
    validate_contact_payload_v2('prepared',plain_v1(prepared(frozen)))


@pytest.mark.parametrize('change',['dict_key','revision_bool','source_drift','extra_frozen','provider_drift'])
def test_exact_frozen_roundtrip_rejects_altered_wire(frozen,change):
    raw=deepcopy(plain_v1(frozen))
    if change=='dict_key':
        raw['input']['adopted_plan']['qualified_read_versions'][0]['key']=asdict(frozen.input.adopted_plan.qualified_read_versions[0].key)
    elif change=='revision_bool':raw['input']['adopted_plan']['qualified_read_versions'][0]['revision']=True
    elif change=='source_drift':raw['input']['adopted_plan']['cause_original_digest']='b'*64
    elif change=='extra_frozen':raw['caller_permission']=True
    else:raw['messages'][1]['content']='{}'
    with pytest.raises(ValueError):thaw_contact_request_v2(raw)
