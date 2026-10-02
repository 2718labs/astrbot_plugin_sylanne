"""Real typed Plan2 wire binding at Contact3 provider read boundary.

The read capability is a non-authorizing seam. Reaching the next mandatory
opportunity read is not permission or installed qualification.
"""
from dataclasses import replace
from types import SimpleNamespace
import pytest
from test_contact_plan_v2 import proof as plan_fixture
from sylanne3.domains.d08.contact_plan_v2 import contact_plan_key_v2
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.runtime.contact_qualification_v3 import _plan_policy
from sylanne3.runtime.contact_claim_adoption_v3 import _expected_claim_v3
from sylanne3.runtime_contracts import canonical_digest
from sylanne3.graph_types import GraphVersion

@pytest.mark.parametrize('consumer',[_plan_policy,_expected_claim_v3])
@pytest.mark.parametrize('drift',[None,'digest','revision'])
def test_real_plan2_wire_is_the_content_binding_before_provider_permission(consumer,drift):
    plan=plan_fixture.__wrapped__().plan
    key=contact_plan_key_v2(plan)
    assert canonical_digest(plan)!=canonical_digest(plain_v1(plan))
    content=SimpleNamespace(plan_version=GraphVersion(key,1),plan_digest=canonical_digest(plain_v1(plan)))
    if drift=='digest':content.plan_digest=canonical_digest(plan)
    if drift=='revision':content.plan_version=GraphVersion(key,2)
    class Read:
        def head(self,db,requested,required=True):
            if requested==key:return SimpleNamespace(value=plain_v1(plan),revision=1)
            raise LookupError('next mandatory opportunity input')
        def complete_inventory(self,db,kind):
            raise LookupError('next mandatory policy inventory')
    if drift is None:
        with pytest.raises(LookupError,match='next mandatory'):consumer(None,Read(),content,None,None,1.)
    else:
        with pytest.raises(ValueError,match='plan changed'):consumer(None,Read(),content,None,None,1.)
