"""Engineering-only candidate manifest construction; never a runtime component."""
from sylanne3.host.package_qualification_v1 import (
    QUALIFICATION_SCHEMA, ALPHA2_QUALIFICATION_SCHEMA, ALPHA2_RUNTIME_SCOPE,
    ALPHA2_UNMET_GATES, BETA1_QUALIFICATION_SCHEMA, BETA1_RUNTIME_SCOPE,
    BETA1_UNMET_GATES,
)


def qualify_test_snapshot_v1(candidate):
    value=dict(candidate)
    value.update(schema=QUALIFICATION_SCHEMA,status='alpha1_test_snapshot',product_status='test_snapshot')
    return value


def qualify_alpha2_candidate_v1(candidate):
    value = dict(candidate)
    value.update(schema=ALPHA2_QUALIFICATION_SCHEMA, status='alpha2_candidate',
        product_status='candidate_only', runtime_scope=ALPHA2_RUNTIME_SCOPE,
        unmet_product_gates=list(ALPHA2_UNMET_GATES))
    return value


def qualify_beta1_candidate_v1(candidate):
    value = dict(candidate)
    value.update(schema=BETA1_QUALIFICATION_SCHEMA, status='beta1_candidate',
        product_status='candidate_only', runtime_scope=BETA1_RUNTIME_SCOPE,
        unmet_product_gates=list(BETA1_UNMET_GATES))
    return value
