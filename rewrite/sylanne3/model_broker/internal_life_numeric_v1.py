"""Independent Life appraisal model identity; outputs remain candidates.

This codec grants no execution permission. The installed producer must obtain
the actual current internal context and before-state qualification separately.
The existing D04 appraisal wire/parser are reused without inventing an ingress.
"""
from dataclasses import dataclass

from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d04_appraisal import (
    AppraisalInputV1, AppraisalInstallationV1, FrozenAppraisalRequestV1,
    TEMPLATE_DIGEST as APPRAISAL_TEMPLATE_DIGEST,
    freeze_appraisal_request_v1, thaw_appraisal_request_v1, parse_appraisal_output_v1,
)

WORK_KIND = 'd06.encode_internal_life_numeric'
TEMPLATE_VERSION = 'sylanne.d06.internal_life_numeric.v1'
TEMPLATE_DIGEST = canonical_digest({'version': TEMPLATE_VERSION,
    'appraisal_template': APPRAISAL_TEMPLATE_DIGEST,
    'scope': 'internal_activity_subjective_appraisal_candidate_not_identified_causation'})


def _sha(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Life numeric commitment differs')


@dataclass(frozen=True, slots=True)
class InternalLifeNumericIdentityV1:
    namespace: NamespaceId
    episode_ref: str
    execution_id: str
    source_ref: str
    occurrence_digest: str
    before_digest: str
    context_digest: str
    schema: str = 'd06.internal-life-numeric-identity.v1'

    def __post_init__(self):
        from ..graph_types import AtomKey
        if type(self.namespace) is not NamespaceId or self.schema != 'd06.internal-life-numeric-identity.v1':
            raise ValueError('Life numeric identity namespace/schema differs')
        for ref, kind in ((self.episode_ref, 'memory.episode.v2'), (self.source_ref, 'memory.source')):
            key = AtomKey.from_token(ref)
            if key.type_name != kind or NamespaceId.from_key(key) != self.namespace:
                raise ValueError('Life numeric identity Source/Episode differs')
        if type(self.execution_id) is not str or not 1 <= len(self.execution_id) <= 512:
            raise ValueError('Life numeric execution identity differs')
        for value in (self.occurrence_digest, self.before_digest, self.context_digest):
            _sha(value)

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def internal_life_numeric_ids_v1(identity):
    if type(identity) is not InternalLifeNumericIdentityV1:
        raise TypeError('Life numeric once identity requires its closed input')
    suffix = identity.digest[:48]
    return {name: 'life-numeric-' + name + ':' + suffix for name in
        ('prepare', 'acquire', 'action', 'job', 'call', 'quote', 'snapshot', 'adopt')}


@dataclass(frozen=True, slots=True)
class FrozenInternalLifeNumericRequestV1:
    identity: InternalLifeNumericIdentityV1
    appraisal: FrozenAppraisalRequestV1
    template_version: str = TEMPLATE_VERSION
    template_digest: str = TEMPLATE_DIGEST
    work_kind: str = WORK_KIND
    assertion_scope: str = 'subjective_appraisal_candidate_not_identified_causation'

    def __post_init__(self):
        if (type(self.identity) is not InternalLifeNumericIdentityV1
                or type(self.appraisal) is not FrozenAppraisalRequestV1
                or self.template_version != TEMPLATE_VERSION or self.template_digest != TEMPLATE_DIGEST
                or self.work_kind != WORK_KIND
                or self.assertion_scope != 'subjective_appraisal_candidate_not_identified_causation'):
            raise ValueError('Life numeric frozen version/scope differs')
        app = self.appraisal
        if (freeze_appraisal_request_v1(app.input, app.installation) != app
                or app.input.namespace != self.identity.namespace
                or tuple(item.source_ref.ref for item in app.input.sources) != (self.identity.source_ref,)
                or app.input.sources[0].record.source_kind != 'internal'
                or app.input.source_qualification.source_family != 'derived'):
            raise ValueError('Life numeric appraisal is not its exact internal Source')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def canonical_wire(self):
        return self.appraisal.canonical_wire


def freeze_internal_life_numeric_request_v1(identity, input, installation):
    if type(input) is not AppraisalInputV1 or type(installation) is not AppraisalInstallationV1:
        raise TypeError('Life numeric requires the existing typed appraisal input/installation')
    return FrozenInternalLifeNumericRequestV1(identity, freeze_appraisal_request_v1(input, installation))


def thaw_internal_life_numeric_request_v1(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw) is not dict or set(raw) != set(FrozenInternalLifeNumericRequestV1.__dataclass_fields__):
        raise ValueError('Life numeric frozen wire fields differ')
    identity = decode_typed_production_value_v1(raw['identity'], InternalLifeNumericIdentityV1)
    result = FrozenInternalLifeNumericRequestV1(identity, thaw_appraisal_request_v1(raw['appraisal']))
    if canonical_serialize(plain_v1(result)) != canonical_serialize(raw):
        raise ValueError('Life numeric frozen wire is not canonical')
    return result


def parse_internal_life_numeric_candidate_v1(text, frozen):
    if type(frozen) is not FrozenInternalLifeNumericRequestV1:
        raise TypeError('Life numeric parser requires its frozen original')
    return parse_appraisal_output_v1(text, frozen.appraisal)
