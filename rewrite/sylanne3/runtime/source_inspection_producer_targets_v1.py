"""Pure exact D06 output keys for preselection; no reads, stage or permission."""
from ..graph_types import AtomKey
from ..memory_types import source_key, access_key
from ..runtime_contracts import NamespaceId, canonical_digest

SIMPLE_INSPECTION_PRODUCERS_V1 = frozenset({'admit_owner_material_source_v1',
    'adopt_artifact_draft_content', 'adopt_artifact_draft_content_v2',
    'derive_artifact_completion_receipt_v1', 'source-correction'})


def _namespace_v1(namespace):
    if type(namespace) is not NamespaceId:
        raise TypeError('actual typed producer namespace required')


def inspection_producer_target_keys_v1(namespace, operation_kind, request, *, operation_id=None):
    _namespace_v1(namespace)
    if operation_kind == 'admit_owner_material_source_v1':
        from .owner_material_source_v1 import AdmitOwnerMaterialSourceRequestV1, owner_material_source_id_v1
        if type(request) is not AdmitOwnerMaterialSourceRequestV1 or type(operation_id) is not str or not operation_id:
            raise TypeError('Owner material target requires its exact request and original operation ID')
        return (source_key(*namespace.as_tuple, owner_material_source_id_v1(namespace, operation_id)),)
    if operation_kind in {'adopt_artifact_draft_content', 'adopt_artifact_draft_content_v2'}:
        from .d11_artifact_draft_content_v1 import AdoptArtifactDraftContentRequestV1, AdoptArtifactDraftContentRequestV2
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1, artifact_draft_model_ids_v2
        phase = operation_kind == 'adopt_artifact_draft_content_v2'
        expected = AdoptArtifactDraftContentRequestV2 if phase else AdoptArtifactDraftContentRequestV1
        if type(request) is not expected:
            raise TypeError('C4 output target requires its exact registered adoption request')
        current_namespace = request.selector.task.namespace if phase else request.selector.namespace
        if current_namespace != namespace:
            raise ValueError('C4 target selector crossed its actual producer namespace')
        ids = (artifact_draft_model_ids_v2 if phase else artifact_draft_model_ids_v1)(request.selector)
        return (source_key(*namespace.as_tuple, ids['source']),)
    if operation_kind == 'derive_artifact_completion_receipt_v1':
        from .artifact_completion_receipt_v1 import DeriveArtifactCompletionReceiptRequestV1, receipt_ids_v1
        if type(request) is not DeriveArtifactCompletionReceiptRequestV1 or request.selector.task.namespace != namespace:
            raise TypeError('completion target requires the exact selected final-phase request')
        return (source_key(*namespace.as_tuple, receipt_ids_v1(request.selector)['source_id']),)
    if operation_kind == 'source-correction':
        from ..domains.d06 import CorrectionRequest, D06DomainAdapter
        if type(request) is not CorrectionRequest:
            raise TypeError('correction targets require the exact D06 correction request')
        keys = tuple(AtomKey.from_token(ref) for ref in request.target_refs)
        if any(key.type_name != 'memory.interpretation' or NamespaceId.from_key(key) != namespace for key in keys):
            raise ValueError('correction output targets crossed actual interpretation namespace')
        return (D06DomainAdapter(namespace).correction_source_key(request), *keys)
    raise ValueError('producer target keys require a registered exact operation or its explicit original metadata')


def method_measurement_source_identity_from_metadata_v1(namespace, experiment_ref, paired_milestone_digests, treatment_calls):
    _namespace_v1(namespace)
    if (type(paired_milestone_digests) is not tuple or len(paired_milestone_digests) != 2
            or any(type(d) is not str or len(d) != 64 or any(c not in '0123456789abcdef' for c in d)
                for d in paired_milestone_digests)
            or type(treatment_calls) is not tuple or not 1 <= len(treatment_calls) <= 8
            or any(type(call) is not str or not call for call in treatment_calls)
            or tuple(sorted(set(treatment_calls))) != treatment_calls):
        raise ValueError('measurement target needs exact paired original digests and ordered actual treatment call metadata')
    key = AtomKey.from_token(experiment_ref)
    if key.type_name != 'd01.method_experiment_plan.v1' or NamespaceId.from_key(key) != namespace:
        raise ValueError('measurement experiment target crossed the actual namespace')
    family = 'method-billing-family:' + canonical_digest(treatment_calls)
    identity = 'method-measurement:' + canonical_digest((namespace, experiment_ref, paired_milestone_digests, treatment_calls))[:48]
    return family, identity, source_key(*namespace.as_tuple, identity), access_key(*namespace.as_tuple, identity)


def inspection_measurement_target_keys_v1(namespace, request, *, paired_milestone_digests, treatment_calls):
    from .d11_method_observation_v1 import ObserveMethodComparisonRequestV1
    if type(request) is not ObserveMethodComparisonRequestV1:
        raise TypeError('measurement target requires the exact registered request')
    return (method_measurement_source_identity_from_metadata_v1(namespace, request.experiment_ref,
        paired_milestone_digests, treatment_calls)[2],)


def inspection_life_target_keys_v1(namespace, request, *, activity_id, effect_id):
    from ..domains.d10.production_operations_v1 import AdvanceCurrentLifeRequestV1
    from .d10_life_outcome_v2 import life_experience_source_id_from_identity_v3
    _namespace_v1(namespace)
    if (type(request) is not AdvanceCurrentLifeRequestV1
            or NamespaceId.from_key(AtomKey.from_token(request.project_ref)) != namespace
            or type(activity_id) is not str or not activity_id or type(effect_id) is not str or not effect_id):
        raise TypeError('Life target needs its exact request and actual terminal activity/effect metadata')
    return (source_key(*namespace.as_tuple, life_experience_source_id_from_identity_v3(namespace, activity_id, effect_id)),)
