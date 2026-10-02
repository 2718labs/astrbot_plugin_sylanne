"""Life content-only model input and candidate, separate from numerical C02.

These public DTOs confer no permission. The installed producer must authenticate
the occurrence, current Source/Owner and actual command before issuing a call.
The candidate records model wording, never a new external event or feeling.
"""
from dataclasses import dataclass
import json
import math

from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.d06_internal_life_encoding_v1 import InternalLifeEncodingCauseV1
from ..runtime.d06_internal_life_episode_v2 import EPISODE, _sha

WORK_KIND = 'd06.encode_internal_life_content'
TEMPLATE_VERSION = 'sylanne.d06.internal_life_content.v1'
OUTPUT_SCHEMA = 'sylanne.d06.internal-life-content-candidate.v1'
SYSTEM = ('Describe only the authenticated internal activity occurrence supplied below. '
    'Return one JSON object with schema, occurrence_digest, summary, and keywords. '
    'schema must be sylanne.d06.internal-life-content-candidate.v1. '
    'Do not assert external events, a before/after comparison, numerical feelings, '
    'or that model wording is an additional occurrence. The before state and '
    'comparison are unavailable; scene and perspective are context only.')
TEMPLATE_DIGEST = canonical_digest({'version': TEMPLATE_VERSION, 'system': SYSTEM,
    'output': OUTPUT_SCHEMA, 'capability': 'content_only'})


def internal_life_content_ids_v1(cause):
    if type(cause) is not InternalLifeEncodingCauseV1:
        raise TypeError('closed authenticated-cause shape required')
    return internal_life_content_ids_for_occurrence_v1(cause.occurrence)


def internal_life_content_ids_for_occurrence_v1(proof):
    from ..runtime.d06_internal_life_episode_v2 import InternalLifeEpisodeProvenanceV2
    if type(proof) is not InternalLifeEpisodeProvenanceV2:
        raise TypeError('closed occurrence shape required for unqualified locators')
    event = proof.event
    # Public operation IDs never enter this once identity. The actual producer
    # will reject a different command op rather than issue another reservation.
    digest = canonical_digest({'schema': 'd06.internal-life-content-once.v1',
        'namespace': event.namespace, 'episode_ref': proof.episode.episode_ref,
        'episode_digest': canonical_digest(plain_v1(proof.episode)),
        'occurrence_digest': canonical_digest(plain_v1(event)),
        'execution_id': event.activity.execution_id,
        'terminal_original_ref': event.activity.terminal_original_ref,
        'd10_causal_operation_id': event.causal_operation_id,
        'd06_producing_operation_id': proof.producing_operation_id})
    return {name: prefix + digest[:48] for name, prefix in (
        ('prepare', 'life-content-prepare:'), ('acquire', 'life-content-acquire:'),
        ('action', 'life-content-action:'), ('job', 'life-content-job:'),
        ('call', 'life-content-call:'), ('quote', 'life-content-quote:'),
        ('snapshot', 'life-content-snapshot:'))}


@dataclass(frozen=True, slots=True)
class InternalLifeContentInputV1:
    cause: InternalLifeEncodingCauseV1
    episode_version: GraphVersion
    self_mapping_version: GraphVersion
    perspective_version: GraphVersion
    audience: str
    frozen_at_utc: float
    expires_at_utc: float
    source_qualification_digest: str
    schema: str = 'd06.internal-life-content-input.v1'

    def __post_init__(self):
        if type(self.cause) is not InternalLifeEncodingCauseV1:
            raise TypeError('Life content requires its closed causal original shape')
        event = self.cause.occurrence.event
        for value, ref, kind in (
            (self.episode_version, self.cause.occurrence.episode.episode_ref, EPISODE),
            (self.self_mapping_version, event.self_mapping_ref, 'd03.self_identity_mapping.v1'),
            (self.perspective_version, event.perspective_ref, 'd03.self_perspective.v1')):
            if (type(value) is not GraphVersion or type(value.revision) is not int
                    or value.revision < 1 or value.key.token != ref
                    or value.key.type_name != kind
                    or NamespaceId.from_key(value.key) != event.namespace):
                raise ValueError('Life content exact occurrence/context Graph versions differ')
        if (self.schema != 'd06.internal-life-content-input.v1'
                or type(self.audience) is not str or not self.audience or len(self.audience) > 256
                or any(type(v) not in (int, float) or not math.isfinite(v)
                    for v in (self.frozen_at_utc, self.expires_at_utc))
                or not event.activity.completed_at <= self.frozen_at_utc < self.expires_at_utc):
            raise ValueError('Life content audience/current finite time scope differs')
        _sha(self.source_qualification_digest)

    @property
    def occurrence_digest(self):
        return canonical_digest(plain_v1(self.cause.occurrence.event))

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class FrozenInternalLifeContentRequestV1:
    input: InternalLifeContentInputV1
    installation_id: str
    provider_config_digest: str
    provider_id: str
    model_id: str
    max_output_tokens: int
    messages: tuple[dict, ...]
    wire_json: str
    template_version: str = TEMPLATE_VERSION
    template_digest: str = TEMPLATE_DIGEST
    purpose: str = 'consolidation'

    def __post_init__(self):
        from .natural_reply import NaturalReplyInstallationV2
        if type(self.input) is not InternalLifeContentInputV1:
            raise TypeError('Life frozen request requires its exact input')
        installation = NaturalReplyInstallationV2(self.installation_id,
            self.provider_config_digest, self.provider_id, self.model_id, self.max_output_tokens)
        messages, wire = _provider_wire(self.input, installation)
        if (self.template_version != TEMPLATE_VERSION or self.template_digest != TEMPLATE_DIGEST
                or self.purpose != 'consolidation' or type(self.messages) is not tuple
                or canonical_serialize(self.messages) != canonical_serialize(messages)
                or self.wire_json != wire):
            raise ValueError('Life frozen provider/template/input bytes differ')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def freeze_internal_life_content_request_v1(input, installation):
    from .natural_reply import NaturalReplyInstallationV2
    if type(input) is not InternalLifeContentInputV1 or type(installation) is not NaturalReplyInstallationV2:
        raise TypeError('closed Life content input and installed model shape required')
    messages, wire = _provider_wire(input, installation)
    return FrozenInternalLifeContentRequestV1(input, installation.installation_id,
        installation.provider_config_digest, installation.provider_id,
        installation.model_id, installation.max_output_tokens, messages, wire)


def _provider_wire(input, installation):
    event = input.cause.occurrence.event
    activity = event.activity
    # Provider input contains a minimal occurrence, rather than the historical
    # SQL read inventory or model output/artifact bytes as asserted facts.
    payload = {'occurrence_digest': input.occurrence_digest,
        'reality': 'internal_life', 'assertion_scope': 'activity_occurred_only',
        'activity_id': activity.activity_id, 'effect_id': activity.effect_id,
        'execution_id': activity.execution_id, 'started_at': activity.started_at,
        'completed_at': activity.completed_at, 'actual_cpu_ms': activity.actual_cpu_ms,
        'artifact_digest': activity.artifact_digest,
        'context': {'scene_ref': event.scene_ref, 'perspective_ref': event.perspective_ref},
        'before_state': 'evidence_unavailable', 'comparison': 'undetermined',
        'affect': 'unavailable'}
    messages = ({'role': 'system', 'content': SYSTEM},
        {'role': 'user', 'content': canonical_serialize(payload)})
    wire = canonical_serialize({'model': installation.model_id,
        'messages': messages, 'temperature': 0.0,
        'max_tokens': installation.max_output_tokens,
        'response_format': {'type': 'json_object'}})
    return messages, wire


def thaw_internal_life_content_request_v1(raw):
    from dataclasses import fields
    from .natural_reply import NaturalReplyInstallationV2
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw) is not dict or set(raw) != {field.name for field in fields(FrozenInternalLifeContentRequestV1)}:
        raise ValueError('Life frozen request exact fields differ')
    # The occurrence owns a lazy closed activity annotation. Decode it through
    # its installed versioned codec, rather than depending on an unrelated
    # earlier Graph read having resolved that annotation as a side effect.
    from typing import get_type_hints
    from ..runtime.d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
    input_raw = raw['input']
    if type(input_raw) is not dict or set(input_raw) != set(InternalLifeContentInputV1.__dataclass_fields__):
        raise ValueError('Life content input exact fields differ')
    cause_raw = input_raw['cause']
    if type(cause_raw) is not dict or set(cause_raw) != set(InternalLifeEncodingCauseV1.__dataclass_fields__):
        raise ValueError('Life content causal original fields differ')
    cause_hints = get_type_hints(InternalLifeEncodingCauseV1)
    cause = InternalLifeEncodingCauseV1(**{
        name: decode_internal_life_value_v2(PROVENANCE, value) if name == 'occurrence'
        else decode_typed_production_value_v1(value, cause_hints[name])
        for name, value in cause_raw.items()})
    input_hints = get_type_hints(InternalLifeContentInputV1)
    input = InternalLifeContentInputV1(**{
        name: cause if name == 'cause' else decode_typed_production_value_v1(value, input_hints[name])
        for name, value in input_raw.items()})
    installation = NaturalReplyInstallationV2(raw['installation_id'], raw['provider_config_digest'],
        raw['provider_id'], raw['model_id'], raw['max_output_tokens'])
    rebuilt = freeze_internal_life_content_request_v1(input, installation)
    if canonical_serialize(plain_v1(rebuilt)) != canonical_serialize(raw):
        raise ValueError('Life frozen request is not its canonical rebuilt typed input')
    return rebuilt


@dataclass(frozen=True, slots=True)
class InternalLifeContentCandidateV1:
    occurrence_digest: str
    input_digest: str
    summary: str
    keywords: tuple[str, ...]
    canonical_output_json: str
    schema: str = OUTPUT_SCHEMA
    assertion_scope: str = 'model_description_only'
    before_state_status: str = 'evidence_unavailable'
    comparison_status: str = 'undetermined'
    affect_status: str = 'unavailable'

    def __post_init__(self):
        _sha(self.occurrence_digest); _sha(self.input_digest)
        if (self.schema != OUTPUT_SCHEMA or self.assertion_scope != 'model_description_only'
                or self.before_state_status != 'evidence_unavailable'
                or self.comparison_status != 'undetermined' or self.affect_status != 'unavailable'
                or type(self.summary) is not str or not self.summary.strip() or len(self.summary) > 2048
                or type(self.keywords) is not tuple or len(self.keywords) > 24
                or any(type(word) is not str or not word.strip() or len(word) > 80 for word in self.keywords)
                or len(set(self.keywords)) != len(self.keywords)
                or self.canonical_output_json != canonical_serialize({'schema': OUTPUT_SCHEMA,
                    'occurrence_digest': self.occurrence_digest, 'summary': self.summary,
                    'keywords': self.keywords})):
            raise ValueError('Life content candidate promotes unavailable capabilities or differs from output')

    @property
    def output_digest(self):
        return canonical_digest(json.loads(self.canonical_output_json))


def parse_internal_life_content_output_v1(raw, frozen):
    if type(raw) is not str or len(raw) > 16384 or type(frozen) is not FrozenInternalLifeContentRequestV1:
        raise TypeError('actual parsed Life model response and frozen request required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Life content output repeats a field')
            result[key] = value
        return result
    output = json.loads(raw, object_pairs_hook=unique)
    if (type(output) is not dict or set(output) != {'schema','occurrence_digest','summary','keywords'}
            or output['schema'] != OUTPUT_SCHEMA or output['occurrence_digest'] != frozen.input.occurrence_digest
            or type(output['keywords']) is not list or len(output['keywords']) > 24):
        raise ValueError('Life model output is not this occurrence content-only candidate')
    return InternalLifeContentCandidateV1(output['occurrence_digest'], frozen.input.digest,
        output['summary'], tuple(output['keywords']), canonical_serialize(output))


def internal_life_provider_messages_v2(request, workflow):
    """Validate the installed content-only provider wire; never issue a grant."""
    from .broker import ModelCallRequest
    from ..host.authority_profile import AdminModelWorkflowV2
    if (type(request) is not ModelCallRequest or type(workflow) is not AdminModelWorkflowV2
            or request.identity.phase != 'internal_life_content_v2'
            or (workflow.work_kind, workflow.purpose, workflow.template_version) !=
                (WORK_KIND, 'consolidation', TEMPLATE_VERSION)
            or request.prompt_template_digest != TEMPLATE_DIGEST
            or request.envelope.authority.purpose != 'consolidation'
            or type(request.envelope.authority.worker_fence) is not int
            or request.envelope.authority.worker_fence < 1
            or (request.provider_id,request.model_id,request.max_output_tokens) !=
                (workflow.provider_id,workflow.model_id,workflow.max_output_tokens)):
        raise ValueError('Life V2 provider input differs from its installed workflow')
    payload=request.payload
    if (type(payload) is not dict or set(payload)!= {'model','messages','temperature','max_tokens','response_format'}
            or payload['model']!=workflow.model_id or payload['temperature']!=0.0
            or type(payload['temperature']) not in (int,float)
            or type(payload['max_tokens']) is not int or payload['max_tokens']!=workflow.max_output_tokens
            or payload['response_format']!={'type':'json_object'}
            or type(payload['messages']) is not list or len(payload['messages'])!=2
            or payload['messages'][0]!={'role':'system','content':SYSTEM}
            or type(payload['messages'][1]) is not dict
            or set(payload['messages'][1])!={'role','content'}
            or payload['messages'][1]['role']!='user' or type(payload['messages'][1]['content']) is not str):
        raise ValueError('Life V2 provider wire closed fields differ')
    occurrence=json.loads(payload['messages'][1]['content'])
    if (type(occurrence) is not dict or set(occurrence)!= {'occurrence_digest','reality','assertion_scope',
            'activity_id','effect_id','execution_id','started_at','completed_at','actual_cpu_ms','artifact_digest',
            'context','before_state','comparison','affect'}
            or canonical_serialize(occurrence)!=payload['messages'][1]['content']
            or occurrence['reality']!='internal_life' or occurrence['assertion_scope']!='activity_occurred_only'
            or occurrence['before_state']!='evidence_unavailable' or occurrence['comparison']!='undetermined'
            or occurrence['affect']!='unavailable' or type(occurrence['context']) is not dict
            or set(occurrence['context'])!={'scene_ref','perspective_ref'}):
        raise ValueError('Life V2 input attempts to promote content into occurrence or numerical evidence')
    _sha(occurrence['occurrence_digest']);_sha(occurrence['artifact_digest'])
    return payload['messages']
