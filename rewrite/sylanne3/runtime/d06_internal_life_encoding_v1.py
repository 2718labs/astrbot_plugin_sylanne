"""Life-only encoding command and authenticated causal prerequisites.

The current numerical baseline/worker interfaces are first-ingress interfaces.
An unavailable Life execution-before bridge is an explicit missing original,
never an all-zero projection or a claim that the algorithm is inapplicable.
No decoded cause or public request authorizes a model/algorithm call.
"""
from dataclasses import dataclass
import json

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import stage_result_v1, plain_v1
from .d06_internal_life_episode_v2 import (
    EPISODE, InternalLifeEpisodeProvenanceV2, internal_life_episode_read_inputs_v2,
    require_current_internal_life_episode_v2, _sha,
)

OPERATION = 'encode_internal_life'
CAUSE_SCHEMA = 'd06.internal-life-encoding-cause.v1'


@dataclass(frozen=True, slots=True)
class EncodeInternalLifeRequestV1:
    episode_ref: str
    causal_operation_id: str

    def __post_init__(self):
        if (type(self.episode_ref) is not str or AtomKey.from_token(self.episode_ref).type_name != EPISODE
                or type(self.causal_operation_id) is not str or not 1 <= len(self.causal_operation_id) <= 512):
            raise ValueError('Life encoding requires its exact Episode-v2/actual D10 locator')


@dataclass(frozen=True, slots=True)
class InternalLifeEncodingCauseV1:
    occurrence: InternalLifeEpisodeProvenanceV2
    prepared_original_ref: str
    prepared_original_digest: str
    execution_before_state_status: str = 'evidence_unavailable'
    comparison_applicability: str = 'undetermined'
    unavailable_reason: str = 'missing_authenticated_activity_execution_before_d04_state'
    schema: str = CAUSE_SCHEMA

    def __post_init__(self):
        if (type(self.occurrence) is not InternalLifeEpisodeProvenanceV2
                or type(self.prepared_original_ref) is not str or not self.prepared_original_ref
                or self.schema != CAUSE_SCHEMA
                or self.execution_before_state_status != 'evidence_unavailable'
                or self.comparison_applicability != 'undetermined'
                or self.unavailable_reason != 'missing_authenticated_activity_execution_before_d04_state'):
            raise ValueError('Life before-state evidence cannot promote an absent causal bridge')
        _sha(self.prepared_original_digest)


def read_plan_internal_life_encoding_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d01_production_operations_v1 import production_read_plan_v1
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or operation_kind != OPERATION or type(request) is not EncodeInternalLifeRequestV1):
        raise ValueError('exact registered current Life encoding read plan required')
    keys, roots, originals = internal_life_episode_read_inputs_v2(db, namespace, request.episode_ref)
    from .d04_life_before_original_v1 import life_d04_before_current_read_inputs_v1
    _, before_roots, _ = life_d04_before_current_read_inputs_v1(db, namespace, request.episode_ref)
    roots = tuple(sorted(set((*roots, *before_roots))))
    return production_read_plan_v1(('d01.persona_activation.v1', 'd03.self_perspective.v1'),
        keys, roots, (*originals, request.causal_operation_id))


def read_current_internal_life_encoding_cause_v1(db, *, frame, request, installed_readers):
    from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from .d11_life_preparation_v1 import _read, read_prepared_life_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1
    if type(request) is not EncodeInternalLifeRequestV1 or type(installed_readers) is not InstalledD06StructuredExperienceReadersV1:
        raise TypeError('actual installed Life encoding readers and closed request required')
    proof = require_current_internal_life_episode_v2(db, frame=frame,
        episode_ref=request.episode_ref, installed_readers=installed_readers)
    if (proof.event.causal_operation_id != request.causal_operation_id
            or proof.event.activity.activity_id != frame.envelope.identity.activity_id):
        raise ValueError('Life encoding command is not its actual occurrence/D10 cause')
    read = CurrentDomainReadV1(frame)
    source = read.head(db, proof.event.activity.source_ref, required=True)
    locator = json.loads(source.value['text'])['actual_provenance_ref']
    read.original(locator)
    saved = _read(db, issuer=installed_readers.issuer, namespace=proof.event.namespace,
        kind='experience', ref=locator)
    if saved is None:
        raise ValueError('Life encoding lost its actual signed experience original')
    terminal = life_from_wire_v1(saved[0]['terminal'], D11LifeTerminalV1)
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=installed_readers.issuer)
    if (prepared is None or terminal.status != 'completed'
            or terminal.binding.execution_id != proof.event.activity.execution_id
            or terminal.original_ref != proof.event.activity.terminal_original_ref):
        raise ValueError('Life encoding preparation/terminal differs from its actual occurrence')
    read.original(prepared.binding.prepared_original_ref)
    # The signed preparation proves its own frozen read rows. It does NOT
    # prove they were the particular activity's execution-before D04 state.
    return InternalLifeEncodingCauseV1(proof, prepared.binding.prepared_original_ref,
        canonical_digest(plain_v1(prepared)))


def stage_encode_internal_life_in_transaction_v1(db, *, frame, request, installed_readers):
    cause = read_current_internal_life_encoding_cause_v1(db, frame=frame,
        request=request, installed_readers=installed_readers)
    return stage_result_v1(frame, 'd06', OPERATION, request,
        provenance={'schema': CAUSE_SCHEMA, 'cause': plain_v1(cause)},
        coverage='waiting_for_original', missing=(cause.unavailable_reason,
            'actual_life_c02_worker_request_and_result_original'))


def decode_internal_life_encoding_cause_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, InternalLifeEncodingCauseV1)
