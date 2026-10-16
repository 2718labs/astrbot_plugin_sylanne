"""Bodyless observations for one actual Contact preparation WRITE attempt.

These values describe a current observation. They grant neither a new budget
nor a dispatch, and cannot replace the original prospective Graph birth.
"""
from dataclasses import dataclass, fields
import json
import math

from .contract import identifier
from .v2_contract import (CurrentEffectReadV2, AuthorityCurrentEffectSnapshotV2,
    to_wire as authority_to_wire, from_wire as authority_from_wire)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

SCHEMA = 'authority.contact-prospective-observation.v1'
MAX_INPUT_BYTES = 65536
MAX_OBSERVATION_BYTES = 131072


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Contact prospective exact digest required')


@dataclass(frozen=True, slots=True)
class ContactProspectiveSelectorV1:
    namespace: NamespaceId
    contact_id: str
    birth_operation_id: str
    birth_request_digest: str
    final_operation_id: str
    effect_id: str
    policy_id: str
    causal_dedupe_key: str

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId:
            raise TypeError('Contact prospective namespace must be typed')
        for name in ('contact_id', 'birth_operation_id', 'final_operation_id', 'effect_id', 'policy_id'):
            value = getattr(self, name)
            identifier(value, name)
            if len(value) > 256:
                raise ValueError('Contact prospective locator exceeds its fixed bound')
        if (not self.contact_id.startswith('contact:') or not self.effect_id.startswith('effect:')
                or self.birth_operation_id == self.final_operation_id):
            raise ValueError('Contact prospective birth and future effect identity differ')
        _digest(self.birth_request_digest)
        _digest(self.causal_dedupe_key)


@dataclass(frozen=True, slots=True)
class ContactProspectiveObservationV1:
    selector: ContactProspectiveSelectorV1
    authority_id: str
    authority_namespace: str
    installation_id: str
    subject: str
    observed_operation_id: str
    observed_request_digest: str
    attempt_id: str
    permit_digest: str
    anchor_digest: str
    selection_digest: str
    joint_preparation_ref: str
    joint_preparation_digest: str
    joint_preparation_operation_id: str
    joint_preparation_receipt_digest: str
    owner_authority_digest: str
    owner_actor: str
    owner_head_digest: str
    owner_revision: int
    principal_epoch: int
    policy_original_ref: str
    policy_original_digest: str
    policy_window_id: str
    policy_version: int
    inputs_json: str
    current_effect: CurrentEffectReadV2
    effect_snapshot: AuthorityCurrentEffectSnapshotV2
    observed_at_utc: float
    deadline_utc: float
    observation_ref: str
    signature: str
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or type(self.selector) is not ContactProspectiveSelectorV1
                or type(self.current_effect) is not CurrentEffectReadV2
                or type(self.effect_snapshot) is not AuthorityCurrentEffectSnapshotV2):
            raise ValueError('Contact prospective observation requires its exact typed originals')
        for name in ('authority_id', 'authority_namespace', 'installation_id', 'subject', 'observed_operation_id', 'attempt_id',
                     'owner_actor', 'owner_head_digest', 'policy_original_ref', 'policy_window_id',
                     'joint_preparation_ref', 'joint_preparation_operation_id'):
            identifier(getattr(self, name), name)
        for name in ('permit_digest', 'anchor_digest', 'selection_digest', 'observed_request_digest', 'owner_authority_digest',
                     'policy_original_digest', 'joint_preparation_digest', 'joint_preparation_receipt_digest', 'signature'):
            _digest(getattr(self, name))
        if (type(self.owner_revision) is not int or self.owner_revision < 1
                or type(self.principal_epoch) is not int or self.principal_epoch < 0
                or type(self.policy_version) is not int or self.policy_version < 1
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in (self.observed_at_utc, self.deadline_utc))
                or not self.observed_at_utc < self.deadline_utc):
            raise ValueError('Contact prospective current Owner or absolute validity differs')
        if type(self.inputs_json) is not str or len(self.inputs_json.encode('utf-8')) > MAX_INPUT_BYTES:
            raise ValueError('Contact prospective input metadata exceeds its original bound')
        from ..runtime.contact_background_inputs_v1 import validate_background_inputs_v1
        inputs = validate_background_inputs_v1(json.loads(self.inputs_json))
        selected = self.selector
        if (canonical_serialize(inputs) != self.inputs_json
                or inputs['namespace'] != {'bot_id': selected.namespace.bot_id, 'persona_id': selected.namespace.persona_id}
                or inputs['contact_id'] != selected.contact_id
                or inputs['operation_id'] != selected.final_operation_id
                or inputs['first_effect_id'] != selected.effect_id
                or self.deadline_utc > inputs['deadline_utc']):
            raise ValueError('Contact prospective inputs differ from their actual future operation')
        if not self.joint_preparation_ref.startswith('joint-contact-preparation:'):
            raise ValueError('Contact prospective requires its actual Joint preparation original')
        if self.observed_operation_id not in {selected.birth_operation_id, selected.final_operation_id}:
            raise ValueError('Contact prospective observation escaped its two actual operation identities')
        if (self.observed_operation_id == selected.birth_operation_id
                and self.observed_request_digest != selected.birth_request_digest):
            raise ValueError('Contact prospective birth request digest differs')
        effect, snapshot = self.current_effect, self.effect_snapshot
        if (effect.authority_id != self.authority_id or effect.namespace != self.authority_namespace
                or effect.effect_id != selected.effect_id or effect.state != 'absent'
                or effect.activation_generation != inputs['generation']
                or snapshot.authority_id != self.authority_id or snapshot.namespace != self.authority_namespace
                or snapshot.coverage != 'complete' or snapshot.anchor.activation_generation != inputs['generation']
                or snapshot.permit_digest != 'sha256:' + self.permit_digest
                or (effect.execution_head_seq, effect.execution_head_digest) !=
                   (snapshot.execution_head_seq, snapshot.execution_head_digest)):
            raise ValueError('Contact prospective effect is not its actual complete pre-dispatch observation')
        if self.observation_ref != 'contact-prospective-observation:' + canonical_digest(self.material()):
            raise ValueError('Contact prospective observation reference differs')

    def material(self):
        return {name: value for name, value in contact_prospective_to_wire_v1(self).items()
                if name not in {'observation_ref', 'signature'}}

    @property
    def digest(self):
        return canonical_digest(contact_prospective_to_wire_v1(self))


def contact_prospective_to_wire_v1(value):
    if type(value) is ContactProspectiveSelectorV1:
        return {field.name: ({'bot_id': value.namespace.bot_id, 'persona_id': value.namespace.persona_id}
                if field.name == 'namespace' else getattr(value, field.name)) for field in fields(value)}
    if type(value) is ContactProspectiveObservationV1:
        result = {field.name: getattr(value, field.name) for field in fields(value)}
        result['selector'] = contact_prospective_to_wire_v1(value.selector)
        result['current_effect'] = authority_to_wire(value.current_effect)
        result['effect_snapshot'] = authority_to_wire(value.effect_snapshot)
        return result
    raise TypeError('Unregistered Contact prospective wire type')


def contact_prospective_from_wire_v1(raw, kind):
    if (kind not in {ContactProspectiveSelectorV1, ContactProspectiveObservationV1}
            or type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}):
        raise ValueError('Contact prospective closed wire fields differ')
    value = dict(raw)
    if kind is ContactProspectiveSelectorV1:
        ns = raw['namespace']
        if type(ns) is not dict or set(ns) != {'bot_id', 'persona_id'}:
            raise ValueError('Contact prospective namespace fields differ')
        value['namespace'] = NamespaceId(**ns)
    else:
        value['selector'] = contact_prospective_from_wire_v1(raw['selector'], ContactProspectiveSelectorV1)
        value['current_effect'] = authority_from_wire(raw['current_effect'])
        value['effect_snapshot'] = authority_from_wire(raw['effect_snapshot'])
    return kind(**value)
