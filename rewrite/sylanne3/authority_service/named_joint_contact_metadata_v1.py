"""Closed signed Contact permission metadata before named Joint Source ALL."""
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable
from .named_joint_binding_source_read_v3 import require_named_joint_inputs_v3, _MetadataStreamV3, _fixed, _run


class _ProspectiveMetadataV3(DispatchOriginalJSONReadV3):
    def __init__(self, state, key):
        from ..runtime.contact_prospective_v1 import TABLE
        self.state = state
        super().__init__(state.work, table=TABLE, column='payload_json', key_columns=('bot', 'persona', 'original_ref'), key=key)
        self.stream = _MetadataStreamV3(self, True)
        self.parser = self.stream
    def _emit(self, event):
        if not event.path or event.path[0] in {'schema', 'namespace', 'contact_id', 'birth_operation_id', 'joint_preparation', 'quote', 'terms', 'final_operation_id', 'effect_id', 'deadline_utc', 'reservation'}:
            super()._emit(event)


def read_named_joint_contact_metadata_v1(state):
    from ..runtime.contact_prospective_v1 import TABLE, SIGN_KIND
    from ..runtime.joint_contact_preparation_v1 import JointContactPreparationOriginalV1
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    work = state.work
    require_named_joint_inputs_v3(work)
    if not state.metadata_only or state.request.argument.executor_kind != 'contact':
        raise AuthorityUnavailable('Contact permission metadata requires the exact named pre-Source profile')
    binding = state.request.command.binding
    key = (*work.namespace.as_tuple, binding.prospective_original_ref)
    row = _fixed(work, TABLE, ('contact_id', 'birth_operation_id', 'payload_digest', 'signature'),
        'bot=? AND persona=? AND original_ref=?', key)
    if row is None or (row[0], row[2]) != (binding.contact_id, binding.prospective_original_digest):
        raise AuthorityUnavailable('Named Contact actual prospective metadata absent or changed')
    column = _ProspectiveMetadataV3(state, key)
    raw = _run(work, column)
    if (column.stream.semantic.hexdigest() != row[2] or raw['schema'] != SIGN_KIND
            or raw['contact_id'] != binding.contact_id or raw['birth_operation_id'] != row[1]
            or raw['namespace'] != {'bot_id': work.namespace.bot_id, 'persona_id': work.namespace.persona_id}):
        raise AuthorityUnavailable('Named Contact metadata full canonical EOF changed its immutable birth')
    state.service.issuer._signer.verify(SIGN_KIND, canonical_serialize((work.namespace, row[0], row[1], row[2])), row[3])
    preparation = raw['joint_preparation']
    table = 'graph_d10_production_inputs_v1'
    selected = (*work.namespace.as_tuple, preparation['ref'])
    header = _fixed(work, table, ('kind', 'producing_operation_id', 'payload_digest', 'signature'),
        'bot=? AND persona=? AND original_ref=?', selected)
    if header is None or header[:3] != ('joint_contact_preparation_v1', preparation['operation_id'], preparation['digest']):
        raise AuthorityUnavailable('Named Contact actual independent Joint preparation metadata differs')
    # Every field of this registered type is fixed identity, Source permission,
    # scope, budget or producer metadata; it contains no paid Contact text.
    original = _run(work, DispatchOriginalJSONReadV3(work, table=table, column='payload_json',
        key_columns=('bot', 'persona', 'original_ref'), key=selected))
    encoded = canonical_serialize(original)
    if canonical_digest(original) != header[2]:
        raise AuthorityUnavailable('Named Contact preparation metadata canonical digest differs')
    state.service.issuer._signer.verify('d11.d10-production-input.v1', encoded, header[3])
    typed = decode_typed_production_value_v1(original, JointContactPreparationOriginalV1)
    if (typed.namespace != work.namespace or typed.original_ref != preparation['ref']
            or typed.request.contact_id != binding.contact_id or typed.digest != preparation['digest']
            or typed.request.joint_plan_ref != binding.plan_ref or typed.request.joint_plan_revision != binding.plan_revision
            or typed.request.node_id != binding.node_id or typed.source_refs != binding.source_refs):
        raise AuthorityUnavailable('Named Contact permission metadata does not equal its exact original prospective request')
    return {'birth_operation_id': row[1], 'birth_digest': row[2], 'birth_locator': raw, 'preparation': typed,
        'preparation_ref': preparation['ref'], 'source_purpose_groups': typed.source_purpose_groups}
