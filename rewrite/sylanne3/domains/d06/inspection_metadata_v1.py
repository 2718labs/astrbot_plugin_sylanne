"""Fixed D06 inspection originals derived before the same authorized W01 commit.

These immutable projections carry no Source text or interpretation claim. Their
producer operation and target commitment are verified against actual Graph
history, event write versions and the same committed bundle receipt header.
"""
from ...graph_types import AtomKey, GraphWrite, TypeSpec
from ...memory_types import (SourceRecord, InterpretationRecord, source_key, interpretation_key,
    validate_source_metadata_v1, _SOURCE_FIELDS, _INTERPRETATION_STATUSES, _text, _string_tuple)
from ...runtime_contracts import canonical_digest, NamespaceId

SOURCE_TYPE = 'd06.source_inspection_metadata.v1'
INTERPRETATION_TYPE = 'd06.interpretation_inspection_metadata.v1'
SOURCE_FIELDS = ('source_id', 'speaker_id', 'source_kind', 'assertion_status', 'occurred_at',
    'recorded_at', 'provenance_root', 'audiences', 'purposes', 'parent_source_ids', 'independence')
INTERPRETATION_FIELDS = ('interpretation_id', 'status', 'source_ids')
_FIELDS = frozenset({'schema', 'target_ref', 'target_revision', 'target_codec', 'target_sha256',
    'target_bytes', 'target_semantic_digest', 'producer_operation_id', 'metadata'})


def inspection_key_v1(target, revision):
    if type(target) is not AtomKey or type(revision) is not int or revision < 1:
        raise ValueError('inspection requires an exact positive target GraphVersion')
    if target.type_name == 'memory.source':
        expected, kind = source_key(*NamespaceId.from_key(target).as_tuple, target.owner.subject), SOURCE_TYPE
    elif target.type_name == 'memory.interpretation':
        expected, kind = interpretation_key(*NamespaceId.from_key(target).as_tuple, target.owner.subject), INTERPRETATION_TYPE
    else:
        raise ValueError('inspection is limited to registered D06 Source/Interpretation targets')
    if target != expected:
        raise ValueError('inspection target is not its canonical D06 key')
    return AtomKey(target.owner, kind, 'revision-' + str(revision))


def validate_inspection_metadata_v1(value, *, source):
    kind = SOURCE_TYPE if source else INTERPRETATION_TYPE
    if type(value) is not dict or set(value) != _FIELDS or value['schema'] != kind:
        raise ValueError('inspection original has another registered fixed schema')
    target = AtomKey.from_token(value['target_ref'])
    if target.token != value['target_ref'] or target.type_name != ('memory.source' if source else 'memory.interpretation'):
        raise ValueError('inspection target identity differs')
    inspection_key_v1(target, value['target_revision'])
    if (value['target_codec'] not in {'canonical-json.ascii.v1', 'canonical-json.utf8.v1'}
            or type(value['target_sha256']) is not str or len(value['target_sha256']) != 64
            or any(c not in '0123456789abcdef' for c in value['target_sha256'])
            or type(value['target_semantic_digest']) is not str or len(value['target_semantic_digest']) != 64
            or any(c not in '0123456789abcdef' for c in value['target_semantic_digest'])
            or type(value['target_bytes']) is not int or value['target_bytes'] < 1):
        raise ValueError('inspection requires its actual canonical target commitment')
    _text(value['producer_operation_id'], 'producer_operation_id')
    metadata = value['metadata']
    if type(metadata) is not dict or set(metadata) != set(SOURCE_FIELDS if source else INTERPRETATION_FIELDS):
        raise ValueError('inspection metadata is outside its exact registered fields')
    if source:
        if _SOURCE_FIELDS != frozenset((*SOURCE_FIELDS, 'text')):
            raise ValueError('Source inspection schema requires explicit registration for this Source version')
        typed = dict(metadata)
        for name in ('audiences', 'purposes', 'parent_source_ids'):
            if type(typed[name]) is not list:
                raise ValueError('inspection Source scopes must be canonical arrays')
            typed[name] = tuple(typed[name])
        validate_source_metadata_v1(**typed)
        if metadata['source_id'] != target.owner.subject:
            raise ValueError('inspection Source identity differs from its target')
    else:
        _text(metadata['interpretation_id'], 'interpretation_id')
        if type(metadata['source_ids']) is not list:
            raise ValueError('inspection source_ids requires a canonical array')
        _string_tuple(tuple(metadata['source_ids']), 'source_ids', require_one=True)
        if metadata['status'] not in _INTERPRETATION_STATUSES or metadata['interpretation_id'] != target.owner.subject:
            raise ValueError('inspection interpretation identity/status differs')
    return value


def _validate_source(value):
    validate_inspection_metadata_v1(value, source=True)


def _validate_interpretation(value):
    validate_inspection_metadata_v1(value, source=False)


def inspection_metadata_type_specs_v1():
    # Producers append once to each version key; the Graph must still invalidate
    # its current head when the actual Source/Interpretation target changes.
    return tuple(TypeSpec(kind, ('event',), 'source', validator, immutable=False,
        writer_domain='d06', schema_hash=canonical_digest({'type': kind, 'version': 1,
            'fields': sorted(_FIELDS), 'metadata_fields': fields, 'codecs': ('canonical-json.ascii.v1', 'canonical-json.utf8.v1')}))
        for kind, validator, fields in ((SOURCE_TYPE, _validate_source, SOURCE_FIELDS),
            (INTERPRETATION_TYPE, _validate_interpretation, INTERPRETATION_FIELDS)))


def inspection_projection_keys_v1(envelope, writes):
    reads = {version.key: version.revision for version in envelope.version_guard.read_versions}
    result = []
    for write in writes:
        if write.key.type_name not in {'memory.source', 'memory.interpretation'}:
            continue
        if write.key not in reads:
            raise ValueError('inspection producer target lacks its actual CAS read')
        result.append(inspection_key_v1(write.key, reads[write.key] + 1))
    return tuple(result)


def derive_inspection_projection_writes_v1(envelope, writes):
    writes = tuple(writes)
    if any(write.key.type_name in {SOURCE_TYPE, INTERPRETATION_TYPE} for write in writes):
        raise ValueError('inspection producer cannot accept caller supplied projection originals')
    reads = {version.key: version.revision for version in envelope.version_guard.read_versions}
    projected = []
    for write, key in zip((w for w in writes if w.key.type_name in {'memory.source', 'memory.interpretation'}),
            inspection_projection_keys_v1(envelope, writes)):
        if reads.get(key) != 0:
            raise ValueError('inspection immutable output requires its actual revision-0 CAS read')
        if write.key.type_name == 'memory.source':
            record = SourceRecord.from_dict(write.value)
            body = record.to_dict()
            metadata = {name: body[name] for name in SOURCE_FIELDS}
            kind = SOURCE_TYPE
        else:
            record = InterpretationRecord.from_dict(write.value)
            metadata = {name: record.to_dict()[name] for name in INTERPRETATION_FIELDS}
            kind = INTERPRETATION_TYPE
        from ...contracts import canonical_json
        from hashlib import sha256
        from ...runtime.owner_material_source_storage_v3 import (issued_sealed_source_graph_write_v3,
            require_sealed_source_graph_write_v3)
        if issued_sealed_source_graph_write_v3(write):
            holder = require_sealed_source_graph_write_v3(write)
            header = holder.seal.header
            codec, physical_sha, physical_bytes = header[1], header[6], header[4]
            semantic_digest = holder.prepared.expected['source'][0]
        else:
            encoded = canonical_json(write.value).encode('utf8')
            codec, physical_sha, physical_bytes = 'canonical-json.ascii.v1', sha256(encoded).hexdigest(), len(encoded)
            semantic_digest = canonical_digest(write.value)
        value = {'schema': kind, 'target_ref': write.key.token,
            'target_revision': reads[write.key] + 1, 'target_codec': codec,
            'target_sha256': physical_sha, 'target_bytes': physical_bytes,
            'target_semantic_digest': semantic_digest,
            'producer_operation_id': envelope.identity.operation_id, 'metadata': metadata}
        validate_inspection_metadata_v1(value, source=kind == SOURCE_TYPE)
        projected.append(GraphWrite(key, value, (write.key,)))
    return writes + tuple(projected)


def validate_inspection_proposal_v1(proposal):
    originals = tuple(w for w in proposal.typed_writes if w.key.type_name not in {SOURCE_TYPE, INTERPRETATION_TYPE})
    expected = derive_inspection_projection_writes_v1(proposal.envelope, originals)
    actual_projections = tuple(w for w in proposal.typed_writes if w.key.type_name in {SOURCE_TYPE, INTERPRETATION_TYPE})
    if actual_projections != expected[len(originals):]:
        raise ValueError('D06 inspection projections must derive from the same actual pre-sign target writes')
    return proposal
