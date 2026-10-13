"""Data-only streaming C02 mechanics; callers own column provenance and authority."""
from __future__ import annotations

from dataclasses import fields
from hashlib import sha256
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphWrite
from ..runtime_contracts import (
    CommandEnvelope, DependencySet, DomainBundle, DomainProposal, NamespaceId,
    _digest, _nonempty, _strings,
)
from .c02_bundle_codec import _FIELDS, _decode
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2


class C02BundleMechanicalReadV3:
    """Consume canonical wire without retaining any GraphWrite.value body.

    This is not an issuer or a column qualification. The caller must bind every
    fragment and the final raw SHA/byte count to its own actual complete column,
    retain its selected-operation lifetime, and qualify the resulting envelope.
    ``business`` and ``event`` are the caller's exact-PK committed row metadata.
    The event digest is intentionally not compared with the bundle digest: the
    old contract requires event existence, and these are separate digest domains.
    """
    def __init__(self, *, namespace, operation_id, archive_schema,
                 archive_digest, business, event, operation):
        if (archive_schema != 'sylanne.first-ingress-c02-candidate.v2'
                or business is None or archive_digest != business[0]):
            raise AuthorityUnavailable('C02 original lacks its committed archive/business identity')
        if event is None:
            raise AuthorityUnavailable('C02 original has no actual committed Graph event')
        self.namespace, self.operation_id = namespace, operation_id
        self.archive_digest, self.business, self.event = archive_digest, business, event
        self.operation = operation
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.nodes, self.frames = {}, []
        self.raw = None
        self.scalar = bytearray()
        self.reserved = 0
        self.wire_hash, self.legacy_hash = sha256(), sha256()
        self.proposal_hash = self.write_hash = None
        self.proposal_fingerprints, self.write_fingerprints = [], []
        self.proposal_count = 0
        self.envelope = None
        self.complete = False
        self._reserve(65536)

    def _reserve(self, extra=0):
        from .source_correction_read_v3 import _heap
        amount = _heap((self.nodes, self.scalar, self.frames,
                        self.proposal_fingerprints, self.write_fingerprints)) + extra + 65536
        if amount > self.reserved:
            self.operation.retain(amount - self.reserved)
            self.reserved = amount

    @staticmethod
    def _shape(raw, kind):
        names = {field.name for field in fields(kind)}
        if kind is DomainBundle:
            names.remove('root_adoption')
        if (type(raw) is not dict or set(raw) != {'$type', *_FIELDS[kind]}
                or raw.get('$type') != kind.__module__ + '.' + kind.__qualname__
                or names != set(_FIELDS[kind])):
            raise AuthorityUnavailable('C02 exact typed fieldset/marker differs')

    @staticmethod
    def _value_path(path):
        return (len(path) >= 5 and path[0] == 'proposals'
                and type(path[1]) is int and path[2] == 'typed_writes'
                and type(path[3]) is int and path[4] == 'value')

    def _token(self, raw, path):
        self.wire_hash.update(raw)
        if path[:1] != ('product_advance',):
            self.legacy_hash.update(raw)
        if self.proposal_hash is not None:
            self.proposal_hash.update(raw)
        if self.write_hash is not None:
            self.write_hash.update(raw)

    def _put(self, path, value):
        if not path:
            self.raw = value
        else:
            parent = self.nodes[path[:-1]]
            if type(parent) is list:
                parent.append(value)
            else:
                parent[path[-1]] = value

    def _start(self, event):
        path = event.path
        if self.frames and self.frames[-1][0] == 'array':
            frame = self.frames[-1]
            if frame[1]:
                self._token(b',', path)
            frame[1] += 1
        if len(path) == 2 and path[0] == 'proposals':
            if event.kind != 'object_start':
                raise AuthorityUnavailable('C02 proposal must be a typed object')
            self.proposal_hash = sha256()
        if len(path) == 4 and path[0] == 'proposals' and path[2] == 'typed_writes':
            if event.kind != 'object_start':
                raise AuthorityUnavailable('C02 write must be a typed object')
            self.write_hash = sha256()
        if self._value_path(path) and len(path) == 5 and event.kind != 'object_start':
            raise AuthorityUnavailable('C02 GraphWrite.value must be a plain JSON object')

    def _envelope(self, raw):
        envelope = _decode(raw, CommandEnvelope)
        if (envelope.identity.operation_id != self.operation_id
                or envelope.authority.namespace != self.namespace
                or envelope.identity.activity_id != self.business[1]
                or envelope.identity.effect_id != self.business[2]
                or envelope.identity.phase != 'first_ingress_c02'):
            raise AuthorityUnavailable('C02 envelope differs from actual committed namespace/operation')
        return envelope

    def _write(self, raw):
        self._shape(raw, GraphWrite)
        key = _decode(raw['key'], AtomKey)
        if (NamespaceId.from_key(key) != self.namespace
                or type(raw['value']) is not dict or type(raw['dependencies']) is not list):
            raise AuthorityUnavailable('C02 write crossed namespace or plain JSON object wire')
        dependencies = tuple(_decode(value, AtomKey) for value in raw['dependencies'])
        if len(set(dependencies)) != len(dependencies):
            raise AuthorityUnavailable('C02 write dependencies repeat')
        self._reserve(256)
        self.write_fingerprints.append(self.write_hash.hexdigest())
        self.write_hash = None

    def _proposal(self, raw):
        self._shape(raw, DomainProposal)
        _nonempty(raw['domain'], 'domain')
        _nonempty(raw['proposal_schema'], 'proposal_schema')
        _digest(raw['proposal_schema_hash'], 'proposal_schema_hash')
        if self.proposal_count >= 2 or raw['domain'] != ('d06', 'd11')[self.proposal_count]:
            raise AuthorityUnavailable('C02 original is not the original two-proposal workflow')
        if _decode(raw['envelope'], CommandEnvelope) != self.envelope:
            raise AuthorityUnavailable('C02 proposal envelope differs from bundle envelope')
        dependencies = _decode(raw['dependencies'], DependencySet)
        refs = (dependencies.current_invalidation + dependencies.historical_provenance
                + dependencies.associations + dependencies.numeric_coupling)
        if any(NamespaceId.from_key(ref.key) != self.namespace for ref in refs):
            raise AuthorityUnavailable('C02 proposal dependencies crossed namespace')
        for name in ('contribution_keys', 'required_bundle_parts'):
            if type(raw[name]) is not list:
                raise AuthorityUnavailable('C02 proposal tuple wire differs')
            values = _strings(raw[name], name)
            if name == 'required_bundle_parts' and values:
                raise AuthorityUnavailable('C02 proposal needs an absent bundle part')
        if type(raw['typed_writes']) is not list:
            raise AuthorityUnavailable('C02 write tuple wire differs')
        if len(set(self.write_fingerprints)) != len(self.write_fingerprints):
            raise AuthorityUnavailable('C02 proposal repeats a canonical write')
        self.proposal_fingerprints.append(self.proposal_hash.hexdigest())
        self.proposal_count += 1
        self.proposal_hash = None
        self.write_fingerprints = []

    def _bundle(self):
        self._shape(self.raw, DomainBundle)
        for name in ('experience_refs', 'choice_refs', 'd02_settlement_refs',
                     'd11_cost_settlement_refs', 'idempotency_keys',
                     'persistent_job_refs', 'outbox_refs'):
            if type(self.raw[name]) is not list or _strings(self.raw[name], name):
                raise AuthorityUnavailable('C02 original carries unsupported bundle parts')
        if (type(self.raw['proposals']) is not list or self.proposal_count != 2
                or self.raw['product_advance'] is not None):
            raise AuthorityUnavailable('C02 original is not the original two-proposal workflow')
        if len(set(self.proposal_fingerprints)) != len(self.proposal_fingerprints):
            raise AuthorityUnavailable('C02 original repeats a canonical proposal')

    def _emit(self, event):
        path, kind = event.path, event.kind
        body = self._value_path(path)
        if kind == 'key':
            frame = self.frames[-1]
            if frame[1]:
                self._token(b',', path)
            frame[1] += 1
            self._token(event.raw + b':', path)
            return
        if kind in ('object_start', 'array_start', 'scalar_start'):
            self._start(event)
        if kind in ('object_start', 'array_start'):
            self._token(event.raw, path)
            self.frames.append(['object' if kind == 'object_start' else 'array', 0])
            if body:
                if len(path) == 5:
                    self._put(path, {})
                return
            self._reserve(1024)
            value = {} if kind == 'object_start' else []
            self.nodes[path] = value
            self._put(path, value)
        elif kind == 'scalar_start':
            if not body:
                self.scalar = bytearray()
        elif kind == 'scalar_chunk':
            self._token(event.raw, path)
            if not body:
                self._reserve(len(event.raw) * 4 + 1024)
                self.scalar.extend(event.raw)
        elif kind == 'scalar_end':
            if not body:
                self._reserve(len(self.scalar) * 4 + 1024)
                self._put(path, json.loads(self.scalar))
                self.scalar = bytearray()
        elif kind in ('object_end', 'array_end'):
            self._token(event.raw, path)
            self.frames.pop()
            if body:
                return
            value = self.nodes.pop(path)
            if path == ('envelope',):
                self.envelope = self._envelope(value)
            elif len(path) == 4 and path[0] == 'proposals' and path[2] == 'typed_writes':
                self._write(value)
                self.nodes[path[:-1]].clear()
            elif len(path) == 2 and path[0] == 'proposals':
                self._proposal(value)
                self.nodes[path[:-1]].clear()

    def feed_v3(self, fragment, meter):
        if self.complete:
            raise AuthorityUnavailable('C02 mechanical EOF is already complete')
        meter.require_available(len(fragment) * 4 + 8192)
        self._reserve(len(fragment) * 4 + 8192)
        self.parser.feed(fragment, self._emit)

    def finish_v3(self, *, sha256, byte_count):
        parsed = self.parser.finish()
        self._bundle()
        if ((parsed.sha256, parsed.byte_count) != (sha256, byte_count)
                or self.wire_hash.hexdigest() != sha256):
            raise AuthorityUnavailable('C02 canonical bytes differ from actual complete column EOF')
        digest = self.legacy_hash.hexdigest()
        if digest != self.archive_digest or digest != self.business[0]:
            raise AuthorityUnavailable('C02 legacy bundle digest differs from committed identity')
        self.bundle_digest, self.sha256, self.byte_count = digest, sha256, byte_count
        self.complete = True
        self.raw = None
        self.nodes.clear()
        self.scalar = bytearray()
        self.parser = None
        return self.envelope
