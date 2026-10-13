"""C09 V2 bounded commitment protocol shared by installed capture producers.

These values check byte commitments and sequencing, not permission or provenance.
Only installed producers may authenticate the scope, frozen file, census and EOF.
V1 signed bytes and schemas are deliberately outside this module.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from contextlib import contextmanager
from hashlib import sha256
import re

from ..runtime_contracts import canonical_serialize as _canonical_serialize, meter_canonical_outputs

@contextmanager
def meter_c09_commitments_v2(meter):
    """Bind the actual reservation; every serializer output is charged once."""
    with meter_canonical_outputs(meter):
        yield meter


def _commit_serialize(value: object) -> str:
    return _canonical_serialize(value)


def _commit_digest(value: object) -> str:
    return sha256(_commit_serialize(value).encode("utf-8")).hexdigest()

MAX_PAGE_RECORDS_V2 = 100
MAX_PAGE_BYTES_V2 = 262144
MAX_DESCRIPTOR_BYTES_V2 = 65536
PROFILE_INPUT_SHA256_V2 = "a4d715d8a155fecd54eaff80b471a27196ebeffa7fd287cac4600f17e727f884"
# These are ceilings from the user's proposed profile, not resource qualification.
ROLES_V2 = frozenset({"graph", "core", "execution", "deletion"})
STREAM_KINDS_V2 = frozenset({
    "schema_catalogue", "source_ancestry", "source_descendants", "dependency_closure",
    "nested_closure", "affected_operations", "row_dispositions", "target_rows",
    "generated_rows", "execution_facts", "d02_facts", "d11_facts", "unknown_facts",
    "graph_facts", "tombstones", "filesystem_metadata", "control_metadata",
    "execution_journal", "execution_bindings", "model_originals",
})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SQL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
PrimaryKeyV2 = tuple[str | int, ...]


def _sha(value: str, name: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _text(value: str, name: str) -> None:
    if type(value) is not str or not value or len(value) > MAX_DESCRIPTOR_BYTES_V2:
        raise ValueError(f"invalid {name}")


def _uint(value: int, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"invalid {name}")


def _key(value: PrimaryKeyV2 | None, name: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if (type(value) is not tuple or not value or len(value) > MAX_DESCRIPTOR_BYTES_V2
            or any(type(part) not in (str, int) for part in value)):
        raise ValueError(f"invalid {name}")
    for part in value:
        if type(part) is int and not -(1 << 63) <= part < (1 << 63):
            raise ValueError(f"{name} integer is outside SQLite range")
        if type(part) is str and len(part) > MAX_DESCRIPTOR_BYTES_V2:
            raise ValueError(f"{name} exceeds descriptor ceiling")
        if type(part) is str:
            part.encode("utf-8")
    if len(_commit_serialize(value).encode("utf-8")) > MAX_DESCRIPTOR_BYTES_V2:
        raise ValueError(f"{name} exceeds descriptor ceiling")


class _CommitmentV2:
    __slots__ = ()

    @property
    def digest(self) -> str:
        return _commit_digest(tuple(getattr(self, f.name) for f in fields(self)))

    def _schema(self, expected: str) -> None:
        if self.schema != expected:
            raise ValueError("C09 schema differs")

    def _descriptor(self) -> None:
        if len(_commit_serialize(self).encode("utf-8")) > MAX_DESCRIPTOR_BYTES_V2:
            raise ValueError("C09 descriptor exceeds proposed profile ceiling")


@dataclass(frozen=True, slots=True)
class C09CaptureScopeV2(_CommitmentV2):
    authority_id: str
    installation_id: str
    authority_namespace: str
    graph_namespace: str
    operation_id: str
    maintenance_generation: int
    old_manifest_digest: str
    expected_pointer_version: int
    accepted_receipt_digest: str
    barrier_digest: str
    writer_freeze_digest: str
    facts_pin_ref: str
    facts_pin_intent_digest: str
    profile_id: str
    profile_digest: str
    codec_catalogue_digest: str
    schema: str = "sylanne3.c09.capture_scope.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.capture_scope.v2")
        for name in ("authority_id", "installation_id", "authority_namespace",
                     "graph_namespace", "operation_id", "facts_pin_ref", "profile_id"):
            _text(getattr(self, name), name)
        for name in ("old_manifest_digest", "accepted_receipt_digest", "barrier_digest",
                     "writer_freeze_digest", "facts_pin_intent_digest", "profile_digest",
                     "codec_catalogue_digest"):
            _sha(getattr(self, name), name)
        _uint(self.maintenance_generation, "maintenance_generation")
        _uint(self.expected_pointer_version, "expected_pointer_version")
        self._descriptor()

    @property
    def scope_digest(self) -> str:
        return self.digest


@dataclass(frozen=True, slots=True)
class C09FrozenRoleSourceV2(_CommitmentV2):
    scope_digest: str
    role: str
    source_path: str
    source_identity: str
    source_file_sha256: str
    schema_root: str
    source_stage_original_ref: str
    source_stage_original_digest: str
    schema: str = "sylanne3.c09.frozen_role_source.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.frozen_role_source.v2")
        if self.role not in ROLES_V2:
            raise ValueError("unknown C09 storage role")
        for name in ("scope_digest", "source_file_sha256", "schema_root",
                     "source_stage_original_digest"):
            _sha(getattr(self, name), name)
        for name in ("source_path", "source_identity", "source_stage_original_ref"):
            _text(getattr(self, name), name)
        self._descriptor()

    @property
    def role_source_digest(self) -> str:
        return self.digest


@dataclass(frozen=True, slots=True)
class C09StreamIdentityV2(_CommitmentV2):
    scope_digest: str
    role_source_digest: str
    stream_kind: str
    family: str
    schema_digest: str
    primary_key_columns: tuple[str, ...]
    primary_key_types: tuple[str, ...]
    ordering_version: str = "sqlite_binary_asc_v1"
    schema: str = "sylanne3.c09.stream_identity.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.stream_identity.v2")
        for name in ("scope_digest", "role_source_digest", "schema_digest"):
            _sha(getattr(self, name), name)
        if self.stream_kind not in STREAM_KINDS_V2:
            raise ValueError("unknown C09 stream kind")
        _text(self.family, "family")
        if (type(self.primary_key_columns) is not tuple or not self.primary_key_columns
                or any(type(c) is not str or _SQL_NAME.fullmatch(c) is None
                       for c in self.primary_key_columns)
                or len(set(self.primary_key_columns)) != len(self.primary_key_columns)):
            raise ValueError("invalid primary-key columns")
        if (type(self.primary_key_types) is not tuple
                or len(self.primary_key_types) != len(self.primary_key_columns)
                or any(t not in ("text", "integer") for t in self.primary_key_types)):
            raise ValueError("invalid primary-key types")
        if self.ordering_version != "sqlite_binary_asc_v1":
            raise ValueError("unsupported C09 key ordering")
        self._descriptor()

    @property
    def stream_id(self) -> str:
        return self.digest


def _stream_key(stream: C09StreamIdentityV2, key: PrimaryKeyV2) -> None:
    _key(key, "primary_key")
    if len(key) != len(stream.primary_key_types):
        raise ValueError("primary-key arity differs")
    for value, kind in zip(key, stream.primary_key_types, strict=True):
        if type(value) is not (str if kind == "text" else int):
            raise ValueError("primary-key storage class differs")


def _key_order(key: PrimaryKeyV2) -> tuple:
    # SQLite BINARY compares TEXT UTF-8 bytes; INTEGER uses signed numeric order.
    return tuple(part.encode("utf-8") if type(part) is str else part for part in key)


@dataclass(frozen=True, slots=True)
class C09CaptureRecordV2(_CommitmentV2):
    primary_key: PrimaryKeyV2
    commitment: str
    schema: str = "sylanne3.c09.capture_record.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.capture_record.v2")
        _key(self.primary_key, "primary_key")
        _sha(self.commitment, "commitment")
        self._descriptor()


@dataclass(frozen=True, slots=True)
class C09PageCursorV2(_CommitmentV2):
    stream_id: str
    page_index: int
    record_offset: int
    encoded_bytes: int
    previous_page_digest: str
    record_chain: str
    last_key: PrimaryKeyV2 | None
    schema: str = "sylanne3.c09.page_cursor.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.page_cursor.v2")
        for name in ("stream_id", "previous_page_digest", "record_chain"):
            _sha(getattr(self, name), name)
        for name in ("page_index", "record_offset", "encoded_bytes"):
            _uint(getattr(self, name), name)
        _key(self.last_key, "last_key", optional=True)
        if (self.record_offset == 0) != (self.last_key is None):
            raise ValueError("cursor key/count differs")
        if self.page_index == 0:
            if self.record_offset != 0 or self.encoded_bytes != 0:
                raise ValueError("initial cursor has data")
        elif not self.page_index <= self.record_offset <= self.page_index * MAX_PAGE_RECORDS_V2:
            raise ValueError("cursor page/record counts differ")
        self._descriptor()


def _position(cursor: C09PageCursorV2) -> tuple:
    return (cursor.page_index, cursor.record_offset, cursor.encoded_bytes,
            cursor.record_chain, cursor.last_key)


def _page_digest(*, stream_id: str, page_index: int, record_offset: int,
                 record_count: int, encoded_bytes: int, previous_page_digest: str,
                 record_chain_before: str, record_chain_after: str,
                 first_key_digest: str, last_key_digest: str, payload_digest: str,
                 next_position: tuple) -> str:
    return _commit_digest(("sylanne3.c09.page.v2", stream_id, page_index,
        previous_page_digest, record_offset, record_count, encoded_bytes,
        record_chain_before, record_chain_after, first_key_digest, last_key_digest,
        payload_digest, next_position))


@dataclass(frozen=True, slots=True)
class C09CapturePageV2(_CommitmentV2):
    stream_id: str
    page_index: int
    record_offset: int
    record_count: int
    encoded_bytes: int
    previous_page_digest: str
    record_chain_before: str
    record_chain_after: str
    first_key_digest: str
    last_key_digest: str
    payload_digest: str
    next_cursor: C09PageCursorV2
    schema: str = "sylanne3.c09.capture_page.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.capture_page.v2")
        for name in ("stream_id", "previous_page_digest", "record_chain_before",
                     "record_chain_after", "first_key_digest", "last_key_digest",
                     "payload_digest"):
            _sha(getattr(self, name), name)
        for name in ("page_index", "record_offset", "record_count", "encoded_bytes"):
            _uint(getattr(self, name), name)
        if not 1 <= self.record_count <= MAX_PAGE_RECORDS_V2:
            raise ValueError("page must contain a bounded nonempty record batch")
        if not 1 <= self.encoded_bytes <= MAX_PAGE_BYTES_V2:
            raise ValueError("page payload exceeds proposed profile ceiling")
        c = self.next_cursor
        if (type(c) is not C09PageCursorV2 or c.stream_id != self.stream_id
                or c.page_index != self.page_index + 1
                or c.record_offset != self.record_offset + self.record_count
                or c.encoded_bytes < self.encoded_bytes
                or c.record_chain != self.record_chain_after
                or _commit_digest(c.last_key) != self.last_key_digest
                or c.previous_page_digest != self.digest):
            raise ValueError("page continuation differs")
        self._descriptor()

    @property
    def digest(self) -> str:
        return _page_digest(**{f.name: getattr(self, f.name) for f in fields(self)
                              if f.name not in ("schema", "next_cursor")},
                            next_position=_position(self.next_cursor))

    @property
    def page_digest(self) -> str:
        return self.digest


@dataclass(frozen=True, slots=True)
class C09CountOriginalV2(_CommitmentV2):
    stream_id: str
    record_count: int
    last_key: PrimaryKeyV2 | None
    eof_observation_digest: str
    original_ref: str
    original_digest: str
    schema: str = "sylanne3.c09.count_original.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.count_original.v2")
        for name in ("stream_id", "eof_observation_digest", "original_digest"):
            _sha(getattr(self, name), name)
        _text(self.original_ref, "original_ref")
        _uint(self.record_count, "record_count")
        _key(self.last_key, "last_key", optional=True)
        if (self.record_count == 0) != (self.last_key is None):
            raise ValueError("census EOF key/count differs")
        self._descriptor()


@dataclass(frozen=True, slots=True)
class C09CompleteStreamV2(_CommitmentV2):
    stream_id: str
    schema_digest: str
    record_count: int
    encoded_bytes: int
    page_count: int
    record_root: str
    page_root: str
    eof_observation_digest: str
    complete_count_original_ref: str
    complete_count_original_digest: str
    census_digest: str
    schema: str = "sylanne3.c09.complete_stream.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.complete_stream.v2")
        for name in ("stream_id", "schema_digest", "record_root", "page_root",
                     "eof_observation_digest", "complete_count_original_digest", "census_digest"):
            _sha(getattr(self, name), name)
        _text(self.complete_count_original_ref, "complete_count_original_ref")
        for name in ("record_count", "encoded_bytes", "page_count"):
            _uint(getattr(self, name), name)
        if self.page_count == 0:
            if self.record_count or self.encoded_bytes:
                raise ValueError("empty stream has data")
        elif not self.page_count <= self.record_count <= self.page_count * MAX_PAGE_RECORDS_V2:
            raise ValueError("complete page/record counts differ")
        self._descriptor()

    @property
    def stream_digest(self) -> str:
        return self.digest


def begin_c09_stream_v2(stream: C09StreamIdentityV2) -> C09PageCursorV2:
    if type(stream) is not C09StreamIdentityV2:
        raise TypeError("C09 V2 requires its exact stream identity")
    return C09PageCursorV2(stream.stream_id, 0, 0, 0,
        _commit_digest(("sylanne3.c09.page-chain.v2", stream.stream_id)),
        _commit_digest(("sylanne3.c09.record-chain.v2", stream)), None)


def _current_cursor(stream: C09StreamIdentityV2, cursor: C09PageCursorV2) -> None:
    if type(stream) is not C09StreamIdentityV2 or type(cursor) is not C09PageCursorV2:
        raise TypeError("C09 V2 requires exact stream and cursor types")
    if cursor.stream_id != stream.stream_id:
        raise ValueError("cursor belongs to a different frozen stream")
    if cursor.page_index == 0 and cursor != begin_c09_stream_v2(stream):
        raise ValueError("initial commitment roots differ")
    if cursor.last_key is not None:
        _stream_key(stream, cursor.last_key)


def append_c09_page_v2(stream: C09StreamIdentityV2, cursor: C09PageCursorV2,
                       records: tuple[C09CaptureRecordV2, ...]) -> C09CapturePageV2:
    """Commit one bounded page; the producer must load cursor from its own database."""
    _current_cursor(stream, cursor)
    if (type(records) is not tuple or not 1 <= len(records) <= MAX_PAGE_RECORDS_V2
            or any(type(r) is not C09CaptureRecordV2 for r in records)):
        raise ValueError("invalid bounded C09 records")
    stream_id = cursor.stream_id
    previous_key = cursor.last_key
    chain = cursor.record_chain
    # Sum individual encodings before making a combined payload allocation.
    size = 2 + len(records) - 1
    for ordinal, record in enumerate(records, cursor.record_offset + 1):
        _stream_key(stream, record.primary_key)
        if previous_key is not None and _key_order(record.primary_key) <= _key_order(previous_key):
            raise ValueError("record keys are repeated or out of order")
        size += len(_commit_serialize(record).encode("utf-8"))
        if size > MAX_PAGE_BYTES_V2:
            raise ValueError("page payload exceeds proposed profile ceiling")
        chain = _commit_digest(("sylanne3.c09.record.v2", stream_id,
                                  ordinal, chain, record))
        previous_key = record.primary_key
    payload_digest = _commit_digest(records)
    next_position = (cursor.page_index + 1, cursor.record_offset + len(records),
                     cursor.encoded_bytes + size, chain, previous_key)
    body = dict(stream_id=stream_id, page_index=cursor.page_index,
        record_offset=cursor.record_offset, record_count=len(records), encoded_bytes=size,
        previous_page_digest=cursor.previous_page_digest,
        record_chain_before=cursor.record_chain, record_chain_after=chain,
        first_key_digest=_commit_digest(records[0].primary_key),
        last_key_digest=_commit_digest(previous_key), payload_digest=payload_digest)
    page_digest = _page_digest(**body, next_position=next_position)
    next_cursor = C09PageCursorV2(stream_id, next_position[0], next_position[1],
                                next_position[2], page_digest, chain, previous_key)
    return C09CapturePageV2(**body, next_cursor=next_cursor)


def verify_c09_page_v2(stream: C09StreamIdentityV2, cursor: C09PageCursorV2,
                       page: C09CapturePageV2,
                       records: tuple[C09CaptureRecordV2, ...]) -> C09PageCursorV2:
    """Recompute the persisted boundary; never repaginate during cold verification."""
    if type(page) is not C09CapturePageV2:
        raise TypeError("unknown C09 page schema")
    expected = append_c09_page_v2(stream, cursor, records)
    if page != expected:
        raise ValueError("C09 page does not match source records and previous page")
    return page.next_cursor


def seal_c09_stream_v2(stream: C09StreamIdentityV2, cursor: C09PageCursorV2,
                       census: C09CountOriginalV2, *,
                       data_eof_observation_digest: str) -> C09CompleteStreamV2:
    """Bind independent census and actual data EOF; this function signs nothing."""
    _current_cursor(stream, cursor)
    if type(census) is not C09CountOriginalV2:
        raise TypeError("C09 V2 requires the exact census type")
    _sha(data_eof_observation_digest, "data_eof_observation_digest")
    if (census.stream_id != stream.stream_id or census.record_count != cursor.record_offset
            or census.last_key != cursor.last_key):
        raise ValueError("data scan does not cover the complete frozen census")
    eof_digest = _commit_digest(("sylanne3.c09.complete-eof.v2", stream.stream_id,
        census.eof_observation_digest, data_eof_observation_digest, cursor.digest))
    return C09CompleteStreamV2(stream.stream_id, stream.schema_digest,
        cursor.record_offset, cursor.encoded_bytes, cursor.page_index, cursor.record_chain,
        cursor.previous_page_digest, eof_digest, census.original_ref,
        census.original_digest, census.digest)


def verify_c09_complete_stream_v2(stream: C09StreamIdentityV2, cursor: C09PageCursorV2,
                                  census: C09CountOriginalV2, seal: C09CompleteStreamV2, *,
                                  data_eof_observation_digest: str) -> None:
    if type(seal) is not C09CompleteStreamV2:
        raise TypeError("unknown C09 complete-stream schema")
    expected = seal_c09_stream_v2(stream, cursor, census,
        data_eof_observation_digest=data_eof_observation_digest)
    if seal != expected:
        raise ValueError("C09 complete stream differs from independently verified pages")

@dataclass(frozen=True, slots=True)
class C09SealedStreamLocatorV2(_CommitmentV2):
    storage_role: str
    identity: C09StreamIdentityV2
    complete: C09CompleteStreamV2
    schema: str = "sylanne3.c09.sealed_stream_locator.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.c09.sealed_stream_locator.v2")
        if (self.storage_role not in ROLES_V2 or type(self.identity) is not C09StreamIdentityV2
                or type(self.complete) is not C09CompleteStreamV2
                or self.complete.stream_id != self.identity.stream_id
                or self.complete.schema_digest != self.identity.schema_digest):
            raise ValueError("sealed stream locator identity differs")
        self._descriptor()


_GRAPH_STREAM_FIELDS_V2 = (
    "schema_catalogue", "disposition_directory", "closure", "tombstones",
    "target_directory", "generated_directory",
)
_GRAPH_STREAM_KINDS_V2 = (
    frozenset({"schema_catalogue"}), frozenset({"row_dispositions"}),
    frozenset({"dependency_closure", "nested_closure"}), frozenset({"tombstones"}),
    frozenset({"target_rows"}), frozenset({"generated_rows"}),
)


@dataclass(frozen=True, slots=True)
class GraphRebaseCandidateV2(_CommitmentV2):
    scope: C09CaptureScopeV2
    source: C09FrozenRoleSourceV2
    target_path: str
    target_identity: tuple[int, int, int, int]
    target_file_sha256: str
    old_incarnation: str
    old_revision: int
    old_graph_epoch: int
    old_access_epoch: int
    old_delete_epoch: int
    new_incarnation: str
    new_graph_epoch: int
    new_access_epoch: int
    new_delete_epoch: int
    schema_catalogue: C09SealedStreamLocatorV2
    disposition_directory: C09SealedStreamLocatorV2
    closure: C09SealedStreamLocatorV2
    tombstones: C09SealedStreamLocatorV2
    target_directory: C09SealedStreamLocatorV2
    generated_directory: C09SealedStreamLocatorV2
    schema: str = "sylanne3.graph.c09_rebase_candidate.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.graph.c09_rebase_candidate.v2")
        if (type(self.scope) is not C09CaptureScopeV2
                or type(self.source) is not C09FrozenRoleSourceV2
                or self.source.role != "graph" or self.source.scope_digest != self.scope.scope_digest):
            raise ValueError("Graph candidate frozen source differs from its capture scope")
        for name in ("target_path", "old_incarnation", "new_incarnation"):
            _text(getattr(self, name), name)
        if self.old_incarnation == self.new_incarnation or self.target_path == self.source.source_path:
            raise ValueError("Graph candidate must have its distinct registered file and incarnation")
        if (type(self.target_identity) is not tuple or len(self.target_identity) != 4
                or any(type(n) is not int or n < 0 for n in self.target_identity)):
            raise ValueError("Graph candidate file identity differs")
        _sha(self.target_file_sha256, "target_file_sha256")
        for name in ("old_revision", "old_graph_epoch", "old_access_epoch", "old_delete_epoch",
                     "new_graph_epoch", "new_access_epoch", "new_delete_epoch"):
            _uint(getattr(self, name), name)
        for name, kinds in zip(_GRAPH_STREAM_FIELDS_V2, _GRAPH_STREAM_KINDS_V2, strict=True):
            locator = getattr(self, name)
            if (type(locator) is not C09SealedStreamLocatorV2 or locator.storage_role != "graph"
                    or locator.identity.scope_digest != self.scope.scope_digest
                    or locator.identity.role_source_digest != self.source.role_source_digest
                    or locator.identity.stream_kind not in kinds):
                raise ValueError("Graph candidate directory scope or kind differs: " + name)
        if len({getattr(self, name).identity.stream_id for name in _GRAPH_STREAM_FIELDS_V2}) != 6:
            raise ValueError("Graph candidate repeats a directory stream")
        self._descriptor()

    @property
    def candidate_digest(self) -> str:
        return self.digest


@dataclass(frozen=True, slots=True)
class GraphErasureRebaseCertificateV2(_CommitmentV2):
    candidate: GraphRebaseCandidateV2
    facts_pin_digest: str
    frozen_inventory_digest: str
    prior_certificate_schema_or_none: str | None
    prior_certificate_digest_or_none: str | None
    cold_read_digest: str
    schema: str = "sylanne3.graph.c09_erasure_rebase.v2"

    def __post_init__(self) -> None:
        self._schema("sylanne3.graph.c09_erasure_rebase.v2")
        if type(self.candidate) is not GraphRebaseCandidateV2:
            raise TypeError("Graph V2 certificate needs the exact compact candidate")
        for name in ("facts_pin_digest", "frozen_inventory_digest", "cold_read_digest"):
            _sha(getattr(self, name), name)
        prior = self.prior_certificate_digest_or_none
        if prior is None:
            if self.prior_certificate_schema_or_none is not None:
                raise ValueError("prior certificate schema without original digest")
        else:
            _sha(prior, "prior_certificate_digest")
            if self.prior_certificate_schema_or_none not in (
                    "sylanne3.graph.c09_erasure_rebase.v1", "sylanne3.graph.c09_erasure_rebase.v2"):
                raise ValueError("unknown historical C09 certificate schema")
        self._descriptor()

    @property
    def certificate_digest(self) -> str:
        return self.digest

_WIRE_TYPES_V2 = frozenset({
    C09CaptureScopeV2, C09FrozenRoleSourceV2, C09StreamIdentityV2, C09CaptureRecordV2,
    C09PageCursorV2, C09CapturePageV2, C09CountOriginalV2, C09CompleteStreamV2,
    C09SealedStreamLocatorV2, GraphRebaseCandidateV2, GraphErasureRebaseCertificateV2,
})


def c09_paged_value_to_wire_v2(value: _CommitmentV2) -> dict:
    """Closed plain-field representation, separate from canonical hash encoding."""
    if type(value) not in _WIRE_TYPES_V2:
        raise TypeError("unknown C09 V2 wire type")
    return asdict(value)


def c09_paged_value_from_wire_v2(raw: dict, cls: type) -> _CommitmentV2:
    """Decode an exact named V2 schema; no V1 fallback or authority is granted."""
    if cls not in _WIRE_TYPES_V2:
        raise TypeError("unknown C09 V2 wire type")
    if type(raw) is not dict or set(raw) != {f.name for f in fields(cls)}:
        raise ValueError("C09 wire fields differ")
    # The transport/SQLite producer must apply byte limits before JSON decoding.
    body = dict(raw)
    for name in ("primary_key", "last_key", "primary_key_columns", "primary_key_types", "target_identity"):
        if name in body and body[name] is not None:
            if type(body[name]) not in (list, tuple):
                raise ValueError(f"invalid wire {name}")
            body[name] = tuple(body[name])
    if cls is C09CapturePageV2:
        body["next_cursor"] = c09_paged_value_from_wire_v2(body["next_cursor"], C09PageCursorV2)
    if cls is C09SealedStreamLocatorV2:
        body["identity"] = c09_paged_value_from_wire_v2(body["identity"], C09StreamIdentityV2)
        body["complete"] = c09_paged_value_from_wire_v2(body["complete"], C09CompleteStreamV2)
    elif cls is GraphRebaseCandidateV2:
        body["scope"] = c09_paged_value_from_wire_v2(body["scope"], C09CaptureScopeV2)
        body["source"] = c09_paged_value_from_wire_v2(body["source"], C09FrozenRoleSourceV2)
        for name in _GRAPH_STREAM_FIELDS_V2:
            body[name] = c09_paged_value_from_wire_v2(body[name], C09SealedStreamLocatorV2)
    elif cls is GraphErasureRebaseCertificateV2:
        body["candidate"] = c09_paged_value_from_wire_v2(body["candidate"], GraphRebaseCandidateV2)
    return cls(**body)