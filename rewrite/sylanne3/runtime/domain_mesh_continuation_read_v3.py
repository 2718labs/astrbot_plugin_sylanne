"""Fixed same-Work tick metadata and public cold-page DTOs; no authority is issued here."""
from dataclasses import dataclass
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId
from ..runtime_storage_v3 import begin_runtime_cell_read_v3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .domain_mesh_contract_v1 import SemanticTickV1, TICK_TYPE, RECIPES
from .domain_mesh_tick_v1 import decode_semantic_tick_v1, semantic_tick_key_v1
from .source_correction_read_v3 import _heap


@dataclass(frozen=True, slots=True)
class SemanticRecoveryPageSelectorV1:
    namespace: NamespaceId
    installation_id: str
    after_token: str = ""
    through_token: str | None = None

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId or type(self.installation_id) is not str or not self.installation_id:
            raise ValueError("semantic recovery selector requires the actual installed namespace")
        for value in (self.after_token, self.through_token):
            if value is None or value == "":
                continue
            key = AtomKey.from_token(value)
            if (len(value) > 4096 or key.type_name != TICK_TYPE
                    or NamespaceId.from_key(key) != self.namespace):
                raise ValueError("semantic recovery cursor crossed its fixed family or namespace")
        if self.after_token and self.through_token is None:
            raise ValueError("continued recovery page must retain its first-page watermark")
        if self.through_token is not None and self.after_token > self.through_token:
            raise ValueError("semantic recovery cursor passed its immutable round watermark")


@dataclass(frozen=True, slots=True)
class SemanticTickMetadataRowV1:
    ref: str
    revision: int
    valid: bool
    disposition: str
    tick: SemanticTickV1


@dataclass(frozen=True, slots=True)
class SemanticRecoveryObservationV1:
    tick_ref: str
    tick_revision: int
    recipe_version: str
    producer_operation_id: str
    causal_original_ref: str
    original_deadline_utc: float
    status: str
    wait_reason: str | None
    dependency_refs: tuple[str, ...]
    original_effect_refs: tuple[str, ...]

    def __post_init__(self):
        if (self.recipe_version not in RECIPES
                or self.status not in ("observed", "completed", "waiting", "unknown", "expired", "invalid", "unavailable")
                or type(self.tick_revision) is not int or self.tick_revision < 1
                or AtomKey.from_token(self.tick_ref).type_name != TICK_TYPE):
            raise ValueError("recovery observation is an exact status locator, never a body or permission")
        for value in (self.dependency_refs, self.original_effect_refs):
            if type(value) is not tuple or len(value) > 128 or any(type(ref) is not str or not ref for ref in value):
                raise ValueError("recovery observation locator set is not bounded")
        if self.status in ("waiting", "unknown", "expired", "invalid", "unavailable") and not self.wait_reason:
            raise ValueError("unresolved recovery requires its concrete original wait reason")


@dataclass(frozen=True, slots=True)
class SemanticRecoveryPageV1:
    namespace: NamespaceId
    after_token: str
    through_token: str
    next_token: str | None
    complete: bool
    observations: tuple[SemanticRecoveryObservationV1, ...]

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or type(self.complete) is not bool
                or type(self.observations) is not tuple or len(self.observations) > 16
                or any(type(row) is not SemanticRecoveryObservationV1 for row in self.observations)
                or self.complete != (self.next_token is None)):
            raise ValueError("semantic page preserves its fixed bounded round and actual EOF")
        for row in self.observations:
            if NamespaceId.from_key(AtomKey.from_token(row.tick_ref)) != self.namespace:
                raise ValueError("semantic recovery observations crossed namespace")


class _SemanticTickMetadataTaskV3:
    def __init__(self, reader, selector):
        if type(selector) is not SemanticRecoveryPageSelectorV1 or selector.namespace != reader.namespace:
            raise ValueError("tick metadata phase requires its actual reader namespace")
        installed = reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
        if (selector.installation_id, selector.namespace) != (installed.installation_id, installed.namespace):
            raise ValueError("tick metadata phase crossed its actual installed package")
        self.reader, self.selector = reader, selector
        self.cursor, self.through_token = selector.after_token, selector.through_token
        self.phase = "watermark" if self.through_token is None else "head"
        self.rows, self.row = [], None
        self.cell = self.parser = None
        self.body = bytearray()
        self.complete, self.coverage, self.next = False, None, None
        self.retained = 0
        self.reserve(65536)

    def reserve(self, extra=0):
        amount = _heap((self.rows, self.row, self.body)) + extra + 65536
        if amount > self.retained:
            self.reader.operation.retain(amount - self.retained)
            self.retained = amount

    def seal(self, complete):
        self.complete = True
        self.coverage = "round_eof" if complete else "bounded_page"
        self.next = None if complete else self.cursor
        self.phase = "complete"
        self.rows = tuple(self.rows)
        self.reserve()

    def advance(self, meter):
        reader, ns = self.reader, self.reader.namespace
        reader.require_current(meter=meter)
        if self.phase == "watermark":
            row = meter.read_fixed_row(reader.db, "graph_atoms", ("token",),
                "bot=? AND persona=? AND type_name=? ORDER BY token DESC",
                (*ns.as_tuple, TICK_TYPE))
            self.through_token = "" if row is None else row[0]
            self.phase = "head"
            return
        if self.phase == "head":
            self.row = meter.read_fixed_row(reader.db, "graph_atoms",
                ("token", "revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND type_name=? AND token>? AND token<=? ORDER BY token",
                (*ns.as_tuple, TICK_TYPE, self.cursor, self.through_token))
            if self.row is None:
                self.seal(True)
                return
            self.row = tuple(self.row)
            header = meter.read_fixed_row(reader.db, "segmented_cells_v1", ("total_bytes",),
                "cell_id=?", (self.row[3],))
            if header is None or type(header[0]) is not int or not 0 < header[0] <= 65536:
                raise AuthorityUnavailable("tick locator has no actual bounded metadata cell")
            if self.rows and _heap(self.rows) + header[0] * 10 + 65536 > 8 * 1024 * 1024:
                self.seal(False)
                return
            self.reserve(header[0] * 10 + 65536)
            self.cell = begin_runtime_cell_read_v3(reader.db, self.row[3],
                erasure_owner_ref=self.row[0], meter=meter)
            self.parser = C09CanonicalJSONStreamV2()
            self.phase = "body"
            return
        if self.phase == "body":
            fragment = self.cell.read_fragment(meter=meter)
            if fragment is not None:
                self.parser.feed(fragment, lambda event: None)
                self.body.extend(fragment)
                return
            self.cell.finish(meter=meter)
            self.parser.finish()
            tick = decode_semantic_tick_v1(json.loads(self.body))
            if (tick.namespace != ns or self.row[0] != semantic_tick_key_v1(ns, tick.activity_id,
                    tick.causal_original.original_ref, tick.recipe_version).token):
                raise AuthorityUnavailable("tick metadata crossed its exact actual producer locator")
            disposition = ("invalid_tick" if not self.row[2] else
                "original_deadline_expired" if reader.initial_now_utc >= tick.original_deadline_utc else
                "current_locator")
            self.rows.append(SemanticTickMetadataRowV1(self.row[0], self.row[1],
                bool(self.row[2]), disposition, tick))
            self.cursor = self.row[0]
            self.cell = self.parser = None
            self.body.clear()
            self.phase = "head"
            self.reserve()
            if len(self.rows) == 16:
                self.seal(False)


def begin_semantic_tick_metadata_v3(reader, selector):
    return _SemanticTickMetadataTaskV3(reader, selector)


def metadata_recovery_observation_v1(row):
    if type(row) is not SemanticTickMetadataRowV1:
        raise TypeError("actual fixed metadata row required")
    tick = row.tick
    if row.disposition == "original_deadline_expired":
        status, reason = "expired", "original_tick_deadline_expired_metadata_only"
    elif row.disposition == "invalid_tick":
        status, reason = "invalid", "current_tick_invalidated_requires_actual_dependency"
    else:
        status, reason = "waiting", "current_original_body_observation_required"
    dependencies = tuple(v.original_ref for v in tick.predecessors)
    effects = tuple(p.original_ref for p in tick.pending if p.kind in ("effect", "call", "financial"))
    return SemanticRecoveryObservationV1(row.ref, row.revision, tick.recipe_version,
        tick.producer_operation_id, tick.causal_original.original_ref,
        tick.original_deadline_utc, status, reason, dependencies, effects)
