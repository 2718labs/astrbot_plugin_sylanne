"""Named D11 labor Source Work on the actual claim/adoption fence.

A signed C metadata original is read before Source qualification. Prepared
Source copies and read-row bodies are opened only after all original audience
and purpose groups have passed the existing Authority Source kernel.
"""
from dataclasses import dataclass
from datetime import datetime
from weakref import WeakKeyDictionary
import json

from .contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime.d11_character_work_segment_v1 import (
    BODY_KIND, ADMISSION_KIND, PREPARED_METADATA_KIND,
    character_labor_prepared_metadata_from_wire_v1,
    character_labor_admission_from_wire_v1, labor_body_preparation_from_wire_v1,
)
from ..runtime.d11_life_contract_v1 import D11LifeExecutionBindingV1

_READERS = WeakKeyDictionary()
_SELECTIONS = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class CharacterLaborSourceReadRequestV1:
    binding: D11LifeExecutionBindingV1
    labor_admission_original_ref: str
    labor_admission_digest: str | None
    phase: str = "claim"

    def __post_init__(self):
        if (type(self.binding) is not D11LifeExecutionBindingV1
                or self.phase not in {"claim", "adoption"}
                or self.labor_admission_original_ref != "character-labor-admission:" + self.binding.execution_id
                or self.labor_admission_digest is not None and (type(self.labor_admission_digest) is not str
                    or len(self.labor_admission_digest) != 64
                    or any(c not in "0123456789abcdef" for c in self.labor_admission_digest))):
            raise ValueError("named labor Source request needs its actual binding and persisted C original")


def _actual(work):
    if type(work.request) is CharacterLaborAckMetadataRequestV1:
        return _require_character_labor_ack_work_v1(work)
    from .current_authority_graph_read_v3 import (
        AuthorityGraphReadWorkV3, require_actual_authority_graph_attachment_owner_v3)
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    if (type(work) is not AuthorityGraphReadWorkV3 or type(work.service) is not AuthorityD11LifeServiceV1
            or type(work.request) is not CharacterLaborSourceReadRequestV1
            or work.controller.kind != "character_labor" or work.controller.service is not work.service
            or work.controller.fences is not work.service.fences
            or work.controller.location is not work.service.current_source_location
            or work.namespace != work.service.namespace
            or work.controller.location._graph_db_path != work.service.graph_path
            or work.permit.namespace != work.service.bridge.namespace
            or work.permit.subject != work.subject or work.credential is not work.service.credential):
        raise AuthorityUnavailable("labor Source requires its actual installed D11 service/Work/namespace")
    binding = work.request.binding
    if (binding.namespace != work.namespace or binding.installation_id != work.service.installation_id
            or binding.manifest_digest != work.service.manifest_digest
            or binding.authority_namespace != work.permit.namespace
            or binding.activation_generation != work.permit.generation
            or work.request.phase == "claim" and (work.permit.operation != "write"
                or work.permit.operation_id != work.service._gate_id(binding, "claim"))
            or work.request.phase == "adoption" and work.permit.operation not in {"write", "accounting"}):
        raise AuthorityUnavailable("labor Source crossed its actual same claim or current adoption fence")
    require_actual_authority_graph_attachment_owner_v3(work, db=work.db)
    return work


def character_labor_namespace_reader_v1(work, *, catalogue, catalogue_hash):
    from .current_authority_graph_read_v3 import _AuthorityNamespaceReadV3
    from ..domains.d06 import SOURCE_CORRECTION_HEAD_TYPE
    _actual(work)
    if type(work.request) is CharacterLaborAckMetadataRequestV1:
        class _LaborAckNamespaceReadV1(_AuthorityNamespaceReadV3):
            def _next(self,meter):
                row = meter.read_fixed_row(self.db,"graph_atoms",("token","revision","valid","type_name","value_cell_id"),
                    "bot=? AND persona=? AND token>? ORDER BY token",(*self.namespace.as_tuple,self.cursor))
                if row is None:
                    if self._epochs(meter) != self.authority_epochs:
                        raise AuthorityUnavailable("labor ACK namespace headers changed before complete EOF")
                    self.graph_eof = True
                    self._graph_eof_v3()
                    return
                token,revision,valid,type_name,cell = row
                key = AtomKey.from_token(token)
                spec = self.catalogue.get(type_name)
                if (NamespaceId.from_key(key) != self.namespace or key.type_name != type_name
                        or spec is None or key.owner.kind not in spec[0]
                        or type(revision) is not int or revision < 1 or valid not in (0,1) or cell is None):
                    raise AuthorityUnavailable("labor ACK header differs from the actual installed catalogue")
                self.cursor = token
                self.heads[token] = (revision,valid,cell)
                self.root = canonical_digest((self.leaf_schema,self.root,token,revision,valid,type_name,cell))
                self.count += 1
        reader = _LaborAckNamespaceReadV1(work,catalogue=catalogue,catalogue_hash=catalogue_hash)
        reader.projection_types = frozenset()
        reader.census_schema = "d11.character-labor-ack-head-census.v1"
        reader.leaf_schema = "d11.character-labor-ack-head-leaf.v1"
        reader.root = canonical_digest((reader.census_schema,work.namespace,work.graph_stamp,catalogue_hash))
        return reader
    reader = _AuthorityNamespaceReadV3(work, catalogue=catalogue, catalogue_hash=catalogue_hash)
    # All heads and origins still participate in the original complete census.
    # Only ACL/correction metadata is retained before SourceALL.
    reader.projection_types = frozenset(("memory.access", SOURCE_CORRECTION_HEAD_TYPE))
    return reader


class _SignedOriginal:
    def __init__(self, reader, kind, ref):
        self.reader, self.work, self.kind, self.ref = reader, reader.work, kind, ref
        from ..runtime.d11_life_preparation_v1 import TABLE
        from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3
        self.request = (TABLE, ("producing_operation_id", "payload_json", "payload_digest", "signature"),
            ("bot", "persona", "kind", "original_ref"), (*self.work.namespace.as_tuple, kind, ref))
        self.attachment = _HostProducerAttachmentV3(self.work, self.request)
        self.complete = False
        self.raw = self.digest = self.producer = None

    def advance(self, meter):
        from ..runtime.d11_life_preparation_v1 import SIGN_KIND
        self.reader.require_current(meter)
        self.attachment.advance(meter)
        if not self.attachment.complete:
            return
        row = self.attachment.require_row_v3(self.work, meter)
        if row is None:
            if self.kind == PREPARED_METADATA_KIND:
                self.complete = True
                return
            raise AuthorityUnavailable("labor Source is missing its formally produced signed metadata original")
        raw = self.attachment.json_columns["payload_json"].require_v3(self.work)
        column = self.attachment.json_columns["payload_json"]
        if column.sha256 != row[2]:
            raise AuthorityUnavailable("labor original lost canonical full EOF/digest")
        from ..runtime.d11_character_labor_accounting_v1 import KIND as BASIS_KIND, SIGN_KIND as BASIS_SIGN_KIND
        signature_kind = BASIS_SIGN_KIND if self.kind == BASIS_KIND else SIGN_KIND
        self.work.service.issuer._signer.verify(signature_kind,
            canonical_serialize((self.work.namespace, self.kind, self.ref, row[2])), row[3])
        self.work.attachments[self.request] = self.attachment
        self.raw, self.producer, self.digest, self.complete = raw, row[0], row[2], True


class _MetadataPoint:
    def __init__(self, reader, request):
        from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3
        self.reader, self.request = reader, request
        self.attachment = _HostProducerAttachmentV3(reader.work, request)
        self.complete = False

    def advance(self, meter):
        self.reader.require_current(meter)
        self.attachment.advance(meter)
        if self.attachment.complete:
            self.attachment.require_row_v3(self.reader.work, meter)
            self.reader.work.attachments[self.request] = self.attachment
            self.complete = True


class _LaborSourceSelection:
    def __init__(self, reader, audience, position):
        self.reader, self.work, self.audience = reader, reader.work, audience
        self.roots = reader.metadata.source_roots
        self.root = reader.metadata.plan.input_source.ref
        self.attention, self.purpose, self.maximum_ancestors = None, "context", 256
        self.position = position
        _SELECTIONS[self] = (reader, self.work, audience, position, self.roots,
            self.work.operation, self.work.scope, self.work.selection_digest)

    def require_v3(self, work):
        if (_SELECTIONS.get(self) != (self.reader, self.work, self.audience, self.position,
                self.roots, work.operation, work.scope, work.selection_digest)
                or work is not self.work or _READERS.get(work) is not self.reader):
            raise AuthorityUnavailable("labor Source selection lost its actual Work/original root metadata")
        _actual(work)
        return self


def _source_reader(reader, selection):
    from .current_authority_graph_read_v3 import _AuthoritySourceMaterialReadV3
    class LaborSourceMaterialReadV1(_AuthoritySourceMaterialReadV3):
        def __init__(self):
            super().__init__(reader.work, selection)
            self.pending = [(ref, False, purpose) for ref in selection.roots
                for purpose in ("context", "consolidation")]

        def _body_refs_v3(self):
            # Every audience's full ancestors and purpose groups must pass
            # before the final group may open the actual root Source bodies.
            return selection.roots if selection.position == len(reader.metadata.plan.audiences) - 1 else ()
    return LaborSourceMaterialReadV1()


class _LegacyFixedSelectionV1:
    __slots__ = ("work", "header")
    def __init__(self, work, header):
        self.work, self.header = work, header


class CharacterLaborSourceReadV1:
    def __init__(self, work):
        _actual(work)
        self.work, self.phase, self.complete = work, "metadata", False
        self.metadata = self.admission = self.body = self.prepared = None
        self.resolved_admission = self.legacy = None
        self.census_reader = self.census = None
        self.scope_metadata,self.scope_columns = {},{}
        self.scope_column = None
        self.scope_selected,self.scope_roots = frozenset(),frozenset()
        self.semantic_scope = None
        self.scope_body_refs,self.scope_body_position = [],0
        self.column = _SignedOriginal(self, PREPARED_METADATA_KIND,
            "character-labor-prepared-metadata:" + work.request.binding.execution_id)
        self.points = []
        self.point = None
        self.groups = []
        self.group = None
        self.selection = None
        self.position = 0
        self.graph_rows = []
        self.graph_position = 0
        self.source_material = None
        self.reserved = 0
        _READERS[work] = self
        self.identity = (work.controller, work.service, work.request, work.permit, work.operation,
            work.scope, work.selection_digest, work.deadline_utc)

    def require_current(self, meter):
        _actual(self.work)
        current = (self.work.controller, self.work.service, self.work.request, self.work.permit,
            self.work.operation, self.work.scope, self.work.selection_digest, self.work.deadline_utc)
        if _READERS.get(self.work) is not self or self.identity != current:
            raise AuthorityUnavailable("labor reader changed actual installed Source Work identity")
        self.work.require_current(meter=meter)
        if self.work.request.phase == "claim" and self.metadata is not None:
            expiry = datetime.fromisoformat(self.metadata.binding.deadline_utc.replace("Z", "+00:00")).timestamp()
            if self.work.now_utc >= min(expiry, self.admission.expires_at_utc if self.admission is not None else expiry):
                raise AuthorityUnavailable("labor Source cannot renew the original claim deadline")

    def _reserve(self):
        from ..runtime.source_correction_read_v3 import _heap
        amount = _heap((self.metadata, self.admission, self.body, self.prepared,
            self.points, self.graph_rows,self.scope_metadata,self.scope_selected,self.scope_body_refs)) + 131072
        if amount > self.reserved:
            self.work.operation.retain(amount - self.reserved)
            self.reserved = amount

    def _memberships(self, metadata):
        # Actual immutable W01 memberships, not a signature alone.
        ns = self.work.namespace
        return [
            ("graph_bundle_operations", ("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"),
                ("bot", "persona", "operation_id"), (*ns.as_tuple, metadata.binding.prepare_operation_id)),
            ("graph_events", ("reads", "revisions", "epoch_revision"),
                ("bot", "persona", "session", "event_id"),
                (*ns.as_tuple, metadata.binding.activity_id, metadata.binding.prepare_operation_id)),
        ]

    def _verify_metadata(self, meter):
        from ..runtime.domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
        metadata, request, work = self.metadata, self.work.request, self.work
        _require_owner_metadata(work, metadata)
        bundle, event = self.points
        receipt = reconstruct_graph_bundle_commit_receipt_v1(work.namespace,
            metadata.binding.prepare_operation_id, bundle.attachment.row, event.attachment.row)
        if (canonical_digest(receipt) != metadata.receipt_digest
                or receipt.invalidated_epochs[0].revision != metadata.graph_epoch
                or self.admission.binding_digest != metadata.binding.digest
                or self.admission.prepared_original_ref != metadata.prepared_ref
                or self.admission.admission_ref != request.labor_admission_original_ref
                or self.body.action_operation_id != metadata.binding.operation_id
                or self.admission.body_preparation_digest != canonical_digest(plain_v1(self.body))
                or self.admission.policy_digest != canonical_digest(plain_v1(self.body.policy))
                or self.admission.quote_digest != canonical_digest(self.body.quote)
                or self.metadata.binding != request.binding):
            raise AuthorityUnavailable("labor metadata lost actual C/sidecar/B/receipt cross-binding")
        if work.request.phase == "claim":
            from ..runtime.d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE
            policy = meter.read_fixed_row(work.db, "graph_d02_production_policies_v1",
                ("revision", "payload_digest", "kind"),
                "bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC",
                (*work.namespace.as_tuple, self.body.policy.policy_ref))
            clock = meter.read_fixed_row(work.db, CLOCK_TABLE, ("revision", "original_digest"),
                "bot=? AND persona=? ORDER BY revision DESC", work.namespace.as_tuple)
            clock_ref = json.loads(metadata.clock_original_json)
            if (policy != (self.body.policy.revision, self.admission.policy_digest, "labor")
                    or clock != (self.body.quote.clock_mapping_version, clock_ref["original_digest"])):
                raise AuthorityUnavailable("labor current installed policy or Owner clock changed after C")
            expected = {v.ref: v.version for v in metadata.read_versions}
            for token, revision in expected.items():
                head = work.heads.get(token)
                if revision == 0:
                    if head is not None:
                        raise AuthorityUnavailable("labor metadata negative read became present")
                elif head is None or head[0] != revision:
                    raise AuthorityUnavailable("labor metadata is no longer the exact current plan read-set")

    def advance(self, meter):
        self.require_current(meter)
        work = self.work
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:
                return
            original, self.column = self.column, None
            if self.phase == "metadata":
                if original.raw is None:
                    self.phase = "legacy_selector"
                    return
                self.metadata = character_labor_prepared_metadata_from_wire_v1(original.raw)
                if (self.metadata.namespace != work.namespace or self.metadata.binding != work.request.binding
                        or original.producer != self.metadata.binding.prepare_operation_id
                        or self.metadata.labor_admission_ref != work.request.labor_admission_original_ref
                        or work.request.labor_admission_digest is not None
                            and self.metadata.labor_admission_digest != work.request.labor_admission_digest):
                    raise AuthorityUnavailable("bodyless labor metadata changed this exact actual request")
                self.points = [_MetadataPoint(self, point) for point in self._memberships(self.metadata)]
                self.phase = "memberships"
            elif self.phase == "admission":
                if (original.digest != self.metadata.labor_admission_digest
                        or set(original.raw) != {"schema", "admission", "body_preparation_digest", "receipt_digest"}
                        or original.raw["schema"] != "d11.character-labor-admission-original.v1"
                        or original.producer != self.metadata.binding.prepare_operation_id
                        or original.raw["receipt_digest"] != self.metadata.receipt_digest):
                    raise AuthorityUnavailable("labor Source C sidecar is not the actual same-C original")
                self.admission = character_labor_admission_from_wire_v1(original.raw["admission"])
                ref = self.metadata.plan.labor_body_preparation_original
                self.column = _SignedOriginal(self, BODY_KIND, ref.original_ref)
                self.phase = "body_preparation"
            elif self.phase == "body_preparation":
                ref = self.metadata.plan.labor_body_preparation_original
                self.body = labor_body_preparation_from_wire_v1(original.raw)
                if (original.digest != ref.original_digest
                        or original.producer != self.body.body_prepare_operation_id
                        or self.body.namespace != work.namespace
                        or self.body.recipe_ref != self.metadata.plan.recipe.ref
                        or self.body.recipe_revision != self.metadata.plan.recipe.revision
                        or self.body.recipe_digest != self.metadata.plan.recipe.digest):
                    raise AuthorityUnavailable("labor Source selected a different actual first combined reservation")
                self._verify_metadata(meter)
                self.phase = "scope_metadata" if work.request.phase == "claim" else "need_census"
            elif self.phase == "prepared_body":
                from ..runtime.d11_life_preparation_v1 import life_prepared_from_wire_v1, D11CharacterLaborLifePreparedV1
                self.prepared = life_prepared_from_wire_v1(original.raw)
                if (type(self.prepared) is not D11CharacterLaborLifePreparedV1
                        or original.digest != self.metadata.prepared_digest
                        or self.prepared.binding != self.metadata.binding
                        or self.prepared.plan != self.metadata.plan
                        or self.prepared.labor_admission_digest != self.metadata.labor_admission_digest):
                    raise AuthorityUnavailable("labor Prepared full Body EOF differs from actual signed metadata")
                self.graph_rows = list(self.prepared.read_rows)
                self.phase = "current_rows"
            self._reserve()
            return
        if self.phase == "scope_metadata":
            from ..runtime.d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
            if self.scope_column is not None:
                column = self.scope_column
                column.advance(meter)
                if not column.complete:
                    return
                self.scope_metadata[column.graph_key.token] = column.require_v3(work)
                self.scope_columns[column.graph_key.token] = column
                self.scope_column = None
                self._reserve()
                return
            for token,head in sorted(work.heads.items()):
                key = AtomKey.from_token(token)
                if key.type_name in LIFE_CURRENT_TYPES and token not in self.scope_metadata:
                    if sum(AtomKey.from_token(v).type_name == key.type_name for v in work.heads) > 128:
                        raise AuthorityUnavailable("labor scope exceeds its original full family metadata bound")
                    self.scope_column = _LaborScopeMetadataColumnV1(self,key,head)
                    return
            _complete_authority_labor_scope_v1(self)
            self.phase = "need_census"
            return
        if self.phase in {"need_census", "census_finalize"}:
            return
        if self.phase == "census_metadata":
            self.census_reader.advance(meter)
            if self.census_reader.complete:
                self.phase = "census_finalize"
            return
        if self.phase == "memberships":
            for point in self.points:
                if not point.complete:
                    point.advance(meter)
                    return
            from ..runtime.domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
            receipt = reconstruct_graph_bundle_commit_receipt_v1(work.namespace,
                self.metadata.binding.prepare_operation_id,
                self.points[0].attachment.row, self.points[1].attachment.row)
            if canonical_digest(receipt) != self.metadata.receipt_digest:
                raise AuthorityUnavailable("labor control locator lacks its actual C W01 membership")
            self.resolved_admission = (self.metadata.labor_admission_ref, self.metadata.labor_admission_digest)
            self.column = _SignedOriginal(self, ADMISSION_KIND, self.resolved_admission[0])
            self.phase = "admission"
            return
        if self.phase == "legacy_selector":
            from ..runtime.d11_life_preparation_v1 import TABLE, SIGN_KIND
            key = (*work.namespace.as_tuple, work.request.binding.prepared_original_ref)
            rows = []
            for kind in ("prepared", "character_labor_prepared_v1"):
                row = meter.read_fixed_row(work.db, TABLE,
                    ("producing_operation_id", "payload_digest", "signature"),
                    "bot=? AND persona=? AND original_ref=? AND kind=?", (*key, kind))
                if row is not None:
                    work.service.issuer._signer.verify(SIGN_KIND, canonical_serialize((work.namespace,
                        kind, key[-1], row[1])), row[2])
                    rows.append((kind, row))
            if (len(rows) != 1 or rows[0][0] != "prepared"
                    or rows[0][1][0] != work.request.binding.prepare_operation_id
                    or work.request.labor_admission_digest is not None):
                raise AuthorityUnavailable("new/orphan/conflicting labor Prepared cannot fall back to legacy Fixed")
            self.legacy = _LegacyFixedSelectionV1(work, rows[0][1])
            self.complete = True
            return
        if self.phase == "sources":
            if self.group is None:
                if self.position == len(self.metadata.plan.audiences):
                    self.source_material = self.groups[-1].proof
                    self.column = _SignedOriginal(self, "character_labor_prepared_v1", self.metadata.prepared_ref)
                    self.phase = "prepared_body"
                    return
                self.selection = _LaborSourceSelection(self, self.metadata.plan.audiences[self.position], self.position)
                self.group = _source_reader(self, self.selection)
            self.group.advance_v3(meter)
            if self.group.complete:
                self.groups.append(self.group); self.group = None; self.position += 1
            return
        if self.phase == "current_rows":
            if self.point is not None:
                self.point.advance(meter)
                if not self.point.complete:
                    return
                row = self.graph_rows[self.graph_position]
                actual = self.point.attachment.row
                if row.revision == 0:
                    if actual is not None:
                        raise AuthorityUnavailable("labor negative Graph read became present")
                elif (actual is None or actual[0] != row.revision or bool(actual[2]) != row.valid
                        or json.loads(actual[1]) != json.loads(row.value_json)):
                    raise AuthorityUnavailable("actual current labor Graph Body differs from its frozen read commitment")
                from .current_authority_graph_read_v3 import _adopt_authority_atom_attachment_v3
                if actual is not None:
                    _adopt_authority_atom_attachment_v3(work, self.point.attachment)
                self.point = None; self.graph_position += 1
                return
            if self.graph_position == len(self.graph_rows):
                frozen = {row.ref for row in self.graph_rows}
                self.scope_body_refs = sorted(self.scope_selected-frozen)
                self.phase = "scope_bodies"
                return
            row = self.graph_rows[self.graph_position]
            key = AtomKey.from_token(row.ref)
            if key.type_name == "memory.source":
                witness = work.sources.get(row.ref)
                record = self.source_material.source_records.get(row.ref)
                if (witness is None or record is None or witness.revision != row.revision
                        or witness.valid != row.valid
                        or canonical_digest(json.loads(row.value_json)) != witness.canonical_semantic_digest):
                    raise AuthorityUnavailable("labor root Source Body differs from actual qualified Source metadata")
                character_labor_source_atom_v1(work, row.ref)
                self.graph_position += 1
                return
            self.point = _MetadataPoint(self, ("graph_atoms", ("revision", "value", "valid"),
                ("token", "bot", "persona"), (row.ref, *work.namespace.as_tuple)))
            return
        if self.phase == "scope_bodies":
            if self.point is not None:
                self.point.advance(meter)
                if not self.point.complete:
                    return
                token = self.scope_body_refs[self.scope_body_position]
                row = self.point.attachment.require_row_v3(work,meter)
                head = work.heads[token]
                if row is None or (row[0],bool(row[2])) != (head[0],bool(head[1])):
                    raise AuthorityUnavailable("labor selected current scope Body changed after its metadata EOF")
                from .current_authority_graph_read_v3 import _adopt_authority_atom_attachment_v3
                _adopt_authority_atom_attachment_v3(work,self.point.attachment)
                self.point = None;self.scope_body_position += 1
                return
            if self.scope_body_position == len(self.scope_body_refs):
                self.complete = True
                return
            token = self.scope_body_refs[self.scope_body_position]
            self.point = _MetadataPoint(self,("graph_atoms",("revision","value","valid"),
                ("token","bot","persona"),(token,*work.namespace.as_tuple)))
            return
        raise AuthorityUnavailable("unregistered character-labor Source read phase")


def advance_character_labor_source_v1(work, meter):
    if type(work.request) is CharacterLaborAckMetadataRequestV1:
        return _advance_character_labor_ack_metadata_v1(work,meter)
    reader = _READERS.get(work)
    if reader is None:
        reader = CharacterLaborSourceReadV1(work)
    reader.advance(meter)
    if reader.complete:
        work.phase = "validate"
    return reader


def require_character_labor_source_result_v1(service, work):
    _actual(work)
    reader = _READERS.get(work)
    if (work.service is not service or reader is None or not reader.complete
            or work.request.phase != "claim" or reader.prepared is None):
        raise AuthorityUnavailable("labor claim requires its actual complete SourceALL and new Prepared EOF")
    return reader.prepared, reader.admission, reader.body


def require_character_labor_source_metadata_v1(service, work):
    _actual(work)
    reader = _READERS.get(work)
    if work.service is not service or reader is None or not reader.complete:
        raise AuthorityUnavailable("labor metadata requires its actual same-fence complete EOF")
    return reader.metadata, reader.admission, reader.body


def release_character_labor_source_v1(work):
    _release_character_labor_ack_metadata_owner_v1(work)
    from .character_labor_census_v1 import release_character_labor_source_census_v1
    from .character_labor_body_readers_v1 import release_authority_character_labor_body_readers_v1
    release_authority_character_labor_body_readers_v1(work)
    release_character_labor_source_census_v1(work)
    _OWNER_OBSERVATIONS.pop(work, None)
    reader = _READERS.pop(work, None)
    if reader is None:
        return
    for selection in tuple(_SELECTIONS):
        if selection.work is work:
            _SELECTIONS.pop(selection, None)
    reader.prepared = reader.body = reader.metadata = reader.admission = None
    reader.points.clear(); reader.groups.clear(); reader.graph_rows.clear()
    reader.column = reader.point = reader.group = reader.source_material = None
    reader.census_reader = reader.census = None
    reader.scope_metadata.clear();reader.scope_columns.clear();reader.scope_body_refs.clear()
    reader.scope_column = reader.semantic_scope = None
    reader.scope_selected = reader.scope_roots = frozenset()



def character_labor_source_outcome_v1(service, work):
    _actual(work)
    reader = _READERS.get(work)
    if reader is None or not reader.complete or work.service is not service:
        raise AuthorityUnavailable("labor family selector has no actual same-Work complete outcome")
    if reader.legacy is not None:
        return reader.legacy
    if work.request.phase == "adoption":
        return require_character_labor_source_metadata_v1(service, work)
    return require_character_labor_source_result_v1(service, work)


def require_character_labor_legacy_selection_v1(value, *, service, work):
    _actual(work)
    reader = _READERS.get(work)
    if (type(value) is not _LegacyFixedSelectionV1 or value.work is not work
            or reader is None or reader.legacy is not value or work.service is not service):
        raise AuthorityUnavailable("legacy Fixed selection requires its actual unique authenticated old kind")
    return value.header

def character_labor_source_family_v1(db, *, namespace, roots, purpose, audiences, records=False):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from ..memory_types import source_key, access_key
    from ..domains.d06 import source_correction_head_key
    work = _authority_attachment_owner_v3(db)
    if work is None or work.controller.kind != "character_labor":
        return None
    _actual(work)
    reader = _READERS.get(work)
    if (reader is None or work.request.phase != "claim" or not db.in_transaction
            or namespace != work.namespace or purpose not in {"context", "consolidation"}
            or not roots or not audiences or len(roots) > 32 or not set(audiences) <= set(reader.metadata.plan.audiences)
            or len(reader.groups) != len(reader.metadata.plan.audiences)):
        raise AuthorityUnavailable("labor Source family is outside its actual complete ALL groups")
    groups = {g.selection.audience: g for g in reader.groups}
    pending, seen, versions, qualified = list(roots), set(), {}, {}
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise AuthorityUnavailable("labor Source family crossed its canonical actual namespace")
        for audience in audiences:
            group = groups[audience]
            group.selection.require_v3(work)
            if ((ref, purpose, False) not in group.qualifications or ref not in group.witnesses):
                raise AuthorityUnavailable("labor family asks for an unqualified Source/purpose/audience")
            group.witnesses[ref].require_current_v3()
        material = groups[audiences[0]].metadata_records[ref]
        qualified[ref] = material
        for target in (key, access_key(*namespace.as_tuple, key.owner.subject),
                source_correction_head_key(namespace, key.owner.subject)):
            head = work.heads.get(target.token)
            versions[target.token] = GraphVersion(target, 0 if head is None else head[0])
        seen.add(ref)
        if len(seen) > 256:
            raise AuthorityUnavailable("labor Source family exceeds its unchanged ancestor bound")
        pending.extend(source_key(*namespace.as_tuple, sid).token for sid in material.parent_source_ids)
    return qualified if records else tuple(versions[token] for token in sorted(versions))


def character_labor_source_atom_v1(work, source_ref):
    from .current_authority_graph_read_v3 import (
        PreparedAuthorityGraphValueOriginalV3, _AUTHORITY_GRAPH_VALUES_V3,
        _track_authority_capability_v3)
    _actual(work)
    reader = _READERS.get(work)
    if (reader is None or reader.source_material is None or work.request.phase != "claim"
            or len(reader.groups) != len(reader.metadata.plan.audiences)
            or source_ref not in reader.metadata.source_roots):
        raise AuthorityUnavailable("labor Source atom lacks its own selected root Body EOF")
    material = reader.source_material
    material.selection.require_v3(work)
    witness = material.witnesses[source_ref].require_current_v3()
    record = material.source_records[source_ref]
    key, value = AtomKey.from_token(source_ref), record.to_dict()
    original = PreparedAuthorityGraphValueOriginalV3.__new__(PreparedAuthorityGraphValueOriginalV3)
    original.work, original.source_material = work, material
    original.key, original.revision, original.valid, original.value = key, witness.revision, witness.valid, value
    _AUTHORITY_GRAPH_VALUES_V3[original] = (work, material, key, witness.revision, witness.valid, value)
    _track_authority_capability_v3(work, _AUTHORITY_GRAPH_VALUES_V3, original)
    work.operation.retain(4096)
    atom = GraphAtom(key, witness.revision, value, witness.valid, _canonical_original=original)
    work.source_atoms[key], work.atom_json_originals[key] = atom, original
    work.members[key] = atom
    return atom


def require_character_labor_body_request_v1(work, request):
    _actual(work)
    if type(work.request) is CharacterLaborAckMetadataRequestV1:
        raise AuthorityUnavailable("adoption ACK metadata never grants a Prepared or Source Body")
    reader = _READERS.get(work)
    if (reader is None or not reader.complete or reader.prepared is None
            or work.request.phase != "claim" or len(request) != 4):
        raise AuthorityUnavailable("labor Body continuation requires its completed actual SourceALL")
    table, columns, key_columns, key = request
    columns, key_columns, key = tuple(columns), tuple(key_columns), tuple(key)
    metadata, prepared, body = reader.metadata, reader.prepared, reader.body
    binding, ns = metadata.binding, work.namespace
    if table == "graph_atoms" and key_columns in {("token",), ("token", "bot", "persona")}:
        ref = key[0]
        if (ref not in {v.ref for v in metadata.read_versions} | set(reader.scope_selected)
                or NamespaceId.from_key(AtomKey.from_token(ref)) != ns):
            raise AuthorityUnavailable("labor continuation asks for a Graph Body outside its exact original read-set")
        if AtomKey.from_token(ref).type_name == "memory.source" and ref not in metadata.source_roots:
            raise AuthorityUnavailable("labor ancestor metadata cannot grant a Source Body")
        return
    if table == "graph_history" and key_columns == ("token", "revision"):
        if key not in {(v.ref, v.version) for v in metadata.read_versions}:
            raise AuthorityUnavailable("labor historical Body is outside its exact current read-set")
        if AtomKey.from_token(key[0]).type_name == "memory.source" and key[0] not in metadata.source_roots:
            raise AuthorityUnavailable("labor ancestor history cannot grant Source Body")
        return
    if table == "graph_d11_life_originals_v1" and key_columns == ("bot", "persona", "kind", "original_ref"):
        allowed = {
            ("character_labor_prepared_v1", metadata.prepared_ref),
            ("character_labor_plan_v1", binding.plan_original_ref),
            (PREPARED_METADATA_KIND, "character-labor-prepared-metadata:" + binding.execution_id),
            (ADMISSION_KIND, metadata.labor_admission_ref),
            (BODY_KIND, metadata.plan.labor_body_preparation_original.original_ref),
            ("action_admission", prepared.admission_ref),
            ("source_note_action", "life-root:" + binding.operation_id),
        }
        if key[:2] != ns.as_tuple or key[2:] not in allowed:
            raise AuthorityUnavailable("labor continuation asks for an unrelated signed Life original")
        return
    operations = {binding.operation_id, binding.prepare_operation_id, body.body_prepare_operation_id}
    if table == "graph_bundle_operations" and key_columns == ("bot", "persona", "operation_id"):
        if key[:2] == ns.as_tuple and key[2] in operations:
            return
    if table == "graph_events" and key_columns == ("bot", "persona", "session", "event_id"):
        if key[:3] == (*ns.as_tuple, binding.activity_id) and key[3] in operations:
            return
    if table == "runtime_jobs" and key_columns == ("job_id",) and key == (binding.job_id,):
        return
    if table == "runtime_resource_quotes" and key_columns == ("quote_id", "version"):
        if key in {(binding.quote_id, binding.quote_version),
                (body.quote.technical_quote_ref, body.quote.technical_quote_version)}:
            return
    if table == "graph_d02_production_policies_v1" and key_columns == ("bot", "persona", "policy_ref", "revision"):
        if key == (*ns.as_tuple, body.policy.policy_ref, body.policy.revision):
            return
    raise AuthorityUnavailable("unregistered exact character-labor metadata/Body continuation request")


_OWNER_OBSERVATIONS = WeakKeyDictionary()


def observe_character_labor_source_owner_v1(work):
    _actual(work)
    if work.db.in_transaction or work.service.bridge.core._db.in_transaction:
        raise AuthorityUnavailable("labor current Owner observation must precede Graph/Core SQL")
    from .d11_life_execution_owner_v1 import observe_d11_life_execution_owner_v1
    owner, returned = observe_d11_life_execution_owner_v1(work)
    if returned != work.permit:
        raise AuthorityUnavailable("labor Owner observation changed the actual original permit")
    _OWNER_OBSERVATIONS[work] = (work.service, work.request, work.permit, work.operation, owner)
    return owner


def _require_owner_metadata(work, metadata):
    saved = _OWNER_OBSERVATIONS.get(work)
    if saved is None or saved[:4] != (work.service, work.request, work.permit, work.operation):
        raise AuthorityUnavailable("labor Source metadata lacks the actual pre-SQL Owner observation")
    owner, binding = saved[4], metadata.binding
    guard = owner.guard
    frozen = json.loads(metadata.owner_guard_json)
    if (guard.authority_id != binding.authority_id or guard.installation_id != binding.installation_id
            or guard.namespace != work.namespace or guard.pending_revoke_operation_id is not None
            or guard.minimum_revocation_epoch
            or guard.minimum_revocation_revision >= guard.authorization_revision
            or work.request.phase == "claim" and (
                frozen["owner_head_digest"] != guard.authorization_head.removeprefix("sha256:")
                or (frozen["grant_ref"], frozen["grant_revision"], frozen["grant_digest"])
                    != (binding.owner_grant_ref, binding.owner_grant_revision, binding.owner_grant_digest))):
        raise AuthorityUnavailable("labor current Owner differs from the real C/binding authority")
    return owner



def resolve_character_labor_source_census_v1(work):
    """Resolve only this Source Work's private metadata census outside SQL."""
    _actual(work)
    if work.db.in_transaction or work.service.bridge.core._db.in_transaction:
        raise AuthorityUnavailable("labor census external phase cannot inherit Graph/Core SQL")
    reader = _READERS.get(work)
    if reader is None or reader.phase not in {"need_census", "census_finalize"}:
        return False
    if reader.identity != (work.controller, work.service, work.request, work.permit, work.operation,
            work.scope, work.selection_digest, work.deadline_utc):
        raise AuthorityUnavailable("labor census Source Work identity changed")
    from .character_labor_census_v1 import (
        prepare_character_labor_source_census_v1, finish_character_labor_source_census_v1)
    if reader.phase == "need_census":
        reader.census_reader = prepare_character_labor_source_census_v1(work,
            profile_id=reader.body.policy.profile_id)
        reader.phase = "census_metadata"
    else:
        reader.census = finish_character_labor_source_census_v1(work)
        if work.request.phase == "adoption":
            reader.phase = "metadata_complete"
            reader.complete = True
            work.phase = "validate"
        else:
            reader.phase = "sources"
    return True



class _LaborScopeMetadataColumnV1:
    def __new__(cls,reader,key,head):
        from .artifact_model_source_read_v3 import _MetadataColumnV3
        from ..runtime.d02_character_labor_read_v1 import character_labor_scope_metadata_fields_v1
        class Column(_MetadataColumnV3):
            def __init__(self):
                self.graph_key,self.expected_header = key,tuple(head[:3])
                super().__init__(reader,"labor_scope",table="graph_atoms",column="value",
                    key_columns=("token","bot","persona"),key=(key.token,*reader.work.namespace.as_tuple),
                    cell_id=head[2])
                names = frozenset(character_labor_scope_metadata_fields_v1(key.type_name))
                self.capture.retain_path_v3 = lambda path: not path or path[0] in names

            def _actual(self):
                _actual(reader.work)
                if _READERS.get(reader.work) is not reader or reader.phase != "scope_metadata":
                    raise AuthorityUnavailable("labor scope column lost its actual named metadata phase")
                return self

            def advance(self,meter):
                self._actual()
                reader.require_current(meter)
                current = meter.read_fixed_row(reader.work.db,"graph_atoms",
                    ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",
                    (key.token,*reader.work.namespace.as_tuple))
                if current != self.expected_header:
                    raise AuthorityUnavailable("labor scope metadata changed its actual complete cell header")
                return super().advance(meter)
        return Column()


def _complete_authority_labor_scope_v1(reader):
    from ..runtime.d11_life_scope_v1 import LifeSemanticScopeV1,life_semantic_source_refs_v1
    work,plan = reader.work,reader.metadata.plan
    action = reader.scope_metadata.get(plan.action_intent.ref)
    if action is None or not work.heads[plan.action_intent.ref][1]:
        raise AuthorityUnavailable("labor scope lacks its actual current action metadata")
    entities = tuple(token for token,value in reader.scope_metadata.items()
        if AtomKey.from_token(token).type_name == "d03.entity_anchor"
        and work.heads[token][1] and value["entity_id"] == action["target_ref"])
    if len(entities) != 1:
        raise AuthorityUnavailable("labor scope has no unique actual current target entity")
    scope = LifeSemanticScopeV1(work.namespace,plan.project.ref,plan.input_source.ref,entities[0],
        action["target_ref"],action["action_id"],action["goal_ref"],tuple(action["commitment_refs"]),
        tuple(plan.audiences),work.now_utc)
    action_ids = {v["action_id"] for token,v in reader.scope_metadata.items()
        if AtomKey.from_token(token).type_name == "d08.action_intent.v1" and work.heads[token][1]
        and scope.includes("d08.action_intent.v1",AtomKey.from_token(token),v)}
    selected,roots = set(),{plan.input_source.ref}
    for token,value in reader.scope_metadata.items():
        key = AtomKey.from_token(token)
        if not work.heads[token][1]:
            continue
        applies = value["action_id"] in action_ids if key.type_name == "d08.action_outcome.v1" else scope.includes(key.type_name,key,value)
        if applies:
            selected.add(token)
            roots.update(life_semantic_source_refs_v1(value))
    if len(roots) > 32 or not roots <= set(reader.metadata.source_roots):
        raise AuthorityUnavailable("current labor scope requires Sources outside its original qualified C selection")
    reader.semantic_scope = scope
    reader.scope_selected = frozenset(selected)
    reader.scope_roots = frozenset(roots)


def complete_authority_labor_scope_inventory_v1(db,read,family):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from ..runtime.d01_production_operations_v1 import CurrentDomainReadV1
    from ..runtime.d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    from ..runtime_contracts import QueryEpoch
    from ..graph_types import GraphVersion
    from dataclasses import replace
    work = _authority_attachment_owner_v3(db)
    if work is None or type(read) is not CurrentDomainReadV1:
        raise AuthorityUnavailable("Authority labor scoped inventory lacks its actual bound read")
    _actual(work)
    reader = _READERS.get(work)
    if (reader is None or not reader.complete or work.request.phase != "claim"
            or reader.semantic_scope is None or family not in LIFE_CURRENT_TYPES
            or read.frame.envelope.authority.namespace != work.namespace
            or read.frame.envelope.identity.operation_id != reader.metadata.binding.prepare_operation_id):
        raise AuthorityUnavailable("Authority labor scoped inventory left its actual same-Work C/binding")
    meter = current_c09_sql_meter_v2()
    if meter is None:
        raise AuthorityUnavailable("Authority labor scope needs its actual current bounded quantum")
    reader.require_current(meter)
    full = tuple(GraphVersion(AtomKey.from_token(token),head[0]) for token,head in sorted(work.heads.items())
        if AtomKey.from_token(token).type_name == family)
    selected = tuple(v for v in full if v.key.token in reader.scope_selected)
    scope = replace(reader.semantic_scope,now_utc=read.frame.now_utc)
    actions = {v["action_id"] for token,v in reader.scope_metadata.items()
        if AtomKey.from_token(token).type_name == "d08.action_intent.v1" and work.heads[token][1]
        and scope.includes("d08.action_intent.v1",AtomKey.from_token(token),v)}
    actual = []
    for v in full:
        column = reader.scope_columns[v.key.token]
        header = meter.read_fixed_row(db,"graph_atoms",("revision","valid","value_cell_id"),
            "token=? AND bot=? AND persona=?",(v.key.token,*work.namespace.as_tuple))
        if header != column.expected_header or not column.complete:
            raise AuthorityUnavailable("Authority labor scope metadata original changed before consumption")
        value = reader.scope_metadata[v.key.token]
        if work.heads[v.key.token][1] and (value["action_id"] in actions
                if family == "d08.action_outcome.v1" else scope.includes(family,v.key,value)):
            actual.append(v)
    if tuple(actual) != selected:
        raise AuthorityUnavailable("Authority labor predicate membership changed after its original bounded read")
    pages = tuple(p for p in read.frame.query_coverage if p.type_id == family)
    if (len(pages) != 1 or not pages[0].complete or pages[0].continuation_ref is not None
            or pages[0].row_versions != full or pages[0].epoch != QueryEpoch(work.namespace,family,work.graph_stamp[0])):
        raise AuthorityUnavailable("Authority labor scoped Bodies lost the full header query guard")
    return tuple(read.head(db,v.key,required=True) for v in selected)


def current_authority_character_labor_admission_frame_v1(db,*,prepared,template_json,now_utc):
    """Current sparse Bodies and distinct complete metadata query guards."""
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from ..runtime.d11_life_preparation_v1 import D11CharacterLaborLifePreparedV1
    from ..runtime.d08_life_admission_v1 import ProductionQueryCoverageV1
    from ..runtime.domain_production_contracts_v1 import CurrentOperationFrameV1,ProductionOwnerGuardV1,ProductionOriginalRefV1,ProductionPolicyRefV1
    from ..runtime.c02_bundle_codec import _decode
    from ..runtime_contracts import CommandEnvelope,QueryEpoch
    from ..graph_types import GraphSnapshot,GraphVersion,NamespaceEpoch
    from dataclasses import replace
    work = _authority_attachment_owner_v3(db)
    if work is None:
        raise AuthorityUnavailable("labor admission frame needs its actual bound Authority Source Work")
    _actual(work)
    reader = _READERS.get(work)
    if (type(prepared) is not D11CharacterLaborLifePreparedV1 or reader is None or not reader.complete
            or reader.prepared is not prepared or work.request.phase != "claim"
            or reader.semantic_scope is None or not db.in_transaction):
        raise AuthorityUnavailable("labor admission frame lacks its actual full Source/Prepared/scope EOF")
    template = json.loads(template_json)
    envelope = _decode(json.loads(template["envelope_json"]),CommandEnvelope)
    if envelope.authority.namespace != work.namespace or envelope.identity.operation_id != prepared.prepare_operation_id:
        raise AuthorityUnavailable("labor admission template changed its real C operation/namespace")
    epoch = NamespaceEpoch(*work.namespace.as_tuple,work.graph_stamp[0])
    pages = []
    for family in template["types"]:
        versions = tuple(GraphVersion(AtomKey.from_token(token),head[0]) for token,head in sorted(work.heads.items())
            if AtomKey.from_token(token).type_name == family)
        if len(versions) > 128:
            raise AuthorityUnavailable("labor current full family headers exceed their original bound")
        pages.append(ProductionQueryCoverageV1(QueryEpoch(work.namespace,family,epoch.revision),family,versions,True,None))
    atoms = tuple(work.members[key] for key in sorted(work.members,key=lambda k:k.token))
    snapshot = GraphSnapshot(atoms,(epoch,))
    envelope = replace(envelope,version_guard=replace(envelope.version_guard,
        read_versions=snapshot.versions,query_epochs=tuple(p.epoch for p in pages)))
    return CurrentOperationFrameV1(envelope,snapshot,now_utc,ProductionOwnerGuardV1(**template["owner_guard"]),
        prepared.binding.activation_generation,tuple(pages),
        tuple(ProductionPolicyRefV1(**v) for v in template["policies"]),
        tuple(ProductionOriginalRefV1(**v) for v in template["originals"]))

_ACK_METADATA_V1 = WeakKeyDictionary()


@dataclass(frozen=True,slots=True)
class CharacterLaborAckMetadataRequestV1:
    gate: object
    phase: str = "adoption_ack_metadata"

    def __post_init__(self):
        from .d11_life_bridge_v1 import D11LifeAdoptionBridgeV1
        if type(self.gate) is not D11LifeAdoptionBridgeV1 or self.phase != "adoption_ack_metadata":
            raise ValueError("exact actual SourceNote adoption bridge metadata request required")

    @property
    def binding(self):
        return self.gate.binding


def _require_character_labor_ack_work_v1(work):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3,require_actual_authority_graph_attachment_owner_v3
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    if (type(work) is not AuthorityGraphReadWorkV3 or type(work.service) is not AuthorityD11LifeServiceV1
            or type(work.request) is not CharacterLaborAckMetadataRequestV1
            or work.controller.kind != "character_labor" or work.controller.service is not work.service
            or work.controller.fences is not work.service.fences
            or work.controller.location is not work.service.current_source_location
            or work.namespace != work.service.namespace or work.credential is not work.service.credential
            or work.permit != work.request.gate.permit or work.permit.operation != "write"
            or work.permit.subject != work.subject or work.subject != work.service._subject
            or work.request.binding.namespace != work.namespace
            or work.request.binding.installation_id != work.service.installation_id
            or work.request.binding.manifest_digest != work.service.manifest_digest
            or work.controller.location._graph_db_path != work.service.graph_path):
        raise AuthorityUnavailable("labor ACK metadata requires its actual same-service gate/selected Work")
    require_actual_authority_graph_attachment_owner_v3(work,db=work.db)
    return work


class _AuthorityLaborAckMetadataOwnerV1:
    def __init__(self,work):
        work = _require_character_labor_ack_work_v1(work)
        if work in _ACK_METADATA_V1:
            raise AuthorityUnavailable("labor ACK cannot replace its actual retained metadata owner")
        self.work,self.gate = work,work.request.gate
        self.db,self.namespace,self.operation = work.db,work.namespace,work.operation
        self.selection_digest,self.issuer = work.selection_digest,work.service.issuer
        self.identity = (work,work.operation,work.handle,work.request,work.permit,
            work.scope,work.selection_digest,work.thread,work.deadline_utc)
        self.task = None
        _ACK_METADATA_V1[work] = self

    def require_v1(self,meter=None):
        return require_actual_character_labor_ack_metadata_owner_v1(self,gate=self.gate,meter=meter)


def require_actual_character_labor_ack_metadata_owner_v1(owner,*,gate,meter=None):
    if type(owner) is not _AuthorityLaborAckMetadataOwnerV1 or _ACK_METADATA_V1.get(owner.work) is not owner:
        raise AuthorityUnavailable("actual private Authority labor ACK metadata owner required")
    work = _require_character_labor_ack_work_v1(owner.work)
    if (gate is not owner.gate or work.request.gate is not gate
            or owner.identity != (work,work.operation,work.handle,work.request,work.permit,
                work.scope,work.selection_digest,work.thread,work.deadline_utc)
            or owner.issuer is not work.service.issuer or owner.db is not work.db
            or owner.operation is not work.operation):
        raise AuthorityUnavailable("labor ACK metadata crossed its retained invocation/gate/resource identity")
    work.require_current(meter=meter)
    return owner


def _advance_character_labor_ack_metadata_v1(work,meter):
    owner = _ACK_METADATA_V1.get(work)
    if owner is None:
        owner = _AuthorityLaborAckMetadataOwnerV1(work)
    owner.require_v1(meter)
    from ..runtime.character_labor_adoption_metadata_v1 import create_character_labor_adoption_ack_metadata_task_v1
    if owner.task is None:
        owner.task = create_character_labor_adoption_ack_metadata_task_v1(owner,gate=owner.gate)
    if owner.task.advance_v1(meter):
        work.phase = "validate"
    return owner


def _consume_character_labor_ack_metadata_v1(work):
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    owner = _ACK_METADATA_V1.get(work)
    if owner is None:
        raise AuthorityUnavailable("actual Authority ACK metadata EOF owner absent")
    meter = current_c09_sql_meter_v2()
    owner.require_v1(meter)
    from ..runtime.character_labor_adoption_metadata_v1 import (
        require_character_labor_adoption_ack_metadata_v1,CharacterLaborAuthorityAckMetadataV1,
        NoCommittedCharacterLaborAuthorityAckV1)
    proof = require_character_labor_adoption_ack_metadata_v1(owner.task,owner,gate=owner.gate,meter=meter)
    proof.require_current_v1(owner,gate=owner.gate,meter=meter)
    if type(proof) is NoCommittedCharacterLaborAuthorityAckV1:
        from ..runtime.d11_life_preparation_v1 import TABLE,SIGN_KIND
        headers = []
        for kind in ("prepared","character_labor_prepared_v1"):
            row = meter.read_fixed_row(work.db,TABLE,("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",
                (*work.namespace.as_tuple,kind,work.request.binding.prepared_original_ref))
            if row is not None:
                owner.issuer._signer.verify(SIGN_KIND,
                    canonical_serialize((work.namespace,kind,work.request.binding.prepared_original_ref,row[1])),row[2])
                if row[1] != owner.gate.prepared_digest or row[0] != work.request.binding.prepare_operation_id:
                    raise AuthorityUnavailable("legacy ACK header differs from its real Core start/terminal")
                headers.append(kind)
        if headers != ["prepared"]:
            raise AuthorityUnavailable("missing labor ACK metadata cannot fall back to new/absent/ambiguous Prepared")
        return False
    if type(proof) is not CharacterLaborAuthorityAckMetadataV1:
        raise AuthorityUnavailable("new labor cannot finish without its committed signed adoption metadata")
    if (proof.gate != owner.gate or proof.metadata.binding_digest != owner.gate.binding.digest
            or proof.metadata.prepared_original.original_digest != owner.gate.prepared_digest
            or proof.receipt.status != "committed"
            or proof.receipt.operation_id != proof.metadata.operation_id):
        raise AuthorityUnavailable("labor ACK metadata is not the actual same adopted lifecycle")
    return True


def verify_character_labor_graph_finish_metadata_v1(service,gate):
    from .d11_life_bridge_v1 import D11LifeAdoptionBridgeV1
    if type(gate) is not D11LifeAdoptionBridgeV1:
        return False
    from .d11_life_execution_owner_v1 import own_d11_life_execution_invocation_v1,require_own_life_adoption_bridge_scope_v1
    from .current_authority_graph_read_v3 import (
        begin_authority_graph_read_work_v3,read_authority_graph_current_v3,finish_authority_graph_read_work_v3)
    require_own_life_adoption_bridge_scope_v1(service,gate.binding,gate)
    work = None
    with own_d11_life_execution_invocation_v1(service,gate.binding,phase="adoption_metadata",permit=gate.permit):
        try:
            work = begin_authority_graph_read_work_v3(service,credential=service.credential,
                subject=gate.permit.subject,permit=gate.permit,namespace=gate.binding.namespace,
                request=CharacterLaborAckMetadataRequestV1(gate),
                parent_original_id=gate.binding.prepare_operation_id,now_utc=service._now(),deadline_utc=None)
            return read_authority_graph_current_v3(work,lambda db:_consume_character_labor_ack_metadata_v1(work))
        except BaseException as error:
            if work is not None and work.failure is None:
                work.failure = error
            raise
        finally:
            if work is not None:
                finish_authority_graph_read_work_v3(work)
                from .current_authority_graph_read_v3 import actual_authority_graph_release_v3
                if work.failure is None and (actual_authority_graph_release_v3(work) is not work.operation or not work.operation.closed):
                    work.failure = AuthorityUnavailable("labor ACK metadata retention is not actually released")
                    raise work.failure


def _release_character_labor_ack_metadata_owner_v1(work):
    owner = _ACK_METADATA_V1.get(work)
    if owner is None:
        return
    if owner.task is not None:
        from ..runtime.character_labor_adoption_metadata_v1 import release_character_labor_adoption_ack_metadata_v1
        release_character_labor_adoption_ack_metadata_v1(owner)
    _ACK_METADATA_V1.pop(work,None)
    owner.task = None
