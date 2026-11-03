"""Complete, bodyless classification of actual D11 Life journal inventory."""
from contextvars import ContextVar
from dataclasses import dataclass, fields, replace
from threading import get_ident
from weakref import WeakKeyDictionary, WeakSet

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2, RestoreAnchor, _anchor_from_wire, _anchor_wire
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime.d11_offline_originals_v1 import _digest, _text

SIGN_KIND = "d11.character-labor-census.v1"
SCHEMA = "d11.character-labor-census.v1"
_SERVICES = WeakSet()
_CAPTURES = WeakKeyDictionary()
_READERS = WeakKeyDictionary()
_CURRENT = ContextVar("actual_character_labor_census_v1", default=None)
_SOURCE_CAPTURES = WeakKeyDictionary()
_SOURCE_RESULTS = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class CharacterLaborCensusReadRequestV1:
    profile_id: str
    segment_page: object | None = None

    def __post_init__(self):
        _text(self.profile_id)
        if self.segment_page is not None and type(self.segment_page) is not CharacterLaborSegmentPageSelectionV1:
            raise ValueError("exact private census page selection required")


@dataclass(frozen=True, slots=True)
class CharacterLaborCensusEntryV1:
    execution_id: str
    binding_digest: str
    binding: object
    claim_sequence: int
    claim_digest: str
    terminal_sequence: int | None
    terminal_digest: str | None
    status: str
    prepared_kind: str
    prepared_ref: str
    prepared_digest: str
    prepared_metadata_ref: str | None
    prepared_metadata_digest: str | None
    classification: str
    accounting_basis_ref: str | None = None
    accounting_basis_digest: str | None = None

    def __post_init__(self):
        from ..runtime.d11_life_contract_v1 import LIFE_BINDING_TYPES, D11LifeExecutionBindingV1
        if (type(self.binding) not in LIFE_BINDING_TYPES or self.binding.digest != self.binding_digest
                or self.binding.execution_id != self.execution_id
                or self.binding.prepared_original_ref != self.prepared_ref
                or type(self.claim_sequence) is not int or self.claim_sequence < 1
                or self.status not in {"claimed", "completed", "failed", "unknown"}):
            raise ValueError("labor census entry requires its exact actual Life claim/binding")
        _digest(self.binding_digest); _digest(self.prepared_digest)
        if not self.claim_digest.startswith("sha256:"):
            raise ValueError("labor census requires its real claim chain")
        _digest(self.claim_digest[7:])
        if self.terminal_sequence is None:
            if self.terminal_digest is not None or self.status != "claimed":
                raise ValueError("labor census cannot invent a terminal")
        elif (type(self.terminal_sequence) is not int or self.terminal_sequence <= self.claim_sequence
                or not self.terminal_digest.startswith("sha256:")):
            raise ValueError("labor census terminal chain differs")
        else:
            _digest(self.terminal_digest[7:])
        if self.classification != "retained_duration_v1" and (
                self.accounting_basis_ref is not None or self.accounting_basis_digest is not None):
            raise ValueError("live/fixed census cannot claim a retired accounting basis")
        if self.classification == "retained_duration_v1":
            if (type(self.binding) is not D11LifeExecutionBindingV1
                    or self.prepared_kind != "character_labor_prepared_v1"
                    or self.prepared_metadata_ref is not None or self.prepared_metadata_digest is not None
                    or self.accounting_basis_ref != "character-labor-accounting:" + self.execution_id):
                raise ValueError("retained duration census requires its explicit independent accounting basis")
            _digest(self.accounting_basis_digest)
        elif self.classification == "fixed_v1":
            if (self.prepared_kind != "prepared" or self.prepared_metadata_ref is not None
                    or self.prepared_metadata_digest is not None):
                raise ValueError("legacy Fixed census must retain its actual old header kind")
        elif self.classification == "character_labor_v1":
            if (type(self.binding) is not D11LifeExecutionBindingV1
                    or self.prepared_kind != "character_labor_prepared_v1"
                    or self.prepared_metadata_ref != "character-labor-prepared-metadata:" + self.execution_id):
                raise ValueError("labor census must retain its exact new protocol metadata locator")
            _digest(self.prepared_metadata_digest)
        else:
            raise ValueError("unclassified actual Life execution cannot be skipped")


@dataclass(frozen=True, slots=True)
class CharacterLaborCensusV1:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    manifest_digest: str
    operation_id: str
    permit_digest: str
    anchor: RestoreAnchor
    selection_digest: str
    mixed_inventory_digest: str
    life_entry_count: int
    ordered_entry_root: str
    graph_stamp: tuple[int, int, int]
    body_state: VersionedRef
    body_state_value_digest: str
    body_state_cursor: float
    entries: tuple[CharacterLaborCensusEntryV1, ...]
    signature: str
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or type(self.namespace) is not NamespaceId
                or type(self.anchor) is not RestoreAnchor or type(self.body_state) is not VersionedRef
                or self.anchor.namespace != self.authority_namespace or self.anchor.authority_id != self.authority_id
                or type(self.entries) is not tuple
                or any(type(e) is not CharacterLaborCensusEntryV1 for e in self.entries)
                or self.entries != tuple(sorted(self.entries, key=lambda e:e.execution_id))
                or len({e.execution_id for e in self.entries}) != len(self.entries)
                or self.life_entry_count != len(self.entries)
                or self.ordered_entry_root != canonical_digest(self.entries)
                or type(self.graph_stamp) is not tuple or len(self.graph_stamp) != 3
                or any(type(v) is not int or v < 0 for v in self.graph_stamp)
                or any(e.binding.namespace != self.namespace for e in self.entries)):
            raise ValueError("complete labor census must describe one exact Core/Graph snapshot")
        import math
        if type(self.body_state_cursor) not in {float,int} or not math.isfinite(self.body_state_cursor) or self.body_state_cursor < 0:
            raise ValueError("labor census requires its actual Body cursor")
        for name in ("manifest_digest","permit_digest","selection_digest","mixed_inventory_digest",
                "ordered_entry_root","body_state_value_digest","signature"):
            _digest(getattr(self,name))
        for name in ("authority_namespace","authority_id","installation_id","operation_id"):
            _text(getattr(self,name))


def _binding_from_wire(raw):
    from ..runtime.d11_life_contract_v1 import LIFE_BINDING_TYPES, life_from_wire_v1
    matches = tuple(t for t in LIFE_BINDING_TYPES
        if t.__dataclass_fields__["schema"].default == raw["schema"])
    if len(matches) != 1:
        raise ValueError("closed actual Life binding schema required")
    return life_from_wire_v1(raw, matches[0])


def character_labor_census_to_wire_v1(value):
    if type(value) is not CharacterLaborCensusV1:
        raise TypeError("exact character labor census required")
    raw = plain_v1(value)
    raw["anchor"] = _anchor_wire(value.anchor)
    return raw


def character_labor_census_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(CharacterLaborCensusV1)}:
        raise ValueError("closed character labor census fields differ")
    value = dict(raw)
    value["namespace"] = NamespaceId(**value["namespace"])
    value["anchor"] = _anchor_from_wire(value["anchor"])
    value["graph_stamp"] = tuple(value["graph_stamp"])
    value["body_state"] = VersionedRef(**value["body_state"])
    entries = []
    for entry in value["entries"]:
        if type(entry) is not dict or set(entry) != {f.name for f in fields(CharacterLaborCensusEntryV1)}:
            raise ValueError("closed labor census member fields differ")
        entry = dict(entry); entry["binding"] = _binding_from_wire(entry["binding"])
        entries.append(CharacterLaborCensusEntryV1(**entry))
    value["entries"] = tuple(entries)
    return CharacterLaborCensusV1(**value)


def verify_character_labor_census_v1(issuer, value, *, permit):
    from ..runtime.issuers import D11BudgetJobIssuer
    if (type(issuer) is not D11BudgetJobIssuer or type(value) is not CharacterLaborCensusV1
            or type(permit) is not FencePermitV2 or permit.operation != "write"
            or value.permit_digest != canonical_digest(permit)
            or value.operation_id != permit.operation_id or value.anchor != permit.pinned_anchor
            or value.authority_namespace != permit.namespace):
        raise AuthorityUnavailable("labor census differs from its actual caller's original WRITE permit")
    raw = character_labor_census_to_wire_v1(value)
    signature = raw.pop("signature")
    issuer._signer.verify(SIGN_KIND, canonical_serialize(raw), signature)
    return value


class _CensusCaptureV1:
    def __init__(self, service, permit, request, inventory, bindings, prepared_digests):
        self.service, self.permit, self.request = service, permit, request
        self.inventory, self.bindings = inventory, bindings
        self.prepared_digests = prepared_digests
        self.thread, self.closed, self.identity = get_ident(), False, object()
        _CAPTURES[self] = self.identity


def _service(service):
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    from ..host.authority_profile import AdminInstallationBundle
    if type(service) is not InstalledCharacterLaborCensusServiceV1 or service not in _SERVICES:
        raise AuthorityUnavailable("actual installed character-labor census facade required")
    life = service.life
    if (type(life) is not AuthorityD11LifeServiceV1 or not life._execution_lock._is_owned()
            or service.bridge is not life.bridge or service.fences is not life.fences
            or service.credential is not life.credential or service.issuer is not life.issuer
            or service.installed_bundle is not life.installed_bundle
            or service.owner_service is not life.owner_service or service.owner_tickets is not life.owner_tickets
            or (service.namespace, service.installation_id, service.manifest_digest, service.graph_path)
                != (life.namespace, life.installation_id, life.manifest_digest, life.graph_path)
            or service.current_source_location is not life.current_source_location
            or type(life.installed_bundle) is not AdminInstallationBundle
            or life.current_source_location is None
            or life.current_source_location.core is not life.bridge.core
            or life.current_source_location._fences is not life.fences
            or life.current_source_location._graph_db_path != life.graph_path
            or life.current_source_location.namespace_id != life.namespace
            or life.current_source_location.installation_id != life.installation_id
            or life.current_source_location._control is not life.bridge.core._c09_storage_reader_v1):
        raise AuthorityUnavailable("labor census left its actual installed Life/Core/Graph composition")
    policy = life.installed_bundle.installation_policy
    if (policy.namespace, policy.installation_id, policy.manifest_digest) != (
            life.namespace, life.installation_id, life.manifest_digest):
        raise AuthorityUnavailable("labor census protected installation changed")
    life.bridge.core._require(life.credential, "execution", life.bridge.namespace)
    life.bridge.core._require(life.credential, "current", life.bridge.namespace)
    return life


def _capture_core(service, permit, request):
    from .d11_life_execution_inventory_v1 import read_life_execution_inventory_v1
    from .d11_life_journal_v1 import decode_life_row_v1
    life = _service(service)
    inventory = read_life_execution_inventory_v1(life, permit=permit)
    bindings, prepared_digests = {}, {}
    with life._frozen() as (db, deletion, execution, _):
        anchor, _ = life._current(db, deletion, execution)
        if anchor != inventory.anchor or anchor != permit.pinned_anchor:
            raise AuthorityUnavailable("labor census Core head changed before actual binding capture")
        life.bridge.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor)
        head, rows = life.bridge.journal._scan_locked()
        if head != execution:
            raise AuthorityUnavailable("labor census actual full mixed journal changed")
        selected = {e.claim_sequence:e for e in inventory.entries if e.family == "life"}
        for row in rows:
            entry = selected.get(row[0])
            if entry is None:
                continue
            binding, start, terminal = decode_life_row_v1(life.bridge.journal, row)
            if (terminal is not None or binding.digest != entry.binding_digest
                    or binding.execution_id != entry.execution_id or row[6] != entry.claim_digest):
                raise AuthorityUnavailable("labor census binding is not its actual authenticated claim")
            life._verify_payload(start)
            bindings[entry.execution_id] = binding
            prepared_digests[entry.execution_id] = start.prepared_digest
        if len(bindings) != len(selected):
            raise AuthorityUnavailable("labor census missed an actual Life entry")
    return _CensusCaptureV1(service, permit, request, inventory, bindings, prepared_digests)


def require_character_labor_census_permission_v1(service, *, credential, subject, permit, request):
    life = _service(service)
    capture = _CURRENT.get()
    if (type(capture) is not _CensusCaptureV1 or _CAPTURES.get(capture) is not capture.identity
            or capture.closed or capture.thread != get_ident() or capture.service is not service
            or capture.request is not request or capture.permit != permit
            or credential is not life.credential or subject != permit.subject
            or type(request) is not CharacterLaborCensusReadRequestV1
            or type(permit) is not FencePermitV2 or permit.operation != "write"
            or permit.namespace != life.bridge.namespace):
        raise AuthorityUnavailable("labor census permission requires its actual same-call private capture")
    if life.bridge.core._db.in_transaction:
        raise AuthorityUnavailable("labor census permission must precede Graph/Core SQL")
    with life._frozen() as (db, deletion, execution, _):
        anchor, holder = life._current(db, deletion, execution)
        if (anchor != capture.inventory.anchor or anchor != permit.pinned_anchor
                or holder != life.owner_service.holder or permit.holder != holder):
            raise AuthorityUnavailable("labor census original namespace/Owner/Core head changed")
        life.bridge.fences.validate_fence_locked(db, permit, subject=subject, current_anchor=anchor)
        owner = life.owner_tickets.current_migration_head_in_tx(db, authority_namespace=life.bridge.namespace)
        if owner is None or owner.state != "active":
            raise AuthorityUnavailable("labor census current Owner is not active")
    return capture


def _actual(work):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3, require_actual_authority_graph_attachment_owner_v3
    if type(work) is AuthorityGraphReadWorkV3 and work.controller.kind == "character_labor":
        from .character_labor_source_read_v1 import _actual as require_source_work
        require_source_work(work)
        capture = _SOURCE_CAPTURES.get(work)
        if (type(capture) is not _CensusCaptureV1 or _CAPTURES.get(capture) is not capture.identity
                or capture.closed or capture.thread != get_ident()
                or capture.service.life is not work.service or capture.permit is not work.permit):
            raise AuthorityUnavailable("labor census lost its private same-SourceWork Core capture")
        return capture
    if (type(work) is not AuthorityGraphReadWorkV3
            or type(work.service) is not InstalledCharacterLaborCensusServiceV1
            or work.controller.kind != "character_labor_census"
            or work.controller.service is not work.service
            or work.namespace != work.service.namespace
            or work.controller.location is not work.service.current_source_location):
        raise AuthorityUnavailable("actual installed character-labor census Work required")
    require_actual_authority_graph_attachment_owner_v3(work, db=work.db)
    capture = _CURRENT.get()
    if (capture is None or capture.service is not work.service or capture.permit != work.permit
            or capture.request is not work.request or capture.closed):
        raise AuthorityUnavailable("labor census Work changed its actual private Core capture")
    return capture


def character_labor_census_namespace_reader_v1(work, *, catalogue, catalogue_hash):
    from .current_authority_graph_read_v3 import _AuthorityNamespaceReadV3
    _actual(work)
    reader = _AuthorityNamespaceReadV3(work, catalogue=catalogue, catalogue_hash=catalogue_hash)
    reader.projection_types = frozenset()
    return reader


class _CharacterLaborCensusReadV1:
    def __init__(self, work):
        from ..graph_types import AtomKey, Owner
        capture = _actual(work)
        self.work, self.capture = work, capture
        self.selected = tuple(sorted((e for e in capture.inventory.entries if e.family == "life"),
            key=lambda e:e.execution_id))
        self.entries, self.position = [], 0
        self.column = self.point = None
        self.points = []; self.pending_entry = None
        self.membership_digest = self.membership_epoch = None
        self.phase, self.complete = "body", False
        self.binding = self.header = self.accounting_basis = None
        self.body_key = AtomKey(Owner("persona", *work.namespace.as_tuple),
            "d02.body_state.v1", capture.request.profile_id)
        self.body_state = None
        self.body_digest = None
        self.body_revision = None
        self.page_bases, self.page_todo = {}, None
        self.reserved = 0
        self._reserve()
        _READERS[work] = self

    def _reserve(self):
        from ..runtime.dispatch_current_inventory_v3 import _heap
        amount = _heap((self.capture.inventory,self.capture.bindings,self.capture.prepared_digests,self.entries,self.body_state,self.accounting_basis,self.page_bases)) + 4096
        if amount > self.reserved:
            self.work.operation.retain(amount-self.reserved)
            self.reserved = amount

    def require_current(self, meter):
        _actual(self.work)
        if _READERS.get(self.work) is not self:
            raise AuthorityUnavailable("labor census reader private issuance changed")
        self.work.require_current(meter=meter)

    def advance(self, meter):
        from ..runtime.d11_life_preparation_v1 import TABLE, SIGN_KIND
        from .character_labor_source_read_v1 import _MetadataPoint, _SignedOriginal
        from ..runtime.d11_character_work_segment_v1 import PREPARED_METADATA_KIND, character_labor_prepared_metadata_from_wire_v1
        from ..runtime.d11_life_accounting_v1 import D11LifeAccountingPreparedV1, life_accounting_original_ref_v1
        self.require_current(meter)
        self._reserve()
        work = self.work
        if self.phase == "body":
            if self.point is None:
                self.point = _MetadataPoint(self, ("graph_atoms", ("value","revision","valid"),
                    ("token",), (self.body_key.token,)))
            self.point.advance(meter)
            if not self.point.complete:
                return
            row = self.point.attachment.require_row_v3(work, meter)
            head = work.heads.get(self.body_key.token)
            if row is None or head is None or not row[2] or row[1] != head[0]:
                raise AuthorityUnavailable("labor census actual current BodyState is absent")
            from ..domains.d02 import BodyState
            raw = self.point.attachment.json_columns["value"].require_v3(work)
            state = BodyState(**raw)
            if state.profile_id != self.capture.request.profile_id or state.version != row[1]:
                raise AuthorityUnavailable("labor census Body profile/version differs")
            self.body_state, self.body_revision, self.body_digest = state, row[1], canonical_digest(raw)
            self.point = None; self.phase = "headers"
            return
        if self.phase == "headers":
            if self.position == len(self.selected):
                selection = self.capture.request.segment_page
                if selection is None:
                    self.complete = True
                else:
                    if tuple(self.entries) != selection.census.entries:
                        raise AuthorityUnavailable("labor page metadata classification differs from its signed complete census")
                    self.page_todo = [entry for entry in self.entries[selection.cursor:selection.cursor+selection.limit]
                        if entry.classification != "fixed_v1"]
                    self.phase = "page_basis"
                return
            fact = self.selected[self.position]
            self.binding = self.capture.bindings[fact.execution_id]
            headers = []
            for kind in ("prepared", "character_labor_prepared_v1"):
                header = meter.read_fixed_row(work.db, TABLE,
                    ("producing_operation_id","payload_digest","signature"),
                    "bot=? AND persona=? AND kind=? AND original_ref=?",
                    (*work.namespace.as_tuple, kind, self.binding.prepared_original_ref))
                if header is not None:
                    work.service.issuer._signer.verify(SIGN_KIND, canonical_serialize((
                        work.namespace, kind, self.binding.prepared_original_ref, header[1])), header[2])
                    headers.append((kind, header))
            if not headers:
                from ..runtime.d11_character_labor_accounting_v1 import KIND
                self.column = _SignedOriginal(self,KIND,"character-labor-accounting:"+self.binding.execution_id)
                self.phase = "retained_basis"
                return
            if len(headers) != 1 or headers[0][1][0] != self.binding.prepare_operation_id:
                raise AuthorityUnavailable("labor census has no unique signed actual Prepared header")
            self.kind, self.header = headers[0]
            kind = PREPARED_METADATA_KIND if self.kind == "character_labor_prepared_v1" else "accounting_prepared"
            ref = ("character-labor-prepared-metadata:" + self.binding.execution_id
                if kind == PREPARED_METADATA_KIND else life_accounting_original_ref_v1(self.binding))
            self.column = _SignedOriginal(self, kind, ref); self.phase = "metadata"
            return
        if self.phase == "page_basis":
            from ..runtime.d11_character_labor_accounting_v1 import KIND, character_labor_accounting_basis_from_wire_v1
            if not self.page_todo:
                self.complete = True
                return
            entry = self.page_todo[0]
            if self.column is None:
                self.column = _SignedOriginal(self,KIND,"character-labor-accounting:"+entry.execution_id)
            self.column.advance(meter)
            if not self.column.complete:
                return
            c = self.column
            if c.raw is None or c.producer != entry.binding.prepare_operation_id:
                raise AuthorityUnavailable("labor page lacks its existing signed actual C accounting basis")
            basis = character_labor_accounting_basis_from_wire_v1(c.raw)
            if ((basis.namespace,basis.execution_id,basis.binding_digest,basis.prepared_digest)
                    != (work.namespace,entry.execution_id,entry.binding_digest,entry.prepared_digest)
                    or entry.accounting_basis_digest is not None and c.digest != entry.accounting_basis_digest):
                raise AuthorityUnavailable("labor page basis changed its actual census execution")
            self.accounting_basis = basis
            self.column = _SignedOriginal(self,"accounting_prepared",basis.accounting_ref)
            self.phase = "page_accounting"
            return
        if self.phase == "page_accounting":
            from ..runtime.d10_offline_tick_execution_v1 import _decode_json
            from ..runtime.d11_character_labor_accounting_v1 import _require_accounting
            self.column.advance(meter)
            if not self.column.complete:
                return
            basis,c = self.accounting_basis,self.column
            if c.raw is None or c.producer != basis.prepare_operation_id or c.digest != basis.accounting_digest:
                raise AuthorityUnavailable("labor page actual old accounting original changed")
            accounting = _decode_json(canonical_serialize(c.raw),D11LifeAccountingPreparedV1)
            _require_accounting(basis,accounting)
            self.page_bases[basis.execution_id] = (basis,accounting)
            self.page_todo.pop(0)
            self.column = self.accounting_basis = None
            self.phase = "page_basis"
            return
        if self.phase == "retained_basis":
            from ..runtime.d11_character_labor_accounting_v1 import character_labor_accounting_basis_from_wire_v1
            self.column.advance(meter)
            if not self.column.complete:
                return
            column = self.column
            if column.raw is None:
                raise AuthorityUnavailable("labor census cannot infer legacy or retirement from missing Prepared metadata")
            basis = character_labor_accounting_basis_from_wire_v1(column.raw)
            b = self.binding
            if ((basis.namespace,basis.authority_namespace,basis.authority_id,basis.installation_id,
                    basis.manifest_digest,basis.execution_id,basis.effect_id,basis.binding_digest,
                    basis.prepare_operation_id,basis.prepared_ref,basis.prepared_digest)
                    != (b.namespace,b.authority_namespace,b.authority_id,b.installation_id,
                        b.manifest_digest,b.execution_id,b.effect_id,b.digest,b.prepare_operation_id,
                        b.prepared_original_ref,self.capture.prepared_digests[b.execution_id])
                    or column.producer != b.prepare_operation_id):
                raise AuthorityUnavailable("retained duration basis is not the actual Core Life claim/binding")
            self.accounting_basis = (basis,column.ref,column.digest)
            self.column = _SignedOriginal(self,"accounting_prepared",basis.accounting_ref)
            self.phase = "retained_accounting"
            return
        if self.phase == "retained_accounting":
            from ..runtime.d10_offline_tick_execution_v1 import _decode_json
            from ..runtime.d11_character_labor_accounting_v1 import _require_accounting
            self.column.advance(meter)
            if not self.column.complete:
                return
            basis,basis_ref,basis_digest = self.accounting_basis
            column = self.column
            if (column.raw is None or column.producer != basis.prepare_operation_id
                    or column.digest != basis.accounting_digest):
                raise AuthorityUnavailable("retained duration lost its independently signed old accounting original")
            accounting = _decode_json(canonical_serialize(column.raw),D11LifeAccountingPreparedV1)
            _require_accounting(basis,accounting)
            fact = self.selected[self.position]
            self.entries.append(CharacterLaborCensusEntryV1(fact.execution_id,fact.binding_digest,
                self.binding,fact.claim_sequence,fact.claim_digest,fact.terminal_sequence,
                fact.terminal_digest,fact.status,"character_labor_prepared_v1",
                basis.prepared_ref,basis.prepared_digest,None,None,"retained_duration_v1",
                basis_ref,basis_digest))
            self.position += 1
            self.column = self.binding = self.header = self.accounting_basis = None
            self.phase = "headers"
            return
        if self.phase == "metadata":
            self.column.advance(meter)
            if not self.column.complete:
                return
            column = self.column
            if column.raw is None or column.producer != self.binding.prepare_operation_id:
                raise AuthorityUnavailable("labor census original is not migrated; no Prepared Body fallback")
            if self.kind == "character_labor_prepared_v1":
                value = character_labor_prepared_metadata_from_wire_v1(column.raw)
                if (value.plan.recipe_version != 2
                        or value.plan.executor_protocol != "source_note_nonpreemptible_segment.v1"):
                    raise AuthorityUnavailable("labor census new kind changed its exact installed protocol")
                classification, metadata_ref, metadata_digest = "character_labor_v1", column.ref, column.digest
            else:
                raw = dict(column.raw); raw["binding"] = _binding_from_wire(raw["binding"])
                value = D11LifeAccountingPreparedV1(**raw)
                classification, metadata_ref, metadata_digest = "fixed_v1", None, None
            if (value.binding != self.binding or value.prepared_digest != self.header[1]
                    or value.prepared_digest != self.capture.prepared_digests[self.binding.execution_id]):
                raise AuthorityUnavailable("labor census metadata differs from its exact signed binding/header")
            fact = self.selected[self.position]
            self.pending_entry = CharacterLaborCensusEntryV1(fact.execution_id, fact.binding_digest,
                self.binding, fact.claim_sequence, fact.claim_digest, fact.terminal_sequence,
                fact.terminal_digest, fact.status, self.kind, self.binding.prepared_original_ref,
                self.header[1], metadata_ref, metadata_digest, classification)
            self.membership_digest = value.receipt_digest if classification == "character_labor_v1" else None
            self.membership_epoch = value.graph_epoch if classification == "character_labor_v1" else None
            self.points = [
                _MetadataPoint(self, ("graph_bundle_operations",
                    ("digest","activity_id","effect_id","commit_seq","receipt_json"),
                    ("bot","persona","operation_id"),
                    (*work.namespace.as_tuple,self.binding.prepare_operation_id))),
                _MetadataPoint(self, ("graph_events",("reads","revisions","epoch_revision"),
                    ("bot","persona","session","event_id"),
                    (*work.namespace.as_tuple,self.binding.activity_id,self.binding.prepare_operation_id)))]
            self.column = None; self.phase = "membership"
            return
        if self.phase == "membership":
            for point in self.points:
                if not point.complete:
                    point.advance(meter)
                    return
            from ..runtime.domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
            receipt = reconstruct_graph_bundle_commit_receipt_v1(work.namespace,
                self.binding.prepare_operation_id,
                self.points[0].attachment.require_row_v3(work,meter),
                self.points[1].attachment.require_row_v3(work,meter))
            if (receipt.activity_id != self.binding.activity_id or receipt.effect_id != self.binding.effect_id
                    or self.membership_digest is not None and canonical_digest(receipt) != self.membership_digest
                    or self.membership_epoch is not None
                        and receipt.invalidated_epochs[0].revision != self.membership_epoch):
                raise AuthorityUnavailable("labor census Prepared metadata lost its exact actual C membership")
            self.entries.append(self.pending_entry)
            self.position += 1
            self.column = self.binding = self.header = self.pending_entry = None
            self.points.clear(); self.membership_digest = self.membership_epoch = None
            self.phase = "headers"
            return
        raise AuthorityUnavailable("unregistered labor census metadata phase")


def advance_character_labor_census_v1(work, meter):
    reader = _READERS.get(work)
    if reader is None:
        reader = _CharacterLaborCensusReadV1(work)
    reader.advance(meter)
    if reader.complete:
        work.phase = "validate"
    return reader


def require_character_labor_census_body_request_v1(work, request):
    _actual(work)
    # The metadata producer issues its exact columns itself. Its terminal mapper
    # never requests historical Body, Source, Prepared or arbitrary attachments.
    raise AuthorityUnavailable("labor census has no business Body attachment capability")


def release_character_labor_census_v1(work):
    reader = _READERS.pop(work, None)
    if reader is not None:
        reader.entries.clear(); reader.points.clear(); reader.page_bases.clear()
        reader.pending_entry = None
        reader.column = reader.point = reader.body_state = reader.accounting_basis = None


class InstalledCharacterLaborCensusServiceV1:
    def __init__(self, life_service):
        from .d11_life_service_v1 import AuthorityD11LifeServiceV1
        if type(life_service) is not AuthorityD11LifeServiceV1:
            raise TypeError("actual installed Life service required")
        self.life = life_service
        for name in ("bridge","fences","namespace","installation_id","manifest_digest","graph_path",
                "credential","issuer","owner_service","owner_tickets","installed_bundle","current_source_location"):
            setattr(self, name, getattr(life_service,name))
        self._clock = life_service._clock
        _SERVICES.add(self)
        from .current_authority_graph_read_v3 import install_authority_graph_read_controller_v3
        install_authority_graph_read_controller_v3(self, service=self, source_location=self.current_source_location)

    def _frozen(self):
        return self.life._frozen()

    def _current(self, db, deletion, execution):
        return self.life._current(db, deletion, execution)

    def _now(self):
        return self.life._now()

    def read_character_labor_census_v1(self, *, permit, namespace, profile_id):
        return self._read_census_request_v1(permit=permit,namespace=namespace,
            request=CharacterLaborCensusReadRequestV1(profile_id))

    def read_character_labor_segment_page_v1(self, *, permit, namespace, census, cursor=0, limit=1):
        from ..graph_types import AtomKey
        selection = CharacterLaborSegmentPageSelectionV1(census,cursor,limit)
        verify_character_labor_census_v1(self.issuer,census,permit=permit)
        if census.namespace != namespace:
            raise AuthorityUnavailable("labor page census namespace differs from its actual caller")
        profile = AtomKey.from_token(census.body_state.ref).name
        return self._read_census_request_v1(permit=permit,namespace=namespace,
            request=CharacterLaborCensusReadRequestV1(profile,selection))

    def _read_census_request_v1(self, *, permit, namespace, request):
        from .current_authority_graph_read_v3 import (
            begin_authority_graph_read_work_v3, read_authority_graph_current_v3,
            finish_authority_graph_read_work_v3)
        if namespace != self.namespace or type(permit) is not FencePermitV2 or permit.operation != "write":
            raise AuthorityUnavailable("labor census requires its actual namespace WRITE inventory permit")
        if type(request) is not CharacterLaborCensusReadRequestV1:
            raise AuthorityUnavailable("actual closed census request required")
        with self.life._execution_lock:
            capture = _capture_core(self, permit, request)
            token = _CURRENT.set(capture)
            work = None
            try:
                work = begin_authority_graph_read_work_v3(self, credential=self.credential,
                    subject=permit.subject, permit=permit, namespace=namespace, request=request,
                    parent_original_id=permit.operation_id, now_utc=self._now(), deadline_utc=None)

                def ready(db):
                    _actual(work)
                    reader = _READERS.get(work)
                    if reader is None or not reader.complete:
                        raise AuthorityUnavailable("labor census is missing its actual complete metadata EOF")
                    return reader

                reader = read_authority_graph_current_v3(work, ready)
                require_character_labor_census_permission_v1(self, credential=self.credential,
                    subject=permit.subject, permit=permit, request=request)
                inventory = capture.inventory
                value = CharacterLaborCensusV1(namespace, self.bridge.namespace, permit.authority_id,
                    self.installation_id, self.manifest_digest, permit.operation_id, canonical_digest(permit),
                    inventory.anchor, work.selection_digest, inventory.digest, len(reader.entries),
                    canonical_digest(tuple(reader.entries)), tuple(work.graph_stamp),
                    VersionedRef(reader.body_key.token, reader.body_revision), reader.body_digest,
                    reader.body_state.cursor, tuple(reader.entries), "0"*64)
                raw = character_labor_census_to_wire_v1(value); raw.pop("signature")
                value = replace(value, signature=self.issuer._signer.sign(SIGN_KIND, canonical_serialize(raw)))
                if request.segment_page is not None:
                    return _finish_census_segment_page_v1(self,work,reader,value)
                return value
            except BaseException as error:
                if work is not None and work.failure is None:
                    work.failure = error
                raise
            finally:
                try:
                    if work is not None:
                        finish_authority_graph_read_work_v3(work)
                finally:
                    capture.closed = True
                    _CAPTURES.pop(capture,None)
                    _CURRENT.reset(token)


def observe_character_labor_census_owner_v1(work):
    _actual(work)
    from .d11_life_execution_owner_v1 import observe_d11_life_execution_owner_v1
    return observe_d11_life_execution_owner_v1(work)


def bind_character_labor_census_owner_v1(work):
    _actual(work)
    from .d11_life_execution_owner_v1 import bind_d11_life_execution_owner_v1
    return bind_d11_life_execution_owner_v1(work)


def release_character_labor_census_owner_v1(work):
    from .d11_life_execution_owner_v1 import release_d11_life_execution_owner_v1
    return release_d11_life_execution_owner_v1(work)


def prepare_character_labor_source_census_v1(work, *, profile_id):
    """Capture original Core inventory outside SQL, on the original Source Work."""
    from .character_labor_source_read_v1 import _actual as require_source_work
    require_source_work(work)
    if work.db.in_transaction or work.service.bridge.core._db.in_transaction:
        raise AuthorityUnavailable("labor census capture must precede Graph/Core SQL")
    if work in _SOURCE_CAPTURES:
        raise AuthorityUnavailable("same Source Work already has its original census capture")
    facade = work.service.character_labor_census_v1
    if type(facade) is not InstalledCharacterLaborCensusServiceV1 or facade.life is not work.service:
        raise AuthorityUnavailable("actual installed same-Life census facade required")
    request = CharacterLaborCensusReadRequestV1(profile_id)
    capture = _capture_core(facade, work.permit, request)
    _SOURCE_CAPTURES[work] = capture
    try:
        return _CharacterLaborCensusReadV1(work)
    except BaseException:
        _SOURCE_CAPTURES.pop(work)
        _CAPTURES.pop(capture, None)
        capture.closed = True
        raise


def finish_character_labor_source_census_v1(work):
    """Final Core bookend; no Graph body or new permit is issued."""
    capture = _actual(work)
    if work.db.in_transaction or work.service.bridge.core._db.in_transaction:
        raise AuthorityUnavailable("labor census final Core bookend must follow Graph SQL")
    reader = _READERS.get(work)
    if reader is None or not reader.complete or reader.capture is not capture:
        raise AuthorityUnavailable("same Source Work has no complete census metadata EOF")
    reader._reserve()
    token = _CURRENT.set(capture)
    try:
        require_character_labor_census_permission_v1(capture.service,
            credential=work.credential, subject=work.subject, permit=work.permit,
            request=capture.request)
    finally:
        _CURRENT.reset(token)
    value = CharacterLaborCensusV1(work.namespace, work.permit.namespace, work.permit.authority_id,
        work.service.installation_id, work.service.manifest_digest, work.permit.operation_id,
        canonical_digest(work.permit), capture.inventory.anchor, work.selection_digest,
        capture.inventory.digest, len(reader.entries), canonical_digest(tuple(reader.entries)),
        tuple(work.graph_stamp), VersionedRef(reader.body_key.token, reader.body_revision),
        reader.body_digest, reader.body_state.cursor, tuple(reader.entries), "0"*64)
    raw = character_labor_census_to_wire_v1(value); raw.pop("signature")
    result = replace(value, signature=work.service.issuer._signer.sign(SIGN_KIND, canonical_serialize(raw)))
    _SOURCE_RESULTS[work] = result
    return result


def require_character_labor_source_census_v1(work, *, meter):
    capture = _actual(work)
    reader = _READERS.get(work)
    result = _SOURCE_RESULTS.get(work)
    if reader is None or not reader.complete or reader.capture is not capture or result is None:
        raise AuthorityUnavailable("actual same-SourceWork complete census is required")
    reader.require_current(meter)
    if (tuple(work.graph_stamp) != result.graph_stamp or work.selection_digest != result.selection_digest
            or work.permit is not capture.permit):
        raise AuthorityUnavailable("labor census source snapshot changed")
    verify_character_labor_census_v1(work.service.issuer, result, permit=work.permit)
    return result


def release_character_labor_source_census_v1(work):
    _SOURCE_RESULTS.pop(work, None)
    capture = _SOURCE_CAPTURES.pop(work, None)
    release_character_labor_census_v1(work)
    if capture is not None:
        capture.closed = True
        _CAPTURES.pop(capture, None)

PAGE_SCHEMA = "d11.character-labor-segment-page.v1"
PAGE_SIGN_KIND = PAGE_SCHEMA
_PAGE_CONTEXT = ContextVar("actual_character_labor_census_segment_page_v1", default=None)
_PAGE_CONTEXTS = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class CharacterLaborSegmentPageSelectionV1:
    census: CharacterLaborCensusV1
    cursor: int
    limit: int

    def __post_init__(self):
        if (type(self.census) is not CharacterLaborCensusV1 or type(self.cursor) is not int
                or not 0 <= self.cursor <= self.census.life_entry_count
                or type(self.limit) is not int or not 1 <= self.limit <= 16):
            raise ValueError("labor page requires its exact signed census and bounded ordered cursor")


@dataclass(frozen=True, slots=True)
class CharacterLaborSegmentPageItemV1:
    entry_index: int
    entry_digest: str
    segment: object

    def __post_init__(self):
        from ..runtime.d11_character_work_segment_v1 import CharacterWorkSegmentOriginalV1
        if type(self.entry_index) is not int or self.entry_index < 0 or type(self.segment) is not CharacterWorkSegmentOriginalV1:
            raise ValueError("labor page item requires an actual signed segment and full census position")
        _digest(self.entry_digest)


@dataclass(frozen=True, slots=True)
class CharacterLaborSegmentPageV1:
    namespace: NamespaceId
    operation_id: str
    permit_digest: str
    census_digest: str
    ordered_entry_root: str
    life_entry_count: int
    selection_digest: str
    anchor: RestoreAnchor
    graph_stamp: tuple
    body_state: VersionedRef
    body_state_value_digest: str
    body_state_cursor: float
    cursor: int
    next_cursor: int | None
    items: tuple
    signature: str
    schema: str = PAGE_SCHEMA

    def __post_init__(self):
        if (self.schema != PAGE_SCHEMA or type(self.namespace) is not NamespaceId
                or type(self.anchor) is not RestoreAnchor or type(self.body_state) is not VersionedRef
                or type(self.cursor) is not int or not 0 <= self.cursor <= self.life_entry_count
                or self.next_cursor is not None and (type(self.next_cursor) is not int
                    or not self.cursor < self.next_cursor < self.life_entry_count)
                or type(self.items) is not tuple or len(self.items) > 16
                or any(type(item) is not CharacterLaborSegmentPageItemV1 for item in self.items)
                or tuple(i.entry_index for i in self.items) != tuple(sorted({i.entry_index for i in self.items}))):
            raise ValueError("closed bounded character-labor segment page required")
        for value in (self.permit_digest,self.census_digest,self.ordered_entry_root,
                self.selection_digest,self.body_state_value_digest,self.signature):
            _digest(value)


def character_labor_segment_page_to_wire_v1(page):
    if type(page) is not CharacterLaborSegmentPageV1:
        raise TypeError("exact character-labor segment page required")
    raw = plain_v1(page)
    raw["anchor"] = _anchor_wire(page.anchor)
    return raw


def character_labor_segment_page_from_wire_v1(raw):
    from ..runtime.d11_character_work_segment_v1 import character_work_segment_from_wire_v1
    if type(raw) is not dict or set(raw) != {f.name for f in fields(CharacterLaborSegmentPageV1)}:
        raise ValueError("closed character-labor segment page fields required")
    value = dict(raw)
    value["namespace"] = NamespaceId(**value["namespace"])
    value["anchor"] = _anchor_from_wire(value["anchor"])
    value["body_state"] = VersionedRef(**value["body_state"])
    value["graph_stamp"] = tuple(value["graph_stamp"])
    value["items"] = tuple(CharacterLaborSegmentPageItemV1(item["entry_index"],item["entry_digest"],
        character_work_segment_from_wire_v1(item["segment"])) for item in value["items"]
        if type(item) is dict and set(item) == {"entry_index","entry_digest","segment"})
    if len(value["items"]) != len(raw["items"]):
        raise ValueError("closed character-labor page item fields required")
    return CharacterLaborSegmentPageV1(**value)


def verify_character_labor_segment_page_v1(issuer, page, *, census, permit, cursor, limit):
    verify_character_labor_census_v1(issuer,census,permit=permit)
    if (type(page) is not CharacterLaborSegmentPageV1 or type(cursor) is not int or type(limit) is not int
            or not 1 <= limit <= 16 or page.cursor != cursor
            or (page.namespace,page.operation_id,page.permit_digest,page.census_digest,
                page.ordered_entry_root,page.life_entry_count,page.selection_digest,page.anchor,
                page.graph_stamp,page.body_state,page.body_state_value_digest,page.body_state_cursor)
            != (census.namespace,census.operation_id,census.permit_digest,canonical_digest(census),
                census.ordered_entry_root,census.life_entry_count,census.selection_digest,census.anchor,
                census.graph_stamp,census.body_state,census.body_state_value_digest,census.body_state_cursor)):
        raise AuthorityUnavailable("labor segment page differs from its actual complete census/WRITE scope")
    end = min(cursor+limit,census.life_entry_count)
    expected = tuple((index,entry) for index,entry in enumerate(census.entries[cursor:end],cursor)
        if entry.classification != "fixed_v1")
    if (page.next_cursor != (None if end == census.life_entry_count else end)
            or tuple(item.entry_index for item in page.items) != tuple(index for index,_ in expected)):
        raise AuthorityUnavailable("labor segment page omitted or repeated an actual census entry")
    for item,(index,entry) in zip(page.items,expected,strict=True):
        s = item.segment
        if (item.entry_digest != canonical_digest(entry)
                or (s.namespace,s.execution_id,s.effect_id,s.binding_digest,s.prepared_digest)
                    != (census.namespace,entry.execution_id,entry.binding.effect_id,entry.binding_digest,entry.prepared_digest)
                or (s.claim_sequence,s.claim_digest,s.terminal_sequence,s.terminal_digest)
                    != (entry.claim_sequence,entry.claim_digest,entry.terminal_sequence,entry.terminal_digest)
                or ("claimed" if s.status == "active" else s.status) != entry.status):
            raise AuthorityUnavailable("labor page segment is not the exact original census lifecycle")
    wire = character_labor_segment_page_to_wire_v1(page)
    signature = wire.pop("signature")
    issuer._signer.verify(PAGE_SIGN_KIND,canonical_serialize(wire),signature)
    return page


class _CensusSegmentContextV1:
    def __init__(self, facade,work,entry,basis,accounting):
        self.facade,self.work,self.entry,self.basis,self.accounting = facade,work,entry,basis,accounting
        self.thread,self.identity = get_ident(),object()
        _PAGE_CONTEXTS[self] = self.identity


def require_character_labor_census_segment_context_v1(service, *, binding, permit, basis):
    context = _PAGE_CONTEXT.get()
    if (type(context) is not _CensusSegmentContextV1
            or _PAGE_CONTEXTS.get(context) is not context.identity or context.thread != get_ident()
            or context.facade.life is not service or context.work.service is not context.facade
            or context.work.permit != permit or context.entry.binding != binding
            or context.basis is not basis or context.work.failure is not None
            or context.work.operation.closed):
        raise AuthorityUnavailable("labor historical segment requires its actual private census-page context")
    _actual(context.work)
    return context.facade,context.work,context.entry,context.accounting


def _page_segment_from_actual_lifecycle_v1(life, entry, basis, claim, terminal, original_segment=None):
    from decimal import Decimal,localcontext
    from ..runtime.clock import _mapping_from_dict
    from ..runtime.d11_character_work_segment_v1 import CharacterWorkSegmentOriginalV1, PROTOCOL
    import json
    b = entry.binding
    mapping = _mapping_from_dict(json.loads(basis.clock_mapping_json))
    if (claim is None or claim.binding != b or claim.payload.prepared_digest != basis.prepared_digest
            or (claim.claim_sequence,claim.claim_digest) != (entry.claim_sequence,entry.claim_digest)
            or (None if terminal is None else terminal.terminal_sequence,
                None if terminal is None else terminal.terminal_digest) != (entry.terminal_sequence,entry.terminal_digest)
            or terminal is not None and (terminal.binding != b or terminal.claim != claim)
            or basis.policy.executor_protocol != PROTOCOL or not basis.policy.accept_local_write_wait
            or (mapping.mapping_id,mapping.version) != (basis.quote.clock_mapping_ref,basis.quote.clock_mapping_version)
            or (claim.payload.clock_mapping_ref,claim.payload.clock_mapping_version) != (mapping.mapping_id,mapping.version)):
        raise AuthorityUnavailable("labor census page lost its exact signed start/terminal/clock/policy")
    with localcontext() as context:
        context.prec = 28
        if Decimal(claim.payload.character_at) != mapping.character_at(claim.payload.claimed_at_utc):
            raise AuthorityUnavailable("labor census page start is not its actual clock endpoint")
        if terminal is not None and terminal.payload.character_at is not None:
            if Decimal(terminal.payload.character_at) != mapping.character_at(terminal.payload.completed_at_utc):
                raise AuthorityUnavailable("labor census page terminal is not its actual clock endpoint")
    material = dict(namespace=b.namespace,effect_id=b.effect_id,execution_id=b.execution_id,
        segment_id="character-work:"+canonical_digest((b.namespace,b.effect_id,b.execution_id,b.digest,
            claim.claim_sequence,claim.claim_digest)),binding_digest=b.digest,prepared_digest=basis.prepared_digest,
        admission_ref=basis.admission_ref,admission_original_digest=basis.admission_digest,
        body_preparation_ref=basis.body_preparation_ref,body_preparation_digest=basis.body_preparation_digest,
        recipe_ref=basis.recipe_ref,recipe_revision=basis.recipe_revision,recipe_digest=basis.recipe_digest,
        policy_digest=basis.policy_digest,
        component_ids=tuple(c.component_id for c in (*basis.policy.fixed_components,*basis.policy.duration_components)),
        channel_id="main_focus",executor_protocol=PROTOCOL,algorithm_build_digest=b.algorithm_build_digest,
        clock_mapping_ref=mapping.mapping_id,clock_mapping_version=mapping.version,
        clock_original_digest=basis.clock_original_digest,claim_original_ref=claim.original_ref,
        claim_sequence=claim.claim_sequence,claim_digest=claim.claim_digest,
        terminal_original_ref=None if terminal is None else terminal.original_ref,
        terminal_sequence=None if terminal is None else terminal.terminal_sequence,
        terminal_digest=None if terminal is None else terminal.terminal_digest,
        started_at_utc=claim.payload.claimed_at_utc,from_character=claim.payload.character_at,
        ended_at_utc=None if terminal is None else terminal.payload.completed_at_utc,
        to_character=None if terminal is None else terminal.payload.character_at,
        status="active" if terminal is None else terminal.payload.status,
        schema="d11.character-work-segment-original.v1")
    if original_segment is not None:
        if type(original_segment) is not CharacterWorkSegmentOriginalV1:
            raise AuthorityUnavailable("retired labor history returned no exact original signed segment")
        original = plain_v1(original_segment)
        original.pop("signature")
        if original != plain_v1(material):
            raise AuthorityUnavailable("retained signed labor segment differs from its original lifecycle and basis")
        return original_segment
    if b.manifest_digest != life.manifest_digest or b.installation_id != life.installation_id:
        raise AuthorityUnavailable("historical labor segment requires its original protected signature")
    return CharacterWorkSegmentOriginalV1(**material,signature=life._sign(material))


def _finish_census_segment_page_v1(facade,work,reader,value):
    from .d11_life_journal_v1 import read_life_rows_locked_v1
    life = _service(facade)
    selected = work.request.segment_page
    if value != selected.census:
        raise AuthorityUnavailable("labor census page cannot join mixed-time Core/Graph captures")
    items = []
    end = min(selected.cursor+selected.limit,len(value.entries))
    for index in range(selected.cursor,end):
        entry = value.entries[index]
        if entry.classification == "fixed_v1":
            continue
        basis,accounting = reader.page_bases[entry.execution_id]
        context = _CensusSegmentContextV1(facade,work,entry,basis,accounting)
        token = _PAGE_CONTEXT.set(context)
        try:
            with life._frozen() as (db,deletion,execution,_):
                anchor,_ = life._current(db,deletion,execution)
                if anchor != value.anchor:
                    raise AuthorityUnavailable("labor page Core head changed after metadata EOF")
                life.bridge.fences.validate_fence_locked(db,work.permit,subject=work.subject,current_anchor=anchor)
                original_segment = None
                actual,claim,terminal,claim_row,terminal_row = read_life_rows_locked_v1(life.bridge.journal,entry.binding)
                if actual != execution:
                    raise AuthorityUnavailable("labor page requires the complete actual verified journal")
                if claim is not None:
                    life._verify_payload(claim.payload)
                    if terminal is not None: life._verify_payload(terminal.payload)
                elif entry.classification == "retained_duration_v1":
                    from .character_labor_execution_history_v1 import read_runtime_character_labor_execution_history_v1
                    history = read_runtime_character_labor_execution_history_v1(life,db,binding=entry.binding,permit=work.permit,basis=basis)
                    if history is None:
                        raise AuthorityUnavailable("retired labor census entry has no authenticated historical lifecycle")
                    claim,terminal,original_segment = history.claim,history.terminal,history.segment
                else:
                    raise AuthorityUnavailable("actual census claim missing from its verified lifecycle")
                segment = _page_segment_from_actual_lifecycle_v1(life,entry,basis,claim,terminal,original_segment)
            items.append(CharacterLaborSegmentPageItemV1(index,canonical_digest(entry),segment))
        finally:
            _PAGE_CONTEXT.reset(token)
            _PAGE_CONTEXTS.pop(context,None)
    require_character_labor_census_permission_v1(facade,credential=work.credential,
        subject=work.subject,permit=work.permit,request=work.request)
    page = CharacterLaborSegmentPageV1(value.namespace,value.operation_id,value.permit_digest,
        canonical_digest(value),value.ordered_entry_root,value.life_entry_count,value.selection_digest,
        value.anchor,value.graph_stamp,value.body_state,value.body_state_value_digest,value.body_state_cursor,
        selected.cursor,None if end == len(value.entries) else end,tuple(items),"0"*64)
    raw = character_labor_segment_page_to_wire_v1(page); raw.pop("signature")
    return replace(page,signature=facade.issuer._signer.sign(PAGE_SIGN_KIND,canonical_serialize(raw)))
