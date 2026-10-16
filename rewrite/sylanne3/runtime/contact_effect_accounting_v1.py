"""Original Contact message budget: signed birth, bodyless Work and one Graph CAS."""
from __future__ import annotations
from dataclasses import asdict, dataclass, fields, is_dataclass, replace
import json
import secrets
import sys
import time
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.contact_effect_accounting_contract_v1 import (
    ContactEffectBudgetOriginV1, SignedContactEffectBudgetOriginV1,
    ContactEffectAccountingRequestV1, ContactEffectAccountingGrantV1, ContactEffectCostFactV1,
    ORIGIN_SIGN, SETTLEMENT_SIGN, encoded_v1, to_wire, from_wire, measurement_quantities_v1,
)
from ..graph_worker import (GraphStorageStepV3, create_graph_storage_work_v3,
    require_graph_storage_work_admission_v3)
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, finish_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, runtime_storage_quantum_v3, _runtime_bounded_fixed_row_v3)
from .budget import settle_budget, settle_budget_partial, resolve_partial_budget, resolve_unconfirmed

ORIGINAL_TABLE = "graph_contact_effect_originals_v1"
ATTEMPT_TABLE = "graph_contact_effect_accounting_attempts_v1"
ORIGINAL_COLUMNS = ("bot", "persona", "kind", "original_ref", "payload_json", "payload_digest", "signature")
ATTEMPT_COLUMNS = ("bot", "persona", "operation_id", "origin_digest", "fact_digest", "request_json", "state")
ORIGINAL_DDL = """CREATE TABLE IF NOT EXISTS graph_contact_effect_originals_v1 (
 bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('origin','settlement')),
 original_ref TEXT NOT NULL, payload_json TEXT NOT NULL CHECK(length(CAST(payload_json AS BLOB))<=65536),
 payload_digest TEXT NOT NULL, signature TEXT NOT NULL,
 PRIMARY KEY(bot,persona,kind,original_ref)) STRICT"""
ATTEMPT_DDL = """CREATE TABLE IF NOT EXISTS graph_contact_effect_accounting_attempts_v1 (
 bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL, origin_digest TEXT NOT NULL,
 fact_digest TEXT NOT NULL, request_json TEXT NOT NULL CHECK(length(CAST(request_json AS BLOB))<=65536),
 state TEXT NOT NULL CHECK(state IN ('open','committed','closed')),
 PRIMARY KEY(bot,persona,operation_id)) STRICT"""
ORIGINAL_TRIGGER_DDLS = tuple("CREATE TRIGGER IF NOT EXISTS " + ORIGINAL_TABLE + "_no_" + action.lower() +
    " BEFORE " + action + " ON " + ORIGINAL_TABLE +
    " BEGIN SELECT RAISE(ABORT,'Contact financial original is immutable'); END" for action in ("UPDATE", "DELETE"))
_KEY = object()
_WORKS = WeakKeyDictionary()
_COMPLETION_PROOFS = WeakKeyDictionary()


def install_contact_effect_schema_v1(db):
    db.execute(ORIGINAL_DDL); db.execute(ATTEMPT_DDL)
    for ddl in ORIGINAL_TRIGGER_DDLS: db.execute(ddl)


def _record(db, namespace, kind, ref, value, signature):
    raw = to_wire(value) if kind == "origin" else value
    wire, digest = canonical_serialize(raw), canonical_digest(raw)
    if len(wire.encode("utf-8")) > 65536:
        raise AuthorityUnavailable("Contact financial original exceeds its closed metadata bound")
    row = db.execute("SELECT payload_json,payload_digest,signature FROM " + ORIGINAL_TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone()
    if row is not None:
        if row != (wire, digest, signature): raise AuthorityUnavailable("Contact financial original conflicts")
        return
    db.execute("INSERT INTO " + ORIGINAL_TABLE + " VALUES(?,?,?,?,?,?,?)",
        (*namespace.as_tuple, kind, ref, wire, digest, signature))


def record_contact_effect_budget_origin_v1(graph, db, *, material, admission, request):
    from .contact_final_stage_v3 import require_installed_contact_material_v3
    from ..graph_coordinator import budget_operation_digest
    m = require_installed_contact_material_v3(material)
    if not db.in_transaction or m.runtime.graph is not graph or admission.admission.operation_id != request.operation_id:
        raise AuthorityUnavailable("Contact budget birth requires its actual final admission CAS")
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    # Keep the actual signed quote and its exact pre-existing reserve; issue nothing here.
    quote, ns = m.quote, m.scope.namespace
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (quote.parent_budget_lease_ref, quote.operation_id)).fetchone()
    digest = budget_operation_digest(m.frame.envelope, quote.parent_budget_lease_ref, dict(quote.ceiling))
    if reservation is None or reservation[0] != digest or json.loads(reservation[1]) != dict(quote.ceiling) or reservation[2] != "reserved":
        raise AuthorityUnavailable("Contact final has no matching original budget reservation")
    policy = bundle.contact_effect_accounting
    if policy is not None and (not policy.valid_from_utc <= m.frame.now_utc < policy.valid_until_utc
            or set(dict(policy.unit_cost)) != set(quote.ceiling)):
        raise AuthorityUnavailable("Contact installed price has no exact original quote dimensions or validity")
    original = ContactEffectBudgetOriginV1(ns, bundle.installation_policy.installation_id,
        bundle.installation_policy.authority_namespace, request.operation_id, request.activity_id,
        request.effect_id, request.attempt_id, admission.admission.admission_ref, admission.receipt_digest,
        canonical_digest(request), quote.quote_id, quote.version, canonical_digest(quote),
        quote.parent_budget_lease_ref, quote.operation_id, digest, tuple(sorted(quote.ceiling.items())),
        m.final_bundle.persistent_job_refs[0], m.final_bundle.outbox_refs[0], quote.deadline_utc, policy)
    issuer = graph._GraphCoordinator__d11_issuer
    signed = SignedContactEffectBudgetOriginV1(original, issuer._signer.sign(ORIGIN_SIGN, encoded_v1(original)))
    _record(db, ns, "origin", request.operation_id, signed, signed.signature)
    return signed


@dataclass(frozen=True, slots=True)
class ContactEffectSettlementResultV1:
    operation_id: str
    effect_id: str
    cost_ref: str
    budget_status: str
    observation_outcome: str
    fact_digest: str
    origin_digest: str
    budget_receipt_digest: str
    accounting_finished: bool

    @property
    def prefix_ready(self):
        return (self.accounting_finished and self.budget_status == "settled"
            and self.observation_outcome in {"accepted", "delivered"})


class ContactEffectCompletionProofV1:
    """Actual paid-prefix fact. Source and Owner requalification is separate."""
    __slots__ = ("_state", "_result", "__weakref__")
    def __init__(self, key, state, result):
        if (key is not _KEY or state.phase != "readback" or not state.accounting_ack
                or type(result) is not ContactEffectSettlementResultV1 or not result.accounting_finished):
            raise AuthorityUnavailable("Contact completion proof requires actual finished accounting readback")
        self._state, self._result = state, result
        _COMPLETION_PROOFS[self] = (state, result)
    def _current(self):
        state = self._state
        if (state.closed or state.operation.closed or state.proof is not self
                or _COMPLETION_PROOFS.get(self) != (state, self._result)
                or _WORKS.get(state) != (state.service, state.operation, state.original_operation_id, state.mode)):
            raise AuthorityUnavailable("Contact financial proof lost its actual original retention lifetime")
        state.service.current()
        return state
    @property
    def prefix_ready(self):
        self._current()
        return self._result.prefix_ready
    @property
    def accounting_finished(self):
        self._current()
        return self._result.accounting_finished
    @property
    def result(self):
        self._current()
        return self._result
    @property
    def current_effect_fact(self):
        return self._current().current_fact


def require_contact_effect_completion_proof_v1(proof, *, namespace, original_operation_id,
        effect_id, admission_ref, parent_budget_lease_ref, quote_id, quote_version,
        observed_receipt_digest):
    if type(proof) is not ContactEffectCompletionProofV1:
        raise AuthorityUnavailable("actual private Contact financial completion proof required")
    state = proof._current()
    origin = state.origin.origin
    if ((origin.namespace, origin.operation_id, origin.effect_id, origin.admission_ref,
            origin.parent_budget_lease_ref, origin.quote_id, origin.quote_version) != (
            namespace, original_operation_id, effect_id, admission_ref,
            parent_budget_lease_ref, quote_id, quote_version) or not proof.prefix_ready
            or state.current_fact.observed_receipt_digest != observed_receipt_digest):
        raise AuthorityUnavailable("Contact effect, original cost or completion linkage remains unresolved")
    return proof.result


class InstalledContactEffectRuntimeV1:
    def __init__(self, key, graph, bootstrap, bundle, port):
        from ..host.authority_profile import AdminInstallationBundle
        from ..host.contact_effect_accounting_port_v1 import InstalledContactEffectAccountingPortV1
        graph._admin(bootstrap)
        if key is not _KEY or type(bundle) is not AdminInstallationBundle or type(port) is not InstalledContactEffectAccountingPortV1:
            raise AuthorityUnavailable("actual installed Contact financial runtime required")
        self.graph, self.bootstrap, self.bundle, self.port = graph, bootstrap, bundle, port
        self.store, self.namespace = graph._GraphCoordinator__store, bundle.installation_policy.namespace
        self.issuer, self.resource = graph._GraphCoordinator__d11_issuer, graph._GraphCoordinator__d02_issuer
    def current(self):
        self.graph._admin(self.bootstrap)
        if self.graph._GraphCoordinator__contact_effect_runtime_v1 is not self:
            raise AuthorityUnavailable("Contact financial runtime was replaced")
        return self


def install_contact_effect_runtime_v1(graph, bootstrap, bundle, fence_port):
    from ..host.contact_effect_accounting_port_v1 import install_contact_effect_accounting_port_v1
    service = InstalledContactEffectRuntimeV1(_KEY, graph, bootstrap, bundle,
        install_contact_effect_accounting_port_v1(fence_port, bundle))
    with service.store._lock: install_contact_effect_schema_v1(service.store._db)
    graph._GraphCoordinator__contact_effect_runtime_v1 = service
    return service


def _heap(value, seen):
    if value is None or id(value) in seen: return 0
    seen.add(id(value)); size = sys.getsizeof(value)
    if type(value) is dict:
        return size + sum(_heap(k, seen) + _heap(v, seen) for k, v in value.items())
    if type(value) in {tuple, list}:
        return size + sum(_heap(v, seen) for v in value)
    if type(value) is ContactEffectCompletionProofV1:
        return size + _heap(value._result, seen)
    from ..runtime_storage_v3 import RuntimeCellReadV3
    from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
    if type(value) is RuntimeCellReadV3:
        return size+sys.getsizeof(value.__dict__)+_heap((value.cell_id,value.header,value.ordinal,value.offset,value.root,value.complete),seen)+sys.getsizeof(value.hash)
    if type(value) is C09CanonicalJSONStreamV2:
        from ..authority_service.owner_location_read_v3 import _owner_location_parser_heap_v3
        return _owner_location_parser_heap_v3(value,set())
    if is_dataclass(value):
        dictionary = getattr(value, "__dict__", None)
        return size + (_heap(dictionary, seen) if dictionary is not None else 0) + sum(_heap(getattr(value, f.name), seen) for f in fields(value))
    return size


class _FinancialMetadataProgressV1(Exception):
    pass


@dataclass(slots=True)
class _FinancialJSONColumnV1:
    table: str
    column: str
    where: str
    args: tuple
    length: int | None = None
    position: int = 0
    raw: bytearray = None
    quote: bool = False
    escape: bool = False
    number: bool = False
    objects: int = 0
    arrays: int = 0
    strings: int = 0
    numbers: int = 0
    keys: int = 0
    digits: int = 0
    literals: int = 0
    wire: str | None = None
    decoded: object = None
    cell_id: str | None = None
    cell: object = None
    canonical_parser: object = None
    canonical_eof: object = None

    def feed(self, raw):
        self.raw.extend(raw)
        for byte in raw:
            if self.quote:
                if self.escape: self.escape = False
                elif byte == 92: self.escape = True
                elif byte == 34: self.quote = False
            elif byte == 34: self.quote = True; self.strings += 1; self.number = False
            elif byte == 123: self.objects += 1; self.number = False
            elif byte == 91: self.arrays += 1; self.number = False
            elif byte == 58: self.keys += 1; self.number = False
            elif byte in b"-0123456789":
                if not self.number: self.numbers += 1; self.number = True
                if 48 <= byte <= 57: self.digits += 1
            elif byte in b".eE+": pass
            elif byte in b"tfn": self.literals += 1; self.number = False
            else: self.number = False

    def decode_bound(self):
        # CPython 3.12 x64, actual JSON census, including initial list capacity.
        pointer = 8
        nodes = self.objects + self.arrays + self.strings + self.numbers + self.literals
        dictionaries = self.objects*(sys.getsizeof({})+8*(8+24)) + self.keys*(4*8+3*24)
        arrays = self.arrays*(sys.getsizeof([])+8*pointer) + nodes*2*pointer
        strings = self.strings*sys.getsizeof(chr(0x10000)) + 4*self.length
        integers = self.numbers*(sys.getsizeof(0)+4) + 4*((self.digits+8)//9)
        typed = self.objects*(2*sys.getsizeof({})+32*(4*pointer+24)) + self.arrays*sys.getsizeof(()) + nodes*pointer
        # JSON, typed construction, canonical material and encoding coexist.
        return 3*(dictionaries+arrays+strings+integers)+typed+5*(4*self.length+sys.getsizeof(""))

    def advance(self, state, meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2
        if self.wire is not None:return
        state.require_current(meter)
        if self.cell_id is not None:
            from ..runtime_storage_v3 import RuntimeCellReadV3
            from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            if self.cell is None:
                self.cell=RuntimeCellReadV3(state.operation.handle,self.cell_id,
                    erasure_owner_ref=self.args[0],meter=meter)
                self.length=self.cell.header[3]
                if self.cell.header[0] not in {"canonical-json.ascii.v1","canonical-json.utf8.v1"} or not 0<self.length<=65536:
                    raise AuthorityUnavailable("Contact cost cell exceeds its registered financial metadata bound")
                self.raw=bytearray()
                self.canonical_parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=="canonical-json.ascii.v1")
            if self.cell.ordinal<self.cell.header[4]:
                size=min(16384,self.length-self.position)
                bound=2*size+2*((self.position+size)*9//8+8)+1024
                state.operation.reserve_retained_state_growth_v3(state,bound)
                try:
                    chunk=self.cell.read_fragment(meter=meter)
                    self.feed(chunk);self.canonical_parser.feed(chunk,lambda event:None)
                    self.position+=len(chunk)
                finally:state.operation.finish_retained_state_growth_v3(state)
                raise _FinancialMetadataProgressV1()
            digest=self.cell.finish(meter=meter)
            self.canonical_eof=self.canonical_parser.finish()
            if self.position!=self.length or self.canonical_eof.byte_count!=self.length or self.canonical_eof.sha256!=digest:
                raise AuthorityUnavailable("Contact cost financial cell lacks complete canonical EOF")
        else:
            with legacy_cell_read_transaction_v2(state.db):
                if self.length is None:
                    _,self.length,kind=read_legacy_sql_cell_fragment_v2(state.db,table=self.table,column=self.column,
                        where=self.where,parameters=self.args,start=0,length=0,meter=meter)
                    if kind!="text" or not 0<self.length<=65536:
                        raise AuthorityUnavailable("Contact financial metadata column is not its bounded original TEXT")
                    self.raw=bytearray()
                size=min(16384,self.length-self.position)
                bound=2*size+2*((self.position+size)*9//8+8)+1024
                state.operation.reserve_retained_state_growth_v3(state,bound)
                try:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(state.db,table=self.table,column=self.column,
                        where=self.where,parameters=self.args,start=self.position,length=size,meter=meter)
                    if total!=self.length or kind!="text":raise AuthorityUnavailable("Contact financial TEXT changed during EOF")
                    self.feed(chunk);self.position+=len(chunk)
                finally:state.operation.finish_retained_state_growth_v3(state)
            if self.position<self.length:raise _FinancialMetadataProgressV1()
        if self.quote or self.escape:raise AuthorityUnavailable("Contact financial JSON has no complete string EOF")
        state.operation.reserve_retained_state_growth_v3(state,self.decode_bound())
        try:
            self.wire=bytes(self.raw).decode("utf8" if self.cell_id is not None else "ascii")
            self.decoded=json.loads(self.wire);self.raw=None
        finally:state.operation.finish_retained_state_growth_v3(state)


class ContactEffectAccountingWorkV1:
    def __init__(self, service, operation_id, mode, operation):
        self.service, self.original_operation_id, self.mode, self.operation = service, operation_id, mode, operation
        self.graph, self.store, self.db, self.namespace = service.graph, service.store, service.store._db, service.namespace
        self.phase, self.closed, self.work = "origin", False, None
        self.origin = self.fact = self.request = self.grant = self.result = self.attempt = self.current_fact = None
        self.graph_stamp = self.graph._v2_graph_stamp(self.namespace)
        self.business_operation_id = None
        self.anchor = None
        self.accounting_ack, self.proof = False, None
        self.columns = {}
        self.decoded = {}
        _WORKS[self] = (service, operation, operation_id, mode)
        operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return sys.getsizeof(self) + sys.getsizeof(self.__dict__) + _heap((self.origin, self.fact, self.request, self.grant,
            self.result, self.attempt, self.current_fact, self.graph_stamp, self.business_operation_id, self.anchor, self.proof, self.columns, self.decoded), set())
    def require_current(self, meter=None):
        if (self.closed or _WORKS.get(self) != (self.service, self.operation, self.original_operation_id, self.mode)
                or self.work is None or self.work.state is not self or self.work.operation is not self.operation):
            raise AuthorityUnavailable("actual Contact financial metadata Work ended")
        self.service.current()
        if meter is not None: self.operation.handle.require_current(meter)
        if self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp:
            raise AuthorityUnavailable("Contact financial Graph changed between quanta")
    def release_payload_v3(self):
        self.closed = True
        _WORKS.pop(self, None)
        if self.proof is not None: _COMPLETION_PROOFS.pop(self.proof, None)
        self.proof = None
        self.origin = self.fact = self.request = self.grant = self.result = self.attempt = None
        self.columns.clear(); self.decoded.clear()
        self.operation.unregister_retained_state_v3(self)
    def row(self, meter, table, columns, where, args):
        self.require_current(meter)
        json_columns = tuple(name for name in columns if name.endswith("_json") or table == "graph_atoms" and name == "value")
        if table=="graph_atoms" and "value" in json_columns:
            from ..graph_types import AtomKey
            from ..runtime_storage_v3 import runtime_storage_v3
            if columns!=("value","valid") or where!="token=?" or len(args)!=1 or self.origin is None or self.business_operation_id is None:
                raise AuthorityUnavailable("Contact financial Graph recipe is the original cost projection only")
            key=AtomKey.from_token(args[0]);origin=self.origin.origin
            if (key.type_name!="runtime.cost_settlement" or key.owner.kind!="activity"
                    or (key.owner.bot,key.owner.persona,key.owner.subject)!=(*origin.namespace.as_tuple,origin.activity_id)):
                raise AuthorityUnavailable("Contact financial cost selector changed its original activity/namespace")
            original=self.decoded.get(("settlement",self.business_operation_id))
            if original is None or original[2].cost_ref!=args[0]:
                raise AuthorityUnavailable("Contact financial cost ref lacks its actual signed settlement selector")
            handle=runtime_storage_v3(self.db)
            if handle is not None:
                if handle is not self.operation.handle:raise AuthorityUnavailable("Contact financial cost cell crossed its actual retained operation")
                fixed=_runtime_bounded_fixed_row_v3(self.db,meter,table,("revision","valid","value_cell_id"),where,args)
                if fixed is None:return None
                revision,valid,cell_id=fixed
                if type(revision) is not int or revision<1 or valid!=1:
                    raise AuthorityUnavailable("Contact financial cost atom has no current valid revision")
                if cell_id is None:raise AuthorityUnavailable("Contact financial V3 cost has no actual sealed cell")
                key=(table,"value_cell_id",where,tuple(args),revision,valid,cell_id)
                reader=self.columns.get(key)
                if reader is None:
                    self.operation.reserve_retained_state_growth_v3(self,64*8+2*sys.getsizeof(self.columns)+1024)
                    try:
                        reader=_FinancialJSONColumnV1(table,"value_cell_id",where,tuple(args),cell_id=cell_id)
                        self.columns[key]=reader
                    finally:self.operation.finish_retained_state_growth_v3(self)
                reader.advance(self,meter)
                return reader.wire,valid
        small = tuple(name for name in columns if name not in json_columns)
        if small:
            fixed = _runtime_bounded_fixed_row_v3(self.db, meter, table, small, where, args)
            if fixed is None: return None
            values = dict(zip(small, fixed, strict=True))
        else:
            if self.db.execute("SELECT 1 FROM " + table + " WHERE " + where + " LIMIT 1", args).fetchone() is None: return None
            values = {}
        for column in json_columns:
            scalar = self.db.execute("SELECT typeof(" + column + ") FROM " + table + " WHERE " + where + " LIMIT 1", args).fetchone()
            meter.charge_read(16)
            if scalar == ("null",):
                values[column] = None
                continue
            key = (table, column, where, tuple(args))
            reader = self.columns.get(key)
            if reader is None:
                self.operation.reserve_retained_state_growth_v3(self, 64*8 + 2*sys.getsizeof(self.columns) + 1024)
                try:
                    reader = _FinancialJSONColumnV1(table, column, where, tuple(args))
                    self.columns[key] = reader
                finally: self.operation.finish_retained_state_growth_v3(self)
            reader.advance(self, meter)
            values[column] = reader.wire
        return tuple(values[name] for name in columns)
    def decode(self, wire, decode):
        key = (wire, decode)
        if key in self.decoded: return self.decoded[key]
        reader = next((value for value in self.columns.values() if value.wire is wire), None)
        if reader is None: raise AuthorityUnavailable("Contact financial decode lacks its actual full EOF census")
        self.operation.reserve_retained_state_growth_v3(self, reader.decode_bound())
        try:
            value = decode(reader.decoded)
            self.decoded[key] = value
            return value
        finally: self.operation.finish_retained_state_growth_v3(self)
    def original(self, meter, kind, ref):
        row = self.row(meter, ORIGINAL_TABLE, ("payload_json", "payload_digest", "signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?", (*self.namespace.as_tuple, kind, ref))
        if row is None: return None
        raw = next(value.decoded for value in self.columns.values() if value.wire is row[0])
        if canonical_digest(raw) != row[1]: raise AuthorityUnavailable("Contact financial original digest differs")
        if kind == "origin":
            signed = self.decode(row[0], _decode_signed_origin_v1)
            self.service.issuer._signer.verify(ORIGIN_SIGN, encoded_v1(signed.origin), signed.signature)
            if (signed.signature != row[2] or signed.origin.namespace != self.namespace
                    or signed.origin.operation_id != ref):
                raise AuthorityUnavailable("Contact budget original row identity differs")
            return signed
        self.service.issuer._signer.verify(SETTLEMENT_SIGN, canonical_serialize(raw), row[2])
        reader = next(value for value in self.columns.values() if value.wire is row[0])
        key = ("settlement", ref)
        if key not in self.decoded:
            self.operation.reserve_retained_state_growth_v3(self, reader.decode_bound())
            try:
                self.decoded[key] = (restore_stored_fact_v1(raw, self.origin),
                    raw["request_ref"], ContactEffectSettlementResultV1(**raw["result"]))
            finally: self.operation.finish_retained_state_growth_v3(self)
        return raw


def prepare_contact_effect_accounting_work_v1(graph, operation_id, *, mode="settle"):
    service = getattr(graph, "_GraphCoordinator__contact_effect_runtime_v1", None)
    if type(service) is not InstalledContactEffectRuntimeV1 or mode not in {"sender", "settle"}:
        raise AuthorityUnavailable("actual installed Contact effect accounting is unavailable")
    service.current(); require_graph_storage_work_admission_v3(graph)
    if type(operation_id) is not str or not 1 <= len(operation_id) <= 128:
        raise ValueError("exact original Contact operation locator required")
    retained = begin_runtime_storage_operation_v3(service.store._db, operation_id, None)
    try:
        state = ContactEffectAccountingWorkV1(service, operation_id, mode, retained)
        work = create_graph_storage_work_v3(graph, kind="contact_effect_accounting_v1", operation_id=operation_id,
            selection_digest=retained.selection_digest, deadline_utc=None, state=state, operation=retained)
        state.work = work
        return work
    except BaseException:
        finish_runtime_storage_operation_v3(retained)
        raise


def _business_receipt(state, meter):
    raw = state.original(meter, "settlement", state.business_operation_id)
    if raw is None: return None
    if (set(raw) != {"schema", "result", "fact", "origin_ref", "request_ref", "budget_receipt", "commit_seq", "epoch_revision"}
            or raw["schema"] != "d11.contact-effect-settlement-original.v1"
            or state.decoded[("settlement", state.business_operation_id)][0] != state.fact):
        raise AuthorityUnavailable("Contact cost committed original differs")
    result = state.decoded[("settlement", state.business_operation_id)][2]
    if (result.operation_id != state.business_operation_id or result.origin_digest != state.origin.origin.digest
            or result.fact_digest != state.fact.digest or result.accounting_finished):
        raise AuthorityUnavailable("Contact budget receipt may not assert future Authority finish")
    event = state.row(meter, "graph_events", ("event_id",), "bot=? AND persona=? AND session=? AND event_id=?",
        (*state.namespace.as_tuple, state.origin.origin.activity_id, state.business_operation_id))
    operation = state.row(meter, "graph_bundle_operations", ("receipt_json", "commit_seq"),
        "bot=? AND persona=? AND operation_id=?", (*state.namespace.as_tuple, state.business_operation_id))
    from ..graph_types import AtomKey
    key = AtomKey.from_token(result.cost_ref)
    origin = state.origin.origin
    if (key.type_name != "runtime.cost_settlement" or key.owner.kind != "activity"
            or (key.owner.bot, key.owner.persona, key.owner.subject) != (*origin.namespace.as_tuple, origin.activity_id)):
        raise AuthorityUnavailable("Contact cost reference is not its original D11 activity")
    atom = state.row(meter, "graph_atoms", ("value", "valid"), "token=?", (result.cost_ref,))
    if event is None or operation is None or json.loads(operation[0]) != raw or operation[1] != raw["commit_seq"] or atom is None or atom[1] != 1:
        raise AuthorityUnavailable("Contact cost original lacks its actual Graph event/operation/atom")
    cost = state.decode(atom[0], _decode_cost_value_v1)
    budget_phase = "settle" if raw["budget_receipt"]["operation_id"] == origin.reservation_operation_id else "resolve"
    budget = state.row(meter, "runtime_budget_operations", ("receipt_json",),
        "bot_id=? AND persona_id=? AND operation_id=? AND phase=?",
        (*origin.namespace.as_tuple, raw["budget_receipt"]["operation_id"], budget_phase))
    if (budget is None or json.loads(budget[0]) != raw["budget_receipt"]
            or cost.bundle_operation_id != result.operation_id or cost.effect_id != origin.effect_id
            or cost.cost_operation_id != origin.reservation_operation_id
            or cost.lease_id != origin.parent_budget_lease_ref or cost.status != result.budget_status
            or cost.budget_receipt_digest != result.budget_receipt_digest):
        raise AuthorityUnavailable("Contact cost readback differs from actual D11 budget and cost projection")
    return raw


def _commit_cost(state, meter):
    from ..contracts import Event, Scope
    from ..graph_types import AtomKey, GraphCandidate, GraphVersion
    from ..graph_store import GraphStore
    from .d11_types import cost_settlement_from_runtime, cost_settlement_graph_write, reconcile_runtime_write, validate_d11_writes
    db, service, graph, origin = state.db, state.service, state.graph, state.origin.origin
    state.require_current(meter)
    if _business_receipt(state, meter) is not None:
        raise AuthorityUnavailable("Contact cost appeared before its original CAS")
    quote_row = state.row(meter, "runtime_resource_quotes", ("quote_json", "signature"),
        "quote_id=? AND version=?", (origin.quote_id, origin.quote_version))
    if quote_row is None: raise AuthorityUnavailable("Contact original signed message quote is absent")
    service.resource._signer.verify("resource-quote.v1", quote_row[0], quote_row[1])
    quote = state.decode(quote_row[0], _decode_message_quote_v1)
    if (canonical_digest(quote) != origin.quote_digest or quote.work_kind != "message"
            or quote.operation_id != origin.reservation_operation_id or quote.parent_budget_lease_ref != origin.parent_budget_lease_ref
            or tuple(sorted(quote.ceiling.items())) != origin.ceiling):
        raise AuthorityUnavailable("Contact original signed message quote differs")
    row = state.row(meter, "runtime_budget_reservations", ("digest", "ceiling_json", "state", "actual_json"),
        "lease_id=? AND operation_id=?", (origin.parent_budget_lease_ref, origin.reservation_operation_id))
    if row is None or row[0] != origin.reservation_digest or json.loads(row[1]) != dict(origin.ceiling):
        raise AuthorityUnavailable("Contact original reservation differs")
    known, unknown = measurement_quantities_v1(state.fact)
    phase, budget_op, prior_ref = "settle", origin.reservation_operation_id, None
    if row[2] == "reserved":
        if known and unknown:
            receipt = settle_budget_partial(db, origin.parent_budget_lease_ref, budget_op, origin.reservation_digest,
                known, unknown, execution_revoked=True)
        else:
            receipt = settle_budget(db, origin.parent_budget_lease_ref, budget_op, origin.reservation_digest,
                None if unknown else known, execution_revoked=True)
    elif row[2] in {"unknown", "partial_unknown", "partial_overrun"}:
        if unknown: raise AuthorityUnavailable("Contact original unknown cost still needs actual measured dimensions")
        phase, budget_op = "resolve", state.business_operation_id
        prior_op = "contact-cost-" + canonical_digest((origin.namespace, origin.effect_id, "initial"))[:48]
        prior = state.original(meter, "settlement", prior_op)
        if prior is None or prior["result"]["origin_digest"] != origin.digest:
            raise AuthorityUnavailable("Contact resolution lacks its actual original unknown receipt")
        prior_ref = prior["result"]["cost_ref"]
        resolution_digest = canonical_digest((origin.digest, state.fact.digest, "unknown_resolution"))
        if row[2] == "unknown":
            receipt = resolve_unconfirmed(db, origin.parent_budget_lease_ref, origin.reservation_operation_id,
                budget_op, resolution_digest, known, execution_revoked=True)
        else:
            before = json.loads(row[3])
            if any(known.get(k) != v for k, v in before.items()):
                raise AuthorityUnavailable("Contact resolution changed a previously measured dimension")
            receipt = resolve_partial_budget(db, origin.parent_budget_lease_ref, origin.reservation_operation_id,
                budget_op, resolution_digest, {k:v for k,v in known.items() if k not in before}, execution_revoked=True)
    else:
        raise AuthorityUnavailable("Contact reservation was already settled by another financial original")
    value = cost_settlement_from_runtime(db, bot_id=origin.namespace.bot_id, persona_id=origin.namespace.persona_id,
        activity_id=origin.activity_id, bundle_operation_id=state.business_operation_id, effect_id=origin.effect_id,
        settlement_id=state.business_operation_id, lease_id=origin.parent_budget_lease_ref,
        cost_operation_id=origin.reservation_operation_id, budget_operation_id=budget_op,
        budget_phase=phase, prior_unknown_ref=prior_ref, execution_revoked=True)
    dependencies = () if prior_ref is None else (AtomKey.from_token(prior_ref),)
    write = cost_settlement_graph_write(value, dependencies)
    if not validate_d11_writes((write,), origin.namespace, operation_id=state.business_operation_id,
            activity_id=origin.activity_id, effect_id=origin.effect_id):
        raise AuthorityUnavailable("Contact cost graph projection is invalid")
    reconcile_runtime_write(db, write)
    metadata, epoch = graph._v2_graph_stamp(origin.namespace)
    if not graph._accounting_anchor_covers(metadata.requirements, state.request.expected_anchor):
        raise AuthorityUnavailable("Contact accounting anchor does not cover its actual Graph")
    digest = canonical_digest(("d11.contact-effect-cost-bundle.v1", state.origin.origin.digest, state.fact.digest, asdict(receipt), write))
    event = Event(Scope(*origin.namespace.as_tuple, origin.activity_id), state.business_operation_id,
        time.time(), "domain_bundle", {"bundle_digest": digest})
    reads = [GraphVersion(write.key, 0)]
    if dependencies:
        previous = state.row(meter, "graph_atoms", ("revision", "valid"), "token=?", (prior_ref,))
        if previous is None or previous[1] != 1:
            raise AuthorityUnavailable("Contact resolution lost the actual prior unknown cost atom")
        reads.append(GraphVersion(dependencies[0], previous[0]))
    candidate = GraphCandidate(event, tuple(reads), (write,), (epoch,))
    graph_receipt = GraphStore._graph_commit_in_transaction(state.store, candidate,
        _capability=graph._GraphCoordinator__graph_capability)
    if graph_receipt.status != "committed": raise AuthorityUnavailable("Contact cost Graph event was already present")
    anchor = state.request.expected_anchor
    state.store.cas_graph_recovery_metadata(metadata, replace(metadata.requirements,
        deletion_seq=anchor.deletion_seq, deletion_digest=anchor.deletion_digest,
        execution_seq=anchor.execution_seq, execution_digest=anchor.execution_digest,
        revocation_epoch=anchor.revocation_epoch), _capability=graph._GraphCoordinator__graph_capability)
    row = db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?", origin.namespace.as_tuple).fetchone()
    seq = (0 if row is None else row[0]) + 1
    db.execute("INSERT INTO graph_bundle_sequence(bot,persona,last_seq) VALUES(?,?,?) "
        "ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq", (*origin.namespace.as_tuple, seq))
    result = ContactEffectSettlementResultV1(state.business_operation_id, origin.effect_id, write.key.token,
        receipt.status, state.fact.observation_outcome, state.fact.digest, origin.digest, canonical_digest(asdict(receipt)), False)
    raw = {"schema":"d11.contact-effect-settlement-original.v1", "result":asdict(result),
        "fact":{k:v for k,v in to_wire(state.fact).items() if k != "origin"},
        "origin_ref":origin.operation_id, "request_ref":state.request.operation_id, "budget_receipt":asdict(receipt),
        "commit_seq":seq, "epoch_revision":graph_receipt.epoch.revision}
    _record(db, origin.namespace, "settlement", state.business_operation_id, raw,
        service.issuer._signer.sign(SETTLEMENT_SIGN, canonical_serialize(raw)))
    db.execute("INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) "
        "VALUES(?,?,?,?,?,?,?,?)", (*origin.namespace.as_tuple, state.business_operation_id, digest,
            origin.activity_id, origin.effect_id, seq, canonical_serialize(raw)))
    changed = db.execute("UPDATE " + ATTEMPT_TABLE + " SET state='committed' WHERE bot=? AND persona=? "
        "AND operation_id=? AND request_json=? AND state='open'", (*origin.namespace.as_tuple,
            state.business_operation_id, encoded_v1(state.request))).rowcount
    if changed != 1: raise AuthorityUnavailable("Contact original accounting attempt CAS changed")
    return result


def _advance_contact_effect_accounting_work_v1(graph, work):
    state = work.state
    if type(state) is not ContactEffectAccountingWorkV1 or state.graph is not graph:
        raise AuthorityUnavailable("Contact financial Work is not its actual installed producer")
    state.require_current()
    service, db = state.service, state.db
    with bind_runtime_storage_operation_v3(state.operation, db):
        if state.phase == "fact":
            if db.in_transaction: raise AuthorityUnavailable("Contact cost RPC cannot run inside Graph SQL")
            state.fact = state.current_fact = service.port.read_fact(state.origin)
            state.phase = "select"
            return GraphStorageStepV3("progress")
        if state.phase == "recover":
            # Close only the saved original maintenance attempt, never the execution call.
            try:
                service.port.recover_finish(state.request)
            except Exception:
                grant = service.port.begin(state.request)
                service.port.finish(state.request, grant)
            state.phase = "closed"
            return GraphStorageStepV3("progress")
        if state.phase == "anchor":
            state.anchor = service.port.port.current_anchor(namespace=state.namespace,
                authority_namespace=state.origin.origin.authority_namespace)
            state.phase = "attempt"
            return GraphStorageStepV3("progress")
        if state.phase == "begin":
            state.grant = service.port.begin(state.request)
            if (type(state.grant) is not ContactEffectAccountingGrantV1
                    or state.grant.fact_digest != state.fact.digest
                    or state.grant.origin_digest != state.origin.origin.digest
                    or state.grant.effect_id != state.origin.origin.effect_id):
                raise AuthorityUnavailable("Contact actual accounting grant differs")
            service.port.validate(state.request, state.grant)
            state.phase = "warm_cost"
            return GraphStorageStepV3("progress")
        if state.phase == "finish":
            service.port.recover_finish(state.request)
            state.accounting_ack = True
            state.phase = "readback"
            return GraphStorageStepV3("progress")
        if state.phase == "commit":
            service.port.validate(state.request, state.grant)
        with state.store._lock, runtime_storage_quantum_v3(db) as meter:
            db.execute("BEGIN IMMEDIATE" if state.phase in {"attempt", "closed", "commit"} else "BEGIN")
            committed = False
            try:
                state.require_current(meter)
                if state.phase == "origin":
                    state.origin = state.original(meter, "origin", state.original_operation_id)
                    if state.origin is None: raise AuthorityUnavailable("actual Contact budget birth original unavailable")
                    if state.mode == "sender":
                        if state.origin.origin.pricing_policy is None:
                            raise AuthorityUnavailable("waiting_for_installed_contact_effect_pricing")
                        return GraphStorageStepV3("complete", (state.origin, service.port))
                    state.phase = "fact"
                elif state.phase == "select":
                    origin = state.origin.origin
                    initial = "contact-cost-" + canonical_digest((origin.namespace, origin.effect_id, "initial"))[:48]
                    previous = state.original(meter, "settlement", initial)
                    state.business_operation_id = initial
                    if previous is not None:
                        saved_fact = state.decoded[("settlement", initial)][0]
                        if saved_fact.origin != state.origin:
                            raise AuthorityUnavailable("Contact previous cost belongs to another budget original")
                        _, unknown = measurement_quantities_v1(state.fact)
                        if previous["result"]["budget_status"] in {"settled", "overrun"} or unknown:
                            state.fact = saved_fact
                        else:
                            state.business_operation_id = "contact-cost-" + canonical_digest((origin.namespace,
                                origin.effect_id, "resolve", state.fact.measurement.receipt_digest))[:48]
                    saved = _business_receipt(state, meter)
                    row = state.row(meter, ATTEMPT_TABLE, ("origin_digest", "fact_digest", "request_json", "state"),
                        "bot=? AND persona=? AND operation_id=?", (*state.namespace.as_tuple, state.business_operation_id))
                    state.attempt = row
                    if row is not None:
                        state.request = state.decode(row[2], _decode_accounting_request_v1)
                        if row[:2] != (origin.digest, state.fact.digest) or state.request.origin != state.origin:
                            raise AuthorityUnavailable("Contact accounting saved original attempt differs")
                    if saved is not None:
                        if row is None or row[3] != "committed" or state.request.operation_id != saved["request_ref"]:
                            raise AuthorityUnavailable("Contact committed cost lost its exact maintenance original")
                        state.result = state.decoded[("settlement", state.business_operation_id)][2]
                        state.phase = "finish"
                    elif row is not None and row[3] == "open":
                        state.phase = "recover"
                    elif row is None or row[3] == "closed":
                        state.phase = "anchor"
                    else:
                        raise AuthorityUnavailable("Contact committed attempt has no real cost CAS")
                elif state.phase == "closed":
                    if _business_receipt(state, meter) is not None:
                        raise AuthorityUnavailable("Contact cost appeared during failed-attempt recovery")
                    changed = db.execute("UPDATE " + ATTEMPT_TABLE + " SET state='closed' WHERE bot=? AND persona=? "
                        "AND operation_id=? AND request_json=? AND state='open'", (*state.namespace.as_tuple,
                            state.business_operation_id, encoded_v1(state.request))).rowcount
                    if changed != 1: raise AuthorityUnavailable("Contact accounting original attempt closure changed")
                    db.commit(); committed = True; state.phase = "anchor"
                elif state.phase == "attempt":
                    if not graph._accounting_anchor_covers(state.graph_stamp[0].requirements, state.anchor):
                        raise AuthorityUnavailable("Contact accounting current anchor does not cover Graph")
                    if _business_receipt(state, meter) is not None:
                        raise AuthorityUnavailable("Contact cost appeared before maintenance admission")
                    origin = state.origin.origin
                    state.request = ContactEffectAccountingRequestV1("contact-cost-fence-" + secrets.token_hex(24),
                        state.origin, state.fact.observed_mutation_id,
                        None if state.fact.measurement is None else state.fact.measurement.receipt_digest, state.anchor)
                    row = state.row(meter, ATTEMPT_TABLE, ("state",), "bot=? AND persona=? AND operation_id=?",
                        (*state.namespace.as_tuple, state.business_operation_id))
                    if row is not None and row[0] != "closed":
                        raise AuthorityUnavailable("Contact previous maintenance attempt remains unresolved")
                    db.execute("INSERT INTO " + ATTEMPT_TABLE + " VALUES(?,?,?,?,?,?,'open') "
                        "ON CONFLICT(bot,persona,operation_id) DO UPDATE SET request_json=excluded.request_json,state='open' "
                        "WHERE " + ATTEMPT_TABLE + ".state='closed' AND " + ATTEMPT_TABLE + ".origin_digest=excluded.origin_digest "
                        "AND " + ATTEMPT_TABLE + ".fact_digest=excluded.fact_digest",
                        (*state.namespace.as_tuple, state.business_operation_id, origin.digest, state.fact.digest, encoded_v1(state.request)))
                    db.commit(); committed = True; state.phase = "begin"
                elif state.phase == "warm_cost":
                    origin = state.origin.origin
                    row = state.row(meter, "runtime_resource_quotes", ("quote_json", "signature"),
                        "quote_id=? AND version=?", (origin.quote_id, origin.quote_version))
                    if row is None: raise AuthorityUnavailable("Contact original message quote is absent")
                    service.resource._signer.verify("resource-quote.v1", row[0], row[1])
                    state.decode(row[0], _decode_message_quote_v1)
                    state.row(meter, "runtime_budget_reservations", ("digest", "ceiling_json", "state", "actual_json"),
                        "lease_id=? AND operation_id=?", (origin.parent_budget_lease_ref, origin.reservation_operation_id))
                    state.phase = "commit"
                elif state.phase == "commit":
                    state.result = _commit_cost(state, meter)
                    db.commit(); committed = True
                    state.graph_stamp = graph._v2_graph_stamp(state.namespace)
                    state.phase = "finish"
                elif state.phase == "readback":
                    saved = _business_receipt(state, meter)
                    if saved is None or state.decoded[("settlement", state.business_operation_id)][2] != state.result:
                        raise AuthorityUnavailable("Contact actual cost CAS disappeared after Authority finish")
                    result = replace(state.result, accounting_finished=True,
                        observation_outcome=state.current_fact.observation_outcome)
                    state.operation.reserve_retained_state_growth_v3(state, 4096)
                    try:
                        state.proof = ContactEffectCompletionProofV1(_KEY, state, result)
                    finally: state.operation.finish_retained_state_growth_v3(state)
                    return GraphStorageStepV3("complete", state.proof)
                else:
                    raise AuthorityUnavailable("unregistered Contact financial Work phase")
                return GraphStorageStepV3("progress")
            finally:
                if not committed and db.in_transaction: db.rollback()


def finish_contact_effect_accounting_work_v1(graph, work, error):
    state = work.state
    if type(state) is not ContactEffectAccountingWorkV1 or state.graph is not graph:
        raise AuthorityUnavailable("Contact financial finish belongs to another Work")
    if error is None:
        state.operation.transfer_payload_release_v3(state.release_payload_v3)
        work.result_lease = state.operation
    else:
        try:
            if state.request is not None:
                try:
                    state.service.port.recover_finish(state.request)
                except Exception:
                    grant = state.service.port.begin(state.request)
                    state.service.port.finish(state.request, grant)
        finally:
            state.release_payload_v3()
            finish_runtime_storage_operation_v3(state.operation)


def _decode_signed_origin_v1(raw):
    return from_wire(raw, SignedContactEffectBudgetOriginV1)

def _decode_accounting_request_v1(raw):
    return from_wire(raw, ContactEffectAccountingRequestV1)


def _financial_rpc_growth_bound_v1():
    # Closed result graph: Fact, SignedOrigin, Origin, Namespace, three Pricing
    # copies, MeasurementReceipt, Measurement plus <=3 quantity vectors of 16.
    # Grant/anchor responses are smaller. The service enforces a 65536-byte wire.
    scan = _FinancialJSONColumnV1("", "", "", ())
    scan.length = 65536
    scan.objects = 12
    scan.arrays = 3*(1+16)
    scan.keys = 12*32
    scan.strings = scan.keys+12*32+3*16
    scan.numbers = 12*32+3*16
    scan.literals = 12*32
    scan.digits = scan.length
    return scan.decode_bound()


def advance_contact_effect_accounting_work_v1(graph, work):
    state = work.state
    growth = state.phase in {"fact", "recover", "anchor", "begin", "finish", "commit"}
    if growth: work.operation.reserve_retained_state_growth_v3(state, _financial_rpc_growth_bound_v1())
    try:
        return _advance_contact_effect_accounting_work_v1(graph, work)
    except _FinancialMetadataProgressV1:
        return GraphStorageStepV3("progress")
    finally:
        if not work.operation.closed:
            if growth: work.operation.finish_retained_state_growth_v3(state)
            else: work.operation.refresh_retained_state_v3(state)


def _decode_message_quote_v1(raw):
    from .issuers import ResourceQuote
    values = dict(raw)
    values["outbox_refs"] = tuple(values["outbox_refs"])
    values["d02_settlement_refs"] = tuple(values["d02_settlement_refs"])
    return ResourceQuote(**values)


def _decode_cost_value_v1(raw):
    from .d11_types import RuntimeCostSettlement
    return RuntimeCostSettlement(**raw)


def restore_stored_fact_v1(raw, signed_origin):
    if type(signed_origin) is not SignedContactEffectBudgetOriginV1 or raw["origin_ref"] != signed_origin.origin.operation_id:
        raise AuthorityUnavailable("Contact saved financial fact needs its actual signed birth original")
    if type(raw["fact"]) is not dict or "origin" in raw["fact"]:
        raise AuthorityUnavailable("Contact saved financial metadata cannot override its joined birth")
    fact = from_wire({**raw["fact"], "origin":to_wire(signed_origin)}, ContactEffectCostFactV1)
    if fact.digest != raw["result"]["fact_digest"]:
        raise AuthorityUnavailable("Contact reconstructed actual financial fact commitment differs")
    return fact
