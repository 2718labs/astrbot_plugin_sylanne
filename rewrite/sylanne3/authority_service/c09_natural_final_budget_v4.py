"""Actual natural budget-check preimages and bounded immutable historical replay.

The private witness is minted at the successful installed D11 inspection read.
Replay uses that same-transaction observation and immutable signed rows; it
never asks a later lease or reservation to remain in its former state.
"""
from copy import copy
from dataclasses import asdict, fields, is_dataclass
import json
import sys
from weakref import WeakSet

from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from ..runtime_contracts import CheckReceipt, NamespaceId, VersionedRef, canonical_digest, canonical_serialize

SCHEMA = "sylanne.natural-final-budget-observation.v4"
_TOKEN = object()
_WITNESSES = WeakSet()
_FIELDS = ("schema", "namespace", "identity", "action_spec", "now_utc", "selected_lease_id",
           "ancestry", "reservation", "reserve_operation", "signed_grant", "signed_quote", "inspection_receipt")
_OPERATION_COLUMNS = ("bot_id", "persona_id", "operation_id", "phase", "digest", "lease_id", "receipt_json", "resolution_binding_json")


class _NaturalFinalBudgetOriginalV4:
    def __init__(self, token, *, db, intent, receipt, now_utc, payload):
        if token is not _TOKEN:
            raise TypeError("actual installed D11 success observation required")
        self.db = db
        self.intent = intent
        self.receipt = receipt
        self.now_utc = now_utc
        self.raw = canonical_serialize(payload)
        self.used = False
        _WITNESSES.add(self)

    def consume_for(self, db, bundle, evidence, scope, checks, now_utc):
        from ..runtime_contracts import DomainBundle, FenceScope
        from ..runtime.dispatch_candidate import NaturalDispatchCandidateEvidenceV2
        from ..graph_types import AtomKey
        actual = tuple(check for check in checks if check.check_kind == "dispatch_budget")
        if (self not in _WITNESSES or self.used or db is not self.db or not db.in_transaction
                or type(bundle) is not DomainBundle or type(scope) is not FenceScope
                or type(evidence) is not NaturalDispatchCandidateEvidenceV2
                or len(actual) != 1 or actual[0] is not self.receipt or now_utc != self.now_utc
                or scope.namespace != bundle.envelope.authority.namespace
                or bundle.envelope.identity != self.intent.identity
                or evidence.operation_id != self.intent.identity.operation_id
                or AtomKey.from_token(evidence.action_ref).name != self.intent.action_id
                or NamespaceId.from_key(AtomKey.from_token(evidence.action_ref)) != scope.namespace):
            raise ValueError("natural budget original crossed its actual successful inspection/transaction/action")
        self.used = True
        _WITNESSES.discard(self)
        return json.loads(self.raw)


def _mint_natural_final_budget_original_v4(db, *, intent, quote, grant, lease, reservation,
                                          receipt, d11_issuer, d02_issuer, now_utc):
    """Call only immediately before the real installed inspector's success return.

    No reservation, balance, grant, cost, deadline or authorization is changed.
    The actual SQL absence queries and all mutable ancestor counters are frozen
    before a later runtime admission can alter them.
    """
    from ..domains.d08 import ActionIntent
    from ..runtime.budget import BudgetLease, BudgetReceipt, get_budget_lease
    from ..runtime.issuers import D11BudgetGrantIssuer, D02ResourceIssuer
    if (not db.in_transaction or type(intent) is not ActionIntent or type(lease) is not BudgetLease
            or type(receipt) is not CheckReceipt or (receipt.result, receipt.coverage) != ("pass", "full")
            or not isinstance(d11_issuer, D11BudgetGrantIssuer) or type(d02_issuer) is not D02ResourceIssuer):
        raise TypeError("actual current natural D11 inspection inputs required")
    specs = tuple(spec for spec in intent.required_checks if spec.check_kind == "dispatch_budget")
    if len(specs) != 1 or specs[0].provider_id != "d11.dispatch_budget":
        raise ValueError("actual D11 inspection has another required budget check")
    spec = specs[0]
    if (receipt.input_versions != spec.required_input_versions
            or (receipt.check_kind, receipt.subject_ref, receipt.action_ref, receipt.purpose, receipt.issuer) !=
               (spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose, spec.provider_id)):
        raise ValueError("successful D11 receipt does not belong to the inspected action")
    namespace = NamespaceId(lease.bot_id, lease.persona_id)
    ancestors = []
    seen = set()
    current = lease
    observed = []
    while True:
        if current.lease_id in seen or current.state != "active":
            raise ValueError("successful budget inspection lost its actual active ancestry")
        seen.add(current.lease_id)
        actual = get_budget_lease(db, current.lease_id)
        if actual != current:
            raise ValueError("budget changed after success before original capture")
        # This is the same existential predicate used by require_budget_family_admissible.
        rows = db.execute("SELECT lease_id,cause_lease_id,cause_operation_id FROM runtime_budget_debt_blocks "
                          "WHERE lease_id=? LIMIT 1", (current.lease_id,)).fetchall()
        if rows:
            raise ValueError("successful inspection now has actual ancestor debt")
        ancestors.append({"lease": asdict(current), "debt_query": {
            "table": "runtime_budget_debt_blocks", "where": "lease_id=?", "parameter": current.lease_id,
            "limit": 1, "columns": ["lease_id", "cause_lease_id", "cause_operation_id"], "rows": rows}})
        observed.append(VersionedRef("d11.budget.lease:" + current.lease_id, current.version))
        if current.parent_id is None:
            break
        parent = get_budget_lease(db, current.parent_id)
        if ((parent.bot_id, parent.persona_id, parent.currency) != (current.bot_id, current.persona_id, current.currency)
                or any(parent.reserved.get(key, 0) < value for key, value in current.limits.items())):
            raise ValueError("successful budget inspection lost its child encumbrance")
        current = parent
    selected = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
                          "WHERE lease_id=? AND operation_id=?", (lease.lease_id, intent.identity.operation_id)).fetchone()
    if selected is None or selected[:3] != reservation or selected[2] != "reserved":
        raise ValueError("actual budget reservation changed before original capture")
    reserve_row = db.execute("SELECT " + ",".join(_OPERATION_COLUMNS) + " FROM runtime_budget_operations "
                             "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
                             (*namespace.as_tuple, intent.identity.operation_id)).fetchone()
    if reserve_row is None:
        raise ValueError("actual selected reservation lost its immutable reserve receipt")
    reserve = dict(zip(_OPERATION_COLUMNS, reserve_row, strict=True))
    budget_receipt = BudgetReceipt(**json.loads(reserve["receipt_json"]))
    if (reserve["lease_id"] != lease.lease_id or reserve["digest"] != selected[0]
            or budget_receipt.status != "reserved" or budget_receipt.lease_id != lease.lease_id
            or budget_receipt.operation_id != intent.identity.operation_id or budget_receipt.digest != selected[0]
            or budget_receipt.version > lease.version):
        raise ValueError("actual selected reserve receipt identity differs")
    grant_row = db.execute("SELECT grant_json,signature,status FROM runtime_budget_grants "
                           "WHERE lease_id=? AND version=?", (grant.lease_id, grant.version)).fetchone()
    quote_row = db.execute("SELECT quote_json,signature,status FROM runtime_resource_quotes "
                           "WHERE quote_id=? AND version=?", (quote.quote_id, quote.version)).fetchone()
    verified_grant, signature = d11_issuer.signed_budget_grant_at_version(db, grant.lease_id, grant.version)
    if grant_row is None or quote_row is None or verified_grant != grant or grant_row[1] != signature:
        raise ValueError("actual signed original budget inputs changed")
    if d02_issuer._load_quote(db, quote.quote_id, quote.version) != quote or grant_row[2] != "active":
        raise ValueError("successful budget inspection lost its signed active inputs")
    observed.extend((VersionedRef(f"d11.budget.reservation:{lease.lease_id}:{intent.identity.operation_id}:{selected[0]}", 1),
                     VersionedRef("d11.budget.grant:" + grant.lease_id, grant.version)))
    expected = tuple(item for item in spec.required_input_versions if item.ref != spec.criteria_version)
    if set(observed) != set(expected) or len(observed) != len(expected):
        raise ValueError("success-capture lease versions differ from actual frozen required inputs")
    payload = {"schema": SCHEMA, "namespace": asdict(namespace), "identity": asdict(intent.identity),
        "action_spec": asdict(spec), "now_utc": now_utc, "selected_lease_id": lease.lease_id,
        "ancestry": ancestors, "reservation": {"lease_id": lease.lease_id, "operation_id": intent.identity.operation_id,
            "digest": selected[0], "ceiling_json": selected[1], "state": selected[2], "actual_json": selected[3]},
        "reserve_operation": reserve,
        "signed_grant": {"lease_id": grant.lease_id, "version": grant.version, "grant_json": grant_row[0],
            "signature": grant_row[1], "observed_status": grant_row[2], "verifier_ref": "d11.budget_grant.installed.v1"},
        "signed_quote": {"quote_id": quote.quote_id, "version": quote.version, "quote_json": quote_row[0],
            "signature": quote_row[1], "observed_status": quote_row[2], "verifier_ref": "d02.resource_quote.installed.v1"},
        "inspection_receipt": asdict(receipt)}
    return _NaturalFinalBudgetOriginalV4(_TOKEN, db=db, intent=intent, receipt=receipt, now_utc=now_utc, payload=payload)


class _BudgetObservationStreamV4(C09CanonicalJSONStreamV2):
    def __init__(self):
        super().__init__(ensure_ascii=True)
        self.starts = {}
        self.ranges = {}
        self.ancestor_count = 0

    def copy(self):
        result = super().copy()
        result.starts = dict(self.starts)
        result.ranges = dict(self.ranges)
        return result

    def _emit(self, emit, kind, path, start, end, **values):
        selected = len(path) == 1 or len(path) == 2 and path[0] == "ancestry" and type(path[1]) is int
        if selected:
            if kind in {"object_start", "array_start", "scalar_start"}:
                self.starts[path] = start
            elif kind in {"object_end", "array_end", "scalar_end"}:
                self.ranges[path] = (self.starts.pop(path), end)
                if len(path) == 2:
                    self.ancestor_count += 1
        super()._emit(emit, kind, path, start, end, **values)


def _heap(value):
    amount = sys.getsizeof(value)
    if type(value) is dict:
        amount += sum(_heap(key) + _heap(item) for key, item in value.items())
    elif type(value) in (tuple, list, set):
        amount += sum(_heap(item) for item in value)
    elif is_dataclass(value) and not isinstance(value, type):
        amount += sum(_heap(getattr(value, field.name)) for field in fields(value))
    return amount


class NaturalFinalBudgetOriginalReadV4:
    """One streamed field, ancestor, or immutable row per installed caller quantum."""
    def __init__(self, parent):
        from .c09_natural_final_history_v4 import NaturalFinalHistoricalPermissionsReadV4
        from ..runtime.issuers import D11BudgetJobIssuer, D02ResourceIssuer
        if (type(parent) is not NaturalFinalHistoricalPermissionsReadV4 or parent.phase != "budget"
                or type(parent.d11_issuer) is not D11BudgetJobIssuer or type(parent.d02_issuer) is not D02ResourceIssuer
                or parent.d11_issuer.resource_issuer is not parent.d02_issuer):
            raise TypeError("actual budget-stage installed final historical permission reader required")
        self.parent = parent
        self.capture = parent.capture
        self.source = parent.source
        self.graph = parent.graph
        original = parent.parent.natural_final_original
        path = ("natural_final_authorization_original", "payload", "budget_observation")
        if path not in original.receipt_parser.ranges:
            self._hold("actual v4 budget observation absent; legacy cannot be backfilled")
        self.left, self.right = original.receipt_parser.ranges[path]
        self.bundle_total = original.bundle_total
        self.row_key = (*parent.parent.namespace.as_tuple, parent.parent.handoff.observation.binding.origin.operation_id)
        self.phase = "scan"
        self.offset = 0
        self.parser = _BudgetObservationStreamV4()
        self.header = {}
        self.field_index = 0
        self.buffer = bytearray()
        self.buffer_offset = 0
        self.ancestor_index = 0
        self.grant = None
        self.quote = None
        self.spec = None
        self.selected_lease = None
        self.previous_lease = None
        self.observed = []
        self.seen = set()
        self.immutable_index = 0
        self.immutable_row = None
        self.complete = False
        self.recomputed_receipt = None
        self.ceiling = None
        self.reservation_digest = None
        self.lease = None
        self.source.arena.add(self)
        self.source.require_arena()

    @staticmethod
    def _hold(message):
        from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold
        raise C09PagedCaptureHold(message)

    def _source_heap_bytes(self):
        return sys.getsizeof(self.__dict__) + sum(_heap(value) for value in
            (self.parser.__dict__, tuple(getattr(self.parser,name) for name in C09CanonicalJSONStreamV2.__slots__ if name != "_emit_callback"),
             self.header, self.buffer, self.selected_lease, self.previous_lease,
             self.observed, self.seen, self.grant, self.quote, self.spec, self.recomputed_receipt, self.immutable_row)) + 4096

    def copy(self):
        self.source.require_arena(self._source_heap_bytes())
        result = copy(self)
        result.parser = self.parser.copy()
        result.header = dict(self.header)
        result.buffer = bytearray(self.buffer)
        result.observed = list(self.observed)
        result.seen = set(self.seen)
        self.source.arena.add(result)
        return result

    def _fragment(self, start, length, meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2, read_legacy_sql_cell_fragment_v2
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            raw, total, kind = read_legacy_sql_cell_fragment_v2(self.graph.pair.source,
                table="graph_bundle_operations", column="receipt_json", where="bot=? AND persona=? AND operation_id=?",
                parameters=self.row_key, start=self.left + start, length=length, meter=meter)
        if kind != "text" or total != self.bundle_total or len(raw) != length:
            self._hold("budget observation lost its actual whole-row source byte range")
        return raw

    def _decode_range(self, path, meter):
        left, right = self.parser.ranges[path]
        if self.buffer_offset < right - left:
            length = min(1024, right - left - self.buffer_offset)
            self.source.require_arena((len(self.buffer) + length) * 2 + 32768)
            self.buffer.extend(self._fragment(left + self.buffer_offset, length, meter))
            self.buffer_offset += length
            return None, False
        self.source.require_arena(len(self.buffer) * 32 + 65536)
        meter.require_available(len(self.buffer))
        meter.charge_encode(len(self.buffer))
        value = json.loads(self.buffer)
        self.buffer.clear()
        self.buffer_offset = 0
        return value, True

    def _scan(self, meter):
        if self.offset < self.right - self.left:
            length = min(1024, self.right - self.left - self.offset)
            self.source.require_arena(length * 32 + 65536)
            self.parser.feed(self._fragment(self.offset, length, meter), lambda event: None)
            self.offset += length
            return
        self.parser.finish(lambda event: None)
        if {path[0] for path in self.parser.ranges if len(path) == 1} != set(_FIELDS):
            self._hold("budget observation has another complete closed field inventory")
        if not self.parser.ancestor_count:
            self._hold("budget observation has no complete lease ancestry")
        self.phase = "fields"

    def _fields(self, meter):
        names = tuple(name for name in _FIELDS if name != "ancestry")
        if self.field_index == len(names):
            self._identity(meter)
            self.phase = "ancestors"
            return
        name = names[self.field_index]
        value, complete = self._decode_range((name,), meter)
        if complete:
            self.header[name] = value
            self.field_index += 1

    def _wire(self, value, meter):
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        upper = c09_canonical_json_size_v3(value, ascii=True)
        meter.require_available(upper)
        self.source.require_arena(upper * 32 + 65536)
        return canonical_serialize(value)

    def _identity(self, meter):
        header = self.header
        spec = next(item for item in self.parent.action.required_checks if item.check_kind == "dispatch_budget")
        if (header["schema"] != SCHEMA or header["namespace"] != asdict(self.parent.scope.namespace)
                or header["identity"] != asdict(self.parent.action.identity)
                or header["now_utc"] != self.parent.now
                or self._wire(header["action_spec"],meter) != self._wire(asdict(spec),meter)):
            self._hold("historical budget observation crosses original action/spec/namespace/time")
        self.spec = spec

    def _ancestors(self, meter):
        from ..runtime.budget import BudgetLease
        if self.ancestor_index == self.parser.ancestor_count:
            if self.previous_lease.parent_id is not None:
                self._hold("historical budget ancestry stopped before its root")
            self.phase = "immutable"
            return
        value, complete = self._decode_range(("ancestry", self.ancestor_index), meter)
        if not complete:
            return
        lease = BudgetLease(**value["lease"])
        query = value["debt_query"]
        expected_query = {"table": "runtime_budget_debt_blocks", "where": "lease_id=?", "parameter": lease.lease_id,
            "limit": 1, "columns": ["lease_id", "cause_lease_id", "cause_operation_id"], "rows": []}
        if query != expected_query or lease.state != "active" or lease.lease_id in self.seen:
            self._hold("historical budget lost its actual debt absence/active acyclic ancestry")
        if self.ancestor_index == 0:
            if lease.lease_id != self.header["selected_lease_id"]:
                self._hold("historical budget selected lease differs")
            self.selected_lease = self.lease = lease
        elif (self.previous_lease.parent_id != lease.lease_id
                or (lease.bot_id, lease.persona_id, lease.currency) !=
                   (self.selected_lease.bot_id, self.selected_lease.persona_id, self.selected_lease.currency)
                or any(lease.reserved.get(key, 0) < amount for key, amount in self.previous_lease.limits.items())):
            self._hold("historical parent counters lost their actual child encumbrance")
        self.observed.append(VersionedRef("d11.budget.lease:" + lease.lease_id, lease.version))
        self.seen.add(lease.lease_id)
        self.previous_lease = lease
        self.ancestor_index += 1

    def _immutable(self, meter):
        from .c09_natural_final_history_v4 import _HistoricalGraphRowReadV4
        cases = (("runtime_budget_grants", "signed_grant", ("grant_json",)),
                 ("runtime_resource_quotes", "signed_quote", ("quote_json",)),
                 ("runtime_budget_operations", "reserve_operation", ("receipt_json", "resolution_binding_json")))
        if self.immutable_index == len(cases):
            self.phase = "receipt"
            return
        table, name, decode = cases[self.immutable_index]
        selected = self.header[name]
        key = ((selected["lease_id"], selected["version"]) if name == "signed_grant" else
               (selected["quote_id"], selected["version"]) if name == "signed_quote" else
               (selected["bot_id"], selected["persona_id"], selected["operation_id"], selected["phase"]))
        if self.immutable_row is None:
            self.immutable_row = _HistoricalGraphRowReadV4(self.parent, table, key, decode=decode)
            return
        if not self.immutable_row.complete:
            self.immutable_row = self.immutable_row.advance(meter)
            return
        row = self.immutable_row
        if name in {"signed_grant", "signed_quote"}:
            column = decode[0]
            actual_raw = self._wire(row.values[column], meter)
            if (actual_raw != selected[column] or row.small["signature"] != selected["signature"]
                    or selected["observed_status"] != "active"):
                self._hold("actual immutable signed budget input differs from captured preimage")
            meter.require_available(len(actual_raw) + 64)
            meter.charge_encode(len(actual_raw) + 64)
            if name == "signed_grant":
                from ..runtime.issuers import _decode_grant
                if selected["verifier_ref"] != "d11.budget_grant.installed.v1":
                    self._hold("historical grant has another installed verifier identity")
                self.parent.d11_issuer._signer.verify("budget-grant.v1", actual_raw, selected["signature"])
                self.grant = _decode_grant(actual_raw)
                if (self.grant.lease_id,self.grant.version)!=(selected["lease_id"],selected["version"]):
                    self._hold("actual signed grant locator differs from its immutable payload")
            else:
                from ..runtime.issuers import _decode_quote
                if selected["verifier_ref"] != "d02.resource_quote.installed.v1":
                    self._hold("historical quote has another installed verifier identity")
                self.parent.d02_issuer._signer.verify("resource-quote.v1", actual_raw, selected["signature"])
                self.quote = _decode_quote(actual_raw)
                if (self.quote.quote_id,self.quote.version)!=(selected["quote_id"],selected["version"]):
                    self._hold("actual signed quote locator differs from its immutable payload")
        else:
            actual = {**row.small, **{column: None if row.values[column] is None else self._wire(row.values[column], meter)
                                     for column in decode}}
            if any(actual.get(column) != selected[column] for column in _OPERATION_COLUMNS):
                self._hold("actual immutable selected reserve operation/receipt differs")
        self.immutable_row = None
        self.immutable_index += 1

    def _receipt(self, meter):
        from ..runtime.budget import BudgetReceipt
        from ..runtime.issuers import private_reply_dispatch_quote_id
        header = self.header
        intent = self.parent.action
        spec = self.spec
        lease = self.selected_lease
        grant = self.grant
        quote = self.quote
        namespace = self.parent.scope.namespace
        reservation = header["reservation"]
        ceiling = json.loads(reservation["ceiling_json"])
        reserve = header["reserve_operation"]
        actual = BudgetReceipt(**json.loads(reserve["receipt_json"]))
        if (reservation["lease_id"] != lease.lease_id or reservation["operation_id"] != intent.identity.operation_id
                or reservation["state"] != "reserved" or not ceiling
                or any(type(amount) is not int or amount <= 0 or lease.reserved.get(key, 0) < amount for key, amount in ceiling.items())
                or (reserve["lease_id"], reserve["operation_id"], reserve["phase"], reserve["digest"]) !=
                   (lease.lease_id, intent.identity.operation_id, "reserve", reservation["digest"])
                or (actual.status, actual.lease_id, actual.operation_id, actual.digest) !=
                   ("reserved", lease.lease_id, intent.identity.operation_id, reservation["digest"])
                or actual.version > lease.version):
            self._hold("historical selected held reservation and immutable receipt do not agree")
        expected = tuple(item for item in spec.required_input_versions if item.ref != spec.criteria_version)
        observed = (*self.observed,
            VersionedRef(f"d11.budget.reservation:{lease.lease_id}:{intent.identity.operation_id}:{reservation['digest']}", 1),
            VersionedRef("d11.budget.grant:" + lease.lease_id, grant.version))
        quotes = tuple(item for item in spec.required_input_versions if item.ref.startswith("d02.resource_quote:"))
        quoted_action = (quote.work_kind == intent.action_kind or intent.action_kind == "communication"
            and intent.identity.phase == "post_c02_reply_dispatch" and quote.work_kind == "message"
            and quote.quote_id == private_reply_dispatch_quote_id(namespace, intent.identity.operation_id)
            and quote.snapshot_ref.startswith("k03snap:private-reply-dispatch-policy-")
            and quote.resource_ref.startswith("private-reply-dispatch-src:"))
        expiry = min(quote.valid_until_utc, grant.valid_until_utc)
        if (len(quotes) != 1 or quotes[0].ref != spec.criteria_version
                or (quote.quote_id, quote.version) != (quotes[0].ref.removeprefix("d02.resource_quote:"), quotes[0].version)
                or quote.parent_budget_lease_ref != lease.lease_id or quote.persona_id != spec.subject_ref.removeprefix("persona:")
                or (quote.activity_id, quote.effect_id, quote.operation_id) !=
                   (intent.identity.activity_id, intent.identity.effect_id, intent.identity.operation_id)
                or not quoted_action or quote.deadline_utc <= self.parent.now or expiry <= self.parent.now
                or grant.lease_id != lease.lease_id or quote.ceiling != ceiling
                or (lease.bot_id, lease.persona_id) != namespace.as_tuple
                or (lease.bot_id, lease.persona_id, lease.currency) != (quote.bot_id, quote.persona_id, grant.currency)
                or (grant.bot_id, grant.persona_id) != namespace.as_tuple
                or quote.work_kind not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(key, 0) for key, amount in ceiling.items())
                or spec.provider_id != "d11.dispatch_budget" or spec.action_ref != intent.action_id or spec.purpose != intent.purpose
                or set(observed) != set(expected) or len(observed) != len(expected)):
            self._hold("historical signed quote/grant/ancestry versions or scope do not reproduce the original budget check")
        receipt = CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
            spec.required_input_versions, "full", "pass", float(expiry), spec.provider_id)
        if self._wire(asdict(receipt),meter) != self._wire(header["inspection_receipt"],meter):
            self._hold("recomputed historical budget receipt differs from actual inspected original")
        self.ceiling = ceiling
        self.reservation_digest = reservation["digest"]
        self.recomputed_receipt = receipt
        self.complete = True

    def advance(self, meter):
        self.source.require_current()
        self.capture.builder.require_current()
        result = self.copy()
        if result.phase == "scan":
            result._scan(meter)
        elif result.phase == "fields":
            result._fields(meter)
        elif result.phase == "ancestors":
            result._ancestors(meter)
        elif result.phase == "immutable":
            result._immutable(meter)
        elif result.phase == "receipt":
            result._receipt(meter)
        else:
            self._hold("unknown historical natural budget reader phase")
        self.source.require_current()
        self.source.require_arena()
        return result
