"""Natural P2 metadata, own Source ALL and closed selected-original preparation.

No initial READ proof can issue this Work's Source barrier. This module has no
model/sender/Root mutation path; real P1/P2 execution remains with the caller.
"""
from dataclasses import fields
from datetime import datetime
from types import MappingProxyType
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, Owner, owner_grant_key, OWNER_GRANT_TYPE
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3, runtime_storage_v3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .natural_dispatch_locator_metadata_v1 import (
    NaturalDispatchLocatorMetadataColumnV1, _FIELD_V1, _OBJECT_FIELDS_V1,
    _META_KEYS_V1, _RECIPE_KEYS_V1,
)
from .natural_dispatch_initial_read_v1 import _NaturalInitialSourcesV1, _NaturalInitialSourceNodeV1
from .natural_dispatch_read_locator_current_v1 import _FINAL_JOB
from .owner_material_source_storage_v3 import CanonicalValueStreamV3
from .source_correction_read_v3 import _heap

_ISSUER_V1 = object()
_READERS_V1 = WeakKeyDictionary()
_METADATA_V1 = WeakKeyDictionary()
_BARRIERS_V1 = WeakKeyDictionary()
_CONTROL_TYPES_V1 = frozenset({"d03.account_binding", "d03.role_binding", "d05.boundary_rule"})


def _control_fields_v1():
    from ..domains.d03 import AccountBinding, RoleBinding, EntityAnchor, WorldEvent
    from ..domains.d05.relationship import BoundaryRule
    from ..domains.d07 import AttentionTicket, FocusState
    values = {"d03.account_binding": AccountBinding, "d03.role_binding": RoleBinding,
        "d03.entity_anchor": EntityAnchor, "d03.world_event": WorldEvent,
        "d05.boundary_rule": BoundaryRule, "d07.focus.v1": FocusState,
        "d07.attention_ticket.v1": AttentionTicket}
    result = {name: frozenset(field.name for field in fields(value)) for name, value in values.items()}
    for name in ("d07.focus.v1", "d07.attention_ticket.v1"):
        result[name] = result[name] | frozenset({"schema"})
    result[OWNER_GRANT_TYPE] = frozenset({"schema", "authority_id", "installation_id", "grant_id", "principal",
        "ticket_id", "creation_operation_id", "creation_digest", "issue_operation_id", "grant_revision", "state",
        "scope", "issuer_ref", "capabilities", "purposes", "audiences", "activation_generation", "graph_incarnation"})
    return result


_CONTROL_FIELDS_V1 = _control_fields_v1()
_CONTROL_ARRAYS_V1 = {
    "d03.role_binding": frozenset({"norm_refs", "source_refs"}),
    "d03.entity_anchor": frozenset({"creation_evidence_refs"}),
    "d03.world_event": frozenset({"participant_roles", "source_refs"}),
    "d05.boundary_rule": frozenset({"source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"}),
    "d07.focus.v1": frozenset({"auxiliary_ticket_refs"}),
    "d07.attention_ticket.v1": frozenset({"cancel_refs", "source_refs"}),
    OWNER_GRANT_TYPE: frozenset({"capabilities", "purposes", "audiences"}),
}


class _NaturalP2ControlColumnV1(DispatchOriginalJSONReadV3):
    """Exact registered control metadata only; unknown nested payload is rejected."""
    def __init__(self, reader, head):
        reader.require_original_work_v1()
        self.controller, self.head = reader, head
        token, _, _, self.kind, cell = head
        if self.kind not in _CONTROL_FIELDS_V1:
            raise AuthorityUnavailable("Natural P2 control kind is outside the closed metadata profile")
        super().__init__(reader.parent, table="graph_atoms", column="value",
            key_columns=("token",), key=(token,), cell_id=cell)
        if self.cell.header[1] != token or self.cell.header[0] not in (
                "canonical-json.ascii.v1", "canonical-json.utf8.v1"):
            raise AuthorityUnavailable("Natural P2 control cell owner/codec differs")
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == "canonical-json.ascii.v1")

    def _emit(self, event):
        path = event.path
        if event.kind == "key":
            if len(path) == 1:
                allowed = _CONTROL_FIELDS_V1[self.kind]
            elif self.kind == OWNER_GRANT_TYPE and len(path) == 2 and path[0] == "principal":
                allowed = frozenset({"identity_provider", "account_ref", "account_incarnation"})
            else:
                raise AuthorityUnavailable("Natural P2 control has an undeclared nested metadata key")
            if event.key not in allowed:
                raise AuthorityUnavailable("Natural P2 control has an undeclared metadata field")
        elif event.kind == "object_start" and path:
            if self.kind != OWNER_GRANT_TYPE or path != ("principal",):
                raise AuthorityUnavailable("Natural P2 control has an undeclared metadata object")
        elif event.kind == "array_start":
            flat = len(path) == 1 and path[0] in _CONTROL_ARRAYS_V1.get(self.kind, ())
            roles = self.kind == "d03.world_event" and len(path) == 2 and path[0] == "participant_roles" and type(path[1]) is int
            if not flat and not roles:
                raise AuthorityUnavailable("Natural P2 control has an undeclared metadata array")
        return super()._emit(event)

    def value_v1(self):
        value = self.require_v3(self.owner)
        if type(value) is not dict or set(value) != _CONTROL_FIELDS_V1[self.kind]:
            raise AuthorityUnavailable("Natural P2 control complete metadata fields differ")
        self.controller.store._registry.spec(self.kind).validator(value)
        return value


class _NaturalP2LocatorMetadataV1:
    def __init__(self, issuer, task):
        if issuer is not _ISSUER_V1 or task.phase != "complete" or not task.column.complete:
            raise AuthorityUnavailable("actual complete P2-owned locator metadata required")
        self.task, self.reader, self.metadata = task, task.reader, task.raw["metadata"]
        self.original_sha, self.original_bytes = task.column.sha256, task.column.byte_count
        _METADATA_V1[self] = (self.task, self.reader, self.metadata, self.original_sha, self.original_bytes)

    def require_for_v1(self, reader):
        if (_METADATA_V1.get(self) != (self.task, self.reader, self.metadata, self.original_sha, self.original_bytes)
                or reader is not self.reader):
            raise AuthorityUnavailable("Natural P2 metadata belongs to another actual Work")
        reader.require_original_work_v1()
        return self.metadata

    def release_payload_v3(self):
        _METADATA_V1.pop(self, None)
        self.task = self.reader = self.metadata = None


class _NaturalP2LocatorReadV1:
    def __init__(self, reader):
        self.reader = reader
        self.column = NaturalDispatchLocatorMetadataColumnV1(reader.parent, reader.parent.binding.operation_id)
        self.raw = self.stream = self.result = None
        self.phase = "column"

    def _joins_v1(self, meter):
        r = self.reader
        a, request, binding = r.parent.admission.admission, r.parent.request, r.parent.binding
        m, ns = self.raw["metadata"], r.namespace
        if (m["namespace"] != {"bot_id": ns.bot_id, "persona_id": ns.persona_id}
                or (m["operation_id"], m["activity_id"], m["effect_id"], m["admission_ref"], m["original_utc_deadline"])
                    != (request.operation_id, request.activity_id, request.effect_id, a.admission_ref, a.utc_deadline)
                or (binding.operation_id, binding.origin.activity_id, binding.origin.effect_id, binding.origin.admission_ref)
                    != (request.operation_id, request.activity_id, request.effect_id, a.admission_ref)
                or m["admission_digest"] != a.digest or m["admission_receipt_digest"] != r.parent.admission.receipt_digest
                or m["request_digest"] != a.request_digest
                or m["graph_incarnation"] != r.graph_stamp[0].requirements.graph_incarnation):
            raise AuthorityUnavailable("Natural P2 locator differs from the actual admission/binding identity")
        bundle = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_bundle_operations",
            ("digest", "activity_id", "effect_id", "commit_seq"), "bot=? AND persona=? AND operation_id=?",
            (*ns.as_tuple, request.operation_id))
        if bundle is None or bundle[:3] != (m["bundle_digest"], request.activity_id, request.effect_id) or bundle[3] < 1:
            raise AuthorityUnavailable("Natural P2 locator has no matching actual W01 bundle")
        header = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_dispatch_admissions",
            ("operation_id", "effect_id", "admission_digest", "graph_revision", "graph_epoch", "receipt_digest"),
            "bot=? AND persona=? AND admission_ref=?", (*ns.as_tuple, a.admission_ref))
        if header != (request.operation_id, request.effect_id, m["admission_digest"],
                m["graph_revision"], m["graph_epoch"], m["admission_receipt_digest"]):
            raise AuthorityUnavailable("Natural P2 locator actual stored admission header differs")
        job = m["final_job"]
        if type(job) is not dict or set(job) != {"job_ref", *_FINAL_JOB}:
            raise AuthorityUnavailable("Natural P2 locator lacks its exact final message job")
        from .d11_types import runtime_job_key
        expected = _runtime_bounded_fixed_row_v3(r.db, meter, "runtime_jobs", (*_FINAL_JOB,
            "lease_holder", "lease_expires_utc", "result_ref"), "job_id=?", (job["job_id"],))
        deadline = datetime.fromisoformat(job["deadline_utc"].replace("Z", "+00:00")).timestamp()
        if (expected is None or expected[:len(_FINAL_JOB)] != tuple(job[name] for name in _FINAL_JOB)
                or any(v is not None for v in expected[len(_FINAL_JOB):])
                or (job["operation_id"], job["activity_id"], job["effect_id"], job["bot_id"], job["persona_id"])
                    != (request.operation_id, request.activity_id, request.effect_id, *ns.as_tuple)
                or (job["phase"], job["work_kind"], job["fence"], job["cancel_epoch"])
                    != ("waiting", "message", 0, 0) or job["budget_ref"] != a.budget_parent_lease_ref
                or job["job_ref"] != runtime_job_key(*ns.as_tuple, request.activity_id, job["job_id"]).token
                or r.parent.read_time.deadline > deadline or r.now_utc >= deadline):
            raise AuthorityUnavailable("Natural P2 original final job is cancelled, stale, crossed or expired")
        event = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_events", ("epoch_revision",),
            "bot=? AND persona=? AND session=? AND event_id=?",
            (*ns.as_tuple, request.activity_id, request.operation_id))
        history = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_history", ("revision", "valid"),
            "token=? AND event_bot=? AND event_persona=? AND event_session=? AND event_id=? ORDER BY revision",
            (job["job_ref"], *ns.as_tuple, request.activity_id, request.operation_id))
        if event != (m["graph_epoch"],) or history is None or history[0] < 1 or history[1] != 1:
            raise AuthorityUnavailable("Natural P2 final message job lacks its actual producing event")
        recipe = m["recipe"]
        if (type(recipe) is not dict or set(recipe) != _RECIPE_KEYS_V1
                or recipe["schema"] != "sylanne.natural_dispatch_read_locator_recipe.v1"
                or recipe["kind"] != "unsealed_producer_metadata_recipe"
                or recipe["namespace"] != m["namespace"]
                or recipe["committed_selection"]["operation_id"] != request.operation_id
                or recipe["committed_selection"]["admission_ref"] != a.admission_ref
                or recipe["admission"]["audience"] != list(a.audience)):
            raise AuthorityUnavailable("Natural P2 original metadata recipe selection differs")
        r.bundle_header, r.admission_header, r.final_job_header = bundle, header, expected
        r.final_job_id = job["job_id"]

    def advance(self, meter):
        self.reader.require_original_work_v1()
        if self.phase == "column":
            if self.column.advance(meter):
                self.raw = self.column.raw
                if (type(self.raw) is not dict or set(self.raw) != _OBJECT_FIELDS_V1[()]
                        or self.raw["schema"] != "sylanne.natural_dispatch_read_locator.v1"
                        or type(self.raw["profile_version"]) is not int or self.raw["profile_version"] != 1
                        or type(self.raw["metadata"]) is not dict or set(self.raw["metadata"]) != _META_KEYS_V1
                        or self.raw["metadata"]["schema"] != self.raw["schema"]
                        or type(self.raw["metadata"]["profile_version"]) is not int or self.raw["metadata"]["profile_version"] != 1):
                    raise AuthorityUnavailable("Natural P2 has no exact producer-issued metadata profile")
                from .dispatch_admission import _digest
                _digest(self.raw["metadata_sha256"], "metadata_sha256")
                if type(self.raw["metadata_byte_count"]) is not int or self.raw["metadata_byte_count"] < 1:
                    raise AuthorityUnavailable("Natural P2 complete metadata length differs")
                self.stream = CanonicalValueStreamV3(self.raw["metadata"])
                self.phase = "digest"
        elif self.phase == "digest":
            self.stream.read_fragment(meter)
            if self.stream.complete:
                if (self.stream.hash.hexdigest(), self.stream.offset) != (self.raw["metadata_sha256"], self.raw["metadata_byte_count"]):
                    raise AuthorityUnavailable("Natural P2 complete metadata SHA/count differs")
                self.phase = "joins"
        elif self.phase == "joins":
            self._joins_v1(meter)
            self.phase = "complete"
            self.result = _NaturalP2LocatorMetadataV1(_ISSUER_V1, self)
        return self.phase == "complete"


class _NaturalP2MetadataCensusV1:
    """Whole namespace heads; complete closed controls; exact route/focus locators."""
    def __init__(self, reader):
        self.reader = reader
        self.phase = "ingress"
        self.cursor = ""
        self.column = self.pending = None
        self.queue = []
        self.complete = False
        self.head_count = 0
        self.head_root = canonical_digest(("sylanne.natural-p2-head-census.v1",
            reader.namespace, reader.query, reader.selection_digest))
        self.heads, self.controls = {}, {}
        self.body_keys = set()
        self.control_columns = {}
        self.exact = set()

    def _ingress_v1(self, meter):
        r = self.reader
        recipe = r.locator.result.require_for_v1(r)["recipe"]
        self.source_ref = recipe["batch"]["source_ref"]["ref"]
        source = AtomKey.from_token(self.source_ref)
        from ..memory_types import source_key
        if source != source_key(*r.namespace.as_tuple, source.owner.subject or ""):
            raise AuthorityUnavailable("Natural P2 selected ingress is not its actual canonical Source")
        from .first_ingress_v2 import ingress_ids, scene_ref_for_conversation
        self.c02_operation_id = recipe["generation_c02_operation_id"]
        self.ingress_operation_id = ingress_ids(source.owner.subject)[2]
        row = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_first_ingress_identity_v1",
            ("source_ref", "platform_ref", "conversation_ref", "sender_ref", "message_id", "visibility", "bundle_digest"),
            "bot=? AND persona=? AND operation_id=?", (*r.namespace.as_tuple, self.ingress_operation_id))
        if (row is None or row[0] != source.owner.subject or row[5] != "private"
                or row[2] != r.parent.admission.admission.audience[0]
                or scene_ref_for_conversation(r.namespace, row[1], row[2]) != r.parent.admission.admission.scene_ref):
            raise AuthorityUnavailable("Natural P2 actual fixed ingress route differs")
        self.ingress_header = row
        self.platform, self.conversation, self.sender, self.message_id = row[1:5]
        suffix = canonical_digest({"namespace": r.namespace.as_tuple,
            "platform_ref": self.platform, "sender_ref": self.sender})
        owner = Owner("persona", *r.namespace.as_tuple)
        self.account_key = AtomKey(owner, "d03.account_binding", "account:v1:" + suffix)
        self.anchor_key = AtomKey(owner, "d03.entity_anchor", "entity:account-v1:" + suffix)
        self.focus_key = AtomKey(owner, "d07.focus.v1", r.namespace.persona_id)
        event_id = "world:message-arrival-v1:" + canonical_digest({"namespace": r.namespace.as_tuple,
            "platform_ref": self.platform, "conversation_ref": self.conversation,
            "message_id": self.message_id, "source_id": source.owner.subject})
        self.arrival_key = AtomKey(Owner("event", *r.namespace.as_tuple, event_id), "d03.world_event", "current")
        self.owner_key = owner_grant_key(*r.namespace.as_tuple)
        self.exact = {self.owner_key.token, self.anchor_key.token, self.focus_key.token, self.arrival_key.token}
        self.phase = "heads"

    def _start_control_v1(self, head):
        if head[2] != 1:
            raise AuthorityUnavailable("Natural P2 selected metadata control is invalid")
        self.pending = head
        self.column = _NaturalP2ControlColumnV1(self.reader, head)

    def _complete_column_v1(self):
        head = self.pending
        value = self.column.value_v1()
        key = AtomKey.from_token(head[0])
        self.reader.operation.retain(2048)
        self.controls[head[0]] = GraphAtom(key, head[1], value, True)
        self.body_keys.add(head[0])
        self.control_columns[head[0]] = self.column
        self.column = self.pending = None

    def _head_v1(self, meter):
        r = self.reader
        row = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_atoms",
            ("token", "revision", "valid", "type_name", "value_cell_id"),
            "bot=? AND persona=? AND token>? ORDER BY token", (*r.namespace.as_tuple, self.cursor))
        if row is None:
            self.queue = sorted(self.exact - set(self.controls))
            self.phase = "selected_controls"
            return
        key = AtomKey.from_token(row[0])
        if ((key.owner.bot, key.owner.persona) != r.namespace.as_tuple or key.type_name != row[3]
                or type(row[1]) is not int or row[1] < 1 or row[2] not in (0, 1) or row[4] is None):
            raise AuthorityUnavailable("Natural P2 namespace head census contains an invalid identity")
        r.store._validate_key(key)
        r.operation.retain(512 + len(row[0]) * 4)
        self.heads[row[0]] = tuple(row)
        self.cursor = row[0]
        self.head_count += 1
        self.head_root = canonical_digest(("sylanne.natural-p2-head.v1", self.head_root, tuple(row)))
        if row[2] == 1 and row[3] in _CONTROL_TYPES_V1:
            self._start_control_v1(tuple(row))

    def _select_dependencies_v1(self):
        r = self.reader
        binding = self.controls.get(self.account_key.token)
        if binding is None:
            raise AuthorityUnavailable("Natural P2 actual account binding metadata is absent")
        value = binding.value
        if (value["account_id"] != self.account_key.name or value["platform_namespace"] != self.platform
                or value["platform_identifier"] != self.sender or value["entity_id"] != self.anchor_key.name):
            raise AuthorityUnavailable("Natural P2 selected account metadata identity differs")
        self.evidence_key = AtomKey.from_token(value["verification_ref"])
        if (self.evidence_key.type_name != "d03.world_event" or self.evidence_key.owner.kind != "event"
                or (self.evidence_key.owner.bot, self.evidence_key.owner.persona) != r.namespace.as_tuple):
            raise AuthorityUnavailable("Natural P2 selected binding evidence metadata crosses namespace")
        focus = self.controls[self.focus_key.token].value
        from ..domains.d07 import attention_ticket_key
        if focus["persona_id"] != r.namespace.persona_id or not focus["primary_ticket_ref"]:
            raise AuthorityUnavailable("Natural P2 has no actual canonical primary focus")
        self.ticket_key = AtomKey.from_token(focus["primary_ticket_ref"])
        if self.ticket_key != attention_ticket_key(r.namespace, self.ticket_key.name):
            raise AuthorityUnavailable("Natural P2 focus selected a noncanonical ticket")
        self.queue = sorted({self.evidence_key.token, self.ticket_key.token} - set(self.controls))
        self.phase = "dependency_controls"

    def _finish_v1(self):
        r = self.reader
        ticket = self.controls[self.ticket_key.token].value
        if (ticket["causal_root"] != self.source_ref or ticket["source_refs"] != [self.source_ref]
                or ticket["category"] != "interaction" or ticket["valid_until"] <= r.now_utc
                or not ticket["eligible"] or not ticket["resources_available"] or ticket["cancel_refs"]):
            raise AuthorityUnavailable("Natural P2 current attention does not select its actual ingress Source")
        arrival = self.controls[self.arrival_key.token].value
        if arrival["source_refs"] != [self.source_ref]:
            raise AuthorityUnavailable("Natural P2 selected arrival has different Source roots")
        roots = {self.source_ref}
        for key in (self.arrival_key, self.evidence_key):
            value = self.controls[key.token].value
            if value["reality"] != "host_observed" or value["kind"] != "message_received":
                raise AuthorityUnavailable("Natural P2 route evidence is not actual host metadata")
            roots.update(value["source_refs"])
        self.route_roots = tuple(sorted(roots))
        self.attention_roots = (self.source_ref,)
        for ref in self.route_roots:
            key = AtomKey.from_token(ref)
            from ..memory_types import source_key
            if key != source_key(*r.namespace.as_tuple, key.owner.subject or ""):
                raise AuthorityUnavailable("Natural P2 actual route Source roots cross namespace")
        self.complete = True
        self.phase = "complete"

    def advance(self, meter):
        self.reader.require_original_work_v1()
        if self.column is not None:
            if self.column.advance(meter):
                self._complete_column_v1()
            return False
        if self.phase == "ingress":
            self._ingress_v1(meter)
        elif self.phase == "heads":
            self._head_v1(meter)
        elif self.phase in {"selected_controls", "dependency_controls"}:
            if self.queue:
                token = self.queue.pop(0)
                head = self.heads.get(token)
                if head is None:
                    raise AuthorityUnavailable("Natural P2 exact selected metadata head is absent")
                self._start_control_v1(head)
            elif self.phase == "selected_controls":
                self._select_dependencies_v1()
            else:
                self._finish_v1()
        return self.complete


class _NaturalP2RouteSourcesV1:
    """Additional CURRENT route/attention groups never alter the producer manifest."""
    def __init__(self, reader):
        self.reader = reader
        self.groups = (("route", reader.census.route_roots, False),
            ("attention", reader.census.attention_roots, True))
        self.index = 0
        self.active, self.done = set(), set()
        self.stack = []
        self.root_index = 0
        self.node = None
        self.members = []
        self.complete = False

    def _enter_v1(self, ref):
        r = self.reader
        if ref in self.active:
            raise AuthorityUnavailable("Natural P2 current route Source family is cyclic")
        if ref in self.done:
            return
        if len(self.active) + len(self.done) >= 256:
            raise AuthorityUnavailable("Natural P2 current route Source family exceeds its original bound")
        if ref not in r.sources:
            self.node = _NaturalInitialSourceNodeV1(r, ref, current_route=True)
            return
        from ..domains.d07.qualified_attention_read import (
            _qualify_source_rights_values_v3, _qualify_source_node_values_v3,
        )
        source = r.sources[ref]
        check = _qualify_source_node_values_v3 if self.groups[self.index][2] else _qualify_source_rights_values_v3
        value = check(r.namespace, ref, source, r.access.get(ref), None,
            audience=r.census.conversation, purpose="expression", metadata_only=True)
        if value is None:
            raise AuthorityUnavailable("Natural P2 current route Source lacks actual expression/attention rights")
        r.reserve_scratch_v1(65536 + len(self.active) * 128 + len(value.parent_source_ids) * 16)
        self.active.add(ref)
        self.stack.append((ref, iter(value.parent_source_ids)))

    def advance(self, meter):
        r = self.reader
        if self.node is not None:
            if self.node.advance(meter):
                ref = self.node.ref
                self.node = None
                self._enter_v1(ref)
            return False
        if self.index == len(self.groups):
            self.complete = True
            return True
        if self.stack:
            ref, parents = self.stack[-1]
            try:
                parent = next(parents)
            except StopIteration:
                self.stack.pop()
                self.active.remove(ref)
                self.done.add(ref)
                return False
            from ..memory_types import source_key
            token = source_key(*r.namespace.as_tuple, parent).token
            meter.charge_encode(len(token))
            self._enter_v1(token)
            return False
        roots = self.groups[self.index][1]
        if self.root_index < len(roots):
            ref = roots[self.root_index]
            self.root_index += 1
            self._enter_v1(ref)
            return False
        r.operation.retain(256 + len(self.done) * 64)
        self.members.append(("expression", (r.census.conversation,), frozenset(self.done)))
        self.active, self.done, self.stack = set(), set(), []
        self.root_index = 0
        self.index += 1
        return False


class _NaturalP2SourceAllV1:
    """This exact P2 Work's current purpose groups, not an initial READ proof."""
    def __init__(self, issuer, reader):
        if (issuer is not _ISSUER_V1 or reader.phase != "route_sources"
                or not reader.producer_sources.complete or not reader.route_sources.complete):
            raise AuthorityUnavailable("actual complete P2 producer/current Source groups required")
        self.reader, self.owner, self.operation, self.work = reader, reader.parent, reader.operation, reader.parent.work
        self.metadata = reader.locator.result
        self.sources, self.access = MappingProxyType(dict(reader.sources)), MappingProxyType(dict(reader.access))
        self.heads = MappingProxyType(dict(reader.heads))
        self.groups = tuple(reader.producer_sources.members) + tuple(reader.route_sources.members)
        self.producer_sources = frozenset(reader.source_originals)
        self.c02_operation_id, self.source_ref = reader.census.c02_operation_id, reader.census.source_ref
        self.head_count, self.head_root = reader.census.head_count, reader.census.head_root
        self.correction_absences = frozenset(reader.correction_absences)
        reader.operation.retain(4096 + 256 * (len(self.sources) + len(self.access) + len(self.heads)))
        _BARRIERS_V1[self] = self._identity_v1()

    def _identity_v1(self):
        return (self.reader, self.owner, self.operation, self.work, self.metadata,
            self.sources, self.access, self.heads, self.groups, self.producer_sources,
            self.c02_operation_id, self.source_ref, self.head_count, self.head_root, self.correction_absences)

    def require_current_v1(self, owner, db):
        if (_BARRIERS_V1.get(self) != self._identity_v1() or owner is not self.owner
                or db is not self.reader.db or owner.work is not self.work
                or self.reader.sources is not self.sources or self.reader.access is not self.access):
            raise AuthorityUnavailable("Natural P2 SourceALL actual issuer/selection changed")
        self.reader.require_original_work_v1()
        self.metadata.require_for_v1(self.reader)
        return self

    def require_c02_selection_v1(self, c02_operation_id, source_ref):
        self.require_current_v1(self.owner, self.reader.db)
        if (c02_operation_id, source_ref) != (self.c02_operation_id, self.source_ref):
            raise AuthorityUnavailable("Natural P2 C02 original differs from its actual SourceALL selection")
        return self

    def release_payload_v3(self):
        _BARRIERS_V1.pop(self, None)
        self.reader = self.owner = self.operation = self.work = self.metadata = None
        self.sources = self.access = self.heads = self.groups = self.producer_sources = self.correction_absences = None


class NaturalP2ClosedProjectionV1:
    """Complete closed controls and selected Body EOF, with full head absence."""
    def __init__(self, reader):
        from .dispatch_current_inventory_v3 import _FrozenDispatchAtomV3, _freeze_value_v3
        self.reader, self._operation = reader, reader.operation
        atoms = tuple(reader.controls.values()) + tuple(reader.access.values()) + tuple(reader.body_atoms.values())
        self._operation.retain(4096 + sum(1024 + _heap(atom.value) * 4 for atom in atoms))
        self._atoms = tuple(_FrozenDispatchAtomV3(atom.key, atom.revision,
            _freeze_value_v3(atom.value), atom.valid, _heap(atom.value)) for atom in atoms)
        self._by_token = {atom.key.token: atom for atom in self._atoms}
        self.epochs = (reader.graph_stamp[1],)
        self.heads = MappingProxyType(reader.census.heads)
        self.complete_control_families = _CONTROL_TYPES_V1
        self.selected_body_keys = frozenset(reader.body_atoms)
        self.namespace_head_eof = True
        self.head_count, self.head_root = reader.census.head_count, reader.census.head_root

    def _view(self, atom):
        from .dispatch_current_inventory_v3 import _detach_value_v3
        self._operation.retain(atom.retained_bytes * 4 + 512)
        return GraphAtom(atom.key, atom.revision, _detach_value_v3(atom.value), atom.valid)

    @property
    def atoms(self):
        raise AuthorityUnavailable("Natural closed projection does not claim every namespace Body")

    def get(self, key):
        value = self._by_token.get(key.token)
        if value is not None:
            return self._view(value)
        head = self.heads.get(key.token)
        if head is None:
            return None
        if head[2] == 0:
            return GraphAtom(key, head[1], {}, False)
        raise AuthorityUnavailable("Natural current head exists but its Body was not prepared")

    def atoms_for_types_v3(self, types):
        wanted = frozenset(types)
        if not wanted <= self.complete_control_families:
            raise AuthorityUnavailable("Natural closed projection has no full Body census for requested types")
        self._operation.retain(256 + len(self._atoms) * 16)
        return tuple(self._view(atom) for atom in self._atoms if atom.valid and atom.key.type_name in wanted)


class _NaturalP2SelectedBodyV1(DispatchOriginalJSONReadV3):
    def __init__(self, reader, token):
        require_natural_p2_source_all_v1(reader.parent, reader.db)
        if reader.phase != "selected_body" or reader.parent.work.terminal or reader.parent.work._finish_called:
            raise AuthorityUnavailable("Natural P2 selected Body requires its actual active post-Source phase")
        head = reader.census.heads.get(token)
        if head is None or head[2] != 1:
            raise AuthorityUnavailable("Natural P2 actual selected Body head is unavailable")
        self.head = head
        super().__init__(reader.parent, table="graph_atoms", column="value", key_columns=("token",),
            key=(token,), cell_id=head[4])
        if self.cell.header[1] != token or self.cell.header[0] not in ("canonical-json.ascii.v1", "canonical-json.utf8.v1"):
            raise AuthorityUnavailable("Natural P2 selected Body physical owner/codec differs")
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == "canonical-json.ascii.v1")


class _NaturalP2ReadV1:
    def __init__(self, issuer, parent):
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
        if issuer is not _ISSUER_V1 or type(parent) is not _DispatchInventoryReadV3 or parent.family != "natural_reply":
            raise AuthorityUnavailable("actual exact Natural P2 inventory Work owner required")
        self.parent = parent
        self.graph, self.store, self.db = parent.graph, parent.store, parent.db
        self.namespace, self.operation, self.fence = parent.namespace, parent.operation, parent.fence
        self.graph_stamp, self.query, self.selection_digest = parent.graph_stamp, parent.query, parent.selection_digest
        self.work = None
        self.phase = "fixed"
        self.locator = self.census = self.producer_sources = self.route_sources = self.barrier = None
        self.sources, self.access, self.heads, self.access_originals = {}, {}, {}, {}
        self.source_originals, self.correction_absences = {}, set()
        self.body_atoms, self.body_columns = {}, {}
        self.controls = {}
        self.body_queue = []
        self.body_column = self.c02_task = None
        self.complete = False
        self.scratch_peak = 0
        self.authority_epochs = self.owner_head = None
        self.bundle_header = self.admission_header = self.final_job_header = self.final_job_id = None

    @property
    def now_utc(self):
        return self.parent.now_utc

    def attach_work_v1(self, work):
        if self.work is not None or work.state is not self.parent or work.operation is not self.operation:
            raise AuthorityUnavailable("Natural P2 source preparation requires its once-issued parent Work")
        self.work = work
        _READERS_V1[self] = self._identity_v1()

    def _identity_v1(self):
        return (self.parent, self.graph, self.db, self.namespace, self.operation, self.fence,
            self.graph_stamp, self.query, self.selection_digest, self.work)

    def reserve_scratch_v1(self, wanted):
        if wanted > self.scratch_peak:
            self.operation.retain(wanted - self.scratch_peak)
            self.scratch_peak = wanted

    def require_original_work_v1(self):
        if (_READERS_V1.get(self) != self._identity_v1() or self.work is None or self.parent.work is not self.work
                or self.work.state is not self.parent or self.work.operation is not self.operation
                or self.work.kind != "dispatch_inventory_prepare_v3" or self.operation.closed
                or self.parent.family != "natural_reply" or runtime_storage_v3(self.db) is not self.operation.handle
                or self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp):
            raise AuthorityUnavailable("Natural P2 original Work/fence/selection changed")
        self.parent.now_utc = self.parent.read_time.require_current_v3(self.graph, self.parent.binding)
        if self.authority_epochs is not None:
            epochs = self.db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                self.namespace.as_tuple).fetchone()
            owner = self.db.execute("SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
                (*self.namespace.as_tuple, owner_grant_key(*self.namespace.as_tuple).token)).fetchone()
            if epochs != self.authority_epochs or owner != self.owner_head:
                raise AuthorityUnavailable("Natural P2 current Owner/Source authority changed")
        if self.final_job_header is not None:
            from ..runtime_storage_v3 import runtime_storage_quantum_v3
            with runtime_storage_quantum_v3(self.db) as meter:
                job = _runtime_bounded_fixed_row_v3(self.db, meter, "runtime_jobs", (*_FINAL_JOB,
                    "lease_holder", "lease_expires_utc", "result_ref"), "job_id=?", (self.final_job_id,))
            if job != self.final_job_header:
                raise AuthorityUnavailable("Natural P2 actual final message job changed after metadata")
        return self

    def _fixed_v1(self, meter):
        self.authority_epochs = _runtime_bounded_fixed_row_v3(self.db, meter, "graph_authority_epochs",
            ("access_epoch", "delete_epoch"), "bot=? AND persona=?", self.namespace.as_tuple)
        self.owner_head = _runtime_bounded_fixed_row_v3(self.db, meter, "graph_atoms",
            ("revision", "valid", "value_cell_id"), "bot=? AND persona=? AND token=?",
            (*self.namespace.as_tuple, owner_grant_key(*self.namespace.as_tuple).token))
        if self.authority_epochs is None or self.owner_head is None or self.owner_head[1] != 1:
            raise AuthorityUnavailable("Natural P2 actual Owner or Source authority metadata absent")
        self.parent.authority_epochs = self.authority_epochs
        self.locator = _NaturalP2LocatorReadV1(self)
        self.phase = "locator"

    def advance(self, meter):
        self.require_original_work_v1()
        if self.phase == "fixed":
            self._fixed_v1(meter)
        elif self.phase == "locator":
            if self.locator.advance(meter):
                m = self.locator.result.require_for_v1(self)
                selected = m["recipe"]["committed_selection"]
                if (selected["access_epoch"], selected["delete_epoch"]) != self.authority_epochs:
                    raise AuthorityUnavailable("Natural P2 producer/current Source epochs differ")
                self.census = _NaturalP2MetadataCensusV1(self)
                self.phase = "census"
        elif self.phase == "census":
            if self.census.advance(meter):
                self.heads = dict(self.census.heads)
                # Shared Source mechanics use their own (revision,valid,cell)
                # head map; the complete namespace census remains separate.
                self.heads = {ref: (head[1], head[2], head[4]) for ref, head in self.heads.items()}
                self.controls = self.census.controls
                self.producer_sources = _NaturalInitialSourcesV1(self, self.locator.result)
                self.phase = "producer_sources"
        elif self.phase == "producer_sources":
            if self.producer_sources.advance(meter):
                self.route_sources = _NaturalP2RouteSourcesV1(self)
                self.phase = "route_sources"
        elif self.phase == "route_sources":
            if self.route_sources.advance(meter):
                self.barrier = _NaturalP2SourceAllV1(_ISSUER_V1, self)
                self.sources, self.access = self.barrier.sources, self.barrier.access
                from .dispatch_admission_read_v3 import DispatchAdmissionReadV3
                self.parent.admission_task = DispatchAdmissionReadV3(self.parent)
                self.phase = "admission"
        elif self.phase == "admission":
            require_natural_p2_source_all_v1(self.parent, self.db)
            if self.parent.admission_task.advance(meter):
                self.parent.admission_originals = self.parent.admission_task.result
                self.parent.admission_task = None
                writes = self.locator.result.metadata["recipe"]["committed_selection"]["candidate_writes"]
                action = AtomKey.from_token(writes[0]["ref"])
                cancellation = AtomKey(action.owner, "d08.action_cancellation.v1", action.name)
                self.body_queue = [writes[0]["ref"], writes[1]["ref"], cancellation.token]
                self.phase = "selected_body"
        elif self.phase == "selected_body":
            require_natural_p2_source_all_v1(self.parent, self.db)
            if self.body_column is not None:
                if self.body_column.advance(meter):
                    column = self.body_column
                    token = column.key[0]
                    value = column.require_v3(self.parent)
                    key = AtomKey.from_token(token)
                    self.store._registry.spec(key.type_name).validator(value)
                    self.body_atoms[token] = GraphAtom(key, column.head[1], value, True)
                    self.body_columns[token] = column
                    self.body_column = None
            elif self.body_queue:
                self.body_column = _NaturalP2SelectedBodyV1(self, self.body_queue.pop(0))
            else:
                from .dispatch_initial_source_read_v3 import DispatchInitialSourceReadsV3
                self.parent.auxiliary = DispatchInitialSourceReadsV3(self.parent, "natural_reply", self.now_utc)
                self.phase = "originals"
        elif self.phase == "originals":
            require_natural_p2_source_all_v1(self.parent, self.db)
            if self.parent.auxiliary.advance(meter):
                original = self.parent.auxiliary.original
                if (original.sha256, original.byte_count) != (self.locator.result.original_sha, self.locator.result.original_bytes):
                    raise AuthorityUnavailable("Natural P2 post-Source receipt differs from its complete metadata EOF")
                self.phase = "c02_originals"
        elif self.phase == "c02_originals":
            require_natural_p2_source_all_v1(self.parent, self.db)
            from .natural_dispatch_p2_c02_originals_v1 import begin_natural_p2_c02_originals_v1
            if self.c02_task is None:
                self.c02_task = begin_natural_p2_c02_originals_v1(self.parent,
                    c02_operation_id=self.barrier.c02_operation_id, source_ref=self.barrier.source_ref)
            elif self.c02_task.advance(meter):
                self.parent.natural_c02_originals = self.c02_task.result
                self.parent.sources = self.sources
                self.parent.heads = dict(self.heads)
                self.parent.atoms = list(self.controls.values()) + list(self.access.values()) + list(self.body_atoms.values())
                self.parent.count, self.parent.root = self.census.head_count, self.census.head_root
                self.complete = True
                self.phase = "complete"
        return self.complete

    def release_payload_v3(self):
        _READERS_V1.pop(self, None)
        if self.barrier is not None:
            self.barrier.release_payload_v3()
        if self.locator is not None and self.locator.result is not None:
            self.locator.result.release_payload_v3()
        self.locator = self.census = self.producer_sources = self.route_sources = self.barrier = None
        self.sources = self.access = self.heads = self.access_originals = self.source_originals = self.controls = None
        self.body_atoms = self.body_columns = self.body_column = self.c02_task = self.body_queue = None
        self.parent.natural_task = None
        self.parent.natural_c02_originals = None


def begin_natural_p2_read_v1(parent):
    return _NaturalP2ReadV1(_ISSUER_V1, parent)


def require_natural_p2_source_all_v1(owner, db):
    from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
    if type(owner) is not _DispatchInventoryReadV3 or owner.family != "natural_reply" or owner.db is not db:
        raise AuthorityUnavailable("exact Natural P2 source-barrier owner required")
    reader = owner.natural_task
    if type(reader) is not _NaturalP2ReadV1 or type(reader.barrier) is not _NaturalP2SourceAllV1:
        raise AuthorityUnavailable("Natural P2 Source ALL has not completed; no Body read allowed")
    result = reader.barrier.require_current_v1(owner, db)
    if owner.work.terminal or owner.work._finish_called:
        from .current_graph_full_read_v3 import _BOUND, _DispatchFullReadBindingV3
        from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3
        bound = _BOUND.get()
        if (type(bound) is not _DispatchFullReadBindingV3
                or type(bound.proof) is not PreparedCurrentDispatchInventoryV3
                or bound.proof.natural_source_all is not result or bound.qualification is None):
            raise AuthorityUnavailable("finished Natural READ cached originals need their actual P1/P2 binding")
        context, binding, claimed, authority_snapshot = bound.qualification
        bound.proof.require_for(context, binding, claimed, db, authority_snapshot=authority_snapshot)
    return result
