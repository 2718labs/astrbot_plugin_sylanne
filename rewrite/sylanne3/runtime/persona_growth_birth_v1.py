"""Same-Work persona birth metadata, never a target or PersonaPlan Body reader."""
from dataclasses import dataclass
import hashlib
import json
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion, Owner, owner_grant_key
from ..runtime_contracts import NamespaceId
from ..runtime_storage_v3 import begin_runtime_cell_read_v3
from ..domains.d01 import _activation_key, _validate_persona_activation
from .persona_growth_review_contract_v1 import target_domain_v1

# Exact primary producing domain and permitted first-write target types. A
# matching name alone is insufficient: the original must read 0 and write 1.
FIRST_CREATE_TARGETS_V1 = {
    "input:create_goal": ("d08", ("d08.goal.v1",)),
    "input:create_aspiration": ("d08", ("d08.aspiration.v1",)),
    "input:create_commitment": ("d08", ("d08.commitment.v1",)),
    "input:create_commitment_with_fulfillment_terms": ("d08", ("d08.commitment.v1", "d08.commitment_fulfillment_terms.v1")),
    "create_personal_plan": ("d08", ("d08.goal.v1", "d08.personal_plan.v1")),
    "compose_artifact_goal_plan": ("d08", ("d08.goal.v1", "d08.personal_plan.v1")),
    "derive_ingress_artifact_task_scope_v1": ("d10", ("d08.goal.v1",)),
    "create_artifact_task_plan_v1": ("d08", ("d08.personal_plan.v1",)),
    "submit_owner_source_note_task_v1": ("d08", ("d08.goal.v1", "d08.personal_plan.v1")),
    "instantiate_current_habit_source_note_context_v1": ("d08", ("d08.goal.v1", "d08.personal_plan.v1")),
    "adopt_joint_plan": ("d08", ("d08.joint_plan.v1",)),
    "adopt_long_term_plan_v1": ("d08", ("d08.long_term_plan.v1",)),
    "input:create_life_project": ("d10", ("d10.life_project.v1", "d10.activity_recipe.v1")),
    "create_artifact_project": ("d10", ("d10.life_project.v1", "d10.activity_recipe.v1")),
    "create_artifact_task_project_v1": ("d10", ("d10.life_project.v1", "d10.activity_recipe.v1")),
    "create_habit_policy_v1": ("d10", ("d10.habit_policy.v1",)),
}
PERSONA_CONTROL_CAPTURE_OPERATIONS_V1 = frozenset(FIRST_CREATE_TARGETS_V1) | {"input:register_commitment_communication", "input:register_commitment_terms_communication"}
_ACTIVATION_FIELDS = ("plan_id", "plan_version", "head_id", "owner_grant_id",
    "owner_grant_revision", "graph_incarnation", "activation_generation", "authorization_revision", "state")
_GRANT_FIELDS = ("schema", "authority_id", "installation_id", "grant_id", "grant_revision",
    "state", "scope", "activation_generation", "graph_incarnation")
_NAMESPACE_PATHS = (("namespace", "bot_id"), ("namespace", "persona_id"))


@dataclass(frozen=True, slots=True)
class PersonaBirthControlV1:
    namespace: NamespaceId
    activation_version: GraphVersion
    persona_head_version: GraphVersion
    owner_grant_version: GraphVersion
    head_id: str
    semantic_version: int
    graph_incarnation: str
    activation_value: dict


@dataclass(frozen=True, slots=True)
class PersonaBirthProofV1:
    target: GraphVersion
    operation_id: str
    original_digest: str
    activation: GraphVersion
    persona_head: GraphVersion
    owner_grant: GraphVersion
    head_id: str
    semantic_version: int
    graph_incarnation: str


class _VersionMembersV1:
    """Hash the entire metadata readset; retain only selected exact members."""
    def __init__(self, selected):
        self.selected = tuple(selected)
        self.members = {}
        self.digest = hashlib.sha256()
        self.count = 0
        self.key_hash = None
        self.offset = 0
        self.matches = ()
        self.high = None
        self.revision = bytearray()
        self.row_revision = None

    def codepoint(self, codepoint):
        if self.high is not None:
            high, self.high = self.high, None
            if 0xdc00 <= codepoint <= 0xdfff:
                codepoint = 0x10000 + ((high - 0xd800) << 10) + codepoint - 0xdc00
            else:
                self._codepoint(high)
        if 0xd800 <= codepoint <= 0xdbff:
            self.high = codepoint
        else:
            self._codepoint(codepoint)

    def _codepoint(self, codepoint):
        self.key_hash.update(chr(codepoint).encode("utf-8", "surrogatepass"))
        self.matches = tuple(key for key in self.matches
            if self.offset < len(key) and ord(key[self.offset]) == codepoint)
        self.offset += 1

    def event(self, event, path):
        key_part, revision_part = 0, 1
        if len(path) == 1 and event.kind in {"array_start", "object_start"}:
            self.key_hash = None
            self.row_revision = None
        elif len(path) == 2 and path[1] == key_part:
            if event.kind == "scalar_start":
                if event.scalar_kind != "string":
                    raise AuthorityUnavailable("Birth readset has another registered key shape")
                self.key_hash = hashlib.sha256()
                self.offset, self.high, self.matches = 0, None, self.selected
            elif event.kind == "scalar_end":
                if self.high is not None:
                    self._codepoint(self.high)
                    self.high = None
                self.matches = tuple(key for key in self.matches if len(key) == self.offset)
        elif len(path) == 2 and path[1] == revision_part:
            if event.kind == "scalar_start":
                self.revision = bytearray()
            elif event.kind == "scalar_chunk":
                if event.scalar_kind != "number" or len(self.revision) + len(event.raw) > 24:
                    raise AuthorityUnavailable("Birth readset requires bounded exact integer revisions")
                self.revision.extend(event.raw)
            elif event.kind == "scalar_end":
                value = json.loads(self.revision)
                if type(value) is not int or value < 0:
                    raise AuthorityUnavailable("Birth readset has a negative/noninteger revision")
                self.row_revision = value
        elif len(path) == 1 and event.kind in {"array_end", "object_end"}:
            if self.key_hash is None or self.row_revision is None:
                raise AuthorityUnavailable("Birth readset has an incomplete exact member")
            self.digest.update(self.key_hash.digest() + str(self.row_revision).encode("ascii") + b";")
            self.count += 1
            for key in self.matches:
                if key in self.members:
                    raise AuthorityUnavailable("Birth readset duplicated an exact selected key")
                self.members[key] = self.row_revision

    def result(self):
        return self.digest.hexdigest(), self.count, dict(self.members)


class GrowthMetadataColumnV1:
    """Canonical full EOF and fixed scalar selectors without semantic retention."""
    def __init__(self, task, *, table, column, keys, key, paths=(), versions=(), cell=None):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.task, self.owner = task, task.owner
        self.table, self.column, self.keys, self.key = table, column, tuple(keys), tuple(key)
        self.paths = frozenset(paths)
        self.fields, self.raw = {}, bytearray()
        self.fragment, self.offset, self.total = b"", 0, None
        self.complete = False
        self.sha256 = None
        self.cell = cell
        self.semantic_decoder = self.semantic_hash = None
        if cell is not None and cell.header[0] == "canonical-json.utf8.v1":
            import codecs
            self.semantic_decoder = codecs.getincrementaldecoder("utf8")("strict")
            self.semantic_hash = hashlib.sha256()
        self.scanners = {tuple(prefix): _VersionMembersV1(selected)
            for prefix, selected in versions}
        metadata = self
        class MetadataStreamV1(C09CanonicalJSONStreamV2):
            def _append_decoded_codepoint(self, codepoint):
                state = self._string
                if state is not None and state["mode"] == "value":
                    path = state["path"]
                    for prefix, scanner in metadata.scanners.items():
                        rest = path[len(prefix):]
                        key_part = 0
                        if path[:len(prefix)] == prefix and len(rest) == 2 and rest[1] == key_part:
                            scanner.codepoint(codepoint)
                            return
                    # Selected scalar strings are decoded from bounded raw
                    # bytes at scalar_end. All other strings are discarded.
                    return
                return super()._append_decoded_codepoint(codepoint)
        self.parser = MetadataStreamV1(ensure_ascii=cell is None or cell.header[0] != "canonical-json.utf8.v1")
        self.owner.operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        from .dispatch_current_inventory_v3 import _heap
        from sys import getsizeof
        return getsizeof(self) + getsizeof(self.__dict__) + _heap((self.fields, self.raw,
            self.fragment, self.paths, tuple((prefix, scanner.members, scanner.matches,
                scanner.revision, scanner.selected) for prefix, scanner in self.scanners.items())))

    def _emit(self, event):
        for prefix, scanner in self.scanners.items():
            if event.path[:len(prefix)] == prefix:
                scanner.event(event, event.path[len(prefix):])
                return
        if event.path not in self.paths:
            return
        if event.kind == "scalar_start":
            self.raw = bytearray()
        elif event.kind == "scalar_chunk":
            if len(self.raw) + len(event.raw) > 65536:
                raise AuthorityUnavailable("Birth fixed control scalar exceeds its registered metadata decoder")
            self.raw.extend(event.raw)
        elif event.kind == "scalar_end":
            self.fields[event.path] = json.loads(self.raw)
            self.raw = bytearray()

    def advance(self, meter):
        from .persona_growth_review_metadata_v1 import _current_v1
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2, read_legacy_sql_cell_fragment_v2, _quote
        _current_v1(self.owner, meter)
        if self.complete:
            return
        self.owner.operation.reserve_retained_state_growth_v3(self, 196608)
        try:
            if self.fragment:
                chunk, self.fragment = self.fragment[:1024], self.fragment[1024:]
                self.parser.feed(chunk, self._emit)
                if self.semantic_decoder is not None:
                    self._semantic_hash_v1(chunk, meter)
                return
            if self.cell is not None:
                chunk = self.cell.read_fragment(meter=meter)
            else:
                where = " AND ".join(_quote(name) + "=?" for name in self.keys)
                with legacy_cell_read_transaction_v2(self.owner.db):
                    if self.total is None:
                        meter.require_available(1024)
                        row = self.owner.db.execute("SELECT typeof(" + _quote(self.column)
                            + "),length(CAST(" + _quote(self.column) + " AS BLOB)) FROM "
                            + _quote(self.table) + " WHERE " + where, self.key).fetchone()
                        meter.charge_read(16)
                        if row is None or row[0] != "text":
                            self.complete = True
                            self.parser = None
                            return
                        self.total = row[1]
                    if self.offset < self.total:
                        chunk, total, kind = read_legacy_sql_cell_fragment_v2(self.owner.db,
                            table=self.table, column=self.column, where=where, parameters=self.key,
                            start=self.offset, length=min(16384, self.total - self.offset), meter=meter)
                        if (total, kind) != (self.total, "text"):
                            raise AuthorityUnavailable("Birth metadata physical identity changed")
                        self.offset += len(chunk)
                    else:
                        chunk = None
            if chunk is not None:
                self.fragment = chunk
                return
            parsed = self.parser.finish()
            if self.cell is not None:
                if (parsed.sha256, parsed.byte_count) != (self.cell.finish(meter=meter), self.cell.header[3]):
                    raise AuthorityUnavailable("Birth metadata cell lost its complete physical EOF")
            elif parsed.byte_count != self.total:
                raise AuthorityUnavailable("Birth metadata legacy column has incomplete EOF")
            if self.semantic_decoder is not None:
                self._semantic_hash_v1(b"", meter, final=True)
                self.sha256 = self.semantic_hash.hexdigest()
            else:
                self.sha256 = parsed.sha256
            self.semantic_decoder = self.semantic_hash = None
            self.complete = True
            self.parser = None
        finally:
            self.owner.operation.finish_retained_state_growth_v3(self)

    def _semantic_hash_v1(self, chunk, meter, *, final=False):
        text = self.semantic_decoder.decode(chunk, final=final)
        raw = "".join(char if ord(char) < 127 else json.dumps(char, ensure_ascii=True)[1:-1]
            for char in text).encode("ascii")
        meter.charge_encode(len(raw))
        self.semantic_hash.update(raw)

    def close(self):
        self.owner.operation.unregister_retained_state_v3(self)

    def value(self):
        if not self.complete:
            raise AuthorityUnavailable("Birth metadata has not completed canonical EOF")
        return {"fields": dict(self.fields), "versions": {prefix: scanner.result()
            for prefix, scanner in self.scanners.items()}, "sha256": self.sha256}


def _fields_v1(record):
    result = {}
    for path, value in record["fields"].items():
        if len(path) == 1:
            result[path[0]] = value
        elif path[0] == "namespace":
            result.setdefault("namespace", {})[path[1]] = value
    return result


class _ControlReadV1:
    def __init__(self, task, key, revision):
        self.task, self.owner, self.key, self.revision = task, task.owner, key, revision
        self.header = self.column = self.result = None
        self.complete = False
        if key.type_name == "d01.persona_activation.v1":
            self.paths = (*_NAMESPACE_PATHS, *((name,) for name in _ACTIVATION_FIELDS))
        elif key.type_name == "d01.persona_plan.v1":
            self.paths = (*_NAMESPACE_PATHS, ("plan_id",), ("version",))
        elif key == owner_grant_key(*self.owner.namespace.as_tuple):
            self.paths = tuple((name,) for name in _GRANT_FIELDS)
        else:
            raise AuthorityUnavailable("Birth control selector has another registered metadata type")

    def _header(self, meter):
        if self.revision == 0:
            return self.task._fixed_metadata_row_v1(meter, "graph_atoms",
                ("revision", "valid", "type_name", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*self.owner.namespace.as_tuple, self.key.token))
        return self.task._fixed_metadata_row_v1(meter, "graph_history",
            ("event_id", "event_bot", "event_persona", "valid"), "token=? AND revision=?",
            (self.key.token, self.revision))

    def advance(self, meter):
        header = self._header(meter)
        if self.header is None:
            if header is None or (header[1] != 1 if self.revision == 0 else header[1:3] != self.owner.namespace.as_tuple or header[3] != 1):
                self.complete = True
                return
            if self.revision == 0 and (header[0] < 1 or header[2] != self.key.type_name):
                raise AuthorityUnavailable("Birth current metadata changed its exact graph identity")
            self.header = header
            return
        if header != self.header:
            raise AuthorityUnavailable("Birth control changed its actual current/historical metadata")
        if self.column is None:
            cell = None
            if self.revision == 0 and header[3] is not None:
                cell = begin_runtime_cell_read_v3(self.owner.db, header[3], erasure_owner_ref=self.key.token)
            self.column = GrowthMetadataColumnV1(self.task,
                table="graph_atoms" if self.revision == 0 else "graph_history", column="value",
                keys=("token", "bot", "persona") if self.revision == 0 else ("token", "revision"),
                key=(self.key.token, *self.owner.namespace.as_tuple) if self.revision == 0 else (self.key.token, self.revision),
                paths=self.paths, cell=cell)
            return
        self.column.advance(meter)
        if not self.column.complete:
            return
        record = self.column.value()
        value = _fields_v1(record)
        if set(record["fields"]) != set(self.paths):
            self.complete = True
            self.close()
            return
        namespace = {"bot_id": self.owner.namespace.bot_id, "persona_id": self.owner.namespace.persona_id}
        if self.key.type_name == "d01.persona_activation.v1":
            _validate_persona_activation(value)
            if value["namespace"] != namespace:
                raise AuthorityUnavailable("Birth activation control crossed namespace")
        elif self.key.type_name == "d01.persona_plan.v1":
            if (value["namespace"] != namespace or value["plan_id"] != self.key.name
                    or type(value["version"]) is not int or value["version"] < 1):
                raise AuthorityUnavailable("Birth PersonaPlan identity metadata crossed namespace/key/version")
        elif (value["schema"] != "sylanne3.graph.owner_grant.v1"
                or value["state"] != "pending_authority" or type(value["grant_revision"]) is not int or value["grant_revision"] != 1
                or type(value["activation_generation"]) is not int or value["activation_generation"] < 1
                or any(type(value[name]) is not str or not value[name] for name in
                    ("authority_id", "installation_id", "grant_id", "graph_incarnation"))):
            self.complete = True
            self.close()
            return
        self.result = {"version": GraphVersion(self.key, header[0] if self.revision == 0 else self.revision),
            "value": value, "digest": record["sha256"],
            "event_id": None if self.revision == 0 else header[0]}
        self.complete = True
        self.close()

    def close(self):
        if self.column is not None:
            self.column.close()
            self.column = None


class _BirthReadV1:
    def __init__(self, task, target):
        self.task, self.owner, self.target = task, task.owner, target
        self.phase = "history"
        self.history = self.header = self.column = self.control = self.result = None
        self.records = {}
        self.complete = False
        self.selected = (target.token, _activation_key(self.owner.namespace).token,
            owner_grant_key(*self.owner.namespace.as_tuple).token)

    def _unknown(self):
        self.close()
        self.result = None
        self.complete = True

    def _original_header(self, meter):
        return self.task._fixed_metadata_row_v1(meter, "graph_domain_production_originals_v1",
            ("domain", "operation_kind", "original_digest", "bundle_digest", "receipt_digest"),
            "bot=? AND persona=? AND operation_id=?", (*self.owner.namespace.as_tuple, self.history[0]))

    def _column(self, name, *, selected=None):
        fields, scans = (), ()
        members = self.selected if selected is None else tuple(selected)
        if name == "read_versions_json":
            scans = (((), members),)
        else:
            fields = tuple((field,) for field in ("status", "operation_id", "operation_digest", "activity_id", "effect_id", "commit_seq"))
            scans = ((("read_versions",), members), (("write_versions",), (self.target.token,)))
        return GrowthMetadataColumnV1(self.task, table="graph_domain_production_originals_v1",
            column=name, keys=("bot", "persona", "operation_id"),
            key=(*self.owner.namespace.as_tuple, self.history[0]), paths=fields, versions=scans)

    def advance(self, meter):
        if self.complete:
            return
        if self.phase == "history":
            self.history = self.task._fixed_metadata_row_v1(meter, "graph_history",
                ("event_id", "event_bot", "event_persona", "valid"), "token=? AND revision=1", (self.target.token,))
            if self.history is None or self.history[1:3] != self.owner.namespace.as_tuple or self.history[3] != 1:
                self._unknown()
                return
            self.phase = "header"
            return
        if self.phase == "header":
            self.header = self._original_header(meter)
            registration = None if self.header is None else FIRST_CREATE_TARGETS_V1.get(self.header[1])
            if registration is None or registration[0] != self.header[0] or self.target.type_name not in registration[1]:
                self._unknown()
                return
            self.phase = "reads"
            return
        if self._original_header(meter) != self.header:
            raise AuthorityUnavailable("Birth producing original changed during complete metadata EOF")
        if self.phase in {"reads", "receipt", "plan_receipt"}:
            name = {"reads": "read_versions_json",
                "receipt": "receipt_json", "plan_receipt": "receipt_json"}[self.phase]
            if self.column is None:
                self.column = self._column(name, selected=(self.plan_key.token,) if self.phase == "plan_receipt" else None)
                return
            self.column.advance(meter)
            if not self.column.complete:
                return
            record = self.column.value()
            self.column.close()
            self.column = None
            self.records[self.phase] = record
            if self.phase == "reads":
                self.phase = "receipt"
            elif self.phase == "receipt":
                if not self._receipt_matches():
                    self._unknown()
                    return
                revision = self.records["receipt"]["versions"][("read_versions",)][2][self.selected[1]]
                self.control = _ControlReadV1(self.task, _activation_key(self.owner.namespace), revision)
                self.phase = "activation"
            else:
                if record["sha256"] != self.header[4] or record["versions"][("read_versions",)][:2] != self.records["receipt"]["versions"][("read_versions",)][:2]:
                    self._unknown()
                    return
                revision = record["versions"][("read_versions",)][2].get(self.plan_key.token, 0)
                if revision < 1:
                    self._unknown()
                    return
                self.control = _ControlReadV1(self.task, self.plan_key, revision)
                self.phase = "plan"
            return
        if self.phase in {"activation", "plan", "grant"}:
            self.control.advance(meter)
            if not self.control.complete:
                return
            if self.control.result is None:
                self._unknown()
                return
            self.records[self.phase] = self.control.result
            self.control = None
            if self.phase == "activation":
                activation = self.records["activation"]["value"]
                self.plan_key = AtomKey(Owner("persona", *self.owner.namespace.as_tuple), "d01.persona_plan.v1", activation["plan_id"])
                self.phase = "plan_receipt"
            elif self.phase == "plan":
                activation, plan = self.records["activation"]["value"], self.records["plan"]["value"]
                # Semantic version and graph revision are separate observations.
                if plan["version"] != activation["plan_version"] or activation["head_id"] != plan["plan_id"] + "@" + str(plan["version"]):
                    self._unknown()
                    return
                revision = self.records["receipt"]["versions"][("read_versions",)][2][self.selected[2]]
                self.control = _ControlReadV1(self.task, owner_grant_key(*self.owner.namespace.as_tuple), revision)
                self.phase = "grant"
            else:
                self.phase = "ledger"
            return
        if self.phase == "ledger":
            ledger = self.task._fixed_metadata_row_v1(meter, "graph_bundle_operations",
                ("digest", "activity_id", "effect_id", "commit_seq"),
                "bot=? AND persona=? AND operation_id=?", (*self.owner.namespace.as_tuple, self.history[0]))
            receipt = self.records["receipt"]["fields"]
            activation, grant = self.records["activation"]["value"], self.records["grant"]["value"]
            if (ledger != (self.header[3], receipt[("activity_id",)], receipt[("effect_id",)], receipt[("commit_seq",)])
                    or activation["owner_grant_id"] != grant["grant_id"]
                    or activation["owner_grant_revision"] != self.records["grant"]["version"].revision
                    or activation["graph_incarnation"] != grant["graph_incarnation"]
                    or activation["activation_generation"] != grant["activation_generation"]
):
                self._unknown()
                return
            self.result = PersonaBirthProofV1(GraphVersion(self.target, 1), self.history[0], self.header[2],
                self.records["activation"]["version"], self.records["plan"]["version"], self.records["grant"]["version"],
                activation["head_id"], activation["plan_version"], activation["graph_incarnation"])
            self.complete = True

    def _receipt_matches(self):
        receipt, reads = self.records["receipt"], self.records["reads"]
        fields = receipt["fields"]
        members = receipt["versions"][("read_versions",)][2]
        if (set(fields) != {(name,) for name in ("status", "operation_id", "operation_digest", "activity_id", "effect_id", "commit_seq")}
                or receipt["sha256"] != self.header[4] or fields.get(("status",)) != "committed"
                or fields.get(("operation_id",)) != self.history[0]
                or fields.get(("operation_digest",)) != self.header[3]
                or reads["versions"][()][:2] != receipt["versions"][("read_versions",)][:2]
                or members.get(self.target.token) != 0
                or receipt["versions"][("write_versions",)][2].get(self.target.token) != 1
                or any(members.get(key, 0) < 1 for key in self.selected[1:])):
            return False
        return True

    def close(self):
        if self.column is not None:
            self.column.close()
            self.column = None
        if self.control is not None:
            self.control.close()
            self.control = None


class GrowthBirthMetadataTaskV1:
    def __init__(self, task):
        self.task, self.owner = task, task.owner
        selector = task.selector
        key = AtomKey.from_token(selector[1])
        if NamespaceId.from_key(key) != task.owner.namespace:
            raise AuthorityUnavailable("Birth metadata selector crossed actual namespace")
        if selector[0] == "birth":
            from .persona_growth_review_owner_read_v1 import is_growth_owner_read_v1
            if is_growth_owner_read_v1(task.owner) and key.token not in task.owner.request.refs:
                raise AuthorityUnavailable("Owner birth metadata target was not explicitly selected")
            target_domain_v1(key)
            self.reader = _BirthReadV1(task, key)
        else:
            if type(selector[2]) is not int or selector[2] < 0:
                raise AuthorityUnavailable("Birth control has another exact revision selector")
            if selector[2] != 0:
                raise AuthorityUnavailable("Historical birth controls require the fixed revision-one proof recipe")
            if key.type_name == "d01.persona_plan.v1":
                from .persona_growth_review_metadata_v1 import _tasks_v1
                activation = _tasks_v1(task.owner).get(("control", _activation_key(task.owner.namespace).token, 0))
                if activation is None or not activation.complete or activation.row is None or activation.row["value"]["plan_id"] != key.name:
                    raise AuthorityUnavailable("PersonaPlan metadata was not selected by actual current activation")
            self.reader = _ControlReadV1(task, key, selector[2])

    def advance(self, meter):
        self.reader.advance(meter)
        self.task.complete, self.task.row = self.reader.complete, self.reader.result

    def retained_heap_v1(self):
        from .dispatch_current_inventory_v3 import _heap
        from sys import getsizeof
        reader = self.reader
        return getsizeof(reader) + getsizeof(reader.__dict__) + _heap((reader.result,
            getattr(reader, "records", None), reader.header, getattr(reader, "history", None)))

    def close(self):
        self.reader.close()


def _control_metadata_v1(db, key, revision=0):
    from .persona_growth_review_metadata_v1 import read_growth_review_metadata_v1
    return read_growth_review_metadata_v1(db, ("control", key.token, revision))


def current_persona_birth_control_v1(db, *, namespace):
    from .persona_growth_review_metadata_v1 import _owner_v1
    owner, _ = _owner_v1(db)
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner) is BackgroundReadWorkV3:
        require_actual_background_attachment_owner_v3(owner,db=db)
        binding=owner.owner
    else:binding=owner.owner_binding
    if namespace != owner.namespace or owner.owner_guard is None or binding is None:
        raise AuthorityUnavailable("Birth metadata requires its actual current signed Owner Source Work")
    activation = _control_metadata_v1(db, _activation_key(namespace))
    grant = _control_metadata_v1(db, owner_grant_key(*namespace.as_tuple))
    if activation is None or grant is None:
        raise AuthorityUnavailable("Birth metadata lacks actual current activation/Owner control")
    value, authority = activation["value"], grant["value"]
    guard = owner.owner_guard
    if (value["owner_grant_id"] != authority["grant_id"]
            or value["owner_grant_revision"] != grant["version"].revision
            or value["graph_incarnation"] != authority["graph_incarnation"]
            or value["activation_generation"] != authority["activation_generation"]
            or value["authorization_revision"] != guard.authorization_revision
            or guard.namespace != namespace or guard.pending_revoke_operation_id is not None
            or guard.minimum_revocation_revision or guard.minimum_revocation_epoch
            or authority["authority_id"] != guard.authority_id
            or authority["installation_id"] != guard.installation_id
            or grant["version"].revision != binding.grant_revision
            or grant["digest"] != binding.grant_digest.removeprefix("sha256:")):
        raise AuthorityUnavailable("Birth current control differs from actual independent Owner EOF")
    key = AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_plan.v1", value["plan_id"])
    plan = _control_metadata_v1(db, key)
    if (plan is None or plan["value"]["version"] != value["plan_version"]
            or value["head_id"] != plan["value"]["plan_id"] + "@" + str(plan["value"]["version"])):
        raise AuthorityUnavailable("Birth activation has no exact actual PersonaPlan identity/version join")
    return PersonaBirthControlV1(namespace, activation["version"], plan["version"], grant["version"],
        value["head_id"], value["plan_version"], value["graph_incarnation"], value)


def augment_persona_birth_plan_v1(db, *, namespace, operation_kind, plan):
    if operation_kind not in PERSONA_CONTROL_CAPTURE_OPERATIONS_V1:
        return plan
    current_persona_birth_control_v1(db, namespace=namespace)
    # Both exact control GraphVersions are added by the existing privately
    # registered metadata CAS composer. No semantic Body key is added here.
    return plan


def require_persona_birth_frame_v1(db, frame):
    if frame.envelope.identity.phase not in PERSONA_CONTROL_CAPTURE_OPERATIONS_V1:
        return
    current = current_persona_birth_control_v1(db, namespace=frame.envelope.authority.namespace)
    required = {current.activation_version, current.persona_head_version, current.owner_grant_version}
    if not required <= set(frame.envelope.version_guard.read_versions):
        raise AuthorityUnavailable("First-create frame lost its exact actual persona metadata CAS join")


def persona_birth_status_v1(db, *, namespace, target_key, current=None):
    from .persona_growth_review_metadata_v1 import read_growth_review_metadata_v1
    if NamespaceId.from_key(target_key) != namespace:
        raise AuthorityUnavailable("Birth target crossed current namespace")
    target_domain_v1(target_key)
    current = current_persona_birth_control_v1(db, namespace=namespace) if current is None else current
    proof = read_growth_review_metadata_v1(db, ("birth", target_key.token))
    if proof is None:
        return "baseline_unknown"
    if (proof.activation == current.activation_version
            and proof.persona_head == current.persona_head_version
            and proof.owner_grant == current.owner_grant_version
            and proof.head_id == current.head_id and proof.semantic_version == current.semantic_version
            and proof.graph_incarnation == current.graph_incarnation):
        return "birth_current"
    return "birth_stale"
