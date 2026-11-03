"""Metadata EOF for actual growth and current head CAS, private to one Work.

The outbox primary key supplies the complete namespace/dedupe keyset. The
selector visits one scalar row per quantum and retains only the latest actual
adoption. It reads no persona claim or historical stage body.
"""
from dataclasses import dataclass
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .persona_growth_review_contract_v1 import GROWTH_EVENTS_V1, REVIEW_OPERATIONS_V1


@dataclass(frozen=True, slots=True)
class GrowthMetadataEOFLatestV1:
    namespace: NamespaceId
    graph_epoch: int
    row_count: int
    census_digest: str
    latest: tuple[str, str, str, int] | None
    schema: str = "sylanne.growth-metadata-eof.v1"


def _owner_v1(db):
    from .domain_background_read_v3 import _active_v3
    from .current_method_learning_read_v3 import _method_active
    background = _active_v3(db)
    method = _method_active(db)
    if background is not None and method is not None:
        raise AuthorityUnavailable("growth metadata has two unrelated active Work owners")
    owner = background if background is not None else method
    if owner is None or owner.db is not db:
        raise AuthorityUnavailable("growth metadata requires the actual installed Source Work")
    return owner, background is not None


def _current_v1(owner, meter=None):
    if hasattr(owner, "require_data_current_v3"):
        owner.require_data_current_v3(meter)
    else:
        owner.require_current(meter=meter)


def _tasks_v1(owner):
    tasks = getattr(owner, "growth_review_metadata_v1", None)
    if tasks is None:
        tasks = {}
        owner.growth_review_metadata_v1 = tasks
    return tasks


class GrowthReviewMetadataTaskV1:
    def __init__(self, owner, selector):
        self.owner, self.selector = owner, selector
        self.after = self.pending = self.latest = self.row = None
        self.complete = False
        self.phase = "scan"
        self.growth_activation_versions = ()
        self._decode_peak_active = False
        self.special = None
        self.row_count = 0
        self.census_digest = canonical_digest(("growth-metadata-eof.v1", owner.namespace, owner.graph_stamp))
        if selector[0] in {"control", "birth"}:
            from .persona_growth_birth_v1 import GrowthBirthMetadataTaskV1
            self.special = GrowthBirthMetadataTaskV1(self)
        elif selector[0] == "head":
            key = AtomKey.from_token(selector[1])
            if NamespaceId.from_key(key) != owner.namespace:
                raise AuthorityUnavailable("growth head metadata crossed namespace")
        elif selector[0] == "producer":
            key = AtomKey.from_token(selector[1])
            if NamespaceId.from_key(key) != owner.namespace or type(selector[2]) is not int or selector[2] < 1:
                raise AuthorityUnavailable("growth target producer crossed namespace/version")
        elif selector != ("latest",):
            raise AuthorityUnavailable("unregistered growth metadata selector")

    def _runtime_retained_heap_bytes_v3(self):
        from .dispatch_current_inventory_v3 import _heap
        from sys import getsizeof
        value = self.row
        if type(value) is GrowthMetadataEOFLatestV1:
            value = (value.namespace.as_tuple, value.graph_epoch, value.row_count,
                value.census_digest, value.latest, value.schema)
        return (0 if self.special is None else self.special.retained_heap_v1()) + getsizeof(self) + getsizeof(self.__dict__) + _heap((
            self.selector, self.after, self.pending, self.latest, value,
            getattr(self, "original", None), self.census_digest, self.row_count, self.phase,
            self.growth_activation_versions))

    def advance(self, meter):
        try:
            self._advance_v1(meter)
        finally:
            if self._decode_peak_active:
                self.owner.operation.finish_retained_state_growth_v3(self)
                self._decode_peak_active = False

    def _fixed_metadata_row_v1(self, meter, table, columns, where, parameters):
        # Observe fixed scalar lengths before Python receives the row. Payload
        # transfer still uses the real reserved native meter. The one current
        # decode peak is released after this quantum; discarded census rows
        # never accumulate in operation.retain().
        from .c09_paged_sql_v2 import _quote
        lengths = self.owner.db.execute("SELECT " + ",".join(
            "length(CAST(" + _quote(column) + " AS BLOB))" for column in columns)
            + " FROM " + _quote(table) + " WHERE " + where + " LIMIT 1", parameters).fetchone()
        if lengths is None:
            # EOF/head-absence still creates a control observation and updates
            # retained task state; use the existing decoder control overhead.
            self.owner.operation.reserve_retained_state_growth_v3(self, 4096)
            self._decode_peak_active = True
            return None
        amount = sum(size or 0 for size in lengths)
        meter.require_available(amount + 256)
        peak = amount * 8 + 4096
        if peak > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable("growth metadata row requires its registered fragment decoder")
        self.owner.operation.reserve_retained_state_growth_v3(self, peak)
        self._decode_peak_active = True
        return meter.read_fixed_row(self.owner.db, table, columns, where, parameters)

    def _advance_v1(self, meter):
        owner = self.owner
        _current_v1(owner, meter)
        if self.special is not None:
            self.special.advance(meter)
            return
        ns = owner.namespace
        if self.selector[0] == "head":
            token = self.selector[1]
            self.row = self._fixed_metadata_row_v1(meter, "graph_atoms",
                ("revision", "valid", "type_name"), "bot=? AND persona=? AND token=?",
                (*ns.as_tuple, token))
            self.complete = True
            return
        if self.selector[0] == "producer":
            row = self._fixed_metadata_row_v1(meter, "graph_history",
                ("event_id", "event_bot", "event_persona", "valid"), "token=? AND revision=?",
                (self.selector[1], self.selector[2]))
            if row is None or row[1:3] != ns.as_tuple or row[3] != 1:
                raise AuthorityUnavailable("growth target lost its actual current producing history")
            self.row = row[0]
            self.complete = True
            return
        if self.phase == "scan":
            where, args = "bot=? AND persona=?", ns.as_tuple
            if self.after is not None:
                where += " AND dedupe_key>?"
                args = (*args, self.after)
            row = self._fixed_metadata_row_v1(meter, "graph_domain_production_outbox_v1",
                ("dedupe_key", "causal_operation_id", "receiver_domain", "event_kind", "original_ref", "original_digest", "state"),
                where + " ORDER BY dedupe_key", args)
            if row is None:
                self.row = GrowthMetadataEOFLatestV1(ns, owner.graph_stamp[1].revision,
                    self.row_count, self.census_digest, self.latest)
                self.complete = True
                return
            self.after = row[0]
            self.row_count += 1
            self.census_digest = canonical_digest((self.census_digest, row[:6]))
            # The paired D10 event shares this causal adoption. Select D08 once.
            if row[2:4] == ("d08", GROWTH_EVENTS_V1["d08"]):
                if row[6] == "retired":
                    raise AuthorityUnavailable("growth lineage was retired by the actual C09 barrier")
                self.pending = row
                self.phase = "original"
            return
        if self.phase == "original":
            row = self._fixed_metadata_row_v1(meter, "graph_domain_production_originals_v1",
                ("domain", "operation_kind", "original_digest", "bundle_digest"),
                "bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, self.pending[1]))
            if (row is None or row[:2] not in {
                    ("d01", "adopt_growth"), ("d01", "adopt_general_growth_v1")}
                    or row[2] != self.pending[5]
                    or self.pending[4] != "d01-current:" + row[2][:48]):
                raise AuthorityUnavailable("growth lineage was erased or changed its actual adopted original")
            self.original = row
            self.phase = "ledger"
            return
        row = self._fixed_metadata_row_v1(meter, "graph_bundle_operations",
            ("digest", "commit_seq"), "bot=? AND persona=? AND operation_id=?",
            (*ns.as_tuple, self.pending[1]))
        if row is None or row[0] != self.original[3]:
            raise AuthorityUnavailable("growth metadata lost its actual committed bundle ledger")
        candidate = (self.pending[1], self.pending[4], self.pending[5], row[1])
        if self.latest is None or candidate[3] > self.latest[3]:
            self.latest = candidate
        elif candidate[3] == self.latest[3] and candidate != self.latest:
            raise AuthorityUnavailable("two growth originals claim the same actual commit sequence")
        self.pending = None
        self.original = None
        self.phase = "scan"

    def require_for_v1(self, owner):
        if (owner is not self.owner or _tasks_v1(owner).get(self.selector) is not self
                or not self.complete):
            raise AuthorityUnavailable("growth metadata lacks this Work's complete namespace EOF")
        _current_v1(owner)
        return self.row


def start_growth_review_metadata_v1(owner, selector):
    tasks = _tasks_v1(owner)
    task = tasks.get(selector)
    if task is None:
        task = GrowthReviewMetadataTaskV1(owner, selector)
        owner.operation.register_retained_state_v3(task)
        tasks[selector] = task
    return task


def read_growth_review_metadata_v1(db, selector):
    owner, background = _owner_v1(db)
    task = _tasks_v1(owner).get(selector)
    if task is None or not task.complete:
        if background:
            from .domain_background_read_v3 import BackgroundReadNeededV3
            if owner.sealed:
                raise AuthorityUnavailable("growth metadata was not prepared before the Source Work sealed")
            raise BackgroundReadNeededV3(("growth_review_metadata_v1", selector))
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(owner, ("growth_review_metadata_v1", selector))
    with runtime_storage_quantum_v3(db) as meter:
        _current_v1(owner, meter)
        return task.require_for_v1(owner)


def growth_metadata_head_v1(db, namespace, key):
    if type(key) is str:
        key = AtomKey.from_token(key)
    owner, _ = _owner_v1(db)
    if owner.namespace != namespace or NamespaceId.from_key(key) != namespace:
        raise AuthorityUnavailable("growth metadata head crossed the current Work namespace")
    row = read_growth_review_metadata_v1(db, ("head", key.token))
    if row is not None and row[2] != key.type_name:
        raise AuthorityUnavailable("growth metadata head type changed")
    return GraphVersion(key, 0 if row is None else row[0]), bool(row is not None and row[1])


def growth_metadata_cas_versions_v1(db):
    owner, _ = _owner_v1(db)
    versions = []
    for selector, task in _tasks_v1(owner).items():
        if selector[0] == "control" and selector[2] == 0:
            row = task.require_for_v1(owner)
            if row is not None:
                versions.append(row["version"])
            continue
        if selector[0] != "head":
            continue
        row = task.require_for_v1(owner)
        versions.append(GraphVersion(AtomKey.from_token(selector[1]), 0 if row is None else row[0]))
    return tuple(sorted(versions, key=lambda version: version.key.token))


def growth_review_metadata_heap_v1(owner):
    from .dispatch_current_inventory_v3 import _heap
    tasks = getattr(owner, "growth_review_metadata_v1", {})
    return sum(_heap((task.selector, task.after, task.pending, task.latest, task.row,
        getattr(task, "original", None))) for task in tasks.values())


def release_growth_review_metadata_v1(owner):
    tasks = getattr(owner, "growth_review_metadata_v1", None)
    if tasks is not None:
        for task in tasks.values():
            if task.special is not None:
                task.special.close()
            owner.operation.unregister_retained_state_v3(task)
        tasks.clear()


_ORIGINAL_CONTROL_COLUMNS_V1 = ("domain", "operation_kind", "original_digest",
    "read_versions_json", "bundle_digest", "receipt_json", "receipt_digest")


def _original_allowed_v1(owner, operation_id):
    from .d01_single_event_review_case_v1 import case_original_control_allowed_v1
    if case_original_control_allowed_v1(owner,operation_id):return True
    tasks = _tasks_v1(owner)
    latest = tasks.get(("latest",))
    allowed = bool(latest is not None and latest.complete and latest.row.latest is not None
        and latest.row.latest[0] == operation_id)
    return allowed or any(task.complete and selector[0] == "producer" and task.row == operation_id
        for selector, task in tasks.items())


def require_growth_original_metadata_point_v1(owner, request):
    if request[:3] != ("graph_domain_production_originals_v1", _ORIGINAL_CONTROL_COLUMNS_V1,
            ("bot", "persona", "operation_id")):
        return False
    if request[3][:2] != owner.namespace.as_tuple or not _original_allowed_v1(owner, request[3][2]):
        raise AuthorityUnavailable("growth original metadata has no actual EOF/target-producer selector")
    return True


def growth_original_control_v1(db, operation_id):
    """Metadata columns only; no request/body or D01 claim is decoded here."""
    owner, background = _owner_v1(db)
    from .persona_growth_review_owner_read_v1 import is_growth_owner_read_v1, growth_owner_original_control_v1
    if is_growth_owner_read_v1(owner):
        return growth_owner_original_control_v1(owner, operation_id)
    if not _original_allowed_v1(owner, operation_id):
        raise AuthorityUnavailable("growth original control was not selected by this actual Work")
    request = ("graph_domain_production_originals_v1", _ORIGINAL_CONTROL_COLUMNS_V1,
        ("bot", "persona", "operation_id"), (*owner.namespace.as_tuple, operation_id))
    if background:
        from .domain_background_read_v3 import background_point_v3
        row = background_point_v3(db, table=request[0], columns=request[1],
            key_columns=request[2], key=request[3], legacy_reader=lambda: None)
    else:
        from .current_method_learning_read_v3 import _need_method_input
        point = owner.points.get(request)
        if point is None or not point.complete:
            _need_method_input(owner, ("point", request))
        with runtime_storage_quantum_v3(db) as meter:
            _current_v1(owner, meter)
            row = point.require_row_v3(meter)
    if row is None:
        raise AuthorityUnavailable("growth or target lineage was erased; currentness is unknown")
    from .domain_background_read_v3 import background_json_loads_v3
    from .domain_production_originals_v1 import _receipt
    receipt = _receipt(background_json_loads_v3(row[5]))
    reads = tuple(GraphVersion(AtomKey.from_token(ref), revision)
        for ref, revision in background_json_loads_v3(row[3]))
    if (receipt.status != "committed" or receipt.operation_id != operation_id
            or receipt.operation_digest != row[4] or canonical_digest(receipt) != row[6]
            or any(NamespaceId.from_key(version.key) != owner.namespace for version in reads)):
        raise AuthorityUnavailable("growth original control changed actual adopted receipt/read metadata")
    result = {"domain": row[0], "operation_kind": row[1], "original_digest": row[2],
        "read_versions": reads, "receipt": receipt}
    latest = _tasks_v1(owner).get(("latest",))
    if latest is not None and latest.complete and latest.row.latest is not None and latest.row.latest[0] == operation_id:
        if ((row[0], row[1]) not in {("d01", "adopt_growth"), ("d01", "adopt_general_growth_v1")}
                or latest.row.latest[2] != row[2] or latest.row.latest[3] != receipt.commit_seq):
            raise AuthorityUnavailable("growth historical activation lacks its actual adopted EOF/receipt")
        versions = tuple((version.key.token, version.revision) for version in receipt.write_versions
            if version.key.type_name == "d01.persona_activation.v1")
        if len(versions) != 1:
            raise AuthorityUnavailable("growth requires one actual adopted activation control")
        if latest.growth_activation_versions != versions:
            owner.operation.reserve_retained_state_growth_v3(latest, 8192)
            try:
                latest.growth_activation_versions = versions
            finally:
                owner.operation.finish_retained_state_growth_v3(latest)
    return result


def growth_target_control_v1(db, target):
    operation = read_growth_review_metadata_v1(db, ("producer", target.key.token, target.revision))
    original = growth_original_control_v1(db, operation)
    if target not in original["receipt"].write_versions:
        raise AuthorityUnavailable("growth target has no actual typed producing receipt member")
    return original


def require_growth_control_metadata_point_v1(owner, request):
    """Allow only the exact activation/review controls for a selected recipe."""
    if request[:3] == ("graph_history", ("event_id", "value", "valid"), ("token", "revision")):
        latest = _tasks_v1(owner).get(("latest",))
        return bool(latest is not None and latest.complete
            and request[3] in latest.growth_activation_versions)
    if request[:3] != ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona")):
        return False
    key = AtomKey.from_token(request[3][0])
    if request[3][1:] != owner.namespace.as_tuple or NamespaceId.from_key(key) != owner.namespace:
        return False
    from .persona_growth_review_contract_v1 import REVIEW_TYPES_V1, TARGET_TYPES_V1, growth_review_key_v1
    from .persona_growth_review_v1 import NEW_WORK_OPERATIONS_V1
    operation = getattr(owner, "operation_kind", None)
    if operation not in NEW_WORK_OPERATIONS_V1 | REVIEW_OPERATIONS_V1:
        return False
    if key.type_name == "d01.persona_activation.v1":
        from ..domains.d01 import _activation_key
        return key == _activation_key(owner.namespace)
    if key.type_name not in REVIEW_TYPES_V1.values():
        return False
    kinds = {kind for values in TARGET_TYPES_V1.values() for kind in values}
    return any(selector[0] == "head" and task.complete
        and AtomKey.from_token(selector[1]).type_name in kinds
        and growth_review_key_v1(owner.namespace, selector[1]) == key
        for selector, task in _tasks_v1(owner).items())


def growth_adoption_activation_control_v1(db, original):
    """Read only the exact historical activation written by the adopted growth.

    A historical Owner grant revision alone cannot establish graph incarnation.
    The actual receipt and immutable activation control supply that identity;
    no persona plan or private semantic growth body is read.
    """
    owner, background = _owner_v1(db)
    latest = _tasks_v1(owner).get(("latest",))
    if (latest is None or not latest.complete or latest.row.latest is None
            or latest.row.latest[0] != original["receipt"].operation_id
            or len(latest.growth_activation_versions) != 1):
        raise AuthorityUnavailable("growth activation history lacks its exact current EOF producer")
    token, revision = latest.growth_activation_versions[0]
    key = AtomKey.from_token(token)
    if key.type_name != "d01.persona_activation.v1" or NamespaceId.from_key(key) != owner.namespace:
        raise AuthorityUnavailable("growth activation historical control crossed namespace/type")
    request = ("graph_history", ("event_id", "value", "valid"),
        ("token", "revision"), (token, revision))
    if background:
        from .domain_background_read_v3 import background_point_v3
        row = background_point_v3(db, table=request[0], columns=request[1],
            key_columns=request[2], key=request[3], legacy_reader=lambda: None)
    else:
        from .current_method_learning_read_v3 import _need_method_input
        point = owner.points.get(request)
        if point is None or not point.complete:
            _need_method_input(owner, ("point", request))
        with runtime_storage_quantum_v3(db) as meter:
            _current_v1(owner, meter)
            row = point.require_row_v3(meter)
    if row is None or row[0] != original["receipt"].operation_id or row[2] != 1:
        raise AuthorityUnavailable("growth activation history was erased or lost its actual producing member")
    from .domain_background_read_v3 import background_json_loads_v3
    from ..domains.d01 import _validate_persona_activation
    value = background_json_loads_v3(row[1])
    _validate_persona_activation(value)
    if value["namespace"] != {"bot_id": owner.namespace.bot_id, "persona_id": owner.namespace.persona_id}:
        raise AuthorityUnavailable("growth activation historical control crossed its actual namespace")
    return value
