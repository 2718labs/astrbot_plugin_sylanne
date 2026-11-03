"""Closed finite bootstrap for the independent Natural original READ Work.

Only fixed headers are read before the actual message job supplies J. This
bootstrap issues no Source grant, P2 identity, fresh deadline or business job.
"""
from datetime import datetime
import math
from time import monotonic

from ..authority_service.contract import AuthorityUnavailable
from ..graph_worker import require_graph_storage_work_admission_v3
from ..runtime_storage_v3 import (
    runtime_storage_v3, begin_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, _runtime_bounded_fixed_row_v3,
)
from .first_ingress_v2 import trusted_upper_at_v4
from .jobs import _utc

_JOB_COLUMNS_V1 = (
    "job_id", "operation_id", "activity_id", "effect_id", "bot_id", "persona_id",
    "snapshot_ref", "phase", "work_kind", "deadline_utc", "budget_ref", "resource_ref",
    "fence", "cancel_epoch", "lease_holder", "lease_expires_utc", "result_ref",
)
_BUNDLE_COLUMNS_V1 = ("digest", "activity_id", "effect_id", "commit_seq")


class _NaturalInitialBootstrapV1:
    def __init__(self, graph, authority, lease, operation_id):
        require_graph_storage_work_admission_v3(graph)
        graph._authorize(lease, authority, frozenset({"d08", "d09", "d11"}))
        self.graph, self.authority, self.lease = graph, authority, lease
        self.namespace, self.selected_operation_id = authority.namespace, operation_id
        self.store = graph._GraphCoordinator__store
        self.db = self.store._db
        self.storage = runtime_storage_v3(self.db)
        if self.storage is None or self.storage.purpose != "business":
            raise AuthorityUnavailable("Natural initial READ requires its actual selected runtime storage")
        port = graph._GraphCoordinator__content_fence_v2
        policy = graph._GraphCoordinator__dispatch_clock_policy
        self.clock = port.read_ingress_clock(policy)
        from ..host.v2_fence_port import VerifiedIngressClockV2
        if type(self.clock) is not VerifiedIngressClockV2 or self.clock.sample.source_id != policy.source_id:
            raise AuthorityUnavailable("Natural initial READ requires the actual installed paired clock")
        self.sample = monotonic()
        self.initial_upper = trusted_upper_at_v4(self.clock, self.sample)
        self.fence = self.operation = None
        self.work = None
        self.finished = False
        self.operation_id = "natural-initial-read:" + operation_id
        try:
            # The existing READ entry meters its fixed Graph stamp internally;
            # all Root RPCs occur outside both the local quantum and Graph lock.
            self.fence = graph._begin_read_fence_v3(authority, operation_id=self.operation_id)
            self.graph_stamp = (self.fence.metadata, self.fence.epoch)
            with self.store._lock, self.storage.quantum() as meter:
                if self.db.in_transaction:
                    raise AuthorityUnavailable("Natural initial bootstrap cannot inherit a transaction")
                self.db.execute("BEGIN")
                try:
                    if graph._v2_graph_stamp(self.namespace) != self.graph_stamp:
                        raise AuthorityUnavailable("Natural initial bootstrap Graph stamp changed")
                    self.bundle_header = _runtime_bounded_fixed_row_v3(
                        self.db, meter, "graph_bundle_operations", _BUNDLE_COLUMNS_V1,
                        "bot=? AND persona=? AND operation_id=?",
                        (*self.namespace.as_tuple, operation_id))
                    if self.bundle_header is None:
                        raise AuthorityUnavailable("actual committed Natural bundle header is absent")
                    self.selected_activity_id, self.selected_effect_id = self.bundle_header[1:3]
                    where = ("bot_id=? AND persona_id=? AND operation_id=? AND activity_id=? "
                             "AND effect_id=? AND work_kind='message'")
                    args = (*self.namespace.as_tuple, operation_id,
                            self.selected_activity_id, self.selected_effect_id)
                    self.job_header = _runtime_bounded_fixed_row_v3(
                        self.db, meter, "runtime_jobs", _JOB_COLUMNS_V1,
                        where + " ORDER BY job_id", args)
                    if self.job_header is None:
                        raise AuthorityUnavailable("actual final Natural message job is absent")
                    other = _runtime_bounded_fixed_row_v3(
                        self.db, meter, "runtime_jobs", ("job_id",),
                        where + " AND job_id<>? ORDER BY job_id", (*args, self.job_header[0]))
                    if other is not None:
                        raise AuthorityUnavailable("actual final Natural message job is ambiguous")
                    self._require_waiting_job_v1(self.job_header)
                    _utc(self.job_header[9], "deadline_utc")
                    self.job_deadline = datetime.fromisoformat(
                        self.job_header[9].replace("Z", "+00:00")).timestamp()
                    if not math.isfinite(self.job_deadline):
                        raise AuthorityUnavailable("actual final message deadline is not finite")
                    self.bundle_lengths = self._fixed_lengths_v1(meter,
                        "graph_bundle_operations", _BUNDLE_COLUMNS_V1,
                        "bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, operation_id))
                    self.job_lengths = self._fixed_lengths_v1(meter,
                        "runtime_jobs", _JOB_COLUMNS_V1, "job_id=?", (self.job_header[0],))
                    from ..graph_types import owner_grant_key
                    self.owner_key = owner_grant_key(*self.namespace.as_tuple)
                    self.owner_header = _runtime_bounded_fixed_row_v3(self.db, meter, "graph_atoms",
                        ("revision", "valid", "value_cell_id"), "bot=? AND persona=? AND token=?",
                        (*self.namespace.as_tuple, self.owner_key.token))
                    if self.owner_header is None or self.owner_header[1] != 1:
                        raise AuthorityUnavailable("Natural initial READ has no current local Owner head")
                    self.authority_epochs = _runtime_bounded_fixed_row_v3(self.db, meter,
                        "graph_authority_epochs", ("access_epoch", "delete_epoch"),
                        "bot=? AND persona=?", self.namespace.as_tuple)
                    if self.authority_epochs is None:
                        raise AuthorityUnavailable("Natural initial Source authority epochs are absent")
                finally:
                    self.db.rollback()
            self.deadline = self.job_deadline
            self.monotonic_limit = self.sample + (self.deadline - self.initial_upper)
            self.require_time_v1()
            graph._validate_read_fence_v3(self.fence)
            self.operation = begin_runtime_storage_operation_v3(
                self.db, self.operation_id, self.deadline)
            # Own the pinned fixed tuples and one replacement decode peak.
            # Per-advance comparisons reuse this reserved space; they do not
            # accumulate a retained-allocation debt for discarded query rows.
            self.operation.retain(65536 + 16 * sum(
                (size or 0) for sizes in (self.bundle_lengths, self.job_lengths) for size in sizes))
        except BaseException:
            try:
                if self.fence is not None:
                    graph._finish_read_fence_v3(self.fence)
            finally:
                finish_runtime_storage_operation_v3(self.operation)
            raise

    @staticmethod
    def _require_waiting_job_v1(header):
        if (header[7] != "waiting" or header[8] != "message"
                or header[12:14] != (0, 0) or any(v is not None for v in header[14:])):
            raise AuthorityUnavailable("actual final message job is cancelled, stale or already consumed")

    def require_time_v1(self):
        now = monotonic()
        upper = trusted_upper_at_v4(self.clock, now)
        if now >= self.monotonic_limit or upper >= self.deadline:
            raise AuthorityUnavailable("Natural initial READ exceeded its original final deadline")
        return upper

    def tighten_to_metadata_v1(self, original):
        if type(original) is not _NaturalInitialLocatorMetadataV1:
            raise AuthorityUnavailable("actual complete initial locator metadata required")
        metadata = original.require_for_v1(self)
        self._tighten_utc_v1(metadata["original_utc_deadline"])

    def tighten_to_admission_v1(self, actual_admission):
        from .dispatch_admission import DispatchAdmissionReceiptV1, namespace_of
        if (type(actual_admission) is not DispatchAdmissionReceiptV1
                or namespace_of(actual_admission.admission) != self.namespace
                or (actual_admission.admission.operation_id,
                    actual_admission.admission.activity_id, actual_admission.admission.effect_id)
                    != (self.selected_operation_id, self.selected_activity_id, self.selected_effect_id)):
            raise AuthorityUnavailable("Natural initial deadline lacks its actual original admission")
        self._tighten_utc_v1(actual_admission.admission.utc_deadline)

    def _tighten_utc_v1(self, deadline_utc):
        _utc(deadline_utc, "deadline_utc")
        value = datetime.fromisoformat(deadline_utc.replace("Z", "+00:00")).timestamp()
        if value > self.deadline:
            raise AuthorityUnavailable("Natural initial admission exceeds its original message job bound")
        self.monotonic_limit -= self.deadline - value
        self.deadline = value
        self.operation.deadline_utc = value
        if self.work is not None:
            self.work.deadline_utc = value
        self.require_time_v1()

    def _fixed_lengths_v1(self, meter, table, columns, where, args):
        from .c09_paged_sql_v2 import _quote
        meter.charge_read(8 * len(columns))
        return self.db.execute("SELECT " + ",".join(
            "length(CAST(" + _quote(name) + " AS BLOB))" for name in columns)
            + " FROM " + _quote(table) + " WHERE " + where + " LIMIT 1", args).fetchone()

    def _require_header_v1(self, meter, table, columns, where, args, lengths, expected):
        actual_lengths = self._fixed_lengths_v1(meter, table, columns, where, args)
        if actual_lengths != lengths:
            raise AuthorityUnavailable("Natural initial pinned fixed header lengths changed")
        meter.require_available(sum(size or 0 for size in lengths) + 256)
        value = meter.read_fixed_row(self.db, table, columns, where, args)
        if value != expected:
            raise AuthorityUnavailable("Natural initial pinned fixed header changed")

    def require_fixed_headers_v1(self, meter):
        self.require_time_v1()
        if (not self.store._lock._is_owned() or not self.db.in_transaction
                or self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp):
            raise AuthorityUnavailable("Natural initial READ lost its actual pinned snapshot")
        self._require_header_v1(meter, "graph_bundle_operations", _BUNDLE_COLUMNS_V1,
            "bot=? AND persona=? AND operation_id=?",
            (*self.namespace.as_tuple, self.selected_operation_id), self.bundle_lengths, self.bundle_header)
        self._require_header_v1(meter, "runtime_jobs", _JOB_COLUMNS_V1,
            "job_id=?", (self.job_header[0],), self.job_lengths, self.job_header)


from weakref import WeakKeyDictionary
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .natural_dispatch_locator_metadata_v1 import (
    NaturalDispatchLocatorMetadataColumnV1, _FIELD_V1, _OBJECT_FIELDS_V1,
    _META_KEYS_V1, _RECIPE_KEYS_V1,
)
_INITIAL_METADATA_V1 = WeakKeyDictionary()



_INITIAL_METADATA_ISSUER_V1 = object()


class _NaturalInitialLocatorMetadataV1:
    """Whole receipt EOF + exact metadata; still no permission to read Body."""
    def __init__(self, issuer, task):
        if (issuer is not _INITIAL_METADATA_ISSUER_V1
                or type(task) is not _NaturalInitialLocatorReadV1
                or task.phase != "complete_metadata" or not task.column.complete
                or not task.stream.complete):
            raise AuthorityUnavailable("actual complete initial metadata producer required")
        self.owner, self.bootstrap = task.owner, task.owner.bootstrap
        self.column, self.metadata = task.column, task.raw["metadata"]
        self.receipt_sha256, self.receipt_byte_count = task.column.sha256, task.column.byte_count
        _INITIAL_METADATA_V1[self] = (self.owner, self.bootstrap, self.column, self.metadata,
            self.receipt_sha256, self.receipt_byte_count)

    def require_for_v1(self, bootstrap):
        if (_INITIAL_METADATA_V1.get(self) != (self.owner, self.bootstrap, self.column, self.metadata,
                self.receipt_sha256, self.receipt_byte_count)
                or self.bootstrap is not bootstrap or self.owner.operation is not bootstrap.operation
                or bootstrap.operation.closed or not self.column.complete):
            raise AuthorityUnavailable("actual same-Work initial metadata EOF required")
        bootstrap.require_time_v1()
        return self.metadata

    def release_payload_v3(self):
        _INITIAL_METADATA_V1.pop(self, None)
        self.owner = self.bootstrap = self.column = self.metadata = None


class _NaturalInitialLocatorReadV1:
    def __init__(self, owner):
        if type(owner) is not _NaturalInitialReadV1:
            raise AuthorityUnavailable("actual independent Natural initial READ required")
        self.owner = owner
        self.column = NaturalDispatchLocatorMetadataColumnV1(owner, owner.selected_operation_id)
        self.phase = "column"
        self.stream = self.raw = self.result = None

    def _fixed_joins_v1(self, meter):
        from .d11_types import runtime_job_key
        owner = self.owner
        bootstrap = owner.bootstrap
        metadata = self.raw["metadata"]
        namespace = {"bot_id":owner.namespace.bot_id, "persona_id":owner.namespace.persona_id}
        if (metadata["schema"] != "sylanne.natural_dispatch_read_locator.v1"
                or type(metadata["profile_version"]) is not int or metadata["profile_version"] != 1
                or metadata["namespace"] != namespace
                or (metadata["operation_id"],metadata["activity_id"],metadata["effect_id"],metadata["bundle_digest"])
                    != (bootstrap.selected_operation_id,bootstrap.selected_activity_id,
                        bootstrap.selected_effect_id,bootstrap.bundle_header[0])
                or metadata["graph_incarnation"] != bootstrap.fence.metadata.requirements.graph_incarnation):
            raise AuthorityUnavailable("Natural initial metadata crossed its actual bundle or namespace")
        job = metadata["final_job"]
        expected_job = dict(zip(_JOB_COLUMNS_V1,bootstrap.job_header,strict=True))
        expected_job = {k:v for k,v in expected_job.items()
                        if k not in ("lease_holder","lease_expires_utc","result_ref")}
        expected_job["job_ref"] = runtime_job_key(owner.namespace.bot_id,owner.namespace.persona_id,
            bootstrap.selected_activity_id,bootstrap.job_header[0]).token
        if job != expected_job:
            raise AuthorityUnavailable("Natural initial locator is not bound to its actual final message job")
        header = _runtime_bounded_fixed_row_v3(owner.db,meter,"graph_dispatch_admissions",
            ("operation_id","effect_id","admission_digest","graph_revision","graph_epoch","receipt_digest"),
            "bot=? AND persona=? AND admission_ref=?",(*owner.namespace.as_tuple,metadata["admission_ref"]))
        if header != (metadata["operation_id"],metadata["effect_id"],metadata["admission_digest"],
                metadata["graph_revision"],metadata["graph_epoch"],metadata["admission_receipt_digest"]):
            raise AuthorityUnavailable("Natural initial locator differs from the actual admission scalar original")
        event = _runtime_bounded_fixed_row_v3(owner.db,meter,"graph_events",("epoch_revision",),
            "bot=? AND persona=? AND session=? AND event_id=?",
            (*owner.namespace.as_tuple,metadata["activity_id"],metadata["operation_id"]))
        if event != (metadata["graph_epoch"],):
            raise AuthorityUnavailable("Natural initial locator has no actual same-commit Graph event")
        recipe = metadata["recipe"]
        if (type(recipe) is not dict or set(recipe) != _RECIPE_KEYS_V1
                or recipe["schema"] != "sylanne.natural_dispatch_read_locator_recipe.v1"
                or recipe["kind"] != "unsealed_producer_metadata_recipe"
                or recipe["namespace"] != namespace
                or recipe["committed_selection"]["operation_id"] != metadata["operation_id"]
                or recipe["committed_selection"]["activity_id"] != metadata["activity_id"]
                or recipe["committed_selection"]["effect_id"] != metadata["effect_id"]
                or recipe["committed_selection"]["admission_ref"] != metadata["admission_ref"]
                or recipe["committed_selection"]["original_utc_deadline"] != metadata["original_utc_deadline"]
                or recipe["admission"]["audience"] != [recipe["plan"]["audience_id"]]):
            raise AuthorityUnavailable("Natural initial locator recipe selectors differ")
        owner.admission_ref = metadata["admission_ref"]
        self.admission_header = header

    def advance(self, meter):
        if self.phase == "column":
            if self.column.advance(meter):
                self.raw = self.column.raw
                if (type(self.raw) is not dict or set(self.raw) != _OBJECT_FIELDS_V1[()]
                        or self.raw["schema"] != "sylanne.natural_dispatch_read_locator.v1"
                        or type(self.raw["profile_version"]) is not int or self.raw["profile_version"] != 1
                        or type(self.raw["metadata"]) is not dict or set(self.raw["metadata"]) != _META_KEYS_V1
                        or type(self.raw["metadata_byte_count"]) is not int or self.raw["metadata_byte_count"] < 1):
                    raise AuthorityUnavailable("Natural initial receipt has no exact versioned metadata profile")
                from .dispatch_admission import _digest
                _digest(self.raw["metadata_sha256"],"locator_metadata_sha256")
                from .owner_material_source_storage_v3 import CanonicalValueStreamV3
                self.stream = CanonicalValueStreamV3(self.raw["metadata"])
                self.phase = "canonical"
        elif self.phase == "canonical":
            self.stream.read_fragment(meter)
            if self.stream.complete:
                if (self.stream.hash.hexdigest(),self.stream.offset) != (
                        self.raw["metadata_sha256"],self.raw["metadata_byte_count"]):
                    raise AuthorityUnavailable("Natural initial complete metadata canonical commitment differs")
                self.phase = "fixed_joins"
        elif self.phase == "fixed_joins":
            self._fixed_joins_v1(meter)
            self.phase = "complete_metadata"
            self.result = _NaturalInitialLocatorMetadataV1(_INITIAL_METADATA_ISSUER_V1,self)
            self.owner.bootstrap.tighten_to_metadata_v1(self.result)
        return self.phase == "complete_metadata"


from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3


class _NaturalInitialAccessColumnV1(DispatchOriginalJSONReadV3):
    """Actual access-control EOF with one owner-shared temporary decode peak."""
    def __init__(self, owner, key, cell_id):
        _require_natural_source_metadata_owner_v1(owner)
        self._payload_retained = 0
        super().__init__(owner,table="graph_atoms",column="value",
            key_columns=("bot","persona","token"),key=(*owner.namespace.as_tuple,key.token),cell_id=cell_id)
        if self.cell.header[1] != key.token:
            raise AuthorityUnavailable("Natural initial access cell crossed its actual key")
        if self.cell.header[0] not in ("canonical-json.ascii.v1","canonical-json.utf8.v1"):
            raise AuthorityUnavailable("Natural initial access has no registered canonical codec")
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=="canonical-json.ascii.v1")

    def _reserve(self,extra=0):
        payload = self._payload_bytes
        if payload > self._payload_retained:
            self.operation.retain(payload-self._payload_retained)
            self._payload_retained = payload
        import sys
        self.owner.reserve_scratch_v1(sys.getsizeof(self.scalar)+sys.getsizeof(self.fragment)+extra+65536)


def _require_natural_source_metadata_owner_v1(owner):
    if type(owner) is _NaturalInitialReadV1:
        return owner
    from .natural_dispatch_p2_read_v1 import _NaturalP2ReadV1
    if type(owner) is not _NaturalP2ReadV1:
        raise AuthorityUnavailable("actual independent initial or P2 metadata reader required")
    owner.require_original_work_v1()
    return owner


class _NaturalInitialSourceNodeV1:
    def __init__(self,owner,ref,*,current_route=False):
        from ..graph_types import AtomKey
        from ..memory_types import source_key
        _require_natural_source_metadata_owner_v1(owner)
        self.owner,self.ref=owner,ref
        self.key=AtomKey.from_token(ref)
        if self.key!=source_key(*owner.namespace.as_tuple,self.key.owner.subject or ""):
            raise AuthorityUnavailable("Natural initial Source crosses its canonical namespace")
        self.original = None if current_route else owner.source_originals.get(ref)
        if self.original is None and not current_route:
            raise AuthorityUnavailable("Natural ancestor is absent from its actual producer locator")
        if current_route and type(owner) is _NaturalInitialReadV1:
            raise AuthorityUnavailable("initial Source traversal cannot acquire a P2 current-route group")
        self.current_route = current_route
        self.phase="inspection";self.inspection=None;self.access_column=None
        self.fragment=b"";self.offset=0;self.result=None

    def advance(self,meter):
        from ..graph_types import GraphAtom
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        from .source_correction_read_v3 import _heap
        owner=self.owner
        if self.phase=="inspection":
            from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3
            inspection_owner=owner if type(owner)is _NaturalInitialReadV1 else owner.parent
            if self.inspection is None:
                self.inspection=InspectionMetadataReadV3(inspection_owner,self.key)
                return False
            self.inspection.advance(meter)
            if not self.inspection.complete:return False
            original=self.inspection.result.require_v3(inspection_owner,meter)
            if self.original is not None and (original.revision,original.cell_id,original.header[2],
                    original.header[3],original.payload_sha256)!=(self.original['version'],self.original['cell_id'],
                    self.original['producer_operation_id'],self.original['byte_count'],self.original['sha256']):
                raise AuthorityUnavailable('Natural Source inspection differs from its exact producer original')
            from .dispatch_current_inventory_v3 import VerifiedDispatchSourceMetadataV3,_ISSUER
            owner.operation.retain(4096+_heap(dict(original.metadata))*2)
            self.result=VerifiedDispatchSourceMetadataV3(_ISSUER,owner,self.key,original.revision,original.valid,
                original.cell_id,original.header,original.payload_sha256,original.metadata)
            owner.sources[self.ref]=self.result
            owner.heads[self.ref]=(original.revision,int(original.valid),original.cell_id)
            self.phase="access_head";return False
        if self.phase=="access_head":
            key=access_key(*owner.namespace.as_tuple,self.key.owner.subject)
            row=_runtime_bounded_fixed_row_v3(owner.db,meter,"graph_atoms",
                ("revision","valid","type_name","value_cell_id"),"bot=? AND persona=? AND token=?",
                (*owner.namespace.as_tuple,key.token))
            if row is None or row[0]<1 or row[1]!=1 or row[2]!="memory.access" or row[3] is None:
                raise AuthorityUnavailable("Natural initial Source actual access is unavailable")
            self.access_key,self.access_head=key,row
            self.access_column=_NaturalInitialAccessColumnV1(owner,key,row[3])
            self.phase="access";return False
        if self.phase=="access":
            if self.access_column.advance(meter):
                value=self.access_column.require_v3(owner)
                owner.operation.retain(1024)
                owner.access[self.ref]=GraphAtom(self.access_key,self.access_head[0],value,True)
                owner.access_originals[self.ref]=self.access_column
                owner.heads[self.access_key.token]=(self.access_head[0],1,self.access_head[3])
                self.access_column=None;self.phase="correction"
            return False
        if self.phase=="correction":
            key=source_correction_head_key(owner.namespace,self.key.owner.subject)
            row=_runtime_bounded_fixed_row_v3(owner.db,meter,"graph_atoms",("revision","valid"),
                "bot=? AND persona=? AND token=?",(*owner.namespace.as_tuple,key.token))
            if row is not None:
                raise AuthorityUnavailable("Natural initial Source was corrected; no authorization revival")
            owner.correction_absences.add(key.token)
            self.phase="complete"
        return self.phase=="complete"


class _NaturalInitialSourcesV1:
    """All declared purpose groups and ancestors, before any business Body."""
    def __init__(self,owner,metadata_original):
        from ..graph_types import AtomKey
        from ..memory_types import source_key
        _require_natural_source_metadata_owner_v1(owner)
        self.owner=owner
        metadata = (metadata_original.require_for_v1(owner.bootstrap) if type(owner) is _NaturalInitialReadV1
            else metadata_original.require_for_v1(owner))
        self.groups=metadata["recipe"]["source_groups"]
        self.group_index=0;self.stack=[];self.active=set();self.done=set()
        self.root_index=0;self.node=None;self.phase="initial";self.complete=False
        self.members=[];self.union=set()
        rows=metadata["source_originals"]
        if type(rows) is not list:
            raise AuthorityUnavailable("Natural initial Source original inventory is absent")
        originals={}
        for row in rows:
            if (type(row)is not dict or set(row)!={"ref","version","cell_id","byte_count","sha256","producer_operation_id"}
                    or row["ref"] in originals or type(row["version"])is not int or row["version"]<1
                    or type(row["byte_count"])is not int or row["byte_count"]<1):
                raise AuthorityUnavailable("Natural initial Source inventory exact shape differs")
            key=AtomKey.from_token(row["ref"])
            if key!=source_key(*owner.namespace.as_tuple,key.owner.subject or ""):
                raise AuthorityUnavailable("Natural initial Source inventory crosses namespace")
            originals[row["ref"]]=row
        if list(originals)!=sorted(originals):
            raise AuthorityUnavailable("Natural initial Source inventory ordering differs")
        self.originals=originals
        owner.operation.retain(4096+len(originals)*128)
        owner.source_originals=originals
        self.audience=metadata["recipe"]["admission"]["audience"]

    def _enter_v1(self,ref,meter):
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        owner=self.owner
        # Use the actual locator's canonical token object. A temporary ancestor
        # encoding does not become one permanently retained string per edge.
        row=self.originals.get(ref)
        if row is None:
            raise AuthorityUnavailable("Natural initial Source ancestry exceeds the actual producer inventory")
        ref=row["ref"]
        if ref in self.active:raise AuthorityUnavailable("Natural initial Source ancestry is cyclic")
        if ref in self.done:return
        if len(self.active)+len(self.done)>=self.limit:
            raise AuthorityUnavailable("Natural initial Source group exceeds its original family bound")
        if ref not in owner.sources:
            self.node=_NaturalInitialSourceNodeV1(owner,ref);return
        source=owner.sources[ref]
        if ref in self.expected and source.revision!=self.expected[ref]:
            raise AuthorityUnavailable("Natural initial selected Source version differs")
        record=None
        for audience in self.group["audience"]:
            record=_qualify_source_rights_values_v3(owner.namespace,ref,source,owner.access.get(ref),None,
                audience=audience,purpose=self.group["purpose"],metadata_only=True)
            if record is None:
                raise AuthorityUnavailable("Natural initial Source lacks its actual current purpose/audience")
        if record is None:raise AuthorityUnavailable("Natural initial Source audience is absent")
        owner.reserve_scratch_v1(65536+len(self.active)*128+len(record.parent_source_ids)*16)
        self.active.add(ref);self.union.add(ref)
        self.stack.append((ref,iter(record.parent_source_ids)))

    def advance(self,meter):
        from ..memory_types import source_key
        owner=self.owner
        if self.node is not None:
            if self.node.advance(meter):
                ref=self.node.ref;self.node=None;self._enter_v1(ref,meter)
            return False
        if self.group_index==len(self.groups):
            if self.union!=set(self.originals):
                raise AuthorityUnavailable("Natural initial complete Source union differs")
            self.complete=True;return True
        if self.phase=="initial":
            group=self.groups[self.group_index]
            if (type(group)is not dict or set(group)!={"group","index","purpose","audience","source_versions","source_walk_profile"}
                    or group["audience"]!=self.audience or not self.audience):
                raise AuthorityUnavailable("Natural initial exact Source group differs")
            profiles={"dispatch_context_32":("context",32),"dispatch_expression_32":("expression",32),
                "producer_expression_256":("expression",256),"material_expression_256":("expression",256)}
            profile=profiles.get(group["source_walk_profile"])
            if profile is None or group["purpose"]!=profile[0]:
                raise AuthorityUnavailable("Natural initial unknown Source purpose profile")
            self.group,self.limit=group,profile[1]
            rows=group["source_versions"]
            if type(rows)is not list or len(rows)>self.limit:
                raise AuthorityUnavailable("Natural initial Source roots exceed the original profile")
            self.expected={}
            for row in rows:
                if (type(row)is not dict or set(row)!={"ref","version"} or row["ref"] in self.expected
                        or type(row["version"])is not int or row["version"]<1 or row["ref"]not in self.originals):
                    raise AuthorityUnavailable("Natural initial Source roots differ from actual originals")
                self.expected[row["ref"]]=row["version"]
            self.roots=tuple(self.expected);self.root_index=0
            owner.reserve_scratch_v1(65536+len(rows)*128)
            self.phase="walk";return False
        if self.stack:
            ref,parents=self.stack[-1]
            try:parent=next(parents)
            except StopIteration:
                self.stack.pop();self.active.remove(ref);self.done.add(ref);return False
            token=source_key(*owner.namespace.as_tuple,parent).token
            meter.charge_encode(len(token))
            self._enter_v1(token,meter);return False
        if self.root_index<len(self.roots):
            ref=self.roots[self.root_index];self.root_index+=1;self._enter_v1(ref,meter);return False
        owner.operation.retain(256+len(self.done)*32)
        self.members.append((self.group["purpose"],tuple(self.group["audience"]),frozenset(self.done)))
        self.group_index+=1;self.active=set();self.done=set();self.phase="initial"
        return False


from types import MappingProxyType
from ..graph_types import AtomKey, GraphAtom, OWNER_GRANT_TYPE
from ..runtime_contracts import QueryEpoch, canonical_digest
from ..graph_worker import GraphStorageStepV3, create_graph_storage_work_v3
from ..runtime_storage_v3 import bind_runtime_storage_operation_v3, runtime_storage_quantum_v3
from .dispatch_current_inventory_v3 import (
    _CurrentNamespaceInventoryKernelV3, CurrentDispatchTypedProjectionV3,
    _FrozenDispatchAtomV3, _freeze_value_v3, PreparedCurrentDispatchInventoryV3,
)
from .source_correction_read_v3 import _heap

_INITIAL_READS_V1 = WeakKeyDictionary()
_INITIAL_SOURCE_ALL_V1 = WeakKeyDictionary()
_INITIAL_PREPARED_V1 = WeakKeyDictionary()
_INITIAL_RESULTS_V1 = WeakKeyDictionary()
_INITIAL_ISSUER_V1 = object()
_INITIAL_WORK_KIND_V1 = "natural_dispatch_initial_read_v1"
_INITIAL_CONTROL_TYPES_V1 = frozenset({
    OWNER_GRANT_TYPE, "d03.account_binding", "d03.role_binding", "d05.boundary_rule",
})


class _NaturalInitialControlCensusV1(_CurrentNamespaceInventoryKernelV3):
    """Complete control census and selected heads; unrelated Body stays unread."""
    def __init__(self, owner):
        owner.require_actual_v1()
        self.owner = owner
        a = owner.admission.admission
        committed = owner.locator_task.result.metadata["recipe"]["committed_selection"]
        action = AtomKey.from_token(committed["candidate_writes"][0]["ref"])
        cancellation = AtomKey(action.owner, "d08.action_cancellation.v1", action.name)
        self.header_only_tokens = frozenset({ref for ref, _ in a.graph_reads}
            | {item.ref for check in a.check_receipts for item in check.input_versions})
        owner.operation.retain(4096 + len(self.header_only_tokens) * 64)
        selected = frozenset({cancellation.token})
        super().__init__(owner.graph, owner.operation, owner.fence,
            projection_types=_INITIAL_CONTROL_TYPES_V1, selected_tokens=selected,
            census_schema="sylanne.natural-initial-control-census.v1",
            leaf_schema="sylanne.natural-initial-control-head.v1")
        self.authority_epochs = owner.bootstrap.authority_epochs

    def _next(self, meter):
        # One fixed head per advance is sufficient to prove that every account,
        # role and boundary is included, without parsing unrelated business cells.
        row = _runtime_bounded_fixed_row_v3(self.db, meter, "graph_atoms",
            ("token", "revision", "valid", "type_name", "value_cell_id"),
            "bot=? AND persona=? AND token>? ORDER BY token",
            (*self.namespace.as_tuple, self.cursor))
        if row is None:
            if self._epochs(meter) != self.authority_epochs:
                raise AuthorityUnavailable("Natural initial control census authority epoch changed")
            self.graph_eof = self.complete = True
            return
        token, revision, valid, kind, cell_id = row
        key = AtomKey.from_token(token)
        if ((key.owner.bot, key.owner.persona) != self.namespace.as_tuple
                or key.type_name != kind or type(revision) is not int or revision < 1
                or valid not in (0, 1) or cell_id is None):
            raise AuthorityUnavailable("Natural initial control census has an invalid current head")
        self.store._validate_key(key)
        self.cursor = token
        if token in self.header_only_tokens:
            self._reserve(4096 + len(token) * 4)
            self.heads[token] = (revision, valid, cell_id)
        # A snapshot readset is a fixed-head commitment, never permission to
        # expose unrelated business Body. Only the closed controls below and
        # the exact selected cancellation record enter the content codec.
        # Source and Access have their own complete pre-Body original proofs.
        if kind in {"memory.source", "memory.access"}:
            return
        if kind not in self.projection_types and token not in self.selected_tokens:
            return
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        self.pending = (key, revision, valid, kind, cell_id)
        self.cell = begin_runtime_cell_read_v3(self.db, cell_id, erasure_owner_ref=token)
        codec = self.cell.header[0]
        if codec not in ("canonical-json.ascii.v1", "canonical-json.utf8.v1"):
            raise AuthorityUnavailable("Natural initial selected control codec is not registered")
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=codec == "canonical-json.ascii.v1")
        self._reserve(self.cell.header[3] * 8 + 32768)
        self.body = bytearray()

    def advance_v1(self, meter):
        self.owner.require_actual_v1()
        if self.cell is None:
            self._next(meter)
        else:
            self._cell(meter)
        return self.complete


class _NaturalInitialSourceAllV1:
    """An issued complete pre-Body Source selection, never a P2 permit."""
    def __init__(self, issuer, owner, task):
        if issuer is not _INITIAL_ISSUER_V1 or type(task) is not _NaturalInitialSourcesV1 or not task.complete:
            raise AuthorityUnavailable("actual complete Natural initial Source traversal required")
        self.owner, self.metadata = owner, owner.locator_task.result
        self.sources, self.access = MappingProxyType(dict(owner.sources)), MappingProxyType(dict(owner.access))
        self.heads = MappingProxyType(dict(owner.heads))
        self.absences, self.groups = frozenset(owner.correction_absences), tuple(task.members)
        owner.operation.retain(4096 + 256 * (len(self.sources) + len(self.access) + len(self.heads)))
        _INITIAL_SOURCE_ALL_V1[self] = self._identity_v1()

    def _identity_v1(self):
        return (self.owner, self.metadata, self.sources, self.access, self.heads, self.absences, self.groups)

    def require_v1(self, owner):
        if (_INITIAL_SOURCE_ALL_V1.get(self) != self._identity_v1() or self.owner is not owner
                or owner.operation.closed or owner.sources is not self.sources
                or owner.access is not self.access or owner.heads is not self.heads):
            raise AuthorityUnavailable("Natural initial complete Source barrier issuer changed")
        self.metadata.require_for_v1(owner.bootstrap)
        return self

    def release_payload_v3(self):
        _INITIAL_SOURCE_ALL_V1.pop(self, None)
        self.owner = self.metadata = self.sources = self.access = self.heads = self.absences = self.groups = None


class _PreparedNaturalInitialReadV1:
    """Independent READ proof. It cannot satisfy a P2 require_for call."""
    def __init__(self, issuer, owner):
        if issuer is not _INITIAL_ISSUER_V1 or not owner.auxiliary.complete or not owner.controls.complete:
            raise AuthorityUnavailable("actual complete initial Natural originals required")
        owner.require_actual_v1()
        self.owner, self.graph, self.db, self.namespace = owner, owner.graph, owner.db, owner.namespace
        self.scope, self.operation = owner.fence.scope, owner.operation
        self.query, self.graph_stamp = owner.query, owner.graph_stamp
        self.selection_digest = owner.selection_digest
        self.sources, self.heads = owner.sources, MappingProxyType(dict(owner.projection_heads))
        self.qualified_sources = frozenset(ref for purpose, _, refs in owner.source_barrier.groups
            if purpose == "expression" for ref in refs)
        atoms = (*owner.access.values(), *owner.controls.atoms)
        owner.operation.retain(4096 + sum(2048 + _heap(atom.value) * 4 for atom in atoms))
        self.projection = CurrentDispatchTypedProjectionV3(tuple(_FrozenDispatchAtomV3(
            atom.key, atom.revision, _freeze_value_v3(atom.value), atom.valid, _heap(atom.value))
            for atom in atoms), (owner.graph_stamp[1],), owner.operation)
        auxiliary = owner.auxiliary
        self.natural_originals = auxiliary.natural_values
        self.natural_history = auxiliary.natural_history
        self.natural_scope_original = auxiliary.natural_scope_original
        self.natural_review_originals = auxiliary.natural_review_originals
        self.natural_parent_stop = auxiliary.natural_parent_stop
        self.admission_originals = owner.admission_originals
        _INITIAL_PREPARED_V1[self] = self._identity_v1()

    def _identity_v1(self):
        return (self.owner, self.graph, self.db, self.namespace, self.scope, self.operation, self.query,
            self.graph_stamp, self.selection_digest, self.sources, self.heads, self.qualified_sources,
            self.projection, self.natural_originals, self.natural_history, self.natural_scope_original,
            self.natural_review_originals, self.natural_parent_stop, self.admission_originals)

    def require_current(self, db, namespace, query, projection=None):
        if (_INITIAL_PREPARED_V1.get(self) != self._identity_v1()
                or db is not self.db or namespace != self.namespace or query != self.query
                or projection is not None and projection is not self.projection):
            raise AuthorityUnavailable("actual independent initial READ identity differs")
        self.owner.require_actual_v1()
        if not self.db.in_transaction or not self.owner.store._lock._is_owned():
            raise AuthorityUnavailable("initial READ consumer requires its actual pinned Graph transaction")
        return self.projection

    # These methods are pure readonly consumers. Their entry calls the distinct
    # require_current above; the initial proof inherits no P2 or claim method.
    source_metadata = PreparedCurrentDispatchInventoryV3.source_metadata
    atoms_for = PreparedCurrentDispatchInventoryV3.atoms_for
    atom_rows = PreparedCurrentDispatchInventoryV3.atom_rows
    correction_head = PreparedCurrentDispatchInventoryV3.correction_head

    def release_payload_v3(self):
        _INITIAL_PREPARED_V1.pop(self, None)
        self.owner = self.graph = self.db = self.namespace = self.scope = self.operation = None
        self.projection = self.sources = self.heads = self.qualified_sources = None
        self.natural_originals = self.natural_history = self.natural_scope_original = None
        self.natural_review_originals = self.natural_parent_stop = self.admission_originals = None


class _NaturalInitialOriginalJoinsV1:
    """Rejoin real full originals with the pre-Body metadata and Source barrier."""
    def __init__(self, owner):
        self.owner, self.inventory = owner, owner.prepared
        owner.require_actual_v1()
        history = self.inventory.natural_history
        self.original = history.original
        m = owner.locator_task.result
        m.require_for_v1(owner.bootstrap)
        if (self.original.sha256, self.original.byte_count) != (m.receipt_sha256, m.receipt_byte_count):
            raise AuthorityUnavailable("Natural pre-Body metadata differs from the later full receipt EOF")
        receipt = history.receipt_v3(owner.db, owner.namespace, owner.selected_operation_id)
        self.wrapper = receipt.get(_FIELD_V1)
        if self.wrapper != owner.locator_task.raw:
            raise AuthorityUnavailable("Natural full receipt locator differs from the pre-Body original")
        self.metadata, self.receipt = m.metadata, receipt
        self.phase = "joins"
        self.stream = None
        self.digests = []
        self.digest_index = 0
        self.source_rows = {}

    def advance(self, meter):
        from .natural_dispatch_read_locator_current_v1 import (
            _NaturalDispatchLocatorOriginalJoinsV1, _PlainDataclassCanonicalStreamV1,
        )
        self.inventory.require_current(self.owner.db, self.owner.namespace, self.inventory.query)
        if self.phase == "joins":
            _NaturalDispatchLocatorOriginalJoinsV1._joins(self, meter)
        elif self.phase == "original_digests":
            if self.digest_index == len(self.digests):
                if self.source_rows != self.owner.source_originals:
                    raise AuthorityUnavailable("Natural full original Source manifest differs from its qualified pre-Body selection")
                self.phase = "complete"
                return True
            name, value, typed = self.digests[self.digest_index]
            if self.stream is None:
                self.stream = (_PlainDataclassCanonicalStreamV1(value, self.owner.operation,
                    plain=not bool(typed)) if typed != "asdict" else
                    _PlainDataclassCanonicalStreamV1(value, self.owner.operation))
            self.stream.read_fragment(meter)
            if self.stream.complete:
                if self.stream.hash.hexdigest() != self.metadata[name]:
                    raise AuthorityUnavailable("Natural initial actual original canonical digest differs: " + name)
                self.stream = None
                self.digest_index += 1
        return self.phase == "complete"


class _NaturalInitialReadV1:
    def __init__(self, bootstrap):
        self.bootstrap = bootstrap
        self.graph, self.store, self.db = bootstrap.graph, bootstrap.store, bootstrap.db
        self.namespace, self.operation, self.fence = bootstrap.namespace, bootstrap.operation, bootstrap.fence
        self.graph_stamp = bootstrap.graph_stamp
        self.query = QueryEpoch(self.namespace, "all", self.graph_stamp[1].revision)
        self.selection_digest = self.operation.selection_digest
        self.selected_operation_id = bootstrap.selected_operation_id
        self.selected_activity_id = bootstrap.selected_activity_id
        self.selected_effect_id = bootstrap.selected_effect_id
        self.admission_ref = None
        self.admission = self.request = self.admission_originals = self.admission_task = None
        self.sources, self.access, self.heads = {}, {}, {}
        self.access_originals, self.source_originals = {}, {}
        self.correction_absences = set()
        self.source_barrier = self.source_task = self.controls = self.prepared = self.auxiliary = None
        self.joins = self.result = None
        self.phase = "metadata"
        self.complete = False
        self.scratch_peak = 0
        self.locator_task = _NaturalInitialLocatorReadV1(self)
        self.now_utc = bootstrap.require_time_v1()
        _INITIAL_READS_V1[self] = self._identity_v1()

    @property
    def work(self):return self.bootstrap.work

    @property
    def authority(self):return self.bootstrap.authority

    def _identity_v1(self):
        return (self.bootstrap, self.graph, self.store, self.db, self.namespace, self.operation,
            self.fence, self.graph_stamp, self.query, self.selection_digest,
            self.selected_operation_id, self.selected_activity_id, self.selected_effect_id)

    def reserve_scratch_v1(self, wanted):
        if wanted > self.scratch_peak:
            self.operation.retain(wanted - self.scratch_peak)
            self.scratch_peak = wanted

    def require_actual_v1(self):
        if (_INITIAL_READS_V1.get(self) != self._identity_v1() or self.operation.closed
                or self.bootstrap.work is None or self.bootstrap.work.state is not self
                or self.bootstrap.work.terminal or self.bootstrap.work._finish_called
                or self.bootstrap.work.operation is not self.operation
                or self.operation.handle is not runtime_storage_v3(self.db)
                or self.selection_digest != self.operation.selection_digest
                or self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp):
            raise AuthorityUnavailable("actual independent Natural initial Work lost its original identity")
        if self.source_barrier is None:
            raise AuthorityUnavailable("Natural initial SourceALL barrier has not completed")
        self.source_barrier.require_v1(self)
        self.now_utc = self.bootstrap.require_time_v1()
        epochs = self.db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
            self.namespace.as_tuple).fetchone()
        head = self.db.execute("SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*self.namespace.as_tuple, self.bootstrap.owner_key.token)).fetchone()
        if epochs != self.bootstrap.authority_epochs or head != self.bootstrap.owner_header:
            raise AuthorityUnavailable("Natural initial current Owner or Source epochs changed")
        return self

    def _step_v1(self, meter):
        if self.phase == "metadata":
            if self.locator_task.advance(meter):
                self.source_task = _NaturalInitialSourcesV1(self, self.locator_task.result)
                self.phase = "source_all"
        elif self.phase == "source_all":
            if self.source_task.advance(meter):
                barrier = _NaturalInitialSourceAllV1(_INITIAL_ISSUER_V1, self, self.source_task)
                self.sources, self.access, self.heads = barrier.sources, barrier.access, barrier.heads
                self.source_barrier = barrier
                self.require_actual_v1()
                from .dispatch_admission_read_v3 import DispatchAdmissionReadV3
                self.admission_task = DispatchAdmissionReadV3(self)
                self.phase = "admission"
        elif self.phase == "admission":
            self.require_actual_v1()
            if self.admission_task.advance(meter):
                self.admission_originals = self.admission_task.result
                self.admission, self.request = self.admission_originals.receipt_v3(), self.admission_originals.request_v3()
                self.bootstrap.tighten_to_admission_v1(self.admission)
                from dataclasses import asdict
                a = self.admission.admission
                policy = self.graph._GraphCoordinator__dispatch_clock_policy
                if (a.clock_policy_ref != policy.source_id
                        or a.clock_policy_digest != canonical_digest(asdict(policy))):
                    raise AuthorityUnavailable("Natural initial admission installed clock policy differs")
                self.controls = _NaturalInitialControlCensusV1(self)
                self.phase = "controls"
        elif self.phase == "controls":
            if self.controls.advance_v1(meter):
                self.projection_heads = {**self.heads, **self.controls.heads}
                if self.projection_heads.get(self.bootstrap.owner_key.token) != self.bootstrap.owner_header:
                    raise AuthorityUnavailable("Natural initial complete Owner original is absent")
                from .dispatch_initial_source_read_v3 import DispatchInitialSourceReadsV3
                self.auxiliary = DispatchInitialSourceReadsV3(self, "natural_reply", self.now_utc)
                self.phase = "originals"
        elif self.phase == "originals":
            self.require_actual_v1()
            if self.auxiliary.advance(meter):
                self.prepared = _PreparedNaturalInitialReadV1(_INITIAL_ISSUER_V1, self)
                self.joins = _NaturalInitialOriginalJoinsV1(self)
                self.phase = "joins"
        elif self.phase == "joins":
            if self.joins.advance(meter):
                self.phase = "result"
        elif self.phase == "result":
            self.require_actual_v1()
            from .natural_dispatch_current_read_v2 import recover_natural_dispatch_candidate_in_transaction_v2
            evidence = recover_natural_dispatch_candidate_in_transaction_v2(self.db, self.namespace,
                self.selected_operation_id, prepared_history=self.prepared.natural_history)
            segment = self.graph._get_natural_dispatch_text_segment_locked(self.namespace, self.request,
                now_utc=self.now_utc, prepared_inventory=self.prepared)
            committed = self.graph._get_operation_locked(self.namespace, self.selected_operation_id,
                prepared_history=self.prepared.natural_history)
            if (evidence is None or segment is None or segment[1] != evidence.evidence
                    or committed is None or committed.status != "committed" or len(committed.outbox_refs) != 1):
                raise AuthorityUnavailable("Natural initial actual committed outbox or text original differs")
            self.result = _NaturalInitialResultV1(_INITIAL_ISSUER_V1, self,
                (self.admission, self.request, evidence.evidence, committed), segment)
            self.complete = True
        else:
            raise AuthorityUnavailable("Natural initial READ phase differs")

    def release_payload_v3(self):
        from .source_inspection_metadata_read_v3 import release_inspection_metadata_owner_v3
        release_inspection_metadata_owner_v3(self)
        _INITIAL_READS_V1.pop(self, None)
        if self.prepared is not None:
            self.prepared.release_payload_v3()
        if self.admission_originals is not None:
            self.admission_originals.release_payload_v3()
        if self.source_barrier is not None:
            self.source_barrier.release_payload_v3()
        if self.locator_task is not None and self.locator_task.result is not None:
            self.locator_task.result.release_payload_v3()
        # No expiry check here: cancellation/abandonment must release stale data.
        self.prepared = self.admission_originals = self.source_barrier = None
        self.locator_task = self.source_task = self.controls = self.auxiliary = self.joins = self.result = None
        self.sources = self.access = self.heads = self.access_originals = self.source_originals = None
        self.projection_heads = self.admission = self.request = None


class _NaturalInitialResultV1:
    def __init__(self, issuer, owner, value, segment):
        if issuer is not _INITIAL_ISSUER_V1 or owner.phase != "result":
            raise AuthorityUnavailable("actual Natural initial terminal producer required")
        self.owner, self.value, self.segment = owner, value, segment
        _INITIAL_RESULTS_V1[self] = (owner, value, segment)

    def require_value_v1(self):
        if (_INITIAL_RESULTS_V1.get(self) != (self.owner, self.value, self.segment)
                or self.owner.operation.closed):
            raise AuthorityUnavailable("actual retained Natural initial terminal required")
        self.owner.bootstrap.require_time_v1()
        return self.value, self.segment, self.owner.operation

    def release_payload_v3(self):
        _INITIAL_RESULTS_V1.pop(self, None)
        owner, self.owner = self.owner, None
        self.value = self.segment = None
        if owner is not None:
            owner.release_payload_v3()


def prepare_natural_dispatch_initial_read_v1(graph, authority, lease, operation_id):
    bootstrap = _NaturalInitialBootstrapV1(graph, authority, lease, operation_id)
    reader = None
    try:
        with bind_runtime_storage_operation_v3(bootstrap.operation, bootstrap.db):
            reader = _NaturalInitialReadV1(bootstrap)
            work = create_graph_storage_work_v3(graph, kind=_INITIAL_WORK_KIND_V1,
                operation_id=bootstrap.operation_id, selection_digest=bootstrap.operation.selection_digest,
                deadline_utc=bootstrap.deadline, state=reader, operation=bootstrap.operation)
            bootstrap.work = work
            def issued(actual):
                if type(actual) is not _NaturalInitialResultV1 or actual.owner is not reader:
                    raise AuthorityUnavailable("Natural initial Work requires its actual same-owner terminal")
                actual.require_value_v1()
                return actual
            def failed(error):
                raise error
            work.map_terminal_v3("issuer", issued, failed)
            return work
    except BaseException:
        try:
            graph._finish_read_fence_v3(bootstrap.fence)
        finally:
            if reader is not None:
                reader.release_payload_v3()
            finish_runtime_storage_operation_v3(bootstrap.operation)
        raise


def advance_natural_dispatch_initial_read_v1(graph, work):
    reader = work.state
    if type(reader) is not _NaturalInitialReadV1 or reader.graph is not graph or reader.bootstrap.work is not work:
        raise AuthorityUnavailable("actual same-operation Natural initial READ Work required")
    b = reader.bootstrap
    b.require_time_v1()
    with bind_runtime_storage_operation_v3(reader.operation, reader.db):
        graph._authorize(b.lease, b.authority, frozenset({"d08", "d09", "d11"}))
        graph._validate_read_fence_v3(reader.fence)
        from .dispatch_initial_source_read_v3 import (
            prepare_pending_host_natural_roster_metadata_v3, bind_host_natural_roster_metadata_v3)
        prepare_pending_host_natural_roster_metadata_v3(reader)
        with reader.store._lock, runtime_storage_quantum_v3(reader.db) as meter:
            if reader.db.in_transaction:
                raise AuthorityUnavailable("Natural initial READ cannot inherit a transaction")
            reader.db.execute("BEGIN")
            try:
                with bind_host_natural_roster_metadata_v3(reader):
                    b.require_fixed_headers_v1(meter)
                    reader.now_utc = b.require_time_v1()
                    reader._step_v1(meter)
            finally:
                reader.db.rollback()
        graph._validate_read_fence_v3(reader.fence)
        b.require_time_v1()
    return GraphStorageStepV3("complete", reader.result) if reader.complete else GraphStorageStepV3("progress")


def finish_natural_dispatch_initial_read_v1(graph, work, error):
    reader = work.state
    failed = error is not None
    try:
        graph._finish_read_fence_v3(reader.fence)
        if not failed:
            work.result_lease = work.operation
    except BaseException:
        failed = True
        raise
    finally:
        if failed:
            try:
                if reader.result is not None:
                    reader.result.release_payload_v3()
                else:
                    reader.release_payload_v3()
            finally:
                finish_runtime_storage_operation_v3(work.operation)
