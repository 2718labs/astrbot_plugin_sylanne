"""Private Numeric metadata recipe on the actual ordinary Method READ."""
from types import MappingProxyType
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3, _runtime_bounded_fixed_row_v3
from .current_method_learning_read_v3 import (MethodJSONColumnV3, _JSON_COLUMNS,
    _READERS, _MethodLearningReadV3, _MethodJSONStreamV3, _method_active, _need_method_input,
    _GENERAL_METHOD_SOURCE_TASKS_V1)
from .dispatch_current_inventory_v3 import _freeze_value_v3, _detach_value_v3, _heap

from .current_method_learning_read_v3 import (_NUMERIC_OWNER_OPERATIONS_V1 as NUMERIC_OWNER_OPERATIONS_V1,
    _NUMERIC_METADATA_OPERATIONS_V3,_NUMERIC_READ_ONLY_OPERATIONS_V3,_NUMERIC_NATIVE_READ_OPERATIONS_V3)
_COLUMNS = WeakKeyDictionary()
_SOURCE_PROOFS = WeakKeyDictionary()
_METADATA_PLANS = WeakKeyDictionary()

# Every retained path is a locator, identity, clock or version. No model text,
# appraisal MeaningFacet, original Source text or numeric transcript is retained.
_PATHS = {
    "cancel_continuation": (("episode_ref",),("causal_operation_id",),("numeric_input_digest",)),
    "numeric_continuation": (("episode_ref",),("causal_operation_id",),("numeric_input_digest",)),
    "numeric_prepare_commit": (("identity",),("provenance","prepared_digest"),("provenance","numeric_input_digest")),
    "cancel_prepare_commit": (("identity",),("provenance","prepared_digest"),("provenance","numeric_input_digest")),
    "episode": (("schema",),("producing_operation_id",), ("episode", "episode_ref"), ("episode", "source_refs"),
        ("event", "namespace"), ("event", "causal_operation_id"),
        ("event", "activity", "source_ref"), ("event", "activity", "execution_id"),
        ("event", "activity", "activity_id"),("event","activity","artifact_ref"),
        ("event","activity","effect_id"),("event","activity","terminal_original_ref"), ("current_reads",),("historical_reads",)),
    "before": (("namespace",), ("original_ref",), ("execution_id",), ("source_roots",),
        ("root_operation_id",),("prepare_operation_id",),("binding_digest",),("prepared_digest",), ("members",),("context_rows",)),
    "context": (("namespace",), ("episode_ref",), ("execution_id",), ("source_ref",),
        ("source_revision",), ("occurrence_digest",), ("before_digest",),
        ("before_ref",), ("operation_id",)),
    "prepared": (("namespace",), ("operation_id",), ("job_id",), ("call_id",),
        ("activity_id",), ("causal_operation_id",), ("quote_id",), ("quote_digest",),("reservation_digest",),("audience",),
        ("read_rows",), ("frozen", "identity")),
    "numeric_model_life_prepared":(("schema",),("binding",),("prepare_operation_id",),
        ("plan","audiences"),("plan","input_source","ref"),("read_rows",)),
    "native_prepared":(("binding",),("original_ref",),("schema",)),
    "native_life_adopted":(("namespace",),("result_ref",),("producing_operation_id",),("source_refs",),("write_commitments",),
        ("terminal","binding"),("terminal","original_ref"),("terminal","claim","original_ref")),
    "native_life_experience":(("schema",),("source_ref",),("source_digest",),("binding",),("adopted_operation_id",),
        ("experience","action_outcome_ref"),("experience","cost_refs"),("terminal","binding"),
        ("terminal","original_ref"),("terminal","claim","original_ref")),
    "native_life_prepared":(("binding",),("plan","input_source"),("plan","input_access"),
        ("plan","project"),("plan","recipe"),("plan","body_effect_request_json"),
        ("plan","action_intent"),("read_rows",)),
    "native_life_accounting":(("binding",),("prepare_operation_id",),("quote_json",),
        ("signed_grant_json",),("signed_grant_signature",)),
    "native_life_action":(("namespace",),("action_operation_id",),("action_intent_ref",),("activity_id",),
        ("input_source_ref",),("input_source_digest",),("context_commitments",),("write_commitments",)),
    "native_grant":((),),
    "native_trace":(("trace","namespace"),("trace","trace_ref"),("trace","episode_ref"),
        ("trace","producing_operation_id"),("trace","baseline","source_ref"),
        ("trace","baseline","joint_operation_id"),("current_reads",),("historical_reads",)),
    "native_baseline":(("namespace",),("original_ref",),("encoding_operation_id",),("episode_ref",),
        ("source_ref",),("source_revision",),("joint_operation_id",),("context_ref",),("before_digest",),
        ("appraisal_acceptance_digests",)),
    "native_acceptance":(("namespace",),("operation_id",),("job_id",),("context_digest",),("before_digest",),
        ("appraisal_ref",),("appraisal_revision",),("prepared_digest",),("result_original_ref",),
        ("result_original_digest",),("cost_original_ref",),("cost_original_digest",),("read_rows",)),
    "binding": ((),),
    "request": (("schema",),("prepared_digest",),("binding_digest",),("request_digest",)),
    "acquire_commit": ((),),
    "quote": ((),),
    "paid": (("prepared_digest",), ("binding_digest",), ("cost", "cost_ref"),
        ("result", "request", "job_id"), ("result", "request", "call_id")),
    "job": (("job_id",), ("work_kind",), ("phase",), ("operation_id",), ("cancel_epoch",), ("fence",)),
    "joint": (("namespace",), ("source_versions",), ("receipt_digest",), ("status",)),
    "c04_cost": (("namespace",), ("operation_id",), ("binding_digest",), ("prepared_digest",),
        ("terminal_receipt_ref",)),
    "drive": (("source_ref",), ("source_revision",)),
    "checkpoint": (("cursor",),),
    "adoption": (("identity",), ("now_utc",)),
}
_LEAF_FIELDS = {
    "current_reads": frozenset(("ref", "revision")),
    "historical_reads":frozenset(("ref","revision")),
    "read_rows": frozenset(("ref", "revision")),
    "context_rows":frozenset(("ref","revision")),
    "checkpoint": frozenset(("ref", "revision")),
}

def require_numeric_owner_metadata_work_v1(reader):
    from .current_method_learning_read_v3 import _NUMERIC_PAID_WRITE_OPERATIONS_V3
    if reader.operation_kind in _NUMERIC_PAID_WRITE_OPERATIONS_V3:
        from .current_life_numeric_paid_write_v3 import require_numeric_paid_write_work_v3
        return require_numeric_paid_write_work_v3(reader)
    from ..authority_service.life_numeric_source_read_v3 import AuthorityNumericSourceReadV3, require_authority_numeric_metadata_work_v3
    if type(reader) is AuthorityNumericSourceReadV3:
        return require_authority_numeric_metadata_work_v3(reader)
    from .current_method_learning_read_v3 import _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3
    if reader.operation_kind in _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3:
        from .current_owner_job_cancel_v3 import require_current_job_cancel_work_v3
        return require_current_job_cancel_work_v3(reader)
    if (type(reader) is not _MethodLearningReadV3 or reader not in _READERS
            or reader.operation_kind not in _NUMERIC_METADATA_OPERATIONS_V3
            or reader.work is None or reader.work.state is not reader
            or reader.work.operation is not reader.operation
            or reader.runtime.graph is not reader.graph
            or reader.fence.scope.operation != "read" or reader.session_proof is None
            or any((reader.background_followup, reader.background_host_lifecycle, reader.background_offline))):
        raise AuthorityUnavailable("Numeric metadata requires its exact ordinary Owner Method READ")
    if reader.operation_kind in _NUMERIC_READ_ONLY_OPERATIONS_V3:
        from .current_life_numeric_read_v3 import require_numeric_read_work_v3
        require_numeric_read_work_v3(reader)
    reader.require_current()
    return reader

def _numeric_metadata_issuers_v3(reader):
    from ..authority_service.life_numeric_source_read_v3 import AuthorityNumericSourceReadV3, numeric_metadata_issuers_v3
    if type(reader) is AuthorityNumericSourceReadV3:
        return numeric_metadata_issuers_v3(reader)
    require_numeric_owner_metadata_work_v1(reader)
    return reader.graph._GraphCoordinator__d11_issuer, reader.graph._GraphCoordinator__d02_issuer

def _retains(profile, path):
    if profile not in _PATHS:
        raise AuthorityUnavailable("unregistered Numeric metadata profile")
    if not path:
        return True
    for selected in _PATHS[profile]:
        if selected[:len(path)] == path:
            return True
        if path[:len(selected)] == selected:
            if selected in {("current_reads",),("read_rows",),("historical_reads",),("context_rows",)}:
                return len(path) <= 2 or len(path) == 3 and path[2] in _LEAF_FIELDS[selected[0]]
            if selected == ("members",):
                return (len(path) <= 2 or len(path) == 3 and path[2] in {"checkpoint","state"}
                    or len(path) == 4 and path[2] in {"checkpoint","state"} and path[3] in _LEAF_FIELDS["checkpoint"])
            return True
    return False

class _NumericReceiptFieldsDigestV1:
    """Stream the actual canonical receipt fields, excluding its two non-fields."""
    def __init__(self):
        import hashlib
        self.hash=hashlib.sha256()
        self.frames=[];self.skip=None;self.fields=set();self.complete=False

    def _value_start(self):
        if self.frames and self.frames[-1][0]=="array":
            frame=self.frames[-1]
            if frame[1]:self.hash.update(b",")
            frame[1]+=1

    def emit(self,event):
        if event.kind=="key" and len(event.path)==1:
            self.fields.add(event.key)
            self.skip=(event.key,) if event.key in {"receipt_digest","status"} else None
        if self.skip is not None and event.path[:1]==self.skip:return
        kind=event.kind
        if kind=="key":
            frame=self.frames[-1]
            if frame[1]:self.hash.update(b",")
            frame[1]+=1;self.hash.update(event.raw);self.hash.update(b":")
        elif kind in {"object_start","array_start"}:
            self._value_start();self.hash.update(event.raw)
            self.frames.append(["object" if kind=="object_start" else "array",0])
        elif kind in {"object_end","array_end"}:
            self.hash.update(event.raw);self.frames.pop()
            if not event.path:self.complete=True
        elif kind=="scalar_start":
            self._value_start()
        elif kind=="scalar_chunk":
            self.hash.update(event.raw)

    def finish(self):
        from ..domains.d04.joint_numeric_receipt import D04JointNumericReceiptCandidateV1
        if not self.complete or self.frames or self.fields!=set(D04JointNumericReceiptCandidateV1.__dataclass_fields__):
            raise AuthorityUnavailable("Numeric receipt fields digest lacks its exact whole canonical EOF")
        return self.hash.hexdigest()


class _NumericMetadataColumnV1(MethodJSONColumnV3):
    def __init__(self, task, *, cell=None):
        owner = require_numeric_owner_metadata_work_v1(task.reader)
        self.owner, self.db, self.operation = owner, owner.db, owner.operation
        self.table, self.column, self.key_columns, self.key = task.table, task.column_name, task.key_columns, task.key
        self.cell, self.profile, self.task = cell, task.profile, task
        self.receipt_fields_stream=_NumericReceiptFieldsDigestV1() if self.profile=="joint" else None
        self.receipt_fields_digest=None
        self.signer = self.signature_kind = self.signature = None
        self.signature_state = None
        self.signature_bytes, self.signature_verified = 0, False
        self.general_metadata_profile, self.general_metadata_task = None, None
        self.general_metadata_fields_seen = set()
        self.nodes, self.value, self.scalar = {}, None, bytearray()
        self.text_parts, self.text_chars, self.text_high = [], [], None
        self.fragment, self.fragment_offset, self.offset, self.total = b"", 0, 0, None
        self.complete, self.frozen, self.sha256, self.byte_count = False, None, None, None
        self.reserved, self.wire_parts, self.wire = 0, [], None
        self.canonical_digest = self.canonical_stream = None
        self.semantic_decoder = self.semantic_hash = None
        if cell is not None and cell.header[0] == "canonical-json.utf8.v1":
            import codecs, hashlib
            self.semantic_decoder = codecs.getincrementaldecoder("utf8")("strict")
            self.semantic_hash = hashlib.sha256()
        self.parser = _MethodJSONStreamV3(self, ensure_ascii=cell is None or cell.header[0] != "canonical-json.utf8.v1")
        _JSON_COLUMNS[self] = (owner, self.db, self.table, self.column, self.key_columns,
            self.key, cell, None, None, None)
        _COLUMNS[self] = (owner, task, self.profile)

    def _actual(self):
        from ..authority_service.life_numeric_source_read_v3 import AuthorityNumericSourceReadV3
        if type(self.owner) is AuthorityNumericSourceReadV3:
            require_numeric_owner_metadata_work_v1(self.owner)
            if _JSON_COLUMNS.get(self) != (self.owner, self.db, self.table, self.column, self.key_columns, self.key, self.cell, None, None, None):
                raise AuthorityUnavailable("Numeric Authority metadata column changed its actual fixed selector")
        else:
            super()._actual()
        if _COLUMNS.get(self) != (self.owner, self.task, self.profile) or self.task.column is not self:
            raise AuthorityUnavailable("Numeric metadata column changed its issuing actual Work task")
        return self

    def retain_path_v3(self, path):
        return _retains(self.profile, path)

    def _emit_v3(self, event):
        if self.receipt_fields_stream is not None:
            self.receipt_fields_stream.emit(event)
        if self.retain_path_v3(event.path):
            super()._emit_v3(event)

    def advance(self, meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2, read_legacy_sql_cell_fragment_v2, _quote
        self._actual()
        self.owner.require_current(meter=meter)
        if self.complete:
            return True
        if self.fragment_offset < len(self.fragment):
            end = min(self.fragment_offset + 1024, len(self.fragment))
            chunk = self.fragment[self.fragment_offset:end]
            self._reserve_v3(131072)
            self.parser.feed(chunk, self._emit_v3)
            if self.semantic_decoder is not None:
                from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
                _D07AuthorityGraphMetadataColumnV3._semantic_v3(self, chunk, meter)
            self.fragment_offset = end
            self._flush_text_v3()
            return False
        if self.cell is not None:
            chunk = self.cell.read_fragment(meter=meter)
        else:
            where = " AND ".join(_quote(name) + "=?" for name in self.key_columns)
            with legacy_cell_read_transaction_v2(self.db):
                if self.total is None:
                    row = self.db.execute("SELECT typeof(" + _quote(self.column) + "),length(CAST(" +
                        _quote(self.column) + " AS BLOB)) FROM " + _quote(self.table) + " WHERE " + where, self.key).fetchone()
                    meter.charge_read(16)
                    if row is None or row[0] != "text":
                        raise AuthorityUnavailable("Numeric metadata original column unavailable")
                    self.total = row[1]
                if self.offset < self.total:
                    chunk, total, kind = read_legacy_sql_cell_fragment_v2(self.db, table=self.table,
                        column=self.column, where=where, parameters=self.key, start=self.offset,
                        length=min(16384, self.total-self.offset), meter=meter)
                    if (total, kind) != (self.total, "text"):
                        raise AuthorityUnavailable("Numeric metadata original byte count/kind changed")
                    self.offset += len(chunk)
                else:
                    chunk = None
        if chunk is not None:
            self.fragment, self.fragment_offset = chunk, 0
            return False
        parsed = self.parser.finish()
        if self.cell is not None:
            if (parsed.sha256, parsed.byte_count) != (self.cell.finish(meter=meter), self.cell.header[3]):
                raise AuthorityUnavailable("Numeric metadata complete canonical cell EOF differs")
        elif parsed.byte_count != self.total:
            raise AuthorityUnavailable("Numeric metadata complete raw EOF differs")
        if self.semantic_decoder is not None:
            from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
            _D07AuthorityGraphMetadataColumnV3._semantic_v3(self, b"", meter, final=True)
            self.canonical_digest = self.semantic_hash.hexdigest()
        else:
            self.canonical_digest = parsed.sha256
        if self.receipt_fields_stream is not None:
            self.receipt_fields_digest=self.receipt_fields_stream.finish()
            self.receipt_fields_stream=None
        self._reserve_v3(_heap(self.value)*2 + 1024)
        self.frozen = _freeze_value_v3(self.value)
        self.sha256, self.byte_count = parsed.sha256, parsed.byte_count
        self.value, self.nodes, self.scalar, self.fragment, self.parser = None, {}, bytearray(), b"", None
        self.semantic_decoder = self.semantic_hash = None
        self.complete = True
        return True

    def json_v3(self):
        raise AuthorityUnavailable("Numeric metadata never exposes a whole protected original")

class NumericMetadataTaskV1:
    def __init__(self, reader, identity):
        self.reader, self.identity = require_numeric_owner_metadata_work_v1(reader), identity
        self.column, self.result, self.metadata = None, None, None
        self.complete, self.phase = False, "header"
        mode, self.profile, ref = identity
        from .current_method_learning_read_v3 import _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3
        if mode in {"cancel_job","cancel_prepare"} or reader.operation_kind in _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3:
            from .current_owner_job_cancel_v3 import require_cancel_metadata_selector_v3
            require_cancel_metadata_selector_v3(reader,identity)
        from ..authority_service.life_numeric_source_read_v3 import AuthorityNumericSourceReadV3, require_authority_numeric_metadata_selector_v3
        if type(reader) is AuthorityNumericSourceReadV3:
            require_authority_numeric_metadata_selector_v3(reader, identity)
        if mode == "numeric_job" and self.profile == "numeric_continuation" and type(reader) is AuthorityNumericSourceReadV3:
            self.table,self.column_name="runtime_jobs","continuation_json"
            self.key_columns,self.key=("job_id",),(ref,)
            self.header_columns=("work_kind","operation_id","activity_id","bot_id","persona_id","phase","deadline_utc","lease_holder","lease_expires_utc","fence","cancel_epoch")
        elif mode == "cancel_job" and self.profile == "cancel_continuation":
            self.table,self.column_name="runtime_jobs","continuation_json"
            self.key_columns,self.key=("job_id",),(ref,)
            self.header_columns=("operation_id","activity_id","bot_id","persona_id","phase","work_kind",
                "deadline_utc","budget_ref","resource_ref","lease_holder","lease_expires_utc","fence","cancel_epoch")
        elif mode == "graph":
            self.atom_key = AtomKey.from_token(ref)
            types = {"episode": "memory.episode_provenance.v2", "drive": "d04.sourced_numeric_drive.v1",
                "checkpoint": "d04.numeric_checkpoint.v2", "job": "runtime.job"}
            if (self.profile not in types or self.atom_key.type_name != types[self.profile]
                    or NamespaceId.from_key(self.atom_key) != reader.namespace):
                raise AuthorityUnavailable("Numeric metadata graph type/namespace differs")
            self.table, self.column_name = "graph_atoms", "value"
            self.key_columns, self.key = ("token", "bot", "persona"), (ref, *reader.namespace.as_tuple)
            self.header_columns = ("revision", "valid", "value_cell_id")
        elif mode == "life":
            kinds = {"numeric_model_life_prepared":"prepared","before": "d04_before_v1", "context": "numeric_context_v1",
                "prepared": "numeric_prepared_v1", "paid": "numeric_paid_v1",
                "binding":"numeric_binding_v1","request":"numeric_request_v1","acquire_commit":"numeric_acquire_commit_v1",
                "native_trace":"numeric_trace_v1","native_baseline":"d04_interval_baseline_v1",
                "native_acceptance":"numeric_appraisal_acceptance_v1","native_life_adopted":"adopted_life",
                "native_life_experience":"experience","native_life_prepared":"prepared","native_life_accounting":"accounting_prepared",
                "native_life_action":"source_note_action"}
            if self.profile not in kinds:
                raise AuthorityUnavailable("Numeric metadata signed original kind differs")
            if self.profile in {"native_trace","native_baseline","native_acceptance","native_life_adopted","native_life_experience","native_life_prepared","native_life_accounting","native_life_action"}:
                from .current_life_numeric_native_read_v3 import require_native_numeric_metadata_selector_v3
                require_native_numeric_metadata_selector_v3(reader,identity)
            self.table, self.column_name = "graph_d11_life_originals_v1", "payload_json"
            self.key_columns = ("bot", "persona", "kind", "original_ref")
            self.key = (*reader.namespace.as_tuple, kinds[self.profile], ref)
            self.header_columns = ("producing_operation_id", "payload_digest", "signature")
        elif mode=="d04" and self.profile=="native_prepared":
            from .current_life_numeric_native_read_v3 import require_native_numeric_metadata_selector_v3
            require_native_numeric_metadata_selector_v3(reader,identity)
            self.table,self.column_name="graph_d04_originals_v3","payload_json"
            self.key_columns,self.key=("bot","persona","kind","original_ref"),(*reader.namespace.as_tuple,"numeric_prepared",ref)
            self.header_columns=("payload_digest",)
        elif mode=="native_grant" and self.profile=="native_grant":
            from .current_life_numeric_native_read_v3 import require_native_numeric_metadata_selector_v3
            require_native_numeric_metadata_selector_v3(reader,identity)
            self.table,self.column_name="runtime_budget_grants","grant_json"
            self.key_columns,self.key=("lease_id","version"),tuple(ref)
            self.header_columns=("signature",)
        elif mode == "quote" and self.profile=="quote":
            self.table,self.column_name="runtime_resource_quotes","quote_json"
            self.key_columns,self.key=("quote_id","version"),(ref,1)
            self.header_columns=("signature",)
        elif mode == "c04_cost" and self.profile == "c04_cost":
            self.table,self.column_name="d11_c04_cpu_cost_originals_v1","original_json"
            self.key_columns,self.key=("bot","persona","operation_id"),(*reader.namespace.as_tuple,ref)
            self.header_columns=("original_digest",)
        elif mode == "joint" and self.profile == "joint":
            self.table, self.column_name = "graph_d04_joint_numeric_originals_v1", "numeric_receipt_json"
            self.key_columns, self.key = ("bot", "persona", "operation_id"), (*reader.namespace.as_tuple, ref)
            self.header_columns = ("evidence_digest", "numeric_receipt_digest", "verification_digest")
        elif (mode, self.profile) in {("cancel_prepare", "cancel_prepare_commit"), ("numeric_prepare", "numeric_prepare_commit")}:
            self.table,self.column_name="graph_domain_production_originals_v1","original_payload_json"
            self.key_columns,self.key=("bot","persona","operation_id"),(*reader.namespace.as_tuple,ref)
            self.header_columns=("domain","operation_kind","original_digest","bundle_digest","receipt_digest")
        elif mode == "adoption" and self.profile == "adoption":
            self.table, self.column_name = "graph_domain_production_originals_v1", "original_payload_json"
            self.key_columns, self.key = ("bot", "persona", "operation_id"), (*reader.namespace.as_tuple, ref)
            self.header_columns = ("domain", "operation_kind", "original_digest", "bundle_digest", "receipt_digest")
        else:
            raise AuthorityUnavailable("unregistered Numeric fixed metadata selector")

    def require_header_v1(self, meter):
        self.reader.require_current(meter=meter)
        if self.reader.operation_kind in _NUMERIC_NATIVE_READ_OPERATIONS_V3:
            from .current_life_numeric_native_read_v3 import recheck_native_numeric_metadata_header_v3
            current=recheck_native_numeric_metadata_header_v3(self,meter)
        elif self.reader.operation_kind=="prepare_internal_life_numeric_drive":
            from .d06_life_numeric_drive_v1 import recheck_drive_numeric_metadata_header_v3
            current=recheck_drive_numeric_metadata_header_v3(self,meter)
        else:
            current = _runtime_bounded_fixed_row_v3(self.reader.db, meter, self.table, self.header_columns,
                " AND ".join(name+"=?" for name in self.key_columns), self.key)
        if current != self.metadata:
            raise AuthorityUnavailable("Numeric metadata original head changed across actual EOF")
        return self

    def advance(self, meter):
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        r = require_numeric_owner_metadata_work_v1(self.reader)
        if self.complete:
            self.require_header_v1(meter)
            return True
        if self.phase == "header":
            self.metadata = _runtime_bounded_fixed_row_v3(r.db, meter, self.table, self.header_columns,
                " AND ".join(name+"=?" for name in self.key_columns), self.key)
            if self.metadata is None:
                if self.identity[0]=="c04_cost":
                    self.complete=True;self.result=None;return True
                raise AuthorityUnavailable("Numeric actual metadata original is unavailable")
            cell = None
            if self.identity[0] == "graph":
                if self.metadata[0] < 1 or self.metadata[1] != 1:
                    raise AuthorityUnavailable("Numeric metadata needs its actual positive valid graph head")
                if self.metadata[2] is not None:
                    cell = begin_runtime_cell_read_v3(r.db, self.metadata[2], erasure_owner_ref=self.key[0])
            if self.profile=="native_prepared":
                from .current_life_numeric_native_read_v3 import NumericNativePreparedMetadataColumnV3
                self.column=NumericNativePreparedMetadataColumnV3(self,cell=cell)
            elif self.profile=="request":
                from .current_life_numeric_read_v3 import NumericRequestEnvelopeMetadataColumnV3
                self.column=NumericRequestEnvelopeMetadataColumnV3(self,cell=cell)
            else:self.column = _NumericMetadataColumnV1(self, cell=cell)
            self.phase = "bytes"
            return False
        self.require_header_v1(meter)
        if not self.column.advance(meter):
            return False
        value = _detach_value_v3(self.column.frozen)
        mode = self.identity[0]
        if mode == "life":
            from .d11_life_preparation_v1 import SIGN_KIND
            if self.column.canonical_digest != self.metadata[1]:
                raise AuthorityUnavailable("Numeric signed metadata whole original digest differs")
            _numeric_metadata_issuers_v3(r)[0]._signer.verify(SIGN_KIND,
                canonical_serialize((r.namespace, self.key[2], self.key[3], self.metadata[1])), self.metadata[2])
            producer = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_bundle_operations", ("commit_seq",),
                "bot=? AND persona=? AND operation_id=?", (*r.namespace.as_tuple, self.metadata[0]))
            if producer is None or producer[0] < 1:
                raise AuthorityUnavailable("Numeric signed metadata lacks its actual committed producer")
            if self.profile in {"native_trace","native_baseline","native_acceptance","native_life_adopted","native_life_experience","native_life_prepared","native_life_accounting","native_life_action"}:
                from .current_life_numeric_native_read_v3 import require_native_numeric_metadata_eof_v3
                require_native_numeric_metadata_eof_v3(self)
        elif mode=="d04":
            if self.column.canonical_digest!=self.metadata[0]:
                raise AuthorityUnavailable("Numeric Native prepared whole canonical original EOF differs")
            from .current_life_numeric_native_read_v3 import require_native_numeric_metadata_eof_v3
            require_native_numeric_metadata_eof_v3(self)
        elif mode=="native_grant":
            raw=canonical_serialize(value)
            if canonical_digest(value)!=self.column.canonical_digest:
                raise AuthorityUnavailable("Numeric Native grant differs from actual canonical whole EOF")
            r.graph._GraphCoordinator__d11_issuer._signer.verify("budget-grant.v1",raw,self.metadata[0])
        elif mode=="quote":
            raw=canonical_serialize(value)
            if canonical_digest(value)!=self.column.canonical_digest:
                raise AuthorityUnavailable("Numeric quote metadata differs from its exact actual canonical EOF")
            _numeric_metadata_issuers_v3(r)[1]._signer.verify("resource-quote.v1",raw,self.metadata[0])
        elif mode == "c04_cost":
            if (self.column.canonical_digest!=self.metadata[0] or NamespaceId(**value["namespace"])!=r.namespace
                    or value["operation_id"]!=self.key[-1]):
                raise AuthorityUnavailable("Numeric C04 cost metadata differs from its actual canonical original")
        elif mode == "joint":
            if (value["receipt_digest"]!=self.metadata[1] or self.column.receipt_fields_digest!=self.metadata[1]
                    or value["status"]!="unsigned_hold_for_w01_atomic_joint_adoption"):
                raise AuthorityUnavailable("Numeric actual receipt fields digest differs from its committed original")
            advance = _runtime_bounded_fixed_row_v3(r.db,meter,"graph_d04_joint_advances_v2",
                ("evidence_digest","bundle_digest"),"bot=? AND persona=? AND operation_id=?",self.key)
            producer = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_bundle_operations", ("digest","commit_seq"),
                "bot=? AND persona=? AND operation_id=?", self.key)
            if (advance is None or advance[0]!=self.metadata[0] or producer is None
                    or producer[0]!=advance[1] or producer[1]<1):
                raise AuthorityUnavailable("Numeric receipt metadata differs from its actual committed joint evidence")
        elif mode in {"cancel_prepare", "numeric_prepare"}:
            if (self.metadata[:2]!=("d11","prepare_internal_life_numeric") or self.column.canonical_digest!=self.metadata[2]):
                raise AuthorityUnavailable("D12 actual Numeric prepare metadata canonical original differs")
            producer=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",("digest","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",self.key)
            if producer is None or producer[0]!=self.metadata[3] or producer[1]<1:
                raise AuthorityUnavailable("D12 actual Numeric prepare metadata has no committed bundle")
        elif mode == "adoption":
            if (self.metadata[:2] != ("d04", "adopt_internal_life_numeric")
                    or self.column.canonical_digest != self.metadata[2]):
                raise AuthorityUnavailable("Numeric actual appraisal adoption metadata differs")
            producer = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_bundle_operations",
                ("digest", "commit_seq"), "bot=? AND persona=? AND operation_id=?",
                (*r.namespace.as_tuple, self.key[-1]))
            if producer is None or producer[0] != self.metadata[3] or producer[1] < 1:
                raise AuthorityUnavailable("Numeric actual appraisal adoption has no matching committed bundle")
        self.result = _freeze_value_v3(value)
        self.complete = True
        return True

def _metadata(reader, mode, profile, ref):
    identity = (mode, profile, ref)
    task = reader.attachments.get(("numeric_owner_metadata", identity))
    if task is None or not task.complete:
        _need_method_input(reader, ("numeric_owner_metadata", identity))
    if task.reader is not reader or task.identity != identity:
        raise AuthorityUnavailable("Numeric metadata crossed its actual selected Work")
    with runtime_storage_quantum_v3(reader.db) as meter:
        task.require_header_v1(meter)
    return _detach_value_v3(task.result), task

def _numeric_paid_operations_v3():
    from .current_method_learning_read_v3 import _NUMERIC_PAID_WRITE_OPERATIONS_V3
    return _NUMERIC_PAID_WRITE_OPERATIONS_V3

def prepare_numeric_metadata_plan_v1(reader):
    from .d06_internal_life_episode_v2 import EPISODE, PROVENANCE
    from .d04_life_before_original_v1 import life_d04_before_ref_v1
    from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1
    from .d01_production_operations_v1 import production_read_plan_v1
    r = require_numeric_owner_metadata_work_v1(reader)
    if reader in _METADATA_PLANS:
        plan, expectations, tasks = _METADATA_PLANS[reader]
        for task in tasks:
            with runtime_storage_quantum_v3(r.db) as meter:
                task.require_header_v1(meter)
        return plan, expectations
    episode = AtomKey.from_token(r.request.episode_ref)
    if episode.type_name != EPISODE or NamespaceId.from_key(episode) != r.namespace:
        raise AuthorityUnavailable("Numeric metadata requires its actual Episode namespace")
    proof, proof_task = _metadata(r, "graph", "episode", AtomKey(episode.owner, PROVENANCE, "record").token)
    event, activity = proof["event"], proof["event"]["activity"]
    if (proof["episode"]["episode_ref"] != episode.token or NamespaceId(**event["namespace"]) != r.namespace
            or event["causal_operation_id"] != r.request.causal_operation_id
            or r.operation_kind not in (_NUMERIC_READ_ONLY_OPERATIONS_V3 | _numeric_paid_operations_v3()) and activity["activity_id"] != r.activity_id
            or proof["episode"]["source_refs"] != [activity["source_ref"]]):
        raise AuthorityUnavailable("Numeric metadata actual occurrence/cause/activity differs")
    if r.operation_kind in _NUMERIC_READ_ONLY_OPERATIONS_V3:
        if r.numeric_native_activity_id is not None and r.numeric_native_activity_id!=activity["activity_id"]:
            raise AuthorityUnavailable("Numeric trace READ activity differs from actual episode occurrence")
        r.activity_id=activity["activity_id"]
    elif r.operation_kind in _numeric_paid_operations_v3():
        r.activity_id=activity["activity_id"]
    roots, expectations, tasks = {activity["source_ref"]}, {}, [proof_task]
    for row in proof["current_reads"]:
        key = AtomKey.from_token(row["ref"])
        if NamespaceId.from_key(key) != r.namespace:
            raise AuthorityUnavailable("Numeric actual occurrence version crossed namespace")
        if key.type_name == "memory.source":
            roots.add(key.token)
            _expect(expectations, key.token, row["revision"])
    before_ref = life_d04_before_ref_v1(r.namespace, activity["execution_id"])
    before, task = _metadata(r, "life", "before", before_ref)
    tasks.append(task)
    if (NamespaceId(**before["namespace"]) != r.namespace or before["original_ref"] != before_ref
            or before["execution_id"] != activity["execution_id"]):
        raise AuthorityUnavailable("Numeric signed Before/Root metadata differs")
    roots.update(before["source_roots"])
    if r.operation_kind in {"prepare_internal_life_numeric_drive", "prepare_internal_life_numeric_joint","read_current_life_numeric_joint_prepared_v3"}:
        appraisal = AtomKey.from_token(r.request.appraisal_ref)
        if appraisal.type_name != "d04.appraisal_bundle.v1" or NamespaceId.from_key(appraisal) != r.namespace:
            raise AuthorityUnavailable("Numeric actual appraisal locator crossed namespace")
        with runtime_storage_quantum_v3(r.db) as meter:
            history = _runtime_bounded_fixed_row_v3(r.db, meter, "graph_history", ("event_id", "valid"),
                "token=? AND revision=1 AND event_bot=? AND event_persona=?", (appraisal.token, *r.namespace.as_tuple))
        if history is None or history[1] != 1:
            raise AuthorityUnavailable("Numeric actual appraisal adoption metadata is unavailable")
        adopted, adopted_task = _metadata(r, "adoption", "adoption", history[0])
        tasks.append(adopted_task)
        if adopted["identity"]["phase"] != "adopt_internal_life_numeric":
            raise AuthorityUnavailable("Numeric actual appraisal adoption clock belongs to another phase")
        for member in before["members"]:
            _, checkpoint_task = _metadata(r, "graph", "checkpoint", member["checkpoint"]["ref"])
            tasks.append(checkpoint_task)
    if r.operation_kind != "prepare_internal_life_numeric_context":
        ref = life_numeric_context_ids_v1(r.namespace, episode.token)["original"]
        context, task = _metadata(r, "life", "context", ref)
        tasks.append(task)
        if (NamespaceId(**context["namespace"]) != r.namespace or context["episode_ref"] != episode.token
                or context["source_ref"] != activity["source_ref"] or context["before_ref"] != before_ref):
            raise AuthorityUnavailable("Numeric actual context/occurrence/Before Source differs")
        roots.add(context["source_ref"])
        _expect(expectations, context["source_ref"], context["source_revision"])
        if r.operation_kind in ({"acquire_internal_life_numeric", "adopt_internal_life_numeric","read_current_life_numeric_model_draft_v3","qualify_current_life_numeric_candidate_v3"} | _numeric_paid_operations_v3()):
            from ..model_broker.internal_life_numeric_v1 import InternalLifeNumericIdentityV1, internal_life_numeric_ids_v1
            identity = InternalLifeNumericIdentityV1(r.namespace, episode.token, context["execution_id"],
                context["source_ref"], context["occurrence_digest"], context["before_digest"], task.column.canonical_digest)
            ids = internal_life_numeric_ids_v1(identity)
            prepared, prepared_task = _metadata(r, "life", "prepared", ids["job"])
            tasks.append(prepared_task)
            from .d11_types import runtime_job_key
            job, job_task = _metadata(r, "graph", "job",
                runtime_job_key(*r.namespace.as_tuple, r.activity_id, ids["job"]).token)
            tasks.append(job_task)
            if job["job_id"] != ids["job"]:
                raise AuthorityUnavailable("Numeric actual current job metadata changed its once identity")
            from ..domains.d01.production_operations_v1 import plain_v1
            if ((prepared["job_id"], prepared["call_id"], prepared["quote_id"], prepared["activity_id"]) != (
                    ids["job"], ids["call"], ids["quote"], r.activity_id)
                    or prepared["frozen"]["identity"] != plain_v1(identity)
                    or tuple(prepared["audience"]) != tuple(r.authority.audience)):
                raise AuthorityUnavailable("Numeric prepared job/call/quote/activity/source/audience metadata differs")
            for row in prepared["read_rows"]:
                if AtomKey.from_token(row["ref"]).type_name == "memory.source":
                    roots.add(row["ref"])
                    _expect(expectations, row["ref"], row["revision"])
            if r.operation_kind in {"read_current_life_numeric_model_draft_v3","qualify_current_life_numeric_candidate_v3"}:
                from .current_life_numeric_read_v3 import prepare_numeric_draft_metadata_v3
                more_roots,more_versions,more_tasks=prepare_numeric_draft_metadata_v3(r,identity,prepared,prepared_task)
                roots.update(more_roots)
                for ref,revision in more_versions.items():_expect(expectations,ref,revision)
                tasks.extend(more_tasks)
            if r.operation_kind == "adopt_internal_life_numeric":
                paid, paid_task = _metadata(r, "life", "paid", ids["job"])
                tasks.append(paid_task)
                if (paid["prepared_digest"] != prepared_task.column.canonical_digest
                        or paid["result"]["request"]["job_id"] != ids["job"]
                        or paid["result"]["request"]["call_id"] != ids["call"]):
                    raise AuthorityUnavailable("Numeric paid metadata has another actual preparation/job/call")
    if r.operation_kind in {"prepare_internal_life_interval_baseline", "adopt_internal_life_numeric_trace"}:
        candidate, task = _metadata(r, "joint", "joint", r.request.joint_operation_id)
        tasks.append(task)
        if NamespaceId(**candidate["namespace"]) != r.namespace:
            raise AuthorityUnavailable("Numeric actual candidate crossed namespace")
        for item in candidate["source_versions"]:
            if len(item) != 7:
                raise AuthorityUnavailable("Numeric actual candidate source-version shape differs")
            drive_ref, drive_revision, source_ref, source_revision, access_ref, access_revision, _family_ref = item
            drive, drive_task = _metadata(r, "graph", "drive", drive_ref)
            tasks.append(drive_task)
            if (drive_task.metadata[0], drive["source_ref"], drive["source_revision"]) != (
                    drive_revision, source_ref, source_revision):
                raise AuthorityUnavailable("Numeric actual candidate drive/Source revision differs")
            from ..memory_types import access_key
            source_key=AtomKey.from_token(source_ref)
            expected_access=access_key(*r.namespace.as_tuple,source_key.owner.subject).token
            if access_ref!=expected_access or type(access_revision)is not int or access_revision<1:
                raise AuthorityUnavailable("Numeric actual candidate access locator/revision differs")
            roots.add(source_ref)
            _expect(expectations, source_ref, source_revision)
            _expect(expectations,access_ref,access_revision)
    if r.operation_kind in {"read_current_life_numeric_joint_prepared_v3","read_current_life_numeric_trace_v3"}:
        from .current_life_numeric_native_read_v3 import prepare_native_numeric_read_metadata_v3
        more_roots,more_versions,more_tasks=prepare_native_numeric_read_metadata_v3(r)
        roots.update(more_roots)
        for ref,revision in more_versions.items():_expect(expectations,ref,revision)
        tasks.extend(more_tasks)
    keys = tuple(AtomKey.from_token(row["ref"]) for row in proof["current_reads"])
    plan = production_read_plan_v1((), keys, tuple(sorted(roots)), ())
    r.operation.retain(_heap((plan, expectations, tuple(tasks))) + 1024)
    expectations = MappingProxyType(dict(expectations))
    _METADATA_PLANS[r] = (plan, expectations, tuple(tasks))
    return plan, expectations

def _expect(expectations, ref, revision):
    if ref in expectations and expectations[ref] != revision:
        raise AuthorityUnavailable("Numeric signed Source version expectations disagree")
    expectations[ref] = revision

class NumericSourcePermissionV1:
    def __init__(self, reader, plan, versions, source_refs, purposes):
        self.reader, self.plan = reader, plan
        self.versions, self.source_refs, self.purposes = versions, source_refs, purposes
        self.owner_entry = reader.general_owner_entry
        _SOURCE_PROOFS[self] = (reader, reader.work, reader.operation, reader.selection_digest,
            reader.fence.scope, reader.authority, plan, versions, source_refs, purposes, self.owner_entry)

    def require_for_v1(self, reader):
        expected = (reader, reader.work, reader.operation, reader.selection_digest,
            reader.fence.scope, reader.authority, self.plan, self.versions, self.source_refs,
            self.purposes, reader.general_owner_entry)
        if (_SOURCE_PROOFS.get(self) != expected or reader.numeric_source_permission is not self
                or _METADATA_PLANS.get(reader, (None,))[0] != self.plan):
            raise AuthorityUnavailable("Numeric protected input lacks its private actual completed Source certificate")
        reader.require_current()
        if reader.selected_plan is not None and not set(reader.selected_plan.source_roots) <= set(self.source_refs):
            raise AuthorityUnavailable("Numeric selected protected plan added an unqualified Source root")
        if reader.read_finished:
            from .current_method_learning_read_v3 import _require_current_general_method_source_write_phase_v1
            _require_current_general_method_source_write_phase_v1(reader)
        else:
            self.owner_entry.require_for_v3(reader)
        with runtime_storage_quantum_v3(reader.db) as meter:
            for ref in self.source_refs:
                _GENERAL_METHOD_SOURCE_TASKS_V1[reader][ref].require_v1(reader, meter)
            for version in self.versions:
                row = meter.read_fixed_row(reader.db, "graph_atoms", ("revision",),
                    "token=? AND bot=? AND persona=?", (version.key.token, *reader.namespace.as_tuple))
                if (0 if row is None else row[0]) != version.revision:
                    raise AuthorityUnavailable("Numeric completed Source/access/correction version changed")
            for task in _METADATA_PLANS[reader][2]:
                task.require_header_v1(meter)
        return self

def require_numeric_method_sources_v1(reader):
    from .current_method_learning_read_v3 import qualify_method_source_metadata_kernel_v1
    r = require_numeric_owner_metadata_work_v1(reader)
    if r.numeric_source_permission is not None:
        return r.numeric_source_permission.require_for_v1(r)
    plan, expectations = prepare_numeric_metadata_plan_v1(r)
    if r.authority.purpose not in {"context", "consolidation"} or not r.authority.audience:
        raise AuthorityUnavailable("Numeric metadata consumer purpose/audience differs from its actual closed recipe")
    if r.general_owner_entry is None:
        raise AuthorityUnavailable("Numeric Source metadata requires its independent Owner EOF")
    r.general_owner_entry.require_for_v3(r)
    purposes = tuple(dict.fromkeys((r.authority.purpose, "consolidation")))
    records, versions = qualify_method_source_metadata_kernel_v1(r, plan.source_roots, purposes=purposes)
    for ref, revision in expectations.items():
        key=AtomKey.from_token(ref)
        actual=versions.get(key)
        if actual is None or actual.revision!=revision:
            raise AuthorityUnavailable("Numeric actual Source/access version expectation differs from completed current EOF")
    result = NumericSourcePermissionV1(r, plan,
        tuple(sorted(versions.values(), key=lambda item: item.key.token)), tuple(sorted(records)), purposes)
    r.numeric_source_permission = result
    return result.require_for_v1(r)

def require_numeric_method_body_v1(reader, table, key):
    if reader.operation_kind not in _NUMERIC_METADATA_OPERATIONS_V3:
        return
    if table == "runtime_budget_grants":
        return
    if table == "graph_atoms":
        from ..graph_types import owner_grant_key
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        atom = AtomKey.from_token(key[0])
        subject = atom.owner.subject or ""
        if atom in {owner_grant_key(*reader.namespace.as_tuple), access_key(*reader.namespace.as_tuple, subject),
                source_correction_head_key(reader.namespace, subject)}:
            return
    if reader.numeric_source_permission is None:
        raise AuthorityUnavailable("Numeric protected original/model output requires ALL actual Source/ancestor metadata EOF")
    proof = reader.numeric_source_permission.require_for_v1(reader)
    if table in {"graph_atoms","graph_history"}:
        atom = AtomKey.from_token(key[0])
        if atom.type_name == "memory.source" and atom.token not in proof.source_refs:
            raise AuthorityUnavailable("Numeric Source body escaped the actual completed all-parent closure")

_C04_SELECTIONS=WeakKeyDictionary()

class NumericC04SelectorTaskV1:
    def __init__(self,reader,plan):
        self.reader=require_numeric_owner_metadata_work_v1(reader)
        self.plan=plan;self.requested=frozenset(plan.required_original_refs)
        self.cursor="";self.count=0;self.child=None;self.pending=None
        self.headers={};self.cost_tasks={};self.selected={}
        self.complete=False
        from .d01_production_operations_v1 import table_exists_v1
        self.cost_table=table_exists_v1(reader.db,"d11_c04_cpu_cost_originals_v1")

    def advance(self,meter):
        r=require_numeric_owner_metadata_work_v1(self.reader)
        if self.complete:return True
        if self.child is not None:
            if not self.child.advance(meter):return False
            operation,binding,prepared=self.pending
            self.cost_tasks[operation]=self.child
            if self.child.result is not None:
                cost=_detach_value_v3(self.child.result)
                if (cost["binding_digest"],cost["prepared_digest"])!=(binding,prepared):
                    raise AuthorityUnavailable("Numeric C04 metadata cost/preparation commitments differ")
                if cost["terminal_receipt_ref"] in self.requested:
                    self.selected[operation]=(binding,prepared)
            self.child=None;self.pending=None;return False
        row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_c04_internal_work_prepared_v1",
            ("operation_id","binding_digest","prepared_digest"),
            "bot=? AND persona=? AND operation_id>? ORDER BY operation_id",(*r.namespace.as_tuple,self.cursor))
        if row is None:
            self.complete=True;self.selected=MappingProxyType(dict(self.selected))
            _C04_SELECTIONS[r]=(self,self.plan,r.work,r.operation,r.selection_digest,self.selected)
            return True
        self.count+=1
        if self.count>128:raise AuthorityUnavailable("Numeric C04 original metadata exceeds its complete original 128-row bound")
        operation,binding,prepared=row
        self.cursor=operation;self.headers[operation]=(binding,prepared)
        r.operation.retain(_heap(row)+1024)
        if "internal-work:component:"+binding in self.requested:self.selected[operation]=(binding,prepared)
        if self.cost_table:
            self.pending=row
            self.child=NumericMetadataTaskV1(r,("c04_cost","c04_cost",operation))
        return False

    def require_for_v1(self,reader,plan):
        expected=(self,plan,reader.work,reader.operation,reader.selection_digest,self.selected)
        if (self.reader is not reader or not self.complete or self.plan!=plan
                or _C04_SELECTIONS.get(reader)!=expected
                or reader.selected_plan is not None and reader.selected_plan!=plan):
            raise AuthorityUnavailable("Numeric C04 original selector is not its actual complete fixed metadata recipe")
        reader.require_current()
        reader.numeric_source_permission.require_for_v1(reader)
        with runtime_storage_quantum_v3(reader.db)as meter:
            cursor=""
            for operation,expected_header in self.headers.items():
                actual=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_c04_internal_work_prepared_v1",
                    ("operation_id","binding_digest","prepared_digest"),
                    "bot=? AND persona=? AND operation_id>? ORDER BY operation_id",(*reader.namespace.as_tuple,cursor))
                if actual!=(operation,*expected_header):raise AuthorityUnavailable("Numeric complete C04 metadata inventory changed")
                cursor=operation
                if operation in self.cost_tasks:self.cost_tasks[operation].require_header_v1(meter)
            tail=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_c04_internal_work_prepared_v1",("operation_id",),
                "bot=? AND persona=? AND operation_id>? ORDER BY operation_id",(*reader.namespace.as_tuple,cursor))
            if tail is not None:raise AuthorityUnavailable("Numeric complete C04 negative metadata coverage changed")
        return self

def read_numeric_c04_original_requests_v1(db,namespace,plan):
    reader=_method_active(db)
    if reader is None or reader.operation_kind not in NUMERIC_OWNER_OPERATIONS_V1:return False,None
    if namespace!=reader.namespace:raise AuthorityUnavailable("Numeric C04 originals crossed namespace")
    identity=("numeric_c04_selection",plan)
    task=reader.attachments.get(identity)
    if task is None or not task.complete:_need_method_input(reader,identity)
    task.require_for_v1(reader,plan)
    from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
    from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
    from .domain_production_read_plans_v1 import C04IndependentOriginalReadRequestV1
    result=[]
    for operation in task.selected:
        prepared=read_c04_internal_work_prepared_v1(db,namespace,operation)
        cost=read_c04_cpu_cost_original_v1(db,namespace,operation)
        result.append(C04IndependentOriginalReadRequestV1(prepared.binding,
            "internal-work:component:"+prepared.binding.binding_digest,cost.proof_digest if cost else None,
            cost.terminal_receipt_ref if cost else None,cost.terminal_receipt_digest if cost else None))
    return True,tuple(result)

def require_numeric_c04_original_selector_v1(reader,request):
    record=_C04_SELECTIONS.get(reader)
    if record is None:raise AuthorityUnavailable("Numeric C04 original requires its complete actual metadata selector")
    task=record[0];task.require_for_v1(reader,task.plan)
    table,columns,key_columns,key=request
    expected_shape=(
        ("graph_c04_internal_work_prepared_v1",("binding_digest","prepared_digest","prepared_json")),
        ("d11_c04_cpu_cost_originals_v1",("original_json","original_digest")))
    if ((table,tuple(columns)) not in expected_shape or tuple(key_columns)!=("bot","persona","operation_id")
            or tuple(key[:2])!=reader.namespace.as_tuple or len(key)!=3 or key[-1] not in task.selected):
        raise AuthorityUnavailable("Numeric C04 original escaped its actual selected current plan/namespace/operation")
    return task

def release_numeric_metadata_payloads_v1(reader):
    _METADATA_PLANS.pop(reader,None)
    _C04_SELECTIONS.pop(reader,None)
    if reader.numeric_source_permission is not None:
        _SOURCE_PROOFS.pop(reader.numeric_source_permission,None)
        reader.numeric_source_permission=None
    for column,(owner,task,profile) in tuple(_COLUMNS.items()):
        if owner is reader:
            _COLUMNS.pop(column,None)

def require_bound_numeric_plan_v1(db, operation_kind):
    reader = _method_active(db)
    if reader is None or operation_kind not in NUMERIC_OWNER_OPERATIONS_V1:
        return None
    if reader.operation_kind != operation_kind:
        raise AuthorityUnavailable("Numeric operation plan crossed its actual originating recipe")
    return require_numeric_method_sources_v1(reader)
