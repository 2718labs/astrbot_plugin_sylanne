"""Fixed Life model body IO and lineage metadata, without a Source grant."""
from __future__ import annotations
from dataclasses import dataclass
import json
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_serialize
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2

GRAPH_BODY = "life_model.graph_body.v3"
ARTIFACT_BODY = "life_model.artifact_body.v3"
ACTION_LOCATOR = "life_model.source_note_action_locator.v3"
_ARTIFACT_COLUMNS = ("binding_digest","artifact_ref","artifact_digest","artifact_length")
_ACTION_COLUMNS = ("original_ref","payload_digest","signature")


def require_life_model_body_request_v3(work, request):
    if request[0] not in {GRAPH_BODY, ARTIFACT_BODY, ACTION_LOCATOR} or len(request) != 5:
        raise AuthorityUnavailable("Life model body IO requires its closed fixed recipe")
    from .internal_life_model_source_read_v3 import require_internal_life_model_body_request_v3
    if require_internal_life_model_body_request_v3(work, request):
        return
    from .life_numeric_source_read_v3 import require_numeric_life_model_body_request_v3
    if require_numeric_life_model_body_request_v3(work, request):
        return
    from .artifact_model_source_read_v3 import require_artifact_model_body_request_v3
    if request[0]==GRAPH_BODY and require_artifact_model_body_request_v3(work,request):return
    raise AuthorityUnavailable("Life model body IO has no actual independent caller capability")


def _artifact_request_v3(work, execution_id):
    return (ARTIFACT_BODY,"graph_d11_life_artifact_stage_v1",_ARTIFACT_COLUMNS,
        ("bot","persona","execution_id"),(*work.namespace.as_tuple,execution_id))


def _action_request_v3(work, action_ref):
    return (ACTION_LOCATOR,"graph_d11_life_originals_v1",_ACTION_COLUMNS,
        ("bot","persona","kind","action_intent_ref"),
        (*work.namespace.as_tuple,"source_note_action",action_ref))


def _artifact_descriptor_v3(work, execution_id):
    from .internal_life_model_source_read_v3 import internal_life_model_artifact_descriptor_v3
    handled, descriptor = internal_life_model_artifact_descriptor_v3(work, execution_id)
    if handled:
        return descriptor
    from .life_numeric_source_read_v3 import numeric_life_model_artifact_descriptor_v3
    handled, descriptor = numeric_life_model_artifact_descriptor_v3(work, execution_id)
    if handled:
        return descriptor
    raise AuthorityUnavailable("Life artifact IO has no actual caller's signed descriptor")


def _accept_action_locator_v3(work, action_ref, original_ref, column, metadata):
    from .internal_life_model_source_read_v3 import internal_life_model_action_locator_eof_v3
    if internal_life_model_action_locator_eof_v3(work,action_ref,original_ref,column,metadata):
        return
    from .life_numeric_source_read_v3 import numeric_life_model_action_locator_eof_v3
    if numeric_life_model_action_locator_eof_v3(work,action_ref,original_ref,column,metadata):
        return
    raise AuthorityUnavailable("Life Action locator EOF has no actual independent receiver")


def register_life_model_signed_body_v3(db, kind, original_ref, raw, producer):
    from .artifact_model_original_family_v3 import register_artifact_signed_original_v3
    if register_artifact_signed_original_v3(db,kind,original_ref,raw,producer):return
    from .internal_life_model_source_read_v3 import register_internal_life_signed_original_v3
    if register_internal_life_signed_original_v3(db,kind,original_ref,raw,producer):
        return
    from .life_numeric_source_read_v3 import register_numeric_life_model_signed_body_v3
    register_numeric_life_model_signed_body_v3(db,kind,original_ref,raw,producer)


def register_life_model_prepared_body_v3(db, prepared):
    from .internal_life_model_source_read_v3 import register_internal_life_prepared_body_v3
    if register_internal_life_prepared_body_v3(db,prepared):
        return
    from .life_numeric_source_read_v3 import register_numeric_life_model_prepared_body_v3
    register_numeric_life_model_prepared_body_v3(db,prepared)


@dataclass(frozen=True, slots=True)
class LifeModelFamilyLocatorV3:
    parent_kind: str
    parent_ref: str
    parent_digest: str
    parent_producer: str
    field_path: tuple
    recipe: tuple


@dataclass(frozen=True, slots=True)
class LifeModelOriginalFamilyPlanV3:
    namespace: object
    operations: tuple
    original_refs: tuple
    job_ids: tuple
    execution_ids: tuple
    quote_versions: tuple
    body_quote_versions: tuple
    action_refs: tuple
    artifact_descriptors: tuple
    locators: tuple


def life_model_family_plan_from_prepared_v3(prepared, parent_kind, parent_ref, parent_digest, parent_producer):
    """Metadata derivation only; each caller validates the signed parent and accepts its keys."""
    from ..runtime.d11_life_contract_v1 import LifeBodyComponentContractV1, life_adoption_operation_id_v1
    from ..runtime.d11_life_accounting_v1 import life_accounting_original_ref_v1
    from .current_authority_graph_read_v3 import _AUTHORITY_JOB_FIELDS_V3
    binding = prepared.binding
    contract = LifeBodyComponentContractV1(**json.loads(prepared.plan.body_effect_request_json))
    operations = (binding.operation_id,binding.reservation_operation_id,
        prepared.prepare_operation_id,life_adoption_operation_id_v1(binding),contract.body_prepare_operation_id)
    original_refs = (binding.prepared_original_ref,binding.execution_id,binding.artifact_ref,
        life_accounting_original_ref_v1(binding),"life-body:"+contract.body_prepare_operation_id)
    quote_versions = ((binding.quote_id,binding.quote_version),
        (contract.resource_quote_ref,contract.resource_quote_version))
    parent = (parent_kind,parent_ref,parent_digest,parent_producer)
    locators = [
        LifeModelFamilyLocatorV3(*parent,("binding","job_id"),
            ("life_model.job_body.v3","runtime_jobs",_AUTHORITY_JOB_FIELDS_V3,("job_id",),(binding.job_id,))),
        LifeModelFamilyLocatorV3(*parent,("binding","execution_id"),
            (ARTIFACT_BODY,"graph_d11_life_artifact_stage_v1",_ARTIFACT_COLUMNS,
                ("bot","persona","execution_id"),(*binding.namespace.as_tuple,binding.execution_id))),
        LifeModelFamilyLocatorV3(*parent,("plan","action_intent","ref"),
            (ACTION_LOCATOR,"graph_d11_life_originals_v1",_ACTION_COLUMNS,
                ("bot","persona","kind","action_intent_ref"),
                (*binding.namespace.as_tuple,"source_note_action",prepared.plan.action_intent.ref))),
        LifeModelFamilyLocatorV3(*parent,("plan","body_effect_request_json","body_quote_ref"),
            ("life_model.body_quote.v3","d02_body_quotes_v1",
                ("quote_version","policy_id","policy_version","operation_id","resource_quote_digest","body_quote_json","signature"),
                ("bot","persona","quote_id"),(*binding.namespace.as_tuple,contract.body_quote_ref))),
    ]
    operation_paths = (
        ("binding","operation_id"),("binding","reservation_operation_id"),
        ("prepare_operation_id",),("derived","life_adoption_operation_id_v1","binding"),
        ("plan","body_effect_request_json","body_prepare_operation_id"))
    for operation, path in zip(operations, operation_paths):
        locators.append(LifeModelFamilyLocatorV3(*parent,path,
            ("life_model.commit_body.v3","graph_bundle_operations",("receipt_json",),
                ("bot","persona","operation_id"),(*binding.namespace.as_tuple,operation))))
    original_paths = (
        ("binding","prepared_original_ref"),("binding","execution_id"),("binding","artifact_ref"),
        ("derived","life_accounting_original_ref_v1","binding"),
        ("derived","life-body-prefix","plan","body_effect_request_json","body_prepare_operation_id"))
    original_kinds = ("prepared","adoption_bridge","adopted_life","accounting_prepared","life_body_preparation")
    for original_ref, kind, path in zip(original_refs,original_kinds,original_paths):
        locators.append(LifeModelFamilyLocatorV3(*parent,path,
            ("life_model.signed_original.v3","graph_d11_life_originals_v1",
                ("producing_operation_id","payload_json","payload_digest","signature"),
                ("bot","persona","kind","original_ref"),(*binding.namespace.as_tuple,kind,original_ref))))
    for index, (quote_id,version) in enumerate(quote_versions):
        path = ("binding","quote_id") if index == 0 else ("plan","body_effect_request_json","resource_quote_ref")
        locators.append(LifeModelFamilyLocatorV3(*parent,path,
            ("life_model.resource_quote.v3","runtime_resource_quotes",("quote_json","signature"),
                ("quote_id","version"),(quote_id,version))))
    return LifeModelOriginalFamilyPlanV3(binding.namespace,operations,original_refs,
        (binding.job_id,),(binding.execution_id,),quote_versions,
        ((contract.body_quote_ref,contract.body_quote_version),),(prepared.plan.action_intent.ref,),
        ((binding.execution_id,binding.digest,binding.artifact_ref),),tuple(locators))


class _LifeModelArtifactBodyReadV3:
    def __init__(self, work, request):
        from ..runtime.d11_life_source_note_v1 import STAGE_TABLE
        require_life_model_body_request_v3(work, _artifact_request_v3(work, request[1]))
        self.work, self.request, self.table = work, request, STAGE_TABLE
        self.key = (*work.namespace.as_tuple, request[1])
        self.phase = "metadata"
        self.metadata = None
        self.data = bytearray()
        self.offset = 0
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.complete = False
        self.row = None
    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2, legacy_cell_read_transaction_v2
        require_life_model_body_request_v3(self.work, _artifact_request_v3(self.work, self.request[1]))
        if self.phase == "metadata":
            self.metadata = _runtime_bounded_fixed_row_v3(self.work.db, meter, self.table,
                ("binding_digest","artifact_ref","artifact_digest","artifact_length"),
                "bot=? AND persona=? AND execution_id=?", self.key)
            descriptor = _artifact_descriptor_v3(self.work, self.request[1])
            if (self.metadata is None or self.metadata != descriptor
                    or not 1 <= self.metadata[3] <= 262144):
                raise AuthorityUnavailable("InternalLife actual durable artifact changed its signed Life descriptor")
            self.work.operation.retain(24 * self.metadata[3] + 65536)
            self.phase = "bytes"
            return
        if self.offset < self.metadata[3]:
            with legacy_cell_read_transaction_v2(self.work.db):
                raw, total, kind = read_legacy_sql_cell_fragment_v2(self.work.db,
                    table=self.table, column="artifact_bytes",
                    where="bot=? AND persona=? AND execution_id=?", parameters=self.key,
                    start=self.offset, length=min(16384, self.metadata[3]-self.offset), meter=meter)
            if kind != "blob" or total != self.metadata[3]:
                raise AuthorityUnavailable("InternalLife durable artifact lost its fixed actual BLOB identity")
            self.parser.feed(raw, lambda event: None)
            self.data.extend(raw)
            self.offset += len(raw)
            return
        summary = self.parser.finish()
        if (summary.sha256, summary.byte_count) != self.metadata[2:]:
            raise AuthorityUnavailable("InternalLife durable artifact has no canonical full byte/hash EOF")
        data = bytes(self.data)
        self.data.clear()
        self.row = (self.metadata[0], self.metadata[1], data, self.metadata[2], self.metadata[3])
        self.complete = True
        self.parser = None
    def require_row_v3(self, work, meter):
        require_life_model_body_request_v3(work, _artifact_request_v3(work, self.request[1]))
        current = meter.read_fixed_row(work.db, self.table,
            ("binding_digest","artifact_ref","artifact_digest","artifact_length"),
            "bot=? AND persona=? AND execution_id=?", self.key)
        if work is not self.work or not self.complete or current != self.metadata:
            raise AuthorityUnavailable("InternalLife durable artifact lost its actual retained body EOF")
        return self.row


def prepare_life_model_artifact_body_v3(work, request):
    return _LifeModelArtifactBodyReadV3(work, request)


class _LifeModelActionLocatorColumnV3(DispatchOriginalJSONReadV3):
    def _emit(self, event):
        if event.path and event.path != ("action_intent_ref",):
            return
        super()._emit(event)


class _LifeModelActionLocatorV3:
    def __init__(self, work, request):
        from ..runtime.d11_life_preparation_v1 import TABLE
        require_life_model_body_request_v3(work, _action_request_v3(work, request[1]))
        self.work, self.request, self.table = work, request, TABLE
        self.after = ""
        self.metadata = self.column = None
        self.rows = []
        self.complete = False
        self.row = None
    def advance(self, meter):
        from ..runtime.d11_life_preparation_v1 import SIGN_KIND
        require_life_model_body_request_v3(self.work, _action_request_v3(self.work, self.request[1]))
        if self.column is None:
            self.metadata = meter.read_fixed_row(self.work.db, self.table,
                ("original_ref","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
                (*self.work.namespace.as_tuple,"source_note_action",self.after))
            if self.metadata is None:
                self.row = tuple(self.rows)
                self.complete = True
                return
            self.after = self.metadata[0]
            self.column = _LifeModelActionLocatorColumnV3(self.work, table=self.table,
                column="payload_json", key_columns=("bot","persona","kind","original_ref"),
                key=(*self.work.namespace.as_tuple,"source_note_action",self.after))
            return
        if not self.column.advance(meter):
            return
        if self.column.sha256 != self.metadata[1]:
            raise AuthorityUnavailable("InternalLife fixed Action locator lacks its exact signed whole EOF")
        self.work.controller.verifier._issuer._signer.verify(SIGN_KIND,
            canonical_serialize((self.work.namespace,"source_note_action",self.after,self.metadata[1])),
            self.metadata[2])
        raw = self.column.require_v3(self.work)
        if raw["action_intent_ref"] == self.request[1]:
            if self.rows:
                raise AuthorityUnavailable("InternalLife actual SourceNote action root has conflicting signed originals")
            self.rows.append((self.after,))
            _accept_action_locator_v3(self.work,self.request[1],self.after,self.column,self.metadata)
        self.metadata = self.column = None
    def require_row_v3(self, work, meter):
        require_life_model_body_request_v3(work, _action_request_v3(work, self.request[1]))
        if work is not self.work or not self.complete:
            raise AuthorityUnavailable("InternalLife fixed Action locator has no same-Work metadata EOF")
        return self.row


def prepare_life_model_action_locator_v3(work, request):
    return _LifeModelActionLocatorV3(work, request)


class _LifeModelGraphBodyColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self, work, **kwargs):
        super().__init__(work, **kwargs)
        codec = None if self.cell is None else self.cell.header[0]
        self.semantic_decoder = self.semantic_hash = None
        if codec == "canonical-json.utf8.v1":
            import codecs
            from hashlib import sha256
            self.parser = C09CanonicalJSONStreamV2(ensure_ascii=False)
            self.semantic_decoder = codecs.getincrementaldecoder("utf-8")("strict")
            self.semantic_hash = sha256()
    def advance(self, meter):
        if self.semantic_decoder is not None and self.fragment_offset < len(self.fragment):
            end = min(self.fragment_offset + 1024, len(self.fragment))
            self._semantic_v3(self.fragment[self.fragment_offset:end], meter)
        complete = super().advance(meter)
        if complete:
            if self.semantic_decoder is None:
                self.canonical_semantic_digest = self.sha256
            else:
                self._semantic_v3(b"", meter, final=True)
                self.canonical_semantic_digest = self.semantic_hash.hexdigest()
            self.semantic_decoder = self.semantic_hash = None
        return complete
    def _semantic_v3(self, fragment, meter, *, final=False):
        text = self.semantic_decoder.decode(fragment, final=final)
        encoded = []
        for char in text:
            codepoint = ord(char)
            if codepoint < 127:
                encoded.append(char)
            elif codepoint <= 65535:
                encoded.append(chr(92)+"u"+format(codepoint,"04x"))
            else:
                codepoint -= 65536
                encoded.append(chr(92)+"u"+format(55296+(codepoint>>10),"04x")
                    +chr(92)+"u"+format(56320+(codepoint&1023),"04x"))
        raw = "".join(encoded).encode("ascii")
        meter.charge_encode(len(raw))
        self.semantic_hash.update(raw)


from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3


class _LifeModelGraphBodyAttachmentV3(_HostProducerAttachmentV3):
    def __init__(self, work, request):
        require_life_model_body_request_v3(work, (GRAPH_BODY,*request))
        super().__init__(work,request)
    def require_row_v3(self, work, meter):
        require_life_model_body_request_v3(work, (GRAPH_BODY,*self.request))
        return super().require_row_v3(work,meter)
    def advance(self, meter):
        require_life_model_body_request_v3(self.owner, (GRAPH_BODY,*self.request))
        if self.phase == "columns" and self.column is None and self.pending:
            name = self.pending.pop(0)
            self.column = _LifeModelGraphBodyColumnV3(self.owner, table=self.table, column=name,
                key_columns=self.key_columns, key=self.key,
                cell_id=self.small.get("value_cell_id") if name == "value" else None)
            return
        if self.phase != "wire":
            return super().advance(meter)
        fragment = self.stream.read_fragment(meter)
        if fragment:
            self.owner.operation.retain(len(fragment)+128)
            self.parts.append(fragment)
        if self.stream.complete:
            if self.stream.hash.hexdigest() != self.column.canonical_semantic_digest:
                raise AuthorityUnavailable("InternalLife Graph body changed its actual raw/semantic whole EOF")
            size = sum(map(len,self.parts))
            self.owner.operation.retain(size*2+1024)
            self.encoded[self.column.column] = b"".join(self.parts).decode("ascii")
            self.column = self.stream = None
            self.parts = []
            self.phase = "columns"


def prepare_life_model_graph_body_attachment_v3(work, request):
    require_life_model_body_request_v3(work, (GRAPH_BODY,*request))
    return _LifeModelGraphBodyAttachmentV3(work, request)

def is_actual_life_model_graph_body_attachment_v3(work, attachment):
    if type(attachment) is not _LifeModelGraphBodyAttachmentV3:
        return False
    if attachment.owner is not work or work.attachments.get(attachment.request) is not attachment:
        raise AuthorityUnavailable("Life model Graph body lost its actual retained same-Work attachment")
    require_life_model_body_request_v3(work, (GRAPH_BODY,*attachment.request))
    return True

def read_bound_life_model_body_point_v3(db, *, table, columns, key_columns, key):
    from .internal_life_model_source_read_v3 import read_bound_internal_life_body_point_v3
    handled,row = read_bound_internal_life_body_point_v3(db,table=table,columns=columns,
        key_columns=key_columns,key=key)
    if handled:
        return True,row
    from .life_numeric_source_read_v3 import read_bound_numeric_life_model_body_point_v3
    return read_bound_numeric_life_model_body_point_v3(db,table=table,columns=columns,
        key_columns=key_columns,key=key)


def read_bound_life_model_history_v3(db, token, revision, columns):
    from .internal_life_model_source_read_v3 import read_bound_internal_life_history_v3
    handled,row = read_bound_internal_life_history_v3(db,token,revision,columns)
    if handled:
        return True,row
    from .life_numeric_source_read_v3 import read_bound_numeric_life_model_history_v3
    return read_bound_numeric_life_model_history_v3(db,token,revision,columns)


def read_bound_life_model_history_by_event_v3(db, token, event_id):
    from .internal_life_model_source_read_v3 import read_bound_internal_life_history_by_event_v3
    handled,row = read_bound_internal_life_history_by_event_v3(db,token,event_id)
    if handled:
        return True,row
    from .life_numeric_source_read_v3 import read_bound_numeric_life_model_history_by_event_v3
    return read_bound_numeric_life_model_history_by_event_v3(db,token,event_id)


def read_bound_life_model_artifact_v3(db, prepared):
    from .internal_life_model_source_read_v3 import read_bound_internal_life_artifact_v3
    handled,row = read_bound_internal_life_artifact_v3(db,prepared)
    if handled:
        return True,row
    from .life_numeric_source_read_v3 import read_bound_numeric_life_model_artifact_v3
    return read_bound_numeric_life_model_artifact_v3(db,prepared)


def read_bound_life_model_action_refs_v3(db, namespace, action_ref):
    from .internal_life_model_source_read_v3 import read_bound_internal_life_action_refs_v3
    handled,row = read_bound_internal_life_action_refs_v3(db,namespace,action_ref)
    if handled:
        return True,row
    from .life_numeric_source_read_v3 import read_bound_numeric_life_model_action_refs_v3
    return read_bound_numeric_life_model_action_refs_v3(db,namespace,action_ref)

def life_model_progress_source_group_v3(metadata):
    """Derive the actual nested consumer group; this metadata grants no read."""
    from ..graph_types import AtomKey
    audiences = tuple(metadata["plan"]["audiences"])
    roots = tuple(row["ref"] for row in metadata["read_rows"]
        if AtomKey.from_token(row["ref"]).type_name == "memory.source")
    return audiences, ("context","consolidation"), roots
