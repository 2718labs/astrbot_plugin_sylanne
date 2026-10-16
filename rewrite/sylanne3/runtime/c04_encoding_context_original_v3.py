"""D11 C04 encoding context read from W01's Owner-fenced graph transaction.

Meaning facets are nested in committed D04 AppraisalBundle graph originals.
Their exact appraisal version and issuer operation are checked from history;
caller-provided facet IDs and times have no authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import re
import sqlite3

from ..domains.d04.affect import _decode_appraisal
from ..domains.d04.joint_state_output_v1 import joint_state_payload_v1
from ..contracts import canonical_json
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import SourceRecord
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_encoding_baseline_store_v3 import _joint_numeric, _receipt
from .c04_v3_contracts import ExactRefV3
from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PERSPECTIVE = frozenset({
    "d03.entity_anchor", "d03.role_binding", "d03.self_perspective.v1",
})
_INTERPRETATION = frozenset({
    "d07.current_interpretation.v1", "d07.belief_revision.v1",
})


class D11EncodingContextHold(ValueError):
    """The encoding-time Owner read or a real facet issuer is unavailable."""


def _sha(value: object, name: str) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError(f"{name} needs a lowercase SHA-256 digest")


def _ref(value: object, namespace: NamespaceId, types: frozenset[str],
         name: str) -> AtomKey:
    if type(value) is not ExactRefV3:
        raise TypeError(f"{name} must be an exact graph version")
    key = AtomKey.from_token(value.ref)
    if NamespaceId.from_key(key) != namespace or key.type_name not in types:
        raise ValueError(f"{name} graph scope or type differs")
    return key


@dataclass(frozen=True, slots=True)
class MeaningFacetIssuerBindingV3:
    """Facet ID inside an exact D04 appraisal; issuer proof is still required."""

    facet_id: str
    appraisal: ExactRefV3
    facet_digest: str
    appraisal_issuer_digest: str

    def __post_init__(self) -> None:
        if type(self.facet_id) is not str or not self.facet_id.strip():
            raise ValueError("facet ID is required")
        if (type(self.appraisal) is not ExactRefV3
                or AtomKey.from_token(self.appraisal.ref).type_name
                   != "d04.appraisal_bundle.v1"):
            raise ValueError("MeaningFacet needs an exact D04 appraisal original")
        _sha(self.facet_digest, "facet")
        _sha(self.appraisal_issuer_digest, "appraisal issuer")


@dataclass(frozen=True, slots=True)
class D11EncodingContextOriginalV3:
    """Frozen shape only; constructing it is never an issuance or commit."""

    namespace: NamespaceId
    encoding_operation_id: str
    joint_operation_id: str
    source: ExactRefV3
    perspective: ExactRefV3
    interpretations: tuple[ExactRefV3, ...]
    feelings: tuple[ExactRefV3, ...]
    meaning_facets: tuple[MeaningFacetIssuerBindingV3, ...]
    as_known_at: float
    owner_fence_digest: str
    joint_receipt_digest: str
    joint_numeric_original_digest: str
    joint_output_original_digest: str
    read_versions: tuple[GraphVersion, ...]
    read_set_digest: str
    schema: str = "d11.c04_encoding_context_original.v3"
    status: str = "w01_owner_fenced_encoding_context"

    def __post_init__(self) -> None:
        if (self.schema not in {"d11.c04_encoding_context_original.v3",
                               "d11.c04_encoding_context_original.authored.v3"}
                or self.status != "w01_owner_fenced_encoding_context"):
            raise ValueError("encoding context cannot claim issuance")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("encoding namespace must be typed")
        for name in ("encoding_operation_id", "joint_operation_id"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"{name} is required")
        _ref(self.source, self.namespace, frozenset({"memory.source"}), "source")
        _ref(self.perspective, self.namespace, _PERSPECTIVE, "perspective")
        for name, values, types in (
            ("interpretations", self.interpretations, _INTERPRETATION),
            ("feelings", self.feelings, frozenset({
                "d04.authored_feeling_state.v1" if self.schema.endswith(".authored.v3")
                else "d04.feeling_state.v1"})),
        ):
            if (type(values) is not tuple or not values
                    or tuple(item.ref for item in values)
                       != tuple(sorted({item.ref for item in values}))):
                raise ValueError(f"{name} must be complete, unique and ordered")
            for item in values:
                _ref(item, self.namespace, types, name)
        if (type(self.meaning_facets) is not tuple or not self.meaning_facets
                or any(type(item) is not MeaningFacetIssuerBindingV3
                       for item in self.meaning_facets)
                or tuple(item.facet_id for item in self.meaning_facets)
                   != tuple(sorted({item.facet_id for item in self.meaning_facets}))):
            raise ValueError("MeaningFacet issuer bindings must be unique and ordered")
        if any(NamespaceId.from_key(AtomKey.from_token(item.appraisal.ref))
               != self.namespace for item in self.meaning_facets):
            raise ValueError("MeaningFacet appraisal crosses namespace")
        if type(self.as_known_at) not in (int, float) or not math.isfinite(self.as_known_at):
            raise ValueError("as_known_at must be finite")
        for name in ("owner_fence_digest", "joint_receipt_digest",
                     "joint_numeric_original_digest", "joint_output_original_digest",
                     "read_set_digest"):
            _sha(getattr(self, name), name)
        if (type(self.read_versions) is not tuple
                or any(type(item) is not GraphVersion for item in self.read_versions)
                or len({item.key for item in self.read_versions}) != len(self.read_versions)
                or self.read_set_digest != canonical_digest(self.read_versions)):
            raise ValueError("encoding read set differs")
        required = (self.source, self.perspective, *self.interpretations,
                    *self.feelings, *(item.appraisal for item in self.meaning_facets))
        reads = set(self.read_versions)
        if any(GraphVersion(AtomKey.from_token(item.ref), item.revision) not in reads
               for item in required):
            raise ValueError("encoding context original is absent from exact reads")


@dataclass(frozen=True, slots=True)
class W01EncodingGraphReadV3:
    """Internal W01 read request; the graph connection remains authoritative."""

    db: sqlite3.Connection
    namespace: NamespaceId
    encoding_operation_id: str
    joint_operation_id: str
    source_ref: str
    perspective_ref: str
    owner_fence_digest: str
    as_known_at: float


def _historical(db: sqlite3.Connection, namespace: NamespaceId,
                version: GraphVersion) -> tuple[dict, str]:
    prepared=active_w01_life_encoding_inputs_v3(db)
    if prepared is not None:return prepared.historical_v3(db,namespace,version)
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    handled,row=read_bound_method_learning_attachment_v3(db,table="graph_history",columns=("event_id","value","valid"),
        key_columns=("token","revision"),key=(version.key.token,version.revision))
    if handled:
        if row is None or row[2]!=1:raise D11EncodingContextHold("encoding historical EOF is absent")
        value=json.loads(row[1])
        if type(value)is not dict or canonical_json(value)!=row[1]:
            raise D11EncodingContextHold("encoding historical EOF is not a canonical object")
        return value,row[0]
    row = db.execute(
        "SELECT value,valid,event_id FROM graph_history WHERE token=? "
        "AND revision=? AND event_bot=? AND event_persona=?",
        (version.key.token, version.revision, *namespace.as_tuple),
    ).fetchone()
    if row is None or row[1] != 1:
        raise D11EncodingContextHold("encoding historical graph value is absent")
    try:
        value = json.loads(row[0])
        if type(value) is not dict or canonical_json(value) != row[0]:
            raise ValueError("historical value is not an object")
    except (TypeError, ValueError) as exc:
        raise D11EncodingContextHold("encoding historical graph value differs") from exc
    return value, row[2]


def issue_d11_encoding_context_original_v3(*, trusted_w01_read: object,
                                            facet_issuer_evidence: object,
                                            ) -> D11EncodingContextOriginalV3:
    """Issue from one authenticated W01 graph read, never caller facet bytes."""
    if (type(trusted_w01_read) is not W01EncodingGraphReadV3
            or facet_issuer_evidence is not None):
        raise D11EncodingContextHold("trusted W01 graph read is required")
    read = trusted_w01_read
    db, namespace = read.db, read.namespace
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId):
        raise D11EncodingContextHold("trusted W01 Owner graph transaction is required")
    _sha(read.owner_fence_digest, "Owner fence")
    if type(read.as_known_at) is not float or not math.isfinite(read.as_known_at):
        raise D11EncodingContextHold("trusted W01 encoding clock is absent")
    receipt = _receipt(db, namespace, read.encoding_operation_id)
    joint_receipt = _receipt(db, namespace, read.joint_operation_id)
    versions = receipt.read_versions
    by_ref = {item.key.token: item for item in versions}
    source = by_ref.get(read.source_ref)
    if source is None or source.revision < 1 or source.key.type_name != "memory.source":
        raise D11EncodingContextHold("encoding source was not an exact W01 read")
    source_value, _ = _historical(db, namespace, source)
    source_record = SourceRecord.from_dict(source_value)
    perspective = by_ref.get(read.perspective_ref)
    if (perspective is None or perspective.revision < 1
            or perspective.key.type_name not in _PERSPECTIVE):
        raise D11EncodingContextHold("encoding perspective was not an exact W01 read")
    _historical(db, namespace, perspective)
    appraisals = tuple(item for item in versions
                       if item.key.type_name == "d04.appraisal_bundle.v1"
                       and item.revision > 0)
    facets: list[MeaningFacetIssuerBindingV3] = []
    interpretations: set[str] = set()
    known_times = [source_record.recorded_at]
    for appraisal_version in appraisals:
        value, issuer_operation = _historical(db, namespace, appraisal_version)
        appraisal = _decode_appraisal(value)
        selected = tuple(facet for facet in appraisal.meaning_facets
                         if read.source_ref in facet.source_refs)
        if not selected:
            continue
        issuer_digest = canonical_digest(asdict(_receipt(
            db, namespace, issuer_operation)))
        known_times.append(appraisal.learned_at)
        for facet in selected:
            interpretations.add(facet.interpretation_ref)
            facets.append(MeaningFacetIssuerBindingV3(
                facet.facet_id,
                ExactRefV3(appraisal_version.key.token,
                           appraisal_version.revision),
                canonical_digest(asdict(facet)), issuer_digest,
            ))
    if not facets:
        raise D11EncodingContextHold("D04 MeaningFacet original is absent")
    if read.as_known_at < max(known_times):
        raise D11EncodingContextHold("encoding clock predates its graph sources")
    interpretation_versions = tuple(by_ref.get(ref) for ref in sorted(interpretations))
    if (any(item is None or item.revision < 1
            or item.key.type_name not in _INTERPRETATION
            for item in interpretation_versions)):
        raise D11EncodingContextHold("MeaningFacet interpretation was not read")
    for item in interpretation_versions:
        _historical(db, namespace, item)
    prepared=active_w01_life_encoding_inputs_v3(db)
    output=(prepared.output_v3(db,namespace,read.joint_operation_id) if prepared is not None
        else read_d04_joint_output_original_v1(db,namespace,read.joint_operation_id))
    if output is None:
        raise D11EncodingContextHold("adopted encoding joint output is absent")
    if prepared is not None:numeric=prepared.numeric_row_v3(db,namespace,read.joint_operation_id)
    else:
        from .natural_producer_qualification_v1 import _producer_original_point_v3
        numeric=_producer_original_point_v3(db,table="graph_d04_joint_numeric_originals_v1",
            columns=("numeric_receipt_json","numeric_receipt_digest","verification_json","verification_digest"),
            key_columns=("bot","persona","operation_id"),key=namespace.as_tuple+(read.joint_operation_id,),
            legacy_reader=lambda:db.execute("SELECT numeric_receipt_json,numeric_receipt_digest,verification_json,"
                "verification_digest FROM graph_d04_joint_numeric_originals_v1 WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple+(read.joint_operation_id,)).fetchone())
    if numeric is None:
        raise D11EncodingContextHold("encoding joint numeric original is absent")
    from ..domains.d04.encoding_baseline_v2 import ProjectionNumericErrorV2
    from .d04_joint_advance_v2 import (
        JointNumericOriginalV1, JointNumericOriginalVerificationV1,
        _decode_numeric_candidate,
    )
    candidate = _decode_numeric_candidate(numeric[0])
    raw_verification = json.loads(numeric[2])
    raw_verification["numeric_error"] = ProjectionNumericErrorV2(
        **raw_verification["numeric_error"])
    verification = JointNumericOriginalVerificationV1(**raw_verification)
    if (candidate.receipt_digest != numeric[1]
            or canonical_digest(asdict(verification)) != numeric[3]):
        raise D11EncodingContextHold("encoding numeric original digest differs")
    source_families = {row[6] for row in candidate.source_versions
                       if row[2] == read.source_ref}
    source_checkpoints = {
        member.checkpoint_ref for member in candidate.members
        if any(family.family_id in source_families
               and read.source_ref in family.source_refs
               for family in member.families)
    }
    source_members = tuple(member for member in output.members
                           if member.kind == "feeling"
                           and member.checkpoint_ref in source_checkpoints)
    feeling_refs = {member.predecessor_state_ref for member in source_members}
    feelings = tuple(item for item in versions
                     if item.key.token in feeling_refs and item.revision > 0)
    if not feelings or {item.key.token for item in feelings} != feeling_refs:
        raise D11EncodingContextHold("encoding Feeling joint members are incomplete")
    for item in feelings:
        value, event_id = _historical(db, namespace, item)
        member = next(member for member in source_members
                      if member.predecessor_state_ref == item.key.token)
        if (event_id != read.joint_operation_id
                or item.revision != member.predecessor_state_revision + 1
                or canonical_digest(value) != canonical_digest(
                    joint_state_payload_v1(member.next_state))):
            raise D11EncodingContextHold("Feeling is not the adopted joint output")
    selected_member = next((member for member in source_members
                            if member.predecessor_state_ref == feelings[0].key.token),
                           None)
    if selected_member is None:
        raise D11EncodingContextHold("encoding numeric member is absent")
    numeric_original = JointNumericOriginalV1(
        selected_member.checkpoint_ref,
        selected_member.predecessor_checkpoint_revision + 1,
        read.joint_operation_id, canonical_digest(asdict(joint_receipt)),
        candidate, verification,
    )
    if _joint_numeric(
            db, namespace, read.joint_operation_id,
            numeric_original.original_ref, numeric_original.original_revision,
            numeric_original.adoption_receipt_digest,
            canonical_digest(asdict(numeric_original))) != numeric_original:
        raise D11EncodingContextHold("encoding numeric original differs")
    return D11EncodingContextOriginalV3(
        namespace, read.encoding_operation_id, read.joint_operation_id,
        ExactRefV3(source.key.token, source.revision),
        ExactRefV3(perspective.key.token, perspective.revision),
        tuple(ExactRefV3(item.key.token, item.revision)
              for item in interpretation_versions),
        tuple(ExactRefV3(item.key.token, item.revision) for item in feelings),
        tuple(sorted(facets, key=lambda item: item.facet_id)),
        read.as_known_at, read.owner_fence_digest,
        canonical_digest(asdict(joint_receipt)),
        canonical_digest(asdict(numeric_original)), output.original_digest,
        versions, canonical_digest(versions),
        schema=("d11.c04_encoding_context_original.authored.v3"
                if output.schema == "d04.joint-state-output.v2"
                else "d11.c04_encoding_context_original.v3"),
    )


__all__ = [
    "D11EncodingContextHold", "D11EncodingContextOriginalV3",
    "MeaningFacetIssuerBindingV3", "W01EncodingGraphReadV3",
    "issue_d11_encoding_context_original_v3",
]

# Actual pre-WRITE encoding inputs, retained only by their selected Method Work.
from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakKeyDictionary,ref
from types import MappingProxyType

_ENCODING_PREPARED_V3=WeakKeyDictionary()
_ENCODING_STAGES_V3={}
_ENCODING_ACTIVE_V3=ContextVar("life_numeric_encoding_w01_v3",default=None)

class PreparedW01LifeEncodingInputsV3:
    def __init__(self,reader,frame,context,joint_receipt,numeric_row,output,historical,receipts,prior,points,headers,life_prior,cell_witnesses):
        self.reader,self.work,self.operation,self.selection=reader,reader.work,reader.operation,reader.selection_digest
        self.frame,self.context,self.joint_receipt,self.numeric_row,self.output=frame,context,joint_receipt,numeric_row,output
        self.historical,self.receipts,self.prior=MappingProxyType(historical),MappingProxyType(receipts),prior
        self.points,self.headers=tuple(points),tuple(headers)
        self.life_prior,self.before_stamp=life_prior,reader.graph_stamp
        self.cell_witnesses=tuple(cell_witnesses)
        _ENCODING_PREPARED_V3[self]=(reader,reader.work,reader.operation,reader.selection_digest,
            frame,context,joint_receipt,numeric_row,output,self.historical,self.receipts,prior,self.points,self.headers,life_prior,reader.graph_stamp,self.cell_witnesses)
    def require_stage_v3(self,db,stage):
        from .d04_life_encoding_baseline_v1 import LifeEncodingBaselineStageV1
        from .current_method_learning_read_v3 import _READERS,_method_active
        r=self.reader
        if (_ENCODING_PREPARED_V3.get(self)!=(r,self.work,self.operation,self.selection,self.frame,self.context,
                self.joint_receipt,self.numeric_row,self.output,self.historical,self.receipts,self.prior,self.points,self.headers,self.life_prior,self.before_stamp,self.cell_witnesses)
                or r not in _READERS or _method_active(db)is not r or r.work is not self.work
                or r.operation is not self.operation or self.operation.closed or not r.inputs_sealed or not r.business_started
                or type(stage)is not LifeEncodingBaselineStageV1 or stage.frame.envelope.identity!=self.frame.envelope.identity
                or stage.frame.envelope.authority!=self.frame.envelope.authority
                or stage.frame.envelope.version_guard!=self.frame.envelope.version_guard
                or stage.frame.snapshot!=self.frame.snapshot or stage.frame.owner_guard!=self.frame.owner_guard
                or stage.context.original!=self.context.original or stage.output_digest!=self.output.original_digest
                or stage.environment.graph is not r.graph):
            raise D11EncodingContextHold("encoding inputs changed actual selected Method/fresh WRITE stage")
        bound=_ENCODING_STAGES_V3.get(id(stage))
        if (bound is None or bound[8]()is not stage or bound[:4]!=(self,r,stage.frame,stage.environment)
                or bound[4].operation!="write" or bound[4].namespace!=r.namespace
                or stage.environment.asset is not bound[6] or stage.environment.policy is not bound[7]
                or stage.owner_fence_digest!=canonical_digest(asdict(bound[4].permit))
                or stage.owner_epoch!=bound[5].authorization_revision):
            raise D11EncodingContextHold("encoding inputs lost actual fresh WRITE scope/Owner/environment binding")
        return self
    def require_active_v3(self,db):
        active=_ENCODING_ACTIVE_V3.get()
        if active is None or active[0]is not self:
            raise D11EncodingContextHold("encoding input material requires its exact active W01 writer")
        capsule,witness,receipt=active
        self.require_stage_v3(db,witness.stage)
        from .d06_life_numeric_commit_v1 import require_exact_life_numeric_math_issuance_v1
        require_exact_life_numeric_math_issuance_v1(witness,witness.graph,witness.bundle)
        if (not db.in_transaction or not witness.graph._GraphCoordinator__store._lock._is_owned()
                or witness.scope.operation!="write" or witness.stage.frame is not witness.frame):
            raise D11EncodingContextHold("encoding inputs lost actual Owner WRITE/SQL/ACTIVE witness")
        return active
    def receipt_v3(self,db,namespace,operation_id):
        _,witness,receipt=self.require_active_v3(db)
        if namespace!=self.context.original.namespace:
            raise D11EncodingContextHold("encoding receipt crossed actual selected namespace")
        if operation_id==receipt.operation_id:return receipt
        if operation_id not in self.receipts:
            raise D11EncodingContextHold("encoding receipt escaped actual frozen joint/facet producers")
        return self.receipts[operation_id]
    def historical_v3(self,db,namespace,version):
        self.require_active_v3(db)
        if namespace!=self.context.original.namespace or version not in self.historical:
            raise D11EncodingContextHold("encoding history escaped its actual prepared EOF versions")
        return self.historical[version]
    def numeric_row_v3(self,db,namespace,operation_id):
        self.require_active_v3(db)
        if (namespace,operation_id)!=(self.context.original.namespace,self.reader.request.joint_operation_id):
            raise D11EncodingContextHold("encoding numeric original escaped actual selected joint")
        return self.numeric_row
    def output_v3(self,db,namespace,operation_id):
        self.require_active_v3(db)
        if (namespace,operation_id)!=(self.context.original.namespace,self.reader.request.joint_operation_id):
            raise D11EncodingContextHold("encoding output escaped actual selected joint")
        return self.output

def capture_prepared_w01_life_encoding_inputs_v3(reader):
    from .current_method_learning_read_v3 import (read_bound_method_learning_attachment_v3,
        require_actual_source_owner_metadata_work_v1,_HISTORY_COLUMNS)
    from .current_life_numeric_metadata_v1 import require_numeric_method_sources_v1
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from .d06_life_numeric_context_v1 import PrepareLifeNumericContextRequestV1,read_current_life_numeric_context_v1
    from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
    from .c04_encoding_baseline_store_v3 import _receipt
    from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    r=require_actual_source_owner_metadata_work_v1(reader)
    if r.operation_kind!="prepare_internal_life_interval_baseline" or r.read_finished:
        raise D11EncodingContextHold("encoding inputs require the exact current Sourcequalified Method READ")
    require_numeric_method_sources_v1(r)
    frame=CurrentOperationFrameV1(*r.frame_fields)
    readers=InstalledD06StructuredExperienceReadersV1(issuer=r.graph._GraphCoordinator__d11_issuer,
        resource_issuer=r.graph._GraphCoordinator__d02_issuer,body_quote_authority=r.graph._GraphCoordinator__body_quote_authority)
    context=read_current_life_numeric_context_v1(r.db,frame=frame,
        request=PrepareLifeNumericContextRequestV1(r.request.episode_ref,r.request.causal_operation_id),installed_readers=readers)
    ns=r.namespace;operation=r.request.joint_operation_id
    joint=_receipt(r.db,ns,operation)
    output=read_d04_joint_output_original_v1(r.db,ns,operation)
    nonseries=require_math_nonseries_metadata_v3(r,operation)
    shape=("graph_d04_joint_numeric_originals_v1",("numeric_receipt_json","numeric_receipt_digest","verification_json","verification_digest"),("bot","persona","operation_id"),(*ns.as_tuple,operation))
    _,numeric=read_bound_method_learning_attachment_v3(r.db,table=shape[0],columns=shape[1],key_columns=shape[2],key=shape[3])
    from .d04_joint_advance_v2 import _decode_numeric_candidate
    candidate=_decode_numeric_candidate(numeric[0])
    versions={v for v in frame.snapshot.versions if v.revision>0 and v.key.type_name in
        ({"memory.source","d04.appraisal_bundle.v1","d04.feeling_state.v1","d04.authored_feeling_state.v1",
          "d04.numeric_checkpoint.v1","d04.numeric_checkpoint.v2"}|_PERSPECTIVE|_INTERPRETATION)}
    versions.update(GraphVersion(AtomKey.from_token(row[0]),row[1])for row in candidate.source_versions)
    historical={};receipts={operation:joint}
    for version in sorted(versions,key=lambda v:(v.key.token,v.revision)):
        _,row=read_bound_method_learning_attachment_v3(r.db,table="graph_history",columns=_HISTORY_COLUMNS,
            key_columns=("token","revision"),key=(version.key.token,version.revision))
        if row is None or row[2]!=1:raise D11EncodingContextHold("encoding historical EOF is unavailable")
        value=json.loads(row[1])
        if type(value)is not dict or canonical_json(value)!=row[1]:
            raise D11EncodingContextHold("encoding prepared history is not a canonical object")
        historical[version]=(value,row[0])
        if version.key.type_name=="d04.appraisal_bundle.v1":
            appraisal=_decode_appraisal(value)
            if any(context.original.source_ref in f.source_refs for f in appraisal.meaning_facets):
                receipts[row[0]]=_receipt(r.db,ns,row[0])
    from .d04_life_encoding_baseline_v1 import life_encoding_baseline_ids_v1
    ids=life_encoding_baseline_ids_v1(ns,r.request.episode_ref,operation)
    columns=("joint_operation_id","original_json","original_digest","proof_json","proof_digest","as_known_at_json",
        "historical_closure_digest","read_versions_json","read_versions_digest","encoding_receipt_digest",
        "joint_receipt_digest","numeric_original_ref","numeric_original_revision","record_digest")
    _,prior=read_bound_method_learning_attachment_v3(r.db,table="graph_c04_encoding_baselines_v3",columns=columns,
        key_columns=("bot","persona","encoding_operation_id","source_ref"),key=(*ns.as_tuple,ids["operation"],context.original.source_ref))
    from .d11_life_preparation_v1 import SIGN_KIND
    from .d04_life_encoding_baseline_v1 import KIND
    _,life_prior=read_bound_method_learning_attachment_v3(r.db,table="graph_d11_life_originals_v1",
        columns=("producing_operation_id","payload_json","payload_digest","signature"),
        key_columns=("bot","persona","kind","original_ref"),key=(*ns.as_tuple,KIND,ids["original"]))
    if life_prior is not None:
        raw=json.loads(life_prior[1])
        from ..runtime_contracts import canonical_serialize
        if (life_prior[0]!=ids["operation"] or canonical_serialize(raw)!=life_prior[1]
                or canonical_digest(raw)!=life_prior[2]):raise D11EncodingContextHold("encoding signed prior EOF differs")
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,KIND,ids["original"],life_prior[2])),life_prior[3])
        receipts[ids["operation"]]=_receipt(r.db,ns,ids["operation"])
    points=[("graph_d04_originals_v3",("bot","persona","kind","original_ref"),
        (*ns.as_tuple,"series_final_native_prefix",operation),("payload_digest",),None)]
    points.extend(("graph_d04_originals_v3",("bot","persona","kind","original_ref"),
        (*ns.as_tuple,"series_root",ref),("payload_digest",),(digest,))for ref,digest in nonseries.headers)
    for task in r.points.values():
        if not task.complete:raise D11EncodingContextHold("encoding inputs have unfinished actual point EOF")
        points.append((task.table,task.key_columns,task.key,task.metadata_columns,task.metadata))
    headers=[];cell_witnesses=[]
    from ..runtime_storage_v3 import begin_runtime_cell_read_v3,read_runtime_cell_origin_v3
    from hashlib import sha256
    with runtime_storage_quantum_v3(r.db)as meter:
        for version in sorted(historical,key=lambda v:(v.key.token,v.revision)):
            cols=("value_cell_id","event_bot","event_persona","event_session","event_id","valid")
            history=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_history",cols,"token=? AND revision=?",
                (version.key.token,version.revision))
            if history is None or history[1:3]!=ns.as_tuple or history[4]!=historical[version][1]or history[5]!=1:
                raise D11EncodingContextHold("encoding historical producer/namespace differs from actual EOF")
            points.append(("graph_history",("token","revision"),(version.key.token,version.revision),cols,history))
            if history[0]is not None:
                cell=begin_runtime_cell_read_v3(r.db,history[0],erasure_owner_ref=version.key.token)
                origin=read_runtime_cell_origin_v3(r.db,history[0],header=cell.header,meter=meter)
                wire=json.dumps(historical[version][0],sort_keys=True,separators=(",",":"),ensure_ascii=cell.header[0]!="canonical-json.utf8.v1").encode("utf8")
                if (cell.header[2]!=history[4]or cell.header[3]!=len(wire)or cell.header[5]!=sha256(wire).hexdigest()
                        or origin is None or origin["operation_id"]!=history[4]):
                    raise D11EncodingContextHold("encoding history cell body/producer differs from actual EOF")
                cell_witnesses.append((history[0],version.key.token,cell.header,origin))
        for version in tuple(dict.fromkeys((*frame.snapshot.versions,*r.numeric_source_permission.versions))):
            head=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(version.key.token,*ns.as_tuple))
            headers.append((version.key,head))
    from .dispatch_current_inventory_v3 import _heap
    r.operation.retain(_heap((historical,receipts,numeric,prior,points,headers,life_prior,cell_witnesses))*2+65536)
    prepared=PreparedW01LifeEncodingInputsV3(r,frame,context,joint,numeric,output,historical,receipts,prior,points,headers,life_prior,cell_witnesses)
    r.prepared_encoding_inputs_v3=prepared
    return prepared

@contextmanager
def bind_actual_w01_life_encoding_inputs_v3(db,*,witness,receipt):
    from .current_method_learning_read_v3 import _method_active
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    reader=_method_active(db);capsule=reader.prepared_encoding_inputs_v3
    capsule.require_stage_v3(db,witness.stage)
    ns=capsule.context.original.namespace
    with runtime_storage_quantum_v3(db)as meter:
        for key,expected in capsule.headers:
            actual=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(key.token,*ns.as_tuple))
            if actual!=expected:raise D11EncodingContextHold("zero-write encoding changed prepared current head")
        for table,keycols,key,cols,expected in capsule.points:
            actual=_runtime_bounded_fixed_row_v3(db,meter,table,cols," AND ".join(name+"=?"for name in keycols),key)
            if actual!=expected:raise D11EncodingContextHold("zero-write encoding changed actual prepared original/header")
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3,read_runtime_cell_origin_v3
        for cell_id,token,header,origin in capsule.cell_witnesses:
            actual=begin_runtime_cell_read_v3(db,cell_id,erasure_owner_ref=token)
            if (actual.header!=header or read_runtime_cell_origin_v3(db,cell_id,header=actual.header,meter=meter)!=origin):
                raise D11EncodingContextHold("encoding ACTIVE writer changed prepared cell header/origin")
    bound=_ENCODING_STAGES_V3.get(id(witness.stage))
    if bound is None or bound[4]is not witness.scope:
        raise D11EncodingContextHold("encoding ACTIVE writer differs from actual stage WRITE scope")
    token=_ENCODING_ACTIVE_V3.set((capsule,witness,receipt))
    try:yield capsule
    finally:_ENCODING_ACTIVE_V3.reset(token)

def active_w01_life_encoding_inputs_v3(db):
    active=_ENCODING_ACTIVE_V3.get()
    if active is None:return None
    active[0].require_active_v3(db)
    return active[0]


def require_life_encoding_prior_selector_v3(reader,request):
    from .current_life_numeric_metadata_v1 import require_numeric_method_sources_v1,_metadata
    from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1
    from .d04_life_encoding_baseline_v1 import life_encoding_baseline_ids_v1,KIND
    if reader.operation_kind!="prepare_internal_life_interval_baseline":return False
    require_numeric_method_sources_v1(reader)
    context,_=_metadata(reader,"life","context",life_numeric_context_ids_v1(reader.namespace,reader.request.episode_ref)["original"])
    ids=life_encoding_baseline_ids_v1(reader.namespace,reader.request.episode_ref,reader.request.joint_operation_id)
    table,columns,keycols,key=request
    shapes={
        ("graph_c04_encoding_baselines_v3",("joint_operation_id","original_json","original_digest","proof_json","proof_digest","as_known_at_json",
            "historical_closure_digest","read_versions_json","read_versions_digest","encoding_receipt_digest","joint_receipt_digest",
            "numeric_original_ref","numeric_original_revision","record_digest"),("bot","persona","encoding_operation_id","source_ref")):
                (*reader.namespace.as_tuple,ids["operation"],context["source_ref"]),
        ("graph_d11_life_originals_v1",("producing_operation_id","payload_json","payload_digest","signature"),
            ("bot","persona","kind","original_ref")):(*reader.namespace.as_tuple,KIND,ids["original"])}
    selected=shapes.get((table,tuple(columns),tuple(keycols)))
    if selected is None:return False
    if tuple(key)!=selected:raise D11EncodingContextHold("encoding prior escaped actual fixed context/joint identities")
    return True

def release_prepared_life_encoding_inputs_v3(reader):
    capsule=reader.prepared_encoding_inputs_v3
    if capsule is None:return
    _ENCODING_PREPARED_V3.pop(capsule,None)
    for stage_id,bound in tuple(_ENCODING_STAGES_V3.items()):
        if bound[0]is capsule:_ENCODING_STAGES_V3.pop(stage_id,None)
    capsule.life_prior=capsule.cell_witnesses=None
    capsule.historical=capsule.receipts=capsule.prior=capsule.points=capsule.headers=None
    capsule.frame=capsule.context=capsule.joint_receipt=capsule.numeric_row=capsule.output=None
    reader.prepared_encoding_inputs_v3=None

def bind_prepared_life_encoding_stage_v3(reader,db,stage,scope,owner_guard):
    from .d04_life_encoding_baseline_v1 import _STAGES,_environment
    from .current_method_learning_read_v3 import _method_active
    issued=_STAGES.get(id(stage))
    capsule=reader.prepared_encoding_inputs_v3
    if (issued is None or issued[0]()is not stage or issued[1]is not db
            or _method_active(db)is not reader or capsule is None
            or scope.operation!="write" or scope.operation_id!=scope.permit.operation_id
            or scope.namespace!=reader.namespace or not db.in_transaction
            or not reader.store._lock._is_owned()):
        raise D11EncodingContextHold("encoding stage requires its actual registered fresh WRITE admission")
    from .current_method_learning_read_v3 import _require_current_general_method_source_write_phase_v1
    phase=_require_current_general_method_source_write_phase_v1(reader)
    expected_attempt="owner-domain-"+canonical_digest((reader.namespace,reader.operation_id,reader.request_digest))[:48]
    if phase[1]is not scope or scope.operation_id!=expected_attempt:
        raise D11EncodingContextHold("encoding stage changed actual current WRITE phase/attempt identity")
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    with runtime_storage_quantum_v3(db)as meter:
        attempt=_runtime_bounded_fixed_row_v3(db,meter,"graph_owner_domain_attempts_v3",("request_digest","attempt_id"),
            "bot=? AND persona=? AND operation_id=?",(*reader.namespace.as_tuple,reader.operation_id))
    if attempt!=(reader.request_digest,scope.operation_id):
        raise D11EncodingContextHold("encoding stage lacks actual registered business request/Owner attempt")
    _environment(db,stage.frame,stage.environment)
    stage_id=id(stage)
    _ENCODING_STAGES_V3[stage_id]=(capsule,reader,stage.frame,stage.environment,scope,owner_guard,
        stage.environment.asset,stage.environment.policy,ref(stage,lambda _:_ENCODING_STAGES_V3.pop(stage_id,None)))
    capsule.require_stage_v3(db,stage)
    return capsule


from .current_life_numeric_metadata_v1 import _NumericMetadataColumnV1
from .dispatch_current_inventory_v3 import _detach_value_v3,_heap
from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
from ..authority_service.contract import AuthorityUnavailable

def _require_math_nonseries_reader_v3(reader,operation_id):
    from .current_method_learning_read_v3 import require_actual_source_owner_metadata_work_v1
    from .current_life_numeric_metadata_v1 import require_numeric_method_sources_v1
    r=require_actual_source_owner_metadata_work_v1(reader)
    if (r.operation_kind!="prepare_internal_life_interval_baseline" or r.read_finished
            or operation_id!=r.request.joint_operation_id):
        raise AuthorityUnavailable("Math nonSeries metadata requires exact selected current baseline joint")
    require_numeric_method_sources_v1(r)
    return r
class _MathSeriesLocatorColumnV3(_NumericMetadataColumnV1):
    def retain_path_v3(self,path):
        return not path or path in {("root_ref",),("numeric_operation_id",)}

class MathNonSeriesMetadataTaskV3:
    def __init__(self,reader,operation_id):
        r=_require_math_nonseries_reader_v3(reader,operation_id)
        self.reader,self.operation_id=r,operation_id
        self.table,self.column_name="graph_d04_originals_v3","payload_json"
        self.key_columns=("bot","persona","kind","original_ref")
        self.profile="math_series_locator";self.key=None;self.column=None
        self.cursor="";self.headers=[];self.metadata=None;self.complete=False;self.stamp=r.graph_stamp
    def advance(self,meter):
        r=_require_math_nonseries_reader_v3(self.reader,self.operation_id)
        prefix=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d04_originals_v3",("payload_digest",),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,"series_final_native_prefix",self.operation_id))
        if prefix is not None:raise AuthorityUnavailable("Math once profile does not satisfy nonSeries prefix absence")
        if self.column is not None:
            if not self.column.advance(meter):return False
            raw=_detach_value_v3(self.column.frozen)
            if self.column.canonical_digest!=self.metadata[1]or raw["root_ref"]!=self.key[-1]:
                raise AuthorityUnavailable("Math series locator full original digest/header EOF differs")
            if raw["numeric_operation_id"]==self.operation_id:
                raise AuthorityUnavailable("Math once profile does not satisfy actual nonSeries root identity")
            self.headers.append((self.key[-1],self.metadata[1]));self.cursor=self.key[-1]
            self.column=None;return False
        row=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,("original_ref","payload_digest"),
            "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
            (*r.namespace.as_tuple,"series_root",self.cursor))
        if row is None:self.complete=True;return True
        self.key=(*r.namespace.as_tuple,"series_root",row[0]);self.metadata=row
        if len(self.headers)>=128:raise AuthorityUnavailable("Math nonSeries metadata exceeds original 128-row bound")
        self.column=_MathSeriesLocatorColumnV3(self)
        r.operation.retain(_heap(row)+256)
        return False
    def require_header_v1(self,meter):
        r=_require_math_nonseries_reader_v3(self.reader,self.operation_id)
        if not self.complete or r.graph_stamp!=self.stamp:
            raise AuthorityUnavailable("Math nonSeries metadata EOF lost actual current selection/epoch")
        prefix=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,("payload_digest",),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,"series_final_native_prefix",self.operation_id))
        if prefix is not None:raise AuthorityUnavailable("Math nonSeries actual prefix absence changed")
        count=r.db.execute("SELECT count(*) FROM graph_d04_originals_v3 WHERE bot=? AND persona=? AND kind='series_root'",
            r.namespace.as_tuple).fetchone()[0];meter.charge_read(8)
        if count!=len(self.headers):raise AuthorityUnavailable("Math nonSeries complete metadata catalogue changed")
        for ref,digest in self.headers:
            actual=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,("payload_digest",),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,"series_root",ref))
            if actual!=(digest,):raise AuthorityUnavailable("Math nonSeries exact original header changed")
        return self

def require_math_nonseries_metadata_v3(reader,operation_id):
    from .current_method_learning_read_v3 import _need_method_input
    r=_require_math_nonseries_reader_v3(reader,operation_id)
    identity=("math_nonseries_metadata",operation_id)
    task=r.attachments.get(identity)
    if task is None or not task.complete:_need_method_input(r,identity)
    if (type(task)is not MathNonSeriesMetadataTaskV3 or task.reader is not r or task.operation_id!=operation_id):
        raise AuthorityUnavailable("Math nonSeries metadata belongs to another actual selected Work")
    with runtime_storage_quantum_v3(r.db)as meter:task.require_header_v1(meter)
    return task
