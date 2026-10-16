"""Installed World adoption and bounded historical reads in the existing W01 transaction.

The index is signed locator metadata, reconstructible from Graph input/history
and the real adoption receipt. It contains no Source text or world truth store.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d03.context import ContextProvider, WorldEvent
from ..domains.d03.self_perspective import SelfPerspective
from ..domains.d03.world_history_v1 import (
    INPUT_TYPE, VIEW_TYPE, EXPRESSION_TYPE, WORLD_OPERATIONS,
    WorldAssertionInputV1, WorldAssertionRevisionV1, AdoptWorldAssertionRequestV1,
    WorldViewRequestV1, WorldViewResultV1, WorldViewCursorV1,
    WorldPerspectiveProjectionV1,WorldInterpretationProjectionV1,WorldErasureBarrierV1,WorldIntervalV1,
    ProjectWorldPerspectiveRequestV1, WorldPerspectiveExpressionInputV1,
    decode_world_value_v1, world_assertion_key_v1, world_view_key_v1, world_expression_key_v1,
)
from ..graph_types import AtomKey, GraphVersion, GraphWrite, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import read_graph_row_v3
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .natural_producer_qualification_v1 import _producer_original_point_v3

TABLE = "graph_world_revision_index_v1"
SIGN_KIND = "d11.world-revision-index.v1"
COLUMNS = ("bot","persona","original_ref","kind","producing_operation_id","payload_json",
    "payload_digest","signature","source_refs_json","assertion_id","assertion_commitment","known_sequence","supersedes_ref")
DDL = """CREATE TABLE IF NOT EXISTS graph_world_revision_index_v1 (
    bot TEXT NOT NULL, persona TEXT NOT NULL, original_ref TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind='world_revision_index'), producing_operation_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,source_refs_json TEXT NOT NULL,
    assertion_id TEXT NOT NULL,assertion_commitment TEXT NOT NULL,known_sequence INTEGER NOT NULL CHECK(known_sequence>0),supersedes_ref TEXT,
    PRIMARY KEY(bot,persona,original_ref),UNIQUE(bot,persona,assertion_commitment,known_sequence),
    UNIQUE(bot,persona,supersedes_ref),
    FOREIGN KEY(bot,persona,producing_operation_id) REFERENCES graph_bundle_operations(bot,persona,operation_id))"""
INDEX_DDL = """CREATE INDEX IF NOT EXISTS graph_world_revision_temporal_v1
    ON graph_world_revision_index_v1(bot,persona,assertion_commitment,known_sequence)"""


ERASURE_TABLE = "graph_world_revision_erasure_barriers_v1"
ERASURE_SIGN_KIND = "d11.world-erasure-barrier.v1"
ERASURE_COLUMNS = ("bot","persona","assertion_commitment","known_sequence","revision_commitment",
    "deletion_generation","deletion_knowledge_sequence","delete_original_commitment","payload_json","payload_digest","signature")
ERASURE_DDL = """CREATE TABLE IF NOT EXISTS graph_world_revision_erasure_barriers_v1 (
    bot TEXT NOT NULL,persona TEXT NOT NULL,assertion_commitment TEXT NOT NULL,
    known_sequence INTEGER NOT NULL CHECK(known_sequence>0),revision_commitment TEXT NOT NULL,
    deletion_generation INTEGER NOT NULL CHECK(deletion_generation>0),deletion_knowledge_sequence INTEGER NOT NULL CHECK(deletion_knowledge_sequence>=0),
    delete_original_commitment TEXT NOT NULL,
    payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,
    PRIMARY KEY(bot,persona,assertion_commitment,known_sequence))"""
ERASURE_INDEX_DDL = """CREATE INDEX IF NOT EXISTS graph_world_erased_knowledge_v1
    ON graph_world_revision_erasure_barriers_v1(bot,persona,assertion_commitment,known_sequence)"""
WORLD_LATEST_SQL = """SELECT entry_kind,known_sequence,locator FROM (
    SELECT 'revision' AS entry_kind,known_sequence,original_ref AS locator
    FROM graph_world_revision_index_v1 WHERE bot=? AND persona=? AND assertion_commitment=?
    UNION ALL SELECT 'erasure',known_sequence,revision_commitment
    FROM graph_world_revision_erasure_barriers_v1 WHERE bot=? AND persona=? AND assertion_commitment=?)
    ORDER BY known_sequence DESC,CASE entry_kind WHEN 'erasure' THEN 0 ELSE 1 END LIMIT 1"""
WORLD_PAGE_SQL = """WITH versions AS (
    SELECT 'revision' AS entry_kind,assertion_commitment,known_sequence,original_ref AS locator
    FROM graph_world_revision_index_v1 WHERE bot=? AND persona=?
    UNION ALL
    SELECT 'erasure',assertion_commitment,known_sequence,revision_commitment
    FROM graph_world_revision_erasure_barriers_v1 WHERE bot=? AND persona=?)
    SELECT a.entry_kind,a.assertion_commitment,a.known_sequence,a.locator FROM versions a
    WHERE a.assertion_commitment>? AND a.known_sequence<=? AND NOT EXISTS(
        SELECT 1 FROM versions b WHERE b.assertion_commitment=a.assertion_commitment
        AND b.known_sequence<=? AND (b.known_sequence>a.known_sequence OR
            b.known_sequence=a.known_sequence AND b.entry_kind='erasure' AND a.entry_kind='revision'))
    ORDER BY a.assertion_commitment LIMIT ?"""


@dataclass(frozen=True, slots=True)
class WorldRevisionIndexV1:
    input_version: GraphVersion
    input_digest: str
    assertion_id: str
    assertion_commitment: str
    valid_interval: WorldIntervalV1
    adoption_operation_id: str
    adoption_receipt_digest: str
    known_from_sequence: int
    source_refs: tuple[str, ...]
    event_version: GraphVersion
    perspective_version: GraphVersion
    interpretation_version: GraphVersion | None
    supersedes_ref: str | None
    correction_ref: str | None
    dispute_refs: tuple[str, ...]
    prior_erasure_digest: str | None
    schema: str = "d03.world-revision-index.v1"

    def __post_init__(self):
        from ..domains.d03.world_history_v1 import _version, _sequence, _digest, _text
        if self.schema != "d03.world-revision-index.v1":
            raise ValueError("World index schema differs")
        _version(self.input_version, INPUT_TYPE)
        _version(self.event_version, "d03.world_event")
        _version(self.perspective_version, "d03.self_perspective.v1")
        if self.interpretation_version is not None:
            _version(self.interpretation_version, "d07.current_interpretation.v1")
        _digest(self.input_digest); _digest(self.adoption_receipt_digest);_digest(self.assertion_commitment)
        if self.prior_erasure_digest is not None:
            _digest(self.prior_erasure_digest)
        if type(self.valid_interval)is not WorldIntervalV1:
            raise TypeError("World index requires its signed valid-time metadata")
        _text(self.assertion_id, "index assertion"); _text(self.adoption_operation_id, "adoption")
        _sequence(self.known_from_sequence, "index adoption")
        if (type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 16
                or len(set(self.source_refs)) != len(self.source_refs)
                or any(AtomKey.from_token(ref).type_name != "memory.source" for ref in self.source_refs)):
            raise ValueError("World index Source roots differ")
        if type(self.dispute_refs) is not tuple or len(self.dispute_refs) > 16:
            raise ValueError("World index dispute closure differs")


def install_world_history_schema_v1(db):
    db.execute(DDL)
    db.execute(INDEX_DDL)
    db.execute(ERASURE_DDL)
    db.execute(ERASURE_INDEX_DDL)


class InstalledWorldHistoryReadersV1:
    def __init__(self, *, issuer, owner_binding):
        from .issuers import D11BudgetJobIssuer
        from ..graph_coordinator import OwnerLeaseBindingV1
        if type(issuer) is not D11BudgetJobIssuer or type(owner_binding) is not OwnerLeaseBindingV1:
            raise TypeError("World needs the actual installed W01 issuer and current Owner binding")
        self.issuer, self.owner_binding = issuer, owner_binding


def _world_point(db,table,columns,key_columns,key):
    where=" AND ".join(name+"=?" for name in key_columns)
    return _producer_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,
        legacy_reader=lambda: db.execute("SELECT "+",".join(columns)+" FROM "+table+" WHERE "+where,key).fetchone())


def _namespace_version(namespace, version):
    if NamespaceId.from_key(version.key) != namespace:
        raise ValueError("World original crossed namespace")


def _index_metadata(db, namespace, issuer, ref):
    from .world_owner_read_v3 import register_world_index_locator_v3
    register_world_index_locator_v3(db,ref)
    row = _producer_original_point_v3(db,table=TABLE,
        columns=("payload_json","payload_digest","signature","source_refs_json","assertion_id","assertion_commitment","known_sequence","supersedes_ref"),
        key_columns=("bot","persona","original_ref"),key=(*namespace.as_tuple,ref),
        legacy_reader=lambda: db.execute("SELECT payload_json,payload_digest,signature,source_refs_json,assertion_id,assertion_commitment,known_sequence,supersedes_ref FROM "+TABLE+
            " WHERE bot=? AND persona=? AND original_ref=?",(*namespace.as_tuple,ref)).fetchone())
    if row is None:
        raise MissingProductionOriginalV1("actual_world_revision_index:" + ref)
    if len(row[0].encode()) > 16384:
        raise ValueError("World fixed metadata exceeds its installed row bound")
    issuer._signer.verify(SIGN_KIND,row[0],row[2])
    raw = json.loads(row[0])
    index = decode_world_value_v1(raw, WorldRevisionIndexV1)
    if (canonical_serialize(raw) != row[0] or canonical_digest(raw) != row[1]
            or index.input_version.key.token != ref
            or canonical_serialize(index.source_refs) != row[3]
            or (index.assertion_id,index.assertion_commitment,index.known_from_sequence,index.supersedes_ref) != row[4:]
            or index.assertion_commitment!=world_assertion_commitment_v1(namespace,index.assertion_id,issuer)):
        raise ValueError("World locator metadata differs from its signed exact original")
    for version in (index.input_version,index.event_version,index.perspective_version,index.interpretation_version):
        if version is not None:
            _namespace_version(namespace,version)
    register_world_index_locator_v3(db,ref,index=index)
    receipt = _world_point(db,"graph_bundle_operations",("receipt_json","commit_seq"),("bot","persona","operation_id"),
        (*namespace.as_tuple,index.adoption_operation_id))
    history = _world_point(db,"graph_history",("event_bot","event_persona","event_id","valid"),("token","revision"),
        (ref,index.input_version.revision))
    if receipt is None or history != (*namespace.as_tuple,index.adoption_operation_id,1):
        raise ValueError("World index has no actual immutable Graph adoption")
    from .domain_production_originals_v1 import _receipt
    actual_receipt = _receipt(json.loads(receipt[0]))
    if (receipt[1] != index.known_from_sequence or actual_receipt.commit_seq != receipt[1]
            or canonical_digest(actual_receipt) != index.adoption_receipt_digest
            or index.input_version not in actual_receipt.write_versions):
        raise ValueError("World knowledge sequence does not match its real adopted receipt")
    from .world_owner_read_v3 import world_producer_metadata_v3
    handled,producer=world_producer_metadata_v3(db,namespace,index.adoption_operation_id)
    if not handled:
        raise MissingProductionOriginalV1("actual_World_producer_metadata_EOF")
    if (producer["domain"]!="d03" or producer["operation_kind"] not in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}
            or producer["operation_id"]!=index.adoption_operation_id or producer["namespace"]!=namespace
            or producer["schema"]!="d03.current-"+producer["operation_kind"]+".v1"
            or tuple(producer["world_source_roots"])!=index.source_refs):
        raise ValueError("World index roots differ from its actual producer metadata provenance")
    return index


def _page_metadata(db, namespace, request, issuer):
    from .world_owner_read_v3 import world_page_metadata_rows_v3
    handled,prepared=world_page_metadata_rows_v3(db,namespace,request)
    actual = None if handled else db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?",namespace.as_tuple).fetchone()
    watermark = prepared[1] if handled else actual[0] if actual else 0
    if request.knowledge_as_of > watermark:
        raise MissingProductionOriginalV1("World_knowledge_point_not_yet_committed")
    if request.cursor is not None:
        if (request.cursor.query_digest != request.query_digest
                or request.cursor.knowledge_watermark != request.knowledge_as_of):
            raise ValueError("World cursor changed its query or frozen knowledge horizon")
    after = request.cursor.after_assertion_commitment if request.cursor else ""
    # Choose the last known revision before applying valid time or perspective;
    # filtering first would resurrect a genuinely superseded earlier assertion.
    rows = prepared[0] if handled else db.execute(WORLD_PAGE_SQL,
        (*namespace.as_tuple,*namespace.as_tuple,after,request.knowledge_as_of,request.knowledge_as_of,
            request.coverage_bound+1)).fetchall()
    selected=tuple(_index_metadata(db,namespace,issuer,locator) if kind=="revision" else
        _erasure_metadata(db,namespace,issuer,identity,sequence)
        for kind,identity,sequence,locator in rows[:request.coverage_bound])
    return selected,len(rows)<=request.coverage_bound,watermark


def _input_index(namespace, value, version, operation_id, receipt, issuer, source_roots):
    return WorldRevisionIndexV1(version,canonical_digest(plain_v1(value)),value.assertion_id,
        world_assertion_commitment_v1(namespace,value.assertion_id,issuer),value.valid_interval,
        operation_id,canonical_digest(receipt),receipt.commit_seq,source_roots,value.event_version,
        value.perspective_version,value.interpretation_version,value.supersedes_ref,value.correction_ref,value.dispute_refs,value.prior_erasure_digest)


def _historical_body(db, namespace, version, *, maximum_sequence):
    _namespace_version(namespace,version)
    row = read_graph_row_v3(db,("value","valid","event_id"),where="token=? AND revision=?",
        parameters=(version.key.token,version.revision),history=True)
    if row is None or row[1] != 1:
        raise MissingProductionOriginalV1("exact_World_historical_version:" + version.key.type_name)
    from .world_owner_read_v3 import register_world_historical_operation_v3
    register_world_historical_operation_v3(db,version,row[2])
    committed = _world_point(db,"graph_bundle_operations",("commit_seq",),("bot","persona","operation_id"),
        (*namespace.as_tuple,row[2]))
    if committed is None or committed[0] > maximum_sequence:
        raise MissingProductionOriginalV1("World_historical_version_not_known_at_requested_sequence")
    value = json.loads(row[0])
    if len(canonical_serialize(value).encode()) > 8192:
        raise MissingProductionOriginalV1("bounded_World_historical_body")
    return value


def _owner_groups(read, db, readers, roots, purpose, audience):
    owner = readers.owner_binding
    if (purpose not in owner.purposes or audience not in owner.audiences
            or read.frame.envelope.authority.purpose != purpose
            or read.frame.envelope.authority.audience != (audience,)):
        raise MissingProductionOriginalV1("current_World_Owner_purpose_audience")
    if roots:
        return read.source_family(db,roots,purpose=purpose,audience=audience)
    return {}


def _metadata_roots(indexes,request):
    roots = tuple(sorted({ref for index in indexes if type(index)is WorldRevisionIndexV1
        and index.perspective_version==request.perspective_version
        and index.valid_interval.at(request.event_time_as_of)!="outside" for ref in index.source_refs}))
    if len(roots) > 16:
        raise MissingProductionOriginalV1("World_page_Source_union_exceeds_existing_semantic_bound")
    return roots


def _query_world(db, read, readers, request):
    ns = read.frame.envelope.authority.namespace
    _require_world_request_perspective_v1(db,ns,request)
    indexes,eof,_ = _page_metadata(db,ns,request,readers.issuer)
    roots = _metadata_roots(indexes,request)
    # Every root and each full current parent/Access/Correction is checked before
    # the first historical World, perspective or interpretation body is opened.
    records = _owner_groups(read,db,readers,roots,request.purpose,request.audience)
    revisions,unknowns = [],[]
    for index in indexes:
        if type(index)is WorldErasureBarrierV1:
            unknowns.append("erased_assertion:"+index.assertion_commitment)
            continue
        if index.perspective_version!=request.perspective_version:
            continue
        if index.valid_interval.at(request.event_time_as_of)=="outside":
            continue
        raw = _historical_body(db,ns,index.input_version,maximum_sequence=request.knowledge_as_of)
        value = decode_world_value_v1(raw,WorldAssertionInputV1)
        source_roots=_world_input_producer_roots_v1(db,ns,index,value)
        if _input_index(ns,value,index.input_version,index.adoption_operation_id,
                _actual_receipt(db,ns,index.adoption_operation_id),readers.issuer,source_roots) != index:
            raise ValueError("World historical body differs from its prior signed Source metadata")
        match = value.valid_interval.at(request.event_time_as_of)
        if match == "outside":
            continue
        if value.assertion_status in {"retracted","unknown"}:
            unknowns.append(index.assertion_id+":"+value.assertion_status)
            continue
        perspective = _historical_body(db,ns,index.perspective_version,maximum_sequence=request.knowledge_as_of)
        decode_world_value_v1(perspective,SelfPerspective)
        interpretation = None
        if index.interpretation_version is not None:
            interpretation = _historical_body(db,ns,index.interpretation_version,maximum_sequence=request.knowledge_as_of)
            from ..domains.d07 import D07DomainProvider
            next(s for s in D07DomainProvider.type_specs() if s.name=="d07.current_interpretation.v1").validator(interpretation)
            if not set(interpretation["source_refs"]) <= set(records):
                raise ValueError("World historical cognition escaped its prior ALL Source closure")
        if match == "unknown":
            unknowns.append(index.assertion_id+":imprecise_event_time")
        successor_sequence = None  # Later knowledge is not disclosed by this historical view.
        perspective_projection=WorldPerspectiveProjectionV1(index.perspective_version,canonical_digest(perspective),
            **{name:perspective[name] for name in ("persona_ref","self_entity_ref","scene_ref","role_head_id","identity_mapping_ref","arrival_event_ref")})
        cognition_projection=None if interpretation is None else WorldInterpretationProjectionV1(index.interpretation_version,canonical_digest(interpretation),
            **{name:interpretation[name] for name in ("question_key","proposition","stance","subjective_conviction","evidence_status")},
            meaningful_unknowns=tuple(interpretation["meaningful_unknowns"]))
        revisions.append(WorldAssertionRevisionV1(index.input_version,index.input_digest,index.adoption_operation_id,
            index.adoption_receipt_digest,index.known_from_sequence,index.known_from_sequence,successor_sequence,value,match,
            perspective_projection,cognition_projection))
    next_cursor = None if eof else WorldViewCursorV1(request.query_digest,request.knowledge_as_of,indexes[-1].assertion_commitment)
    source_versions = tuple(version for version in read.frame.snapshot.versions if version.key.token in records)
    return WorldViewResultV1(request,tuple(revisions),"partial" if not eof or request.cursor is not None else "unknown" if unknowns else "complete",
        eof,next_cursor,request.knowledge_as_of,len(indexes),tuple(unknowns),roots,source_versions,
        read.frame.envelope.version_guard.access_epoch,read.frame.envelope.version_guard.delete_epoch)


def _actual_receipt(db, namespace, operation_id):
    from .domain_production_originals_v1 import _receipt
    row=_world_point(db,"graph_bundle_operations",("receipt_json",),("bot","persona","operation_id"),
        (*namespace.as_tuple,operation_id))
    if row is None:
        raise MissingProductionOriginalV1("actual_World_adoption_receipt")
    return _receipt(json.loads(row[0]))


def _input_refs(value):
    return tuple(dict.fromkeys((value.event_version.key.token,value.perspective_version.key.token,
        *((value.interpretation_version.key.token,) if value.interpretation_version is not None else ()),
        )))


def read_plan_world_operation_v1(db, *, namespace, activity_id, operation_id, operation_kind, request, installed_readers):
    keys=[owner_grant_key(*namespace.as_tuple)]
    if operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
        value=request.assertion
        keys.extend(AtomKey.from_token(ref) for ref in _input_refs(value))
        keys.append(world_assertion_key_v1(namespace,value.revision_id))
        related=_world_related_metadata_v1(db,namespace,value,installed_readers.issuer)
        roots=tuple(sorted({*value.source_refs,*(ref for index in related for ref in index.source_refs)}))
        if len(roots)>16:
            raise MissingProductionOriginalV1("World_reference_sources_exceed_original_root_bound")
        _require_latest_world_predecessor_v1(db,namespace,value,installed_readers.issuer,
            prior_erasure_ref=request.prior_erasure_ref if operation_kind=="relearn_world_assertion_v1" else None)
        if value.supersedes_ref is not None:
            prior=_index_metadata(db,namespace,installed_readers.issuer,value.supersedes_ref)
            if prior.assertion_id!=value.assertion_id:
                raise ValueError("World predecessor changed stable assertion identity")
        causal_ref=value.event_version.key.token
    elif operation_kind=="query_world_view_v1":
        _require_world_request_perspective_v1(db,namespace,request)
        indexes,_,_=_page_metadata(db,namespace,request,installed_readers.issuer)
        roots=_metadata_roots(indexes,request)
        keys.append(world_view_key_v1(namespace,operation_id))
        causal_ref=owner_grant_key(*namespace.as_tuple).token
    elif operation_kind=="project_world_perspective_v1":
        view=_view_plan_metadata(db,namespace,request.view_version)
        roots=tuple(view["source_refs"])
        keys.extend((request.view_version.key,request.communication_grant_version.key,
            world_expression_key_v1(namespace,activity_id,operation_id)))
        causal_ref=request.view_version.key.token
    else:
        raise ValueError("unregistered World operation")
    if operation_kind!="query_world_view_v1":
        from .domain_mesh_tick_v1 import semantic_tick_key_v1
        keys.append(semantic_tick_key_v1(namespace,activity_id,causal_ref,"world-history.v1"))
    return production_read_plan_v1((),tuple(keys),roots,())


def _view_plan_metadata(db, namespace, version):
    # Dependency rows are locator-only. The signed World body is opened by the
    # actual stage only after the current full Source closure in its frame.
    _namespace_version(namespace,version)
    from .world_owner_read_v3 import world_view_source_keys_v3
    handled,keys=world_view_source_keys_v3(db,namespace,version)
    if handled:
        return {"source_refs":keys}
    row=db.execute("SELECT revision,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (version.key.token,*namespace.as_tuple)).fetchone()
    if row!=(version.revision,1):
        raise MissingProductionOriginalV1("actual_current_World_view")
    refs=db.execute("SELECT dependency_token FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token",
        (version.key.token,)).fetchall()
    sources=tuple(ref for (ref,) in refs if AtomKey.from_token(ref).type_name=="memory.source")
    if not sources or len(sources)>16:
        raise MissingProductionOriginalV1("actual_World_view_Source_metadata")
    return {"source_refs":sources}


def require_current_world_view_v1(db, *, read, readers, atom):
    value=decode_world_value_v1(atom.value,WorldViewResultV1)
    _require_actual_world_view_adoption_v1(db,read.frame.envelope.authority.namespace,atom,value)
    roots=_view_plan_metadata(db,read.frame.envelope.authority.namespace,GraphVersion(atom.key,atom.revision))["source_refs"]
    _owner_groups(read,db,readers,roots,value.request.purpose,value.request.audience)
    current=_query_world(db,read,readers,value.request)
    if (value.coverage!="complete" or value.request.cursor is not None or not value.eof or value.unknowns or not value.revisions
            or (current.request,current.revisions,current.coverage,current.eof,current.source_refs) !=
                (value.request,value.revisions,value.coverage,value.eof,value.source_refs)):
        raise MissingProductionOriginalV1("complete_currently_authorized_actual_historical_World_view")
    return value


def _mesh_stage(db, frame, request, kind, causal, roots, semantic_versions, *, writes, provenance, domain, proposal_hash):
    from .domain_mesh_tick_v1 import MeshTickInputsV1,stage_world_mesh_companion_v1,combine_semantic_mesh_stage_v1
    semantic_value=provenance["world_assertion"] if kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"} else provenance["world_expression"]
    semantic_digest=world_progress_digest_v1(kind,semantic_value)
    inputs=MeshTickInputsV1(causal_original=causal,source_roots=roots,predecessors=(),
        semantic_originals=(causal,),semantic_versions=semantic_versions,
        cancellation_generation=0,semantic_digest=semantic_digest,original_deadline_utc=frame.envelope.deadline_utc)
    companion=stage_world_mesh_companion_v1(db,frame=frame,operation_kind=kind,request=request,actual_inputs=inputs)
    base=stage_result_v1(frame,domain,kind,request,writes=writes,
        provenance={**provenance,"semantic_mesh":companion.trace},
        proposal_schema=domain+".proposal.v1",proposal_hash=proposal_hash)
    result=combine_semantic_mesh_stage_v1(base,companion)
    _register_world_proposals(db,result,request,kind)
    return result


def stage_world_operation_v1(db, *, operation_kind, frame, request, installed_readers):
    if type(installed_readers) is not InstalledWorldHistoryReadersV1 or operation_kind not in WORLD_OPERATIONS:
        raise TypeError("exact installed World readers and operation required")
    read=CurrentDomainReadV1(frame)
    read.check(db)
    ns=frame.envelope.authority.namespace
    if operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
        value=request.assertion
        records=_owner_groups(read,db,installed_readers,value.source_refs,"consolidation",frame.envelope.authority.audience[0])
        barrier=_require_latest_world_predecessor_v1(db,ns,value,installed_readers.issuer,
            prior_erasure_ref=request.prior_erasure_ref if operation_kind=="relearn_world_assertion_v1" else None)
        event=read.head(db,value.event_version.key,required=True)
        perspective=read.head(db,value.perspective_version.key,required=True)
        if (event.revision!=value.event_version.revision or perspective.revision!=value.perspective_version.revision
                or not set(event.value["source_refs"])<=set(records)):
            raise ValueError("World assertion must use actual guarded event/perspective versions and Source closure")
        typed_event=decode_world_value_v1(event.value,WorldEvent)
        typed_perspective=decode_world_value_v1(perspective.value,SelfPerspective)
        if operation_kind=="relearn_world_assertion_v1":
            _require_fresh_world_sources_v1(db,read,barrier,typed_event.source_refs)
        if value.received_at is not None:
            raise MissingProductionOriginalV1("World_received_time_requires_actual_ingress_original_not_caller_time")
        if (typed_perspective.arrival_event_ref!=event.key.token or typed_event.learned_at!=value.learned_at
                or (typed_event.occurred_from,typed_event.occurred_until)!=(value.occurred_interval.lower,value.occurred_interval.upper)
                or typed_event.reality!=value.reality):
            raise ValueError("World time/origin/perspective must match its actual material event")
        if value.origin_kind=="simulated" and value.reality!="simulated" or value.origin_kind!="simulated" and any(r.source_kind=="simulated" for r in records.values()):
            raise ValueError("World cannot upgrade simulated ancestry")
        primary=tuple(records[ref] for ref in typed_event.source_refs)
        if value.origin_kind=="observed" and not all(record.source_kind=="observed" for record in primary):
            raise MissingProductionOriginalV1("World_observed_origin_requires_actual_primary_observations")
        if value.assertion_status=="confirmed" and (typed_event.reality in {"candidate","simulated"}
                or not any(record.source_kind=="observed" and record.assertion_status=="confirmed" for record in primary)):
            raise MissingProductionOriginalV1("World_confirmation_requires_actual_event_primary_observed_confirmed_support")
        allowed_roots=set(typed_event.source_refs)
        if value.interpretation_version is not None:
            cognition=read.head(db,value.interpretation_version.key,required=True)
            from ..domains.d07 import D07DomainProvider
            next(spec for spec in D07DomainProvider.type_specs() if spec.name==cognition.key.type_name).validator(cognition.value)
            actual_sequence=db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?",ns.as_tuple).fetchone()[0]
            if _historical_body(db,ns,value.interpretation_version,maximum_sequence=actual_sequence)!=cognition.value:
                raise ValueError("World cognition differs from its actual historical adoption")
            allowed_roots.update(cognition.value["source_refs"])
            if cognition.revision!=value.interpretation_version.revision or not set(cognition.value["source_refs"])<=set(records):
                raise ValueError("World interpretation must be the actual D07 adopted source-qualified version")
        if not set(value.source_refs)<=allowed_roots:
            raise ValueError("World auxiliary roots are not actual event or selected cognition dependencies")
        related_roots=_require_world_related_originals_v1(db,read,installed_readers,value)
        prior=None
        if value.supersedes_ref is not None:
            prior=_index_metadata(db,ns,installed_readers.issuer,value.supersedes_ref)
            if prior.assertion_id!=value.assertion_id:
                raise ValueError("World successor changed stable assertion identity")
        key=world_assertion_key_v1(ns,value.revision_id)
        if read.head(db,key).revision:
            raise ValueError("World input revisions are immutable")
        roots=tuple(sorted(set((*value.source_refs,*related_roots))))
        write=GraphWrite(key,plain_v1(value))
        causal=ProductionOriginalRefV1("d03.world_event",event.key.token,canonical_digest(event.value),(value.event_version,))
        return _mesh_stage(db,frame,request,operation_kind,causal,roots,(value.event_version,value.perspective_version),
            writes=(write,),provenance={"world_assertion":plain_v1(value),"world_source_roots":roots},domain="d03",
            proposal_hash=ContextProvider().descriptor.request_schema_hash)
    if operation_kind=="query_world_view_v1":
        value=_query_world(db,read,installed_readers,request)
        key=world_view_key_v1(ns,frame.envelope.identity.operation_id)
        if read.head(db,key).revision:
            raise ValueError("World view operation already has an immutable result")
        dependencies=tuple(AtomKey.from_token(ref) for ref in value.source_refs)
        result=stage_result_v1(frame,"d03",operation_kind,request,
            writes=(GraphWrite(key,plain_v1(value),dependencies),),provenance={"world_view":plain_v1(value)},
            proposal_schema="d03.proposal.v1",proposal_hash=ContextProvider().descriptor.request_schema_hash)
        _register_world_proposals(db,result,request,operation_kind)
        return result
    return _stage_world_expression(db,read,installed_readers,request)


def record_world_assertion_after_commit_v1(db, *, stage, receipt, installed_readers):
    if stage.operation_kind not in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
        return None
    if not db.in_transaction or receipt.status!="committed" or receipt.operation_id!=stage.operation_id:
        raise ValueError("World index requires its same actual W01 adoption transaction")
    raw=json.loads(stage.original_payload_json)["request"]["assertion"]
    value=decode_world_value_v1(raw,WorldAssertionInputV1)
    key=world_assertion_key_v1(stage.namespace,value.revision_id)
    versions=tuple(v for v in receipt.write_versions if v.key==key)
    if len(versions)!=1:
        raise ValueError("World immutable input is absent from the real receipt members")
    version=versions[0]
    actual=db.execute("SELECT event_bot,event_persona,event_id,valid FROM graph_history WHERE token=? AND revision=?",
        (key.token,version.revision)).fetchone()
    if actual!=(*stage.namespace.as_tuple,stage.operation_id,1):
        raise ValueError("World same-CAS immutable history member differs from its verified stage/receipt")
    source_roots=tuple(json.loads(stage.original_payload_json)["provenance"]["world_source_roots"])
    index=_input_index(stage.namespace,value,version,stage.operation_id,receipt,installed_readers.issuer,source_roots)
    encoded=canonical_serialize(plain_v1(index))
    row=(*stage.namespace.as_tuple,key.token,"world_revision_index",stage.operation_id,encoded,
        canonical_digest(plain_v1(index)),installed_readers.issuer._signer.sign(SIGN_KIND,encoded),
        canonical_serialize(index.source_refs),index.assertion_id,index.assertion_commitment,index.known_from_sequence,index.supersedes_ref)
    db.execute("INSERT INTO "+TABLE+" VALUES("+",".join("?" for _ in COLUMNS)+")",row)
    return ProductionOriginalRefV1(SIGN_KIND,key.token,canonical_digest(plain_v1(index)),(version,))


def _stage_world_expression(db,read,readers,request):
    from ..domains.d08.execution import _decode_communication_grant
    from ..domains.d09 import D09ExpressionProvider,ExpressionClaim,ClaimKind
    ns=read.frame.envelope.authority.namespace
    _owner_groups(read,db,readers,tuple(_view_plan_metadata(db,ns,request.view_version)["source_refs"]),
        "expression",read.frame.envelope.authority.audience[0])
    atom=read.head(db,request.view_version.key,required=True)
    if atom.revision!=request.view_version.revision:
        raise ValueError("World expression changed its exact view version")
    view=require_current_world_view_v1(db,read=read,readers=readers,atom=atom)
    grant_atom=read.head(db,request.communication_grant_version.key,required=True)
    if grant_atom.revision!=request.communication_grant_version.revision:
        raise ValueError("World expression changed its actual D08 grant")
    grant=_decode_communication_grant(grant_atom.value)
    claims=[]
    versions=[]
    for revision in view.revisions:
        if revision.assertion.interpretation_version is None or revision.interpretation is None:
            raise MissingProductionOriginalV1("actual_historical_D07_interpretation_for_World_expression")
        perspective=revision.perspective
        if perspective.scene_ref!=request.scene_ref:
            raise MissingProductionOriginalV1("actual_historical_perspective_scene")
        historical=revision.interpretation
        # Preserve the actual historical adopted explanation as a reported
        # belief. D09 cannot promote it to today's independently confirmed fact.
        text=("当时的解释（知识序号 "+str(revision.known_from_sequence)+"，立场 "+historical.stance+"）："
            +historical.proposition)
        if type(text) is not str or not text or len(text)>2048:
            raise MissingProductionOriginalV1("bounded_actual_historical_interpretation_text")
        claims.append(ExpressionClaim("world-then:"+revision.input_digest,text,ClaimKind.SUBJECTIVE_JUDGMENT,
            revision.assertion.source_refs,(view.request.audience,),("expression",),
            revision.assertion.interpretation_version.key.token))
        versions.append(revision.assertion.interpretation_version)
    prepared=D09ExpressionProvider.prepare_blueprint(grant,request.scene_ref,request.conversation_epoch,tuple(claims),
        now=read.frame.now_utc)
    if prepared.status!="complete":
        raise MissingProductionOriginalV1("current_D08_granted_World_expression_blueprint")
    output=WorldPerspectiveExpressionInputV1(request.view_version,view.digest,view.request.perspective_version,
        tuple(versions),canonical_serialize(plain_v1(prepared.blueprint)),view.source_refs)
    key=world_expression_key_v1(ns,read.frame.envelope.identity.activity_id,read.frame.envelope.identity.operation_id)
    if read.head(db,key).revision:
        raise ValueError("World expression input is immutable")
    causal=ProductionOriginalRefV1(VIEW_TYPE,atom.key.token,canonical_digest(atom.value),(request.view_version,))
    return _mesh_stage(db,read.frame,request,"project_world_perspective_v1",causal,view.source_refs,
        (request.view_version,request.communication_grant_version),writes=(GraphWrite(key,plain_v1(output),
            (atom.key,grant_atom.key,*(AtomKey.from_token(ref) for ref in view.source_refs))),),
        provenance={"world_expression":plain_v1(output)},domain="d09",
        proposal_hash=D09ExpressionProvider().descriptor.request_schema_hash)


def world_semantic_target_v1(db, *, issuer, frame, question, atom):
    from .d07_execution_v1 import D07SemanticTargetOriginalV1
    # The existing D07 service supplies a current Owner-bound frame; its
    # existing Source/Owner admission remains mandatory for this target.
    from ..domains.d01.production_operations_v1 import current_frame_guard_v1
    current_frame_guard_v1(frame)
    read=CurrentDomainReadV1(frame)
    value=decode_world_value_v1(atom.value,WorldViewResultV1)
    read.source_family(db,value.source_refs,purpose=frame.envelope.authority.purpose,audience=frame.envelope.authority.audience[0])
    if (value.request.purpose!=frame.envelope.authority.purpose
            or frame.envelope.authority.audience!=(value.request.audience,)
            or set(value.source_refs)!=set(question.source_refs) or value.coverage!="complete"
            or value.request.cursor is not None or not value.eof or value.unknowns):
        raise MissingProductionOriginalV1("current_complete_World_semantic_target")
    _require_actual_world_view_adoption_v1(db,frame.envelope.authority.namespace,atom,value)
    # This target is fed by the existing freeze_current_d07_stage/cognition
    # workflow and its original adoption validator, not a new belief adopter.
    encoded=canonical_serialize(atom.value)
    return D07SemanticTargetOriginalV1("graph_head",atom.key.token,atom.revision,canonical_digest(atom.value),
        encoded,value.source_refs,(GraphVersion(atom.key,atom.revision),*value.source_versions))


def read_world_cold_page_v1(db, *, frame, request, installed_readers):
    """The real cold consumer resumes the same query cursor and current rights."""
    read=CurrentDomainReadV1(frame)
    read.check(db)
    return _query_world(db,read,installed_readers,request)

def world_progress_digest_v1(operation_kind,value):
    """Only actual semantic changes advance a mesh wave; control IDs do not."""
    if operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
        names=("assertion_id","event_version","perspective_version","interpretation_version",
            "valid_interval","occurred_interval","learned_at","received_at","source_refs",
            "origin_kind","reality","assertion_status","scope","correction_ref","dispute_refs")
        return canonical_digest({name:value[name] for name in names})
    if operation_kind=="project_world_perspective_v1":
        blueprint=json.loads(value["blueprint_json"])
        return canonical_digest({"perspective":value["perspective_version"],
            "historical_interpretations":value["historical_interpretation_versions"],
            "claims":[{name:claim[name] for name in ("text","kind","source_refs","allowed_audiences","eligibility","disclosure_ref")}
                for claim in blueprint["claims"]],"scene_ref":blueprint["scene_ref"],
            "source_refs":value["source_refs"]})
    raise ValueError("World query and cold observations do not manufacture semantic progress")


def _register_world_proposals(db,stage,request,operation_kind):
    from .world_owner_read_v3 import register_world_staged_proposal_v3
    for proposal in stage.proposals:
        if proposal.domain in {"d03","d09"}:
            register_world_staged_proposal_v3(db,proposal,request=request,operation_kind=operation_kind)

def world_assertion_commitment_v1(namespace,assertion_id,issuer):
    """Purpose-keyed opaque stable identity; this commitment grants no rights."""
    return issuer._signer.sign("d11.world-assertion-identity.v1",
        canonical_serialize((namespace.as_tuple,assertion_id)))


def world_revision_commitment_v1(index,issuer):
    return issuer._signer.sign("d11.world-revision-erasure-identity.v1",
        canonical_serialize((index.input_version,index.input_digest,index.adoption_receipt_digest)))


def world_erasure_barrier_payload_v1(index,*,namespace,revision_commitment,deletion_generation,deletion_knowledge_sequence,delete_original_commitment):
    """Pure conversion only; Root's actual C09 transaction supplies verified originals."""
    if type(index)is not WorldRevisionIndexV1:
        raise TypeError("World erasure conversion needs its authenticated exact index metadata")
    return WorldErasureBarrierV1(namespace,index.assertion_commitment,index.known_from_sequence,
        revision_commitment,deletion_generation,deletion_knowledge_sequence,delete_original_commitment)


def decode_world_erasure_barrier_row_v1(columns,row,*,namespace=None):
    if tuple(columns)!=ERASURE_COLUMNS or len(row)!=len(ERASURE_COLUMNS):
        raise ValueError("World erasure barrier row shape differs")
    raw=dict(zip(columns,row))
    actual_namespace=NamespaceId(raw["bot"],raw["persona"])
    if namespace is not None and actual_namespace!=namespace:
        raise ValueError("World erasure barrier crossed namespace")
    payload=json.loads(raw["payload_json"])
    value=decode_world_value_v1(payload,WorldErasureBarrierV1)
    if (value.namespace!=actual_namespace or canonical_serialize(payload)!=raw["payload_json"]
            or canonical_digest(payload)!=raw["payload_digest"]
            or (value.assertion_commitment,value.known_from_sequence,value.revision_commitment,
                value.deletion_generation,value.deletion_knowledge_sequence,value.delete_original_commitment)!=(raw["assertion_commitment"],
                raw["known_sequence"],raw["revision_commitment"],raw["deletion_generation"],raw["deletion_knowledge_sequence"],raw["delete_original_commitment"])):
        raise ValueError("World erasure barrier exact metadata commitment differs")
    from ..domains.d03.world_history_v1 import _digest
    _digest(raw["signature"])
    return value


def _erasure_metadata(db,namespace,issuer,identity,sequence):
    row=_world_point(db,ERASURE_TABLE,ERASURE_COLUMNS,("bot","persona","assertion_commitment","known_sequence"),
        (*namespace.as_tuple,identity,sequence))
    if row is None:
        raise MissingProductionOriginalV1("actual_World_erasure_coverage_barrier")
    value=decode_world_erasure_barrier_row_v1(ERASURE_COLUMNS,row,namespace=namespace)
    issuer._signer.verify(ERASURE_SIGN_KIND,row[8],row[10])
    return value

def _require_actual_world_view_adoption_v1(db,namespace,atom,value):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    history=_world_point(db,"graph_history",("event_id","valid"),("token","revision"),(atom.key.token,atom.revision))
    if history is None or history[1]!=1:
        raise MissingProductionOriginalV1("actual_adopted_World_view_history")
    original=read_adopted_domain_operation_v1(db,namespace,history[0])
    if (original is None or (original["domain"],original["operation_kind"])!=("d03","query_world_view_v1")
            or original["payload"]["request"]!=plain_v1(value.request)
            or original["payload"]["provenance"]!={"world_view":atom.value}
            or original["payload"]["coverage"]!="complete"
            or original["payload"]["missing_inputs"]):
        raise ValueError("World view must be its exact actual query producer original")
    receipt=original["receipt"]
    if GraphVersion(atom.key,atom.revision) not in receipt.write_versions:
        raise ValueError("World view is not in its actual W01 receipt members")
    if tuple(original["payload"]["writes"])!=({"key":atom.key.token,"value":atom.value,
            "dependencies":list(value.source_refs)},):
        raise ValueError("World view producer writes or Source dependencies differ")
    current_roots=_view_plan_metadata(db,namespace,GraphVersion(atom.key,atom.revision))["source_refs"]
    if set(current_roots)!=set(value.source_refs):
        raise ValueError("World view lost its full actual root dependencies")
    actual_sources={v.key.token for v in receipt.read_versions if v.key.type_name=="memory.source"}
    if not {v.key.token for v in value.source_versions}<=actual_sources:
        raise ValueError("World view historical producer Source closure is incomplete")
    return original

def decode_world_revision_index_row_v1(columns,row,*,namespace=None):
    """Pure exact retained-row codec, never proof of permission or adoption."""
    if tuple(columns)!=COLUMNS or len(row)!=len(COLUMNS):
        raise ValueError("World revision index row shape differs")
    data=dict(zip(columns,row))
    actual_namespace=NamespaceId(data["bot"],data["persona"])
    if namespace is not None and namespace!=actual_namespace:
        raise ValueError("World revision index crossed namespace")
    raw=json.loads(data["payload_json"])
    index=decode_world_value_v1(raw,WorldRevisionIndexV1)
    if (canonical_serialize(raw)!=data["payload_json"] or canonical_digest(raw)!=data["payload_digest"]
            or data["kind"]!="world_revision_index"
            or index.input_version.key.token!=data["original_ref"]
            or index.adoption_operation_id!=data["producing_operation_id"]
            or canonical_serialize(index.source_refs)!=data["source_refs_json"]
            or (index.assertion_id,index.assertion_commitment,index.known_from_sequence,index.supersedes_ref)!=(
                data["assertion_id"],data["assertion_commitment"],data["known_sequence"],data["supersedes_ref"])):
        raise ValueError("World revision index exact typed locator differs")
    for version in (index.input_version,index.event_version,index.perspective_version,index.interpretation_version):
        if version is not None:
            _namespace_version(actual_namespace,version)
    from ..domains.d03.world_history_v1 import _digest
    _digest(data["signature"])
    return index

def _require_latest_world_predecessor_v1(db,namespace,value,issuer,*,prior_erasure_ref=None):
    from .world_owner_read_v3 import world_latest_metadata_v3
    identity=world_assertion_commitment_v1(namespace,value.assertion_id,issuer)
    handled,latest=world_latest_metadata_v3(db,namespace,identity)
    if not handled:
        latest=db.execute(WORLD_LATEST_SQL,(*namespace.as_tuple,identity,*namespace.as_tuple,identity)).fetchone()
    if latest is not None and latest[0]=="erasure":
        if prior_erasure_ref is None:
            raise MissingProductionOriginalV1("World_current_predecessor_erased_requires_explicit_relearning_lineage")
        barrier=_erasure_metadata(db,namespace,issuer,identity,latest[1])
        digest=canonical_digest(plain_v1(barrier))
        if ((prior_erasure_ref.assertion_commitment,prior_erasure_ref.known_from_sequence,prior_erasure_ref.payload_digest)!=
                (identity,barrier.known_from_sequence,digest) or value.prior_erasure_digest!=digest
                or value.supersedes_ref is not None):
            raise ValueError("World relearning changed its exact latest erasure lineage")
        return barrier
    if prior_erasure_ref is not None or value.prior_erasure_digest is not None:
        raise MissingProductionOriginalV1("World_relearning_requires_the_latest_actual_erasure_barrier")
    if (None if latest is None else latest[2])!=value.supersedes_ref:
        raise MissingProductionOriginalV1("actual_latest_World_predecessor")
    return None


def _require_fresh_world_sources_v1(db,read,barrier,primary_refs):
    if type(barrier)is not WorldErasureBarrierV1:
        raise ValueError("World relearning requires its authenticated current barrier")
    ns=read.frame.envelope.authority.namespace
    for ref in primary_refs:
        atom=read.head(db,ref,required=True)
        if atom.revision!=1 or atom.value["source_kind"] not in {"reported","observed"}:
            raise MissingProductionOriginalV1("World_relearning_requires_actual_new_material_Source")
        version=GraphVersion(atom.key,atom.revision)
        header=_world_point(db,"graph_history",("event_id","valid"),("token","revision"),(ref,version.revision))
        if header is None or header[1]!=1:
            raise MissingProductionOriginalV1("World_relearning_actual_Source_birth")
        from .world_owner_read_v3 import register_world_historical_operation_v3
        register_world_historical_operation_v3(db,version,header[0])
        receipt=_actual_receipt(db,ns,header[0])
        if receipt.commit_seq<=barrier.deletion_knowledge_sequence or version not in receipt.write_versions:
            raise MissingProductionOriginalV1("World_relearning_Source_must_be_born_after_actual_deletion_watermark")
    return primary_refs

def _world_related_metadata_v1(db,namespace,value,issuer):
    refs=tuple(dict.fromkeys((*( (value.correction_ref,) if value.correction_ref is not None else ()),*value.dispute_refs)))
    result=[]
    for ref in refs:
        key=AtomKey.from_token(ref)
        if key.type_name!=INPUT_TYPE or NamespaceId.from_key(key)!=namespace:
            raise ValueError("World correction/dispute is not a same-namespace World revision")
        index=_index_metadata(db,namespace,issuer,ref)
        if index.assertion_id!=value.assertion_id:
            raise ValueError("World correction/dispute changed stable assertion identity")
        result.append(index)
    return tuple(result)


def _require_world_related_originals_v1(db,read,readers,value):
    ns=read.frame.envelope.authority.namespace
    related=_world_related_metadata_v1(db,ns,value,readers.issuer)
    roots=tuple(sorted({ref for index in related for ref in index.source_refs}))
    if roots:
        _owner_groups(read,db,readers,roots,"consolidation",read.frame.envelope.authority.audience[0])
    for index in related:
        raw=_historical_body(db,ns,index.input_version,maximum_sequence=_actual_receipt(db,ns,index.adoption_operation_id).commit_seq)
        original=decode_world_value_v1(raw,WorldAssertionInputV1)
        actual_roots=_world_input_producer_roots_v1(db,ns,index,original)
        if (original.assertion_id!=value.assertion_id or canonical_digest(raw)!=index.input_digest
                or actual_roots!=index.source_refs):
            raise ValueError("World correction/dispute lost its actual typed historical original")
    return roots


def _world_input_producer_roots_v1(db,namespace,index,value):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    original=read_adopted_domain_operation_v1(db,namespace,index.adoption_operation_id)
    if (original is None or original["domain"]!="d03" or original["operation_kind"] not in {
            "adopt_world_assertion_v1","relearn_world_assertion_v1"}
            or original["receipt"].commit_seq!=index.known_from_sequence
            or canonical_digest(original["receipt"])!=index.adoption_receipt_digest
            or index.input_version not in original["receipt"].write_versions):
        raise ValueError("World input roots require its actual adopted producer")
    payload=original["payload"]
    if payload["request"]["assertion"]!=plain_v1(value) or payload["provenance"]["world_assertion"]!=plain_v1(value):
        raise ValueError("World input producer lost its actual immutable input")
    roots=tuple(payload["provenance"]["world_source_roots"])
    if (roots!=tuple(sorted(set(roots))) or not set(value.source_refs)<=set(roots)
            or any(AtomKey.from_token(ref).type_name!="memory.source" or
                NamespaceId.from_key(AtomKey.from_token(ref))!=namespace for ref in roots)):
        raise ValueError("World producer Source roots are not its complete typed current group")
    source_reads={version.key.token for version in original["read_versions"] if version.key.type_name=="memory.source"}
    if not set(roots)<=source_reads or roots!=index.source_refs:
        raise ValueError("World index Source closure differs from the actual producer provenance/readset")
    return roots


def _require_world_request_perspective_v1(db,namespace,request):
    version=request.perspective_version
    _namespace_version(namespace,version)
    row=_world_point(db,"graph_history",("event_bot","event_persona","event_id","valid"),
        ("token","revision"),(version.key.token,version.revision))
    if row is None or row[:2]!=namespace.as_tuple or row[3]!=1:
        raise MissingProductionOriginalV1("actual_World_request_perspective_original")
    from .world_owner_read_v3 import register_world_historical_operation_v3
    register_world_historical_operation_v3(db,version,row[2])
    receipt=_actual_receipt(db,namespace,row[2])
    if receipt.commit_seq>request.knowledge_as_of or version not in receipt.write_versions:
        raise MissingProductionOriginalV1("World_request_perspective_was_not_known_at_requested_sequence")
    return version
