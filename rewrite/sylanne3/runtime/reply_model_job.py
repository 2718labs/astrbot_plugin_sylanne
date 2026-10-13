"""Transaction-scoped, source-bound D11 preparation for a post-C02 reply.

This module does not grant model egress.  The Authority mints the model fence
from a later GraphCoordinator-produced ``ModelEgressDraftV1``.
"""

from __future__ import annotations

from ..authority_service.current_authority_graph_read_v3 import (
    authority_graph_projection_for_db_v3,require_authority_source_metadata_v3,
    _authority_attachment_owner_v3,read_authority_current_point_v3,authority_current_json_v3,
    authority_current_json_matches_v3)

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json

from ..domains.d07 import CurrentAttentionTicketReadV1
from ..graph_types import GraphSnapshot
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..model_broker.reply_language import ReplySourceSnapshot
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest, canonical_serialize
from .budget import get_budget_lease, reserve_budget
from .d11_types import job_graph_write, runtime_job_key
from .issuers import D02ResourceIssuer, D11BudgetJobIssuer, ResourceQuote
from .jobs import PersistentJob, create_job, get_job


class ReplyModelJobHold(RuntimeError):
    """A current source, attention, cost, or installed authority is missing."""


def d07_attention_quote_id_v1(namespace: NamespaceId, operation_id: str) -> str:
    return "d07-attention-q:" + canonical_digest({
        "schema": "sylanne.post-c02-attention-quote.v1",
        "namespace": list(namespace.as_tuple), "operation_id": operation_id,
    })[:48]


def reply_job_original_operation_id_v1(c02_operation_id: str, source_ref: str) -> str:
    return "reply-job-origin:" + canonical_digest({
        "schema": "sylanne.post-c02-reply-job.v1",
        "c02_operation_id": c02_operation_id, "source_ref": source_ref,
    })[:48]


def reply_job_id_v1(c02_operation_id: str, source_ref: str) -> str:
    return "reply-job:" + canonical_digest({
        "schema": "sylanne.post-c02-reply-job-id.v1",
        "c02_operation_id": c02_operation_id, "source_ref": source_ref,
    })[:48]


@dataclass(frozen=True, slots=True)
class CurrentReplyModelInputsV1:
    c02_receipt: CommitReceipt
    source: ReplySourceSnapshot
    attention: CurrentAttentionTicketReadV1
    conversation_ref: str
    graph_snapshot: GraphSnapshot


_PREPARED_REPLY_INPUT_ISSUER_V3 = object()


@dataclass(frozen=True, slots=True)
class _PreparedReplySourceMetadataV3:
    witness: object
    source_ref: str
    source_revision: int
    access_revision: int

    @property
    def source(self):
        from .dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
        return _SourceMetadataRecordV3(self.witness.metadata)


class _PreparedCurrentReplyModelInputsV3:
    def __init__(self, issuer, receipt, source, attention, conversation, projection, inventory):
        if issuer is not _PREPARED_REPLY_INPUT_ISSUER_V3:
            raise ReplyModelJobHold("actual prepared C02 input issuer required")
        self.c02_receipt,self.source,self.attention = receipt,source,attention
        self.conversation_ref,self.graph_snapshot,self.prepared_inventory = conversation,projection,inventory

    def require_for_v3(self,db,namespace,source_ref):
        inventory=self.prepared_inventory
        inventory.require_current(db,namespace,inventory.query,self.graph_snapshot)
        from ..graph_types import AtomKey
        actual=inventory.source_metadata(db,namespace,inventory.query,AtomKey.from_token(source_ref),
            revision=self.source.source_revision,require_grant=False)
        if actual is not self.source.witness or self.source.source_ref!=source_ref:
            raise ReplyModelJobHold("actual prepared C02 Source witness changed")


class _PrefinalReplyModelInputsV3:
    """Verified C02/current metadata under the actual prefinal Work; no body grant."""
    def __init__(self,issuer,receipt,source,attention,conversation,projection,prefinal,family):
        if issuer is not _PREPARED_REPLY_INPUT_ISSUER_V3:
            raise ReplyModelJobHold('actual prefinal C02 evidence issuer required')
        self.c02_receipt,self.source,self.attention=receipt,source,attention
        self.conversation_ref,self.graph_snapshot=conversation,projection
        self.prefinal_inventory,self.attention_source_read=prefinal,family


class _PreparedFullReplyModelInputsV3:
    """Current FULL metadata route; Source material keeps its separate rights-scoped Work."""
    def __init__(self,issuer,receipt,source,attention,conversation,projection,full_read,source_family,witness,material):
        if issuer is not _PREPARED_REPLY_INPUT_ISSUER_V3:
            raise ReplyModelJobHold('actual ordinary FULL C02 input issuer required')
        self.c02_receipt,self.source,self.attention=receipt,source,attention
        self.conversation_ref,self.graph_snapshot=conversation,projection
        self.prepared_full_read,self.attention_source_read=full_read,source_family
        self.source_witness,self.source_material=witness,material
    def require_for_v3(self,db,namespace,source_ref):
        from .current_graph_full_read_v3 import (PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3,
            require_bound_graph_full_read_proof_for_db_v3,require_bound_graph_full_source_metadata_v3,
            CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3)
        from ..domains.d07.qualified_attention_read import require_qualified_attention_source_family_v3
        from ..graph_types import AtomKey
        full=self.prepared_full_read
        if type(full) not in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):
            raise ReplyModelJobHold('actual ordinary FULL reply input proof required')
        actual=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
            required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3}))
        if actual is not full or self.graph_snapshot is not actual.projection:
            raise ReplyModelJobHold('ordinary FULL reply projection/Work changed')
        witness=require_bound_graph_full_source_metadata_v3(db,namespace,AtomKey.from_token(source_ref),revision=self.source.source_revision)
        if witness is not self.source_witness or self.source.source_ref!=source_ref:
            raise ReplyModelJobHold('ordinary FULL reply Source witness changed')
        if self.source_material is not None:
            record=self.source_material.source_record_for_v3(db=db,prepared_full_read=full,namespace=namespace,
                source_ref=source_ref,audiences=(self.conversation_ref,))
            if record is not self.source.source:raise ReplyModelJobHold('actual Source material changed')
            return
        family=require_qualified_attention_source_family_v3(self.graph_snapshot,namespace,attention=self.attention,
            audience=self.conversation_ref,purpose='expression',prepared_full_read=full,db=db)
        if (family.read_versions!=self.attention_source_read.read_versions
                or family.source_metadata!=self.attention_source_read.source_metadata):
            raise ReplyModelJobHold('ordinary FULL reply Source family/current rights changed')


class _PreparedAuthorityReplyModelInputsV3:
    """Only this Authority Work's selected expression Source body and original C02."""
    def __init__(self,issuer,work,receipt,source,attention,conversation):
        if issuer is not _PREPARED_REPLY_INPUT_ISSUER_V3:
            raise ReplyModelJobHold('actual Authority current C02 input issuer required')
        self.work,self.c02_receipt,self.source,self.attention=work,receipt,source,attention
        self.conversation_ref,self.graph_snapshot=conversation,work.projection
        self.require_for_v3(work.db,work.namespace,source.source_ref)
    def require_for_v3(self,db,namespace,source_ref):
        work=_authority_attachment_owner_v3(db)
        if work is not self.work or self.graph_snapshot is not work.projection:
            raise ReplyModelJobHold('Authority C02 inputs crossed the original Work/projection')
        material=work.source_material
        record=material.source_record_for_v3(db=db,prepared_full_read=work.prepared,namespace=namespace,
            source_ref=source_ref,audiences=(self.conversation_ref,))
        witness=material.witnesses[source_ref].require_current_v3()
        if (record is not self.source.source or self.source.source_ref!=source_ref
                or self.source.source_revision!=witness.revision or material.attention!=self.attention):
            raise ReplyModelJobHold('Authority C02 Source body/attention/versions changed')


@dataclass(frozen=True, slots=True)
class CurrentReplyRouteManifestV2:
    """Original committed private ingress route, pending live host recheck."""

    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    platform_ref: str
    conversation_ref: str
    scene_ref: str
    route_digest: str


def read_current_reply_route_manifest_v2(
    db, namespace: NamespaceId, inputs: CurrentReplyModelInputsV1,
    source_ref: str,
) -> CurrentReplyRouteManifestV2:
    """Derive a reply route from the sealed ingress identity in this graph tx."""
    from .first_ingress_v2 import scene_ref_for_conversation
    from .ingress_observation import read_committed_ingress_identity

    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(inputs) not in {CurrentReplyModelInputsV1, SettledC02ReplySourceV1, _PreparedCurrentReplyModelInputsV3, _PreparedFullReplyModelInputsV3, _PreparedAuthorityReplyModelInputsV3}
            or inputs.c02_receipt.status != "committed"
            or inputs.source.source_ref != source_ref):
        raise ReplyModelJobHold("transactional original reply route required")
    if type(inputs) in (_PreparedCurrentReplyModelInputsV3,_PreparedFullReplyModelInputsV3,_PreparedAuthorityReplyModelInputsV3):
        inputs.require_for_v3(db,namespace,source_ref)
    source_id = source_key_from_ref(source_ref, namespace)
    original = read_committed_ingress_identity(db, namespace, source_id)
    if original is None:
        raise ReplyModelJobHold("original private ingress route is absent")
    try:
        identity = json.loads(original.identity_json)
        platform_ref = identity["platform_ref"]
        conversation_ref = identity["conversation_ref"]
        visibility = identity["visibility"]
        platform = json.loads(platform_ref)
        conversation = json.loads(conversation_ref)
        if (visibility != "private"
                or conversation_ref != inputs.conversation_ref
                or type(platform) is not list or len(platform) != 3
                or type(conversation) is not list or len(conversation) != 2
                or any(type(item) is not str or not item
                       for item in (*platform, *conversation))
                or json.dumps(platform, ensure_ascii=True, separators=(",", ":"))
                   != platform_ref
                or json.dumps(conversation, ensure_ascii=True, separators=(",", ":"))
                   != conversation_ref):
            raise ReplyModelJobHold("original private reply route differs")
        scene_ref = scene_ref_for_conversation(
            namespace, platform_ref, conversation_ref)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ReplyModelJobHold("original private reply route is invalid") from exc
    return CurrentReplyRouteManifestV2(
        namespace, inputs.c02_receipt.operation_id, source_ref,
        platform_ref, conversation_ref, scene_ref,
        canonical_digest({
            "account_ref": platform_ref,
            "destination_ref": conversation_ref,
            "scene_ref": scene_ref,
        }),
    )


@dataclass(frozen=True, slots=True)
class SettledC02ReplySourceV1:
    c02_receipt: CommitReceipt
    source: ReplySourceSnapshot
    conversation_ref: str
    source_qualification: object


def read_settled_c02_reply_source_v1(
    db, issuer: D02ResourceIssuer, namespace: NamespaceId,
    c02_receipt: CommitReceipt, source_ref: str,
    snapshot: GraphSnapshot,
) -> SettledC02ReplySourceV1:
    """Read current D06 source/access and the original settled v2 C02."""
    from .c02_bundle_codec import c02_bundle_from_wire
    from .issuers import d06_first_ingress_c02_quote_id

    if (not db.in_transaction or type(issuer) is not D02ResourceIssuer
            or type(c02_receipt) is not CommitReceipt
            or c02_receipt.status != "committed"
            or type(snapshot) is not GraphSnapshot
            or len(snapshot.epochs) != 1
            or snapshot.epochs[0].bot != namespace.bot_id
            or snapshot.epochs[0].persona != namespace.persona_id):
        raise ReplyModelJobHold("transactional current C02 source read required")
    op = c02_receipt.operation_id
    archived = db.execute(
        "SELECT schema,bundle_digest,bundle_json,quote_json "
        "FROM graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (op,),
    ).fetchone()
    business = db.execute(
        "SELECT digest,activity_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (op,),
    ).fetchone()
    cost_state = db.execute(
        "SELECT state FROM graph_c02_cost_attempts_v1 WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (op,),
    ).fetchone()
    cost_op = "c02-cost-" + canonical_digest({
        "namespace": list(namespace.as_tuple), "operation_id": op})[:48]
    cost = db.execute(
        "SELECT activity_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (cost_op,),
    ).fetchone()
    if (archived is None or business is None or cost_state != ("committed",)
            or cost is None
            or archived[0] != "sylanne.first-ingress-c02-candidate.v2"
            or archived[1] != c02_receipt.operation_digest
            or business[:2] != (c02_receipt.operation_digest,
                                c02_receipt.activity_id)
            or cost[0] != c02_receipt.activity_id):
        raise ReplyModelJobHold("original v2 C02 or cost is not committed")
    try:
        bundle = c02_bundle_from_wire(archived[2])
        source_id = source_key_from_ref(source_ref, namespace)
        source_key_value = source_key(*namespace.as_tuple, source_id)
        access_key_value = access_key(*namespace.as_tuple, source_id)
        source_atom = snapshot.get(source_key_value)
        access_atom = snapshot.get(access_key_value)
        source = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        quote = issuer.original_signed_quote(
            db, d06_first_ingress_c02_quote_id(namespace, op), 1)
        cost_detail = json.loads(cost[1])
        business_detail = json.loads(business[2])["first_ingress_c02"]
    except (TypeError, ValueError, KeyError, AttributeError,
            json.JSONDecodeError) as exc:
        raise ReplyModelJobHold("original C02 or current source is invalid") from exc
    source_receipt_versions = tuple(
        version for version in c02_receipt.write_versions
        if version.key.type_name in {
            "memory.episode.v1", "memory.subjective_trace.v2"})
    ingress = db.execute(
        "SELECT operation_id,conversation_ref,visibility FROM "
        "graph_first_ingress_identity_v1 WHERE bot=? AND persona=? "
        "AND source_ref=?", namespace.as_tuple + (source_id,),
    ).fetchall()
    dependency = db.execute(
        "SELECT dependency_revision FROM graph_dependencies "
        "WHERE dependent_token=? AND dependency_token=?",
        (access_key_value.token, source_ref),
    ).fetchone()
    reservation = db.execute(
        "SELECT state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, op),
    ).fetchone()
    if (bundle.envelope.identity.operation_id != op
            or bundle.envelope.source_qualification.source_refs != (source_ref,)
            or business_detail.get("seal_schema") != archived[0]
            or archived[3] != canonical_serialize(asdict(quote))
            or cost_detail.get("original_operation_id") != op
            or db.execute(
                "SELECT 1 FROM graph_atoms WHERE token=? AND valid=1",
                (cost_detail.get("cost_ref"),),
            ).fetchone() is None
            or db.execute(
                "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? "
                "AND persona_id=? AND operation_id=? AND phase='settle'",
                namespace.as_tuple + (op,),
            ).fetchone() is None
            or reservation is None
            or reservation[0] not in {"unknown", "settled", "overrun"}
            or len(source_receipt_versions) != 2
            or any(db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (version.key.token,),
            ).fetchone() != (version.revision, 1)
                   for version in source_receipt_versions)
            or source_atom is None or access_atom is None
            or not source_atom.valid or not access_atom.valid
            or dependency != (source_atom.revision,)
            or source.source_id != access_atom.value["source_id"]
            or access_atom.value["status"] != "active"
            or "expression" not in source.purposes
            or "expression" not in access_atom.value["purposes"]
            or not set(access_atom.value["audiences"]).issubset(source.audiences)
            or len(ingress) != 1 or ingress[0][2] != "private"
            or ingress[0][1] not in access_atom.value["audiences"]):
        raise ReplyModelJobHold("settled C02 source, access or private audience differs")
    return SettledC02ReplySourceV1(
        c02_receipt, ReplySourceSnapshot(
            source, source_ref, source_atom.revision, access_atom.revision),
        ingress[0][1], bundle.envelope.source_qualification)


@dataclass(frozen=True, slots=True)
class ReplyModelQueuedPreparationV1:
    c02_operation_id: str
    source_ref: str
    original_operation_id: str
    job: PersistentJob
    quote: ResourceQuote
    reservation_digest: str
    graph_job_revision: int


@dataclass(frozen=True, slots=True)
class ReplyModelRecoveryItemV1:
    job_id: str
    preparation: ReplyModelQueuedPreparationV1 | None
    conversation_ref: str | None
    hold_reason: str | None


@dataclass(frozen=True, slots=True)
class ReplyModelRecoveryPageV1:
    namespace: NamespaceId
    installation_id: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    items: tuple[ReplyModelRecoveryItemV1, ...]
    next_cursor: str | None


def read_saved_reply_job_v1(db, issuer: D02ResourceIssuer,
                            namespace: NamespaceId, c02_operation_id: str,
                            source_ref: str) -> ReplyModelQueuedPreparationV1 | None:
    row = db.execute(
        "SELECT original_operation_id,job_id,activity_id,quote_id,quote_version,"
        "reservation_digest,graph_job_ref,graph_job_revision,state "
        "FROM graph_post_c02_reply_model_preparations_v1 WHERE bot=? AND persona=? "
        "AND c02_operation_id=? AND source_ref=?",
        namespace.as_tuple + (c02_operation_id, source_ref),
    ).fetchone()
    if row is None:
        return None
    original_operation_id, job_id, activity_id, quote_id, version, digest, job_ref, revision, state = row
    if (state not in {"queued", "acquired"}
            or original_operation_id != reply_job_original_operation_id_v1(
                c02_operation_id, source_ref)
            or job_id != reply_job_id_v1(c02_operation_id, source_ref)
            or job_ref != runtime_job_key(*namespace.as_tuple, activity_id,
                                          job_id).token):
        raise ReplyModelJobHold("saved reply identity differs")
    quote = issuer.original_signed_quote(db, quote_id, version)
    job = get_job(db, job_id)
    reservation=read_authority_current_point_v3(db,table='runtime_budget_reservations',columns=('digest','ceiling_json','state'),
        key_columns=('lease_id','operation_id'),key=(quote.parent_budget_lease_ref,original_operation_id),
        legacy_reader=lambda:db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
            (quote.parent_budget_lease_ref,original_operation_id)).fetchone())
    projection=read_authority_current_point_v3(db,table='graph_atoms',columns=('revision','value','valid'),
        key_columns=('token',),key=(job_ref,),legacy_reader=lambda:db.execute(
            'SELECT revision,value,valid FROM graph_atoms WHERE token=?',(job_ref,)).fetchone())
    if ((job.bot_id, job.persona_id, job.activity_id, job.operation_id,
         job.work_kind, job.budget_ref) != (*namespace.as_tuple, activity_id,
                                          original_operation_id, "reply",
                                          quote.parent_budget_lease_ref)
            or (quote.bot_id, quote.persona_id, quote.activity_id,
                quote.operation_id, quote.work_kind, quote.graph_job_ref) != (
                    *namespace.as_tuple, activity_id, original_operation_id,
                    "reply", job_ref)
            or reservation is None or reservation[0] != digest
            or authority_current_json_v3(reservation[1]) != dict(quote.ceiling)
            or reservation[2] not in {"reserved", "unknown", "settled"}
            or projection is None or projection[0] != revision
            or projection[2] != 1
            or authority_current_json_v3(projection[1]) != job_graph_write(job).value
            or db.execute(
                "SELECT 1 FROM graph_events WHERE bot=? AND persona=? "
                "AND session=? AND event_id=?",
                namespace.as_tuple + (activity_id, original_operation_id),
            ).fetchone() is None):
        raise ReplyModelJobHold("saved reply quote, budget, or job differs")
    return ReplyModelQueuedPreparationV1(
        c02_operation_id, source_ref, original_operation_id, job, quote,
        digest, revision)


def read_current_reply_model_inputs_v1(
    db, issuer: D02ResourceIssuer, namespace: NamespaceId,
    c02_receipt: CommitReceipt, source_ref: str,
    snapshot: GraphSnapshot, attention: CurrentAttentionTicketReadV1, *, prepared_inventory=None, prepared_full_read=None, _prefinal_source_inventory=None, _prepared_c02_originals=None,
) -> CurrentReplyModelInputsV1 | _PreparedCurrentReplyModelInputsV3 | _PreparedFullReplyModelInputsV3 | _PrefinalReplyModelInputsV3:
    """Join the original settled C02 to current source/access/attention.

    ``snapshot`` must be read by GraphCoordinator from the same live SQLite
    transaction.  Every relevant atom is checked against that transaction.
    """
    authority_projection=authority_graph_projection_for_db_v3(db,namespace)
    authority_work=None if authority_projection is None else _authority_attachment_owner_v3(db)
    if authority_work is not None and (snapshot is not authority_projection or prepared_inventory is not None
            or prepared_full_read is not None or _prefinal_source_inventory is not None):
        raise ReplyModelJobHold("Authority C02 inputs must use their exact independently prepared projection")
    if _prefinal_source_inventory is not None:
        from .current_graph_full_read_v3 import _PrefinalSourceInventoryV3
        if (type(_prefinal_source_inventory) is not _PrefinalSourceInventoryV3
                or prepared_inventory is not None or prepared_full_read is not None):
            raise ReplyModelJobHold('actual private prefinal C02 inventory required')
        _prefinal_source_inventory.require_current()
        if (snapshot is not _prefinal_source_inventory.projection or namespace!=_prefinal_source_inventory.namespace
                or db is not _prefinal_source_inventory.db
                or _prefinal_source_inventory.actual_entry.c02_operation_id!=c02_receipt.operation_id):
            raise ReplyModelJobHold('prefinal C02 metadata belongs to another actual entry/Work')
    if prepared_inventory is not None and prepared_full_read is not None:
        raise ReplyModelJobHold('reply inputs require one actual prepared read authority')
    if prepared_full_read is not None:
        from .current_graph_full_read_v3 import (PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3,
            require_bound_graph_full_read_proof_for_db_v3,CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3)
        if type(prepared_full_read) not in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):
            raise ReplyModelJobHold('actual ordinary FULL reply input proof required')
        actual=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
            required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3}))
        if actual is not prepared_full_read or snapshot is not actual.projection:
            raise ReplyModelJobHold('reply inputs must use the actual ordinary FULL fixed projection')
        actual.operation.retain(8192)
    if prepared_inventory is not None:
        from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3
        if type(prepared_inventory) is not PreparedCurrentDispatchInventoryV3:
            raise ReplyModelJobHold("actual prepared reply inventory required")
        prepared_inventory.require_current(db,namespace,prepared_inventory.query,snapshot)
        prepared_inventory.operation.retain(8192)
    if (not db.in_transaction or type(issuer) is not D02ResourceIssuer
            or type(namespace) is not NamespaceId
            or type(c02_receipt) is not CommitReceipt
            or c02_receipt.status != "committed"
            or prepared_inventory is None and prepared_full_read is None and _prefinal_source_inventory is None and authority_work is None and type(snapshot) is not GraphSnapshot
            or type(attention) is not CurrentAttentionTicketReadV1
            or len(snapshot.epochs) != 1
            or snapshot.epochs[0].bot != namespace.bot_id
            or snapshot.epochs[0].persona != namespace.persona_id):
        raise ReplyModelJobHold("transactional C02/current graph evidence required")
    meter=None
    actual_reader=authority_work if authority_work is not None else _prefinal_source_inventory if _prefinal_source_inventory is not None else prepared_full_read
    if actual_reader is not None:
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2,require_c09_reserved_meter_v3
        current=current_c09_sql_meter_v2()
        meter=require_c09_reserved_meter_v3(current.budget)
    def read_row(table,columns,where,args):
        if authority_work is not None:
            keys={
                'bot=? AND persona=? AND operation_id=?':('bot','persona','operation_id'),
                'lease_id=? AND operation_id=?':('lease_id','operation_id'),
                'dependent_token=? AND dependency_token=?':('dependent_token','dependency_token'),
                'token=?':('token',),'token=? AND valid=1':('token',),
                "bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'":('bot_id','persona_id','operation_id','phase'),
            }.get(where)
            if keys is not None:
                actual_args=tuple(args)+(('settle',)if keys[-1]=='phase'else())
                return read_authority_current_point_v3(db,table=table,columns=columns,key_columns=keys,
                    key=actual_args,required_valid=where=='token=? AND valid=1',
                    legacy_reader=lambda:None)
        if meter is None:
            return db.execute('SELECT '+','.join(columns)+' FROM '+table+' WHERE '+where,args).fetchone()
        row=meter.read_fixed_row(db,table,columns,where,args)
        if row is not None:
            actual_reader.operation.retain(sum(len(value)*32 for value in row if type(value)in(str,bytes))+4096)
        return row
    originals=_prepared_c02_originals
    if originals is None and prepared_full_read is not None and prepared_full_read.source_material is not None:
        originals=prepared_full_read.source_material.c02_originals
    if originals is not None:
        from .current_graph_source_material_v3 import PreparedCurrentC02OriginalsV3
        prefinal=_prefinal_source_inventory if _prefinal_source_inventory is not None else prepared_full_read.prefinal
        if type(originals)is not PreparedCurrentC02OriginalsV3:
            raise ReplyModelJobHold('actual completed same-Work C02 original columns required')
        originals.require_for_v3(prefinal,prefinal.actual_entry)
        if originals.entry.c02_operation_id!=c02_receipt.operation_id:
            raise ReplyModelJobHold('completed C02 originals belong to another actual entry')
    c02_operation_id=c02_receipt.operation_id
    archive=read_row('graph_first_ingress_c02_committed_seals_v2',
        ('schema','bundle_digest')if originals is not None else('schema','bundle_digest','evidence_json','quote_json'),
        'bot=? AND persona=? AND operation_id=?',namespace.as_tuple+(c02_operation_id,))
    business=read_row('graph_bundle_operations',
        ('digest','activity_id')if originals is not None else('digest','activity_id','receipt_json'),
        'bot=? AND persona=? AND operation_id=?',namespace.as_tuple+(c02_operation_id,))
    cost_attempt=read_row('graph_c02_cost_attempts_v1',('state',),
        'bot=? AND persona=? AND operation_id=?',namespace.as_tuple+(c02_operation_id,))
    cost_operation_id='c02-cost-'+canonical_digest({'namespace':list(namespace.as_tuple),'operation_id':c02_operation_id})[:48]
    cost=read_row('graph_bundle_operations',('operation_id',)if originals is not None else('receipt_json',),
        'bot=? AND persona=? AND operation_id=?',namespace.as_tuple+(cost_operation_id,))
    if (archive is None or business is None or cost_attempt != ("committed",)
            or cost is None or archive[0] != "sylanne.first-ingress-c02-candidate.v2"
            or archive[1] != business[0]
            or business[0] != c02_receipt.operation_digest
            or business[1] != c02_receipt.activity_id
            or not {"memory.episode.v1", "memory.subjective_trace.v2"}
               <= {version.key.type_name for version in c02_receipt.write_versions}):
        raise ReplyModelJobHold("original C02 business and cost are not committed")
    try:
        evidence=authority_current_json_v3(archive[2])if originals is None else originals.value_v3('evidence')
        detail=(authority_current_json_v3(business[2])if originals is None else originals.value_v3('business'))['first_ingress_c02']
        cost_detail=authority_current_json_v3(cost[0])if originals is None else originals.value_v3('cost')
        from .issuers import d06_first_ingress_c02_quote_id
        quote = issuer.original_signed_quote(
            db, d06_first_ingress_c02_quote_id(namespace, c02_operation_id), 1, meter=meter, prepared_originals=originals)
        source_key_value = source_key(*namespace.as_tuple,
                                      source_key_from_ref(source_ref, namespace))
        access_key_value = access_key(*namespace.as_tuple,
                                      source_key_value.owner.subject)
        if authority_work is not None:
            source_atom=require_authority_source_metadata_v3(db,namespace,source_ref)
        elif _prefinal_source_inventory is not None:
            source_atom=_prefinal_source_inventory.source_metadata(db,namespace,_prefinal_source_inventory.query,
                source_key_value,require_grant=False)
        elif prepared_full_read is not None:
            from .current_graph_full_read_v3 import require_bound_graph_full_source_metadata_v3
            source_atom=require_bound_graph_full_source_metadata_v3(db,namespace,source_key_value)
        else:
            source_atom = (snapshot.get(source_key_value) if prepared_inventory is None else
                prepared_inventory.source_metadata(db,namespace,prepared_inventory.query,source_key_value,require_grant=False))
        access_atom = snapshot.get(access_key_value)
        if prepared_inventory is None and prepared_full_read is None and _prefinal_source_inventory is None and authority_work is None:
            source = SourceRecord.from_dict(source_atom.value)
        else:
            from .dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
            source = _SourceMetadataRecordV3(source_atom.metadata)
        validate_access(access_atom.value)
    except (KeyError, TypeError, ValueError, AttributeError,
            json.JSONDecodeError) as exc:
        raise ReplyModelJobHold("C02 or current source evidence is invalid") from exc
    settled = read_row('runtime_budget_operations',('operation_id',),"bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",namespace.as_tuple + (c02_operation_id,))
    reservation = read_row('runtime_budget_reservations',('state',),'lease_id=? AND operation_id=?',(quote.parent_budget_lease_ref, c02_operation_id))
    dep = read_row('graph_dependencies',('dependency_revision',),'dependent_token=? AND dependency_token=?',(access_key_value.token, source_ref))
    if meter is None:
        ingress=db.execute('SELECT conversation_ref,visibility FROM graph_first_ingress_identity_v1 '
            'WHERE bot=? AND persona=? AND source_ref=?',namespace.as_tuple+(source.source_id,)).fetchall()
    else:
        first=read_row('graph_first_ingress_identity_v1',('operation_id','conversation_ref','visibility'),
            'bot=? AND persona=? AND source_ref=? ORDER BY operation_id',namespace.as_tuple+(source.source_id,))
        second=None if first is None else read_row('graph_first_ingress_identity_v1',('operation_id','conversation_ref','visibility'),
            'bot=? AND persona=? AND source_ref=? AND operation_id>? ORDER BY operation_id',
            namespace.as_tuple+(source.source_id,first[0]))
        ingress=[]if first is None else[first[1:]]if second is None else[first[1:],second[1:]]
    episode_versions = tuple(
        version for version in c02_receipt.write_versions
        if version.key.type_name in {
            "memory.episode.v1", "memory.subjective_trace.v2"})
    if originals is not None:originals.require_archive_quote_v3()
    if (evidence.get("source_ref") != source.source_id
            or detail.get("seal_schema") != archive[0]
            or cost_detail.get("original_operation_id") != c02_operation_id
            or cost_detail.get("cost_ref") is None
            or read_row('graph_atoms',('token',),'token=? AND valid=1',(cost_detail["cost_ref"],)) is None
            or settled is None or reservation is None
            or reservation[0] not in {"unknown", "settled", "overrun"}
            or originals is None and not authority_current_json_matches_v3(archive[3],asdict(quote),legacy_serializer=canonical_serialize)
            or (quote.bot_id, quote.persona_id, quote.activity_id,
                quote.operation_id) != (*namespace.as_tuple,
                                        c02_receipt.activity_id, c02_operation_id)
            or len(episode_versions) != 2
            or any(read_row('graph_atoms',('revision', 'valid'),'token=?',(version.key.token,)) != (version.revision, 1)
                   for version in episode_versions)
            or source_atom is None or access_atom is None
            or not source_atom.valid or not access_atom.valid
            or dep != (source_atom.revision,)
            or source_ref != source_key_value.token
            or source.source_id != access_atom.value["source_id"]
            or access_atom.value["status"] != "active"
            or "expression" not in source.purposes
            or "expression" not in access_atom.value["purposes"]
            or not set(access_atom.value["audiences"]).issubset(source.audiences)
            or len(ingress) != 1 or ingress[0][1] != "private"
            or ingress[0][0] not in access_atom.value["audiences"]
            or attention.ticket.causal_root != source_ref
            or attention.ticket.source_refs != (source_ref,)
            or attention.ticket.category != "interaction"
            or snapshot.get(attention.focus_version.key).revision
               != attention.focus_version.revision
            or snapshot.get(attention.ticket_version.key).revision
               != attention.ticket_version.revision
            or len(attention.source_versions) != 1
            or attention.source_versions[0].key != source_key_value
            or attention.source_versions[0].revision != source_atom.revision):
        raise ReplyModelJobHold("current source, audience, or D07 ticket differs")
    if authority_work is not None:
        material=authority_work.source_material
        record=material.source_record_for_v3(db=db,prepared_full_read=authority_work.prepared,namespace=namespace,
            source_ref=source_ref,audiences=(ingress[0][0],))
        return _PreparedAuthorityReplyModelInputsV3(_PREPARED_REPLY_INPUT_ISSUER_V3,authority_work,c02_receipt,
            ReplySourceSnapshot(record,source_ref,source_atom.revision,access_atom.revision),attention,ingress[0][0])
    if _prefinal_source_inventory is not None:
        return _PrefinalReplyModelInputsV3(_PREPARED_REPLY_INPUT_ISSUER_V3,c02_receipt,
            _PreparedReplySourceMetadataV3(source_atom,source_ref,source_atom.revision,access_atom.revision),
            attention,ingress[0][0],snapshot,_prefinal_source_inventory,None)
    if prepared_full_read is not None:
        material=prepared_full_read.source_material
        if material is not None:
            record=material.source_record_for_v3(db=db,prepared_full_read=prepared_full_read,namespace=namespace,
                source_ref=source_ref,audiences=(ingress[0][0],))
            current_source=ReplySourceSnapshot(record,source_ref,source_atom.revision,access_atom.revision)
            family=material.family
        else:
            from ..domains.d07.qualified_attention_read import require_qualified_attention_source_family_v3
            try:
                family=require_qualified_attention_source_family_v3(snapshot,namespace,attention=attention,
                    audience=ingress[0][0],purpose='expression',prepared_full_read=prepared_full_read,db=db)
            except ValueError as exc:
                raise ReplyModelJobHold('ordinary FULL reply Source ancestry/rights or D07 evidence differs')from exc
            current_source=_PreparedReplySourceMetadataV3(source_atom,source_ref,source_atom.revision,access_atom.revision)
        return _PreparedFullReplyModelInputsV3(_PREPARED_REPLY_INPUT_ISSUER_V3,c02_receipt,current_source,
            attention,ingress[0][0],snapshot,prepared_full_read,family,source_atom,material)
    if prepared_inventory is not None:
        return _PreparedCurrentReplyModelInputsV3(_PREPARED_REPLY_INPUT_ISSUER_V3,c02_receipt,
            _PreparedReplySourceMetadataV3(source_atom,source_ref,source_atom.revision,access_atom.revision),
            attention,ingress[0][0],snapshot,prepared_inventory)
    return CurrentReplyModelInputsV1(
        c02_receipt, ReplySourceSnapshot(source, source_ref,
                                        source_atom.revision,
                                        access_atom.revision),
        attention, ingress[0][0], snapshot)


def source_key_from_ref(source_ref: str, namespace: NamespaceId) -> str:
    from ..graph_types import AtomKey

    key = AtomKey.from_token(source_ref)
    if (key.type_name != "memory.source" or key.owner.kind != "event"
            or (key.owner.bot, key.owner.persona) != namespace.as_tuple):
        raise ValueError("reply source reference crosses namespace")
    return key.owner.subject


def install_schema(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_post_c02_reply_model_preparations_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        c02_operation_id TEXT NOT NULL, source_ref TEXT NOT NULL,
        original_operation_id TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE,
        activity_id TEXT NOT NULL, c02_receipt_digest TEXT NOT NULL,
        source_id TEXT NOT NULL, source_revision INTEGER NOT NULL,
        access_revision INTEGER NOT NULL, attention_ticket_id TEXT NOT NULL,
        focus_revision INTEGER NOT NULL, audience TEXT NOT NULL,
        quote_id TEXT NOT NULL, quote_version INTEGER NOT NULL,
        reservation_digest TEXT NOT NULL, deadline_utc REAL NOT NULL,
        graph_job_ref TEXT NOT NULL, graph_job_revision INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('queued','acquired')),
        acquire_operation_id TEXT, actor TEXT, worker_fence INTEGER,
        call_id TEXT, model_request_digest TEXT, binding_digest TEXT,
        envelope_json TEXT, request_json TEXT,
        PRIMARY KEY(bot,persona,c02_operation_id,source_ref),
        UNIQUE(bot,persona,original_operation_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_post_c02_reply_model_acquires_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        acquire_operation_id TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','closed','committed')),
        PRIMARY KEY(bot,persona,acquire_operation_id),
        UNIQUE(bot,persona,original_operation_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_post_c02_reply_model_attempts_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        input_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','closed','committed')),
        PRIMARY KEY(bot,persona,original_operation_id)
    )""")


def issue_reply_job_in_transaction_v1(
    db, *, namespace: NamespaceId, inputs: CurrentReplyModelInputsV1,
    installed_bundle, d02_issuer: D02ResourceIssuer,
    d11_issuer: D11BudgetJobIssuer, now_utc: float,
) -> tuple[PersistentJob, ResourceQuote, str]:
    """Sign one bounded reply quote and reserve its original D11 job budget."""
    from ..host.authority_profile import AdminInstallationBundle
    from ..model_broker.reply_language import REPLY_TEMPLATE_VERSION

    if (not db.in_transaction or type(inputs) is not CurrentReplyModelInputsV1
            or type(installed_bundle) is not AdminInstallationBundle
            or type(d02_issuer) is not D02ResourceIssuer
            or type(d11_issuer) is not D11BudgetJobIssuer
            or d11_issuer.resource_issuer is not d02_issuer
            or type(now_utc) not in (int, float)):
        raise ReplyModelJobHold("installed transactional reply issuers required")
    policy = installed_bundle.installation_policy
    workflows = installed_bundle.model_workflows
    if (policy.namespace != namespace or workflows is None
            or inputs.c02_receipt.operation_id == ""):
        raise ReplyModelJobHold("installed reply workflow is absent")
    workflow = workflows.reply
    grant = d11_issuer.current_budget_grant(db, policy.root_lease.lease_id)
    lease = get_budget_lease(db, grant.lease_id)
    ceiling = dict(workflow.quote_ceiling)
    if (grant != policy.root_grant
            or (lease.lease_id, lease.parent_id, lease.bot_id,
                lease.persona_id, lease.currency, lease.limits) != (
                    policy.root_lease.lease_id, policy.root_lease.parent_id,
                    policy.root_lease.bot_id, policy.root_lease.persona_id,
                    policy.root_lease.currency, policy.root_lease.limits)
            or workflow.work_kind != "reply" or workflow.purpose != "proposal"
            or workflow.template_version != REPLY_TEMPLATE_VERSION
            or inputs.conversation_ref not in workflow.audiences
            or inputs.conversation_ref not in inputs.source.source.audiences
            or grant.policy_ref != policy.root_grant.policy_ref
            or "reply" not in grant.allowed_work_kinds
            or lease.state != "active" or grant.valid_until_utc <= now_utc
            or any(amount > grant.max_ceiling.get(name, 0)
                   or amount > lease.available(name)
                   for name, amount in ceiling.items())):
        raise ReplyModelJobHold("signed root budget or reply profile differs")
    c02_operation_id = inputs.c02_receipt.operation_id
    source_ref = inputs.source.source_ref
    from .natural_reply_job_v2 import install_schema as install_natural_schema
    install_natural_schema(db)
    if db.execute(
            "SELECT 1 FROM graph_natural_generation_preparations_v2 "
            "WHERE bot=? AND persona=? AND parent_original_id=?",
            namespace.as_tuple + (c02_operation_id,),
    ).fetchone() is not None:
        raise ReplyModelJobHold("original natural reply identity already exists")
    original_operation_id = reply_job_original_operation_id_v1(
        c02_operation_id, source_ref)
    job_id = reply_job_id_v1(c02_operation_id, source_ref)
    identity_digest = canonical_digest({
        "c02_operation_id": c02_operation_id, "source_ref": source_ref})
    activity_id = "reply-activity:" + identity_digest[:48]
    quote_id = "reply-quote:" + identity_digest[:48]
    deadline = min(now_utc + workflow.timeout_seconds + 60,
                   inputs.attention.ticket.valid_until,
                   grant.valid_until_utc)
    if deadline <= now_utc + workflow.timeout_seconds:
        raise ReplyModelJobHold("reply attention or budget expires before model deadline")
    snapshot_ref = "reply-snapshot:" + canonical_digest({
        "source_ref": inputs.source.source_ref,
        "source_revision": inputs.source.source_revision,
        "access_revision": inputs.source.access_revision,
        "ticket_id": inputs.attention.ticket.ticket_id,
        "focus_revision": inputs.attention.focus_version.revision,
    })[:48]
    graph_job_ref = runtime_job_key(*namespace.as_tuple, activity_id, job_id).token
    quote = ResourceQuote(
        quote_id, 1, *namespace.as_tuple, activity_id,
        original_operation_id, None, grant.lease_id, "reply",
        snapshot_ref, deadline, workflow.provider_config_ref,
        graph_job_ref, (), (), ceiling, None, deadline)
    digest = canonical_digest({
        "schema": "sylanne.post-c02-reply-budget-reservation.v1",
        "original_operation_id": original_operation_id,
        "quote": asdict(quote), "c02_receipt": asdict(inputs.c02_receipt),
    })
    job = PersistentJob(
        job_id, original_operation_id, activity_id, None,
        *namespace.as_tuple, snapshot_ref, "queued", "reply", {
            "c02_operation_id": c02_operation_id, "source_ref": source_ref,
            "attention_ticket_id": inputs.attention.ticket.ticket_id,
        }, None,
        datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace(
            "+00:00", "Z"), grant.lease_id, workflow.provider_config_ref,
        {"resource_quote": f"{quote_id}:1"}, None, None, 0, 0, {}, None)
    d02_issuer.issue_quote(db, quote)
    reserve_budget(db, grant.lease_id, original_operation_id, digest, ceiling)
    create_job(db, job, "create:" + original_operation_id, digest)
    db.execute(
        "INSERT INTO graph_post_c02_reply_model_preparations_v1"
        "(bot,persona,c02_operation_id,source_ref,original_operation_id,job_id,"
        "activity_id,c02_receipt_digest,source_id,source_revision,access_revision,"
        "attention_ticket_id,focus_revision,audience,quote_id,quote_version,"
        "reservation_digest,deadline_utc,graph_job_ref,graph_job_revision,state) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        namespace.as_tuple + (c02_operation_id, source_ref,
        original_operation_id, job_id, activity_id,
        canonical_digest(asdict(inputs.c02_receipt)),
        inputs.source.source.source_id, inputs.source.source_revision,
        inputs.source.access_revision, inputs.attention.ticket.ticket_id,
        inputs.attention.focus_version.revision, inputs.conversation_ref,
        quote_id, 1, digest, deadline, graph_job_ref, 1, "queued"),
    )
    return job, quote, digest


def freeze_acquired_reply_binding_v1(
    db, *, namespace: NamespaceId, inputs: CurrentReplyModelInputsV1,
    job: PersistentJob, quote: ResourceQuote, authority,
    installed_bundle, graph_epoch: int, access_epoch: int,
    delete_epoch: int, now_utc: float, monotonic_now: float,
    acquire_operation_id: str,
):
    """Freeze the original installed model request from one acquired worker."""
    from ..host.installed_reply_model_driver import reply_model_operation_id_v1
    from ..model_broker.reply_language import freeze_installed_reply_request_v1
    from ..runtime_contracts import (
        AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch,
        VersionGuard, VersionedRef,
    )
    from .c02_bundle_codec import c02_bundle_from_wire

    if (not db.in_transaction or type(authority) is not AuthorityContext
            or acquire_operation_id != reply_model_operation_id_v1(
                inputs.c02_receipt.operation_id, inputs.source.source_ref)
            or (job.bot_id, job.persona_id) != namespace.as_tuple
            or job.phase != "running" or job.lease_holder != authority.actor
            or job.fence != authority.worker_fence or job.cancel_epoch != 0
            or job.operation_id != quote.operation_id
            or quote.parent_budget_lease_ref != job.budget_ref
            or quote.required_worker_fence is not None
            or authority.namespace != namespace
            or authority.issuer_domain != "d11"
            or authority.purpose != "proposal"
            or authority.audience != (inputs.conversation_ref,)):
        raise ReplyModelJobHold("acquired D11 reply worker differs")
    archive = db.execute(
        "SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (inputs.c02_receipt.operation_id,),
    ).fetchone()
    if archive is None:
        raise ReplyModelJobHold("original C02 source qualification is absent")
    original = c02_bundle_from_wire(archive[0]).envelope
    source_ref = inputs.source.source_ref
    if original.source_qualification.source_refs != (source_ref,):
        raise ReplyModelJobHold("original C02 source qualification differs")
    from datetime import datetime
    deadline = datetime.fromisoformat(
        job.deadline_utc.replace("Z", "+00:00")).timestamp()
    if not now_utc < deadline or monotonic_now < 0:
        raise ReplyModelJobHold("reply model deadline expired")
    guard = VersionGuard(
        inputs.graph_snapshot.versions,
        (QueryEpoch(namespace, "all", graph_epoch),),
        access_epoch, delete_epoch,
        installed_bundle.installation_policy.catalogue_hash,
        installed_bundle.installation_policy.scheme_version,
        installed_bundle.installation_policy.operator_version,
        installed_bundle.installation_policy.policy_version,
        (), (VersionedRef(inputs.attention.ticket_version.key.token,
                          inputs.attention.ticket_version.revision),),
        (VersionedRef(quote.quote_id, quote.version),),
    )
    envelope = CommandEnvelope(
        original.schema,
        OperationIdentity(
            job.activity_id, None,
            "reply-model-attempt:" + canonical_digest({
                "original_operation_id": job.operation_id,
                "acquire_operation_id": acquire_operation_id,
            })[:48],
            "post_c02_reply_model", acquire_operation_id,
            canonical_digest({"input_refs": [source_ref]})),
        authority, guard, original.source_qualification, (source_ref,),
        job.budget_ref, deadline,
        monotonic_now + (deadline - now_utc),
        "reply-character:" + canonical_digest({
            "c02_operation_id": inputs.c02_receipt.operation_id,
            "source_ref": source_ref,
        })[:48],
        (inputs.c02_receipt.operation_id,),
    )
    installed = freeze_installed_reply_request_v1(
        envelope, inputs.source, bundle=installed_bundle)
    request = installed.request
    request_wire = reply_request_wire_v1(envelope, request)
    binding_digest = reply_binding_digest_v1(
        job, inputs, acquire_operation_id,
        request.call_id, request.digest)
    return envelope, installed, binding_digest, canonical_serialize(request_wire)


def reply_request_wire_v1(envelope, request) -> dict:
    """The complete persisted request body used for exact restart comparison."""
    return {
        "envelope": asdict(envelope), "call_id": request.call_id,
        "provider_id": request.provider_id, "model_id": request.model_id,
        "required_capabilities": sorted(request.required_capabilities),
        "privacy_tier": request.privacy_tier,
        "prompt_template_digest": request.prompt_template_digest,
        "payload": dict(request.payload),
        "timeout_seconds": request.timeout_seconds,
        "max_output_tokens": request.max_output_tokens,
    }


def reply_binding_digest_v1(job: PersistentJob,
                            inputs: CurrentReplyModelInputsV1,
                            acquire_operation_id: str, call_id: str,
                            request_digest: str) -> str:
    return canonical_digest({
        "schema": "sylanne.post-c02-reply-model-binding.v1",
        "job_id": job.job_id, "original_operation_id": job.operation_id,
        "acquire_operation_id": acquire_operation_id,
        "worker_fence": job.fence,
        "source_ref": inputs.source.source_ref,
        "source_revision": inputs.source.source_revision,
        "access_revision": inputs.source.access_revision,
        "attention_ticket_id": inputs.attention.ticket.ticket_id,
        "focus_revision": inputs.attention.focus_version.revision,
        "call_id": call_id, "request_digest": request_digest,
    })


def reply_envelope_from_wire_v1(text: str):
    """Decode only the fixed runtime DTO tree used by the C02 source contract."""
    from ..runtime_contracts import CommandEnvelope
    from .c02_bundle_codec import _decode

    raw = authority_current_json_v3(text)
    envelope = _decode(raw, CommandEnvelope)
    if not authority_current_json_matches_v3(text,asdict(envelope),legacy_serializer=canonical_serialize):
        raise ReplyModelJobHold("stored reply envelope is noncanonical")
    return envelope


__all__ = (
    "ReplyModelJobHold", "CurrentReplyModelInputsV1",
    "ReplyModelQueuedPreparationV1", "read_saved_reply_job_v1",
    "reply_job_original_operation_id_v1", "reply_job_id_v1",
    "read_current_reply_model_inputs_v1", "issue_reply_job_in_transaction_v1",
    "install_schema",
)
