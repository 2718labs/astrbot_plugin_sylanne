"""Transaction-scoped, source-bound D11 preparation for a post-C02 reply.

This module does not grant model egress.  The Authority mints the model fence
from a later GraphCoordinator-produced ``ModelEgressDraftV1``.
"""

from __future__ import annotations

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
            or type(inputs) not in {CurrentReplyModelInputsV1, SettledC02ReplySourceV1}
            or inputs.c02_receipt.status != "committed"
            or inputs.source.source_ref != source_ref):
        raise ReplyModelJobHold("transactional original reply route required")
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
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, original_operation_id),
    ).fetchone()
    projection = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (job_ref,),
    ).fetchone()
    if ((job.bot_id, job.persona_id, job.activity_id, job.operation_id,
         job.work_kind, job.budget_ref) != (*namespace.as_tuple, activity_id,
                                          original_operation_id, "reply",
                                          quote.parent_budget_lease_ref)
            or (quote.bot_id, quote.persona_id, quote.activity_id,
                quote.operation_id, quote.work_kind, quote.graph_job_ref) != (
                    *namespace.as_tuple, activity_id, original_operation_id,
                    "reply", job_ref)
            or reservation is None or reservation[0] != digest
            or json.loads(reservation[1]) != dict(quote.ceiling)
            or reservation[2] not in {"reserved", "unknown", "settled"}
            or projection is None or projection[0] != revision
            or projection[2] != 1
            or json.loads(projection[1]) != job_graph_write(job).value
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
    snapshot: GraphSnapshot, attention: CurrentAttentionTicketReadV1,
) -> CurrentReplyModelInputsV1:
    """Join the original settled C02 to current source/access/attention.

    ``snapshot`` must be read by GraphCoordinator from the same live SQLite
    transaction.  Every relevant atom is checked against that transaction.
    """
    if (not db.in_transaction or type(issuer) is not D02ResourceIssuer
            or type(namespace) is not NamespaceId
            or type(c02_receipt) is not CommitReceipt
            or c02_receipt.status != "committed"
            or type(snapshot) is not GraphSnapshot
            or type(attention) is not CurrentAttentionTicketReadV1
            or len(snapshot.epochs) != 1
            or snapshot.epochs[0].bot != namespace.bot_id
            or snapshot.epochs[0].persona != namespace.persona_id):
        raise ReplyModelJobHold("transactional C02/current graph evidence required")
    c02_operation_id = c02_receipt.operation_id
    archive = db.execute(
        "SELECT schema,bundle_digest,evidence_json,quote_json FROM "
        "graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (c02_operation_id,),
    ).fetchone()
    business = db.execute(
        "SELECT digest,activity_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (c02_operation_id,),
    ).fetchone()
    cost_attempt = db.execute(
        "SELECT state FROM graph_c02_cost_attempts_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (c02_operation_id,),
    ).fetchone()
    cost_operation_id = "c02-cost-" + canonical_digest({
        "namespace": list(namespace.as_tuple), "operation_id": c02_operation_id,
    })[:48]
    cost = db.execute(
        "SELECT receipt_json FROM graph_bundle_operations WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (cost_operation_id,),
    ).fetchone()
    if (archive is None or business is None or cost_attempt != ("committed",)
            or cost is None or archive[0] != "sylanne.first-ingress-c02-candidate.v2"
            or archive[1] != business[0]
            or business[0] != c02_receipt.operation_digest
            or business[1] != c02_receipt.activity_id
            or not {"memory.episode.v1", "memory.subjective_trace.v2"}
               <= {version.key.type_name for version in c02_receipt.write_versions}):
        raise ReplyModelJobHold("original C02 business and cost are not committed")
    try:
        evidence = json.loads(archive[2])
        detail = json.loads(business[2])["first_ingress_c02"]
        cost_detail = json.loads(cost[0])
        from .issuers import d06_first_ingress_c02_quote_id
        quote = issuer.original_signed_quote(
            db, d06_first_ingress_c02_quote_id(namespace, c02_operation_id), 1)
        source_key_value = source_key(*namespace.as_tuple,
                                      source_key_from_ref(source_ref, namespace))
        access_key_value = access_key(*namespace.as_tuple,
                                      source_key_value.owner.subject)
        source_atom = snapshot.get(source_key_value)
        access_atom = snapshot.get(access_key_value)
        source = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
    except (KeyError, TypeError, ValueError, AttributeError,
            json.JSONDecodeError) as exc:
        raise ReplyModelJobHold("C02 or current source evidence is invalid") from exc
    settled = db.execute(
        "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='settle'",
        namespace.as_tuple + (c02_operation_id,),
    ).fetchone()
    reservation = db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE lease_id=? "
        "AND operation_id=?", (quote.parent_budget_lease_ref, c02_operation_id),
    ).fetchone()
    dep = db.execute(
        "SELECT dependency_revision FROM graph_dependencies WHERE dependent_token=? "
        "AND dependency_token=?", (access_key_value.token, source_ref),
    ).fetchone()
    ingress = db.execute(
        "SELECT conversation_ref,visibility FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source.source_id,),
    ).fetchall()
    episode_versions = tuple(
        version for version in c02_receipt.write_versions
        if version.key.type_name in {
            "memory.episode.v1", "memory.subjective_trace.v2"})
    if (evidence.get("source_ref") != source.source_id
            or detail.get("seal_schema") != archive[0]
            or cost_detail.get("original_operation_id") != c02_operation_id
            or cost_detail.get("cost_ref") is None
            or db.execute(
                "SELECT 1 FROM graph_atoms WHERE token=? AND valid=1",
                (cost_detail["cost_ref"],),
            ).fetchone() is None
            or settled is None or reservation is None
            or reservation[0] not in {"unknown", "settled", "overrun"}
            or archive[3] != canonical_serialize(asdict(quote))
            or (quote.bot_id, quote.persona_id, quote.activity_id,
                quote.operation_id) != (*namespace.as_tuple,
                                        c02_receipt.activity_id, c02_operation_id)
            or len(episode_versions) != 2
            or any(db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (version.key.token,),
            ).fetchone() != (version.revision, 1)
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

    raw = json.loads(text)
    envelope = _decode(raw, CommandEnvelope)
    if canonical_serialize(envelope) != text:
        raise ReplyModelJobHold("stored reply envelope is noncanonical")
    return envelope


__all__ = (
    "ReplyModelJobHold", "CurrentReplyModelInputsV1",
    "ReplyModelQueuedPreparationV1", "read_saved_reply_job_v1",
    "reply_job_original_operation_id_v1", "reply_job_id_v1",
    "read_current_reply_model_inputs_v1", "issue_reply_job_in_transaction_v1",
    "install_schema",
)
