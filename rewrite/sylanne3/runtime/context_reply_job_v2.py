"""Original context-reply identities and sealed preparation storage.

The v2 workflow has a separate identity domain from paid source_reply.v1.
Only GraphCoordinator may insert a preparation from its current graph write
transaction.  Reading a row grants no model call or reply dispatch.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json

from ..contracts import canonical_json
from ..graph_types import AtomKey, GraphVersion, Owner
from ..memory_types import SourceRecord, access_key, source_key
from ..model_broker.context_reply import (
    ContextReplyInputV1, ContextReplyInstallationV1, ContextReplyMessageV1,
    ContextReplyPartV1, FrozenContextReplyRequestV1,
    freeze_context_reply_request_v1,
)
from ..runtime_contracts import (
    CONTEXT_REPLY_WORKFLOW_V1, ContextReplyOriginalSealV2, NamespaceId,
    QueryEpoch, VersionedRef, canonical_digest, canonical_serialize,
    context_reply_graph_guard_digest_v2,
)
from .budget import get_budget_lease, reserve_budget
from .d11_types import runtime_job_key
from .issuers import ResourceQuote
from .jobs import PersistentJob, create_job


class ContextReplyJobHold(RuntimeError):
    """No safe original v2 context-reply identity can be established."""


def _identity(namespace: NamespaceId, c02_operation_id: str, source_ref: str) -> str:
    return canonical_digest({
        "schema": "sylanne.post-c02-context-reply-identity.v2",
        "namespace": namespace.as_tuple,
        "c02_operation_id": c02_operation_id,
        "source_ref": source_ref,
        "template_version": CONTEXT_REPLY_WORKFLOW_V1,
    })[:48]


def context_reply_job_ids_v2(
        namespace: NamespaceId, c02_operation_id: str, source_ref: str,
) -> tuple[str, str, str, str]:
    """Stable job/original/acquire/call IDs, disjoint from source_reply.v1."""
    digest = _identity(namespace, c02_operation_id, source_ref)
    return tuple(prefix + digest for prefix in (
        "context-reply-job:", "context-reply-origin:",
        "context-reply-acquire:", "context-reply-call:",
    ))


def freeze_current_context_reply_v2(
        namespace: NamespaceId, c02_operation_id: str, source_ref: str,
        snapshot, attention, route, workflow, installation_id: str,
        *, now_utc: float, expires_at_utc: float, access_epoch: int,
        delete_epoch: int, activation_generation: int,
) -> FrozenContextReplyRequestV1:
    """Freeze the current D06/D07 graph values selected by W01's write tx."""
    from ..model_broker.context_reply import ContextReplyPartV1

    audience = VersionedRef(route.conversation_ref, 0)
    parts = []
    for ref in attention.ticket.source_refs:
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise ContextReplyJobHold("selected D06 source key differs")
        source_atom = snapshot.get(key)
        access_atom = snapshot.get(access_key(*namespace.as_tuple, key.owner.subject))
        if (source_atom is None or access_atom is None
                or not source_atom.valid or not access_atom.valid):
            raise ContextReplyJobHold("selected D06 source or access unavailable")
        source = SourceRecord.from_dict(source_atom.value)
        dependencies = tuple(VersionedRef(
            source_key(*namespace.as_tuple, parent).token,
            snapshot.get(source_key(*namespace.as_tuple, parent)).revision,
        ) for parent in source.parent_source_ids)
        parts.append(ContextReplyPartV1(
            "d06_evidence", VersionedRef(ref, source_atom.revision), audience,
            expires_at_utc, source.text, dependencies,
            VersionedRef(access_atom.key.token, access_atom.revision),
        ))
    if not parts or source_ref not in attention.ticket.source_refs:
        raise ContextReplyJobHold("original question is not selected by D07")
    original = snapshot.get(AtomKey.from_token(source_ref))
    question_text = SourceRecord.from_dict(original.value).text
    question = ContextReplyPartV1(
        "question", VersionedRef("c02-question:" + c02_operation_id,
                                 attention.ticket_version.revision),
        audience, expires_at_utc, question_text,
    )
    frozen_input = ContextReplyInputV1(
        namespace, VersionedRef(route.scene_ref, 0), audience,
        route.conversation_ref, access_epoch, delete_epoch,
        activation_generation, now_utc, expires_at_utc, question,
        tuple(parts),
    )
    installation = ContextReplyInstallationV1(
        installation_id, workflow.provider_config_digest,
        workflow.provider_id, workflow.model_id, workflow.max_output_tokens,
    )
    return freeze_context_reply_request_v1(frozen_input, installation)


def install_schema(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_context_reply_preparations_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        c02_operation_id TEXT NOT NULL, source_ref TEXT NOT NULL,
        job_id TEXT NOT NULL UNIQUE, original_operation_id TEXT NOT NULL UNIQUE,
        seal_json TEXT NOT NULL, frozen_request_json TEXT NOT NULL,
        read_versions_json TEXT NOT NULL, query_epoch_json TEXT NOT NULL,
        graph_epoch INTEGER NOT NULL, access_epoch INTEGER NOT NULL,
        delete_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('queued','acquired','terminal')),
        PRIMARY KEY(bot,persona,c02_operation_id,source_ref)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_context_reply_attempts_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        input_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','closed','committed')),
        PRIMARY KEY(bot,persona,original_operation_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_context_reply_acquires_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        acquire_operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL,
        graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','committed','rejected')),
        PRIMARY KEY(bot,persona,acquire_operation_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_context_reply_call_bindings_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        acquire_operation_id TEXT NOT NULL,
        call_id TEXT NOT NULL UNIQUE,
        worker_fence INTEGER NOT NULL,
        original_seal_digest TEXT NOT NULL,
        frozen_request_digest TEXT NOT NULL,
        model_call_request_digest TEXT NOT NULL,
        model_call_request_json TEXT NOT NULL,
        PRIMARY KEY(bot,persona,original_operation_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_context_reply_terminals_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        terminal_receipt_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','committed','rejected')),
        PRIMARY KEY(bot,persona,original_operation_id)
    )""")


def bind_original_context_reply_call_v2(
        db, saved: SavedContextReplyPreparationV2, job: PersistentJob,
        request,
) -> str:
    """Persist the acquired ModelCallRequest digest apart from wire SHA256.

    The original context-reply seal binds the three-message provider wire.
    The paid observation instead names ``ModelCallRequest.digest``; this row
    connects the two before any external call and cannot be rewritten.
    """
    from ..model_broker.broker import ModelCallRequest
    from ..model_broker.context_reply import CONTEXT_REPLY_TEMPLATE_DIGEST
    from .reply_model_job import reply_request_wire_v1

    if (not db.in_transaction or type(saved) is not SavedContextReplyPreparationV2
            or saved.state not in {"queued", "acquired"}):
        raise ContextReplyJobHold("original V2 call needs graph write tx")
    seal = saved.seal
    frozen = saved.frozen_request
    if (type(request) is not ModelCallRequest
            or job.job_id != seal.job_id
            or job.operation_id != seal.original_operation_id
            or job.phase != "running" or job.fence < 1
            or request.call_id != seal.call_id
            or request.identity.operation_id != seal.acquire_operation_id
            or request.provider_id != frozen.installation.provider_id
            or request.model_id != frozen.installation.model_id
            or request.max_output_tokens != frozen.installation.max_output_tokens
            or request.prompt_template_digest != CONTEXT_REPLY_TEMPLATE_DIGEST
            or dict(request.payload) != json.loads(frozen.canonical_wire)
            or seal.model_request_digest != frozen.digest):
        raise ContextReplyJobHold("acquired V2 model call differs from original wire")
    call_wire = canonical_serialize(reply_request_wire_v1(request.envelope, request))
    seal_digest = canonical_digest(asdict(seal))
    existing = db.execute(
        "SELECT acquire_operation_id,call_id,worker_fence,original_seal_digest,"
        "frozen_request_digest,model_call_request_digest,model_call_request_json "
        "FROM graph_context_reply_call_bindings_v2 "
        "WHERE bot=? AND persona=? AND original_operation_id=?",
        seal.namespace.as_tuple + (seal.original_operation_id,),
    ).fetchone()
    expected = (
        seal.acquire_operation_id, seal.call_id, job.fence, seal_digest,
        frozen.digest, request.digest, call_wire,
    )
    if existing is not None:
        if existing != expected:
            raise ContextReplyJobHold("original V2 paid call identity differs")
        if saved.state != "acquired":
            raise ContextReplyJobHold("original V2 call binding state differs")
        return request.digest
    db.execute(
        "INSERT INTO graph_context_reply_call_bindings_v2"
        "(bot,persona,original_operation_id,acquire_operation_id,call_id,"
        "worker_fence,original_seal_digest,frozen_request_digest,"
        "model_call_request_digest,model_call_request_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        seal.namespace.as_tuple + (seal.original_operation_id,) + expected,
    )
    changed = db.execute(
        "UPDATE graph_context_reply_preparations_v2 SET state='acquired' "
        "WHERE bot=? AND persona=? AND c02_operation_id=? AND source_ref=? "
        "AND state='queued' AND seal_json=?",
        seal.namespace.as_tuple + (
            seal.c02_operation_id, seal.source_ref,
            canonical_serialize(asdict(seal))),
    ).rowcount
    if changed != 1:
        raise ContextReplyJobHold("original V2 preparation acquire CAS differed")
    return request.digest


@dataclass(frozen=True, slots=True)
class SavedContextReplyCallBindingV2:
    model_call_request: object
    model_call_request_digest: str
    worker_fence: int


def read_original_context_reply_call_binding_v2(
        db, saved: SavedContextReplyPreparationV2,
) -> SavedContextReplyCallBindingV2 | None:
    """Rebuild the typed paid-call request from its separate original row."""
    from ..model_broker.broker import ModelCallRequest
    from ..model_broker.context_reply import CONTEXT_REPLY_TEMPLATE_DIGEST
    from ..runtime_contracts import (
        AuthorityContext, CommandEnvelope, OperationIdentity,
        SourceQualification, VersionGuard,
    )
    from .reply_model_job import reply_request_wire_v1

    if not db.in_transaction or type(saved) is not SavedContextReplyPreparationV2:
        raise ContextReplyJobHold("original V2 call needs current graph tx")
    from ..authority_service.current_authority_graph_read_v3 import require_authority_context_call_binding_v3
    handled,binding=require_authority_context_call_binding_v3(db,saved)
    if handled:return binding
    seal = saved.seal
    row = db.execute(
        "SELECT acquire_operation_id,call_id,worker_fence,original_seal_digest,"
        "frozen_request_digest,model_call_request_digest,model_call_request_json "
        "FROM graph_context_reply_call_bindings_v2 "
        "WHERE bot=? AND persona=? AND original_operation_id=?",
        seal.namespace.as_tuple + (seal.original_operation_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        raw = json.loads(row[6])
        source_envelope = raw["envelope"]
        authority_data = dict(source_envelope["authority"])
        authority_data["namespace"] = NamespaceId(**authority_data["namespace"])
        guard_data = dict(source_envelope["version_guard"])
        guard_data["read_versions"] = tuple(GraphVersion(
            AtomKey(Owner(**item["key"]["owner"]),
                    item["key"]["type_name"], item["key"]["name"]),
            item["revision"],
        ) for item in guard_data["read_versions"])
        guard_data["query_epochs"] = tuple(QueryEpoch(
            NamespaceId(**item["namespace"]), item["scope_ref"],
            item["revision"],
        ) for item in guard_data["query_epochs"])
        for name in ("source_grant_refs", "focus_lease_versions",
                     "resource_lease_versions"):
            guard_data[name] = tuple(VersionedRef(**item)
                                     for item in guard_data[name])
        qualification_data = dict(source_envelope["source_qualification"])
        qualification_data["source_refs"] = tuple(qualification_data["source_refs"])
        envelope = CommandEnvelope(
            source_envelope["schema"],
            OperationIdentity(**source_envelope["identity"]),
            AuthorityContext(**authority_data), VersionGuard(**guard_data),
            SourceQualification(**qualification_data),
            tuple(source_envelope["input_refs"]),
            source_envelope["parent_budget_lease_ref"],
            source_envelope["deadline_utc"],
            source_envelope["monotonic_deadline"],
            source_envelope["character_interval_ref"],
            tuple(source_envelope["causation"]),
        )
        request = ModelCallRequest(
            envelope, raw["call_id"], raw["provider_id"], raw["model_id"],
            frozenset(raw["required_capabilities"]), raw["privacy_tier"],
            raw["prompt_template_digest"], raw["payload"],
            raw["timeout_seconds"], raw["max_output_tokens"],
        )
        if (canonical_json(raw) != row[6]
                or canonical_serialize(reply_request_wire_v1(envelope, request))
                   != row[6]
                or row[:2] != (seal.acquire_operation_id, seal.call_id)
                or type(row[2]) is not int or row[2] < 1
                or row[3] != canonical_digest(asdict(seal))
                or row[4] != saved.frozen_request.digest
                or row[5] != request.digest
                or request.call_id != seal.call_id
                or request.identity.operation_id != seal.acquire_operation_id
                or request.prompt_template_digest != CONTEXT_REPLY_TEMPLATE_DIGEST
                or request.provider_id
                   != saved.frozen_request.installation.provider_id
                or request.model_id != saved.frozen_request.installation.model_id
                or dict(request.payload)
                   != json.loads(saved.frozen_request.canonical_wire)):
            raise ContextReplyJobHold("original V2 paid call binding differs")
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise ContextReplyJobHold("original V2 paid call binding invalid") from exc
    return SavedContextReplyCallBindingV2(request, request.digest, row[2])


def legacy_reply_identity_exists_v1(
        db, namespace: NamespaceId, c02_operation_id: str, source_ref: str,
) -> bool:
    """Any v1 preparation or write attempt pins this ingress to v1 forever."""
    from .reply_model_job import reply_job_original_operation_id_v1

    identity = namespace.as_tuple + (c02_operation_id, source_ref)
    original = reply_job_original_operation_id_v1(c02_operation_id, source_ref)
    return any(db.execute(query, args).fetchone() is not None for query, args in (
        ("SELECT 1 FROM graph_post_c02_reply_model_preparations_v1 "
         "WHERE bot=? AND persona=? AND c02_operation_id=? AND source_ref=?", identity),
        ("SELECT 1 FROM graph_post_c02_reply_model_attempts_v1 "
         "WHERE bot=? AND persona=? AND original_operation_id=?",
         namespace.as_tuple + (original,)),
        ("SELECT 1 FROM graph_post_c02_reply_model_acquires_v1 "
         "WHERE bot=? AND persona=? AND original_operation_id=?",
         namespace.as_tuple + (original,)),
    ))


def issue_context_reply_job_in_transaction_v2(
        db, *, namespace: NamespaceId, c02_receipt, source_ref: str,
        attention, frozen: FrozenContextReplyRequestV1,
        read_versions: tuple[GraphVersion, ...], query_epoch: QueryEpoch,
        graph_epoch: int, installed_bundle, d02_issuer, d11_issuer,
        now_utc: float,
) -> tuple[PersistentJob, ResourceQuote, str, ContextReplyOriginalSealV2]:
    """Reserve one original V2 job and seal its exact pre-call request."""
    if not db.in_transaction:
        raise ContextReplyJobHold("context reply preparation needs graph write tx")
    install_schema(db)
    from .reply_model_job import install_schema as install_legacy_schema
    install_legacy_schema(db)
    from .natural_reply_job_v2 import install_schema as install_natural_schema
    install_natural_schema(db)
    if legacy_reply_identity_exists_v1(
            db, namespace, c02_receipt.operation_id, source_ref):
        raise ContextReplyJobHold("original source_reply.v1 identity already exists")
    if db.execute(
            "SELECT 1 FROM graph_natural_generation_preparations_v2 "
            "WHERE bot=? AND persona=? AND parent_original_id=?",
            namespace.as_tuple + (c02_receipt.operation_id,),
    ).fetchone() is not None:
        raise ContextReplyJobHold("original natural reply identity already exists")
    if db.execute(
            "SELECT 1 FROM graph_context_reply_preparations_v2 "
            "WHERE bot=? AND persona=? AND c02_operation_id=? AND source_ref=?",
            namespace.as_tuple + (c02_receipt.operation_id, source_ref),
    ).fetchone() is not None:
        raise ContextReplyJobHold("original context reply already prepared")
    policy = installed_bundle.installation_policy
    workflow = installed_bundle.model_workflows.context_reply
    grant = d11_issuer.current_budget_grant(db, policy.root_lease.lease_id)
    lease = get_budget_lease(db, grant.lease_id)
    ceiling = dict(workflow.quote_ceiling)
    if (policy.namespace != namespace or grant != policy.root_grant
            or workflow.template_version != CONTEXT_REPLY_WORKFLOW_V1
            or workflow.work_kind != "context_reply" or workflow.purpose != "proposal"
            or frozen.input.namespace != namespace
            or frozen.input.conversation_ref not in workflow.audiences
            or frozen.installation.installation_id != policy.installation_id
            or frozen.installation.provider_config_digest
               != workflow.provider_config_digest
            or frozen.installation.provider_id != workflow.provider_id
            or frozen.installation.model_id != workflow.model_id
            or frozen.installation.max_output_tokens != workflow.max_output_tokens
            or frozen.input.expires_at_utc <= now_utc + workflow.timeout_seconds
            or grant.policy_ref != policy.root_grant.policy_ref
            or "context_reply" not in grant.allowed_work_kinds
            or lease.state != "active" or grant.valid_until_utc <= now_utc
            or any(amount > grant.max_ceiling.get(name, 0)
                   or amount > lease.available(name)
                   for name, amount in ceiling.items())):
        raise ContextReplyJobHold("current installed V2 reply budget unavailable")
    job_id, original_id, acquire_id, call_id = context_reply_job_ids_v2(
        namespace, c02_receipt.operation_id, source_ref)
    identity = _identity(namespace, c02_receipt.operation_id, source_ref)
    activity_id = "context-reply-activity:" + identity
    quote_id = "context-reply-quote:" + identity
    graph_job_ref = runtime_job_key(*namespace.as_tuple, activity_id, job_id).token
    deadline = frozen.input.expires_at_utc
    snapshot_ref = "context-reply-snapshot:" + canonical_digest({
        "frozen_input_digest": canonical_digest(asdict(frozen.input)),
        "read_versions": [(version.key.token, version.revision)
                          for version in read_versions],
    })[:48]
    quote = ResourceQuote(
        quote_id, 1, *namespace.as_tuple, activity_id, original_id, None,
        grant.lease_id, "context_reply", snapshot_ref, deadline,
        workflow.provider_config_ref, graph_job_ref, (), (), ceiling,
        None, deadline,
    )
    reservation_digest = canonical_digest({
        "schema": "sylanne.context-reply-budget-reservation.v2",
        "original_operation_id": original_id,
        "quote": asdict(quote), "c02_receipt": asdict(c02_receipt),
    })
    job = PersistentJob(
        job_id, original_id, activity_id, None, *namespace.as_tuple,
        snapshot_ref, "queued", "context_reply", {
            "c02_operation_id": c02_receipt.operation_id,
            "source_ref": source_ref,
            "template_version": CONTEXT_REPLY_WORKFLOW_V1,
            "frozen_input_digest": canonical_digest(asdict(frozen.input)),
        }, None,
        datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace(
            "+00:00", "Z"), grant.lease_id, workflow.provider_config_ref,
        {"resource_quote": f"{quote_id}:1"}, None, None, 0, 0, {}, None,
    )
    guard_digest = context_reply_graph_guard_digest_v2(
        read_versions, query_epoch, graph_epoch=graph_epoch,
        access_epoch=frozen.input.access_epoch,
        delete_epoch=frozen.input.delete_epoch,
        activation_generation=frozen.input.activation_generation,
    )
    seal = ContextReplyOriginalSealV2(
        namespace, c02_receipt.operation_id, source_ref,
        policy.installation_id, workflow.provider_config_digest,
        job_id, original_id, acquire_id, call_id,
        CONTEXT_REPLY_WORKFLOW_V1,
        canonical_digest(asdict(frozen.input)), frozen.digest, guard_digest,
    )
    d02_issuer.issue_quote(db, quote)
    reserve_budget(db, grant.lease_id, original_id, reservation_digest, ceiling)
    create_job(db, job, "create:" + original_id, reservation_digest)
    db.execute(
        "INSERT INTO graph_context_reply_preparations_v2"
        "(bot,persona,c02_operation_id,source_ref,job_id,original_operation_id,"
        "seal_json,frozen_request_json,read_versions_json,query_epoch_json,"
        "graph_epoch,access_epoch,delete_epoch,state) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'queued')",
        namespace.as_tuple + (
            c02_receipt.operation_id, source_ref, job_id, original_id,
            canonical_serialize(asdict(seal)), canonical_serialize(asdict(frozen)),
            canonical_serialize([{"key": version.key.token, "revision": version.revision}
                                 for version in read_versions]),
            canonical_serialize(asdict(query_epoch)), graph_epoch,
            frozen.input.access_epoch, frozen.input.delete_epoch,
        ),
    )
    return job, quote, reservation_digest, seal


@dataclass(frozen=True, slots=True)
class SavedContextReplyPreparationV2:
    seal: ContextReplyOriginalSealV2
    frozen_request: FrozenContextReplyRequestV1
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    state: str


def _versioned(value: dict) -> VersionedRef:
    return VersionedRef(**value)


def _part(value: dict) -> ContextReplyPartV1:
    return ContextReplyPartV1(
        value["kind"], _versioned(value["ref"]),
        _versioned(value["audience_ref"]), value["expires_at_utc"],
        value["text"], tuple(_versioned(item) for item in value["dependencies"]),
        _versioned(value["access_ref"]) if value["access_ref"] is not None else None,
    )


def _frozen(value: dict) -> FrozenContextReplyRequestV1:
    raw = value["input"]
    input = ContextReplyInputV1(
        NamespaceId(**raw["namespace"]), _versioned(raw["scene_ref"]),
        _versioned(raw["audience_ref"]), raw["conversation_ref"],
        raw["access_epoch"], raw["delete_epoch"],
        raw["activation_generation"], raw["frozen_at_utc"],
        raw["expires_at_utc"], _part(raw["question"]),
        tuple(_part(part) for part in raw["evidence"]),
        tuple(_part(part) for part in raw["focus"]),
        tuple(_part(part) for part in raw["required_checks"]),
        tuple(_part(part) for part in raw["dialogue_state"]),
        tuple(_part(part) for part in raw["history"]),
        tuple(_part(part) for part in raw["stable_history"]),
    )
    installation = ContextReplyInstallationV1(**value["installation"])
    frozen = freeze_context_reply_request_v1(input, installation)
    if frozen != FrozenContextReplyRequestV1(
            input, installation,
            tuple(ContextReplyMessageV1(**item) for item in value["messages"]),
            value["canonical_wire"], value["stable_prefix_wire"],
            value["stable_prefix_digest"], value["digest"]):
        raise ContextReplyJobHold("frozen context reply request differs")
    return frozen


def read_original_context_reply_preparation_v2(
        db, namespace: NamespaceId, c02_operation_id: str, source_ref: str,
) -> SavedContextReplyPreparationV2 | None:
    """Recompute the original seal from W01's durable row inside a graph tx."""
    if not db.in_transaction:
        raise ContextReplyJobHold("current graph read transaction required")
    from ..authority_service.current_authority_graph_read_v3 import require_authority_context_reply_preparation_v3
    handled,saved=require_authority_context_reply_preparation_v3(db,namespace,c02_operation_id,source_ref)
    if handled:return saved

    row = db.execute(
        "SELECT seal_json,frozen_request_json,read_versions_json,"
        "query_epoch_json,graph_epoch,access_epoch,delete_epoch,state "
        "FROM graph_context_reply_preparations_v2 WHERE bot=? AND persona=? "
        "AND c02_operation_id=? AND source_ref=?",
        namespace.as_tuple + (c02_operation_id, source_ref),
    ).fetchone()
    if row is None:
        return None
    try:
        seal_wire, request_wire, versions_wire, query_wire = row[:4]
        seal_data = json.loads(seal_wire)
        seal_data["namespace"] = NamespaceId(**seal_data["namespace"])
        seal = ContextReplyOriginalSealV2(**seal_data)
        frozen = _frozen(json.loads(request_wire))
        versions = tuple(GraphVersion(AtomKey.from_token(item["key"]),
                                      item["revision"])
                         for item in json.loads(versions_wire))
        query_data = json.loads(query_wire)
        query_data["namespace"] = NamespaceId(**query_data["namespace"])
        query = QueryEpoch(**query_data)
        expected_ids = context_reply_job_ids_v2(
            namespace, c02_operation_id, source_ref)
        guard_digest = context_reply_graph_guard_digest_v2(
            versions, query, graph_epoch=row[4], access_epoch=row[5],
            delete_epoch=row[6],
            activation_generation=frozen.input.activation_generation,
        )
        if (any(canonical_json(json.loads(wire)) != wire
                for wire in (seal_wire, request_wire, versions_wire, query_wire))
                or seal.namespace != namespace
                or (seal.c02_operation_id, seal.source_ref)
                   != (c02_operation_id, source_ref)
                or (seal.job_id, seal.original_operation_id,
                    seal.acquire_operation_id, seal.call_id) != expected_ids
                or seal.frozen_input_digest != canonical_digest(asdict(frozen.input))
                or seal.model_request_digest != frozen.digest
                or seal.graph_guard_digest != guard_digest
                or seal.installation_id != frozen.installation.installation_id
                or seal.provider_config_digest
                   != frozen.installation.provider_config_digest
                or frozen.input.namespace != namespace
                or row[5:7] != (frozen.input.access_epoch, frozen.input.delete_epoch)
                or row[7] not in {"queued", "acquired", "terminal"}):
            raise ContextReplyJobHold("saved context reply original seal differs")
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise ContextReplyJobHold("saved context reply preparation is invalid") from exc
    return SavedContextReplyPreparationV2(
        seal, frozen, versions, query, row[4], row[5], row[6], row[7])
