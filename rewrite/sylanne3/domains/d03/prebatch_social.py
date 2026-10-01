"""Current private D03/D05 checks before a D09 batch exists.

The caller must hold W01's verified write fence and the same SQLite write
transaction that exposes the provisional D08 action/schema at graph epoch
E+1. This helper reads the immutable ingress route itself; it accepts no
caller-authored audience, scene, D09 batch, or dispatch permit.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import sqlite3

from ...domains.d05.prebatch_boundary import issue_prebatch_boundary_check_v1
from ...domains.d06 import source_correction_head_key
from ...domains.d08 import ActionIntent, ActionSchema, ActionSchemaRecord, GoalExecutionProvider
from ...domains.d09 import (
    ClaimKind, D09ExpressionProvider, SourceReplyExpressionV1,
    segment_payload_digest,
)
from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, Owner
from ...memory_types import access_key, source_key
from ...runtime.dispatch_current_projection import (
    derive_current_domain_reads, read_current_dispatch_projection,
)
from ...runtime.dispatch_source_correction_barrier import read_source_correction_barrier
from ...runtime.reply_model_job import CurrentReplyRouteManifestV2
from ...runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from ...runtime_contracts import (
    CheckReceipt, FenceScope, NamespaceId, QueryEpoch,
    canonical_digest,
)
from .context import AccountBinding, ContextProvider, EntityAnchor, RoleBindingRequest, WorldEvent


@dataclass(frozen=True, slots=True)
class PrebatchPrivateManifestV1:
    """Graph-derived route and one source-bound, still unadmitted payload."""

    operation_id: str
    c02_operation_id: str
    action_id: str
    target_ref: str
    source_ref: str
    account_ref: str
    destination_ref: str
    scene_ref: str
    audience: tuple[str, ...]
    segment_id: str
    effect_id: str
    payload_digest: str
    provenance_digest: str
    route_digest: str

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class PrebatchSocialCandidateV1:
    """Provider check candidates and exact E+1 read closure, never admission."""

    status: str
    missing: tuple[str, ...]
    manifest: PrebatchPrivateManifestV1 | None
    role_receipt: CheckReceipt | None
    boundary_receipt: CheckReceipt | None
    graph_epoch: int | None
    positive_reads: tuple[GraphVersion, ...]
    negative_query: QueryEpoch | None
    negative_predicates: tuple[str, ...] = ()


def _current_atom(db, snapshot: GraphSnapshot, namespace: NamespaceId,
                  key: AtomKey):
    atoms = {atom.key: atom for atom in snapshot.atoms}
    atom = atoms.get(key)
    if (atom is None or not atom.valid or atom.revision < 1
            or (key.owner.bot, key.owner.persona) != namespace.as_tuple):
        raise ValueError("current graph atom is missing")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
        "AND bot=? AND persona=?", (key.token, *namespace.as_tuple),
    ).fetchone()
    if (row is None or row[0] != atom.revision or row[2] != 1
            or json.loads(row[1]) != atom.value):
        raise ValueError("current graph atom differs from staged snapshot")
    return atom


def _private_route(db, namespace: NamespaceId, source_ref: str):
    from ...host.identity import astrbot_namespace
    from ...runtime.first_ingress_v2 import scene_ref_for_conversation

    source = AtomKey.from_token(source_ref)
    if source != source_key(*namespace.as_tuple, source.owner.subject or ""):
        raise ValueError("reply source is not canonical D06 ingress source")
    rows = db.execute(
        "SELECT platform_ref,conversation_ref,sender_ref,message_id,visibility FROM "
        "graph_first_ingress_identity_v1 WHERE bot=? AND persona=? "
        "AND source_ref=?", (*namespace.as_tuple, source.owner.subject),
    ).fetchall()
    if len(rows) != 1:
        raise ValueError("one original host ingress route required")
    account_ref, destination_ref, sender_ref, message_id, visibility = rows[0]
    account = json.loads(account_ref)
    destination = json.loads(destination_ref)
    if (visibility != "private" or type(account) is not list or len(account) != 3
            or type(destination) is not list or len(destination) != 2
            or any(type(item) is not str or not item for item in (*account, *destination))
            or json.dumps(account, ensure_ascii=True, separators=(",", ":")) != account_ref
            or json.dumps(destination, ensure_ascii=True, separators=(",", ":")) != destination_ref
            or astrbot_namespace(account[0], account[2], "route-check").bot_id
               != namespace.bot_id):
        raise ValueError("original private AstrBot route differs")
    if (type(sender_ref) is not str or not sender_ref
            or type(message_id) is not str or not message_id):
        raise ValueError("original private sender is unavailable")
    return account_ref, destination_ref, sender_ref, message_id, scene_ref_for_conversation(
        namespace, account_ref, destination_ref)


def _current_account_route(
    db, snapshot: GraphSnapshot, namespace: NamespaceId, query: QueryEpoch,
    route: CurrentReplyRouteManifestV2,
    binding: CurrentReplyEntityRouteBindingV2, *,
    account_ref: str, destination_ref: str, sender_ref: str, message_id: str,
    scene_ref: str, now_utc: float,
) -> tuple[GraphVersion, ...]:
    """Recheck W01's account endpoint against the E+1 graph and full scan."""
    identity = {
        "namespace": namespace.as_tuple,
        "platform_ref": account_ref,
        "sender_ref": sender_ref,
    }
    suffix = canonical_digest(identity)
    entity_id = "entity:account-v1:" + suffix
    account_id = "account:v1:" + suffix
    arrival_id = "world:message-arrival-v1:" + canonical_digest({
        "namespace": namespace.as_tuple,
        "platform_ref": account_ref,
        "conversation_ref": destination_ref,
        "message_id": message_id,
        "source_id": AtomKey.from_token(route.source_ref).owner.subject,
    })
    if ((binding.namespace, binding.c02_operation_id, binding.source_ref,
         binding.platform_ref, binding.sender_ref, binding.conversation_ref,
         binding.scene_ref, binding.target_entity_ref, binding.account_id) != (
         namespace, route.c02_operation_id, route.source_ref, account_ref,
         sender_ref, destination_ref, scene_ref, entity_id, account_id)
            or binding.query != QueryEpoch(namespace, "all", query.revision - 1)
            or not binding.binding_digest
            or (binding.valid_until_utc is not None
                and now_utc >= binding.valid_until_utc)):
        raise ValueError("current reply account route differs from original ingress")
    versions = (
        binding.anchor_version, binding.binding_version,
        binding.arrival_event_version, binding.binding_evidence_event_version,
        binding.source_version, binding.access_version,
    )
    if (type(binding.binding_scan_versions) is not tuple
            or any(type(item) is not GraphVersion or item.revision < 1
                   for item in (*versions, *binding.binding_scan_versions))
            or binding.anchor_version.key != AtomKey(
                Owner("persona", *namespace.as_tuple), "d03.entity_anchor", entity_id)
            or binding.binding_version.key != AtomKey(
                Owner("persona", *namespace.as_tuple), "d03.account_binding", account_id)
            or binding.arrival_event_version.key != AtomKey(
                Owner("event", *namespace.as_tuple, arrival_id),
                "d03.world_event", "current")
            or binding.source_version.key != AtomKey.from_token(route.source_ref)
            or binding.access_version.key != access_key(
                *namespace.as_tuple, binding.source_version.key.owner.subject or "")):
        raise ValueError("current reply account version closure differs")
    atoms = tuple(_current_atom(db, snapshot, namespace, item.key)
                  for item in versions)
    if any(atom.revision != item.revision for atom, item in zip(atoms, versions)):
        raise ValueError("current reply account version changed")
    anchor = EntityAnchor(**{
        **atoms[0].value,
        "creation_evidence_refs": tuple(atoms[0].value["creation_evidence_refs"]),
    })
    account = AccountBinding(**atoms[1].value)
    arrival = WorldEvent(**{
        **atoms[2].value,
        "participant_roles": tuple(tuple(pair) for pair in atoms[2].value["participant_roles"]),
        "source_refs": tuple(atoms[2].value["source_refs"]),
    })
    evidence = WorldEvent(**{
        **atoms[3].value,
        "participant_roles": tuple(tuple(pair) for pair in atoms[3].value["participant_roles"]),
        "source_refs": tuple(atoms[3].value["source_refs"]),
    })
    if (anchor.entity_id != entity_id or anchor.kind != "account"
            or anchor.status != "active"
            or anchor.owner_scope != f"persona:{namespace.persona_id}"
            or account.account_id != account_id
            or account.entity_id != entity_id
            or account.platform_namespace != account_ref
            or account.platform_identifier != sender_ref
            or account.verification_ref != binding.binding_evidence_event_version.key.token
            or account.valid_until != binding.valid_until_utc
            or account.valid_from > now_utc
            or arrival.kind != "message_received" or arrival.reality != "host_observed"
            or arrival.participant_roles != ((entity_id, "sender_account"),)
            or arrival.source_refs != (route.source_ref,)
            or arrival.scene_ref != scene_ref
            or evidence.kind != "message_received" or evidence.reality != "host_observed"
            or evidence.participant_roles != ((entity_id, "sender_account"),)
            or evidence.learned_at != account.valid_from):
        raise ValueError("current reply account endpoint differs")
    rows = db.execute(
        "SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='d03.account_binding' AND valid=1 ORDER BY token",
        namespace.as_tuple,
    ).fetchall()
    scan = tuple(GraphVersion(AtomKey.from_token(token), revision)
                 for token, revision, _ in rows)
    if scan != binding.binding_scan_versions:
        raise ValueError("current account binding scan changed")
    matches = []
    for token, _, encoded in rows:
        row = AccountBinding(**json.loads(encoded))
        key = AtomKey.from_token(token)
        _current_atom(db, snapshot, namespace, key)
        if (row.platform_namespace == account_ref
                and row.platform_identifier == sender_ref
                and row.valid_from <= now_utc
                and (row.valid_until is None or now_utc < row.valid_until)):
            matches.append(key)
    if matches != [binding.binding_version.key]:
        raise ValueError("current reply account binding is ambiguous")
    return tuple(dict.fromkeys((*versions, *scan)))


def issue_prebatch_private_social_v1(
    db, snapshot: GraphSnapshot, query: QueryEpoch,
    intent: ActionIntent, schema_record: ActionSchemaRecord,
    expression: SourceReplyExpressionV1, *,
    route: CurrentReplyRouteManifestV2,
    route_binding: CurrentReplyEntityRouteBindingV2,
    context: ContextProvider, scope: FenceScope, now_utc: float,
    valid_until_utc: float | None = None,
) -> PrebatchSocialCandidateV1:
    """Issue D03/D05 check candidates from a provisional E+1 graph view.

    W01 must validate ``scope`` with Authority before this call and again at
    seal. A Python FenceScope object alone is not a live permit. Reinvoke this
    function in the final receipt hook and compare the entire result before
    matching the actual D09 batch with ``match_prebatch_batch_v1``.
    """
    def hold(reason: str, *, manifest=None, role=None, boundary=None):
        return PrebatchSocialCandidateV1(
            "hold", (reason,), manifest, role, boundary, None, (), None)

    if (not getattr(db, "in_transaction", False)
            or type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(intent) is not ActionIntent
            or type(schema_record) is not ActionSchemaRecord
            or type(expression) is not SourceReplyExpressionV1
            or type(route) is not CurrentReplyRouteManifestV2
            or type(route_binding) is not CurrentReplyEntityRouteBindingV2
            or type(context) is not ContextProvider
            or type(scope) is not FenceScope
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        return hold("social.current_staged_transaction_or_typed_inputs")
    expiry = now_utc + 1.0 if valid_until_utc is None else valid_until_utc
    if (type(expiry) not in (int, float) or not math.isfinite(expiry)
            or expiry <= now_utc):
        return hold("social.current_check_deadline_unavailable")
    namespace = scope.namespace
    if (scope.operation != "write"
            or scope.operation_id != scope.permit.operation_id
            or scope.graph_epoch.revision + 1 != query.revision
            or query != QueryEpoch(namespace, "all", query.revision)
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona,
                snapshot.epochs[0].revision) != (*namespace.as_tuple, query.revision)
            or intent.action_kind != "message" or intent.purpose != "expression"
            or len(intent.source_refs) != 1
            or len(expression.segments) != 1
            or not expression.claims
            or route.namespace != namespace
            or route.source_ref != intent.source_refs[0]
            or type(route.c02_operation_id) is not str
            or not route.c02_operation_id):
        return hold("social.staged_write_scope_or_single_reply")
    segment = expression.segments[0]
    if (segment.media_refs or segment.delay_seconds != 0.0
            or segment.segment_id != "segment:" + expression.provenance_digest
            or segment_payload_digest(segment.body, segment.media_refs,
                                      segment.claim_uses) != expression.payload_digest
            or len(segment.body) > 2048
            or any(type(claim) is not str or len(claim) != 64
                   or any(char not in "0123456789abcdef" for char in claim)
                   for claim in (expression.provenance_digest,
                                 expression.result_read_request_digest,
                                 expression.observation_digest))
            or any(claim.source_refs != intent.source_refs
                   or claim.kind is not ClaimKind.REPORTED_CLAIM
                   for claim in expression.claims)):
        return hold("social.source_reply_manifest_differs")
    try:
        frozen = ActionSchema(
            schema_record.schema_id, schema_record.action_kind,
            schema_record.proactive, schema_record.required_checks)
        bound_schema = ActionSchemaRecord.bind(intent, frozen)
    except (TypeError, ValueError):
        return hold("social.staged_action_schema_identity")
    if (schema_record != bound_schema or frozen.proactive
            or schema_record.required_checks != intent.required_checks):
        return hold("social.staged_action_schema_identity")
    owner = Owner("activity", *namespace.as_tuple, intent.identity.activity_id)
    action_key = AtomKey(owner, "d08.action_intent.v1", intent.action_id)
    schema_key = AtomKey(owner, "d08.action_schema.v1", schema_record.schema_ref)
    try:
        action_atom = _current_atom(db, snapshot, namespace, action_key)
        schema_atom = _current_atom(db, snapshot, namespace, schema_key)
        source_ref = intent.source_refs[0]
        source_atom = _current_atom(
            db, snapshot, namespace, AtomKey.from_token(source_ref))
        access_atom = _current_atom(
            db, snapshot, namespace,
            access_key(*namespace.as_tuple,
                       AtomKey.from_token(source_ref).owner.subject or ""))
        d08 = {spec.name: spec for spec in GoalExecutionProvider().register_types()}
        if (d08[action_key.type_name].validator(action_atom.value) != intent
                or d08[schema_key.type_name].validator(schema_atom.value)
                   != schema_record):
            raise ValueError("staged D08 values differ")
        account_ref, destination_ref, sender_ref, message_id, scene_ref = _private_route(
            db, namespace, intent.source_refs[0])
        if ((route.platform_ref, route.conversation_ref, route.scene_ref)
                != (account_ref, destination_ref, scene_ref)
                or route.route_digest != canonical_digest({
                    "account_ref": account_ref,
                    "destination_ref": destination_ref,
                    "scene_ref": scene_ref,
                })):
            raise ValueError("sealed ingress route differs from current route")
        account_versions = _current_account_route(
            db, snapshot, namespace, query, route, route_binding,
            account_ref=account_ref, destination_ref=destination_ref,
            sender_ref=sender_ref, message_id=message_id,
            scene_ref=scene_ref, now_utc=now_utc)
        if intent.target_ref != route_binding.target_entity_ref:
            raise ValueError("staged action targets a different account entity")
        if any(claim.allowed_audiences != (destination_ref,)
               or claim.disclosure_ref != source_ref
               for claim in expression.claims):
            raise ValueError("quoted claims differ from private route audience")
        manifest = PrebatchPrivateManifestV1(
            intent.identity.operation_id, route.c02_operation_id,
            intent.action_id, intent.target_ref,
            intent.source_refs[0], account_ref, destination_ref, scene_ref,
            (destination_ref,), segment.segment_id, segment.effect_id,
            expression.payload_digest, expression.provenance_digest,
            route.route_digest,
        )
        projection = read_current_dispatch_projection(
            db, namespace, snapshot, query)
        request = RoleBindingRequest(
            f"persona:{namespace.persona_id}", intent.target_ref, None,
            scene_ref, intent.action_kind, intent.purpose, now_utc, True,
        )
        role_read, boundary_read = derive_current_domain_reads(
            db, projection, request, context)
        specs = {item.check_kind: item for item in intent.required_checks
                 if item.check_kind in {"role_binding", "boundary"}}
        if (len(specs) != 2
                or specs["role_binding"].provider_id != "d03.role_binding"
                or specs["boundary"].provider_id != "d05.boundary"):
            raise ValueError("frozen social check specs differ")
        criteria_atoms = []
        for spec in specs.values():
            criteria = tuple(item for item in spec.required_input_versions
                             if item.ref == spec.criteria_version)
            if len(criteria) != 1:
                raise ValueError("current social criterion missing")
            key = AtomKey.from_token(criteria[0].ref)
            criterion = _current_atom(db, snapshot, namespace, key)
            if criterion.revision != criteria[0].version:
                raise ValueError("social criterion revision changed")
            criteria_atoms.append(criterion)
        role = context.provide_required_check(
            intent, role_read, valid_until=expiry)
        boundary = issue_prebatch_boundary_check_v1(
            intent, frozen, boundary_read, audience_scope=destination_ref,
            scene_ref=scene_ref, now_utc=now_utc,
            valid_until_utc=expiry)
        correction_refs = {source_ref}
        for atom in (*projection.role_bindings, *projection.boundary_rules):
            refs = atom.value.get("source_refs")
            if type(refs) is not list or not refs:
                raise ValueError("social row lacks source closure")
            correction_refs.update(refs)
        correction_missing = []
        for ref in sorted(correction_refs):
            correction_missing.extend(read_source_correction_barrier(
                db, namespace, query, (ref,), dependent_ref=intent.action_id,
            ).missing_sources)
        predicate_refs = tuple(sorted({
            source_correction_head_key(
                namespace, AtomKey.from_token(ref).owner.subject or "").token
            for ref in correction_refs
        }))
        closure = {
            atom.key: GraphVersion(atom.key, atom.revision)
            for atom in (action_atom, schema_atom, source_atom, access_atom,
                         *criteria_atoms, *projection.role_bindings,
                         *projection.boundary_rules)
        }
        closure.update({item.key: item for item in account_versions})
    except (sqlite3.Error, TypeError, ValueError, KeyError, StopIteration):
        return hold("social.current_graph_provider_read_unavailable")
    missing = []
    if projection.coverage != "full":
        missing.extend(projection.missing_sources)
    missing.extend(correction_missing)
    if (role.result, role.coverage) != ("pass", "full"):
        missing.append("d03.current_role_binding_not_pass")
    if boundary.status != "check_pass":
        missing.extend(boundary.missing)
    return PrebatchSocialCandidateV1(
        "hold" if missing else "checks_candidate",
        tuple(dict.fromkeys(missing)), manifest, role, boundary.receipt,
        query.revision, tuple(sorted(closure.values(),
                                     key=lambda item: item.key.token)), query,
        ("d03.role_binding:all_valid", "d05.boundary_rule:all_valid")
        + (f"graph_first_ingress_identity_v1:source:{source_ref}:unique_private",)
        + ("d03.account_binding:all_valid:unique_current_sender",)
        + predicate_refs,
    )


def match_prebatch_batch_v1(
    candidate: PrebatchSocialCandidateV1, batch: dict,
) -> bool:
    """Compare a newly reissued candidate to W01's actual D09 batch row."""
    if (type(candidate) is not PrebatchSocialCandidateV1
            or candidate.status != "checks_candidate"
            or type(batch) is not dict or candidate.manifest is None):
        return False
    try:
        next(spec for spec in D09ExpressionProvider.register_types()
             if spec.name == "d09.verified_segment_batch.v1").validator(batch)
        manifest = candidate.manifest
        segment = batch["segments"]
        return (len(segment) == 1
                and batch["action_id"] == manifest.action_id
                and batch["target_ref"] == manifest.target_ref
                and batch["scene_ref"] == manifest.scene_ref
                and tuple(batch["audiences"]) == manifest.audience
                and tuple(segment[0]["source_refs"]) == (manifest.source_ref,)
                and not segment[0]["media_refs"]
                and (segment[0]["segment_id"], segment[0]["effect_id"],
                     segment[0]["payload_digest"]) == (
                         manifest.segment_id, manifest.effect_id,
                         manifest.payload_digest))
    except (KeyError, TypeError, ValueError, StopIteration):
        return False


__all__ = ["PrebatchPrivateManifestV1", "PrebatchSocialCandidateV1",
           "issue_prebatch_private_social_v1", "match_prebatch_batch_v1"]
