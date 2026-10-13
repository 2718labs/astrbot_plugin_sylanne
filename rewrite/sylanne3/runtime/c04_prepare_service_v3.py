"""Prepare one installed C04 execution inside W01's Owner write transaction.

W01 stages one D02 reservation GraphWrite, commits it by its normal graph CAS,
then calls the record function from that CAS's receipt hook. The hook freezes
the post-reservation observation epoch and reserves CPU in the same SQLite
transaction. Neither function starts Authority work or adopts an experience.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import sqlite3

from ..authority_service.internal_work_contract import InternalWorkBindingV1
from ..contracts import canonical_json
from ..domains.d02 import BodyDomain, BodyReservation, BodyState
from ..domains.d02.body_quote_original import (
    D02BodyQuoteAuthority, OriginalFixedBodyReservation,
)
from ..domains.d04.interval_projection_v2 import D04IntervalProjectionPolicyV2
from ..domains.d06 import CandidateItem, CandidateSet
from ..domains.d06.current_association_candidates import CurrentAssociationBudgetV1
from ..domains.d07 import D07DomainProvider
from ..graph_types import (
    AtomKey, GraphVersion, GraphWrite, Owner, owner_grant_key,
    validate_owner_grant_v1,
)
from ..host.post_c02_attention_driver import post_c02_attention_operation_id
from ..memory_association import ActivationPolicy
from ..memory_types import SourceRecord, access_key
from ..native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ..runtime_contracts import (
    CommandEnvelope, NamespaceId, VersionedRef, canonical_digest,
)
from .budget import reserve_budget
from .c04_association_graph_collector_v2 import (
    collect_c04_association_graph_originals_v2,
)
from .c04_cpu_quote_policy import (
    C04_INTERNAL_CPU_WORK_KIND, C04InternalCpuQuotePolicyAuthorityV1,
)
from .c04_current_projection_service_v3 import issue_current_c04_targets_v3
from .c04_frozen_association_original_v3 import (
    read_c04_frozen_association_original_v3,
    record_c04_frozen_association_original_v3,
    verify_current_association_input_heads_v3,
)
from .c04_internal_work_original_v1 import (
    C04InternalWorkPreparedV1, read_c04_internal_work_prepared_v1,
    record_c04_internal_work_prepared_v1,
)
from .c04_v3_contracts import (
    ALGORITHM_ID_V3, AssociationBudgetV3, AssociationPageV3,
    AssociationWorkInputV3, GraphHeadV3, canonical_v3_digest,
)
from .issuers import D02ResourceIssuer, D11BudgetGrantIssuer, ResourceQuote
from .jobs import PersistentJob, create_job, get_job


class C04PrepareHold(ValueError):
    """Preparation cannot preserve its originals or current admission."""


@dataclass(frozen=True, slots=True)
class C04PrepareStageV3:
    """Internal W01 candidate; construction is not a caller capability."""

    envelope: CommandEnvelope
    resource_quote: ResourceQuote
    body: OriginalFixedBodyReservation
    work: AssociationWorkInputV3
    execution_id: str
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    body_profile_ref: str
    body_profile_revision: int
    body_state_ref: str
    body_state_revision: int
    read_versions: tuple[GraphVersion, ...]
    replayed: bool = False
    prepared: C04InternalWorkPreparedV1 | None = None

    @property
    def reservation_write(self) -> GraphWrite:
        return self.body.reservation_write

    @property
    def job_id(self) -> str:
        return c04_prepare_job_id_v3(self.work.namespace, self.work.operation_id)


def c04_prepare_job_id_v3(namespace: NamespaceId, operation_id: str) -> str:
    """Stable lookup for the job that owns this prepared binding's recovery."""
    if type(namespace) is not NamespaceId or type(operation_id) is not str or not operation_id:
        raise TypeError("typed C04 job namespace and operation required")
    return "c04job-" + canonical_digest({
        "schema": "c04.prepared-job.v3", "namespace": namespace.as_tuple,
        "operation_id": operation_id,
    })[:48]


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise C04PrepareHold("caller-owned W01 write transaction required")


def _head(db: sqlite3.Connection, namespace: NamespaceId, key: AtomKey):
    if NamespaceId.from_key(key) != namespace:
        raise C04PrepareHold("prepare graph reference crosses namespace")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
        "AND bot=? AND persona=?", (key.token, *namespace.as_tuple),
    ).fetchone()
    if row is None or row[0] < 1 or row[2] != 1:
        raise C04PrepareHold("required current prepare graph original is absent")
    value = json.loads(row[1])
    if type(value) is not dict or canonical_json(value) != row[1]:
        raise C04PrepareHold("prepare graph original is noncanonical")
    return row[0], value


def _replay(
    db, *, envelope, owner, body_policy_id, body_policy_version,
    cpu_policy_id, cpu_policy_version, reservation_id, execution_id,
    cue_source_ref, focus_ref, attention_ticket_ref, mood_ref,
    encoding_operations, budget, context_tags, algorithm_build_digest,
    d02_issuer, body_authority, cpu_authority,
) -> C04PrepareStageV3 | None:
    namespace = envelope.authority.namespace
    prepared = read_c04_internal_work_prepared_v1(
        db, namespace, envelope.identity.operation_id)
    if prepared is None:
        return None
    binding = prepared.binding
    work = read_c04_frozen_association_original_v3(db, namespace, binding)
    cpu_policy, resource = cpu_authority.read_original_request_quote(
        db, namespace, binding.operation_id)
    request = db.execute(
        "SELECT request_json FROM runtime_c04_cpu_quote_requests_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, binding.operation_id),
    ).fetchone()
    body_policy = db.execute(
        "SELECT policy_id,policy_version FROM d02_body_quotes_v1 "
        "WHERE bot=? AND persona=? AND quote_id=?",
        (*namespace.as_tuple, binding.body_quote_ref),
    ).fetchone()
    if (work is None or request is None
            or json.loads(request[0]).get("envelope_digest") != canonical_digest(envelope)
            or body_policy != (body_policy_id, body_policy_version)
            or (cpu_policy.policy_id, cpu_policy.version)
               != (cpu_policy_id, cpu_policy_version)
            or (binding.execution_id, AtomKey.from_token(binding.body_reservation_ref).name,
                binding.activation_generation, binding.parent_budget_lease_ref,
                binding.activity_id) !=
               (execution_id, reservation_id, envelope.authority.activation_generation,
                envelope.parent_budget_lease_ref, envelope.identity.activity_id)
            or (work.cue_source_ref, work.focus_ref, work.attention_ticket_ref,
                work.mood_ref, work.budget, work.context_tags,
                work.algorithm_build_digest, work.audience, work.purpose) !=
               (cue_source_ref, focus_ref, attention_ticket_ref, mood_ref,
                budget, context_tags, algorithm_build_digest,
                owner.audience, owner.purpose)
            or tuple((target.source_ref, target.baseline.encoding_operation_id)
                     for target in work.targets) != encoding_operations
            or resource != d02_issuer.original_signed_quote(
                db, binding.resource_quote_ref, binding.resource_quote_version)
            or canonical_digest(resource) != binding.resource_quote_digest):
        raise C04PrepareHold("same C04 operation changed its immutable prepare request")
    body_quote = body_authority.original_body_quote(
        db, binding.body_quote_ref, binding.body_quote_version, resource,
        binding.operation_id)
    row = db.execute(
        "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
        "AND event_bot=? AND event_persona=?",
        (binding.body_reservation_ref, prepared.body_reservation_revision,
         *namespace.as_tuple),
    ).fetchone()
    if (row is None or row[1] != 1
            or canonical_digest(body_quote) != binding.body_quote_digest):
        raise C04PrepareHold("replayed original body reservation differs")
    reservation = BodyReservation(**json.loads(row[0]))
    body = OriginalFixedBodyReservation(
        body_quote, binding.body_quote_version, reservation,
        BodyDomain.reservation_write(namespace, binding.activity_id, reservation), True)
    job = get_job(db, c04_prepare_job_id_v3(namespace, binding.operation_id))
    if ((job.bot_id, job.persona_id, job.operation_id, job.activity_id,
         job.effect_id, job.work_kind, job.budget_ref, job.resource_ref) !=
        (*namespace.as_tuple, binding.operation_id, binding.activity_id,
         resource.effect_id, C04_INTERNAL_CPU_WORK_KIND,
         binding.parent_budget_lease_ref, resource.resource_ref)):
        raise C04PrepareHold("C04 prepared recovery job identity differs")
    return C04PrepareStageV3(
        replace(envelope, version_guard=replace(envelope.version_guard,
            resource_lease_versions=(VersionedRef(resource.quote_id, resource.version),))),
        resource, body, work, execution_id, prepared.owner_grant_ref,
        prepared.owner_grant_revision, prepared.owner_grant_digest,
        prepared.body_profile_ref, prepared.body_profile_revision,
        prepared.body_state_ref, prepared.body_state_revision,
        tuple(GraphVersion(AtomKey.from_token(ref), revision)
              for ref, revision in prepared.read_versions), True, prepared,
    )


def stage_current_c04_prepare_v3(
    db: sqlite3.Connection, *, envelope: CommandEnvelope, owner: object,
    body_policy_id: str, body_policy_version: int,
    cpu_policy_id: str, cpu_policy_version: int,
    reservation_id: str, execution_id: str,
    cue_source_ref: str, focus_ref: str, attention_ticket_ref: str, mood_ref: str,
    encoding_operations: tuple[tuple[str, str], ...],
    budget: AssociationBudgetV3, context_tags: tuple[str, ...],
    algorithm_build_digest: str, asset: D04LoadedTanhReadoutAsset,
    projection_policy: D04IntervalProjectionPolicyV2,
    d02_issuer: D02ResourceIssuer, d11_issuer: D11BudgetGrantIssuer,
    body_authority: D02BodyQuoteAuthority,
    cpu_authority: C04InternalCpuQuotePolicyAuthorityV1,
    installation_id: str, now_utc: float,
) -> C04PrepareStageV3:
    """Collect and authenticate inputs; price but do not execute or graph-write.

    The external W01 API must supply current Owner/fence, the pre-quote
    envelope, installed providers/asset/build, and a trusted current time.
    Work, salience, bindings, quotes, results and actual costs are never caller
    inputs. Roll back this entire transaction if staging or graph CAS fails.
    """
    from ..graph_coordinator import OwnerLeaseBindingV1

    _transaction(db)
    if (type(envelope) is not CommandEnvelope
            or type(owner) is not OwnerLeaseBindingV1
            or type(budget) is not AssociationBudgetV3
            or type(asset) is not D04LoadedTanhReadoutAsset
            or type(projection_policy) is not D04IntervalProjectionPolicyV2
            or type(d02_issuer) is not D02ResourceIssuer
            or not isinstance(d11_issuer, D11BudgetGrantIssuer)
            or type(body_authority) is not D02BodyQuoteAuthority
            or type(cpu_authority) is not C04InternalCpuQuotePolicyAuthorityV1
            or type(context_tags) is not tuple
            or tuple(sorted(set(context_tags))) != context_tags
            or type(encoding_operations) is not tuple or not encoding_operations
            or any(type(pair) is not tuple or len(pair) != 2
                   or any(type(value) is not str or not value for value in pair)
                   for pair in encoding_operations)
            or tuple(sorted({ref for ref, _ in encoding_operations}))
               != tuple(ref for ref, _ in encoding_operations)):
        raise C04PrepareHold("typed installed C04 preparation inputs required")
    authority, identity = envelope.authority, envelope.identity
    namespace = authority.namespace
    if (authority.issuer_domain != "d12" or identity.phase != "realize-recollection"
            or identity.effect_id is None or authority.worker_fence is not None
            or envelope.version_guard.resource_lease_versions
            or (owner.namespace, owner.actor, owner.purpose, (owner.audience,))
               != (namespace, authority.actor, authority.purpose, authority.audience)
            or "c04.internal_work.prepare" not in owner.capabilities):
        raise C04PrepareHold("C04 current Owner or pre-quote envelope differs")
    prior = _replay(db, envelope=envelope, owner=owner,
        body_policy_id=body_policy_id, body_policy_version=body_policy_version,
        cpu_policy_id=cpu_policy_id, cpu_policy_version=cpu_policy_version,
        reservation_id=reservation_id, execution_id=execution_id,
        cue_source_ref=cue_source_ref, focus_ref=focus_ref,
        attention_ticket_ref=attention_ticket_ref, mood_ref=mood_ref,
        encoding_operations=encoding_operations, budget=budget,
        context_tags=context_tags, algorithm_build_digest=algorithm_build_digest,
        d02_issuer=d02_issuer, body_authority=body_authority, cpu_authority=cpu_authority)
    if prior is not None:
        return prior
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if epochs != (owner.access_epoch, owner.delete_epoch) or epochs != (
            envelope.version_guard.access_epoch, envelope.version_guard.delete_epoch):
        raise C04PrepareHold("C04 current rights changed")
    originals = collect_c04_association_graph_originals_v2(
        db, namespace, cue_source_ref=cue_source_ref, focus_ref=focus_ref,
        attention_ticket_ref=attention_ticket_ref, mood_ref=mood_ref,
        budget=CurrentAssociationBudgetV1(budget.max_hops, budget.max_edges,
            budget.max_nodes, budget.max_iterations, budget.max_candidates),
        context_tags=context_tags)
    heads = {row.key.token: row for row in originals.reads}
    for version in envelope.version_guard.read_versions:
        key = version.key
        if NamespaceId.from_key(key) != namespace:
            raise C04PrepareHold("C04 envelope read crosses namespace")
        row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if (row[0] if row else 0) != version.revision:
            raise C04PrepareHold("C04 envelope graph read changed")
    if any(query.namespace != namespace or query.revision != originals.graph_epoch.revision
           for query in envelope.version_guard.query_epochs):
        raise C04PrepareHold("C04 envelope query epoch changed")
    focus = heads[focus_ref].value
    ticket = heads[attention_ticket_ref].value
    spec = next(spec for spec in D07DomainProvider.type_specs()
                if spec.name == "d07.attention_ticket.v1")
    spec.validator(ticket)
    focus_spec = next(spec for spec in D07DomainProvider.type_specs()
                      if spec.name == "d07.focus.v1")
    focus_spec.validator(focus)
    issuance = db.execute(
        "SELECT operation_id,c02_operation_id FROM graph_d07_attention_issuance_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        (*namespace.as_tuple, ticket["causal_root"])).fetchall()
    if (ticket["valid_until"] <= now_utc or not ticket["eligible"]
            or not ticket["resources_available"] or ticket["cancel_refs"]
            or focus["primary_ticket_ref"] != attention_ticket_ref
            or ticket["ticket_id"] != AtomKey.from_token(attention_ticket_ref).name
            or cue_source_ref not in ticket["source_refs"]
            or sum(operation == post_c02_attention_operation_id(c02, ticket["causal_root"])
                   and ticket["ticket_id"] == "attention:" + canonical_digest({
                       "operation_id": operation})[:48]
                   for operation, c02 in issuance) != 1):
        raise C04PrepareHold("current D07 cue attention has no live adopted issuance")
    mood_revision = heads[mood_ref].revision
    mood_joint = db.execute(
        "SELECT event_id FROM graph_history WHERE token=? AND revision=? "
        "AND event_bot=? AND event_persona=?",
        (mood_ref, mood_revision, *namespace.as_tuple)).fetchone()
    if mood_joint is None:
        raise C04PrepareHold("current Mood has no joint adoption original")
    targets = issue_current_c04_targets_v3(
        db, namespace=namespace, operation_id=identity.operation_id,
        encoding_operations=encoding_operations, mood_joint_operation_id=mood_joint[0],
        mood_ref=mood_ref, audience=owner.audience, purpose=owner.purpose,
        owner_epoch=owner.revocation_epoch, access_epoch=epochs[0], delete_epoch=epochs[1],
        asset=asset, policy=projection_policy)
    source = SourceRecord.from_dict(heads[cue_source_ref].value)
    access = heads[access_key(*namespace.as_tuple, source.source_id).token].value
    allowed = tuple(sorted(set(source.purposes) & set(access["purposes"])))
    if owner.purpose not in allowed:
        raise C04PrepareHold("cue does not permit the current recollection purpose")
    policy = ActivationPolicy(0.5, 0.25, budget.max_iterations, budget.max_nodes, 1e-6)
    cue_set = CandidateSet("c04-prepare-cue:" + canonical_digest({
        "schema": "d07.c04-prepare-cue.v3", "namespace": namespace.as_tuple,
        "operation": identity.operation_id, "activity": identity.activity_id,
        "cue": (cue_source_ref, heads[cue_source_ref].revision,
                canonical_digest(heads[cue_source_ref].value)),
        "focus": (focus_ref, heads[focus_ref].revision),
        "ticket": (attention_ticket_ref, heads[attention_ticket_ref].revision),
        "focus_epoch": focus["focus_epoch"], "audience": owner.audience,
        "purpose": owner.purpose, "policy": policy,
        "algorithm": ALGORITHM_ID_V3, "build": algorithm_build_digest,
    }), (CandidateItem(source.source_id, source.source_id, source.provenance_root,
        "c04_prepare_cue_v3", allowed, 0.0, "subjective_association_only"),),
        "complete", None, epochs[0], epochs[1])
    selection = D07DomainProvider.select_recollection(
        activity_id=identity.activity_id, focus_epoch=focus["focus_epoch"],
        candidates=cue_set, selected_candidate_ids=(source.source_id,)).selection_ticket
    work = AssociationWorkInputV3(
        namespace, identity.activity_id, identity.operation_id,
        cue_source_ref, focus_ref, attention_ticket_ref, mood_ref,
        selection, canonical_v3_digest(selection), owner.audience, owner.purpose,
        context_tags, tuple(GraphHeadV3(row.key.token, row.revision, row.valid,
            row.value_json) for row in originals.reads),
        tuple(sorted((AssociationPageV3(query.source_ref, query.hop,
            query.edge_refs, query.next_after) for query in originals.edge_queries),
            key=lambda page: page.source_ref)), budget, policy,
        originals.graph_epoch.revision, owner.revocation_epoch, *epochs,
        originals.truncated, ALGORITHM_ID_V3, algorithm_build_digest, targets,
        schema=("c04.current_association.authored.v3.input"
                if AtomKey.from_token(mood_ref).type_name == "d04.authored_mood_state.v1"
                else "c04.current_association.v3.input"))
    verify_current_association_input_heads_v3(db, work)
    owner_key = owner_grant_key(*namespace.as_tuple)
    owner_revision, owner_value = _head(db, namespace, owner_key)
    validate_owner_grant_v1(owner_value)
    if ("sha256:" + canonical_digest(owner_value) != owner.grant_digest
            or owner_revision != owner.grant_revision
            or owner_value["installation_id"] != installation_id
            or owner_value["grant_id"] != owner.grant_id
            or owner_value["activation_generation"] != authority.activation_generation):
        raise C04PrepareHold("C04 current Owner graph original differs")
    cpu_policy = cpu_authority.read_policy(db, namespace, cpu_policy_id, cpu_policy_version)
    if cpu_policy.installation_id != installation_id or cpu_policy.algorithm_ref != ALGORITHM_ID_V3:
        raise C04PrepareHold("installed CPU policy or algorithm differs")
    resource = cpu_authority.request_quote(
        db, namespace=namespace, policy_id=cpu_policy_id, policy_version=cpu_policy_version,
        envelope=envelope, owner=owner, d11_issuer=d11_issuer,
        algorithm_ref=ALGORITHM_ID_V3, now_utc=now_utc)
    versions = {row.key.token: row.revision for row in originals.reads}
    for target in work.targets:
        versions[target.condition.current_checkpoint.ref] = target.condition.current_checkpoint.revision
    versions[owner_key.token] = owner_revision
    resources = _prepare_c04_body_resources_v3(db, envelope=envelope, resource=resource,
        body_policy_id=body_policy_id, body_policy_version=body_policy_version,
        reservation_id=reservation_id, d02_issuer=d02_issuer, body_authority=body_authority,
        now_utc=now_utc, original_reads=tuple(GraphVersion(AtomKey.from_token(ref), revision)
            for ref, revision in sorted(versions.items())))
    return C04PrepareStageV3(resources.envelope, resource, resources.body, work, execution_id,
        owner_key.token, owner_revision, canonical_digest(owner_value),
        resources.body_profile_ref, resources.body_profile_revision,
        resources.body_state_ref, resources.body_state_revision, resources.read_versions)


@dataclass(frozen=True, slots=True)
class C04BodyResourcesV3:
    envelope: CommandEnvelope
    body: OriginalFixedBodyReservation
    body_profile_ref: str
    body_profile_revision: int
    body_state_ref: str
    body_state_revision: int
    read_versions: tuple[GraphVersion, ...]


def _prepare_c04_body_resources_v3(db, *, envelope, resource, body_policy_id, body_policy_version,
        reservation_id, d02_issuer, body_authority, now_utc, original_reads):
    """Common fixed Body/CPU materialization; only qualified Owner/Self wrappers call."""
    _transaction(db)
    namespace, identity = envelope.authority.namespace, envelope.identity
    body_policy = body_authority.policy(db, namespace, body_policy_id, body_policy_version)
    if body_policy.work_kind != C04_INTERNAL_CPU_WORK_KIND or body_policy.valid_until < envelope.deadline_utc:
        raise C04PrepareHold("installed C04 fixed Body policy differs or expires")
    profile_write = BodyDomain.profile_write(body_policy.profile)
    profile_revision, profile_value = _head(db, namespace, profile_write.key)
    if profile_value != profile_write.value:
        raise C04PrepareHold("current body profile differs from installed policy")
    state_key = AtomKey(Owner("persona", *namespace.as_tuple),
                        "d02.body_state.v1", body_policy.profile.profile_id)
    state_revision, state_value = _head(db, namespace, state_key)
    state = BodyState(**state_value)
    if state.version != state_revision:
        raise C04PrepareHold("current body state version differs")
    inventory = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND owner_kind='activity' AND type_name='d02.reservation.v1' "
        "ORDER BY token LIMIT 1025", namespace.as_tuple).fetchall()
    if len(inventory) > 1024:
        raise C04PrepareHold("current body reservation inventory exceeds bound")
    reservations = []
    versions = {version.key.token: version.revision for version in original_reads}
    for ref, revision, value, valid in inventory:
        key = AtomKey.from_token(ref)
        if valid != 1:
            raise C04PrepareHold("current body inventory contains invalid original")
        reservation = BodyReservation(**json.loads(value))
        if key != BodyDomain.reservation_write(namespace, key.owner.subject, reservation).key:
            raise C04PrepareHold("body reservation inventory identity differs")
        reservations.append(reservation)
        versions[ref] = revision
    if (len({item.reservation_id for item in reservations}) != len(reservations)
            or len({item.effect_id for item in reservations}) != len(reservations)):
        raise C04PrepareHold("body reservation inventory is ambiguous")
    d02_issuer.issue_quote(db, resource)
    post_quote = replace(envelope, version_guard=replace(envelope.version_guard,
        resource_lease_versions=(VersionedRef(resource.quote_id, resource.version),)))
    if d02_issuer.qualified_quote(post_quote, db, now_utc=now_utc) != resource:
        raise C04PrepareHold("C04 original signed CPU quote differs")
    body = body_authority.issue_fixed_quote_and_reservation(
        db, d02_issuer, post_quote, resource, body_policy_id, body_policy_version,
        state, tuple(reservations), reservation_id, identity.effect_id)
    if body.replayed:
        raise C04PrepareHold("body quote exists without complete C04 prepared original")
    for ref in (body.reservation_write.key.token, *resource.d02_settlement_refs):
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (ref,)).fetchone() is not None:
            raise C04PrepareHold("new C04 body graph key already exists")
        versions[ref] = 0
    versions.update({profile_write.key.token: profile_revision, state_key.token: state_revision})
    return C04BodyResourcesV3(post_quote, body, profile_write.key.token, profile_revision,
        state_key.token, state_revision, tuple(GraphVersion(AtomKey.from_token(ref), revision)
            for ref, revision in sorted(versions.items())))


def record_committed_current_c04_prepare_v3(
    db: sqlite3.Connection, stage: C04PrepareStageV3, *, graph_revision: int,
    asset: D04LoadedTanhReadoutAsset,
    projection_policy: D04IntervalProjectionPolicyV2, running_job=None,
) -> C04InternalWorkPreparedV1:
    """CAS receipt hook: reserve CPU and freeze both originals exactly once.

    W01 must invoke this before COMMIT, after committing only the staged body
    reservation. On any exception W01 rolls back graph, both quotes, CPU and
    both originals together. A replay returns the prior original without CAS,
    pricing, reservation, charging or execution.
    """
    _transaction(db)
    if type(stage) is not C04PrepareStageV3:
        raise C04PrepareHold("typed internal C04 prepare stage required")
    namespace = stage.work.namespace
    if stage.replayed:
        original = read_c04_internal_work_prepared_v1(db, namespace, stage.work.operation_id)
        if original is None or original != stage.prepared:
            raise C04PrepareHold("C04 prepared replay changed")
        return original
    if type(graph_revision) is not int or graph_revision < 1:
        raise C04PrepareHold("post-CAS graph revision required")
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                       namespace.as_tuple).fetchone()
    if epoch != (stage.work.graph_epoch + (2 if running_job is not None else 1),):
        raise C04PrepareHold("prepare must commit its exact actual reservation/job Graph CAS")
    reservation_revision, reservation_value = _head(db, namespace, stage.reservation_write.key)
    if reservation_revision != 1 or reservation_value != stage.reservation_write.value:
        raise C04PrepareHold("staged body reservation was not committed exactly")
    for version in stage.read_versions:
        if version.key == stage.reservation_write.key:
            continue
        row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (version.key.token,)).fetchone()
        if (row[0] if row else 0) != version.revision:
            raise C04PrepareHold("C04 preparation content or body ledger changed during CAS")
    work = replace(stage.work, graph_epoch=epoch[0])
    verify_current_association_input_heads_v3(db, work)
    from ..graph_coordinator import namespace_ref

    quote, body_quote = stage.resource_quote, stage.body.body_quote
    if len(body_quote.components) != 1 or body_quote.components[0].duration_rate != 0:
        raise C04PrepareHold("C04 needs one installed fixed body component")
    binding = InternalWorkBindingV1(
        namespace_ref(namespace), work.activity_id, work.operation_id,
        stage.execution_id, work.input_digest.removeprefix("sha256:"),
        quote.quote_id, quote.version, canonical_digest(quote),
        body_quote.quote_id, stage.body.body_quote_version, canonical_digest(body_quote),
        stage.reservation_write.key.token, body_quote.components[0].component_id,
        quote.parent_budget_lease_ref, stage.envelope.authority.activation_generation,
        ALGORITHM_ID_V3, quote.snapshot_ref,
        work.algorithm_build_digest.removeprefix("sha256:"))
    budget_operation = "c04-internal-budget:" + binding.binding_digest
    receipt = reserve_budget(db, binding.parent_budget_lease_ref,
        budget_operation, binding.binding_digest, quote.ceiling)
    reservation = db.execute(
        "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace.as_tuple, budget_operation)).fetchone()
    if (receipt.status != "reserved" or reservation is None
            or reservation[:2] != (binding.binding_digest, binding.parent_budget_lease_ref)):
        raise C04PrepareHold("C04 CPU reservation original differs")
    versions = {version.key.token: version.revision for version in stage.read_versions}
    versions[stage.reservation_write.key.token] = reservation_revision
    if running_job is not None:
        from .d11_types import job_graph_write
        actual_job = get_job(db, c04_prepare_job_id_v3(namespace, work.operation_id))
        job_write = job_graph_write(actual_job)
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (job_write.key.token,)).fetchone()
        if (actual_job != running_job or actual_job.phase != "running" or actual_job.fence != 1
                or actual_job.cancel_epoch or actual_job.lease_holder is None or actual_job.lease_expires_utc is None
                or row is None or row[0] != 1 or row[2] != 1 or json.loads(row[1]) != job_write.value):
            raise C04PrepareHold("C04 final freeze requires its actual same-transaction running job projection")
        versions[job_write.key.token] = 1
    prepared = C04InternalWorkPreparedV1(
        binding, stage.body_profile_ref, stage.body_profile_revision,
        stage.body_state_ref, stage.body_state_revision, reservation_revision,
        stage.owner_grant_ref, stage.owner_grant_revision, stage.owner_grant_digest,
        budget_operation, hashlib.sha256(reservation[2].encode()).hexdigest(),
        tuple(sorted(versions.items())), graph_revision,
        work.access_epoch, work.delete_epoch)
    record_c04_internal_work_prepared_v1(db, namespace, prepared)
    record_c04_frozen_association_original_v3(db, namespace, binding, work,
        asset=asset, policy=projection_policy)
    # A queued record schedules inspection of this exact binding. Execution
    # authority still belongs to Authority's one-time claim/CAS; recovering a
    # worker lease must never authorize a replacement execution identity.
    job = PersistentJob(
        c04_prepare_job_id_v3(namespace, work.operation_id),
        work.operation_id, work.activity_id, stage.envelope.identity.effect_id,
        *namespace.as_tuple, quote.snapshot_ref, "queued", C04_INTERNAL_CPU_WORK_KIND,
        {"schema": "c04.prepared-job-continuation.v3",
         "operation_id": work.operation_id, "execution_id": binding.execution_id,
         "binding_digest": binding.binding_digest,
         "input_digest": binding.input_digest,
         "prepared_digest": prepared.prepared_digest,
         "prepared_ref": "graph_c04_internal_work_prepared_v1/" + work.operation_id,
         "frozen_input_ref": "graph_c04_association_inputs_v3/" + work.operation_id,
         "algorithm_id": work.algorithm_id,
         "algorithm_build_digest": binding.algorithm_build_digest,
         "activation_generation": binding.activation_generation,
         "recovery_policy": "inspect_original_binding_before_execution"},
        None, datetime.fromtimestamp(stage.envelope.deadline_utc, timezone.utc)
            .isoformat().replace("+00:00", "Z"),
        binding.parent_budget_lease_ref, quote.resource_ref,
        {"algorithm": work.algorithm_id, "build": binding.algorithm_build_digest,
         "catalogue": stage.envelope.version_guard.catalogue_version,
         "operator": stage.envelope.version_guard.operator_version,
         "policy": stage.envelope.version_guard.policy_version},
        None, None, 0, 0, {}, None)
    if running_job is None:
        create_job(db, job, "c04-prepare-job:" + binding.binding_digest, canonical_digest(job))
    return prepared


__all__ = ["C04PrepareHold", "C04PrepareStageV3",
           "stage_current_c04_prepare_v3", "record_committed_current_c04_prepare_v3",
           "c04_prepare_job_id_v3"]


def create_running_c04_preparation_job_v3(db, stage, *, holder, now_utc):
    """Actual same-transaction job acquisition before the final input freeze.

    The stable continuation names the not-yet-frozen original by identity. It
    never predicts the future input digest or Graph epoch.
    """
    from .jobs import acquire_job
    if not db.in_transaction or type(stage) is not C04PrepareStageV3 or stage.replayed:
        raise C04PrepareHold('actual new C04 preparation transaction required')
    namespace, work, quote = stage.work.namespace, stage.work, stage.resource_quote
    if type(holder) is not str or not holder or now_utc >= stage.envelope.deadline_utc:
        raise C04PrepareHold('C04 actual worker/deadline unavailable')
    job = PersistentJob(c04_prepare_job_id_v3(namespace, work.operation_id), work.operation_id,
        work.activity_id, stage.envelope.identity.effect_id, *namespace.as_tuple, quote.snapshot_ref,
        'queued', C04_INTERNAL_CPU_WORK_KIND,
        {'schema':'c04.prepared-job-continuation.v4','operation_id':work.operation_id,
         'execution_id':stage.execution_id,'prepared_ref':'graph_c04_internal_work_prepared_v1/'+work.operation_id,
         'frozen_input_ref':'graph_c04_association_inputs_v3/'+work.operation_id,
         'algorithm_id':work.algorithm_id,'algorithm_build_digest':work.algorithm_build_digest.removeprefix('sha256:'),
         'activation_generation':stage.envelope.authority.activation_generation,
         'recovery_policy':'inspect_original_binding_before_execution'}, None,
        datetime.fromtimestamp(stage.envelope.deadline_utc,timezone.utc).isoformat().replace('+00:00','Z'),
        quote.parent_budget_lease_ref,quote.resource_ref,
        {'algorithm':work.algorithm_id,'build':work.algorithm_build_digest.removeprefix('sha256:'),
         'catalogue':stage.envelope.version_guard.catalogue_version,
         'operator':stage.envelope.version_guard.operator_version,'policy':stage.envelope.version_guard.policy_version},
        None,None,0,0,{},None)
    create_job(db,job,'c04-prepare-running:'+canonical_digest((namespace,work.operation_id))[:48],canonical_digest(job))
    return acquire_job(db,job.job_id,holder,
        now_utc=datetime.fromtimestamp(now_utc,timezone.utc).isoformat().replace('+00:00','Z'),
        lease_seconds=min(300, max(1, int(stage.envelope.deadline_utc-now_utc))))
