"""Core current-source reconstruction for the prospective V7 generation plan.

The functions read actual C02/D07/D03/Source originals inside the caller's
qualified Graph transaction. They issue no permit, CPU quote or model admission.
"""
from __future__ import annotations

from .current_authority_graph_read_v3 import (read_authority_current_point_v3 as _authority_point_v3,
    authority_current_json_v3 as _authority_json_v3,authority_current_json_matches_v3 as _authority_json_matches_v3,
    authority_current_versions_v3 as _authority_versions_v3,authority_reply_attention_versions_v3)
from dataclasses import dataclass
from contextlib import contextmanager
from contextvars import ContextVar
from threading import get_ident
from weakref import WeakKeyDictionary,WeakSet
import json
from ..contracts import StaleRead
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite, NamespaceEpoch, Owner
from ..runtime_contracts import NamespaceId, CommitReceipt, VersionedRef, canonical_digest
from .contract import AuthorityUnavailable as UnavailableGuard

@dataclass(frozen=True, slots=True)
class D13ProspectivePlanV1:
    plan: object
    plan_write: object
    read_versions: tuple
    question: object
    grant: object
    inputs: object
    route: object
    route_binding: object
    snapshot: object
    query: object
    preparation_evidence: object

def read_current_counter_attention_v1(
        db, namespace: NamespaceId, source_ref: str,
        now_utc: float, epoch: NamespaceEpoch):
    """Read the selected D07 ticket and complete D06 ancestry in one tx."""
    from ..domains.d06 import source_correction_head_key
    from ..domains.d07 import attention_ticket_key
    from ..domains.d07.qualified_attention_read import (
        read_qualified_focus_attention_ticket,
    )
    from ..memory_types import SourceRecord, access_key, source_key

    if not db.in_transaction:
        raise UnavailableGuard("qualified reply attention needs current graph tx")
    from .current_authority_graph_read_v3 import require_authority_current_reply_attention_v3
    actual=require_authority_current_reply_attention_v3(db,namespace,source_ref=source_ref,now_utc=now_utc,epoch=epoch)
    if actual is not None:return actual
    source_id = AtomKey.from_token(source_ref).owner.subject
    ingress = db.execute(
        "SELECT conversation_ref FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source_id,),
    ).fetchall()
    if len(ingress) != 1:
        raise UnavailableGuard("reply source has no unique original audience")
    focus_key = AtomKey(Owner("persona", *namespace.as_tuple),
                        "d07.focus.v1", namespace.persona_id)
    atoms = {}

    def load(key):
        if key not in atoms:
            row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (key.token,),
            ).fetchone()
            atoms[key] = (GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
                          if row else GraphAtom(key, 0, {}, False))
        return atoms[key]

    focus = load(focus_key)
    if not focus.valid:
        raise UnavailableGuard("current D07 focus is absent")
    try:
        ticket_key = AtomKey.from_token(focus.value["primary_ticket_ref"])
        if ticket_key != attention_ticket_key(namespace, ticket_key.name):
            raise ValueError("ticket key differs")
        ticket = load(ticket_key)
        pending = list(ticket.value["source_refs"])
        if not pending or len(pending) > 256:
            raise ValueError("ticket source roots invalid")
        seen = set()
        while pending:
            ref = pending.pop()
            if ref in seen:
                continue
            if len(seen) >= 256:
                raise ValueError("source closure exceeds bound")
            key = AtomKey.from_token(ref)
            if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
                raise ValueError("ticket source key differs")
            seen.add(ref)
            atom = load(key)
            load(access_key(*namespace.as_tuple, key.owner.subject))
            load(source_correction_head_key(namespace, key.owner.subject))
            record = SourceRecord.from_dict(atom.value)
            pending.extend(source_key(*namespace.as_tuple, parent).token
                           for parent in record.parent_source_ids)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise UnavailableGuard("qualified D07 source closure unavailable") from exc
    snapshot = GraphSnapshot(tuple(atoms.values()), (epoch,))
    qualified = read_qualified_focus_attention_ticket(
        snapshot, namespace, now=now_utc,
        audience=ingress[0][0], purpose="expression")
    if qualified is None:
        raise UnavailableGuard("qualified D07 attention is unavailable")
    return snapshot, qualified.attention


def read_current_counter_inputs_v1(
    db, d02_issuer, namespace: NamespaceId, c02_operation_id: str,
    source_ref: str, now_utc: float, epoch: NamespaceEpoch,
):
    """Read original C02 and current D06/D07 atoms in this graph tx."""
    from ..runtime.reply_model_job import (
        ReplyModelJobHold, read_current_reply_model_inputs_v1,
    )

    snapshot, attention = read_current_counter_attention_v1(
        db, namespace, source_ref, now_utc, epoch)
    c02_row = _authority_point_v3(db,table='graph_bundle_operations',columns=('digest', 'activity_id', 'effect_id', 'commit_seq', 'receipt_json'),key_columns=('bot', 'persona', 'operation_id'),key=tuple(namespace.as_tuple + (c02_operation_id,)),legacy_reader=lambda: db.execute(
        "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
        "FROM graph_bundle_operations WHERE bot=? AND persona=? "
        "AND operation_id=?",
        namespace.as_tuple + (c02_operation_id,),
    ).fetchone())
    if c02_row is None:
        raise ReplyModelJobHold("original C02 receipt is absent")
    c02_event = _authority_point_v3(db,table='graph_events',columns=('reads', 'revisions', 'epoch_revision'),key_columns=('bot', 'persona', 'session', 'event_id'),key=tuple(namespace.as_tuple + (c02_row[1], c02_operation_id)),legacy_reader=lambda: db.execute(
        "SELECT reads,revisions,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        namespace.as_tuple + (c02_row[1], c02_operation_id),
    ).fetchone())
    if c02_event is None:
        raise ReplyModelJobHold("original C02 graph event is absent")
    c02_detail = _authority_json_v3(c02_row[4])
    receipt = CommitReceipt(
        "committed", c02_operation_id, c02_row[0], c02_row[1],
        c02_row[2], c02_row[3],
        tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in _authority_json_v3(c02_event[0])),
        tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in _authority_json_v3(c02_event[1])),
        (NamespaceEpoch(*namespace.as_tuple, c02_event[2]),),
        tuple(c02_detail["ledger_refs"]),
        tuple(c02_detail["outbox_refs"]))
    return read_current_reply_model_inputs_v1(
        db, d02_issuer, namespace, receipt,
        source_ref, snapshot, attention)


def read_current_counter_scope_v1(
    db, d02_issuer, context, namespace: NamespaceId, c02_operation_id: str,
    source_ref: str, now_utc: float, epoch: NamespaceEpoch,
):
    """Bind one private C02 reply to current D06/D07/D03 scope in one tx."""
    from ..domains.d03.context import ContextProvider, RoleBindingRequest
    from ..runtime.dispatch_current_projection import (
        derive_current_domain_reads, read_current_dispatch_projection,
    )
    from ..runtime.reply_entity_route_v2 import (
        read_current_reply_entity_route_binding_v2,
    )
    from ..runtime_contracts import VersionedRef

    if not db.in_transaction or type(context) is not ContextProvider:
        raise ValueError('actual current Core read transaction and installed D03 resolver required')
    from ..runtime.reply_model_job import read_current_reply_route_manifest_v2
    inputs = read_current_counter_inputs_v1(db, d02_issuer, namespace, c02_operation_id, source_ref, now_utc, epoch)
    route = read_current_reply_route_manifest_v2(db, namespace, inputs, source_ref)
    from .current_authority_graph_read_v3 import authority_graph_projection_for_db_v3,AuthorityRouteMetadataInventoryV6
    actual_projection=authority_graph_projection_for_db_v3(db,namespace)
    if actual_projection is not None:
        from ..runtime_contracts import QueryEpoch
        full,query=actual_projection,QueryEpoch(namespace,'all',epoch.revision)
        if full.epochs!=(epoch,):raise StaleRead('Authority Core current graph epoch changed')
    else:
        rows = db.execute('SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? ORDER BY token', namespace.as_tuple).fetchall()
        atoms = []
        for token, revision, encoded, valid in rows:
            key = AtomKey.from_token(token)
            if NamespaceId.from_key(key) != namespace or revision < 1 or valid not in (0, 1):
                raise ValueError('current Core namespace Graph row differs')
            atoms.append(GraphAtom(key, revision, json.loads(encoded), bool(valid)))
        from ..runtime_contracts import QueryEpoch
        actual_epoch = db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?', namespace.as_tuple).fetchone()
        if actual_epoch != (epoch.revision,):
            raise ValueError('Core read transaction graph epoch differs')
        full, query = GraphSnapshot(tuple(atoms), (epoch,)), QueryEpoch(namespace, 'all', epoch.revision)
    if query.revision != epoch.revision:
        raise StaleRead("natural generation graph epoch changed")
    # SQL's absence is a real D06 correction-head rev0 proof in this tx.
    if actual_projection is not None:
        if inputs.graph_snapshot is not full:raise StaleRead('Authority current Source projection changed')
        snapshot=full
    else:
        atoms = {atom.key: atom for atom in full.atoms}
        for atom in inputs.graph_snapshot.atoms:
            if atom.key in atoms and atoms[atom.key] != atom:
                raise StaleRead("natural generation source closure changed")
            atoms[atom.key] = atom
        snapshot = GraphSnapshot(tuple(atoms.values()), full.epochs)
    binding = read_current_reply_entity_route_binding_v2(
        db, namespace, route, query, now_utc=now_utc,
        **({}if actual_projection is None else {"prepared_inventory":AuthorityRouteMetadataInventoryV6(actual_projection.work)}))
    projection = read_current_dispatch_projection(db, namespace, snapshot, query)
    request = RoleBindingRequest(
        f"persona:{namespace.persona_id}", binding.target_entity_ref,
        None, route.scene_ref, "expression", "reply", now_utc, True,
    )
    role_read, boundary_read = derive_current_domain_reads(
        db, projection, request, context)
    if (role_read.status != "complete" or len(role_read.matched_bindings) != 1
            or projection.coverage != "full"
            or boundary_read.coverage != "full"):
        raise UnavailableGuard("current private scene role is not unique; HOLD")
    matched = role_read.matched_bindings[0]
    selected = tuple(atom for atom in projection.role_bindings
                     if atom.key.name == matched
                     and atom.value.get("scene_ref") == route.scene_ref)
    if len(selected) != 1:
        raise UnavailableGuard("current scene role proof is absent; HOLD")
    scene = VersionedRef(selected[0].key.token, selected[0].revision)
    audience = VersionedRef(binding.binding_version.key.token,
                            binding.binding_version.revision)
    return (inputs, route, binding, snapshot, query, role_read,
            boundary_read, scene, audience)


def _counter_source_expression_kwargs_v3(db,namespace):
    from .current_authority_graph_read_v3 import authority_source_expression_kwargs_v3
    value=authority_source_expression_kwargs_v3(db,namespace)
    return{}if value is None else value


def derive_current_counter_plan_v1(db, *, d02_issuer, d11_issuer, context, namespace, c02_operation_id, source_ref, installed_bundle, now_utc, epoch, original_deadline):
    """Derive the first private source plan from current graph and budget."""
    from ..domains.d06.qualified_expression import QualifiedExpressionRequest, SourceTextSpan, prepare_qualified_expression_unit
    from ..domains.d08.natural_plan import NaturalPlanPreparationEvidenceV2, natural_final_effect_id_v2, natural_plan_id_v2, natural_plan_key_v2, natural_route_semantic_digest_v2, prepare_coordinator_natural_plan_write_v2
    from ..domains.d09.natural_reply import NaturalExpressionPlanV2, QualifiedExpressionUnitV2
    from ..domains.d09 import ClaimKind
    from ..host.post_c02_reply_driver import post_c02_reply_operation_id
    from ..model_broker.context_reply import ContextReplyPartV1
    from ..runtime_contracts import VersionedRef
    inputs, route, binding, snapshot, query, role_read, boundary_read, scene, audience = read_current_counter_scope_v1(db, d02_issuer, context, namespace, c02_operation_id, source_ref, now_utc, epoch)
    from ..runtime.natural_producer_qualification_v1 import natural_basis_snapshot_v1, read_live_producer_candidates_v1, fresh_c04_report_candidate_v1, producer_expression_unit_v1, source_expression_unit_v1, CANDIDATE_TYPES
    snapshot = natural_basis_snapshot_v1(db, namespace=namespace, snapshot=snapshot, units=())
    workflow = installed_bundle.model_workflows.natural_generation
    review = installed_bundle.model_workflows.natural_review
    if workflow is None or review is None:
        raise UnavailableGuard('both natural paid workflows must be installed; HOLD')
    from ..runtime.natural_reply_budget_v3 import resolve_natural_reply_budget_for_new_admission_v3
    _budget, grant = resolve_natural_reply_budget_for_new_admission_v3(db, namespace=namespace, c02_operation_id=c02_operation_id, source_ref=source_ref, issuer=d11_issuer, installed_bundle=installed_bundle, now_utc=now_utc)
    if not {'natural_generation', 'natural_review'}.issubset(grant.allowed_work_kinds) or route.conversation_ref not in workflow.audiences or route.conversation_ref not in review.audiences:
        raise UnavailableGuard('natural budget or audience differs; HOLD')
    expiry = min((value for value in (inputs.attention.ticket.valid_until, binding.valid_until_utc, role_read.valid_until, grant.valid_until_utc, original_deadline if original_deadline is not None else now_utc + 300.0) if value is not None))
    if expiry <= now_utc + (workflow.timeout_seconds + 1):
        raise UnavailableGuard('natural scope expires before paid generation')
    source = inputs.source.source
    barrier = db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?', namespace.as_tuple).fetchone()
    if barrier is None:
        raise UnavailableGuard('natural source barrier absent')
    candidate = prepare_qualified_expression_unit(snapshot, namespace=namespace, request=QualifiedExpressionRequest(source_ref, 'attributed_report', SourceTextSpan(0, len(source.text))), audiences=(route.conversation_ref,), access_epoch=barrier[0], deletion_epoch=barrier[1], valid_until=expiry, **_counter_source_expression_kwargs_v3(db,namespace))
    source_versions = {row.key.token: row.revision for row in candidate.read_versions}
    unit = QualifiedExpressionUnitV2('basis:c02-report', ClaimKind.REPORTED_CLAIM, candidate.source_excerpt, None, tuple((VersionedRef(ref, source_versions[ref]) for ref in candidate.lineage_source_refs)), tuple((VersionedRef(row.key.token, row.revision) for row in candidate.read_versions if row.key.type_name == 'memory.access')), tuple((VersionedRef(row.key.token, row.revision) for row in candidate.read_versions if row.key.type_name == 'd06.source_correction_head.v1')), route.conversation_ref, 'expression', candidate.valid_until, speaker_id=candidate.speaker_id, content_reality='external_report', qualification_digest=candidate.qualification_digest, occurred_at=candidate.occurred_at, learned_at=candidate.learned_at, source_kind=candidate.source_kind, assertion_status=candidate.assertion_status, d06_claim_kind=candidate.claim_kind, attribution_required=candidate.attribution_required, polarity_status=candidate.polarity_status, source_excerpt=candidate.source_excerpt, evidence_span=(candidate.evidence_span.start, candidate.evidence_span.end))
    producers = read_live_producer_candidates_v1(db, snapshot=snapshot, audience_id=route.conversation_ref, expires_at_utc=expiry, now_utc=now_utc)
    bounded_expiry = min((expiry, *(value.context.expires_at_utc for value in producers)))
    if bounded_expiry != expiry:
        expiry = bounded_expiry
        if expiry <= now_utc + workflow.timeout_seconds + 1:
            raise UnavailableGuard('producer original expires before paid natural generation')
        candidate = prepare_qualified_expression_unit(snapshot, namespace=namespace, request=QualifiedExpressionRequest(source_ref, 'attributed_report', SourceTextSpan(0, len(source.text))), audiences=(route.conversation_ref,), access_epoch=barrier[0], deletion_epoch=barrier[1], valid_until=expiry, **_counter_source_expression_kwargs_v3(db,namespace))
        unit = source_expression_unit_v1(candidate, basis_id='basis:c02-report', audience_id=route.conversation_ref)
        producers = read_live_producer_candidates_v1(db, snapshot=snapshot, audience_id=route.conversation_ref, expires_at_utc=expiry, now_utc=now_utc)
    reports = tuple((value for value in fresh_c04_report_candidate_v1(db, snapshot=snapshot, audience_id=route.conversation_ref, expires_at_utc=expiry, access_epoch=barrier[0], deletion_epoch=barrier[1]) if value.qualification_digest != candidate.qualification_digest))
    candidates = (candidate, *reports, *producers)
    units = (unit, *(source_expression_unit_v1(value, basis_id='basis:c04-report', audience_id=route.conversation_ref) for value in reports), *(producer_expression_unit_v1(value) for value in producers))
    plan_id = natural_plan_id_v2(namespace, c02_operation_id, source_ref)
    plan_key = natural_plan_key_v2(namespace, inputs.c02_receipt.activity_id, plan_id)
    plan = NaturalExpressionPlanV2(namespace, VersionedRef(plan_key.token, 1), scene, audience, ('reply',), ('paraphrase',), (), units, expiry, inputs.c02_receipt.activity_id, post_c02_reply_operation_id(c02_operation_id, source_ref), natural_final_effect_id_v2(namespace, c02_operation_id, source_ref), route.scene_ref, route.conversation_ref)
    reads = tuple(dict.fromkeys((*authority_reply_attention_versions_v3(inputs.graph_snapshot), *role_read.read_versions, binding.anchor_version, binding.binding_version, binding.arrival_event_version, binding.binding_evidence_event_version, *binding.binding_scan_versions)))
    if len(candidates) > 1 or any((type(value) in CANDIDATE_TYPES for value in candidates)):
        basis_reads = tuple((row for value in candidates for row in (value.context.read_versions if type(value) in CANDIDATE_TYPES else value.read_versions)))
        reads = tuple(dict.fromkeys((*reads, *basis_reads)))
    semantic = natural_route_semantic_digest_v2(binding)
    evidence = NaturalPlanPreparationEvidenceV2(c02_operation_id, VersionedRef(source_ref, inputs.source.source_revision), VersionedRef(inputs.attention.focus_version.key.token, inputs.attention.focus_version.revision), VersionedRef(inputs.attention.ticket_version.key.token, inputs.attention.ticket_version.revision), canonical_digest({'schema': 'sylanne.natural-preparation-evidence.v2', 'c02_receipt': inputs.c02_receipt.operation_digest, 'route': semantic, 'read_versions': sorted(((row.key.token, row.revision) for row in reads)), 'qualification': candidates[0].qualification_digest if len(candidates) == 1 else canonical_digest(tuple((value.qualification_digest for value in candidates)))}), semantic, grant.lease_id, grant.version, canonical_digest(grant), tuple(sorted(workflow.quote_ceiling.items())), tuple(sorted(review.quote_ceiling.items())))
    plan_write, plan_reads = prepare_coordinator_natural_plan_write_v2(plan=plan, evidence=evidence, snapshot=snapshot, d06_candidates=candidates, access_epoch=barrier[0], deletion_epoch=barrier[1], now_utc=now_utc)
    question = ContextReplyPartV1('question', VersionedRef(source_ref, inputs.source.source_revision),
        audience, expiry, source.text)
    return D13ProspectivePlanV1(plan, plan_write, tuple(dict.fromkeys((*reads, *plan_reads))),
        question, grant, inputs, route, binding, snapshot, query, evidence)


@dataclass(frozen=True, slots=True)
class D13CurrentCounterSourceV1:
    prospective: D13ProspectivePlanV1
    pair: object
    source_location: object
    current_self: object
    current_owner: object
    owner_grant_digest: str
    source_scope_digest: str
    frozen_at_utc: float
    expires_at_utc: float


class InstalledD13CounterSourceV1:
    """Independent installed Source/Self/Owner reader; no Host payload input."""
    def __init__(self, *, foreground_observer, context_provider, policy, paid_verifier_factory):
        from .current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
        from ..domains.d03.context import ContextProvider
        from .d13_core_counter_contract_v1 import InstalledD13WirePolicyV7
        from .d13_installed_counter_factory_v1 import InstalledD13CounterPaidVerifierFactoryV1
        if (type(foreground_observer) is not InstalledCurrentForegroundActivityV1
                or type(context_provider) is not ContextProvider
                or type(policy) is not InstalledD13WirePolicyV7
                or type(paid_verifier_factory) is not InstalledD13CounterPaidVerifierFactoryV1
                or paid_verifier_factory.resource_issuer is not foreground_observer.issuer.resource_issuer
                or paid_verifier_factory.budget_issuer is not foreground_observer.issuer
                or foreground_observer.installed_bundle is None
                or foreground_observer.self_identity._source_location is None
                or foreground_observer.self_identity._owner_storage is None
                or policy.installation.installation_id != foreground_observer.self_identity._installation_id):
            raise UnavailableGuard('counter needs actual installed Self/Owner/location/bundle composition')
        self.observer = foreground_observer
        self.self_identity = foreground_observer.self_identity
        self.context = context_provider
        self.policy = policy
        self.paid_verifier_factory = paid_verifier_factory
        from .current_authority_graph_read_v3 import install_authority_graph_read_controller_v3
        install_authority_graph_read_controller_v3(self,service=self,source_location=self.self_identity._source_location)

    def _prepare_current_counter_work_v3(self,work,meter):
        from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
        from ..graph_types import owner_grant_key,validate_owner_grant_v1
        from .current_authority_graph_read_v3 import _DEADLINES
        work.require_current(meter=meter)
        self.self_identity._source_location.require_graph_snapshot_v1(work.db,work.counter_location,graph_db_path=self.self_identity._graph._path)
        if work.graph_stamp[0]!=work.counter_current_self.graph_epoch:
            raise UnavailableGuard('counter current Self/Graph query changed')
        prospective=derive_current_counter_plan_v1(work.db,d02_issuer=self.observer.issuer.resource_issuer,
            d11_issuer=self.observer.issuer,context=self.context,namespace=work.namespace,
            c02_operation_id=work.parent_original_id,source_ref=work.source_selection.root,
            installed_bundle=self.observer.installed_bundle,now_utc=work.now_utc,
            epoch=NamespaceEpoch(*work.namespace.as_tuple,work.graph_stamp[0]),original_deadline=work.deadline_utc)
        if prospective.plan.plan_ref!=work.request.plan_ref:
            raise UnavailableGuard('counter selector differs from actual prospective D08 plan')
        work.counter_prospective=prospective
        scope=PreparedAuthorityCounterMaterialScopeV7(_COUNTER_CALL_ISSUER_V3,self,work,prospective)
        work.counter_material_scope=scope
        if scope.deadline_utc<work.deadline_utc:
            work.deadline_utc=scope.deadline_utc;work.deadline_original=scope
            if not work.borrowed_counter_operation:work.operation.deadline_utc=scope.deadline_utc
            _DEADLINES[work]=(work.operation,work.deadline_utc,scope)
        grant=work.projection.get(owner_grant_key(*work.namespace.as_tuple))
        if not grant.valid:raise UnavailableGuard('counter current Owner Graph grant missing')
        validate_owner_grant_v1(grant.value);work.counter_owner_grant=grant.value
        recipe={'schema':'sylanne3.d13.counter-current-source.v1','namespace':work.namespace,
            'source':prospective.preparation_evidence.source_ref,'plan':prospective.plan,'plan_write':prospective.plan_write,
            'reads':prospective.read_versions,'owner_guard':work.counter_owner.guard,'owner_grant':grant.value,
            'storage':(work.counter_location.storage_generation,work.counter_location.manifest_digest,work.counter_location.pointer_version)}
        work.counter_source_digest_reader=_CanonicalComparisonV3(recipe,operation=work.operation)

    def read(self, selector, *, credential, subject, permit, frozen_at_utc=None,
             expires_at_utc=None):
        from contextlib import closing, nullcontext
        from pathlib import Path
        import sqlite3
        from .d13_core_counter_contract_v1 import D13CurrentFramePrepareSelectorV7
        from .v2_self_identity_contract import SelfIdentityCurrentRequestV1
        from ..graph_types import owner_grant_key, validate_owner_grant_v1
        from ..runtime.natural_producer_qualification_v1 import (
            fresh_natural_producer_selectors_v1, _bind_natural_frame,
            observe_authority_natural_producers_v1)
        from ..runtime.installed_d13_natural_frame_v7 import prepare_current_natural_history_pair_v7
        service = self.self_identity
        if (type(selector) is not D13CurrentFramePrepareSelectorV7
                or selector.namespace != service._namespace_id
                or selector.install_id != service._installation_id
                or selector.authority_namespace != service._fences.namespace
                or subject != service._read_subject or permit.operation != 'read'):
            raise UnavailableGuard('counter source crossed actual installed read scope')
        service._fences.validate_fence(credential=credential, subject=subject, permit=permit)
        stop = self.observer._owner_stop_reply_service_v1
        if stop is None:
            raise UnavailableGuard('counter current reply retirement barrier unavailable')
        stop.require_reply_cycle_not_retired_v1(c02_operation_id=selector.c02_operation_id)
        current_self = service.current(credential=credential, subject=subject,
            request=SelfIdentityCurrentRequestV1(permit.authority_id, selector.authority_namespace,
                selector.namespace, selector.install_id, service._manifest_digest, permit.operation_id, permit))
        if current_self is None:
            raise UnavailableGuard('counter independently registered Self is absent')
        location = service._source_location.observe_business_for_fence_v1(
            credential=credential, subject=subject, permit=permit)
        owner, owner_permit = service._owner_storage.get_current_background_owner_authority_for_fence_v1(
            credential=credential, subject=subject, permit=permit)
        if owner_permit != permit or owner.guard.authorization_head != current_self.owner_authorization_head:
            raise UnavailableGuard('counter upstream current Owner changed')
        clock = self.observer.clock()
        now = clock.utc_seconds + clock.utc_error_seconds
        frozen = now if frozen_at_utc is None else frozen_at_utc
        deadline = now + 300.0 if expires_at_utc is None else expires_at_utc
        if not frozen <= now < deadline:
            raise UnavailableGuard('counter absolute original lifetime expired')
        namespace = selector.namespace
        path = Path(location.graph_db_path)
        if service._core._runtime_storage_v3 is not None:
            from .current_authority_graph_read_v3 import begin_authority_graph_read_work_v3,read_authority_graph_current_v3
            call=_COUNTER_CALL_BINDING_V3.get()
            if call is None:raise UnavailableGuard('segmented counter Source requires its actual Core context-manager lifetime')
            call.require_current_v3(self,selector,credential,subject,permit)
            if call.work is not None:raise UnavailableGuard('counter Source call already owns its original Work')
            work=begin_authority_graph_read_work_v3(self,credential=credential,subject=subject,permit=permit,
                namespace=namespace,request=selector,parent_original_id=selector.c02_operation_id,now_utc=now,deadline_utc=deadline)
            call.work=work;work.counter_call=call
            work.counter_current_self,work.counter_owner,work.counter_location=current_self,owner,location
            work.counter_frozen_at_utc=frozen
            result=read_authority_graph_current_v3(work,lambda db:work.counter_result)
            service._fences.validate_fence(credential=credential,subject=subject,permit=permit)
            stop.require_reply_cycle_not_retired_v1(c02_operation_id=selector.c02_operation_id)
            return result
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            try:
                service._source_location.require_graph_snapshot_v1(db, location, graph_db_path=path)
                selectors = fresh_natural_producer_selectors_v1(db, namespace=namespace,
                    parent_original_id=selector.c02_operation_id, issuer=self.observer.issuer)
            finally:
                db.rollback()
            observation = (nullcontext(None) if selectors.empty else observe_authority_natural_producers_v1(
                fences=service._fences, credential=credential, subject=subject, permit=permit,
                namespace=namespace, c02_operation_id=selector.c02_operation_id, graph_db=db,
                c04_ref=selectors.c04_ref, draft_result_ref=selectors.draft_result_ref))
            with observation as observed, _bind_natural_frame(db, namespace,
                    selector.c02_operation_id, selectors, observed, None):
                db.execute('BEGIN')
                try:
                    service._source_location.require_graph_snapshot_v1(db, location, graph_db_path=path)
                    epoch = db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?', namespace.as_tuple).fetchone()
                    if epoch != (current_self.graph_epoch,):
                        raise UnavailableGuard('counter current Self/Graph query changed')
                    sources = db.execute('SELECT source_ref FROM graph_d07_attention_issuance_v1 WHERE bot=? AND persona=? AND c02_operation_id=?',
                        (*namespace.as_tuple, selector.c02_operation_id)).fetchall()
                    if len(sources) != 1:
                        raise UnavailableGuard('counter original C02 has no unique D07 Source')
                    source_ref = sources[0][0]
                    prospective = derive_current_counter_plan_v1(db,
                        d02_issuer=self.observer.issuer.resource_issuer, d11_issuer=self.observer.issuer,
                        context=self.context, namespace=namespace, c02_operation_id=selector.c02_operation_id,
                        source_ref=source_ref, installed_bundle=self.observer.installed_bundle,
                        now_utc=now, epoch=NamespaceEpoch(*namespace.as_tuple, epoch[0]), original_deadline=deadline)
                    if prospective.plan.plan_ref != selector.plan_ref:
                        raise UnavailableGuard('counter selector differs from actual prospective D08 plan')
                    paid_verifier = self.paid_verifier_factory.for_current_read(db, namespace=namespace,
                        scene_ref=prospective.plan.scene_id, conversation_ref=prospective.plan.audience_id,
                        now_utc=now, activation_generation=current_self.activation_generation, max_slots=self.policy.max_slots)
                    pair = prepare_current_natural_history_pair_v7(db, namespace=namespace,
                        plan=prospective.plan, question=prospective.question, installation=self.policy.installation,
                        now_utc=now, frozen_at_utc=frozen, expires_at_utc=prospective.plan.valid_until_utc,
                        activation_generation=current_self.activation_generation, paid_verifier=paid_verifier,
                        policy_digest=self.policy.policy_digest, max_slots=self.policy.max_slots)
                    grant_row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',
                        (owner_grant_key(*namespace.as_tuple).token,)).fetchone()
                    if grant_row is None or grant_row[2] != 1:
                        raise UnavailableGuard('counter current Owner Graph grant missing')
                    grant = json.loads(grant_row[1]); validate_owner_grant_v1(grant)
                    source_digest = canonical_digest({'schema':'sylanne3.d13.counter-current-source.v1',
                        'namespace':namespace, 'source':prospective.preparation_evidence.source_ref,
                        'plan':prospective.plan, 'plan_write':prospective.plan_write,
                        'reads':prospective.read_versions,
                        'owner_guard':owner.guard, 'owner_grant':grant,
                        'storage':(location.storage_generation,location.manifest_digest,location.pointer_version)})
                    result = D13CurrentCounterSourceV1(prospective, pair, location, current_self,
                        owner, canonical_digest(grant), source_digest, frozen, pair.raw.input.expires_at_utc)
                finally:
                    db.rollback()
        service._fences.validate_fence(credential=credential, subject=subject, permit=permit)
        stop.require_reply_cycle_not_retired_v1(c02_operation_id=selector.c02_operation_id)
        return result


_COUNTER_CALL_ISSUER_V3=object()
_COUNTER_CALLS_V3=WeakSet()
_COUNTER_CALL_BINDING_V3=ContextVar('sylanne_authority_counter_read_call_v3',default=None)
_COUNTER_MATERIAL_SCOPES_V7=WeakKeyDictionary()


class _CounterSourceCallV3:
    def __init__(self,issuer,service,*,selector,credential,subject,permit,draft):
        from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
        if (issuer is not _COUNTER_CALL_ISSUER_V3 or type(service)is not InstalledD13CoreCounterServiceV1
                or type(service.source)is not InstalledD13CounterSourceV1 or service.fences is not service.source.self_identity._fences):
            raise UnavailableGuard('actual installed Core counter call lifetime required')
        service.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        outer=require_counter_call_resource_scope_v3(service,selector.counter_operation_id)
        original=service._original(selector.counter_operation_id,'draft')
        if(original is None)!=(draft is None)or(original is not None and original!=draft):
            raise UnavailableGuard('counter original draft cannot be omitted or replaced at current-source entry')
        self.service,self.source,self.selector,self.credential,self.subject,self.permit,self.draft=(
            service,service.source,selector,credential,subject,permit,draft)
        self.thread=get_ident();self.work=None;self.closed=False;self.resource_scope=outer
        outer.bind_source_call_v3(self,selector,draft)
        _COUNTER_CALLS_V3.add(self)
    def require_current_v3(self,source,selector,credential,subject,permit):
        if (self not in _COUNTER_CALLS_V3 or self.closed or self.thread!=get_ident()
                or self.source is not source or self.selector is not selector or self.credential is not credential
                or self.subject!=subject or self.permit is not permit or _COUNTER_CALL_BINDING_V3.get()is not self
                or self.resource_scope.source_call is not self):
            raise UnavailableGuard('counter Source moved outside its actual Core call/context lifetime')
        self.resource_scope.require_current_v3();return self
    def close_v3(self):
        if self.closed:return
        self.closed=True;_COUNTER_CALLS_V3.discard(self)
        if self.work is not None:
            from .current_authority_graph_read_v3 import finish_authority_graph_read_work_v3
            finish_authority_graph_read_work_v3(self.work)
        self.work=None
        self.resource_scope.clear_source_call_v3(self)


@contextmanager
def retain_authority_counter_source_call_v3(service,*,selector,credential,subject,permit,draft):
    call=_CounterSourceCallV3(_COUNTER_CALL_ISSUER_V3,service,selector=selector,credential=credential,
        subject=subject,permit=permit,draft=draft)
    if _COUNTER_CALL_BINDING_V3.get()is not None:raise UnavailableGuard('counter Source call lifetime is already bound')
    token=_COUNTER_CALL_BINDING_V3.set(call)
    try:yield call
    finally:
        _COUNTER_CALL_BINDING_V3.reset(token);call.close_v3()


class PreparedAuthorityCounterMaterialScopeV7:
    """Read-only input identity after the existing prospective-plan gates."""
    def __init__(self,issuer,source,work,prospective):
        from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
        if(issuer is not _COUNTER_CALL_ISSUER_V3 or type(work)is not AuthorityGraphReadWorkV3
                or work.controller.kind!='counter'or work.controller.service is not source
                or type(prospective)is not D13ProspectivePlanV1 or work.counter_prospective is not prospective
                or _COUNTER_CALL_BINDING_V3.get()is not work.counter_call):
            raise UnavailableGuard('actual Counter Work/prospective-plan material issuer required')
        work._actual()
        if(prospective.plan.plan_ref!=work.request.plan_ref or prospective.plan.namespace!=work.namespace
                or prospective.question.ref.ref!=work.source_selection.root
                or not work.counter_frozen_at_utc<=work.now_utc<prospective.plan.valid_until_utc
                or prospective.plan.valid_until_utc>work.deadline_utc):
            raise UnavailableGuard('Counter material differs from original Source/selector/time bounds')
        self.work,self.source,self.prospective=work,source,prospective
        self.plan,self.question,self.installation=prospective.plan,prospective.question,source.policy.installation
        self.policy,self.policy_digest,self.max_slots=source.policy,source.policy.policy_digest,source.policy.max_slots
        self.now_utc,self.frozen_at_utc,self.deadline_utc=work.now_utc,work.counter_frozen_at_utc,prospective.plan.valid_until_utc
        self.activation_generation=work.counter_current_self.activation_generation
        self.actual_source_ref=work.source_selection.root
        _COUNTER_MATERIAL_SCOPES_V7[self]=(work,source,prospective,self.plan,self.question,self.installation,self.policy,
            self.now_utc,self.frozen_at_utc,self.deadline_utc,self.activation_generation,self.actual_source_ref,
            work.counter_call,work.operation,work.scope,work.selection_digest)
    def require_current_v7(self,work):
        if(_COUNTER_MATERIAL_SCOPES_V7.get(self)!=(work,self.source,self.prospective,self.plan,self.question,
                self.installation,self.policy,self.now_utc,self.frozen_at_utc,self.deadline_utc,
                self.activation_generation,self.actual_source_ref,work.counter_call,work.operation,work.scope,work.selection_digest)
                or self.work is not work or work.counter_material_scope is not self):
            raise UnavailableGuard('Counter material scope changed its actual input/Work/selection')
        work.counter_call.require_current_v3(self.source,work.request,work.credential,work.subject,work.permit)
        work._actual()
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        with runtime_storage_quantum_v3(work.db)as meter:work.require_current(meter=meter)
        return self



def require_current_authority_counter_call_work_v3(service,current):
    from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    call=_COUNTER_CALL_BINDING_V3.get()
    if call is None or call.work is None:return None
    if type(service)is not InstalledD13CoreCounterServiceV1 or call.service is not service:
        raise UnavailableGuard('Counter current material consumer is not its actual installed service')
    call.require_current_v3(call.source,call.selector,call.credential,call.subject,call.permit)
    work=call.work
    if type(work)is not AuthorityGraphReadWorkV3 or work.counter_result is not current or not work.complete:
        raise UnavailableGuard("Counter current material is not this call's actual completed Work")
    return work._actual()



_COUNTER_RESOURCE_SCOPES_V3=WeakSet()
_COUNTER_RESOURCE_BOUND_V3=ContextVar('sylanne_counter_call_resource_v3',default=None)
_COUNTER_RESOURCE_CHILDREN_V3=WeakKeyDictionary()

class _CounterCallResourceScopeV3:
    """The actual two installed Counter RPCs own one Core/Graph resource operation."""
    def __init__(self,issuer,service,selector,credential,subject):
        from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
        from .d13_core_counter_contract_v1 import D13CurrentFramePrepareSelectorV7,D13CurrentWireCountSelectorV1
        from ..runtime_storage_v3 import runtime_storage_v3,begin_runtime_storage_operation_v3
        if (issuer is not _COUNTER_CALL_ISSUER_V3 or type(service)is not InstalledD13CoreCounterServiceV1
                or type(selector)not in(D13CurrentFramePrepareSelectorV7,D13CurrentWireCountSelectorV1)
                or subject!=service.source.self_identity._read_subject or not service._lock._is_owned()
                or selector.install_id!=service.policy.installation.installation_id
                or selector.authority_namespace!=service.bridge.namespace
                or type(selector)is D13CurrentFramePrepareSelectorV7 and selector.namespace!=service.namespace):
            raise UnavailableGuard('actual installed Counter call/locked selector/subject required')
        service.core._require(credential,'read',service.bridge.namespace)
        self.service,self.selector,self.credential,self.subject=service,selector,credential,subject
        self.core,self.db,self.handle=service.core,service.core._db,runtime_storage_v3(service.core._db)
        self.thread=get_ident();self.active=True;self.source_call=self.child=None
        self.readers=[];self.originals={};self.failure=None
        self.lease=begin_runtime_storage_operation_v3(self.db,selector.counter_operation_id,None)
        _COUNTER_RESOURCE_SCOPES_V3.add(self)
    def require_current_v3(self):
        from ..runtime_storage_v3 import runtime_storage_v3,_OPERATION
        if (self not in _COUNTER_RESOURCE_SCOPES_V3 or not self.active or self.thread!=get_ident()
                or _COUNTER_RESOURCE_BOUND_V3.get()is not self or not self.service._lock._is_owned()
                or self.service.core is not self.core or self.core._db is not self.db
                or runtime_storage_v3(self.db)is not self.handle):
            raise UnavailableGuard('Counter call resource ownership/installed Core changed')
        if self.handle is not None and (self.lease is None or self.lease.closed or _OPERATION.get()is not self.lease
                or self.lease.handle is not self.handle or self.lease.pool is not self.handle.pool
                or self.lease.selection_digest!=self.handle.selection_digest
                or self.lease.operation_id!=self.selector.counter_operation_id or self.lease.deadline_utc is not None):
            raise UnavailableGuard('Counter call lost its single actual bound resource operation')
        return self
    def record_original_v3(self,reader,value):
        from ..runtime_storage_v3 import _CorePayloadReadV3
        self.require_current_v3()
        if (type(reader)is not _CorePayloadReadV3 or reader.db is not self.db
                or reader.table!='authority_d13_counter_originals_v1' or reader.operation is not self.lease
                or not reader.complete or reader.key[:2]!=(self.service.bridge.namespace,self.selector.counter_operation_id)):
            raise UnavailableGuard('Counter original registration requires its actual same-operation Core EOF')
        proof=reader.require_v3(self.db,reader.table,reader.key)
        if proof is None:raise UnavailableGuard('Counter original registration has no complete physical payload')
        if not proof.matches_v3(value):
            raise UnavailableGuard('Counter original decoded value differs from actual Core EOF')
        if reader not in self.readers:self.readers.append(reader)
        self.originals[reader.key[2]]=(reader,value)
    def bind_source_call_v3(self,call,selector,draft):
        from .d13_core_counter_contract_v1 import D13CurrentFramePrepareSelectorV7,D13CurrentWireCountSelectorV1,d13_core_counter_from_wire_v1
        self.require_current_v3()
        if self.source_call is not None or self.child is not None or type(selector)is not D13CurrentFramePrepareSelectorV7:
            raise UnavailableGuard('Counter call already has an active Source child')
        if type(self.selector)is D13CurrentFramePrepareSelectorV7:
            if selector is not self.selector:raise UnavailableGuard('Counter prepare Source changed its actual outer selector')
        elif type(self.selector)is D13CurrentWireCountSelectorV1:
            item=self.originals.get('draft')
            if self.handle is not None and (item is None or item[1]!=draft):
                raise UnavailableGuard('Counter count Source lacks its actual read Core draft')
            if draft is None or selector!=d13_core_counter_from_wire_v1(draft['selector'],D13CurrentFramePrepareSelectorV7):
                raise UnavailableGuard('Counter count Source is not its actual original prepare selector')
        if selector.counter_operation_id!=self.selector.counter_operation_id:
            raise UnavailableGuard('Counter Source changed actual outer operation')
        self.source_call=call
    def clear_source_call_v3(self,call):
        if self.source_call is call:self.source_call=None
    def close_v3(self):
        if not self.active:return
        try:
            if self.source_call is not None:self.source_call.close_v3()
            for reader in self.readers:reader.release_payload_v3()
            self.readers.clear();self.originals.clear()
        finally:
            self.active=False;_COUNTER_RESOURCE_SCOPES_V3.discard(self)
            from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
            finish_runtime_storage_operation_v3(self.lease)


@contextmanager
def retain_counter_call_resource_scope_v3(service,*,selector,read_credential,subject):
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    if _COUNTER_RESOURCE_BOUND_V3.get()is not None:raise UnavailableGuard('Counter call resource is already bound')
    scope=_CounterCallResourceScopeV3(_COUNTER_CALL_ISSUER_V3,service,selector,read_credential,subject)
    token=_COUNTER_RESOURCE_BOUND_V3.set(scope)
    try:
        with bind_runtime_storage_operation_v3(scope.lease,scope.db):yield scope
    finally:
        try:scope.close_v3()
        finally:_COUNTER_RESOURCE_BOUND_V3.reset(token)


def require_counter_call_resource_scope_v3(service,operation_id=None):
    scope=_COUNTER_RESOURCE_BOUND_V3.get()
    if type(scope)is not _CounterCallResourceScopeV3 or scope.service is not service:
        raise UnavailableGuard('Counter Core payload has no actual outer resource lifetime')
    scope.require_current_v3()
    if operation_id is not None and operation_id!=scope.selector.counter_operation_id:
        raise UnavailableGuard('Counter Core payload changed actual outer operation')
    return scope


def borrow_authority_counter_resource_lease_v3(work):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    from ..runtime_storage_v3 import _OPERATION
    if type(work)is not AuthorityGraphReadWorkV3 or work.controller.kind!='counter':
        raise UnavailableGuard('only the actual Counter Source Work may borrow its outer resource operation')
    call=_COUNTER_CALL_BINDING_V3.get()
    if call is None:raise UnavailableGuard('Counter Source has no actual call')
    outer=call.resource_scope.require_current_v3();call.require_current_v3(call.source,call.selector,call.credential,call.subject,call.permit)
    if (outer.child is not None or outer.lease is None or work.controller.service is not outer.service.source
            or work.credential is not call.credential or work.subject!=call.subject or work.permit is not call.permit
            or work.request is not call.selector or work.namespace!=outer.service.namespace
            or work.controller.fences.core is not outer.core or work.handle.pool is not outer.lease.pool
            or work.handle.selection_digest!=outer.lease.selection_digest or _OPERATION.get()is not outer.lease):
        raise UnavailableGuard('Counter Source resource borrow crossed actual caller/permit/selection/pool')
    outer.child=work
    _COUNTER_RESOURCE_CHILDREN_V3[work]=(outer,call,work.handle,work.permit,work.request,work.deadline_utc)
    return outer.lease


def require_authority_counter_resource_borrow_v3(work):
    item=_COUNTER_RESOURCE_CHILDREN_V3.get(work)
    if item is None:raise UnavailableGuard('Counter Source resource borrow was never issued')
    outer,call,handle,permit,selector,deadline=item;outer.require_current_v3()
    if(outer.child is not work or outer.source_call is not call or work.handle is not handle
            or work.permit is not permit or work.request is not selector or work.operation is not outer.lease):
        raise UnavailableGuard('Counter Source lost actual borrowed operation/child binding')
    return outer


def release_authority_counter_resource_borrow_v3(work):
    item=_COUNTER_RESOURCE_CHILDREN_V3.pop(work,None)
    if item is not None and item[0].child is work:item[0].child=None
