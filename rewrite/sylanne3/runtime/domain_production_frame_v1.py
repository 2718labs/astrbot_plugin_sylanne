
from ..runtime_storage_v3 import read_graph_row_v3, read_graph_rows_v3
"""Bounded materialization of an installed operation's actual W01 read plan."""
from dataclasses import replace
import json

from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, owner_grant_key
from ..memory_types import SourceRecord, source_key, access_key
from ..runtime_contracts import CommandEnvelope, FenceScope, NamespaceId, QueryEpoch, canonical_digest
from .domain_production_contracts_v1 import (
    CurrentOperationFrameV1, ProductionOperationLimitsV1, ProductionOwnerGuardV1,
    ProductionQueryCoverageV1, ProductionReadPlanV1,
)


def freeze_domain_production_frame_v1(graph, db, *, envelope, current_owner, scope,
        plan, now_utc, observed_originals=(), installed_policy_refs=(), limits=ProductionOperationLimitsV1()):
    """Read only; a frame carries no ability to commit or to perform execution."""
    from ..graph_coordinator import GraphCoordinator, OwnerLeaseBindingV1
    if (type(graph) is not GraphCoordinator or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or type(envelope) is not CommandEnvelope or type(current_owner) is not OwnerLeaseBindingV1
            or type(scope) is not FenceScope or type(plan) is not ProductionReadPlanV1
            or type(limits) is not ProductionOperationLimitsV1):
        raise ValueError("production frame needs the installed current W01 transaction")
    ns = envelope.authority.namespace
    metadata, epoch = graph._v2_graph_stamp(ns)
    if (scope.namespace != ns or current_owner.namespace != ns or scope.graph_epoch != epoch
            or scope.graph_revision != metadata.graph_revision or scope.generation != envelope.authority.activation_generation
            or not graph._anchor_matches(metadata.requirements, scope.pinned_anchor)
            or envelope.authority.activation_generation != metadata.requirements.activation_generation
            or current_owner.authorization_head == "genesis"
            or envelope.authority.actor != current_owner.actor
            or envelope.authority.purpose not in current_owner.purposes
            or not set(envelope.authority.audience).issubset(current_owner.audiences)):
        raise ValueError("production frame current namespace/Owner/fence or purpose/audience differs")
    guard = ProductionOwnerGuardV1(owner_grant_key(*ns.as_tuple).token, current_owner.grant_revision,
        current_owner.grant_digest.removeprefix("sha256:"), current_owner.authorization_head.removeprefix("sha256:"))
    from .domain_background_read_v3 import read_bound_background_frame_inputs_v3
    handled, prepared = read_bound_background_frame_inputs_v3(db, graph=graph, scope=scope,
        plan=plan, envelope=envelope, current_owner=current_owner)
    if not handled:
        from .current_method_learning_read_v3 import read_bound_method_frame_inputs_v3
        handled, prepared = read_bound_method_frame_inputs_v3(db, graph=graph, scope=scope,
            plan=plan, envelope=envelope, current_owner=current_owner)
    if handled:
        prepared.require_current_v3(db, scope, current_owner)
    return _materialize_current_domain_frame_v1(graph, db, envelope=envelope, scope=scope, plan=plan,
        prepared_inputs=prepared if handled else None,
        now_utc=now_utc, expected_owner_guard=guard, expected_rights=(current_owner.access_epoch, current_owner.delete_epoch),
        observed_originals=observed_originals, installed_policy_refs=installed_policy_refs, limits=limits)


def freeze_foreground_production_frame_v1(graph, db, *, envelope, issued, scope, plan, now_utc, operation, request, process_lease,
        observed_originals=(), installed_policy_refs=(), limits=ProductionOperationLimitsV1()):
    """Explicit self channel, qualified through the actual paired issued handle."""
    from ..graph_coordinator import GraphCoordinator
    from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
    if (type(graph) is not GraphCoordinator or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or type(envelope) is not CommandEnvelope or type(scope) is not FenceScope
            or type(plan) is not ProductionReadPlanV1 or type(limits) is not ProductionOperationLimitsV1):
        raise ValueError("foreground frame needs the actual installed W01 transaction")
    evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
    graph._authorize(process_lease, envelope.authority, frozenset(evidence.allowed_write_domains))
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    if (evidence.request.operation_kind != operation.operation_kind
            or envelope.identity.phase != operation.operation_kind
            or envelope.authority.issuer_domain != operation.domain
            or evidence.request.request_digest != foreground_typed_command_digest_v1(operation, request)
            or tuple(envelope.authority.owner_scope) != tuple(sorted(graph._GraphCoordinator__leases[process_lease][5]))):
        raise ValueError("foreground installed issuer/phase/request/write domains differ from actual issuance")
    ns = envelope.authority.namespace
    metadata, epoch = graph._v2_graph_stamp(ns)
    from datetime import datetime
    if (ns != evidence.request.namespace or envelope.authority.actor != evidence.current_self.self_entity_ref
            or envelope.identity.operation_id != evidence.request.operation_id
            or envelope.identity.activity_id != evidence.request.activity_id
            or envelope.parent_budget_lease_ref != evidence.request.parent_budget_lease_ref
            or envelope.authority.purpose != evidence.request.purpose
            or envelope.authority.audience != evidence.request.audiences
            or scope.graph_epoch != epoch or scope.graph_revision != metadata.graph_revision
            or evidence.current_self.graph_revision != metadata.graph_revision
            or evidence.query_epoch.revision != epoch.revision
            or not graph._anchor_matches(metadata.requirements, scope.pinned_anchor)
            or envelope.authority.activation_generation != evidence.current_self.activation_generation
            or envelope.deadline_utc > datetime.fromisoformat(evidence.valid_until_utc.replace("Z", "+00:00")).timestamp()):
        raise ValueError("foreground actual self/origin/budget/deadline/Graph witness differs")
    qualified_sources = {version.key.token for version in evidence.read_versions if version.key.type_name == "memory.source"}
    if not set(plan.source_roots) <= qualified_sources:
        raise ValueError("foreground frame cannot add a source outside the actually qualified task closure")
    # Private issuance supplies independently observed reads. The same SQL
    # snapshot rechecks them before any domain compiler sees the common frame.
    for version in evidence.read_versions:
        row = db.execute("SELECT revision FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*ns.as_tuple, version.key.token)).fetchone()
        if (0 if row is None else row[0]) != version.revision:
            raise ValueError("foreground independent read changed before actual W01 materialization")
    combined = ProductionReadPlanV1(plan.fixed_type_ids,
        tuple(sorted(set((*plan.exact_keys, *(version.key for version in evidence.read_versions))), key=lambda key: key.token)),
        plan.source_roots, plan.required_original_refs)
    from .current_method_learning_read_v3 import read_bound_method_issued_frame_inputs_v3
    handled, prepared = read_bound_method_issued_frame_inputs_v3(db, graph=graph, scope=scope,
        plan=combined, issued=issued)
    if handled:
        prepared.require_issued_current_v3(db, scope, issued)
    return _materialize_current_domain_frame_v1(graph, db, envelope=envelope, scope=scope, plan=combined,
        prepared_inputs=prepared if handled else None,
        now_utc=now_utc, expected_owner_guard=evidence.owner_guard,
        expected_rights=(evidence.access_epoch, evidence.delete_epoch), observed_originals=observed_originals,
        installed_policy_refs=installed_policy_refs, limits=limits)


def freeze_owner_source_note_task_frame_v1(graph, db, *, envelope, issued, scope, plan, now_utc,
        operation, request, process_lease, observed_originals=(), installed_policy_refs=(),
        limits=ProductionOperationLimitsV1()):
    from ..graph_coordinator import GraphCoordinator
    from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
    from ..authority_service.current_owner_source_note_task_v1 import owner_task_typed_command_digest_v1
    from .owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
    from datetime import datetime
    if (type(graph) is not GraphCoordinator or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or type(envelope) is not CommandEnvelope or type(scope) is not FenceScope
            or type(plan) is not ProductionReadPlanV1 or type(limits) is not ProductionOperationLimitsV1):
        raise ValueError('Owner task frame requires the actual installed W01 transaction')
    evidence = require_owner_source_note_task_issuance_v1(issued, graph, scope)
    auth = evidence.authorization
    selector = evidence.request
    graph._authorize(process_lease, envelope.authority, frozenset(evidence.allowed_write_domains))
    ns = envelope.authority.namespace
    metadata, epoch = graph._v2_graph_stamp(ns)
    ids = owner_source_note_task_ids_v1(ns, auth.cause.owner_operation_id)
    if (selector.operation_kind != operation.operation_kind
            or selector.request_digest != owner_task_typed_command_digest_v1(operation, request)
            or envelope.identity.phase != operation.operation_kind or envelope.authority.issuer_domain != operation.domain
            or envelope.identity.operation_id != selector.operation_id
            or envelope.identity.activity_id != ids['activity_id']
            or ns != selector.namespace or envelope.authority.actor != evidence.current_self.self_entity_ref
            or envelope.parent_budget_lease_ref != auth.cause.parent_budget_lease_ref
            or envelope.authority.purpose != 'consolidation' or envelope.authority.audience != auth.cause.audiences
            or scope.graph_epoch != epoch or scope.graph_revision != metadata.graph_revision
            or evidence.current_self.graph_revision != metadata.graph_revision
            or evidence.query_epoch.revision != epoch.revision
            or envelope.authority.activation_generation != evidence.current_self.activation_generation
            or not graph._anchor_matches(metadata.requirements, scope.pinned_anchor)
            or envelope.deadline_utc > datetime.fromisoformat(evidence.valid_until_utc.replace('Z','+00:00')).timestamp()
            or now_utc >= envelope.deadline_utc):
        raise ValueError('Owner task frame changed its actual independent current command/Self/Root/deadline')
    qualified = {v.key.token for v in evidence.read_versions if v.key.type_name == 'memory.source'}
    if not set(plan.source_roots) <= qualified:
        raise ValueError('Owner task frame added Source outside its independently qualified closure')
    for version in evidence.read_versions:
        row = db.execute('SELECT revision FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*ns.as_tuple, version.key.token)).fetchone()
        if (0 if row is None else row[0]) != version.revision:
            raise ValueError('Owner task independent read changed before W01')
    combined = ProductionReadPlanV1(plan.fixed_type_ids,
        tuple(sorted(set((*plan.exact_keys, *(v.key for v in evidence.read_versions))), key=lambda key:key.token)),
        plan.source_roots, plan.required_original_refs)
    from .current_method_learning_read_v3 import read_bound_method_issued_frame_inputs_v3
    handled, prepared = read_bound_method_issued_frame_inputs_v3(db, graph=graph, scope=scope,
        plan=combined, issued=issued)
    if handled:
        prepared.require_issued_current_v3(db, scope, issued)
    return _materialize_current_domain_frame_v1(graph, db, envelope=envelope, scope=scope, plan=combined,
        prepared_inputs=prepared if handled else None,
        now_utc=now_utc, expected_owner_guard=evidence.owner_guard,
        expected_rights=(evidence.access_epoch,evidence.delete_epoch), observed_originals=observed_originals,
        installed_policy_refs=installed_policy_refs, limits=limits)


def _materialize_current_domain_frame_v1(graph, db, **kwargs):
    return CurrentOperationFrameV1(*_materialize_current_domain_frame_fields_v1(graph, db, **kwargs))


def freeze_owner_stop_projection_frame_v1(graph, db, *, envelope, issued, scope, plan, now_utc):
    from ..graph_coordinator import GraphCoordinator
    from .foreground_activity_issuance_v1 import require_owner_stop_projection_issuance_v1
    from .domain_production_contracts_v1 import CurrentOwnerStopProjectionFrameV1, ProductionOriginalRefV1
    from .jobs import get_job
    from datetime import datetime
    if (type(graph) is not GraphCoordinator or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or type(envelope) is not CommandEnvelope or type(scope) is not FenceScope
            or type(plan) is not ProductionReadPlanV1):
        raise TypeError("Stop projection frame requires its actual W01 metadata transaction")
    observed = require_owner_stop_projection_issuance_v1(issued, graph, scope)
    metadata, epoch = graph._v2_graph_stamp(observed.request.namespace)
    if (scope.operation != "write" or scope.permit != observed.permit
            or metadata.requirements != observed.requirements or metadata.graph_revision != observed.graph_revision
            or epoch.revision != observed.graph_epoch or epoch != scope.graph_epoch
            or plan.source_roots or plan.fixed_type_ids
            or set(plan.required_original_refs) != {observed.initial_original.original_ref}
            or set(plan.exact_keys) != {v.key for v in observed.read_versions}):
        raise ValueError("Stop projection snapshot/permit or exact metadata inventory differs")
    cycle = get_job(db, AtomKey.from_token(observed.request.cycle_job_ref).name)
    original_deadline = datetime.fromisoformat(cycle.deadline_utc.replace("Z", "+00:00")).timestamp()
    if envelope.deadline_utc != original_deadline or envelope.parent_budget_lease_ref != cycle.budget_ref:
        raise ValueError("Stop projection must preserve the original work deadline/budget identity")
    for version in observed.read_versions:
        row = db.execute("SELECT revision FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (version.key.token, *observed.request.namespace.as_tuple)).fetchone()
        if row is None or row[0] != version.revision:
            raise ValueError("Stop projection actual metadata read changed before W01")
    original = ProductionOriginalRefV1("owner_stop_reply_v1", observed.initial_original.original_ref,
        observed.initial_original.original_digest.removeprefix("sha256:"))
    guard = ProductionOwnerGuardV1(observed.owner_grant_ref, observed.owner_grant_revision,
        observed.owner_grant_digest, observed.owner_authorization.authorization_head.removeprefix("sha256:"))
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
        observed.request.namespace.as_tuple).fetchone()
    fields = _materialize_current_domain_frame_fields_v1(graph, db, envelope=envelope, scope=scope, plan=plan,
        now_utc=now_utc, expected_owner_guard=guard, expected_rights=rights, observed_originals=(original,),
        installed_policy_refs=(), limits=ProductionOperationLimitsV1())
    return CurrentOwnerStopProjectionFrameV1(*fields, issuance=issued)


def _materialize_current_domain_read_set_v3(graph, db, *, namespace, plan,
        expected_owner_guard, expected_rights, observed_originals, limits, prepared_inputs=None):
    """The original read-set algorithm, without issuing a frame or authority."""
    ns = namespace
    _, epoch = graph._v2_graph_stamp(ns)
    atoms = {}
    def load(key):
        if type(key) is not AtomKey or NamespaceId.from_key(key) != ns:
            raise ValueError("production read plan crossed the actual namespace")
        if key in atoms:
            return atoms[key]
        if len(atoms) >= limits.max_graph_heads:
            raise ValueError("production read plan exceeds complete current head limit")
        graph._GraphCoordinator__store._registry.spec(key.type_name)
        if prepared_inputs is not None:
            atom = prepared_inputs.head_v3(key)
        else:
            row = read_graph_row_v3(db, ('revision', 'value', 'valid'), where='token=? AND bot=? AND persona=?', parameters=(key.token, *ns.as_tuple), history=False)
            atom = GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])) if row else GraphAtom(key, 0, {}, False)
        atoms[key] = atom
        return atom
    owner_key = owner_grant_key(*ns.as_tuple)
    owner = load(owner_key)
    if (not owner.valid or owner.revision != expected_owner_guard.grant_revision
            or canonical_digest(owner.value) != expected_owner_guard.grant_digest):
        raise ValueError("production actual Owner grant no longer matches its independently read head")
    pages = []
    query_epoch = QueryEpoch(ns, "namespace", epoch.revision)
    for type_id in plan.fixed_type_ids:
        graph._GraphCoordinator__store._registry.spec(type_id)
        if prepared_inputs is not None:
            rows = tuple((atom.key.token, atom.revision) for atom in prepared_inputs.inventory_v3(type_id))
        else:
            rows = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? "
                "ORDER BY token LIMIT ?", (*ns.as_tuple, type_id, limits.max_query_rows + 1)).fetchall()
        selected, complete = rows[:limits.max_query_rows], len(rows) <= limits.max_query_rows
        versions = tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision in selected)
        for version in versions:
            load(version.key)
        continuation = None if complete else "production-query:" + canonical_digest(
            (ns, type_id, epoch.revision, selected[-1][0]))[:48]
        pages.append(ProductionQueryCoverageV1(query_epoch, type_id, versions, complete, continuation))
    for key in plan.exact_keys:
        load(key)
    active, seen = set(), set()
    def source_closure(ref):
        key = AtomKey.from_token(ref)
        if key != source_key(*ns.as_tuple, key.owner.subject or ""):
            raise ValueError("production source locator is not canonical D06 identity")
        if ref in active:
            raise ValueError("production source family contains a cycle")
        if ref in seen:
            return
        active.add(ref)
        source = load(key)
        load(access_key(*ns.as_tuple, key.owner.subject))
        load(source_correction_head_key(ns, key.owner.subject))
        if source.valid and source.revision > 0:
            value = SourceRecord.from_dict(source.value)
            if value.source_id != key.owner.subject:
                raise ValueError("production source record and key identity differ")
            for parent in value.parent_source_ids:
                source_closure(source_key(*ns.as_tuple, parent).token)
        active.remove(ref)
        seen.add(ref)
    for ref in plan.source_roots:
        source_closure(ref)
    for original in observed_originals:
        for version in original.read_versions:
            if load(version.key).revision != version.revision:
                raise ValueError("production independently read original changed in the held transaction")
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    if rights != expected_rights:
        raise ValueError("production current source rights differ from its Owner view")
    snapshot = GraphSnapshot(tuple(sorted(atoms.values(), key=lambda atom: atom.key.token)), (epoch,))
    return snapshot, tuple(pages), rights


def _materialize_current_domain_frame_fields_v1(graph, db, *, envelope, scope, plan, now_utc,
        expected_owner_guard, expected_rights, observed_originals, installed_policy_refs, limits, prepared_inputs=None):
    """Common bounded SQL materialization; caller-specific issuance is above."""
    ns = envelope.authority.namespace
    _, epoch = graph._v2_graph_stamp(ns)
    snapshot, pages, rights = _materialize_current_domain_read_set_v3(graph, db,
        namespace=ns, plan=plan, expected_owner_guard=expected_owner_guard,
        expected_rights=expected_rights, observed_originals=observed_originals,
        limits=limits, prepared_inputs=prepared_inputs)
    query_epoch = QueryEpoch(ns, "namespace", epoch.revision)
    inputs = tuple(sorted(set(plan.source_roots + plan.required_original_refs)))
    actual_envelope = replace(envelope,
        identity=replace(envelope.identity, canonical_input_digest=canonical_digest({"input_refs": list(inputs)})),
        input_refs=inputs, source_qualification=replace(envelope.source_qualification, source_refs=plan.source_roots),
        version_guard=replace(envelope.version_guard,
        read_versions=snapshot.versions, query_epochs=(query_epoch,), access_epoch=rights[0], delete_epoch=rights[1],
        catalogue_version=graph._GraphCoordinator__store._registry.catalogue_hash))
    return (actual_envelope, snapshot, now_utc, expected_owner_guard,
        scope.generation, tuple(pages), tuple(installed_policy_refs), tuple(observed_originals), limits)
