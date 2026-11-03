"""Installed D08/D10 review producers and current selection qualification.

Growth is a reason to review an obligation, never permission to change it.
Only the explicit signed Owner keep command can restore candidate eligibility.
"""
from dataclasses import dataclass, fields, is_dataclass
from ..authority_service.contract import AuthorityUnavailable
from ..domains.d01 import PersonaDomain, _activation_key
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, GraphVersion, GraphWrite, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .persona_growth_review_contract_v1 import (
    REVIEW_TYPES_V1, TARGET_TYPES_V1, GROWTH_EVENTS_V1, MARK_OPERATIONS_V1, CONFIRM_OPERATIONS_V1,
    REVIEW_OPERATIONS_V1, MarkCurrentGrowthReviewRequestV1, ConfirmCurrentGrowthReviewRequestV1,
    PersonaGrowthReviewV1, decode_persona_growth_review_v1, growth_review_key_v1, target_domain_v1)
from .persona_growth_review_metadata_v1 import (
    _owner_v1, growth_metadata_head_v1, growth_target_control_v1, growth_original_control_v1,
    read_growth_review_metadata_v1, growth_adoption_activation_control_v1)

_READER_KEY_V1 = object()

# These operations create/select a new candidate or start additional work.
# Reconciliation and adoption of an already observed result are deliberately
# separate operations and do not pass through this new-work list.
NEW_WORK_OPERATIONS_V1 = frozenset({
    "prepare_source_note_action", "prepare_selected_source_note_action_v2",
    "prepare_personal_candidates_v1", "prepare_personal_candidate_eligibility_v1",
    "adopt_personal_candidate_eligibility_v1", "select_personal_step", "select_personal_step_v2",
    "propose_artifact_draft_action", "propose_artifact_draft_phase_action_v2",
    "prepare_artifact_draft_model_v2", "acquire_artifact_draft_model_v2",
    "prepare_life", "prepare_offline_tick", "prepare_joint_window_v1",
    "enter_current_joint_window_v1", "finalize_current_joint_window_v1",
    "advance_long_term_window_v1", "qualify_habit_occurrence_v1",
})


@dataclass(frozen=True, slots=True)
class InstalledGrowthReviewReadersV1:
    key: object
    graph: object
    owner_binding: object
    owner_guard: object
    background_issuance: object
    domain: str
    operation_kind: str

    def __post_init__(self):
        if self.key is not _READER_KEY_V1:
            raise TypeError("growth reviews use the actual fresh Owner reader factory")


def install_growth_review_readers_v1(graph, *, scope, owner_guard, owner_binding, operation):
    from .d08_project_control_v1 import install_project_control_readers_v1
    actual = install_project_control_readers_v1(graph, scope=scope,
        owner_guard=owner_guard, owner_binding=owner_binding)
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    issued = getattr(runtime, "_active_background_followup_v1", None)
    if operation.operation_kind in MARK_OPERATIONS_V1.values() and issued is not None:
        from .domain_followup_consumer_v1 import require_background_followup_v1
        require_background_followup_v1(issued, graph, issued.authority, issued.operation_id)
        if (issued.event.event_kind != GROWTH_EVENTS_V1[operation.domain]
                or issued.command.operation_kind != operation.operation_kind):
            raise ValueError("growth marker changed its actual outbox consumer")
    elif issued is not None:
        raise ValueError("a growth event cannot confer explicit Owner keep confirmation")
    return InstalledGrowthReviewReadersV1(_READER_KEY_V1, graph,
        actual.owner_binding, actual.owner_guard, issued, operation.domain, operation.operation_kind)


def _control_v1(db, frame):
    owner, _ = _owner_v1(db)
    read = CurrentDomainReadV1(frame)
    ns = frame.envelope.authority.namespace
    read.head(db, _activation_key(ns), required=True)
    activation = frame.snapshot.get(_activation_key(ns))
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3
    if type(owner) is BorrowedMethodLearningReadV3:
        control = require_borrowed_persona_head_metadata_v1(owner, frame, activation)
    else:
        control = PersonaDomain.resolve_active_role_control_v3(frame.snapshot,
            namespace=ns, current_guard=owner.owner_guard)
    head, valid = growth_metadata_head_v1(db, ns, control.plan_key)
    if not valid or head.revision < 1:
        raise MissingProductionOriginalV1("actual_current_persona_control_head_metadata")
    grant = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    from .persona_growth_birth_v1 import current_persona_birth_control_v1
    birth_control = current_persona_birth_control_v1(db, namespace=ns)
    if (birth_control.activation_version != GraphVersion(activation.key, activation.revision)
            or birth_control.persona_head_version != head or birth_control.head_id != control.head_id):
        raise AuthorityUnavailable("Growth control differs from its exact current metadata plan join")
    return control, GraphVersion(activation.key, activation.revision), head, grant


def qualify_growth_metadata_v1(db, namespace, controls):
    """Qualify the actual adopted growth using control metadata only."""
    census = read_growth_review_metadata_v1(db, ("latest",))
    control, activation, head, grant = controls
    if census.latest is None:
        if control.plan_version != 1:
            raise MissingProductionOriginalV1("unknown_erased_or_unbound_persona_growth_lineage")
        return None, census, (control, activation, head, grant)
    operation_id, original_ref, digest, commit_seq = census.latest
    original = growth_original_control_v1(db, operation_id)
    if ((original["domain"], original["operation_kind"]) not in {
            ("d01", "adopt_growth"), ("d01", "adopt_general_growth_v1")}
            or original["original_digest"] != digest
            or original["receipt"].commit_seq != commit_seq):
        raise MissingProductionOriginalV1("actual_growth_in_current_Owner_graph_incarnation")
    adopted_activation = growth_adoption_activation_control_v1(db, original)
    if adopted_activation["graph_incarnation"] != grant.value["graph_incarnation"]:
        raise MissingProductionOriginalV1("actual_growth_current_graph_incarnation_lineage")
    writes = original["receipt"].write_versions
    if not any(version.key.type_name == "d01.persona_activation.v1" for version in writes) or not any(
            version.key.type_name == "d01.persona_plan.v1" for version in writes):
        raise ValueError("growth event lacks an actual typed persona adoption")
    from ..graph_types import Owner
    adopted_plan_key = AtomKey(Owner("persona", *namespace.as_tuple),
        "d01.persona_plan.v1", adopted_activation["plan_id"])
    if not any(version.key == adopted_plan_key for version in writes):
        raise ValueError("growth receipt differs from its actual adopted activation plan control")
    return (operation_id, original_ref, original), census, controls


def _growth_v1(db, frame, *, require_body):
    controls = _control_v1(db, frame)
    growth, census, controls = qualify_growth_metadata_v1(db, frame.envelope.authority.namespace, controls)
    if growth is None:
        return growth, census, controls
    operation_id, original_ref, original = growth
    digest = original["original_digest"]
    if require_body:
        adopted = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, operation_id)
        if (adopted is None or adopted["original_digest"] != digest
                or adopted["receipt"] != original["receipt"]):
            raise MissingProductionOriginalV1("actual_Source_qualified_growth_original")
        CurrentDomainReadV1(frame).original(original_ref,
            kind="d01.current-" + original["operation_kind"], digest=digest)
    return growth, census, controls


def _source_roots_v1(originals):
    return tuple(sorted({version.key.token for original in originals for version in original["read_versions"]
        if version.key.type_name == "memory.source"}))


def read_plan_growth_review_v1(db, *, namespace, request):
    key = AtomKey.from_token(request.target_ref)
    if NamespaceId.from_key(key) != namespace:
        raise ValueError("growth review request crossed namespace")
    target, valid = growth_metadata_head_v1(db, namespace, key)
    if not valid or target.revision != request.expected_target_revision:
        raise MissingProductionOriginalV1("actual_current_growth_review_target_version")
    census = read_growth_review_metadata_v1(db, ("latest",))
    if census.latest is None or census.latest[0] != request.growth_operation_id:
        raise MissingProductionOriginalV1("actual_latest_growth_review_original")
    from .d01_production_operations_v1 import raw_head_value_v1
    from ..graph_types import Owner
    active = raw_head_value_v1(db, namespace, _activation_key(namespace))
    if active is None:
        raise MissingProductionOriginalV1("actual_current_growth_review_activation")
    growth_metadata_head_v1(db, namespace, AtomKey(Owner("persona", *namespace.as_tuple),
        "d01.persona_plan.v1", active["plan_id"]))
    origin = growth_target_control_v1(db, target)
    growth = growth_original_control_v1(db, census.latest[0])
    roots = _source_roots_v1((origin, growth))
    return production_read_plan_v1((), (key, _activation_key(namespace),
        growth_review_key_v1(namespace, key)), roots, (census.latest[1], origin["receipt"].operation_id))


def _stage_growth_review_v1(db, *, frame, request, installed_readers, confirm):
    if type(installed_readers) is not InstalledGrowthReviewReadersV1:
        raise TypeError("growth review requires the actual independently issued Owner reader")
    expected = ConfirmCurrentGrowthReviewRequestV1 if confirm else MarkCurrentGrowthReviewRequestV1
    if type(request) is not expected:
        raise TypeError("growth review command has another registered intent type")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    key = AtomKey.from_token(request.target_ref)
    domain = target_domain_v1(key)
    kind = (CONFIRM_OPERATIONS_V1 if confirm else MARK_OPERATIONS_V1)[domain]
    if domain != installed_readers.domain or kind != installed_readers.operation_kind:
        raise ValueError("growth review target differs from its actual registered domain/operation")
    readers, authority = installed_readers, frame.envelope.authority
    owner = readers.owner_binding
    if (authority.actor != owner.actor or "workbench.control" not in owner.capabilities
            or not {"context", "consolidation"} <= owner.purposes
            or not set(authority.audience) <= owner.audiences
            or readers.owner_guard.authorization_head.removeprefix("sha256:") != frame.owner_guard.owner_head_digest):
        raise ValueError("growth review lacks its actual current Owner control/purpose/audience")
    if not confirm and readers.background_issuance is not None and (
            readers.background_issuance.command.request != request
            or readers.background_issuance.event.causal_operation_id != request.growth_operation_id):
        raise ValueError("growth marker changed its exact authenticated event/target command")
    if confirm and readers.background_issuance is not None:
        raise ValueError("Owner keep confirmation cannot be synthesized by the growth consumer")
    growth, census, controls = _growth_v1(db, frame, require_body=True)
    if growth is None:
        raise MissingProductionOriginalV1("actual_growth_to_review")
    control, activation, head, grant = controls
    if (growth[0] != request.growth_operation_id or control.head_id != request.expected_head_id
            or activation.revision != request.expected_activation_revision):
        raise MissingProductionOriginalV1("unchanged_current_growth_review_control")
    target_atom = read.head(db, key, required=True)
    if target_atom.revision != request.expected_target_revision:
        raise MissingProductionOriginalV1("unchanged_growth_review_target")
    target = GraphVersion(key, target_atom.revision)
    origin = growth_target_control_v1(db, target)
    adopted = read_adopted_domain_operation_v1(db, ns, origin["receipt"].operation_id)
    if adopted is None or adopted["receipt"] != origin["receipt"]:
        raise MissingProductionOriginalV1("actual_Source_qualified_review_target_producer")
    read.original(origin["receipt"].operation_id, digest=origin["original_digest"])
    roots = _source_roots_v1((origin, growth[2]))
    records = {}
    for root in roots:
        records.update(read.source_family(db, (root,), purpose="consolidation"))
    review_key = growth_review_key_v1(ns, key)
    before = read.head(db, review_key)
    if before.revision != request.expected_review_revision:
        raise MissingProductionOriginalV1("unchanged_exact_growth_review_head")
    prior = decode_persona_growth_review_v1(before.value) if before.valid else None
    matches = prior is not None and (
        prior.target_version, prior.activation_version, prior.persona_head_version,
        prior.persona_head_id, prior.growth_operation_id, prior.growth_original_digest,
        prior.graph_incarnation) == (
        target, activation, head, control.head_id, growth[0], growth[2]["original_digest"],
        grant.value["graph_incarnation"])
    if confirm and (not matches or prior.state != "pending"):
        raise MissingProductionOriginalV1("actual_current_pending_growth_review_for_explicit_Owner_keep")
    # A late marker must not downgrade a current explicit Owner confirmation.
    after = prior if matches and not confirm else PersonaGrowthReviewV1(
        ns, target, activation, head, control.head_id, growth[0], growth[2]["original_digest"],
        grant.value["graph_incarnation"], "owner_confirmed_keep" if confirm else "pending",
        frame.envelope.identity.operation_id, GraphVersion(grant.key, grant.revision), roots)
    noop = matches and not confirm
    from ..memory_types import access_key
    from ..domains.d06 import source_correction_head_key
    source_controls = tuple(control_key for ref, record in records.items() for control_key in (
        AtomKey.from_token(ref),
        access_key(*ns.as_tuple, record.source_id), source_correction_head_key(ns, record.source_id)))
    dependencies = tuple(dict.fromkeys((key, activation.key, head.key, grant.key, *source_controls)))
    provider = _provider_v1(domain)
    return stage_result_v1(frame, domain, kind, request,
        writes=() if noop else (GraphWrite(review_key, plain_v1(after), dependencies),),
        provenance={"growth_review": after, "metadata_eof": census,
            "target_original_ref": origin["receipt"].operation_id, "noop": noop},
        proposal_schema=domain + ".proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)


def _provider_v1(domain):
    if domain == "d08":
        from ..domains.d08.execution import GoalExecutionProvider
        return GoalExecutionProvider()
    from ..domains.d10 import LifeDomain
    return LifeDomain()


def stage_mark_growth_review_v1(db, *, frame, request, installed_readers):
    from .d01_production_operations_v1 import waiting_stage_v1
    try:
        return _stage_growth_review_v1(db, frame=frame, request=request,
            installed_readers=installed_readers, confirm=False)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, target_domain_v1(AtomKey.from_token(request.target_ref)),
            MARK_OPERATIONS_V1[target_domain_v1(AtomKey.from_token(request.target_ref))], request, missing)


def stage_confirm_growth_review_v1(db, *, frame, request, installed_readers):
    from .d01_production_operations_v1 import waiting_stage_v1
    try:
        return _stage_growth_review_v1(db, frame=frame, request=request,
            installed_readers=installed_readers, confirm=True)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, target_domain_v1(AtomKey.from_token(request.target_ref)),
            CONFIRM_OPERATIONS_V1[target_domain_v1(AtomKey.from_token(request.target_ref))], request, missing)


def validate_growth_review_provenance_v1(domain, kind, provenance):
    if kind not in REVIEW_OPERATIONS_V1:
        return None
    if provenance == {}:
        return ()
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .persona_growth_review_metadata_v1 import GrowthMetadataEOFLatestV1
    if set(provenance) != {"growth_review", "metadata_eof", "target_original_ref", "noop"}:
        raise ValueError("growth review original has another closed provenance")
    review = decode_persona_growth_review_v1(provenance["growth_review"])
    census = decode_typed_production_value_v1(provenance["metadata_eof"], GrowthMetadataEOFLatestV1)
    if (target_domain_v1(review.target_version.key) != domain or census.namespace != review.namespace
            or census.latest is None or census.latest[0] != review.growth_operation_id
            or census.latest[2] != review.growth_original_digest
            or type(provenance["noop"]) is not bool or type(provenance["target_original_ref"]) is not str
            or kind == CONFIRM_OPERATIONS_V1[domain] and review.state != "owner_confirmed_keep"):
        raise ValueError("growth review original changed actual owner/target/watermark/state")
    return tuple(sorted(set((review.target_version.key.token, review.activation_version.key.token,
        review.persona_head_version.key.token, review.owner_grant.key.token, *review.source_refs))))


def require_current_growth_review_targets_v1(db, *, frame, target_keys):
    """Current candidate qualification only; cannot reconcile/replay an old effect."""
    read = CurrentDomainReadV1(frame)
    growth, _, controls = _growth_v1(db, frame, require_body=False)
    if growth is None:
        return
    control, activation, head, grant = controls
    ns = frame.envelope.authority.namespace
    for target_key in target_keys:
        target = read.head(db, target_key, required=True)
        from .persona_growth_birth_v1 import persona_birth_status_v1
        if persona_birth_status_v1(db, namespace=ns, target_key=target_key) == "birth_current":
            continue
        atom = read.head(db, growth_review_key_v1(ns, target_key))
        review = decode_persona_growth_review_v1(atom.value) if atom.valid else None
        if (review is None or review.state != "owner_confirmed_keep"
                or review.target_version != GraphVersion(target.key, target.revision)
                or review.activation_version != activation or review.persona_head_version != head
                or review.persona_head_id != control.head_id or review.growth_operation_id != growth[0]
                or review.growth_original_digest != growth[2]["original_digest"]
                or review.graph_incarnation != grant.value["graph_incarnation"]
                or review.owner_grant != GraphVersion(grant.key, grant.revision)):
            raise MissingProductionOriginalV1("pending_explicit_Owner_growth_review:" + target.key.token)
        producer = growth_target_control_v1(db, GraphVersion(atom.key, atom.revision))
        if producer["operation_kind"] != CONFIRM_OPERATIONS_V1[target_domain_v1(target_key)]:
            raise MissingProductionOriginalV1("actual_Owner_keep_review_producer")
        if (producer["domain"] != target_domain_v1(target_key)
                or producer["receipt"].operation_id != review.review_operation_id):
            raise MissingProductionOriginalV1("actual_current_Owner_growth_confirmation_control_link")
        # The typed current review is metadata only. Its writer bound all
        # actual Source/Access/correction and Owner/head dependencies. This
        # consumer neither reads their semantic bodies nor grants new Source.


def _request_target_keys_v1(value):
    result = set()
    def visit(item):
        if type(item) is AtomKey:
            if item.type_name in {kind for kinds in TARGET_TYPES_V1.values() for kind in kinds}:
                result.add(item)
        elif type(item) is GraphVersion:
            visit(item.key)
        elif is_dataclass(item):
            for field in fields(item):
                visit(getattr(item, field.name))
        elif type(item) in (tuple, list):
            for child in item:
                visit(child)
        elif type(item) is str and item.startswith('["'):
            try:
                key = AtomKey.from_token(item)
            except ValueError:
                return
            visit(key)
    visit(value)
    return result


def _growth_review_target_keys_v1(request, actual_keys):
    kinds = {kind for values in TARGET_TYPES_V1.values() for kind in values}
    return tuple(sorted(_request_target_keys_v1(request) |
        {key for key in actual_keys if key.type_name in kinds}, key=lambda key: key.token))


def growth_review_target_keys_for_plan_v1(request, plan):
    return _growth_review_target_keys_v1(request, plan.exact_keys)


def augment_growth_review_plan_v1(db, *, namespace, operation_kind, request, plan):
    if operation_kind not in NEW_WORK_OPERATIONS_V1:
        return plan
    from .d01_production_operations_v1 import raw_head_value_v1
    from ..graph_types import Owner
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    from .persona_growth_birth_v1 import current_persona_birth_control_v1, persona_birth_status_v1
    birth_control = current_persona_birth_control_v1(db, namespace=namespace)
    census = read_growth_review_metadata_v1(db, ("latest",))
    activation_key = _activation_key(namespace)
    activation = raw_head_value_v1(db, namespace, activation_key)
    if activation is None:
        raise MissingProductionOriginalV1("actual_active_persona_growth_control")
    # Only the activation control is read. The plan is an independently
    # observed metadata CAS version, never a synthetic or empty PersonaPlan.
    plan_key = AtomKey(Owner("persona", *namespace.as_tuple),
        "d01.persona_plan.v1", activation["plan_id"])
    head, valid = growth_metadata_head_v1(db, namespace, plan_key)
    if not valid:
        raise MissingProductionOriginalV1("actual_current_persona_growth_head_metadata")
    keys = set(plan.exact_keys) | {activation_key}
    roots, originals = set(plan.source_roots), set(plan.required_original_refs)
    targets = growth_review_target_keys_for_plan_v1(request, plan)
    if census.latest is not None:
        # The gate needs the fixed adoption receipt/control metadata, not its
        # private growth body. The existing Self task Source scope is unchanged.
        growth_original_control_v1(db, census.latest[0])
        for key in targets:
            target, valid = growth_metadata_head_v1(db, namespace, key)
            if not valid:
                raise MissingProductionOriginalV1("actual_current_growth_review_scope_target")
            if persona_birth_status_v1(db, namespace=namespace, target_key=key, current=birth_control) == "birth_current":
                continue
            review_key = growth_review_key_v1(namespace, key)
            keys.add(review_key)
            review, review_valid = growth_metadata_head_v1(db, namespace, review_key)
            if review_valid:
                growth_target_control_v1(db, review)
    return ProductionReadPlanV1(plan.fixed_type_ids, tuple(sorted(keys, key=lambda key: key.token)),
        tuple(sorted(roots)), tuple(sorted(originals)))


def require_growth_review_new_work_v1(db, *, frame, operation_kind, request):
    if operation_kind not in NEW_WORK_OPERATIONS_V1:
        return
    # Derive target identities directly from the actual issued frame.
    targets = _growth_review_target_keys_v1(request, (atom.key for atom in frame.snapshot.atoms))
    census = read_growth_review_metadata_v1(db, ("latest",))
    if census.latest is not None and not targets:
        raise MissingProductionOriginalV1("actual_current_growth_review_target_scope_for_new_work")
    require_current_growth_review_targets_v1(db, frame=frame, target_keys=targets)


def growth_followup_read_plan_v1(db, *, namespace, event):
    from .domain_background_read_v3 import background_inventory_v3
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    census = read_growth_review_metadata_v1(db, ("latest",))
    keys, roots, originals = {_activation_key(namespace)}, set(), set()
    if census.latest is not None:
        original = growth_original_control_v1(db, census.latest[0])
        roots.update(_source_roots_v1((original,)))
        originals.add(census.latest[1])
    kinds = TARGET_TYPES_V1[event.receiver_domain]
    for kind in kinds:
        for atom in background_inventory_v3(db, namespace, kind, valid_only=True):
            target = GraphVersion(atom.key, atom.revision)
            origin = growth_target_control_v1(db, target)
            roots.update(_source_roots_v1((origin,)))
            originals.add(origin["receipt"].operation_id)
            keys.add(atom.key)
            keys.add(growth_review_key_v1(namespace, atom.key))
    # The latest persona head itself remains a named metadata read, not a body.
    from .d01_production_operations_v1 import raw_head_value_v1
    from ..graph_types import Owner
    active = raw_head_value_v1(db, namespace, _activation_key(namespace))
    if active is not None:
        growth_metadata_head_v1(db, namespace, AtomKey(Owner("persona", *namespace.as_tuple),
            "d01.persona_plan.v1", active["plan_id"]))
    return ProductionReadPlanV1(tuple(kinds), tuple(sorted(keys, key=lambda key: key.token)),
        tuple(sorted(roots)), tuple(sorted(originals)))


def resolve_growth_followup_v1(db, *, frame, event, original, continuation):
    from .domain_production_followups_v1 import DomainFollowupCommandV1, DomainFollowupResolutionV1
    read = CurrentDomainReadV1(frame)
    census = read_growth_review_metadata_v1(db, ("latest",))
    if census.latest is not None and census.latest[0] != event.causal_operation_id:
        return DomainFollowupResolutionV1("growth_review_observed", (), (), (), None)
    growth, _, controls = _growth_v1(db, frame, require_body=True)
    if growth is None or growth[0] != event.causal_operation_id:
        return DomainFollowupResolutionV1("growth_review_observed", (), (), (), None)
    control, activation, head, grant = controls
    ns = frame.envelope.authority.namespace
    targets, commands = [], []
    remaining = 0
    for kind in TARGET_TYPES_V1[event.receiver_domain]:
        for atom in read.complete_inventory(db, kind):
            if not atom.valid:
                continue
            targets.append(atom.key.token)
            review_atom = read.head(db, growth_review_key_v1(ns, atom.key))
            prior = decode_persona_growth_review_v1(review_atom.value) if review_atom.valid else None
            if (prior is not None and prior.target_version == GraphVersion(atom.key, atom.revision)
                    and prior.activation_version == activation and prior.persona_head_version == head
                    and prior.growth_operation_id == growth[0]
                    and prior.growth_original_digest == growth[2]["original_digest"]
                    and prior.graph_incarnation == grant.value["graph_incarnation"]):
                continue
            remaining += 1
            if len(commands) >= frame.limits.max_followup_jobs:
                continue
            request = MarkCurrentGrowthReviewRequestV1(atom.key.token, atom.revision, growth[0],
                control.head_id, activation.revision, review_atom.revision)
            commands.append(DomainFollowupCommandV1(event.receiver_domain,
                MARK_OPERATIONS_V1[event.receiver_domain], request,
                "growth-review:" + canonical_digest((event.dedupe_key, atom.key.token))[:48],
                frame.envelope.authority.audience[0], tuple(frame.envelope.authority.audience)))
    if len(targets) > 128:
        raise MissingProductionOriginalV1("bounded_current_growth_review_target_inventory")
    if commands and "workbench.control" not in _owner_v1(db)[0].owner.capabilities:
        return DomainFollowupResolutionV1("waiting_for_original", (), tuple(targets),
            ("independent_current_Owner_growth_review_control_capability",), continuation)
    if not commands:
        # Complete query coverage is required by every complete_inventory above.
        # This acknowledges the notification, never a compatible/released goal.
        return DomainFollowupResolutionV1("growth_review_observed", (), tuple(targets), (), None)
    missing = len(commands) < remaining
    return DomainFollowupResolutionV1("partial" if missing else "ready", tuple(commands),
        tuple(targets), ("bounded_current_growth_review_tail",) if missing else (),
        continuation if missing else None)


def validate_growth_review_proposal_v1(proposal):
    """Domain validator for its one registered metadata write, not an issuer."""
    from .persona_growth_review_contract_v1 import REVIEW_TYPES_V1
    domain = proposal.domain
    kind = REVIEW_TYPES_V1[domain]
    if len(proposal.typed_writes) != 1 or proposal.typed_writes[0].key.type_name != kind:
        raise ValueError("growth review proposal may contain only its one owned metadata head")
    write = proposal.typed_writes[0]
    value = decode_persona_growth_review_v1(write.value)
    if (value.namespace != proposal.envelope.authority.namespace
            or write.key != growth_review_key_v1(value.namespace, value.target_version.key)
            or value.review_operation_id != proposal.envelope.identity.operation_id
            or any(version not in proposal.envelope.version_guard.read_versions
                for version in (value.target_version, value.activation_version,
                    value.persona_head_version, value.owner_grant))):
        raise ValueError("growth review proposal differs from its actual target/control CAS scope")
    return proposal


def require_borrowed_persona_head_metadata_v1(reader, frame, activation):
    """Consume the exact already issued Self control; issue no Authority guard."""
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3, _require_borrowed_issuance_v3
    from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
    from ..domains.d01 import ActiveRoleHeadControlV3, _validate_persona_activation
    from ..graph_types import Owner
    if type(reader) is not BorrowedMethodLearningReadV3:
        raise AuthorityUnavailable("growth borrowed control requires its actual Source Work")
    reader.require_current()
    evidence = _require_borrowed_issuance_v3(reader.issued, reader.graph)
    current = reader.current_self
    ns = reader.namespace
    grant = frame.snapshot.get(owner_grant_key(*ns.as_tuple))
    _validate_persona_activation(activation.value)
    value = activation.value
    origin = current.origin_graph_incarnation or current.graph_incarnation
    if (evidence is not reader.evidence or evidence.current_self is not current
            or type(current) is not AuthorityCurrentSelfIdentityV1
            or current.namespace != ns or current.permit != reader.issued.scope.permit
            or (current.graph_revision, current.graph_epoch) !=
                (reader.graph_stamp[0].graph_revision, reader.graph_stamp[1].revision)
            or current.graph_incarnation != reader.graph_stamp[0].requirements.graph_incarnation
            or current.activation_generation != frame.activation_generation
            or activation.key != _activation_key(ns)
            or frame.snapshot.get(activation.key) is not activation
            or grant is None or not grant.valid
            or value["namespace"] != {"bot_id": ns.bot_id, "persona_id": ns.persona_id}
            or value["head_id"] != current.role_head_id
            or value["head_id"] != value["plan_id"] + "@" + str(value["plan_version"])
            or value["activation_generation"] != current.activation_generation
            or value["graph_incarnation"] != origin
            or grant.value["graph_incarnation"] != origin
            or value["owner_grant_id"] != grant.value["grant_id"]
            or value["owner_grant_revision"] != grant.revision
            or value["authorization_revision"] != current.owner_authorization_revision
            or current.owner_authorization_head.removeprefix("sha256:") != frame.owner_guard.owner_head_digest):
        raise AuthorityUnavailable("growth borrowed control differs from its actual Self/Owner/activation witness")
    return ActiveRoleHeadControlV3(ns, current.role_head_id,
        AtomKey(Owner("persona", *ns.as_tuple), "d01.persona_plan.v1", value["plan_id"]),
        value["plan_version"], (GraphVersion(activation.key, activation.revision),
            GraphVersion(grant.key, grant.revision)), current.graph_epoch, current.owner_authorization_revision)
