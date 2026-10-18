"""Prospective D02 quotes and whole-method capacity, before D01 ordering.

No D01 evaluator, Decision, reserve, worker or model call is manufactured here.
The installed counter runs outside the Graph transaction and its signed result
is accepted only against the same current input, Owner, budget and read scope.
"""
from dataclasses import replace
import json
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d02.method_readiness_v1 import (OPERATION, FULL_METHOD, SAMPLE_METHOD, METHODS, DIMENSIONS,
    QuoteCurrentMethodChoicesRequestV1, MethodReadinessOriginalV1, MethodPhasePriceBoundV1,
    MethodChoiceQuoteEvidenceV1, MethodReadinessEvidenceV1)
from ..domains.d08.personal_candidate_v1 import CurrentPersonalNeedQualificationV1, ArtifactPhaseCandidateBindingV3
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import canonical_digest
from .d01_production_operations_v1 import (CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1,
    raw_head_value_v1, waiting_stage_v1)
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d08_personal_candidate_v1 import (InstalledPersonalCandidateReadersV1, CurrentArtifactTaskChoiceRequestV2,
    read_current_artifact_task_choice_material_v2, _plan_goal, _artifact_scope,
    prospective_personal_candidate_input_v1, prospective_personal_future_identity_v1,
    actual_personal_phase_price_ceiling_v1)
from .budget import get_budget_lease, require_budget_family_admissible
from .issuers import ResourceQuote
from .jobs import get_job
from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, require_current_foreground_responsibility_v1
from .d11_life_preparation_v1 import _read
from .d11_offline_originals_v1 import _utc


def _readers(value):
    if type(value) is not InstalledPersonalCandidateReadersV1:
        raise TypeError("method readiness uses the actual installed personal candidate readers")
    return value.current()


def method_readiness_operation_id_v1(task, plan_head):
    return "d02-method-readiness:" + canonical_digest((task, plan_head))[:48]


def _choice(db, namespace, request, readers):
    if type(request) is not QuoteCurrentMethodChoicesRequestV1 or request.task.namespace != namespace:
        raise TypeError("exact same-namespace actual method task selector required")
    value = read_current_artifact_task_choice_material_v2(db, namespace=namespace,
        request=CurrentArtifactTaskChoiceRequestV2(request.task), installed_readers=readers)
    prepare = value.prepare_request
    if (len(prepare.bindings) != 2 or any(type(binding) is not ArtifactPhaseCandidateBindingV3 or binding.phase_index != 0 for binding in prepare.bindings)
            or {binding.method_ref for binding in prepare.bindings} != METHODS):
        raise MissingProductionOriginalV1("actual_two_legal_method_phase_zero_bindings")
    from .d07_task_history_v1 import read_adopted_task_no_search_v1
    no_search = read_adopted_task_no_search_v1(db, namespace=namespace, c02_operation_id=request.task.c02_operation_id)
    if no_search is not None:
        prepare = replace(prepare, need_qualification_original_ref="d07-current:" + no_search[1]["original_digest"][:48])
    return value, prepare


def _need(db, read, readers, prepare, task):
    from .d07_task_history_v1 import (_prior_need, read_adopted_task_no_search_v1,
        require_current_task_no_search_v1)
    from .d06_ingress_recall_v1 import (InstalledIngressRecallReadersV1, PrepareIngressRecallNeedRequestV1,
        stage_ingress_recall_need_in_transaction_v1, NEED_OPERATION, LEDGER_TYPES)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d07 import IngressRecallNeedV1
    ns = read.frame.envelope.authority.namespace
    prior, origin = _prior_need(db, ns, task.c02_operation_id)
    no_search = read_adopted_task_no_search_v1(db, namespace=ns, c02_operation_id=task.c02_operation_id)
    if no_search is not None:
        value, authenticated, actual = require_current_task_no_search_v1(db, frame=read.frame,
            request=no_search[0].request, installed_readers=readers)
        need, deadline = value.need, value.original_deadline_utc
    else:
        current = stage_ingress_recall_need_in_transaction_v1(db, frame=read.frame,
            request=PrepareIngressRecallNeedRequestV1(prior.c02_operation_id, prior.source_ref, prior.cycle_job_ref, prior.policy_digest),
            installed_readers=InstalledIngressRecallReadersV1(readers.issuer, readers.bundle))
        raw = json.loads(current.original_payload_json)
        need = decode_typed_production_value_v1(raw["provenance"]["need"], IngressRecallNeedV1)
        if need != prior or need.triggers or need.required_checks or need.missing_items:
            raise MissingProductionOriginalV1("complete_current_method_readiness_Need")
        authenticated = read.original("d07-current:" + origin["original_digest"][:48],
            kind="d07.current-" + NEED_OPERATION, digest=origin["original_digest"])
        actual, deadline = origin, prior.deadline_utc
    job = get_job(db, AtomKey.from_token(task.cycle_job_ref).name)
    from .d11_types import job_graph_write
    if read.head(db, task.cycle_job_ref, required=True).value != job_graph_write(job).value:
        raise MissingProductionOriginalV1("current_method_readiness_foreground_job")
    continuation = foreground_cycle_from_wire_v1(job.continuation)
    responsibility = require_current_foreground_responsibility_v1(db, namespace=ns, job=job,
        installed_bundle=readers.bundle, issuer=readers.issuer, owner_guard=read.frame.owner_guard,
        purpose=read.frame.envelope.authority.purpose, audiences=read.frame.envelope.authority.audience, now_utc=read.frame.now_utc)
    if (responsibility is None or responsibility.digest != need.responsibility_digest
            or (need.c02_operation_id, need.cycle_job_ref, job.activity_id, job.budget_ref) !=
                (task.c02_operation_id, task.cycle_job_ref, read.frame.envelope.identity.activity_id, read.frame.envelope.parent_budget_lease_ref)
            or job.phase != "running" or job.lease_holder != read.frame.envelope.authority.actor
            or job.cancel_epoch != need.cancel_generation or continuation.pending_effect_refs or continuation.wait is not None
            or any(attempt.slot in {"C4", "C5", "C6"} for attempt in continuation.call_plan.attempts)):
        raise MissingProductionOriginalV1("actual_running_method_predecision_cycle_without_prior_generation")
    if no_search is None:
        from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1, read_current_ingress_recall_attempt_v1
        from .d07_execution_v1 import read_prepared_d07_execution_v1, require_current_d07_content_reads_v1
        from .d07_ingress_recall_result_v1 import read_adopted_ingress_recall_routing_v1, ADOPT_OPERATION
        ids = ingress_recall_model_ids_v1(ns, task.c02_operation_id)
        prepared = read_prepared_d07_execution_v1(db, readers.issuer, ns, ids["job"])
        attempts = tuple(a for a in continuation.call_plan.attempts if a.slot == "C3" and a.call_id == ids["call"])
        if len(attempts) != 1 or prepared is None:
            raise MissingProductionOriginalV1("actual_semantic_resolution_before_method_readiness")
        attempt = read_current_ingress_recall_attempt_v1(db, namespace=ns, continuation=continuation, attempt=attempts[0], issuer=readers.issuer)
        if attempt != attempts[0] or attempt.state != "completed":
            raise MissingProductionOriginalV1("actual_completed_method_readiness_C3")
        require_current_d07_content_reads_v1(db, prepared, issuer=readers.issuer)
        for row in prepared.read_rows: read.head(db, row.ref)
        routing = read_adopted_ingress_recall_routing_v1(db, namespace=ns, c02_operation_id=task.c02_operation_id, issuer=readers.issuer)
        adopted = read_adopted_domain_operation_v1(db, ns, ids["adopt"])
        if (routing is None or adopted is None or routing["stop_reason"] != "no_history_needed"
                or routing["need_digest"] != canonical_digest(prior) or routing["cycle_job_ref"] != task.cycle_job_ref
                or routing["prepared_digest"] != prepared.digest or routing["execution_ref"] != attempt.terminal_ref
                or routing["required_checks"] or routing["missing_items"] or routing["meaningful_unknowns"]):
            raise MissingProductionOriginalV1("actual_current_C3_no_history_needed_not_a_manual_flag")
        read.original(ids["adopt"], kind="d07.current-" + ADOPT_OPERATION, digest=adopted["original_digest"])
    if authenticated.original_ref != prepare.need_qualification_original_ref:
        raise ValueError("readiness cannot substitute another actual Need")
    keys = {v.key for v in actual["read_versions"]} | {AtomKey.from_token(prepare.plan_ref), AtomKey.from_token(prepare.goal_ref)}
    versions = tuple(GraphVersion(key, read.head(db, key).revision) for key in sorted(keys, key=lambda key:key.token))
    coverage = tuple(page for page in read.frame.query_coverage if page.type_id in LEDGER_TYPES)
    need_qualification = CurrentPersonalNeedQualificationV1(authenticated,
        GraphVersion(AtomKey.from_token(prepare.plan_ref), prepare.expected_plan_revision),
        GraphVersion(AtomKey.from_token(prepare.goal_ref), prepare.expected_goal_revision), versions, coverage,
        True, False, (), min(deadline, responsibility.deadline_utc))
    return need_qualification, continuation.call_plan


def _facts(db, frame, request, readers):
    read = CurrentDomainReadV1(frame); read.check(db); ns = frame.envelope.authority.namespace
    material, prepare = _choice(db, ns, request, readers)
    plan_atom, goal_atom, plan, goal, nodes = _plan_goal(db, read, prepare, installed_readers=readers)
    need, call_plan = _need(db, read, readers, prepare, request.task)
    require_budget_family_admissible(db, frame.envelope.parent_budget_lease_ref)
    grant = readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    lease = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    if lease.state != "active" or (lease.bot_id, lease.persona_id) != ns.as_tuple:
        raise MissingProductionOriginalV1("current_original_method_readiness_parent_budget")
    from .artifact_task_text_extent_v1 import require_current_artifact_task_text_extent_v1
    from .artifact_phase_postconditions_v1 import require_current_artifact_phase_postcondition_policy_v1, authorize_current_task_predecision_v2
    frozen = []
    for binding in prepare.bindings:
        scope, root = _artifact_scope(db, read, readers, binding, plan)
        require_current_artifact_task_text_extent_v1(db, frame=frame, binding=binding, goal_ref=prepare.goal_ref, installed_readers=readers)
        policy = require_current_artifact_phase_postcondition_policy_v1(db, frame=frame, binding=binding,
            goal_ref=prepare.goal_ref, plan_ref=prepare.plan_ref, installed_readers=readers)
        authorize_current_task_predecision_v2(db, frame=frame, task=request.task,
            operation="prepare_personal_candidates_v1", method_ref=binding.method_ref, installed_readers=readers)
        node = nodes[binding.node_id]
        if node.pending_original_effects or node.carried_forward_verified:
            raise MissingProductionOriginalV1("unstarted_method_candidate_without_unknown_prior_effect")
        deadline = min(need.original_deadline_utc, policy.original_deadline_utc, grant.valid_until_utc,
            _utc(scope.valid_until_utc).timestamp(), _utc(root.valid_until_utc).timestamp(), frame.envelope.deadline_utc)
        from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_predicate_deadline_v2
        predicate_deadline=resolve_artifact_task_predicate_deadline_v2(db,namespace=ns,
            root_registration_ref=root.registration_ref,goal_ref=prepare.goal_ref,
            original_predicate_deadline_utc=goal.satisfaction_predicate.valid_until,issuer=readers.issuer,
            bundle=readers.bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
            parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref)
        if predicate_deadline is not None:deadline=min(deadline,predicate_deadline)
        if goal.deadline_ref is not None:
            observed_deadline = read.head(db, goal.deadline_ref, required=True).value.get("deadline_utc")
            if type(observed_deadline) is str: observed_deadline = _utc(observed_deadline).timestamp()
            import math
            if type(observed_deadline) not in {int, float} or not math.isfinite(observed_deadline):
                raise MissingProductionOriginalV1("actual_established_method_goal_deadline")
            deadline = min(deadline, observed_deadline)
        if frame.now_utc >= deadline: raise MissingProductionOriginalV1("original_method_readiness_deadline")
        encoded, digest = prospective_personal_candidate_input_v1(db, read, request=prepare, binding=binding,
            plan_atom=plan_atom, goal_atom=goal_atom, need=need, deadline=deadline, installed_readers=readers)
        future = prospective_personal_future_identity_v1(ns, prepare, binding, plan_atom, deadline, lease.lease_id)
        frozen.append((binding, encoded, digest, future))
    return read, material, prepare, plan, goal, nodes, need, call_plan, grant, lease, tuple(frozen)


def freeze_current_method_readiness_count_materials_v1(db, *, frame, request, installed_readers):
    return _facts(db, frame, request, _readers(installed_readers))[-1]


def _phase_bounds(policy, method_ref):
    from ..model_broker.artifact_draft_v1 import PHASE_TOKEN_CEILINGS_V2, artifact_draft_phase_sequence_v2
    result = []
    for kind in artifact_draft_phase_sequence_v2(method_ref):
        if kind not in {"tone_sample", "full"}: continue
        inp, out = next((i, o) for k, i, o in PHASE_TOKEN_CEILINGS_V2 if k == kind)
        ceiling = dict(policy.quote_ceiling)
        ceiling["input_tokens"] = min(ceiling["input_tokens"], inp)
        ceiling["output_tokens"] = min(ceiling["output_tokens"], out, policy.max_output_tokens)
        ceiling["model_tokens"] = min(ceiling["model_tokens"], ceiling["input_tokens"] + ceiling["output_tokens"])
        result.append(MethodPhasePriceBoundV1(kind, tuple(sorted(ceiling.items()))))
    return tuple(result)


def stage_quote_current_method_choices_v1(db, *, frame, request, installed_readers):
    readers = _readers(installed_readers)
    try:
        read, material, prepare, plan, goal, nodes, need, call_plan, grant, lease, frozen = _facts(db, frame, request, readers)
        if frame.envelope.identity.operation_id != method_readiness_operation_id_v1(request.task, material.plan_head):
            raise ValueError("method readiness changed its original task/Plan operation identity")
        from .d02_artifact_phase_price_v1 import (InstalledArtifactPhasePriceReaderV1,
            read_current_artifact_phase_price_policy_v1, _installed_phase_count_policy_v1)
        policy, _, _ = read_current_artifact_phase_price_policy_v1(db, frame=frame, installed_readers=readers)
        if type(readers.phase_price_reader) is not InstalledArtifactPhasePriceReaderV1:
            raise MissingProductionOriginalV1("actual_installed_signed_method_readiness_counter")
        from .foreground_call_plan_v1 import require_protected_reply_budget_v1, SLOTS
        require_protected_reply_budget_v1(db, namespace=request.task.namespace, plan=call_plan,
            issuer=readers.issuer, now_utc=frame.now_utc, installed_bundle=readers.bundle, owner_guard=frame.owner_guard)
        from .foreground_call_plan_v1 import _read_actual_reply_allocation_v1
        _, reply, _, _ = _read_actual_reply_allocation_v1(db, namespace=request.task.namespace,
            c02_operation_id=request.task.c02_operation_id, source_ref=_read(db, issuer=readers.issuer,
                namespace=request.task.namespace, kind="artifact_task_scope", ref=prepare.bindings[0].activity_scope_ref)[0]["source_ref"],
            issuer=readers.issuer)
        from ..host.authority_profile import AdminArtifactDraftToolScopeV1, AdminArtifactDraftToolScopeV2
        tool = readers.bundle.artifact_draft.tool_scope
        if type(tool) is AdminArtifactDraftToolScopeV2: version_cap = tool.maximum_artifact_version
        elif type(tool) is AdminArtifactDraftToolScopeV1: version_cap = 1
        else: raise MissingProductionOriginalV1("actual_installed_method_file_scope")
        quotes, choices, counts = [], [], []
        for binding, encoded, digest, future in frozen:
            price = readers.phase_price_reader(db=db, frame=frame, binding=binding, plan=plan, goal=goal, need=need,
                prospective_input_json=encoded, prospective_input_digest=digest, future_identity=future)
            ceiling = actual_personal_phase_price_ceiling_v1(price, binding.phase_kind)
            if (price.candidate_ref, price.parameter_digest, price.serialized_input_digest) != (binding.candidate_ref, binding.digest, digest):
                raise ValueError("readiness price changed its actual prospective candidate input")
            read.original(price.original.original_ref, kind=price.original.kind, digest=price.original.original_digest)
            if price.installed_policy not in frame.installed_policy_refs:
                raise MissingProductionOriginalV1("current_method_readiness_price_policy_pin")
            bounds = _phase_bounds(policy, binding.method_ref)
            total = {dim:sum(dict(bound.ceiling)[dim] for bound in bounds) for dim in DIMENSIONS}
            physical = len(call_plan.attempts) + len(bounds) + 2
            auxiliary = sum(SLOTS[a.slot][3] for a in call_plan.attempts) + len(bounds)
            inputs = sum(a.input_ceiling for a in call_plan.attempts) + total["input_tokens"] + dict(reply.generation_ceiling)["input_tokens"] + dict(reply.review_ceiling)["input_tokens"]
            outputs = sum(a.output_ceiling for a in call_plan.attempts) + total["output_tokens"] + dict(reply.generation_ceiling)["output_tokens"] + dict(reply.review_ceiling)["output_tokens"]
            slots_fit = physical <= 6 and auxiliary <= 2 and inputs <= 48000 and outputs <= 8000
            if binding.method_ref == SAMPLE_METHOD and any(a.slot == "C3" for a in call_plan.attempts): slots_fit = False
            node_ceiling = dict(nodes[binding.node_id].cost_ceiling)
            budget_fits = (price.work_kind in grant.allowed_work_kinds and all(amount <= lease.available(dim) for dim, amount in total.items())
                and all(amount <= grant.max_ceiling.get(dim, -1) for bound in bounds for dim, amount in bound.ceiling)
                and (not node_ceiling or all(amount <= node_ceiling.get(dim, -1) for dim, amount in total.items())))
            ref = "method-readiness-quote:" + canonical_digest((request.task.namespace, frame.envelope.identity.operation_id, binding.digest, digest))[:48]
            quote = ResourceQuote(ref, 1, *request.task.namespace.as_tuple, future.activity_id,
                future.model_prepare_operation_id, None, lease.lease_id, price.work_kind, "method-readiness-input:" + digest[:48],
                future.deadline_utc, price.resource_ref, None, (), (), ceiling, None, future.deadline_utc)
            quotes.append(quote)
            choices.append(MethodChoiceQuoteEvidenceV1(binding.method_ref, binding.digest, ref, canonical_digest(quote),
                price, bounds, tuple(sorted(total.items())), physical, auxiliary, inputs, outputs, budget_fits, slots_fit))
            counts.append(readers.phase_price_reader.count_provenance_for_candidate_v1(binding=binding, prospective_input_digest=digest))
        sample = next(c for c in choices if c.method_ref == SAMPLE_METHOD)
        sample_binding = next(b for b in prepare.bindings if b.method_ref == SAMPLE_METHOD)
        initial_version = sample_binding.target.expected_prior_version
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1, _decode
        row = _read(db, issuer=readers.issuer, namespace=request.task.namespace, kind="artifact_task_scope", ref=sample_binding.activity_scope_ref)
        scope = _decode(row[0], IngressArtifactTaskScopeOriginalV1)
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
        if type(scope) is IngressArtifactTaskScopeOriginalV3:version_cap=min(version_cap,scope.continuation_authorization.maximum_artifact_version)
        summary = MethodReadinessOriginalV1(request.task.c02_operation_id, sample_binding.activity_scope_ref,
            canonical_digest(plain_v1(scope)), prepare.goal_ref, prepare.expected_goal_revision, lease.lease_id,
            min(q.valid_until_utc for q in quotes), tuple(sorted(METHODS)),
            {"local_sample_permitted": initial_version + 2 <= version_cap,
                "budget_deadline_feasible": sample.budget_fits and sample.slots_fit,
                "fact_permission_gap": False}, tuple(q.quote_id for q in quotes))
        counter = _installed_phase_count_policy_v1(readers)
        evidence = MethodReadinessEvidenceV1(request.task.namespace, request.task, material.plan_head,
            need.original.original_ref, need.original.original_digest, canonical_digest(plain_v1(call_plan)),
            canonical_digest((lease, grant)), counter.source_scope, tuple(choices))
        stage = stage_result_v1(frame, "d02", OPERATION, request,
            provenance={"method_readiness": summary, "method_quote_evidence": evidence, "artifact_phase_counts": tuple(counts)})
        for quote in quotes: readers.resource_issuer.issue_quote(db, quote)
        return stage
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d02", OPERATION, request, missing)


def read_plan_current_method_readiness_v1(db, *, namespace, activity_id, operation_kind, request, installed_readers):
    if operation_kind != OPERATION: raise ValueError("unregistered method readiness operation")
    readers = _readers(installed_readers); _, prepare = _choice(db, namespace, request, readers)
    keys = [owner_grant_key(*namespace.as_tuple), AtomKey.from_token(prepare.plan_ref), AtomKey.from_token(prepare.goal_ref), AtomKey.from_token(request.task.cycle_job_ref)]
    roots, originals, types = [], [prepare.need_qualification_original_ref], []
    plan = raw_head_value_v1(db, namespace, AtomKey.from_token(prepare.plan_ref))
    if plan:
        roots.extend(plan["source_refs"]); keys.extend(AtomKey.from_token(v["ref"]) for v in plan["fact_versions"])
    goal = raw_head_value_v1(db, namespace, AtomKey.from_token(prepare.goal_ref))
    if goal and goal["deadline_ref"] is not None: keys.append(AtomKey.from_token(goal["deadline_ref"]))
    from .d07_task_history_v1 import _prior_need, read_adopted_task_no_search_v1
    from .d06_ingress_recall_v1 import LEDGER_TYPES
    need, origin = _prior_need(db, namespace, request.task.c02_operation_id)
    types.extend(LEDGER_TYPES); keys.extend(v.key for v in origin["read_versions"]); roots.append(need.source_ref)
    originals.append("d07-current:" + origin["original_digest"][:48])
    no_search = read_adopted_task_no_search_v1(db, namespace=namespace, c02_operation_id=request.task.c02_operation_id)
    if no_search is not None:
        keys.extend(v.key for v in no_search[1]["read_versions"])
        originals.extend((no_search[0].c1_original_ref, no_search[0].prior_need_ref, no_search[0].request.task_scope_ref))
    else:
        from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
        from .d07_execution_v1 import read_prepared_d07_execution_v1
        ids = ingress_recall_model_ids_v1(namespace, request.task.c02_operation_id)
        prepared = read_prepared_d07_execution_v1(db, readers.issuer, namespace, ids["job"])
        if prepared is not None:
            keys.extend(AtomKey.from_token(row.ref) for row in prepared.read_rows)
            roots.extend(row.ref for row in prepared.read_rows if AtomKey.from_token(row.ref).type_name == "memory.source")
            originals.append(ids["adopt"])
    for binding in prepare.bindings:
        originals.extend((binding.activity_scope_ref, binding.task.root_registration_ref))
        row = _read(db, issuer=readers.issuer, namespace=namespace, kind="artifact_task_scope", ref=binding.activity_scope_ref)
        if row is not None:
            scope = row[0]; originals.extend((scope["c1_intent_ref"], scope["objective_ref"], scope["approval_original_ref"]))
            producer = read_adopted_domain_operation_v1(db, namespace, row[1])
            originals.append(producer["receipt"].operation_id); keys.extend(v.key for v in producer["read_versions"])
    from .artifact_task_text_extent_v1 import read_plan_personal_candidate_text_extents_v1
    from .d02_artifact_phase_price_v1 import InstalledArtifactPhasePriceReaderV1
    for extra in (read_plan_personal_candidate_text_extents_v1(db, namespace=namespace, request=prepare, installed_readers=readers),
            InstalledArtifactPhasePriceReaderV1(readers).read_plan_inputs_v1(db=db, namespace=namespace, activity_id=activity_id, request=prepare)):
        types.extend(extra.fixed_type_ids); keys.extend(extra.exact_keys); roots.extend(extra.source_roots); originals.extend(extra.required_original_refs)
    return production_read_plan_v1(types, keys, roots, originals)


def read_current_method_readiness_quote_original_v1(db, *, namespace, ref, issuer):
    if not ref.startswith("method-readiness-quote:"): return None
    rows = db.execute("SELECT operation_id FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND domain='d02' AND operation_kind=? "
        "AND EXISTS(SELECT 1 FROM json_each(original_payload_json,'$.provenance.method_readiness.quote_original_refs') WHERE value=?) LIMIT 2",
        (*namespace.as_tuple, OPERATION, ref)).fetchall()
    if len(rows) != 1: return None
    original = read_adopted_domain_operation_v1(db, namespace, rows[0][0])
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    evidence = decode_typed_production_value_v1(original["payload"]["provenance"]["method_quote_evidence"], MethodReadinessEvidenceV1)
    choices = tuple(c for c in evidence.choices if c.quote_original_ref == ref)
    if len(choices) != 1 or original["payload"]["coverage"] != "complete": return None
    quote = issuer.resource_issuer.original_signed_quote(db, ref, 1)
    if (quote.bot_id, quote.persona_id) != namespace.as_tuple or canonical_digest(quote) != choices[0].quote_digest:
        raise ValueError("method readiness quote changed its actual signed original")
    return ProductionOriginalRefV1("d02.method-readiness-quote", ref, canonical_digest(quote))


def require_current_method_readiness_v1(db, *, frame, operation_id, issuer):
    read = CurrentDomainReadV1(frame); read.check(db)
    origin = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, operation_id)
    if origin is None or (origin["domain"], origin["operation_kind"]) != ("d02", OPERATION) or origin["payload"]["coverage"] != "complete":
        raise MissingProductionOriginalV1("actual_adopted_method_readiness")
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    summary = decode_typed_production_value_v1(origin["payload"]["provenance"]["method_readiness"], MethodReadinessOriginalV1)
    evidence = decode_typed_production_value_v1(origin["payload"]["provenance"]["method_quote_evidence"], MethodReadinessEvidenceV1)
    for version in origin["read_versions"]:
        if read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_method_readiness_Graph_inputs")
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    for raw_page in origin["payload"]["query_coverage"]:
        page = decode_typed_production_value_v1(raw_page, ProductionQueryCoverageV1)
        current = read.complete_inventory(db, page.type_id)
        if not page.complete or tuple(GraphVersion(atom.key, atom.revision) for atom in current) != page.row_versions:
            raise MissingProductionOriginalV1("current_complete_method_readiness_negative_scope")
    lease = get_budget_lease(db, summary.parent_budget_lease_ref); grant = issuer.current_budget_grant(db, lease.lease_id)
    require_budget_family_admissible(db, lease.lease_id)
    cycle = foreground_cycle_from_wire_v1(get_job(db, AtomKey.from_token(evidence.task.cycle_job_ref).name).continuation)
    if (origin["payload"]["owner_guard"] != plain_v1(frame.owner_guard) or frame.now_utc >= summary.valid_until_utc
            or summary.parent_budget_lease_ref != frame.envelope.parent_budget_lease_ref
            or evidence.parent_budget_scope_digest != canonical_digest((lease, grant))
            or evidence.call_plan_digest != canonical_digest(plain_v1(cycle.call_plan))):
        raise MissingProductionOriginalV1("current_method_readiness_Owner_clock_parent_budget_and_slots")
    for choice in evidence.choices:
        if choice.first_phase_price.installed_policy not in frame.installed_policy_refs:
            raise MissingProductionOriginalV1("current_method_readiness_installed_price_pin")
        original = read_current_method_readiness_quote_original_v1(db, namespace=evidence.namespace, ref=choice.quote_original_ref, issuer=issuer)
        if original is None: raise MissingProductionOriginalV1("actual_signed_method_readiness_quote")
        read.original(original.original_ref, kind=original.kind, digest=original.original_digest)
    return summary, evidence, origin


from contextlib import contextmanager
from dataclasses import dataclass

_COUNT_KEY = object()
_ACTIVE_COUNTS = {}


@dataclass(frozen=True, slots=True, init=False)
class MethodReadinessCountMaterialV1:
    runtime: object
    issued: object
    operation_id: str
    request: QuoteCurrentMethodChoicesRequestV1
    scope: object
    readers: object
    command_deadline_utc: float
    count_materials: tuple

    def __init__(self, key, **values):
        if key is not _COUNT_KEY: raise TypeError("readiness count material requires its real private foreground fence")
        for name in self.__dataclass_fields__: object.__setattr__(self, name, values[name])


def _freeze_foreground_counts(runtime, db, *, issued, operation, request, scope, external_originals, now_utc, process_lease, capability):
    import time, secrets
    from datetime import datetime
    from ..runtime_contracts import (AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch,
        RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_serialize)
    from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
    from .d02_artifact_phase_price_v1 import read_current_artifact_phase_price_policy_v1, freeze_artifact_phase_count_request_in_transaction_v1
    from ..model_broker.artifact_phase_count_v1 import artifact_phase_prospective_provider_request_v1
    from ..model_broker.artifact_draft_v1 import PHASE_TOKEN_CEILINGS_V2
    graph = runtime.graph
    evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
    selector = evidence.request
    grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, selector.parent_budget_lease_ref)
    require_budget_family_admissible(db, grant.lease_id)
    _, epoch = graph._v2_graph_stamp(selector.namespace)
    versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' AND kind IN ('scheme','operator','policy')", selector.namespace.as_tuple).fetchall())
    if set(versions) != {"scheme", "operator", "policy"}: raise MissingProductionOriginalV1("current_method_quote_guard_heads")
    deadline = min(selector.requested_deadline_utc, grant.valid_until_utc,
        datetime.fromisoformat(evidence.valid_until_utc.replace("Z", "+00:00")).timestamp())
    authority = AuthorityContext(evidence.current_self.self_entity_ref, operation.domain, capability, selector.namespace,
        tuple(sorted(graph._GraphCoordinator__leases[process_lease][5])), selector.purpose, selector.audiences,
        grant.policy_ref, evidence.current_self.activation_generation)
    envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(selector.activity_id, None, selector.operation_id,
        operation.operation_kind, selector.operation_id, canonical_digest({"input_refs": []})), authority,
        VersionGuard((), (QueryEpoch(selector.namespace, "namespace", epoch.revision),), evidence.access_epoch, evidence.delete_epoch,
            graph._GraphCoordinator__store._registry.catalogue_hash, versions["scheme"], versions["operator"], versions["policy"], (), (), ()),
        SourceQualification((), "derived", None, now_utc, "inference", "ineligible", None, "not_applicable"), (),
        selector.parent_budget_lease_ref, deadline, time.monotonic() + deadline - now_utc, "foreground-current:" + selector.operation_id, ())
    if runtime._active_foreground_issuance_v1 is not None or runtime._active_foreground_process_lease_v1 is not None:
        raise ValueError("another actual foreground compilation is already active")
    runtime._active_foreground_issuance_v1 = issued; runtime._active_foreground_process_lease_v1 = process_lease
    try:
        frame, stage, readers = runtime.compile_foreground_in_transaction(db, operation=operation, request=request,
            envelope=envelope, scope=scope, issued=issued, now_utc=now_utc, external_originals=external_originals)
        material = freeze_current_method_readiness_count_materials_v1(db, frame=frame, request=request, installed_readers=readers)
        policy, _, _ = read_current_artifact_phase_price_policy_v1(db, frame=frame, installed_readers=readers)
        requests = []
        for binding, encoded, digest, future in material:
            output_limit = next(out for kind, _, out in PHASE_TOKEN_CEILINGS_V2 if kind == binding.phase_kind)
            output = min(dict(policy.quote_ceiling)["output_tokens"], policy.max_output_tokens, output_limit)
            body = artifact_phase_prospective_provider_request_v1(model_id=policy.model_id, prospective_input_json=encoded, max_output_tokens=output)
            requests.append(freeze_artifact_phase_count_request_in_transaction_v1(db, frame=frame, binding=binding,
                input_kind="prospective", frozen_material_digest=digest, provider_request_json=canonical_serialize(body),
                original_deadline_utc=future.deadline_utc, nonce=secrets.token_hex(16), installed_readers=readers))
        return frame, readers, tuple(requests)
    finally:
        runtime._active_foreground_issuance_v1 = None; runtime._active_foreground_process_lease_v1 = None


@contextmanager
def method_readiness_counts_for_foreground_fence_v1(runtime, *, issued, operation, request, scope, external_originals, now_utc):
    from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
    from .d02_artifact_phase_price_v1 import (_installed_phase_count_policy_v1,
        install_artifact_phase_price_reader_v1)
    from ..authority_service.artifact_phase_counter_v1 import InstalledArtifactPhaseCounterCommandV1
    from ..runtime_contracts import canonical_serialize
    from .first_ingress_v2 import trusted_upper
    runtime._current()
    if operation.operation_kind != OPERATION or type(request) is not QuoteCurrentMethodChoicesRequestV1:
        raise TypeError("method readiness counter serves its exact named operation")
    graph = runtime.graph; store = graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned(): raise ValueError("method counting starts outside Graph locks/transactions")
    if getattr(runtime, "_active_method_readiness_counts_v1", None) is not None:
        raise ValueError("an actual readiness count fence is already active")
    evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
    process, capability = graph.grant(runtime._bootstrap, actor=evidence.current_self.self_entity_ref,
        issuer_domain=operation.domain, namespace=evidence.request.namespace, domains=evidence.allowed_write_domains,
        activation_generation=evidence.current_self.activation_generation, operation_id=evidence.request.operation_id)
    prior_readers = getattr(runtime, "_personal_candidate_readers_v1", None)
    readers = material = prior_price = None
    try:
        with store._lock:
            store._db.execute("BEGIN")
            try:
                frame, readers, requests = _freeze_foreground_counts(runtime, store._db, issued=issued, operation=operation,
                    request=request, scope=scope, external_originals=external_originals, now_utc=now_utc,
                    process_lease=process, capability=capability)
            finally: store._db.rollback()
        policy = _installed_phase_count_policy_v1(readers); command = InstalledArtifactPhaseCounterCommandV1(policy)
        counted = []
        for count_request in requests:
            now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
            envelope = command.count_outside_graph_transaction_v1(db=store._db, request=count_request, now_utc=now)
            counted.append((count_request, canonical_serialize(envelope)))
        prior_price = readers.phase_price_reader
        readers.phase_price_reader = install_artifact_phase_price_reader_v1(readers=readers, count_materials=tuple(counted))
        runtime._personal_candidate_readers_v1 = readers
        material = MethodReadinessCountMaterialV1(_COUNT_KEY, runtime=runtime, issued=issued,
            operation_id=evidence.request.operation_id, request=request, scope=scope, readers=readers,
            command_deadline_utc=frame.envelope.deadline_utc, count_materials=tuple(counted))
        _ACTIVE_COUNTS[id(material)] = material; runtime._active_method_readiness_counts_v1 = material
        yield material
    finally:
        if material is not None:
            _ACTIVE_COUNTS.pop(id(material), None); readers.phase_price_reader = prior_price
        runtime._active_method_readiness_counts_v1 = None; runtime._personal_candidate_readers_v1 = prior_readers
        graph.release_authority_lease(runtime._bootstrap, process)


def current_method_readiness_count_deadline_v1(runtime, *, issued, operation_id, request, scope):
    value = getattr(runtime, "_active_method_readiness_counts_v1", None)
    if (type(value) is not MethodReadinessCountMaterialV1 or _ACTIVE_COUNTS.get(id(value)) is not value
            or value.runtime is not runtime or value.issued is not issued or value.operation_id != operation_id
            or value.request != request or value.scope != scope):
        raise MissingProductionOriginalV1("actual_same_private_method_readiness_count_fence")
    return value.command_deadline_utc


METHOD_FOREGROUND_OPERATIONS = frozenset({OPERATION, "adopt_current_task_no_search_v1", "adopt_current_c1_method_conditions_v1"})


def qualify_current_method_foreground_v1(db, *, request, job, continuation, issuer, installed_bundle,
        current_self, owner_guard, now, atom):
    """Independent Authority reconstructs exact selector bodies, without C1-body inference."""
    from ..authority_service.contract import AuthorityUnavailable
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    from .ingress_artifact_task_scope_v1 import (IngressArtifactTaskScopeOriginalV1, IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3,
        ArtifactTaskObjectiveV1, _decode, task_scope_ref_v1)
    from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
    from .d07_task_history_v1 import AdoptCurrentTaskNoSearchRequestV1, task_no_search_operation_id_v1
    from .d07_method_conditions_v1 import AdoptCurrentC1MethodConditionsRequestV1
    from .foreground_call_plan_v1 import ForegroundCallPlanV1
    if (request.operation_kind not in METHOD_FOREGROUND_OPERATIONS or job is None
            or type(continuation.call_plan) is not ForegroundCallPlanV1 or request.purpose != "consolidation"
            or request.draft_root_registration_ref is None):
        raise AuthorityUnavailable("method facts require the actual predecision task foreground")
    task = artifact_draft_task_selector_v1(request.namespace, c02_operation_id=request.c02_operation_id,
        root_registration_ref=request.draft_root_registration_ref)
    scope_ref = task_scope_ref_v1(task.root_registration_ref)
    row = _read(db, issuer=issuer, namespace=request.namespace, kind="artifact_task_scope", ref=scope_ref)
    if row is None: raise AuthorityUnavailable("actual signed method task scope is absent")
    scope = _decode(row[0], IngressArtifactTaskScopeOriginalV1)
    if type(scope) not in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3} or scope.objective_ref is None:
        raise AuthorityUnavailable("method facts need their actual approved Goal task")
    stored = _read(db, issuer=issuer, namespace=request.namespace, kind="artifact_task_objective", ref=scope.objective_ref)
    if stored is None or canonical_digest(stored[0]) != scope.objective_digest:
        raise AuthorityUnavailable("method facts lost their signed task objective")
    objective = _decode(stored[0], ArtifactTaskObjectiveV1)
    goal = atom(objective.goal_ref)
    revision = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (objective.goal_ref,)).fetchone()[0]
    root = scope.root; installation = installed_bundle.installation_policy
    if (scope.c02_operation_id != request.c02_operation_id or scope.source_ref != request.cue_source_ref
            or request.cycle_job_ref != task.cycle_job_ref or job.budget_ref != request.parent_budget_lease_ref
            or goal["state"] != "active" or goal["revision"] != revision
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
                (owner_guard.grant_ref, owner_guard.grant_revision, owner_guard.grant_digest)
            or (root.installation_id, root.manifest_digest) != (installation.installation_id, installation.manifest_digest)):
        raise AuthorityUnavailable("method facts changed actual task/Goal/Owner/root/budget")
    sources = {scope.source_ref}
    if request.operation_kind == "adopt_current_task_no_search_v1":
        if scope.task_kind != "draft_then_corrected_revision" or any(a.slot == "C3" for a in continuation.call_plan.attempts):
            raise AuthorityUnavailable("no-search cannot replace a continuation or an actual C3")
        body = AdoptCurrentTaskNoSearchRequestV1(request.c02_operation_id,request.cue_source_ref,scope_ref,objective.goal_ref,revision)
        expected = task_no_search_operation_id_v1(request.namespace, request.c02_operation_id)
    else:
        from .d08_personal_candidate_v1 import readonly_current_artifact_task_choice_material_v2
        material = readonly_current_artifact_task_choice_material_v2(db, namespace=request.namespace,
            request=CurrentArtifactTaskChoiceRequestV2(task), issuer=issuer)
        if (material.goal_head.key.token, material.goal_head.revision) != (objective.goal_ref, revision):
            raise AuthorityUnavailable("method facts changed the actual current candidate Goal")
        plan = atom(material.plan_head.key); sources.update(plan["source_refs"])
        for binding in material.prepare_request.bindings:
            if binding.prior_content is not None: sources.add(binding.prior_content.source_head.ref)
        if request.operation_kind == OPERATION:
            body = QuoteCurrentMethodChoicesRequestV1(task)
            expected = method_readiness_operation_id_v1(task, material.plan_head)
        else:
            readiness_id = method_readiness_operation_id_v1(task, material.plan_head)
            readiness = read_adopted_domain_operation_v1(db, request.namespace, readiness_id)
            readiness_id = readiness_id if readiness is not None and readiness["payload"]["coverage"] == "complete" else None
            body = AdoptCurrentC1MethodConditionsRequestV1(request.c02_operation_id,scope_ref,objective.goal_ref,revision,readiness_id)
            expected = "foreground-op:" + canonical_digest((request.namespace,request.c02_operation_id,request.operation_kind,body))[:40]
    if (request.operation_id != expected or request.request_digest != foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind),body)):
        raise AuthorityUnavailable("method foreground changed its actual fixed typed selector body")
    from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
    authorization_deadline=resolve_artifact_task_authorization_deadline_v2(db,namespace=request.namespace,
        scope=scope,objective=objective,issuer=issuer,bundle=installed_bundle,owner_guard=owner_guard,
        now_utc=now,parent_budget_lease_ref=request.parent_budget_lease_ref)
    deadline = min(authorization_deadline, _utc(root.valid_until_utc).timestamp())
    if not now < deadline: raise AuthorityUnavailable("method task original deadline expired")
    return sources, deadline
