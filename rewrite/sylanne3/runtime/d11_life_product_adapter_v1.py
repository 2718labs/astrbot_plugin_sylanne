"""Installed Life input and preparation adapters for the shared W01 runtime."""
from dataclasses import replace
import json

from ..graph_types import AtomKey, Owner, owner_grant_key
from ..memory_types import source_key, access_key
from ..runtime_contracts import canonical_digest
from .d01_production_operations_v1 import production_read_plan_v1, table_exists_v1, MissingProductionOriginalV1, waiting_stage_v1
from .d11_life_contract_v1 import RegisteredLifePlanV2, RegisteredLifeOutcomeV2, life_from_wire_v1
from .d11_life_preparation_v1 import TABLE, _read, life_ids_v1, PrepareCurrentLifeRequestV1

LIFE_CURRENT_TYPES = (
    "d03.entity_anchor", "d03.role_binding", "d03.self_identity_mapping.v1", "d01.persona_activation.v1",
    "d01.persona_plan.v1", "d05.boundary_rule", "d08.goal.v1", "d08.commitment.v1",
    "d08.action_intent.v1", "d08.action_schema.v1", "d08.action_outcome.v1",
    "d08.action_cancellation.v1", "d07.attention_ticket.v1", "d07.focus.v1",
    "d12.active_scheme_head.v1",
    "d02.body_state.v1", "d02.body_profile.v1", "d02.reservation.v1", "d02.settlement.v1",
)


def raw_life_original_v1(db, namespace, kind, ref):
    """Locate frozen read inputs; the installed stage separately authenticates them."""
    if not table_exists_v1(db, TABLE):
        return None
    row = db.execute("SELECT payload_json FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone()
    return None if row is None else json.loads(row[0])


def life_inventory_read_inputs_v1(db, *, namespace, scope):
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    from .d01_life_activation_original_v1 import life_activation_read_keys_v1
    keys.extend(life_activation_read_keys_v1(db, namespace))
    inventory = {}
    for type_name in LIFE_CURRENT_TYPES:
        rows = db.execute("SELECT token,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
            (*namespace.as_tuple, type_name)).fetchall()
        if len(rows) > 128:
            raise MissingProductionOriginalV1("complete_life_input_inventory:" + type_name)
        inventory[type_name] = tuple((AtomKey.from_token(token), json.loads(encoded))
            for token, encoded, valid in rows if valid)
    action_ids = {value["action_id"] for key, value in inventory["d08.action_intent.v1"]
        if scope.includes("d08.action_intent.v1", key, value)}
    for type_name, rows in inventory.items():
        for key, value in rows:
            if (value.get("action_id") not in action_ids if type_name == "d08.action_outcome.v1"
                    else not scope.includes(type_name, key, value)):
                continue
            refs = (*value.get("source_refs", ()), *value.get("creation_evidence_refs", ()), *value.get("reason_refs", ()))
            for ref in refs:
                try:
                    key = AtomKey.from_token(ref)
                except ValueError:
                    # Owner configuration is an original locator, not a D06
                    # Source. Its concrete original reader decides its status.
                    originals.append(ref)
                    continue
                if key.type_name == "memory.source":
                    roots.append(ref)
                else:
                    keys.append(key)
                    originals.append(ref)
    return keys, roots, originals


def life_plan_read_inputs_v1(db, *, namespace, plan, originals=(), now_utc=None):
    keys = [owner_grant_key(*namespace.as_tuple)]
    keys.extend(AtomKey.from_token(getattr(plan, name).ref) for name in
        ("project", "recipe", "action_intent", "input_source", "input_access"))
    keys.append(AtomKey(Owner("activity", *namespace.as_tuple, plan.activity_id), "runtime.job", life_ids_v1(plan)["job"]))
    roots = [plan.input_source.ref]
    originals = list(originals)
    from .d11_role_clock_installation_v1 import role_clock_mapping_id_v1
    originals.append(role_clock_mapping_id_v1(namespace))
    if plan.body_effect_request_json is not None:
        contract = json.loads(plan.body_effect_request_json)
        keys.extend(AtomKey.from_token(contract[name]) for name in ("reservation_ref", "settlement_ref"))
        originals.extend(contract[name] for name in ("body_quote_ref", "resource_quote_ref", "effect_policy_ref"))
    from .d11_life_scope_v1 import life_scope_from_action_v1
    scope = life_scope_from_action_v1(db, namespace=namespace, action_ref=plan.action_intent.ref,
        project_ref=plan.project.ref, input_source_ref=plan.input_source.ref, audiences=plan.audiences, now_utc=now_utc)
    inventory_keys, inventory_roots, inventory_originals = life_inventory_read_inputs_v1(db, namespace=namespace, scope=scope)
    keys.extend(inventory_keys)
    roots.extend(inventory_roots)
    originals.extend(inventory_originals)
    return production_read_plan_v1(LIFE_CURRENT_TYPES, keys, roots, originals)


def read_plan_current_life_preparation_v1(db, *, namespace, activity_id, operation_kind, request, now_utc, before_capture_policy=None):
    if operation_kind != "prepare_life" or type(request) is not PrepareCurrentLifeRequestV1:
        raise TypeError("exact installed Life preparation read request required")
    raw = raw_life_original_v1(db, namespace, "plan", request.plan_original_ref)
    if raw is None:
        return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple),), (), (request.plan_original_ref,))
    plan = life_from_wire_v1(raw, RegisteredLifePlanV2)
    if plan.activity_id != activity_id:
        raise ValueError("Life preparation belongs to another actual adopted activity")
    reads = life_plan_read_inputs_v1(db, namespace=namespace, plan=plan, originals=(request.plan_original_ref,), now_utc=now_utc)
    if before_capture_policy is not None:
        from .d04_life_before_original_v1 import life_d04_before_read_inputs_v1
        keys, roots, originals = life_d04_before_read_inputs_v1(
            db, namespace=namespace, policy=before_capture_policy)
        reads = production_read_plan_v1(reads.fixed_type_ids,
            (*reads.exact_keys, *keys), (*reads.source_roots, *roots),
            (*reads.required_original_refs, *originals))
    return reads


def stage_prepare_current_life_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d11_life_preparation_v1 import prepare_current_life_in_transaction_v1
    from .d08_life_admission_v1 import InstalledLifeAdmissionReaderV1
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    graph = installed_readers.role_clock_reader.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    try:
        if assembly is None or assembly.installation_policy.namespace != frame.envelope.authority.namespace:
            raise MissingProductionOriginalV1("actual_installed_life_build")
        inventory = installed_readers.life_execution_inventory
        if inventory is None:
            raise MissingProductionOriginalV1("actual_same_head_life_execution_inventory")
        policy = assembly.installation_policy
        reader = InstalledLifeAdmissionReaderV1(issuer=installed_readers.issuer,
            resource_issuer=graph._GraphCoordinator__d02_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority,
            execution_inventory=inventory, scope=installed_readers.life_scope)
        build = read_installed_d11_life_build_v1(assembly.package_root, policy.manifest_digest)
        return prepare_current_life_in_transaction_v1(db, frame=frame, request=request,
            issuer=installed_readers.issuer, resource_issuer=graph._GraphCoordinator__d02_issuer,
            installation_id=policy.installation_id, authority_id=policy.expected_authority_id,
            authority_namespace=policy.authority_namespace, manifest_digest=policy.manifest_digest,
            job_holder=graph._GraphCoordinator__holder, installed_build=build,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority, admission_reader=reader,
            before_capture_policy=graph._GraphCoordinator__life_d04_before_capture_policy)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "prepare_life", request, missing)


def read_plan_current_life_progress_v2(db, *, namespace, activity_id, request):
    raw = raw_life_original_v1(db, namespace, "outcome", request.activity_outcome_ref)
    if raw is None:
        return None
    outcome = life_from_wire_v1(raw, RegisteredLifeOutcomeV2)
    return life_outcome_read_plan_v2(db, namespace=namespace, activity_id=activity_id,
        outcome=outcome, original_ref=request.activity_outcome_ref, project_ref=request.project_ref)


def life_outcome_read_plan_v2(db, *, namespace, activity_id, outcome, original_ref, project_ref=None):
    plan_raw = raw_life_original_v1(db, namespace, "plan", outcome.plan_original_ref)
    if plan_raw is None:
        raise MissingProductionOriginalV1("actual_registered_life_plan_v2")
    plan = life_from_wire_v1(plan_raw, RegisteredLifePlanV2)
    if plan.activity_id != activity_id or project_ref is not None and plan.project.ref != project_ref:
        raise ValueError("Life V2 outcome belongs to another project/activity")
    base = life_plan_read_inputs_v1(db, namespace=namespace, plan=plan,
        originals=(original_ref, outcome.plan_original_ref, outcome.start_original_ref,
            outcome.terminal_original_ref, outcome.artifact_ref, *outcome.paid_cost_refs))
    owner = Owner("activity", *namespace.as_tuple, activity_id)
    from .d11_life_contract_v1 import D11LifeTerminalV1
    from .d11_life_graph_types_v1 import life_role_segment_key_v1
    from .d10_life_outcome_v2 import life_experience_source_id_v1
    adopted = raw_life_original_v1(db, namespace, "adopted_life", outcome.artifact_ref)
    extra = [AtomKey.from_token(outcome.action_outcome_ref), AtomKey.from_token(outcome.artifact_ref),
        AtomKey(owner, "d10.life_progress.v1", plan.effect_id)]
    if adopted:
        terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
        from .d10_life_progress_provenance_v1 import life_progress_read_keys_v1
        extra.extend(life_progress_read_keys_v1(terminal.binding))
        from .d11_life_fact_provenance_v1 import life_fact_auxiliary_key_v1, PROVENANCE_TYPE, ELIGIBILITY_TYPE
        facts=(AtomKey.from_token(terminal.binding.artifact_ref),life_role_segment_key_v1(terminal.binding,'start'),life_role_segment_key_v1(terminal.binding,'end'))
        extra.extend(life_fact_auxiliary_key_v1(fact,kind) for fact in facts for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE))
        from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
        extra.extend(life_outcome_read_keys_v1(terminal.binding,plan.action_intent.ref))
        source_id = life_experience_source_id_v1(terminal.binding)
        extra.extend((life_role_segment_key_v1(terminal.binding, "start"), life_role_segment_key_v1(terminal.binding, "end"),
            source_key(*namespace.as_tuple, source_id), access_key(*namespace.as_tuple, source_id)))
    extra.extend(AtomKey.from_token(ref) for ref in outcome.paid_cost_refs)
    return production_read_plan_v1(base.fixed_type_ids, (*base.exact_keys, *extra), base.source_roots, base.required_original_refs)


def read_current_life_original_ref_v1(db, *, namespace, original_ref, issuer):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    if not table_exists_v1(db, TABLE):
        return None
    rows = db.execute("SELECT kind FROM " + TABLE + " WHERE bot=? AND persona=? AND original_ref=?",
        (*namespace.as_tuple, original_ref)).fetchall()
    if len(rows) > 1:
        raise ValueError("Life original reference is ambiguous across kinds")
    if rows:
        kind = rows[0][0]
        if kind not in {"plan", "prepared", "outcome", "adopted_life", "experience", "action_admission", "source_note_action", "life_body_preparation"}:
            return None
        value = _read(db, issuer=issuer, namespace=namespace, kind=kind, ref=original_ref)
        return ProductionOriginalRefV1("d11.life_" + kind, original_ref, canonical_digest(value[0]))
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1
    for (artifact_ref,) in db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='adopted_life' ORDER BY original_ref",
            namespace.as_tuple).fetchall():
        adopted = read_adopted_life_original_v1(db, namespace=namespace, result_ref=artifact_ref, issuer=issuer)
        terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
        for kind, value in (("start", terminal.claim), ("terminal", terminal)):
            if value.original_ref == original_ref:
                return ProductionOriginalRefV1("d11.life_" + kind, original_ref, canonical_digest(value))
    return None
