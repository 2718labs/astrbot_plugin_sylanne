"""Exact current Source profile for the first explicit character-labor Body reserve."""
from dataclasses import fields
from types import SimpleNamespace
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d02.character_labor_v1 import CharacterLaborPolicyV1, character_labor_policy_from_wire_v1
from ..graph_types import AtomKey, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .d01_production_operations_v1 import MissingProductionOriginalV1, production_read_plan_v1
from .d11_character_work_segment_v1 import PrepareCharacterLaborBodyRequestV1, _refs

OPERATIONS = frozenset({"prepare_character_labor_body","rebuild_character_labor_body","select_character_labor_rebuild_v1","list_character_labor_rebuild_options_v1"})
WORK_KIND = "current_character_labor_source_read_v1"
_STATES = WeakKeyDictionary()
_WRITES = WeakKeyDictionary()
_HEAD_FIELDS = ("schema", "identity", "action_id", "action_kind", "target_ref", "goal_ref",
    "commitment_refs", "action_ref", "goal_id", "commitment_id", "fulfillment_state", "entity_id",
    "concern_ref", "source_refs", "creation_evidence_refs", "reason_refs")
_DOMAINS = frozenset({"d01","d02","d03","d04","d05","d06","d07","d08","d10","d11"})


def required_character_labor_domains_v1():
    return _DOMAINS


def _identity(r):
    return (r.graph,r.work,r.operation,r.fence,r.namespace,r.selection_digest,r.graph_stamp,
        r.request,r.operation_id,r.authority,r.owner_binding)


def register_character_labor_source_v1(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(r)
    from .d02_character_labor_rebuild_v1 import RebuildCharacterLaborBodyRequestV1,CharacterLaborRebuildSelectorV1,CharacterLaborRebuildOptionsRequestV1
    expected = {"prepare_character_labor_body":PrepareCharacterLaborBodyRequestV1,"rebuild_character_labor_body":RebuildCharacterLaborBodyRequestV1,
        "select_character_labor_rebuild_v1":CharacterLaborRebuildSelectorV1,
        "list_character_labor_rebuild_options_v1":CharacterLaborRebuildOptionsRequestV1}
    if (r.operation_kind not in OPERATIONS or type(r.request) is not expected[r.operation_kind]
            or r in _STATES or r.work.kind != WORK_KIND):
        raise AuthorityUnavailable("labor Body Source requires its actual once-issued typed B Work")
    _STATES[r] = SimpleNamespace(identity=_identity(r),selected=set(),tasks={},keys=set(),roots=set(),
        originals=set(),producers=set(),permission=None,policy=None,root=None,metadata_complete=False,
        semantic_scope=None,scope_inventory_keys=frozenset(),scope_inventories={},rebuild=None,
        selector_request=None,selector_proof=None,selector_checkpoint=None,selector_history=None,options=None)


def require_character_labor_source_v1(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(r)
    state = _STATES.get(r)
    if (state is None or state.identity[:-1] != _identity(r)[:-1]
            or state.permission is not None and state.identity[-1] is not r.owner_binding):
        raise AuthorityUnavailable("labor B Source changed actual Work/selection/current Owner")
    return state


def pin_character_labor_owner_v1(r):
    state = require_character_labor_source_v1(r)
    r.general_owner_entry.require_for_v3(r)
    state.identity = _identity(r)


def _metadata(r,identity):
    from .current_method_learning_read_v3 import _need_method_input
    state = require_character_labor_source_v1(r)
    state.selected.add(identity)
    task = state.tasks.get(identity)
    if task is None or not task.complete:
        _need_method_input(r,("character_labor_metadata",identity))
    with runtime_storage_quantum_v3(r.db) as meter:
        task.require_header_v3(meter)
    return task.result


def create_character_labor_metadata_task_v1(r,identity):
    state = require_character_labor_source_v1(r)
    if identity not in state.selected:
        raise AuthorityUnavailable("labor metadata selector was not issued by its actual B recipe")
    task = state.tasks.get(identity)
    if task is None:
        from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
        task = (_BodyCheckpointFenceReadV1(r,identity) if identity[0] == "rebuild_install_fence"
            else _LaborPolicyOptionsCatalogueV1(r,identity) if identity[0] == "options_catalog"
            else create_current_beta1_metadata_task_v3(r,identity))
        state.tasks[identity] = task
    return task


def character_labor_metadata_spec_v1(r,identity):
    state = require_character_labor_source_v1(r)
    if identity not in state.selected:
        raise AuthorityUnavailable("labor metadata lacks its private recipe selection")
    kind,ref = identity
    if kind.startswith("options_"):
        return _options_metadata_spec_v1(r,state,identity)
    if kind.startswith("selector_"):
        return _selector_metadata_spec_v1(r,state,identity)
    if kind.startswith("rebuild_"):
        return _rebuild_metadata_spec_v1(r,state,identity)
    if kind in {"c_plan","c_body"}:
        c = _C_PREPARES.get(r)
        if c is None or c.work is not r.work:
            raise AuthorityUnavailable("labor C original lacks its actual generic Method issuance")
        original_kind = "character_labor_plan_v1" if kind == "c_plan" else "character_labor_body_preparation_v1"
        expected = r.request.plan_original_ref if kind == "c_plan" else c.plan.labor_body_preparation_original.original_ref
        if ref != expected:
            raise AuthorityUnavailable("labor C metadata locator left its signed actual Plan/B chain")
        return ("graph_d11_life_originals_v1","payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,original_kind,ref),("producing_operation_id","payload_digest","signature"),((),),None)
    if kind == "policy":
        policy_ref,policy_revision = _policy_locator(r,state)
        if ref != policy_ref:
            raise AuthorityUnavailable("labor policy metadata left its actual typed B request")
        return ("graph_d02_production_policies_v1","payload_json",
            ("bot","persona","policy_ref","revision"),
            (*r.namespace.as_tuple,ref,policy_revision),
            ("kind","profile_id","payload_digest","signature"),
            tuple((f.name,) for f in fields(CharacterLaborPolicyV1)),"d11.d02-production-policy.v1")
    if kind == "root":
        if ref not in state.originals or not ref.startswith("life-root:"):
            raise AuthorityUnavailable("labor A original is not the actual selected action")
        return ("graph_d11_life_originals_v1","payload_json",
            ("bot","persona","kind","original_ref"),(*r.namespace.as_tuple,"source_note_action",ref),
            ("producing_operation_id","payload_digest","signature"),((),),None)
    if kind == "head":
        key = AtomKey.from_token(ref)
        if key not in state.keys or NamespaceId.from_key(key) != r.namespace:
            raise AuthorityUnavailable("labor metadata head left its fixed current input inventory")
        names = character_labor_scope_metadata_fields_v1(key.type_name)
        return ("graph_atoms","value",("token","bot","persona"),(ref,*r.namespace.as_tuple),
            ("revision","valid","value_cell_id"),tuple((name,) for name in names),None)
    raise AuthorityUnavailable("unregistered exact labor metadata kind")


def retain_character_labor_metadata_path_v1(task,path):
    normalized = tuple("*" if type(part) is int else part for part in path)
    return not path or any(p[:len(normalized)] == normalized or normalized[:len(p)] == p for p in task.paths)


def finish_character_labor_metadata_v1(task,value):
    r = task.reader
    state = require_character_labor_source_v1(r)
    kind,ref = task.identity
    if kind.startswith("options_"):
        return _finish_options_metadata_v1(task,value)
    if kind.startswith("rebuild_"):
        return _finish_rebuild_metadata_v1(task,value)
    if kind in {"c_plan","c_body"}:
        from .d11_life_preparation_v1 import SIGN_KIND
        original_kind = "character_labor_plan_v1" if kind == "c_plan" else "character_labor_body_preparation_v1"
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,original_kind,ref,task.metadata[1])),task.metadata[2])
        if kind == "c_plan":
            from .d11_life_contract_v1 import RegisteredCharacterLaborLifePlanV1,life_from_wire_v1
            plan = life_from_wire_v1(value,RegisteredCharacterLaborLifePlanV1)
            if (plan.activity_id != r.activity_id or any(NamespaceId.from_key(AtomKey.from_token(v.ref)) != r.namespace
                    for v in (plan.project,plan.recipe,plan.action_intent,plan.input_source,plan.input_access))):
                raise AuthorityUnavailable("labor C signed Plan changed its actual namespace/activity")
            state.plan = plan
        else:
            from .d11_character_work_segment_v1 import labor_body_preparation_from_wire_v1
            body = labor_body_preparation_from_wire_v1(value)
            plan = state.plan
            if (body.namespace != r.namespace or body.action_operation_id != plan.operation_id
                    or body.recipe_ref != plan.recipe.ref or body.recipe_revision != plan.recipe.revision
                    or body.recipe_digest != plan.recipe.digest
                    or task.metadata[1] != plan.labor_body_preparation_original.original_digest
                    or task.metadata[0] != body.body_prepare_operation_id):
                raise AuthorityUnavailable("labor C signed B changed its exact Plan/first reservation")
            state.body,state.policy = body,body.policy
        return value
    if kind == "policy":
        policy = character_labor_policy_from_wire_v1(value)
        if (task.metadata[:2] != ("labor",policy.profile_id) or policy.namespace != r.namespace
                or (policy.policy_ref,policy.revision) != _policy_locator(r,state)):
            raise AuthorityUnavailable("actual signed labor policy metadata changed namespace/version/profile")
        state.policy = policy
    elif kind == "root":
        from .d11_life_preparation_v1 import SIGN_KIND
        from .d08_source_note_action_v1 import source_note_action_original_from_wire_v1
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,"source_note_action",ref,task.metadata[1])),task.metadata[2])
        root = source_note_action_original_from_wire_v1(value)
        if (root.action_intent_ref != _action_ref(r,state)
                or ref != "life-root:" + root.action_operation_id
                or task.metadata[0] != root.action_operation_id):
            raise AuthorityUnavailable("labor B metadata did not select its actual committed action A")
        state.root = root
        state.producers.add((root.activity_id,root.action_operation_id))
    return value


def require_character_labor_body_profile_v1(r):
    """Retained scalar locator; all currentness is checked again by the WRITE consumer."""
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_identity_v3
    require_current_beta1_source_work_identity_v3(r)
    state = _STATES.get(r)
    if state is None or state.identity[:-1] != _identity(r)[:-1] or state.policy is None:
        raise AuthorityUnavailable("labor Body profile requires the actual signed policy metadata EOF")
    task = state.tasks.get(("policy",r.request.policy_ref))
    if task is None or not task.complete or task.result is None or state.policy.profile_id != task.metadata[1]:
        raise AuthorityUnavailable("labor Body profile lost its completed selected policy original")
    return state.policy.profile_id


def read_plan_character_labor_source_v1(db,*,namespace,activity_id,operation_kind,request,operation_id=None):
    from .current_method_learning_read_v3 import _method_active
    from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
    from .d11_life_scope_v1 import LifeSemanticScopeV1, life_semantic_source_refs_v1
    r = _method_active(db)
    if (r is None or r.namespace != namespace or r.operation_kind != operation_kind
            or r.request is not request or operation_kind not in OPERATIONS and not is_character_labor_prepare_profile_v1(r)):
        raise AuthorityUnavailable("labor B plan requires its actual current Source Work")
    state = require_character_labor_source_v1(r)
    policy_ref,policy_revision = _policy_locator(r,state)
    action_ref = _action_ref(r,state)
    if _metadata(r,("policy",policy_ref)) is None:
        raise MissingProductionOriginalV1("actual_signed_character_labor_policy")
    state.keys.add(AtomKey.from_token(action_ref))
    action = _metadata(r,("head",action_ref))
    if action is None or not state.tasks[("head",action_ref)].metadata[1]:
        raise MissingProductionOriginalV1("actual_character_labor_action_A")
    root_ref = "life-root:" + action["identity"]["operation_id"]
    state.originals.add(root_ref)
    if _metadata(r,("root",root_ref)) is None:
        raise MissingProductionOriginalV1("actual_signed_character_labor_action_A")
    root = state.root
    action_task = state.tasks[("head",action_ref)]
    if root.action_intent_digest != action_task.column.canonical_digest:
        raise AuthorityUnavailable("labor A signed original is not the exact current action head EOF")
    if _is_character_labor_rebuild_v1(r):
        _prepare_rebuild_controls_v1(r,state)
    state.keys.update(AtomKey.from_token(ref) for ref in
        (root.project_ref,root.recipe_ref,root.action_intent_ref,root.target_entity_ref,root.role_binding_ref))
    state.keys.add(owner_grant_key(*namespace.as_tuple))
    state.keys.update(_output_keys(r,state))
    inventory = {}
    for token in sorted(r.heads):
        key = AtomKey.from_token(token)
        if key.type_name in LIFE_CURRENT_TYPES:
            state.keys.add(key)
            value = _metadata(r,("head",token))
            task = state.tasks[("head",token)]
            if task.metadata[1]:
                inventory.setdefault(key.type_name,[]).append((key,value))
    entities = tuple(key.token for key,value in inventory.get("d03.entity_anchor",())
        if value["entity_id"] == action["target_ref"])
    if len(entities) != 1:
        raise MissingProductionOriginalV1("unique_current_character_labor_target_entity")
    scope = LifeSemanticScopeV1(namespace,root.project_ref,root.input_source_ref,entities[0],
        action["target_ref"],action["action_id"],action["goal_ref"],tuple(action["commitment_refs"]),
        tuple(root.audiences),r.initial_now_utc)
    selected = {owner_grant_key(*namespace.as_tuple),*_output_keys(r,state)}
    selected.update(AtomKey.from_token(ref) for ref in
        (root.project_ref,root.recipe_ref,root.action_intent_ref,root.target_entity_ref,root.role_binding_ref))
    roots = {root.input_source_ref}
    scope_selected = set()
    action_ids = {value["action_id"] for key,value in inventory.get("d08.action_intent.v1",())
        if scope.includes("d08.action_intent.v1",key,value)}
    for type_name,rows in inventory.items():
        for key,value in rows:
            applies = value["action_id"] in action_ids if type_name == "d08.action_outcome.v1" else scope.includes(type_name,key,value)
            if applies:
                scope_selected.add(key)
                selected.add(key)
                roots.update(life_semantic_source_refs_v1(value))
    from ..domains.d02.character_labor_v1 import character_labor_rebuild_key_v1
    selected.add(character_labor_rebuild_key_v1(namespace,state.policy.profile_id))
    for key in selected:
        if key.token in r.heads and key.type_name != "runtime.owner_grant.v1":
            state.keys.add(key)
            metadata = _metadata(r,("head",key.token))
            if metadata is not None:
                roots.update(life_semantic_source_refs_v1(metadata))
    for ref in roots:
        if NamespaceId.from_key(AtomKey.from_token(ref)) != namespace or AtomKey.from_token(ref).type_name != "memory.source":
            raise AuthorityUnavailable("labor B metadata roots crossed their actual Source namespace")
    state.roots = roots
    state.originals.add(policy_ref)
    if not _is_character_labor_rebuild_v1(r):
        state.originals.add(_clock_ref(r,state))
    if r in _C_PREPARES:
        state.originals.update((r.request.plan_original_ref,state.plan.labor_body_preparation_original.original_ref))
    state.metadata_complete = True
    state.semantic_scope = scope
    state.scope_inventory_keys = frozenset(scope_selected)
    return production_read_plan_v1((*LIFE_CURRENT_TYPES,"d02.character_labor_rebuild_head.v1"),
        tuple(sorted(selected,key=lambda k:k.token)),tuple(sorted(roots)),tuple(sorted(state.originals)))


def character_labor_source_groups_v1(r,roots):
    state = require_character_labor_source_v1(r)
    if not state.metadata_complete or set(roots) != state.roots or state.root is None:
        raise AuthorityUnavailable("labor Source groups require complete actual A/policy/head metadata")
    return tuple((purpose,tuple(state.root.audiences),tuple(sorted(roots)))
        for purpose in ("context","consolidation"))


def require_character_labor_sources_v1(r,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    state = require_character_labor_source_v1(r)
    state.permission = qualify_current_beta1_source_groups_v3(r,roots)
    return state.permission


def prepare_current_character_labor_dependencies_v1(r):
    require_character_labor_sources_v1(r,r.selected_plan.source_roots)
    if _is_character_labor_rebuild_v1(r):
        _prepare_rebuild_facts_v1(r,require_character_labor_source_v1(r))
    return False


def release_character_labor_source_v1(r):
    from .d02_character_labor_rebuild_v1 import release_character_labor_rebuild_selections_v1
    release_character_labor_rebuild_selections_v1(r)
    state = _STATES.pop(r,None)
    _C_PREPARES.pop(r,None)
    _WRITES.pop(r,None)
    if state is not None:
        for proof in tuple(state.scope_inventories.values()):
            _SCOPE_INVENTORIES.pop(proof,None)
        state.scope_inventories.clear()
        state.semantic_scope = None
        state.scope_inventory_keys = frozenset()
        state.rebuild = None
        state.tasks.clear();state.selected.clear();state.keys.clear();state.roots.clear()
        state.originals.clear();state.producers.clear();state.permission=state.policy=state.root=None


def require_character_labor_body_v1(r,table,key):
    if is_character_labor_metadata_selector_v1(r):
        raise AuthorityUnavailable("labor metadata selection does not grant any Source or selected Body")
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    state = require_character_labor_source_v1(r)
    if require_beta1_source_control_point_v3(r,(table,("revision","value","valid"),
            ("token","bot","persona"),tuple(key))):
        return
    if state.permission is None:
        raise AuthorityUnavailable("labor Body requires actual completed context/consolidation SourceALL")
    state.permission.require_for_v3(r)
    if table in {"graph_atoms","graph_history"}:
        atom = AtomKey.from_token(key[0])
        if (atom not in r.selected_plan.exact_keys
                or atom.type_name == "memory.source" and atom.token not in state.roots):
            raise AuthorityUnavailable("labor Body is outside the actual selected current A/B inputs")
        if table == "graph_history":
            head = r.heads.get(atom.token)
            if head is None or head[0] != key[1]:
                raise AuthorityUnavailable("labor historical Body is outside its current exact revision")
        return
    if table == "graph_d11_life_originals_v1":
        allowed = {("source_note_action","life-root:"+state.root.action_operation_id)}
        if r in _C_PREPARES:
            allowed.update({("character_labor_plan_v1",r.request.plan_original_ref),
                ("character_labor_body_preparation_v1",state.plan.labor_body_preparation_original.original_ref)})
        if tuple(key[-2:]) not in allowed:
            raise AuthorityUnavailable("labor B cannot read an unrelated Life original")
        return
    if table == "graph_d02_production_policies_v1":
        if tuple(key[-2:]) != _policy_locator(r,state):
            raise AuthorityUnavailable("labor B selected a different policy")
        return
    if table == "runtime_budget_grants":
        if r.budget_task is None or tuple(key) != tuple(r.budget_task.metadata[:2]):
            raise AuthorityUnavailable("labor Body grant is not its actual selected parent")
        return
    raise AuthorityUnavailable("unregistered labor B Body table")


def require_character_labor_point_v1(r,request):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    state = require_character_labor_source_v1(r)
    table,columns,key_columns,key = request
    if require_beta1_source_control_point_v3(r,request):
        return
    if table == "graph_atoms" and key_columns == ("token","bot","persona"):
        if tuple(key[1:]) != r.namespace.as_tuple:
            raise AuthorityUnavailable("labor graph point crossed namespace")
        require_character_labor_body_v1(r,table,key)
        return
    if table == "graph_history" and key_columns == ("token","revision"):
        require_character_labor_body_v1(r,table,key)
        return
    if table in {"graph_d02_production_policies_v1","graph_d11_life_originals_v1"}:
        if tuple(key[:2]) != r.namespace.as_tuple:
            raise AuthorityUnavailable("labor Original point crossed namespace")
        require_character_labor_body_v1(r,table,key)
        return
    if table == "graph_events" and key_columns == ("bot","persona","session","event_id"):
        if tuple(key[:2]) != r.namespace.as_tuple or tuple(key[2:]) not in state.producers:
            raise AuthorityUnavailable("labor event is outside actual A/B producers")
        return
    if table == "graph_bundle_operations" and key_columns == ("bot","persona","operation_id"):
        if tuple(key[:2]) != r.namespace.as_tuple or key[2] not in {op for _,op in state.producers}:
            raise AuthorityUnavailable("labor receipt is outside actual A/B producers")
        return
    raise AuthorityUnavailable("unregistered labor B point profile")


def character_labor_point_v1(db,table,columns,key_columns,key):
    from .current_method_learning_read_v3 import _method_active, _need_method_input, MethodJSONColumnV3
    r = _method_active(db)
    if r is None or r not in _STATES:
        return False,None
    request = (table,tuple(columns),tuple(key_columns),tuple(key))
    require_character_labor_point_v1(r,request)
    state = require_character_labor_source_v1(r)
    identity = None
    if table == "graph_d02_production_policies_v1":
        identity = ("policy",_policy_locator(r,state)[0])
    elif table == "graph_d11_life_originals_v1":
        identity = {"source_note_action":("root","life-root:"+state.root.action_operation_id),
            "character_labor_plan_v1":("c_plan",r.request.plan_original_ref) if r in _C_PREPARES else None,
            "character_labor_body_preparation_v1":("c_body",state.plan.labor_body_preparation_original.original_ref) if r in _C_PREPARES else None}.get(key[-2])
    if identity is not None:
        original = state.tasks.get(identity)
        if original is None or not original.complete or original.result is None:
            raise AuthorityUnavailable("labor metadata Original did not reach its actual complete EOF")
        with runtime_storage_quantum_v3(db) as meter:
            original.require_header_v3(meter)
        if (table,tuple(key_columns),tuple(key)) != (original.table,original.key_columns,original.key):
            raise AuthorityUnavailable("labor point is not its exact retained metadata Original")
        values = dict(zip(original.key_columns,original.key))
        values.update(zip(original.header_columns,original.metadata))
        values[original.column_name] = original.column.wire
        if any(name not in values for name in columns):
            raise AuthorityUnavailable("labor retained Original does not contain this exact metadata column")
        return True,tuple(values[name] for name in columns)
    task = r.points.get(request)
    if task is None or not task.complete:
        _need_method_input(r,("point",request))
    with runtime_storage_quantum_v3(db) as meter:
        row = task.require_row_v3(meter)
    return True,None if row is None else tuple(
        value.wire if type(value) is MethodJSONColumnV3 else value for value in row)


def read_bound_character_labor_policies_v1(db,*,namespace,plan):
    from .current_method_learning_read_v3 import _method_active
    from .domain_production_contracts_v1 import ProductionPolicyRefV1
    r = _method_active(db)
    if r is None or r not in _STATES:
        return False,None
    state = require_character_labor_source_v1(r)
    if namespace != r.namespace or plan != r.selected_plan or state.policy is None:
        raise AuthorityUnavailable("labor policy pins left the actual selected complete metadata")
    ref,revision = _policy_locator(r,state)
    task = state.tasks[("policy",ref)]
    with runtime_storage_quantum_v3(db) as meter:
        task.require_header_v3(meter)
    return True,(ProductionPolicyRefV1(ref,revision,task.metadata[2]),)


def register_character_labor_write_v1(inputs,scope,current_owner):
    r = inputs.owner
    state = require_character_labor_source_v1(r)
    if not r.inputs_sealed:
        return
    from .current_method_learning_read_v3 import _method_active
    if (not r.read_finished or not r.business_started or scope.operation != "write"
            or scope is r.fence.scope or current_owner != r.owner_binding
            or inputs.plan != r.selected_plan or _method_active(r.db) is not r or state.permission is None):
        raise AuthorityUnavailable("labor WRITE requires its same actual sealed Source/Owner inputs")
    _WRITES[r] = (inputs,scope,current_owner,state.identity,state.permission)


def require_character_labor_write_v1(r):
    state = require_character_labor_source_v1(r)
    saved = _WRITES.get(r)
    if (saved is None or saved[0].owner is not r or saved[2] != r.owner_binding
            or saved[3:] != (state.identity,state.permission) or not r.business_started):
        raise AuthorityUnavailable("labor Source lost actual same-Work WRITE binding")
    return saved


def _policy_locator(r,state):
    return (state.body.policy.policy_ref,state.body.policy.revision) if r in _C_PREPARES else (r.request.policy_ref,r.request.policy_revision)


def _action_ref(r,state):
    return state.plan.action_intent.ref if r in _C_PREPARES else r.request.action_intent_ref


def _clock_ref(r,state):
    return state.body.quote.clock_mapping_ref if r in _C_PREPARES else r.request.clock_mapping_ref


def _output_keys(r,state):
    if _is_character_labor_rebuild_v1(r):
        from ..domains.d02.character_labor_v1 import character_labor_correction_key_v1,character_labor_rebuild_key_v1
        rb = _rebuild_state_v1(r,state)
        head = character_labor_rebuild_key_v1(r.namespace,state.policy.profile_id)
        revision = 1 if head.token not in r.heads else r.heads[head.token][0]+1
        keys = {head,character_labor_correction_key_v1(r.namespace,state.policy.profile_id,revision),
            AtomKey.from_token(r.request.checkpoint.ref)}
        keys.update(AtomKey.from_token(ref) for basis in rb.bases.values()
            for ref in (basis.reservation_ref,basis.settlement_ref))
        return tuple(sorted(keys,key=lambda key:key.token))
    if r not in _C_PREPARES:
        return _refs(r.namespace,r.activity_id,r.operation_id)
    from ..graph_types import Owner
    from .d11_life_preparation_v1 import life_ids_v1
    ids = life_ids_v1(state.plan)
    return (AtomKey(Owner("activity",*r.namespace.as_tuple,state.plan.activity_id),"runtime.job",ids["job"]),
        AtomKey.from_token(state.body.reservation_ref),AtomKey.from_token(state.body.settlement_ref))


_C_PREPARES = WeakKeyDictionary()


def register_character_labor_prepare_constructor_v1(r, *, issuer, graph, operation, fence):
    """Exact generic Method constructor intent; it grants metadata classification only."""
    from .current_method_learning_read_v3 import _MethodLearningReadV3, _ISSUER, METHOD_LEARNING_TYPES_V3
    from .d11_life_preparation_v1 import PrepareCurrentLifeRequestV1
    from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
    if r.operation_kind != "prepare_life":
        return False
    if (issuer is not _ISSUER or type(r) is not _MethodLearningReadV3
            or type(r.request) is not PrepareCurrentLifeRequestV1 or r in _C_PREPARES
            or r.source_pending_owner is not None or operation.closed
            or r.runtime.graph is not graph or operation.operation_id != r.operation_id
            or fence.scope.operation != "read" or fence.scope.namespace != r.authority.namespace):
        raise AuthorityUnavailable("labor C classification requires its actual ordinary Method constructor")
    state = SimpleNamespace(constructor=(graph,operation,fence,r.runtime,r.authority,r.lease,
        r.request,r.operation_id,r.activity_id,r.parent_budget_lease_ref,r.request_digest),
        mode="pending",work=None,identity=None,selected=set(),tasks={},keys=set(),roots=set(),
        originals=set(),producers=set(),permission=None,policy=None,root=None,plan=None,body=None,
        metadata_complete=False,semantic_scope=None,scope_inventory_keys=frozenset(),scope_inventories={},
        classifier_phase="header",classifier_task=None,plan_header=None,
        legacy_projection=METHOD_LEARNING_TYPES_V3,legacy_preplan=frozenset(LIFE_CURRENT_TYPES))
    _C_PREPARES[r] = state
    return True


def is_character_labor_prepare_profile_v1(r):
    state = _C_PREPARES.get(r)
    if state is None:
        return False
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    c = state.constructor
    if (type(r) is not _MethodLearningReadV3 or r.operation_kind != "prepare_life"
            or (r.runtime,r.authority,r.lease,r.request,r.operation_id,r.activity_id,
                r.parent_budget_lease_ref,r.request_digest) != c[3:]
            or c[1].closed or state.mode not in {"pending","new"}):
        raise AuthorityUnavailable("labor C pending profile left its real constructor identity")
    return True


def bind_character_labor_prepare_work_v1(r,work):
    from .current_method_learning_read_v3 import _READERS, METHOD_LEARNING_WORK_KIND_V3
    from ..graph_worker import GraphStorageWorkV3
    if not is_character_labor_prepare_profile_v1(r):
        return False
    state = _C_PREPARES[r]
    c = state.constructor
    if (r not in _READERS or type(work) is not GraphStorageWorkV3 or state.work is not None
            or r.work is not work or work.state is not r or work.kind != METHOD_LEARNING_WORK_KIND_V3
            or work.coordinator is not c[0] or work.operation is not c[1] or r.fence is not c[2]
            or r.operation is not c[1] or r.graph is not c[0]
            or work.operation_id != r.operation_id or work.selection_digest != r.selection_digest):
        raise AuthorityUnavailable("labor C profile cannot move or replace its actual generic Method Work")
    state.work = work
    state.identity = _identity(r)
    _STATES[r] = state
    return True


def advance_character_labor_prepare_classification_v1(r,meter):
    """Called by Method._next before its generic Body census."""
    if not is_character_labor_prepare_profile_v1(r):
        return False
    state = require_character_labor_source_v1(r)
    if state.mode == "new":
        return False
    from .d11_life_preparation_v1 import TABLE, SIGN_KIND
    if state.classifier_phase == "header":
        headers = []
        for kind in ("plan","character_labor_plan_v1"):
            row = meter.read_fixed_row(r.db,TABLE,("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",
                (*r.namespace.as_tuple,kind,r.request.plan_original_ref))
            if row is not None:
                r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                    canonical_serialize((r.namespace,kind,r.request.plan_original_ref,row[1])),row[2])
                headers.append((kind,row))
        if len(headers) != 1:
            raise AuthorityUnavailable("Life C needs exactly one actual signed old/new Plan header")
        kind,header = headers[0]
        if kind == "plan":
            # Positive authenticated old family only. Absence/new failures never enter it.
            r.projection_types = state.legacy_projection
            r.preplan_families = state.legacy_preplan
            from .current_beta1_source_read_v3 import release_current_beta1_source_work_v3
            release_current_beta1_source_work_v3(r)
            release_character_labor_source_v1(r)
            return True
        state.plan_header = header
        identity = ("c_plan",r.request.plan_original_ref)
        state.selected.add(identity)
        state.classifier_task = create_character_labor_metadata_task_v1(r,identity)
        state.classifier_phase = "plan"
        return True
    task = state.classifier_task
    task.advance(meter)
    if not task.complete:
        return True
    if task.result is None:
        raise MissingProductionOriginalV1("actual_character_labor_C_signed_metadata")
    if state.classifier_phase == "plan":
        identity = ("c_body",state.plan.labor_body_preparation_original.original_ref)
        state.selected.add(identity)
        state.classifier_task = create_character_labor_metadata_task_v1(r,identity)
        state.classifier_phase = "body"
    elif state.classifier_phase == "body":
        state.mode = "new"
        state.classifier_phase = "complete"
        state.classifier_task = None
    else:
        raise AuthorityUnavailable("unregistered labor C metadata classifier phase")
    return True


def require_character_labor_prepare_body_profile_v1(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_identity_v3
    require_current_beta1_source_work_identity_v3(r)
    state = _C_PREPARES.get(r)
    if (state is None or not is_character_labor_prepare_profile_v1(r) or state.mode != "new"
            or state.identity[:-1] != _identity(r)[:-1] or state.body is None or state.plan is None):
        raise AuthorityUnavailable("labor C Body profile requires actual signed Plan/B metadata EOF")
    task = state.tasks[("c_body",state.plan.labor_body_preparation_original.original_ref)]
    if not task.complete or task.result is None or task.metadata[1] != state.plan.labor_body_preparation_original.original_digest:
        raise AuthorityUnavailable("labor C Body profile lost its exact retained B metadata EOF")
    return state.body.policy.profile_id


_SCOPE_ISSUER = object()
_SCOPE_INVENTORIES = WeakKeyDictionary()


class CharacterLaborScopeInventoryV1:
    """Explicit scoped body inventory plus a distinct full HEAD census."""
    def __init__(self,issuer,r,family,full,selected):
        if issuer is not _SCOPE_ISSUER:
            raise AuthorityUnavailable("labor scope inventory requires its actual Source producer")
        from ..runtime_contracts import QueryEpoch
        self.reader,self.family,self.row_versions,self.selected_versions = r,family,full,selected
        self.epoch = QueryEpoch(r.namespace,family,r.graph_stamp[1].revision)
        _SCOPE_INVENTORIES[self] = (r,require_character_labor_source_v1(r),full,selected,self.epoch)

    def require_v1(self,r,*,meter):
        state = require_character_labor_source_v1(r)
        if (_SCOPE_INVENTORIES.get(self) != (r,state,self.row_versions,self.selected_versions,self.epoch)
                or state.scope_inventories.get(self.family) is not self or not state.metadata_complete
                or state.permission is None or self.epoch.revision != r.graph_stamp[1].revision):
            raise AuthorityUnavailable("labor scope inventory lost its actual metadata/Source issuance")
        state.permission.require_for_v3(r)
        from ..graph_types import GraphVersion
        current = tuple(GraphVersion(AtomKey.from_token(token),head[0]) for token,head in sorted(r.heads.items())
            if AtomKey.from_token(token).type_name == self.family)
        if current != self.row_versions:
            raise AuthorityUnavailable("labor scope full family HEAD census changed")
        selected = []
        for version in self.row_versions:
            task = state.tasks[("head",version.key.token)]
            task.require_header_v3(meter)
            if task.metadata[1] and version.key in state.scope_inventory_keys:
                selected.append(version)
        if tuple(selected) != self.selected_versions:
            raise AuthorityUnavailable("labor scope predicate membership changed after metadata EOF")
        return self


def require_character_labor_scope_inventory_v1(r,family):
    state = require_character_labor_source_v1(r)
    from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
    from ..graph_types import GraphVersion
    if (family not in LIFE_CURRENT_TYPES or not state.metadata_complete
            or state.permission is None or state.semantic_scope is None):
        raise AuthorityUnavailable("labor scoped inventory requires its actual complete signed semantic selection")
    state.permission.require_for_v3(r)
    proof = state.scope_inventories.get(family)
    if proof is None:
        full = tuple(GraphVersion(AtomKey.from_token(token),head[0]) for token,head in sorted(r.heads.items())
            if AtomKey.from_token(token).type_name == family)
        if len(full) > 128:
            raise AuthorityUnavailable("labor scope exceeds the original full family HEAD bound")
        selected = tuple(v for v in full if v.key in state.scope_inventory_keys and r.heads[v.key.token][1])
        proof = CharacterLaborScopeInventoryV1(_SCOPE_ISSUER,r,family,full,selected)
        state.scope_inventories[family] = proof
    return proof


def complete_labor_scope_inventory_v1(db,read,family):
    """Only selected real Bodies; this does not claim a full Body inventory."""
    from .current_method_learning_read_v3 import _method_active
    from .d01_production_operations_v1 import CurrentDomainReadV1
    r = _method_active(db)
    if r is None:
        from ..authority_service.character_labor_source_read_v1 import complete_authority_labor_scope_inventory_v1
        return complete_authority_labor_scope_inventory_v1(db,read,family)
    if r not in _STATES or type(read) is not CurrentDomainReadV1:
        raise AuthorityUnavailable("labor scope inventory requires its actual same-Work D02/D08 read")
    if (read.frame.envelope.authority.namespace != r.namespace
            or read.frame.envelope.identity.operation_id != r.operation_id):
        raise AuthorityUnavailable("labor scope inventory left its current actual production frame")
    proof = require_character_labor_scope_inventory_v1(r,family)
    with runtime_storage_quantum_v3(db) as meter:
        proof.require_v1(r,meter=meter)
    read.check(db)
    from dataclasses import replace
    state = require_character_labor_source_v1(r)
    current_scope = replace(state.semantic_scope,now_utc=read.frame.now_utc)
    current_actions = {state.tasks[("head",token)].result["action_id"] for token,head in r.heads.items()
        if AtomKey.from_token(token).type_name == "d08.action_intent.v1" and head[1]
        and current_scope.includes("d08.action_intent.v1",AtomKey.from_token(token),state.tasks[("head",token)].result)}
    current_selected = tuple(v for v in proof.row_versions if r.heads[v.key.token][1] and (
        state.tasks[("head",v.key.token)].result["action_id"] in current_actions
        if family == "d08.action_outcome.v1" else
        current_scope.includes(family,v.key,state.tasks[("head",v.key.token)].result)))
    if current_selected != proof.selected_versions:
        raise AuthorityUnavailable("labor scope predicate membership changed after the original bounded READ")
    pages = tuple(p for p in read.frame.query_coverage if p.type_id == family)
    if (len(pages) != 1 or not pages[0].complete or pages[0].continuation_ref is not None
            or pages[0].epoch != proof.epoch or pages[0].row_versions != proof.row_versions):
        raise AuthorityUnavailable("labor scoped Bodies lost their separate full header query/negative guard")
    return tuple(read.head(db,v.key,required=True) for v in proof.selected_versions)


def character_labor_scope_metadata_fields_v1(family):
    """Data-only projection fields; issuance remains with each actual reader."""
    if family == "d03.role_binding":
        from ..domains.d03.context import RoleBinding
        return tuple(f.name for f in fields(RoleBinding))
    if family == "d05.boundary_rule":
        from ..domains.d05.relationship import BoundaryRule
        return tuple(f.name for f in fields(BoundaryRule))
    return _HEAD_FIELDS

_REBUILD_KINDS = ("basis","segment","passive","component")


def _is_character_labor_rebuild_v1(r):
    from .d02_character_labor_rebuild_v1 import RebuildCharacterLaborBodyRequestV1
    return r.operation_kind == "rebuild_character_labor_body" and type(r.request) is RebuildCharacterLaborBodyRequestV1


def _rebuild_state_v1(r,state):
    if not _is_character_labor_rebuild_v1(r) and not is_character_labor_metadata_selector_v1(r):
        raise AuthorityUnavailable("actual typed labor rebuild Source Work required")
    if state.rebuild is None:
        state.rebuild = SimpleNamespace(rows={},scan_index=0,cursor=None,pending=None,
            controls_complete=False,facts_complete=False,bases={},accounting={},segments={},
            passive={},components={},receipts={},reserved=0,install_original=None,
            install_fence=None,install_fence_pending=False)
    return state.rebuild


def _reserve_rebuild_v1(r,rb):
    from .dispatch_current_inventory_v3 import _heap
    state = _STATES[r]
    amount = _heap((rb.rows,rb.bases,rb.accounting,rb.segments,rb.passive,rb.components,rb.receipts,
        rb.install_original,rb.install_fence,state.selector_request,state.selector_history)) + 4096
    if amount > rb.reserved:
        r.operation.retain(amount-rb.reserved)
        rb.reserved = amount


def _rebuild_table_query_v1(r,state,kind,cursor):
    ns = r.namespace.as_tuple
    if kind in {"basis","segment"}:
        actual_kind = "character_labor_accounting_basis_v1" if kind == "basis" else "character_work_segment_v1"
        return ("graph_d11_life_originals_v1",
            ("original_ref","producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
            (*ns,actual_kind,"" if cursor is None else cursor))
    if kind == "component":
        return ("graph_d02_action_components_v1",
            ("original_ref","producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND original_ref>? ORDER BY original_ref",
            (*ns,"" if cursor is None else cursor))
    if kind == "passive":
        last_ref,last_revision = ("",0) if cursor is None else cursor
        return ("graph_d02_production_policies_v1",
            ("policy_ref","revision","kind","profile_id","from_role_cursor","to_role_cursor","payload_digest","signature"),
            "bot=? AND persona=? AND kind='passive' AND profile_id=? AND (policy_ref>? OR (policy_ref=? AND revision>?)) ORDER BY policy_ref,revision",
            (*ns,state.policy.profile_id,last_ref,last_ref,last_revision))
    raise AuthorityUnavailable("unregistered fixed labor rebuild inventory")


def _rebuild_metadata_spec_v1(r,state,identity):
    rb = _rebuild_state_v1(r,state)
    kind,ref = identity
    if kind in {"rebuild_basis","rebuild_segment","rebuild_accounting"}:
        original_kind = {"rebuild_basis":"character_labor_accounting_basis_v1",
            "rebuild_segment":"character_work_segment_v1","rebuild_accounting":"accounting_prepared"}[kind]
        return ("graph_d11_life_originals_v1","payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,original_kind,ref),("producing_operation_id","payload_digest","signature"),((),),None)
    if kind == "rebuild_install":
        return ("graph_d11_life_originals_v1","payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,"body_policy_checkpoint_v1",ref),
            ("producing_operation_id","payload_digest","signature"),((),),None)
    if kind in {"rebuild_install_reads","rebuild_install_writes","rebuild_install_epochs","rebuild_install_invalidated"}:
        if rb.install_original is None or rb.install_original.producing_operation_id != ref:
            raise AuthorityUnavailable("initial Body event locator needs its authenticated checkpoint")
        column = {"rebuild_install_reads":"reads","rebuild_install_writes":"revisions",
            "rebuild_install_epochs":"epoch_reads","rebuild_install_invalidated":"invalidated"}[kind]
        return ("graph_events",column,("bot","persona","session","event_id"),
            (*r.namespace.as_tuple,"c04.fixed_body_install.v1",ref),("digest","epoch_revision"),((),),None)
    if kind == "rebuild_passive":
        policy_ref,revision = ref
        return ("graph_d02_production_policies_v1","payload_json",("bot","persona","policy_ref","revision"),
            (*r.namespace.as_tuple,policy_ref,revision),
            ("kind","profile_id","from_role_cursor","to_role_cursor","payload_digest","signature"),((),),"d11.d02-production-policy.v1")
    if kind == "rebuild_component":
        return ("graph_d02_action_components_v1","payload_json",("bot","persona","original_ref"),
            (*r.namespace.as_tuple,ref),("producing_operation_id","payload_digest","signature"),((),),"d11.d02-completed-action-component.v1")
    if kind == "rebuild_checkpoint":
        if state.permission is None:
            raise AuthorityUnavailable("labor checkpoint Body waits for its actual SourceALL")
        state.permission.require_for_v3(r)
        q = r.request
        return ("graph_history","value",("token","revision"),(q.checkpoint.ref,q.checkpoint.version),
            ("valid","value_cell_id","event_bot","event_persona","event_session","event_id"),((),),None)
    if kind == "rebuild_receipt":
        return ("graph_bundle_operations","receipt_json",("bot","persona","operation_id"),
            (*r.namespace.as_tuple,ref),("digest","activity_id","effect_id","commit_seq"),
            (("ledger_refs",),("outbox_refs",)),None)
    if kind in {"rebuild_reads","rebuild_writes"}:
        receipt = state.tasks.get(("rebuild_receipt",ref))
        if receipt is None or not receipt.complete:
            raise AuthorityUnavailable("labor event selection requires its actual receipt metadata EOF")
        return ("graph_events","reads" if kind == "rebuild_reads" else "revisions",
            ("bot","persona","session","event_id"),
            (*r.namespace.as_tuple,receipt.metadata[1],ref),("digest","epoch_revision"),((),),None)
    raise AuthorityUnavailable("unregistered exact labor rebuild metadata column")


def _finish_rebuild_metadata_v1(task,value):
    from .d11_life_preparation_v1 import SIGN_KIND
    from .d11_character_labor_accounting_v1 import (
        SIGN_KIND as BASIS_SIGN_KIND,character_labor_accounting_basis_from_wire_v1)
    from .d11_character_work_segment_v1 import character_work_segment_from_wire_v1
    from .d11_life_accounting_v1 import D11LifeAccountingPreparedV1
    from .d10_offline_tick_execution_v1 import _decode_json
    from .d02_production_operations_v1 import PassiveBodyPolicyV1,CompletedActionBodyComponentV1
    from ..domains.d02 import BodyPassiveRates,BodyState
    r = task.reader
    state = require_character_labor_source_v1(r)
    rb = _rebuild_state_v1(r,state)
    kind,ref = task.identity
    if kind == "rebuild_install":
        from .d02_character_labor_rebuild_v1 import (
            BODY_POLICY_CHECKPOINT_KIND_V1,BODY_POLICY_CHECKPOINT_SIGN_KIND_V1,body_policy_checkpoint_from_wire_v1)
        r.graph._GraphCoordinator__d11_issuer._signer.verify(BODY_POLICY_CHECKPOINT_SIGN_KIND_V1,
            canonical_serialize((r.namespace,BODY_POLICY_CHECKPOINT_KIND_V1,ref,task.metadata[1])),task.metadata[2])
        parsed = body_policy_checkpoint_from_wire_v1(value)
        if (parsed.namespace != r.namespace or parsed.original_ref != ref
                or task.metadata[0] != parsed.producing_operation_id):
            raise AuthorityUnavailable("initial Body checkpoint moved from its real signed producer")
        rb.install_original = parsed
    elif kind in {"rebuild_basis","rebuild_segment","rebuild_accounting"}:
        original_kind = {"rebuild_basis":"character_labor_accounting_basis_v1",
            "rebuild_segment":"character_work_segment_v1","rebuild_accounting":"accounting_prepared"}[kind]
        r.graph._GraphCoordinator__d11_issuer._signer.verify(
            BASIS_SIGN_KIND if kind == "rebuild_basis" else SIGN_KIND,
            canonical_serialize((r.namespace,original_kind,ref,task.metadata[1])),task.metadata[2])
        if kind == "rebuild_basis":
            parsed = character_labor_accounting_basis_from_wire_v1(value)
            if (parsed.namespace != r.namespace or ref != "character-labor-accounting:"+parsed.execution_id
                    or task.metadata[0] != parsed.prepare_operation_id):
                raise AuthorityUnavailable("labor rebuild basis left its actual signed C producer")
            rb.bases[parsed.execution_id] = parsed
        elif kind == "rebuild_segment":
            parsed = character_work_segment_from_wire_v1(value)
            if parsed.namespace != r.namespace or parsed.segment_id != ref:
                raise AuthorityUnavailable("labor rebuild Graph segment locator differs from its signed original")
            rb.segments[ref] = parsed
        else:
            parsed = _decode_json(canonical_serialize(value),D11LifeAccountingPreparedV1)
            rb.accounting[ref] = parsed
    elif kind == "rebuild_passive":
        raw = dict(value)
        raw["namespace"] = NamespaceId(**raw["namespace"])
        raw["rates"] = BodyPassiveRates(**raw["rates"])
        parsed = PassiveBodyPolicyV1(**raw)
        if ((parsed.policy_ref,parsed.revision) != ref or parsed.namespace != r.namespace
                or parsed.profile_id != state.policy.profile_id
                or task.metadata[:4] != ("passive",parsed.profile_id,parsed.from_role_cursor,parsed.to_role_cursor)):
            raise AuthorityUnavailable("labor rebuild passive policy differs from its actual fixed metadata")
        rb.passive[ref] = parsed
    elif kind == "rebuild_component":
        parsed = CompletedActionBodyComponentV1(**dict(value,paid_cost_refs=tuple(value["paid_cost_refs"])))
        if parsed.original_ref != ref:
            raise AuthorityUnavailable("labor rebuild completed component changed its signed original ref")
        rb.components[ref] = parsed
    elif kind == "rebuild_checkpoint":
        parsed = BodyState(**value)
        q = r.request
        if (parsed.profile_id != state.policy.profile_id or parsed.version != q.checkpoint.version
                or task.column.canonical_digest != q.checkpoint_digest or task.metadata[0] != 1
                or task.metadata[2:] != (*r.namespace.as_tuple,q.checkpoint_producer_activity_id,q.checkpoint_producer_operation_id)):
            raise AuthorityUnavailable("labor checkpoint is not its exact true Body history and producing event")
        rb.checkpoint_state = parsed
    _reserve_rebuild_v1(r,rb)
    return value


def _rebuild_receipt_v1(r,state,operation):
    from ..runtime_contracts import CommitReceipt
    from ..graph_types import GraphVersion,NamespaceEpoch
    rb = _rebuild_state_v1(r,state)
    for kind in ("rebuild_receipt","rebuild_reads","rebuild_writes"):
        if _metadata(r,(kind,operation)) is None:
            raise MissingProductionOriginalV1("actual_character_labor_producer_receipt_and_event")
    receipt,reads,writes = (state.tasks[(kind,operation)] for kind in
        ("rebuild_receipt","rebuild_reads","rebuild_writes"))
    if reads.metadata != writes.metadata:
        raise AuthorityUnavailable("labor original receipt event columns crossed actual commits")
    def versions(task):
        return tuple(GraphVersion(AtomKey.from_token(key),revision) for key,revision in task.result)
    result = CommitReceipt("committed",operation,*receipt.metadata,versions(reads),versions(writes),
        (NamespaceEpoch(*r.namespace.as_tuple,reads.metadata[1]),),
        tuple(receipt.result["ledger_refs"]),tuple(receipt.result["outbox_refs"]))
    rb.receipts[operation] = result
    return result


def _prepare_rebuild_controls_v1(r,state):
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    from .d11_character_labor_accounting_v1 import _require_accounting
    rb = _rebuild_state_v1(r,state)
    q = r.request
    action_task = state.tasks[("head",q.action_intent_ref)]
    root_task = state.tasks[("root","life-root:"+state.root.action_operation_id)]
    policy_task = state.tasks[("policy",q.policy_ref)]
    if (q.action_original.original_ref != "life-root:"+state.root.action_operation_id
            or NamespaceId.from_key(AtomKey.from_token(q.checkpoint.ref)) != r.namespace
            or action_task.metadata[0] != q.action_intent.version
            or action_task.column.canonical_digest != q.action_intent_digest
            or q.action_original.kind != "d11.life_source_note_action"
            or root_task.metadata[1] != q.action_original.original_digest
            or q.policy_digest != policy_task.metadata[2]
            or q.trigger_original != q.action_original
            or state.root.activity_id != r.activity_id
            or AtomKey.from_token(q.checkpoint.ref).name != state.policy.profile_id):
        raise AuthorityUnavailable("labor rebuild changed its actual A/policy/checkpoint/trigger originals")
    if q.checkpoint_original is not None:
        receipt = _initial_body_checkpoint_v1(r,state)
    else:
        receipt = _rebuild_receipt_v1(r,state,q.checkpoint_producer_operation_id)
        if (receipt.activity_id != q.checkpoint_producer_activity_id
                or canonical_digest(receipt) != q.checkpoint_receipt_digest):
            raise AuthorityUnavailable("labor rebuild checkpoint producer receipt differs from its expected original")
    meter = current_c09_sql_meter_v2()
    if meter is None:
        raise AuthorityUnavailable("labor rebuild controls require their actual bounded Method quantum")
    while rb.scan_index < len(_REBUILD_KINDS):
        kind = _REBUILD_KINDS[rb.scan_index]
        if rb.pending is None:
            table,columns,where,args = _rebuild_table_query_v1(r,state,kind,rb.cursor)
            row = meter.read_fixed_row(r.db,table,columns,where,args)
            if row is None:
                rb.scan_index += 1
                rb.cursor = None
                continue
            if len(rb.rows.get(kind,())) >= 128:
                raise MissingProductionOriginalV1("complete_bounded_character_labor_rebuild_metadata:"+kind)
            rb.pending = tuple(row)
        row = rb.pending
        ref = (row[0],row[1]) if kind == "passive" else row[0]
        identity = ("rebuild_"+kind,ref)
        if _metadata(r,identity) is None:
            raise MissingProductionOriginalV1("existing_character_labor_rebuild_original:"+kind)
        if kind == "basis":
            basis = next(b for b in rb.bases.values() if "character-labor-accounting:"+b.execution_id == ref)
            if _metadata(r,("rebuild_accounting",basis.accounting_ref)) is None:
                raise MissingProductionOriginalV1("existing_labor_original_cpu_accounting")
            _require_accounting(basis,rb.accounting[basis.accounting_ref])
            state.keys.update(AtomKey.from_token(v) for v in (basis.reservation_ref,basis.settlement_ref))
        if kind == "component":
            state.keys.add(AtomKey.from_token(rb.components[ref].settlement_ref))
        rb.rows.setdefault(kind,[]).append(row)
        rb.cursor,rb.pending = ref,None
        _reserve_rebuild_v1(r,rb)
    rb.controls_complete = True
    if q.checkpoint_original is None:
        state.producers.add((q.checkpoint_producer_activity_id,q.checkpoint_producer_operation_id))


def _prepare_rebuild_facts_v1(r,state):
    rb = _rebuild_state_v1(r,state)
    if state.permission is None or not rb.controls_complete:
        raise AuthorityUnavailable("labor rebuild Body history requires its actual complete SourceALL/controls")
    state.permission.require_for_v3(r)
    if _metadata(r,("rebuild_checkpoint",r.request.checkpoint.ref)) is None:
        raise MissingProductionOriginalV1("actual_body_checkpoint_history_eof")
    for ref,component in rb.components.items():
        task = state.tasks[("rebuild_component",ref)]
        _rebuild_receipt_v1(r,state,task.metadata[0])
    rb.facts_complete = True
    _reserve_rebuild_v1(r,rb)


def _require_rebuild_header_censuses_v1(r,state,meter):
    rb = _rebuild_state_v1(r,state)
    for kind in _REBUILD_KINDS:
        cursor = None
        for expected in rb.rows.get(kind,()):
            table,columns,where,args = _rebuild_table_query_v1(r,state,kind,cursor)
            row = meter.read_fixed_row(r.db,table,columns,where,args)
            if row != expected:
                raise AuthorityUnavailable("labor rebuild metadata census changed before current W01")
            cursor = (row[0],row[1]) if kind == "passive" else row[0]
        table,columns,where,args = _rebuild_table_query_v1(r,state,kind,cursor)
        if meter.read_fixed_row(r.db,table,columns,where,args) is not None:
            raise AuthorityUnavailable("labor rebuild metadata negative EOF changed before current W01")
    for identity in tuple(state.selected):
        state.tasks[identity].require_header_v3(meter)


def require_character_labor_rebuild_inputs_v1(db, *, frame, request, body_readers):
    from .current_method_learning_read_v3 import _method_active
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    from ..graph_types import GraphVersion
    r = _method_active(db)
    if r is None or not _is_character_labor_rebuild_v1(r) or r.request is not request:
        raise AuthorityUnavailable("labor rebuild requires its actual retained same-Method Source inputs")
    state = require_character_labor_source_v1(r)
    rb = _rebuild_state_v1(r,state)
    write = _WRITES.get(r)
    if (write is None or write[1] is not body_readers.labor_scope or write[2] != r.owner_binding
            or not rb.controls_complete or not rb.facts_complete or not r.inputs_sealed
            or not r.read_finished or not r.business_started
            or frame.envelope.identity.operation_id != r.operation_id):
        raise AuthorityUnavailable("labor rebuild left its actual Source EOF or fresh WRITE pairing")
    require_character_labor_write_v1(r)
    state.permission.require_for_v3(r)
    meter = current_c09_sql_meter_v2()
    if meter is None:
        raise AuthorityUnavailable("labor rebuild metadata requires its actual bounded WRITE quantum")
    _require_rebuild_header_censuses_v1(r,state,meter)
    read = CurrentDomainReadV1(frame)
    profile,current,reservations = body_readers._current_body(db,read,state.policy.profile_id)
    census = body_readers.require_labor_census_v1(db,read,current)
    bodies = tuple(a for a in frame.snapshot.atoms if a.key.type_name in {
        "d02.body_state.v1","d02.body_profile.v1","d02.reservation.v1","d02.settlement.v1","d02.character_labor_rebuild_head.v1"})
    q = r.request
    checkpoint_task = state.tasks[("rebuild_checkpoint",q.checkpoint.ref)]
    checkpoint = ((q.checkpoint.ref,q.checkpoint.version),(rb.checkpoint_state,
        rb.receipts[q.checkpoint_producer_operation_id],checkpoint_task.column.canonical_digest,checkpoint_task.metadata))
    from .d02_character_labor_rebuild_v1 import _body_checkpoint_versions_v1
    if GraphVersion(AtomKey.from_token(q.checkpoint.ref),q.checkpoint.version) not in _body_checkpoint_versions_v1(checkpoint[1][1]):
        raise AuthorityUnavailable("labor Body checkpoint is not its true producing W01 member")
    wanted = {e.execution_id for e in census.entries if e.classification != "fixed_v1"}
    if not wanted <= set(rb.bases):
        raise MissingProductionOriginalV1("fresh_core_labor_entry_not_in_sealed_graph_basis_census")
    components = tuple((c,state.tasks[("rebuild_component",ref)].metadata[0],
        state.tasks[("rebuild_component",ref)].metadata[1],
        rb.receipts[state.tasks[("rebuild_component",ref)].metadata[0]]) for ref,c in sorted(rb.components.items()))
    metadata = SimpleNamespace(checkpoints=(checkpoint,),passive_policies=tuple(rb.passive.values()),
        body_atoms=bodies,components=components,segments=tuple(rb.segments.values()),
        census=census,source_versions=state.permission.versions)
    return metadata,tuple(rb.bases[k] for k in sorted(wanted)),state.policy

def read_current_character_labor_resource_inventory_v1(db,read,family):
    """Named scope inventory; unrelated or invalid heads are never fake Bodies."""
    if family not in {"d02.body_state.v1","d02.body_profile.v1","d02.reservation.v1","d02.settlement.v1"}:
        raise AuthorityUnavailable("unregistered labor resource inventory family")
    from .current_method_learning_read_v3 import _method_active
    r = _method_active(db)
    if r is not None and r in _STATES:
        require_character_labor_source_v1(r)
        return True,complete_labor_scope_inventory_v1(db,read,family)
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from ..authority_service.character_labor_source_read_v1 import (
        _READERS as authority_labor_readers,complete_authority_labor_scope_inventory_v1)
    work = _authority_attachment_owner_v3(db)
    if work is not None and work in authority_labor_readers:
        return True,complete_authority_labor_scope_inventory_v1(db,read,family)
    return False,None

class _BodyCheckpointFenceReadV1:
    def __init__(self,reader,identity):
        self.reader,self.identity = reader,identity
        self.complete,self.result = False,None

    def advance(self,meter):
        state = require_character_labor_source_v1(self.reader)
        rb = _rebuild_state_v1(self.reader,state)
        self.reader.require_current(meter=meter)
        if rb.install_fence is not None:
            self.complete,self.result = True,rb.install_fence

    def require_header_v3(self,meter):
        state = require_character_labor_source_v1(self.reader)
        rb = _rebuild_state_v1(self.reader,state)
        if not self.complete or self.result != rb.install_fence:
            raise AuthorityUnavailable("actual Body install fence lookup is incomplete")
        self.reader.require_current(meter=meter)


def resolve_character_labor_checkpoint_fence_v1(work):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,_READERS
    r = work.state
    if type(r) is not _MethodLearningReadV3 or r not in _READERS or r.work is not work:
        return False
    state = _STATES.get(r)
    if state is None or not _is_character_labor_rebuild_v1(r) or state.rebuild is None:
        return False
    rb = state.rebuild
    original = rb.install_original
    if original is None or not rb.install_fence_pending or rb.install_fence is not None:
        return False
    if r.db.in_transaction or r.store._db.in_transaction:
        raise AuthorityUnavailable("Body checkpoint fence lookup must precede Graph SQL")
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    work._require_invocation(r.graph)
    require_character_labor_source_v1(r)
    r.graph._validate_read_fence_v3(r.fence)
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock,runtime_storage_quantum_v3(r.db) as meter:
        r.require_current(meter=meter)
    port = r.graph._GraphCoordinator__content_fence_v2
    permit,status = port.get_fence_operation(namespace=r.namespace,
        authority_namespace=original.authority_namespace,operation_id=original.attempt_id)
    if (permit is None or status != "finished" or permit.operation != "write"
            or permit.operation_id != original.attempt_id or permit.namespace != original.authority_namespace
            or permit.generation != original.activation_generation or canonical_digest(permit) != original.permit_digest):
        raise AuthorityUnavailable("initial Body checkpoint has no exact actual finished Core WRITE gate")
    r.graph._validate_read_fence_v3(r.fence)
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock,runtime_storage_quantum_v3(r.db) as meter:
        r.require_current(meter=meter)
    rb.install_fence = (permit,status)
    return True


def _initial_body_checkpoint_v1(r,state):
    from ..contracts import Event,Scope
    from .d02_character_labor_rebuild_v1 import BODY_POLICY_CHECKPOINT_KIND_V1
    import json
    q,rb = r.request,_rebuild_state_v1(r,state)
    original = q.checkpoint_original
    if (original.kind != "d02."+BODY_POLICY_CHECKPOINT_KIND_V1
            or _metadata(r,("rebuild_install",original.original_ref)) is None):
        raise MissingProductionOriginalV1("actual_signed_initial_body_checkpoint")
    checkpoint = rb.install_original
    task = state.tasks[("rebuild_install",original.original_ref)]
    receipt = checkpoint.graph_receipt
    if (task.metadata[1] != original.original_digest or checkpoint.original_ref != original.original_ref
            or checkpoint.namespace != r.namespace or checkpoint.producing_operation_id != q.checkpoint_producer_operation_id
            or q.checkpoint_producer_activity_id != "c04.fixed_body_install.v1"
            or canonical_digest(receipt) != q.checkpoint_receipt_digest
            or (q.checkpoint,q.checkpoint_digest) not in checkpoint.write_digests):
        raise AuthorityUnavailable("initial Body checkpoint left its authenticated policy/event/Body locator")
    raw = json.loads(checkpoint.event_json)
    event = Event(Scope(**raw["scope"]),raw["event_id"],raw["occurred_at"],raw["kind"],raw["payload"])
    expected = {"rebuild_install_reads":[[v.ref,0] for v,_ in checkpoint.write_digests],
        "rebuild_install_writes":[[v.key.token,v.revision] for v in receipt.revisions],
        "rebuild_install_epochs":[[*r.namespace.as_tuple,checkpoint.before_epoch]],
        "rebuild_install_invalidated":[[v.key.token,v.revision] for v in receipt.invalidated]}
    for kind,value in expected.items():
        if _metadata(r,(kind,checkpoint.producing_operation_id)) is None:
            raise MissingProductionOriginalV1("actual_initial_body_checkpoint_event_metadata")
        actual = state.tasks[(kind,checkpoint.producing_operation_id)]
        if canonical_serialize(actual.result) != canonical_serialize(value) or actual.metadata != (event.digest,receipt.epoch.revision):
            raise AuthorityUnavailable("initial Body checkpoint differs from its complete real Graph event")
    rb.install_fence_pending = True
    _metadata(r,("rebuild_install_fence",checkpoint.attempt_id))
    rb.receipts[q.checkpoint_producer_operation_id] = receipt
    return receipt

SELECT_REBUILD_KIND_V1 = "select_character_labor_rebuild_v1"


def is_character_labor_rebuild_selector_v1(reader):
    from .d02_character_labor_rebuild_v1 import CharacterLaborRebuildSelectorV1
    return (reader in _STATES and reader.operation_kind == SELECT_REBUILD_KIND_V1
        and type(reader.request) is CharacterLaborRebuildSelectorV1)


def _selector_metadata_spec_v1(r,state,identity):
    from ..domains.d02.character_labor_v1 import CharacterLaborRebuildHeadV1
    kind,ref = identity
    if not is_character_labor_rebuild_selector_v1(r):
        raise AuthorityUnavailable("actual private labor metadata selector required")
    key = AtomKey.from_token(ref)
    if (kind != "selector_head" or key.type_name != "d02.character_labor_rebuild_head.v1"
            or NamespaceId.from_key(key) != r.namespace or key.name != state.policy.profile_id):
        raise AuthorityUnavailable("labor selector can read only its explicit chronological control metadata")
    return ("graph_atoms","value",("token","bot","persona"),(ref,*r.namespace.as_tuple),
        ("revision","valid","value_cell_id"),tuple((f.name,) for f in fields(CharacterLaborRebuildHeadV1)),None)


def advance_character_labor_rebuild_selection_v1(r,meter):
    from ..graph_types import Owner,GraphVersion
    from ..runtime_contracts import VersionedRef
    from ..domains.d02.character_labor_v1 import CharacterLaborRebuildHeadV1,character_labor_rebuild_key_v1
    from .d02_character_labor_rebuild_v1 import (
        RebuildCharacterLaborBodyRequestV1,PreparedCharacterLaborRebuildSelectionV1,_REBUILD_SELECTION_KEY_V1,
        BODY_POLICY_CHECKPOINT_KIND_V1,_body_checkpoint_versions_v1)
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    if not is_character_labor_rebuild_selector_v1(r) or not r.inventory_sealed:
        raise AuthorityUnavailable("labor selector requires its actual complete Method HEAD census")
    state = require_character_labor_source_v1(r)
    r.require_current(meter=meter)
    if state.selector_request is not None:
        require_character_labor_rebuild_selector_ready_v1(r,meter=meter)
        return state.selector_proof
    request = r.request
    if _metadata(r,("policy",request.policy_ref)) is None:
        raise MissingProductionOriginalV1("actual_explicit_signed_labor_policy")
    state.keys.add(AtomKey.from_token(request.action_intent_ref))
    action = _metadata(r,("head",request.action_intent_ref))
    action_task = state.tasks[("head",request.action_intent_ref)]
    if action is None or not action_task.metadata[1]:
        raise MissingProductionOriginalV1("actual_selected_action_A")
    ref = "life-root:"+action["identity"]["operation_id"]
    state.originals.add(ref)
    _metadata(r,("root",ref))
    root = state.root
    if root.activity_id != r.activity_id or root.action_intent_digest != action_task.column.canonical_digest:
        raise AuthorityUnavailable("labor selector changed the actual signed action A")
    receipt_a = _rebuild_receipt_v1(r,state,root.action_operation_id)
    expected_a = tuple(GraphVersion(AtomKey.from_token(k),v) for k,v,_ in root.write_commitments)
    if (canonical_digest(receipt_a) != root.receipt_digest
            or set(receipt_a.write_versions) != set(expected_a)
            or GraphVersion(AtomKey.from_token(root.action_intent_ref),action_task.metadata[0]) not in expected_a):
        raise AuthorityUnavailable("labor selection has no exact complete producing A receipt/event")
    body_key = AtomKey(Owner("persona",*r.namespace.as_tuple),"d02.body_state.v1",state.policy.profile_id)
    if body_key.token not in r.heads:
        raise MissingProductionOriginalV1("actual_current_Body_before_labor_rebuild")
    if r.heads[body_key.token][1] != 1:
        raise MissingProductionOriginalV1("valid_actual_current_Body_before_labor_rebuild")
    head_key = character_labor_rebuild_key_v1(r.namespace,state.policy.profile_id)
    head = None
    if head_key.token in r.heads:
        raw = _metadata(r,("selector_head",head_key.token))
        task = state.tasks[("selector_head",head_key.token)]
        if raw is None or task.metadata[1] != 1:
            raise MissingProductionOriginalV1("valid_actual_labor_rebuild_head_or_authenticated_initial_checkpoint")
        head = CharacterLaborRebuildHeadV1(**raw)
        if head.profile_id != state.policy.profile_id or head.revision != task.metadata[0]:
            raise AuthorityUnavailable("labor selection changed its actual chronological head")
    state.selector_checkpoint = (VersionedRef(body_key.token,1) if head is None
        else VersionedRef(head.checkpoint_ref,head.checkpoint_revision))
    checkpoint = state.selector_checkpoint
    if checkpoint.ref != body_key.token:
        raise AuthorityUnavailable("labor Head checkpoint belongs to a different Body")
    history = meter.read_fixed_row(r.db,"graph_history",
        ("valid","value_cell_id","event_bot","event_persona","event_session","event_id"),
        "token=? AND revision=?",(checkpoint.ref,checkpoint.version))
    if history is None or history[0] != 1 or history[1] is None:
        raise MissingProductionOriginalV1("actual_Body_checkpoint_history_locator")
    if history[2:4] != r.namespace.as_tuple:
        raise AuthorityUnavailable("labor checkpoint event crossed its actual namespace")
    state.selector_history = (checkpoint,tuple(history))
    checkpoint_digest = None if head is None else head.checkpoint_digest
    activity,operation = history[4:6]
    original_ref = None
    if activity == "c04.fixed_body_install.v1":
        table = "graph_d11_life_originals_v1"
        row = meter.read_fixed_row(r.db,table,("original_ref","payload_digest"),
            "bot=? AND persona=? AND kind=? AND producing_operation_id=? ORDER BY original_ref",
            (*r.namespace.as_tuple,BODY_POLICY_CHECKPOINT_KIND_V1,operation))
        if row is None:
            raise MissingProductionOriginalV1("initial_Body_checkpoint_NOT_MIGRATED")
        if meter.read_fixed_row(r.db,table,("original_ref",),
                "bot=? AND persona=? AND kind=? AND producing_operation_id=? AND original_ref>? ORDER BY original_ref",
                (*r.namespace.as_tuple,BODY_POLICY_CHECKPOINT_KIND_V1,operation,row[0])) is not None:
            raise AuthorityUnavailable("initial Body checkpoint producer has ambiguous originals")
        _metadata(r,("rebuild_install",row[0]))
        rb = _rebuild_state_v1(r,state)
        original = rb.install_original
        original_digests = tuple(d for v,d in original.write_digests if v == checkpoint)
        if (len(original_digests) != 1 or checkpoint_digest is not None and original_digests[0] != checkpoint_digest
                or original.producing_operation_id != operation or original.namespace != r.namespace
                or row[1] != state.tasks[("rebuild_install",row[0])].metadata[1]):
            raise AuthorityUnavailable("initial Body selection is not its true same-install original")
        checkpoint_digest = original_digests[0]
        receipt = original.graph_receipt
        original_ref = ProductionOriginalRefV1("d02."+BODY_POLICY_CHECKPOINT_KIND_V1,row[0],row[1])
    else:
        if checkpoint_digest is None:
            raise MissingProductionOriginalV1("authenticated_checkpoint_metadata_before_first_labor_head")
        receipt = _rebuild_receipt_v1(r,state,operation)
        if receipt.activity_id != activity:
            raise AuthorityUnavailable("Body checkpoint is not its actual W01 producing receipt")
    if GraphVersion(body_key,checkpoint.version) not in _body_checkpoint_versions_v1(receipt):
        raise AuthorityUnavailable("Body checkpoint is outside its actual producing receipt")
    root_task = state.tasks[("root",ref)]
    a_original = ProductionOriginalRefV1("d11.life_source_note_action",ref,root_task.metadata[1])
    state.selector_request = RebuildCharacterLaborBodyRequestV1(
        VersionedRef(request.action_intent_ref,action_task.metadata[0]),action_task.column.canonical_digest,
        a_original,request.policy_ref,request.policy_revision,state.tasks[("policy",request.policy_ref)].metadata[2],
        checkpoint,checkpoint_digest,operation,activity,canonical_digest(receipt),a_original,original_ref)
    _reserve_rebuild_v1(r,_rebuild_state_v1(r,state))
    state.selector_proof = PreparedCharacterLaborRebuildSelectionV1(_REBUILD_SELECTION_KEY_V1,r,state.selector_request)
    return state.selector_proof


def require_character_labor_rebuild_selector_ready_v1(r,*,meter=None):
    if not is_character_labor_rebuild_selector_v1(r):
        raise AuthorityUnavailable("actual private labor rebuild selector required")
    state = require_character_labor_source_v1(r)
    if state.selector_request is None or state.permission is not None or state.semantic_scope is not None:
        raise AuthorityUnavailable("labor selector is metadata-only and requires complete selected originals")
    r.require_current(meter=meter)
    if meter is None:
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter = current_c09_sql_meter_v2()
    if meter is None:
        raise AuthorityUnavailable("labor selector requires its actual bounded Method metadata quantum")
    checkpoint,expected_history = state.selector_history
    actual_history = meter.read_fixed_row(r.db,"graph_history",
        ("valid","value_cell_id","event_bot","event_persona","event_session","event_id"),
        "token=? AND revision=?",(checkpoint.ref,checkpoint.version))
    if actual_history != expected_history:
        raise AuthorityUnavailable("labor selector checkpoint history locator changed")
    for identity in tuple(state.selected):
        state.tasks[identity].require_header_v3(meter)
    return state.selector_request

LIST_REBUILD_OPTIONS_KIND_V1 = "list_character_labor_rebuild_options_v1"


def is_character_labor_rebuild_options_v1(r):
    from .d02_character_labor_rebuild_v1 import CharacterLaborRebuildOptionsRequestV1
    return (r in _STATES and r.operation_kind == LIST_REBUILD_OPTIONS_KIND_V1
        and type(r.request) is CharacterLaborRebuildOptionsRequestV1)


def is_character_labor_metadata_selector_v1(r):
    return is_character_labor_rebuild_selector_v1(r) or is_character_labor_rebuild_options_v1(r)


def advance_character_labor_metadata_selection_v1(r,meter):
    return (advance_character_labor_rebuild_options_v1(r,meter) if is_character_labor_rebuild_options_v1(r)
        else advance_character_labor_rebuild_selection_v1(r,meter))


def _options_metadata_spec_v1(r,state,identity):
    kind,ref = identity
    if not is_character_labor_rebuild_options_v1(r):
        raise AuthorityUnavailable("actual private labor options READ required")
    if kind == "options_policy":
        if ref not in state.options.headers:
            raise AuthorityUnavailable("labor policy is outside its actual complete-PK catalogue")
        return ("graph_d02_production_policies_v1","payload_json",
            ("bot","persona","policy_ref","revision"),(*r.namespace.as_tuple,*ref),
            ("kind","profile_id","payload_digest","signature"),
            tuple((f.name,) for f in fields(CharacterLaborPolicyV1)),"d11.d02-production-policy.v1")
    if kind == "options_recipe":
        from ..domains.d10 import ActivityRecipe
        if state.root is None or ref != state.root.recipe_ref:
            raise AuthorityUnavailable("labor options recipe left its signed actual A")
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != r.namespace or key.type_name != "d10.activity_recipe.v1":
            raise AuthorityUnavailable("labor options require their actual recipe namespace")
        return ("graph_atoms","value",("token","bot","persona"),(ref,*r.namespace.as_tuple),
            ("revision","valid","value_cell_id"),tuple((f.name,) for f in fields(ActivityRecipe)),None)
    raise AuthorityUnavailable("unknown exact labor options metadata projection")


def _finish_options_metadata_v1(task,value):
    from ..domains.d10 import ActivityRecipe
    r,state = task.reader,require_character_labor_source_v1(task.reader)
    kind,ref = task.identity
    if kind == "options_policy":
        policy = character_labor_policy_from_wire_v1(value)
        if (policy.namespace != r.namespace or (policy.policy_ref,policy.revision) != ref
                or task.metadata != state.options.headers[ref]
                or task.metadata[:2] != ("labor",policy.profile_id)):
            raise AuthorityUnavailable("labor policy catalogue lost its signed PK/profile/namespace")
        return policy
    if kind == "options_recipe":
        if type(value) is not dict or set(value) != {f.name for f in fields(ActivityRecipe)}:
            raise AuthorityUnavailable("closed actual labor recipe metadata required")
        value = dict(value);value["allowed_steps"] = tuple(value["allowed_steps"])
        result = ActivityRecipe(**value)
        if task.metadata[1] != 1:
            raise AuthorityUnavailable("labor options recipe is not its valid actual current head")
        return result
    raise AuthorityUnavailable("unknown labor options decoder")


class _LaborPolicyOptionsCatalogueV1:
    def __init__(self,r,identity):
        self.reader,self.identity = r,identity
        self.cursor,self.pending,self.complete,self.result = ("",0),None,False,None
        self.rows = []

    def _next(self,meter,cursor):
        r = self.reader
        return meter.read_fixed_row(r.db,"graph_d02_production_policies_v1",
            ("policy_ref","revision","kind","profile_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind='labor' AND (policy_ref>? OR (policy_ref=? AND revision>?)) ORDER BY policy_ref,revision",
            (*r.namespace.as_tuple,cursor[0],cursor[0],cursor[1]))

    def advance(self,meter):
        r,state = self.reader,require_character_labor_source_v1(self.reader)
        r.require_current(meter=meter)
        if self.complete:
            self.require_header_v3(meter);return True
        if self.pending is None:
            row = self._next(meter,self.cursor)
            if row is None:
                self.complete,self.result = True,tuple(self.rows);return True
            if len(self.rows) >= 128:
                raise MissingProductionOriginalV1("complete_labor_policy_catalogue_exceeds_128_query_cap")
            locator = row[:2]
            state.options.headers[locator] = row[2:]
            state.selected.add(("options_policy",locator))
            from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
            task = create_current_beta1_metadata_task_v3(r,("options_policy",locator))
            state.tasks[("options_policy",locator)] = task
            self.pending = (row,task)
            _reserve_labor_options_v1(r)
            return False
        row,task = self.pending
        if not task.advance(meter):
            return False
        task.require_header_v3(meter)
        policy = task.result
        from ..graph_types import Owner
        from .d11_life_contract_v1 import RECIPE_ID,WORK_KIND
        recipe = state.tasks[("options_recipe",state.root.recipe_ref)]
        recipe_value = recipe.result
        expected_recipe = (RECIPE_ID,2,"real_execution",("source_note",),False)
        reasons = []
        if (recipe_value.recipe_id,recipe_value.version,recipe_value.reality,
                recipe_value.allowed_steps,recipe_value.preemptible) != expected_recipe:
            reasons.append("recipe_not_nonpreemptible_source_note_v2")
        if (policy.recipe_ref,policy.recipe_revision,policy.recipe_digest) != (
                state.root.recipe_ref,recipe.metadata[0],recipe.column.canonical_digest):
            reasons.append("policy_recipe_mismatch")
        if policy.work_kind != WORK_KIND or policy.reality != "real_execution":
            reasons.append("policy_work_kind_or_reality_mismatch")
        if policy.valid_until_utc <= r.initial_now_utc:
            reasons.append("policy_expired")
        profile = AtomKey(Owner("persona",*r.namespace.as_tuple),"d02.body_profile.v1",policy.profile_id)
        body = AtomKey(Owner("persona",*r.namespace.as_tuple),"d02.body_state.v1",policy.profile_id)
        if profile.token not in r.heads or r.heads[profile.token][1] != 1:
            reasons.append("current_profile_absent")
        if body.token not in r.heads or r.heads[body.token][1] != 1:
            reasons.append("current_body_absent")
        self.rows.append({"policy_ref":policy.policy_ref,"policy_revision":policy.revision,
            "policy_digest":row[4],"profile_id":policy.profile_id,"recipe_ref":policy.recipe_ref,
            "recipe_revision":policy.recipe_revision,"valid_until_utc":policy.valid_until_utc,
            "eligible":not reasons,"unavailable_reasons":reasons})
        self.cursor,self.pending = row[:2],None
        _reserve_labor_options_v1(r)
        return False

    def require_header_v3(self,meter):
        r,state = self.reader,require_character_labor_source_v1(self.reader)
        r.require_current(meter=meter)
        if not self.complete:
            raise AuthorityUnavailable("labor policy catalogue remains partial")
        # Installed policy rows are immutable W01 originals. The actual Method
        # stamp bookends their entire paged census; do not reread 128 rows in
        # the terminal quantum after each row already completed its own EOF.
        if len(self.rows) != len(state.options.headers) or self._next(meter,self.cursor) is not None:
            raise AuthorityUnavailable("labor policy catalogue acquired an unselected entry")


def _reserve_labor_options_v1(r):
    from .dispatch_current_inventory_v3 import _heap
    state = _STATES[r]
    size = _heap((state.options.headers,tuple((k,t.result) for k,t in state.tasks.items()),
        tuple(t.rows for k,t in state.tasks.items() if k[0] == "options_catalog")))+4096
    if size > state.options.reserved:
        r.operation.retain(size-state.options.reserved)
        state.options.reserved = size


def advance_character_labor_rebuild_options_v1(r,meter):
    from ..graph_types import GraphVersion
    from .d02_character_labor_rebuild_v1 import PreparedCharacterLaborRebuildOptionsV1,_REBUILD_SELECTION_KEY_V1
    if not is_character_labor_rebuild_options_v1(r) or not r.inventory_sealed:
        raise AuthorityUnavailable("labor options require their complete actual Method HEAD census")
    state = require_character_labor_source_v1(r)
    r.require_current(meter=meter)
    if state.options is None:
        state.options = SimpleNamespace(headers={},reserved=0,proof=None)
    if state.options.proof is not None:
        require_character_labor_rebuild_options_ready_v1(r,meter=meter)
        return state.options.proof
    action_ref = r.request.action_intent_ref
    state.keys.add(AtomKey.from_token(action_ref))
    action = _metadata(r,("head",action_ref))
    action_task = state.tasks[("head",action_ref)]
    if action is None or action_task.metadata[1] != 1:
        raise MissingProductionOriginalV1("actual_signed_action_A_for_labor_options")
    root_ref = "life-root:"+action["identity"]["operation_id"]
    state.originals.add(root_ref)
    if _metadata(r,("root",root_ref)) is None:
        raise MissingProductionOriginalV1("actual_signed_A_original_for_labor_options")
    root = state.root
    if root.activity_id != r.activity_id or root.action_intent_digest != action_task.column.canonical_digest:
        raise AuthorityUnavailable("labor options changed the actual A control commitments")
    receipt = _rebuild_receipt_v1(r,state,root.action_operation_id)
    expected = tuple(GraphVersion(AtomKey.from_token(k),v) for k,v,_ in root.write_commitments)
    if (canonical_digest(receipt) != root.receipt_digest or set(receipt.write_versions) != set(expected)
            or GraphVersion(AtomKey.from_token(action_ref),action_task.metadata[0]) not in expected):
        raise AuthorityUnavailable("labor options lack the complete actual producing A event")
    if _metadata(r,("options_recipe",root.recipe_ref)) is None:
        raise MissingProductionOriginalV1("actual_A_recipe_control_metadata")
    rows = _metadata(r,("options_catalog",action_ref))
    view = {"schema":"d02.character-labor-rebuild-options.v1","action_intent_ref":action_ref,
        "activity_id":r.activity_id,"audience_ref":r.audience_ref,
        "parent_budget_lease_ref":r.parent_budget_lease_ref,"coverage":"complete",
        "as_of_utc":r.initial_now_utc,"policy_count":len(rows),"options":list(rows)}
    state.options.proof = PreparedCharacterLaborRebuildOptionsV1(_REBUILD_SELECTION_KEY_V1,r,view)
    return state.options.proof


def require_character_labor_rebuild_options_ready_v1(r,*,meter=None):
    state = require_character_labor_source_v1(r)
    if (not is_character_labor_rebuild_options_v1(r) or state.options is None
            or state.options.proof is None or state.permission is not None or state.semantic_scope is not None):
        raise AuthorityUnavailable("actual complete metadata-only labor options required")
    r.require_current(meter=meter)
    if meter is None:
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter = current_c09_sql_meter_v2()
    if meter is None:
        raise AuthorityUnavailable("labor options currentness needs its actual bounded metadata quantum")
    for identity,task in tuple(state.tasks.items()):
        if identity[0] != "options_policy":
            task.require_header_v3(meter)
    return state.options.proof
