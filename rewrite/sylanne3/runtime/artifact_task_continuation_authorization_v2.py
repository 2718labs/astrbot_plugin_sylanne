"""One prospective continuation generation, with immutable prior file history."""
from dataclasses import dataclass
import json, math
from ..runtime_contracts import NamespaceId, canonical_digest
from ..graph_types import AtomKey
from ..domains.d01.production_operations_v1 import plain_v1
from .d01_production_operations_v1 import MissingProductionOriginalV1
from .d11_life_preparation_v1 import _read, TABLE

KIND = "artifact_task_continuation_authorization_v2"

@dataclass(frozen=True, slots=True)
class ArtifactTaskContinuationAuthorizationV2:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    authorization_id: str
    generation: int
    original_objective_ref: str
    original_objective_digest: str
    goal_ref: str
    project_ref: str
    plan_ref: str
    waiting_checkpoint_ref: str
    waiting_checkpoint_revision: int
    waiting_checkpoint_digest: str
    predecessor_result_ref: str
    predecessor_result_digest: str
    predecessor_effect_id: str
    predecessor_effect_marker: str
    fresh_c02_operation_id: str
    fresh_source_ref: str
    fresh_source_revision: int
    fresh_source_digest: str
    fresh_root_registration_ref: str
    fresh_root_registration_digest: str
    current_standing_policy_ref: str
    current_standing_policy_version: int
    current_standing_policy_digest: str
    current_parent_budget_lease_ref: str
    current_parent_budget_grant_version: int
    current_parent_budget_grant_digest: str
    predecessor_artifact_version: int
    maximum_artifact_version: int
    maximum_new_versions: int
    valid_from_utc: float
    valid_until_utc: float
    previous_authorization_ref: str | None
    previous_authorization_digest: str | None
    authorized_file_action: str = "replace_verified_predecessor"
    maximum_method_runs: int = 1
    schema: str = "d11.artifact-task-continuation-authorization.v2"

    def __post_init__(self):
        if (self.schema != "d11.artifact-task-continuation-authorization.v2"
                or type(self.namespace) is not NamespaceId
                or self.authorized_file_action != "replace_verified_predecessor" or self.maximum_method_runs != 1
                or self.maximum_artifact_version-self.predecessor_artifact_version != self.maximum_new_versions
                or any(type(getattr(self, n)) is not int or getattr(self, n) < 1 for n in
                    ("generation", "waiting_checkpoint_revision", "fresh_source_revision", "current_standing_policy_version", "current_parent_budget_grant_version", "predecessor_artifact_version", "maximum_artifact_version", "maximum_new_versions"))
                or any(type(t) not in (int, float) or not math.isfinite(t) for t in (self.valid_from_utc, self.valid_until_utc))
                or not self.valid_from_utc < self.valid_until_utc
                or (self.previous_authorization_ref is None) != (self.previous_authorization_digest is None)
                or (self.generation == 1) != (self.previous_authorization_ref is None)):
            raise ValueError("exact prospective finite one-method continuation generation required")
        for n in self.__dataclass_fields__:
            v = getattr(self, n)
            if n.endswith("digest") and v is not None and (type(v) is not str or len(v) != 64 or any(c not in "0123456789abcdef" for c in v)):
                raise ValueError("continuation authorization lost immutable digest")
        for n, kind in (("goal_ref", "d08.goal.v1"), ("project_ref", "d10.life_project.v1"),
                ("plan_ref", "d08.personal_plan.v1"), ("fresh_source_ref", "memory.source")):
            k = AtomKey.from_token(getattr(self, n))
            if k.type_name != kind or NamespaceId.from_key(k) != self.namespace:
                raise ValueError("continuation authorization crossed stable task namespace")
        if self.authorization_id != continuation_authorization_id_v2(self.namespace, self.fresh_c02_operation_id, self.fresh_root_registration_ref):
            raise ValueError("continuation authorization changed stable Source/C02/Root identity")

    @property
    def original_ref(self): return self.authorization_id
    @property
    def digest(self): return canonical_digest(plain_v1(self))


def continuation_authorization_id_v2(namespace, c02_operation_id, root_registration_ref):
    return "artifact-task-continuation:" + canonical_digest((namespace, c02_operation_id, root_registration_ref))[:48]


def decode_continuation_authorization_v2(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, ArtifactTaskContinuationAuthorizationV2)


def _predecessor_v2(db, *, namespace, checkpoint, issuer):
    from ..domains.d10.project_checkpoint_v1 import WORK_TYPE, decode_project_checkpoint_type_v1
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1, D11DraftTerminalV1, life_from_wire_v1
    from .d11_life_preparation_v1 import read_prepared_life_v1
    from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
    found = []
    for ref in checkpoint.work_version_refs:
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?", (ref, *namespace.as_tuple)).fetchone()
        if row is None or row[1] != 1: raise MissingProductionOriginalV1("actual_continuation_completed_work")
        work = decode_project_checkpoint_type_v1(WORK_TYPE, json.loads(row[0]))
        adopted = read_adopted_life_original_v1(db, namespace=namespace, result_ref=work.artifact_ref, issuer=issuer)
        if adopted is None: raise MissingProductionOriginalV1("query_original_draft_effect_without_new_attempt")
        terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
        if type(terminal) is not D11DraftTerminalV1 or terminal.status != "completed":
            raise MissingProductionOriginalV1("query_original_draft_effect_without_new_attempt")
        prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
        if prepared is None: raise MissingProductionOriginalV1("actual_continuation_predecessor_prepared")
        witness = require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
        if (work.effect_id, work.project_ref, prepared.plan.project.ref) != (terminal.binding.effect_id, checkpoint.project_ref, checkpoint.project_ref):
            raise ValueError("continuation predecessor crossed actual completed project")
        found.append((witness.version, work.artifact_ref, canonical_digest(adopted), terminal, witness, prepared))
    if not found: raise MissingProductionOriginalV1("actual_verified_continuation_predecessor")
    latest = max(v[0] for v in found); values = [v for v in found if v[0] == latest]
    if len(values) != 1: raise MissingProductionOriginalV1("unique_actual_latest_continuation_predecessor")
    return values[0]


def continuation_authorization_candidate_v2(db, *, objective, checkpoint, checkpoint_ref, checkpoint_digest,
        scope, approval, grant, tool, issuer, now_utc):
    from .ingress_artifact_task_scope_v1 import task_objective_ref_v1
    from .d11_offline_originals_v1 import _utc
    if approval is None or scope.task_kind != "continue":
        raise MissingProductionOriginalV1("current_Owner_approved_named_continuation")
    _, result_ref, result_digest, terminal, witness, prepared = _predecessor_v2(db,
        namespace=scope.namespace, checkpoint=checkpoint, issuer=issuer)
    target = prepared.plan.target
    root = scope.root
    if (target.root_resource_id, target.root_identity, target.filename) != (root.resource_id, root.root_identity, root.filenames[0]):
        raise ValueError("continuation authorization changed physical predecessor file")
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind=? "
        "AND json_extract(payload_json,'$.original_objective_ref')=? ORDER BY json_extract(payload_json,'$.generation') DESC LIMIT 2",
        (*scope.namespace.as_tuple, KIND, task_objective_ref_v1(objective))).fetchall()
    previous = None
    if rows:
        saved = _read(db, issuer=issuer, namespace=scope.namespace, kind=KIND, ref=rows[0][0])
        previous = require_continuation_authorization_history_v2(db, namespace=scope.namespace,
            original_ref=rows[0][0], producing_operation_id=saved[1], raw=saved[0])
        if len(rows) == 2:
            second = _read(db, issuer=issuer, namespace=scope.namespace, kind=KIND, ref=rows[1][0])
            if second[0]["generation"] == previous.generation: raise ValueError("continuation generation fork")
    generation = 1 if previous is None else previous.generation + 1
    from ..host.authority_profile import AdminArtifactDraftToolScopeV1,AdminArtifactDraftToolScopeV2
    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftToolScopeV3
    from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
    if type(tool) in {AdminArtifactDraftToolScopeV2,AdminArtifactDraftToolScopeV3}:physical_cap=tool.maximum_artifact_version
    elif type(tool) is AdminArtifactDraftToolScopeV1:physical_cap=1
    else:raise TypeError("explicit installed continuation tool scope required")
    allowed_writes=max(sum(phase in {"tone_sample","full"} for phase in artifact_draft_phase_sequence_v2(method)) for method in approval.scope.method_refs)
    physical_cap=min(physical_cap,witness.version+allowed_writes)
    maximum_new_versions=physical_cap-witness.version
    if maximum_new_versions<1:raise MissingProductionOriginalV1("actual_continuation_physical_version_capacity")
    deadline = min(_utc(root.valid_until_utc).timestamp(), approval.original_deadline_utc, grant.valid_until_utc)
    if not now_utc < deadline: raise MissingProductionOriginalV1("current_continuation_generation_deadline")
    return ArtifactTaskContinuationAuthorizationV2(scope.namespace, root.installation_id, root.manifest_digest,
        continuation_authorization_id_v2(scope.namespace, scope.c02_operation_id, root.registration_ref), generation,
        task_objective_ref_v1(objective), canonical_digest(plain_v1(objective)), objective.goal_ref, objective.project_ref,
        objective.plan_ref, checkpoint_ref, checkpoint.revision, checkpoint_digest, result_ref, result_digest,
        terminal.binding.effect_id, witness.effect_marker, scope.c02_operation_id, scope.source_ref,
        scope.source_revision, scope.source_digest, root.registration_ref, canonical_digest(plain_v1(root)),
        approval.scope.policy_ref, approval.scope.policy_version, approval.scope_digest, grant.lease_id,
        grant.version, canonical_digest(grant), witness.version,physical_cap,maximum_new_versions,scope.cause_frozen_at_utc, deadline,
        None if previous is None else previous.original_ref, None if previous is None else previous.digest)


def require_continuation_authorization_history_v2(db, *, namespace, original_ref, producing_operation_id, raw):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    value = decode_continuation_authorization_v2(raw)
    producer = read_adopted_domain_operation_v1(db, namespace, producing_operation_id)
    if (value.namespace != namespace or value.original_ref != original_ref or producer is None
            or (producer["domain"], producer["operation_kind"]) != ("d10", "derive_ingress_artifact_task_scope_v1")
            or producer["payload"]["provenance"]["artifact_task_scope"].get("continuation_authorization") != raw):
        raise ValueError("continuation authorization lacks its exact same-W01 scope producer")
    history = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
        (value.waiting_checkpoint_ref, value.waiting_checkpoint_revision)).fetchone()
    if history is None or history[1] != 1 or canonical_digest(json.loads(history[0])) != value.waiting_checkpoint_digest:
        raise ValueError("continuation authorization lost actual waiting checkpoint history")
    scope = producer["payload"]["provenance"]["artifact_task_scope"]
    root = scope["root"]
    objective = producer["payload"]["provenance"]["artifact_task_objective"]
    if (scope["task_kind"] != "continue"
            or (root["installation_id"],root["manifest_digest"])!=(value.installation_id,value.manifest_digest)
            or canonical_digest(objective) != value.original_objective_digest
            or (objective["goal_ref"], objective["project_ref"], objective["plan_ref"]) != (value.goal_ref, value.project_ref, value.plan_ref)
            or (scope["source_ref"], scope["source_revision"], scope["source_digest"], scope["c02_operation_id"]) !=
                (value.fresh_source_ref, value.fresh_source_revision, value.fresh_source_digest, value.fresh_c02_operation_id)
            or canonical_digest(root) != value.fresh_root_registration_digest or root["registration_ref"] != value.fresh_root_registration_ref
            or scope["standing_policy_digest"] != value.current_standing_policy_digest):
        raise ValueError("continuation authorization changed its original objective/fresh inputs/Root")
    from .c09_life_originals_v1 import _read_archive_life_original_v1
    result = _read_archive_life_original_v1(db, namespace, "adopted_life", value.predecessor_result_ref)
    if result is None or canonical_digest(result[0]) != value.predecessor_result_digest:
        raise ValueError("continuation authorization lost original predecessor result")
    from ..domains.d10.project_checkpoint_v1 import CHECKPOINT_TYPE, WORK_TYPE, decode_project_checkpoint_type_v1
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,json.loads(history[0]))
    from .d11_life_contract_v1 import D11LifeTerminalV1,D11DraftTerminalV1,life_from_wire_v1
    from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
    from .d11_life_preparation_v1 import life_prepared_from_wire_v1
    terminal=life_from_wire_v1(result[0]["terminal"],D11LifeTerminalV1)
    if type(terminal) is not D11DraftTerminalV1 or terminal.status!="completed":
        raise ValueError("continuation cannot authorize a new attempt for an unresolved old effect")
    prepared_row=_read_archive_life_original_v1(db,namespace,"prepared",terminal.binding.prepared_original_ref)
    if prepared_row is None:raise ValueError("continuation predecessor lost signed prepared original")
    prepared=life_prepared_from_wire_v1(prepared_row[0])
    witness=require_draft_terminal_readback_v1(prepared=prepared,terminal=terminal)
    works=[]
    for ref in checkpoint.work_version_refs:
        work_row=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=1",(ref,)).fetchone()
        if work_row is None or work_row[1]!=1:raise ValueError("continuation lost original waiting work member")
        works.append(decode_project_checkpoint_type_v1(WORK_TYPE,json.loads(work_row[0])))
    if (checkpoint.state!="waiting" or checkpoint.project_ref!=value.project_ref
            or sum(w.artifact_ref==value.predecessor_result_ref and w.effect_id==value.predecessor_effect_id for w in works)!=1
            or (terminal.binding.effect_id,witness.effect_marker,witness.version)!=(value.predecessor_effect_id,value.predecessor_effect_marker,value.predecessor_artifact_version)):
        raise ValueError("continuation authorization crossed original waiting checkpoint/effect marker")
    if value.previous_authorization_ref is not None:
        prior = _read_archive_life_original_v1(db, namespace, KIND, value.previous_authorization_ref)
        if (prior is None or canonical_digest(prior[0]) != value.previous_authorization_digest
                or prior[0]["generation"] + 1 != value.generation
                or prior[0]["original_objective_ref"] != value.original_objective_ref):
            raise ValueError("continuation authorization lost unbroken generation history")
    return value


def resolve_artifact_task_authorization_deadline_v2(db, *, namespace, scope, objective, issuer,
        bundle, owner_guard, now_utc, parent_budget_lease_ref=None):
    """The shared Graph/Authority reader: only the actually bound child may renew."""
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
    if type(scope) is not IngressArtifactTaskScopeOriginalV3:
        return objective.valid_until_utc
    value = scope.continuation_authorization
    saved = _read(db, issuer=issuer, namespace=namespace, kind=KIND, ref=value.original_ref)
    if saved is None: raise MissingProductionOriginalV1("actual_signed_continuation_generation")
    actual = require_continuation_authorization_history_v2(db, namespace=namespace,
        original_ref=value.original_ref, producing_operation_id=saved[1], raw=saved[0])
    from .artifact_phase_postconditions_v1 import read_current_artifact_standing_predecision_approval_v2
    from .budget import get_budget_lease, require_budget_family_admissible
    approval = read_current_artifact_standing_predecision_approval_v2(db, namespace=namespace,
        bundle=bundle, issuer=issuer, owner_guard=owner_guard, now_utc=now_utc)
    lease_ref = value.current_parent_budget_lease_ref if parent_budget_lease_ref is None else parent_budget_lease_ref
    require_budget_family_admissible(db, lease_ref)
    lease = get_budget_lease(db, lease_ref)
    while lease.lease_id != value.current_parent_budget_lease_ref:
        if lease.parent_id is None: raise ValueError("continuation child escaped approved parent budget")
        lease = get_budget_lease(db, lease.parent_id)
    grant = issuer.current_budget_grant(db, lease.lease_id)
    root = scope.root
    source=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (value.fresh_source_ref,*namespace.as_tuple)).fetchone()
    if source is None or source[2]!=1 or (source[0],canonical_digest(json.loads(source[1])))!=(value.fresh_source_revision,value.fresh_source_digest):
        raise MissingProductionOriginalV1("current_exact_continuation_authorization_Source_head")
    from ..host.authority_profile import AdminArtifactDraftToolScopeV1,AdminArtifactDraftToolScopeV2
    from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4,AdminArtifactDraftToolScopeV3,select_paired_tool_scope_v3
    tool=bundle.artifact_draft.tool_scope
    if type(bundle.artifact_draft) is AdminArtifactDraftPairedPolicyV4:tool=select_paired_tool_scope_v3(bundle.artifact_draft,root.filenames[0])
    if type(tool) in {AdminArtifactDraftToolScopeV2,AdminArtifactDraftToolScopeV3}:physical_cap=tool.maximum_artifact_version
    elif type(tool) is AdminArtifactDraftToolScopeV1:physical_cap=1
    else:raise TypeError("actual continuation installed tool scope required")
    from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
    method_writes=max(sum(phase in {"tone_sample","full"} for phase in artifact_draft_phase_sequence_v2(method)) for method in approval.scope.method_refs)
    if value.maximum_artifact_version>min(physical_cap,value.predecessor_artifact_version+method_writes):
        raise ValueError("continuation generation exceeds actually approved physical file capacity")
    if (actual != value or scope.objective_ref != value.original_objective_ref
            or canonical_digest(plain_v1(objective)) != value.original_objective_digest
            or (root.installation_id, root.manifest_digest) != (value.installation_id, value.manifest_digest)
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
                (owner_guard.grant_ref, owner_guard.grant_revision, owner_guard.grant_digest)
            or (approval.scope.policy_ref, approval.scope.policy_version, approval.scope_digest) !=
                (value.current_standing_policy_ref, value.current_standing_policy_version, value.current_standing_policy_digest)
            or (grant.version, canonical_digest(grant)) != (value.current_parent_budget_grant_version, value.current_parent_budget_grant_digest)
            or not value.valid_from_utc <= now_utc < value.valid_until_utc):
        raise MissingProductionOriginalV1("current_exact_continuation_generation_Owner_standing_budget")
    return value.valid_until_utc


def resolve_artifact_task_predicate_deadline_v2(db, *, namespace, root_registration_ref, goal_ref,
        original_predicate_deadline_utc, issuer, bundle, owner_guard, now_utc, parent_budget_lease_ref):
    """Execution window of a bound child; the historic Goal predicate stays immutable."""
    from .ingress_artifact_task_scope_v1 import (task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,
        IngressArtifactTaskScopeOriginalV3,ArtifactTaskObjectiveV1,_decode)
    row=_read(db,issuer=issuer,namespace=namespace,kind="artifact_task_scope",ref=task_scope_ref_v1(root_registration_ref))
    if row is None:return original_predicate_deadline_utc
    scope=_decode(row[0],IngressArtifactTaskScopeOriginalV1)
    if type(scope) is not IngressArtifactTaskScopeOriginalV3:return original_predicate_deadline_utc
    saved=_read(db,issuer=issuer,namespace=namespace,kind="artifact_task_objective",ref=scope.objective_ref)
    if saved is None:raise MissingProductionOriginalV1("actual_continuation_child_objective")
    objective=_decode(saved[0],ArtifactTaskObjectiveV1)
    if objective.goal_ref!=goal_ref:raise ValueError("continuation child borrowed another historic Goal predicate")
    return resolve_artifact_task_authorization_deadline_v2(db,namespace=namespace,scope=scope,objective=objective,
        issuer=issuer,bundle=bundle,owner_guard=owner_guard,now_utc=now_utc,parent_budget_lease_ref=parent_budget_lease_ref)
