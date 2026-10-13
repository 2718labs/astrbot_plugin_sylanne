"""Permanent closed original replay contract for existing artifact revisions."""
from typing import get_type_hints

import pytest

from sylanne3.runtime.artifact_continuation_v1 import ExistingArtifactRevisionBasisV1
from sylanne3.runtime.d11_artifact_draft_contract_v1 import RECIPE_ID
from sylanne3.runtime.domain_production_erasure_v1 import (
    DomainProductionErasureHold, decode_typed_production_value_v1,
)


def test_existing_artifact_recipe_replay_preserves_actual_graph_json():
    recipe = {"recipe_id": RECIPE_ID, "version": 1, "reality": "real_execution",
              "allowed_steps": [RECIPE_ID], "preemptible": True}
    recipe_type = get_type_hints(ExistingArtifactRevisionBasisV1)["recipe_value"]
    restored = decode_typed_production_value_v1(recipe, recipe_type)
    # The current composer compares with the registered declaration, and a
    # missing current recipe may be rewritten from this actual original value.
    assert restored == recipe
    assert type(restored["allowed_steps"]) is list


def test_existing_artifact_recipe_replay_rejects_unregistered_nested_values():
    recipe_type = get_type_hints(ExistingArtifactRevisionBasisV1)["recipe_value"]
    with pytest.raises(DomainProductionErasureHold, match="union field"):
        decode_typed_production_value_v1({"allowed_steps": {"injected": RECIPE_ID}}, recipe_type)


def _typed_installed_scope_case(tmp_path, *, replacement):
    from sylanne3.host.authority_profile import (
        AdminArtifactDraftBodyPolicyV1, AdminArtifactDraftPolicyV1,
        AdminArtifactDraftToolScopeV1, AdminArtifactDraftToolScopeV2,
        AdminModelWorkflowV2, installed_model_config_ref,
    )
    from sylanne3.memory_types import source_key
    from sylanne3.runtime.d11_artifact_draft_contract_v1 import (
        DraftFileIdentityV1, DraftFileTargetV1, DraftRootCapabilityV1,
    )
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.runtime_contracts import canonical_digest
    config_digest = "a" * 64
    model = AdminModelWorkflowV2("artifact_draft_v1", "fixture-provider", "fixture-model",
        installed_model_config_ref("fixture-provider", "fixture-model", config_digest),
        config_digest, "consolidation", ("self",), "private",
        "sylanne.artifact_draft_template.v1", ("text",), 2, 64,
        {"input_tokens": 128, "output_tokens": 64, "model_tokens": 192, "model_microusd": 100})
    common = dict(resource_id="export", filename="draft.txt", max_file_bytes=65536,
                  generated_text_bytes=4096, readback_chunk_bytes=65536, execution_timeout_seconds=300)
    scope = (AdminArtifactDraftToolScopeV2(**common, maximum_artifact_version=2,
        operations=("create", "replace_verified_predecessor")) if replacement else
        AdminArtifactDraftToolScopeV1(**common, mode="create"))
    policy = AdminArtifactDraftPolicyV1(model, scope,
        AdminArtifactDraftBodyPolicyV1("fixture-body", 1, "fixture-component", 1, 100, "export"), None)
    stat = tmp_path.stat()
    identity = DraftFileIdentityV1(stat.st_dev, stat.st_ino)
    root = DraftRootCapabilityV1("fixture-install", "b" * 64, "export", "fixture-root",
        identity, ("draft.txt",), 65536, "2100-01-01T00:00:00Z",
        source_key("bot", "persona", "task").token, "fixture-owner-grant", 1, "c" * 64)
    target = DraftFileTargetV1(root.resource_id, root.registration_ref, canonical_digest(plain_v1(root)),
        root.root_identity, "draft.txt", "replace", 1, "d" * 64, identity, "e" * 64, 65536)
    # These are typed policy inputs only. Authenticating a predecessor and
    # issuing a current Root/installation grant belongs to the actual service.
    return policy, root, target


def test_legacy_create_scope_rejects_replacement_without_new_policy(tmp_path):
    from sylanne3.host.authority_profile import require_installed_artifact_target_v2
    policy, root, target = _typed_installed_scope_case(tmp_path, replacement=False)
    with pytest.raises(ValueError, match="create-only"):
        require_installed_artifact_target_v2(policy, root, target)


def test_explicit_replace_policy_roundtrips_and_retains_version_boundary(tmp_path):
    from dataclasses import replace
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.host.authority_profile import (
        artifact_draft_policy_from_payload_v1, require_installed_artifact_target_v2,
    )
    policy, root, target = _typed_installed_scope_case(tmp_path, replacement=True)
    restored = artifact_draft_policy_from_payload_v1(plain_v1(policy))
    assert restored == policy
    assert require_installed_artifact_target_v2(restored, root, target) == target
    with pytest.raises(ValueError, match="version boundary"):
        require_installed_artifact_target_v2(restored, root, replace(target, expected_prior_version=2))


@pytest.mark.parametrize("changed", ["filename", "root_registration", "byte_limit"])
def test_explicit_replace_policy_cannot_borrow_another_root_target(tmp_path, changed):
    from dataclasses import replace
    from sylanne3.host.authority_profile import require_installed_artifact_target_v2
    policy, root, target = _typed_installed_scope_case(tmp_path, replacement=True)
    assert require_installed_artifact_target_v2(policy, root, target) == target
    target = {"filename": replace(target, filename="other.txt"),
              "root_registration": replace(target, root_registration_ref="foreign-root"),
              "byte_limit": replace(target, max_bytes=65537)}[changed]
    with pytest.raises(ValueError, match="intersection"):
        require_installed_artifact_target_v2(policy, root, target)


def _unissued_continuation_case(tmp_path):
    """Typed prospective inputs only; this helper never commits a W01 producer."""
    from dataclasses import replace
    from sylanne3.runtime_contracts import NamespaceId,canonical_digest
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.memory_types import source_key
    from sylanne3.domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    from sylanne3.runtime.d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    from sylanne3.runtime.ingress_artifact_task_scope_v1 import (
        ArtifactTaskObjectiveV1,IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3,
        task_objective_ref_v1)
    from sylanne3.runtime.artifact_task_continuation_authorization_v2 import (
        ArtifactTaskContinuationAuthorizationV2,continuation_authorization_id_v2)
    _,old_root,_=_typed_installed_scope_case(tmp_path,replacement=True)
    ns=NamespaceId("bot","persona")
    keys=artifact_goal_plan_keys_v1(ns,c02_operation_id="initial-c02",root_registration_ref=old_root.registration_ref)
    objective=ArtifactTaskObjectiveV1(ns,old_root.installation_id,old_root.manifest_digest,"initial-c02",
        old_root.source_ref,1,"a"*64,"standing",1,"b"*64,"private-owner","private-platform",
        old_root.resource_id,old_root.root_identity,"draft.txt",old_root.registration_ref,
        *(key.token for key in keys),1.0,2.0)
    root=replace(old_root,registration_ref="new-typed-root",source_ref=source_key(*ns.as_tuple,"fresh-task").token)
    objective_ref=task_objective_ref_v1(objective);objective_digest=canonical_digest(plain_v1(objective))
    auth=ArtifactTaskContinuationAuthorizationV2(namespace=ns,installation_id=root.installation_id,
        manifest_digest=root.manifest_digest,authorization_id=continuation_authorization_id_v2(ns,"fresh-c02",root.registration_ref),
        generation=1,original_objective_ref=objective_ref,original_objective_digest=objective_digest,
        goal_ref=objective.goal_ref,project_ref=objective.project_ref,plan_ref=objective.plan_ref,
        waiting_checkpoint_ref=project_checkpoint_key_v1(ns,objective.project_ref).token,
        waiting_checkpoint_revision=1,waiting_checkpoint_digest="c"*64,predecessor_result_ref="unissued-result",
        predecessor_result_digest="d"*64,predecessor_effect_id="old-effect",predecessor_effect_marker="e"*64,
        fresh_c02_operation_id="fresh-c02",fresh_source_ref=root.source_ref,fresh_source_revision=1,
        fresh_source_digest="f"*64,fresh_root_registration_ref=root.registration_ref,
        fresh_root_registration_digest=canonical_digest(plain_v1(root)),current_standing_policy_ref="standing",
        current_standing_policy_version=1,current_standing_policy_digest="b"*64,current_parent_budget_lease_ref="parent",
        current_parent_budget_grant_version=1,current_parent_budget_grant_digest="a"*64,
        predecessor_artifact_version=1,maximum_artifact_version=2,maximum_new_versions=1,
        valid_from_utc=10.0,valid_until_utc=300.0,previous_authorization_ref=None,previous_authorization_digest=None)
    approved=IngressArtifactTaskScopeOriginalV2(ns,"fresh-c02",root.source_ref,1,"f"*64,"unissued-c1","a"*64,
        "b"*64,root,"continue",objective_ref,objective_digest,10.0,
        approval_original_ref="unissued-owner-approval",approval_original_digest="c"*64)
    scope=IngressArtifactTaskScopeOriginalV3(**{n:getattr(approved,n) for n in approved.__dataclass_fields__ if n!="schema"},
        continuation_authorization=auth)
    return objective,approved,scope


def test_typed_continuation_cannot_renew_without_actual_signed_original(tmp_path):
    import sqlite3
    from sylanne3.runtime.artifact_task_continuation_authorization_v2 import resolve_artifact_task_authorization_deadline_v2
    from sylanne3.runtime.d11_life_preparation_v1 import install_d11_life_schema_v1
    from sylanne3.runtime.d01_production_operations_v1 import MissingProductionOriginalV1
    from sylanne3.runtime.issuers import D02ResourceIssuer,D11BudgetJobIssuer
    objective,approved,scope=_unissued_continuation_case(tmp_path)
    issuer=D11BudgetJobIssuer(D02ResourceIssuer(b"d"*32),b"l"*32)
    with sqlite3.connect(":memory:") as db:
        install_d11_life_schema_v1(db)
        # A prospective approved scope does not extend the historic objective.
        assert resolve_artifact_task_authorization_deadline_v2(db,namespace=scope.namespace,scope=approved,
            objective=objective,issuer=issuer,bundle=None,owner_guard=None,now_utc=100.0)==2.0
        # A typed V3 whose timestamp is in the future still has no execution rights.
        with pytest.raises(MissingProductionOriginalV1,match="actual_signed_continuation_generation"):
            resolve_artifact_task_authorization_deadline_v2(db,namespace=scope.namespace,scope=scope,
                objective=objective,issuer=issuer,bundle=None,owner_guard=None,now_utc=100.0)


@pytest.mark.parametrize("kind",["artifact_task_continuation_authorization_v2","artifact_task_amendment"])
def test_product_original_reader_rejects_unsigned_task_original_row(tmp_path,kind):
    import sqlite3
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.runtime_contracts import canonical_digest,canonical_serialize
    from sylanne3.runtime.d11_life_preparation_v1 import install_d11_life_schema_v1,TABLE
    from sylanne3.runtime.d11_life_product_adapter_v1 import read_current_life_original_ref_v1
    from sylanne3.runtime.issuers import D02ResourceIssuer,D11BudgetJobIssuer,IssuerAuthorityDenied
    objective,_,scope=_unissued_continuation_case(tmp_path)
    from sylanne3.runtime.artifact_task_amendment_v1 import amendment_from_scope_v1,amendment_original_ref_v1
    original=(scope.continuation_authorization if kind=="artifact_task_continuation_authorization_v2" else amendment_from_scope_v1(scope,objective))
    original_ref=(original.original_ref if kind=="artifact_task_continuation_authorization_v2" else amendment_original_ref_v1(original))
    issuer=D11BudgetJobIssuer(D02ResourceIssuer(b"d"*32),b"l"*32)
    with sqlite3.connect(":memory:") as db:
        install_d11_life_schema_v1(db)
        raw=plain_v1(original)
        db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?,?)",(*scope.namespace.as_tuple,kind,
            original_ref,"unissued-producer",canonical_serialize(raw),canonical_digest(raw),"0"*64))
        with pytest.raises(IssuerAuthorityDenied,match="signature is invalid"):
            read_current_life_original_ref_v1(db,namespace=scope.namespace,original_ref=original_ref,issuer=issuer)
