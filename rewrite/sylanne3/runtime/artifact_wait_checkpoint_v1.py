"""Finite current waiting checkpoint and immutable artifact capacity attribution.

Admission uses the existing private foreground W01 path.
Historical metadata checks in this module never reauthorize old Source bytes,
an old Root deadline, a model attempt or a native file effect.
"""
from dataclasses import dataclass, replace
import json

from ..graph_types import AtomKey, GraphVersion, GraphWrite, owner_grant_key
from ..runtime_contracts import NamespaceId, QueryEpoch, VersionedRef, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d10 import LifeDomain
from ..domains.d10.project_checkpoint_v1 import (
    CHECKPOINT_TYPE, ProjectCheckpointV1, ProjectWaitConditionV1,
    project_checkpoint_key_v1,
)
from .artifact_continuation_originals_v1 import (
    ExistingArtifactContinuationRequestV1, _request_basis,
    read_completed_draft_predecessor_v1, read_current_artifact_renewal_root_v1,
    require_unique_existing_artifact_project_v1,
    read_selected_artifact_continuation_request_v1,
)
from .artifact_continuation_v1 import (
    ExistingArtifactRevisionBasisV1, continuation_replace_target_v1,
)
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
from .d11_life_preparation_v1 import _read, read_prepared_life_v1
from .d11_life_terminal_v1 import read_adopted_life_original_v1
from .d11_life_contract_v1 import D11LifeTerminalV1, D11DraftTerminalV1, life_from_wire_v1
from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1

WAIT_OPERATION = "await_existing_artifact_revision_v1"
WAIT_SCHEMA = "d10.existing-artifact-wait-original.v1"


@dataclass(frozen=True, slots=True)
class ExistingArtifactWaitOriginalV1:
    request: ExistingArtifactContinuationRequestV1
    basis: ExistingArtifactRevisionBasisV1
    root: DraftRootCapabilityV1
    checkpoint: ProjectCheckpointV1
    source_versions: tuple[VersionedRef, ...]
    # Observed validity is metadata, never a positive dependency or permission.
    control_eligibility: tuple[tuple[str, int, bool], ...]
    schema: str = WAIT_SCHEMA


def artifact_wait_operation_id_v1(selector):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
    if type(selector) is not ArtifactDraftTaskSelectorV1:
        raise TypeError("exact current artifact selector required")
    return "artifact-continuation-await:" + canonical_digest(
        ("d10.existing-artifact-wait.v1", selector))[:48]


def validate_artifact_wait_original_v1(value):
    """Closed structural contract; this function alone supplies no authority."""
    if type(value) is not ExistingArtifactWaitOriginalV1 or value.schema != WAIT_SCHEMA:
        raise ValueError("closed actual artifact wait original required")
    request, basis, root, checkpoint = value.request, value.basis, value.root, value.checkpoint
    if (request.selector.namespace != NamespaceId.from_key(AtomKey.from_token(basis.project_ref))
            or (request.project_ref, request.goal_ref, request.plan_ref, request.recipe_ref,
                request.predecessor_result_ref, request.correction_head_ref) !=
               (basis.project_ref, basis.goal_ref, basis.plan_ref, basis.recipe_ref,
                basis.predecessor_result_ref, basis.correction_head_ref)
            or root.registration_ref != request.selector.root_registration_ref):
        raise ValueError("wait bridge crossed the selected existing work")
    continuation_replace_target_v1(basis, root)
    versions = {v.key.token: v.revision for v in basis.current_versions}
    historical = {v.key.token: v.revision for v in basis.last_valid_versions}
    refs = (basis.goal_ref, basis.plan_ref, basis.project_ref, basis.recipe_ref, basis.checkpoint_ref)
    if (len(versions) != 5 or set(versions) != set(refs) or set(historical) != set(refs)
            or any(not 1 <= historical[ref] <= versions[ref] for ref in refs)
            or len(basis.producer_digests) != 5
            or value.control_eligibility != tuple(
                (ref, versions[ref], valid) for ref, _, valid in value.control_eligibility)
            or tuple(row[0] for row in value.control_eligibility) != refs
            or any(type(row[2]) is not bool for row in value.control_eligibility)):
        raise ValueError("wait bridge lost separate current heads and last valid producers")
    old = basis.checkpoint
    node_ids = {node.node_id for node in basis.plan.nodes}
    effects = dict(basis.verified_effects_by_node)
    if (basis.goal.state != "active" or basis.plan.state not in {"active", "waiting"}
            or old.state in {"cancelled", "paused"}
            or basis.plan.goal_ref != basis.goal_ref
            or basis.plan.goal_revision != basis.goal.revision
            or old.plan_ref != basis.plan_ref or old.plan_revision != basis.plan.revision
            or old.project_ref != basis.project_ref
            or len(effects) != len(basis.verified_effects_by_node) or set(effects) != node_ids
            or set(old.completed_node_refs) != node_ids
            or any(not row for row in effects.values())
            or any(node.pending_original_effects for node in basis.plan.nodes)
            or basis.predecessor_effect_id not in {e for row in effects.values() for e in row}):
        raise ValueError("wait bridge needs actual settled old work and an unfinished goal")
    wake = checkpoint.wait_condition
    if (checkpoint != replace(old, revision=versions[basis.checkpoint_ref] + 1,
            next_step=None, state="waiting", wait_condition=wake)
            or type(wake) is not ProjectWaitConditionV1
            or (wake.producer_domain, wake.event_kind, wake.resume_job_ref) !=
               ("d06", "artifact_draft_content_adopted", request.selector.cycle_job_ref)
            or wake.observed_versions != value.source_versions
            or wake.query_epoch.namespace != request.selector.namespace
            or root.source_ref not in {v.ref for v in value.source_versions}
            or not value.source_versions or wake.next_due_utc is not None):
        raise ValueError("wait bridge changed old work or invented an executable next step")
    return value


def stage_await_existing_artifact_revision_v1(db, *, frame, request, installed_readers):
    """One CP CAS, no old control rewrite, no model/native side effect."""
    basis = _request_basis(db, frame=frame, request=request, installed_readers=installed_readers)
    previous, _, _, _ = read_completed_draft_predecessor_v1(
        db, frame=frame, result_ref=request.predecessor_result_ref,
        issuer=installed_readers.issuer)
    read, cycle, _, root, family, mapping_atom, _ = read_current_artifact_renewal_root_v1(
        db, frame=frame, selector=request.selector, installed_readers=installed_readers,
        predecessor=previous)
    require_unique_existing_artifact_project_v1(db, frame=frame, basis=basis, root=root)
    if frame.envelope.identity.operation_id != artifact_wait_operation_id_v1(request.selector):
        raise ValueError("wait bridge changed its fixed once identity")
    # A selected stale checkpoint is the sole bounded bridge target.
    for other in read.complete_inventory(db, CHECKPOINT_TYPE):
        if other.key.token != basis.checkpoint_ref and not other.valid:
            raise MissingProductionOriginalV1("actual_current_other_project_capacity_checkpoint")
    # source_family already qualified the fresh cue and every parent/access/
    # correction head under the independently issued current Self/Owner scope.
    facts = tuple(VersionedRef(ref, read.head(db, ref, required=True).revision)
                  for ref in sorted(family))
    cycle_atom = read.head(db, request.selector.cycle_job_ref, required=True)
    from .d11_types import job_graph_write
    if job_graph_write(cycle).value != cycle_atom.value:
        raise ValueError("wait registration lost its actual SQL/Graph cycle")
    wake = ProjectWaitConditionV1("d06", "artifact_draft_content_adopted", facts,
        QueryEpoch(request.selector.namespace, "namespace", frame.snapshot.epochs[0].revision),
        request.selector.cycle_job_ref, cycle_atom.revision)
    key = project_checkpoint_key_v1(request.selector.namespace, request.project_ref)
    checkpoint = replace(basis.checkpoint, revision=read.head(db, key).revision + 1,
                         state="waiting", next_step=None, wait_condition=wake)
    eligibility = tuple((v.key.token, v.revision, read.head(db, v.key).valid)
                        for v in basis.current_versions)
    value = validate_artifact_wait_original_v1(ExistingArtifactWaitOriginalV1(
        request, basis, root, checkpoint, facts, eligibility))
    # Old Goal/Plan/Project/recipe and corrected Source are historical reads.
    # Only the fresh Source family plus current Self/Owner invalidate this CP.
    from ..memory_types import access_key
    from ..domains.d06 import source_correction_head_key
    dependencies = [mapping_atom.key, owner_grant_key(*request.selector.namespace.as_tuple)]
    for ref in sorted(family):
        source = AtomKey.from_token(ref)
        dependencies.extend((source, access_key(*request.selector.namespace.as_tuple, source.owner.subject),
                             source_correction_head_key(request.selector.namespace, source.owner.subject)))
    dependencies = tuple(key for key in dict.fromkeys(dependencies)
                         if read.head(db, key).revision > 0)
    return stage_result_v1(frame, "d10", WAIT_OPERATION, request,
        writes=(GraphWrite(key, plain_v1(checkpoint), dependencies),),
        provenance={"schema": WAIT_SCHEMA, "wait": value},
        receiver_events=(("d11", "project_checkpoint_wait_registered"),),
        proposal_schema="d10.proposal.v1", proposal_hash=LifeDomain().descriptor.request_schema_hash)


def _require_history_member(db, *, namespace, original, key, revision, value):
    """Actual receipt, write bytes and Graph history, not a provenance DTO."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    version = GraphVersion(key, revision)
    writes = tuple(decode_typed_production_value_v1(row, GraphWrite)
                   for row in original["payload"]["writes"])
    found = tuple(write for write in writes if write.key == key)
    row = db.execute("SELECT event_id,value,valid FROM graph_history "
        "WHERE token=? AND revision=?", (key.token, revision)).fetchone()
    if (NamespaceId.from_key(key) != namespace or len(found) != 1 or found[0].value != value
            or version not in original["receipt"].write_versions
            or row is None or row[0] != original["receipt"].operation_id
            or json.loads(row[1]) != value or row[2] != 1):
        raise MissingProductionOriginalV1("actual_exact_artifact_checkpoint_write_member")
    return found[0]


def require_artifact_wait_checkpoint_member_v1(db, *, namespace, original, key, revision, value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if original is None or (original["domain"], original["operation_kind"]) != ("d10", WAIT_OPERATION):
        raise MissingProductionOriginalV1("actual_d10_artifact_wait_original")
    p = original["payload"]["provenance"]
    if set(p) != {"schema", "wait"} or p["schema"] != WAIT_SCHEMA:
        raise ValueError("wait producer has another exact provenance variant")
    waiting = validate_artifact_wait_original_v1(
        decode_typed_production_value_v1(p["wait"], ExistingArtifactWaitOriginalV1))
    if (waiting.request.selector.namespace != namespace
            or original["receipt"].operation_id != artifact_wait_operation_id_v1(waiting.request.selector)
            or original["payload"]["request"] != plain_v1(waiting.request)
            or value != plain_v1(waiting.checkpoint)
            or key != project_checkpoint_key_v1(namespace, waiting.request.project_ref)
            or len(original["payload"]["writes"]) != 1):
        raise ValueError("wait checkpoint does not belong to this actual once producer")
    _require_history_member(db, namespace=namespace, original=original, key=key,
                            revision=revision, value=value)
    # The consumed cursor is the real adopted cycle Graph version at this CAS.
    wake = waiting.checkpoint.wait_condition
    cycle_key = AtomKey.from_token(wake.resume_job_ref)
    if GraphVersion(cycle_key, wake.consume_cursor) not in original["read_versions"]:
        raise ValueError("wait cursor was not read by its actual original transaction")
    cycle_history = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
                              (cycle_key.token, wake.consume_cursor)).fetchone()
    if cycle_history is None or cycle_history[1] != 1:
        raise MissingProductionOriginalV1("actual_wait_cycle_history")
    cycle_value = json.loads(cycle_history[0])
    if (cycle_value["continuation"]["c02_operation_id"] != waiting.request.selector.c02_operation_id
            or cycle_value["continuation"]["source_ref"] != waiting.root.source_ref):
        raise ValueError("wait producer was attached to another actual task")
    return waiting


def require_current_artifact_wait_before_selection_v1(db, *, frame, request):
    read = CurrentDomainReadV1(frame)
    key = project_checkpoint_key_v1(request.selector.namespace, request.project_ref)
    atom = read.head(db, key, required=True)
    original = read_adopted_domain_operation_v1(
        db, request.selector.namespace, artifact_wait_operation_id_v1(request.selector))
    waiting = require_artifact_wait_checkpoint_member_v1(db,
        namespace=request.selector.namespace, original=original, key=key,
        revision=atom.revision, value=atom.value)
    if waiting.request != request:
        raise ValueError("selection differs from its exact committed waiting bridge")
    return waiting


def require_artifact_revision_checkpoint_member_v1(db, *, namespace, original, key, revision, value):
    """One known D08 primary original contains its actual joint D10 member."""
    from .domain_production_erasure_v1 import (
        decode_typed_production_value_v1, validate_domain_stage_provenance_v1,
    )
    from .artifact_continuation_originals_v1 import artifact_continuation_operation_id_v1
    from .artifact_continuation_v1 import ArtifactRevisionCandidateV1
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1
    if original is None or (original["domain"], original["operation_kind"]) != (
            "d08", "revise_existing_artifact_v1"):
        raise MissingProductionOriginalV1("actual_joint_artifact_revision_original")
    p = original["payload"]["provenance"]
    validate_domain_stage_provenance_v1("d08", "revise_existing_artifact_v1", p)
    candidate = decode_typed_production_value_v1(p["candidate"], ArtifactRevisionCandidateV1)
    adoption = decode_typed_production_value_v1(p["content_adoption"], ArtifactDraftContentAdoptionV1)
    selected = read_selected_artifact_continuation_request_v1(
        db, namespace=namespace, selector=adoption.selector)
    if (selected is None or original["receipt"].operation_id !=
            artifact_continuation_operation_id_v1(adoption.selector, revision=True)
            or original["payload"]["request"] != plain_v1(selected[0])
            or p["selection_original_digest"] != selected[1]["original_digest"]
            or p["basis"] != selected[1]["payload"]["provenance"]["basis"]
            or key != project_checkpoint_key_v1(namespace, selected[0].project_ref)
            or value != plain_v1(candidate.checkpoint)
            or original["payload"]["writes"] != plain_v1((*candidate.d08_writes, *candidate.d10_writes))):
        raise ValueError("joint checkpoint lost its actual selection and exact D08/D10 membership")
    members = tuple(write for write in candidate.d10_writes if write.key == key)
    if len(members) != 1 or members[0].value != value:
        raise ValueError("checkpoint is not the exact joint D10 member")
    _require_history_member(db, namespace=namespace, original=original, key=key,
                            revision=revision, value=value)
    # All companion writes must have committed in the SAME original receipt.
    for write in (*candidate.d08_writes, *candidate.d10_writes):
        member = tuple(v for v in original["receipt"].write_versions if v.key == write.key)
        if len(member) != 1:
            raise ValueError("joint revision lost a companion CAS member")
        _require_history_member(db, namespace=namespace, original=original, key=write.key,
                                revision=member[0].revision, value=write.value)
    return candidate


def require_finite_artifact_checkpoint_member_v1(db, *, namespace, original, atom):
    pair = None if original is None else (original["domain"], original["operation_kind"])
    if pair == ("d10", WAIT_OPERATION):
        return require_artifact_wait_checkpoint_member_v1(db, namespace=namespace,
            original=original, key=atom.key, revision=atom.revision, value=atom.value)
    if pair == ("d08", "revise_existing_artifact_v1"):
        return require_artifact_revision_checkpoint_member_v1(db, namespace=namespace,
            original=original, key=atom.key, revision=atom.revision, value=atom.value)
    raise MissingProductionOriginalV1("actual_immutable_project_capacity_checkpoint_member")


def historical_selected_artifact_project_v1(db, *, namespace, selector, target, issuer):
    """Immutable attribution only: do not require an old Root to be unexpired."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    selected = read_selected_artifact_continuation_request_v1(db, namespace=namespace, selector=selector)
    if target.mode != "replace" or selected is None:
        raise MissingProductionOriginalV1("actual_selection_for_signed_replace_job")
    request, original = selected
    p = original["payload"]["provenance"]
    if (set(p) != {"schema", "selector", "basis", "replacement_target"}
            or p["schema"] != "d08.existing-artifact-continuation-original.v1"
            or p["selector"] != plain_v1(selector) or p["replacement_target"] != plain_v1(target)):
        raise ValueError("historical replacement job changed the actual selected target")
    basis = decode_typed_production_value_v1(p["basis"], ExistingArtifactRevisionBasisV1)
    root_original = _read(db, issuer=issuer, namespace=namespace,
                         kind="draft_root_capability", ref=selector.root_registration_ref)
    if root_original is None:
        raise MissingProductionOriginalV1("actual_signed_root_for_job_attribution")
    root = draft_from_wire_v1(root_original[0], DraftRootCapabilityV1)
    if (continuation_replace_target_v1(basis, root) != target
            or (request.project_ref, request.goal_ref, request.plan_ref, request.recipe_ref,
                request.predecessor_result_ref, request.correction_head_ref) !=
               (basis.project_ref, basis.goal_ref, basis.plan_ref, basis.recipe_ref,
                basis.predecessor_result_ref, basis.correction_head_ref)):
        raise ValueError("historical replacement job lost its stable project/file lineage")
    adopted = read_adopted_life_original_v1(db, namespace=namespace,
        result_ref=basis.predecessor_result_ref, issuer=issuer)
    if adopted is None:
        raise MissingProductionOriginalV1("signed_predecessor_for_replacement_job")
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    if type(terminal) is not D11DraftTerminalV1 or terminal.status != "completed":
        raise MissingProductionOriginalV1("actual_completed_predecessor_for_replacement_job")
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if prepared is None:
        raise MissingProductionOriginalV1("signed_prepared_predecessor_for_replacement_job")
    witness = require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
    if (basis.predecessor_prepared_digest != prepared.digest
            or basis.predecessor_adopted_digest != canonical_digest(adopted)
            or basis.predecessor_target != prepared.plan.target
            or basis.predecessor_effect_id != terminal.binding.effect_id
            or prepared.plan.project.ref != request.project_ref
            or (basis.prior_version, basis.prior_content_digest, basis.prior_file_identity, basis.prior_effect_marker) !=
               (witness.version, witness.content_digest, witness.file_identity, witness.effect_marker)):
        raise ValueError("historical replacement job differs from signed actual predecessor")
    return request.project_ref


def artifact_model_project_for_capacity_v1(db, *, prepared, issuer):
    from .d11_artifact_draft_model_v1 import read_artifact_draft_frozen_v1
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    frozen = read_artifact_draft_frozen_v1(db, prepared=prepared, issuer=issuer)
    if frozen.target.mode == "create":
        return artifact_goal_plan_keys_v1(prepared.namespace,
            c02_operation_id=prepared.selector.c02_operation_id,
            root_registration_ref=prepared.selector.root_registration_ref)[2].token
    return historical_selected_artifact_project_v1(db, namespace=prepared.namespace,
        selector=prepared.selector, target=frozen.target, issuer=issuer)


def prospective_artifact_project_for_capacity_v1(db, *, frame, selector, issuer):
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    from .d11_artifact_draft_contract_v1 import DraftFileTargetV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    selected = read_selected_artifact_continuation_request_v1(db, namespace=selector.namespace, selector=selector)
    if selected is None:
        return artifact_goal_plan_keys_v1(selector.namespace, c02_operation_id=selector.c02_operation_id,
            root_registration_ref=selector.root_registration_ref)[2].token
    request, original = selected
    target = decode_typed_production_value_v1(
        original["payload"]["provenance"]["replacement_target"], DraftFileTargetV1)
    project_ref = historical_selected_artifact_project_v1(db, namespace=selector.namespace,
        selector=selector, target=target, issuer=issuer)
    # Current new admission additionally requires the same actual waiting CP.
    require_current_artifact_wait_before_selection_v1(db, frame=frame, request=request)
    return project_ref
