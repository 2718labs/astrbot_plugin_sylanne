"""Actual W01 candidate preparation and selected adapter reads; no reserve/job/provider."""
from contextlib import contextmanager
from dataclasses import dataclass, fields, replace
from typing import TYPE_CHECKING
import json

if TYPE_CHECKING:
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1, MethodStrategyProjectionV1
from ..domains.d08.personal_candidate_v1 import (
    PREPARE_OPERATION_V1, ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3, SourceNoteCandidateBindingV1,
    PrepareCurrentPersonalCandidatesRequestV1, SelectCurrentPersonalStepRequestV2,
    CurrentPersonalNeedQualificationV1, CurrentPersonalCandidateEligibilityV1,
    CurrentPersonalCandidatePriceV1, PersonalCandidateFutureIdentityV1,
    PreparedPersonalCandidateV1, PreparedPersonalCandidateSetV1, ConsumePersonalDecisionRequestV1)
from ..domains.d08.personal_plan_v1 import PLAN_TYPE, DECISION_TYPE, decode_personal_plan_type_v1
from ..domains.d08.execution import _decode_goal
from ..graph_types import AtomKey, GraphVersion, Owner, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import (CurrentDomainReadV1, MissingProductionOriginalV1,
    production_read_plan_v1, raw_head_value_v1, method_condition_read_inputs_v1)
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .issuers import D11BudgetJobIssuer, D02ResourceIssuer, ResourceQuote
from .budget import get_budget_lease, require_budget_family_admissible

_INSTALLED = object()


_PHASE_TRANSITION_KEY = object()
_ACTIVE_PHASE_TRANSITIONS = {}


@dataclass(frozen=True, slots=True, init=False)
class PhasePreparationTransitionV1:
    graph: object
    frame: object
    readers: object
    request: ConsumePersonalDecisionRequestV1
    phase_selector: object
    candidate_original_digest: str
    prepared_candidates: PreparedPersonalCandidateSetV1
    selected_binding_digest: str
    decision_digest: str
    group_identity_digest: str
    frozen_digest: str
    prepare_operation_id: str
    reservation_digest: str
    reservation_ceiling: tuple[tuple[str, int], ...]
    before_cycle: object
    after_cycle: object
    projections: tuple
    producer_originals: tuple

    def __init__(self, token, **values):
        if token is not _PHASE_TRANSITION_KEY:
            raise TypeError("phase transition is built only from actual installed W01 originals")
        for name, value in values.items():
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True, init=False)
class CompletedPhaseActionTransitionV1(PhasePreparationTransitionV1):
    content_adoption_ref: str
    content_adoption_digest: str
    paid_original_digest: str



@dataclass(frozen=True,slots=True,init=False)
class SelectedArtifactPhaseTransitionV2:
    graph:object
    frame:object
    readers:object
    request:ConsumePersonalDecisionRequestV1
    phase_selector:object
    candidate_original_digest:str
    prepared_candidates:PreparedPersonalCandidateSetV1
    selected_binding_digest:str
    decision_digest:str
    after_cycle:object
    snapshot_digest:str
    projections:tuple
    producer_originals:tuple

    def __init__(self,token,**values):
        if token is not _PHASE_TRANSITION_KEY:
            raise TypeError("selected transition is reconstructed only from actual installed W01 originals")
        for name in self.__dataclass_fields__:object.__setattr__(self,name,values[name])

def _phase_transition_digest_v1(value):
    return canonical_digest((type(value).__name__, tuple((field.name, getattr(value, field.name))
        for field in fields(value) if field.name not in {"graph", "frame", "readers"})))


def _require_phase_transition_v1(db, *, frame, readers, transition):
    active = _ACTIVE_PHASE_TRANSITIONS.get(id(transition))
    if (type(transition) not in {PhasePreparationTransitionV1,CompletedPhaseActionTransitionV1,SelectedArtifactPhaseTransitionV2} or active is None or active[0] is not transition
            or active[1] != _phase_transition_digest_v1(transition) or transition.frame is not frame
            or transition.readers is not readers or transition.graph is not readers.current().graph
            or db is not transition.graph._GraphCoordinator__store._db or not db.in_transaction
            or not transition.graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError("phase projection lacks its exact active installed W01 reconstruction")
    if type(transition) is SelectedArtifactPhaseTransitionV2 and transition.snapshot_digest!=canonical_digest(plain_v1(frame.snapshot)):
        raise ValueError("selected transition changed its actual frozen snapshot")
    return transition


class _PhasePersonalCandidateReadV1(CurrentDomainReadV1):
    def __init__(self, frame, *, db, readers, transition):
        _require_phase_transition_v1(db, frame=frame, readers=readers, transition=transition)
        super().__init__(frame)
        self._phase_db, self._phase_readers, self._phase_transition = db, readers, transition
        self._checking_current = False

    def check(self, db):
        self._checking_current = True
        try:
            return super().check(db)
        finally:
            self._checking_current = False

    def head(self, db, key, *, required=False):
        actual = super().head(db, key, required=required)
        if self._checking_current:
            return actual
        t = _require_phase_transition_v1(db, frame=self.frame, readers=self._phase_readers,
            transition=self._phase_transition)
        for before, after, digest in t.projections:
            if actual.key == after.key:
                if actual.revision != after.revision or canonical_digest(actual.value) != digest:
                    raise MissingProductionOriginalV1("exact_current_phase_transition_after_head")
                if required and (not before.valid or before.revision < 1):
                    raise MissingProductionOriginalV1("actual_prior_phase_candidate_required_head")
                return before
        return actual

    def complete_inventory(self, db, type_name):
        # The base reader authenticates the actual complete current page first.
        atoms = super().complete_inventory(db, type_name)
        return tuple(atom for atom in atoms if atom.revision > 0)


def _phase_projection_evidence_v1(db, *, frame, readers, transition, current, prior):
    t = _require_phase_transition_v1(db, frame=frame, readers=readers, transition=transition)
    actual_read = CurrentDomainReadV1(frame)
    mapping = {after.key: before for before, after, _ in t.projections}
    prior_keys = {version.key for version in prior.read_versions}
    versions = []
    for version in current.read_versions:
        actual = actual_read.head(db, version.key)
        before = mapping.get(version.key)
        if before is None:
            if actual.revision != version.revision:
                raise MissingProductionOriginalV1("current_phase_qualification_other_head")
            versions.append(version)
        else:
            if version.revision not in {before.revision, actual.revision}:
                raise MissingProductionOriginalV1("exact_phase_qualification_projection_version")
            if version.key in prior_keys:
                versions.append(GraphVersion(before.key, before.revision))
    prior_pages = {page.type_id: page for page in prior.query_coverage}
    pages = []
    for page in current.query_coverage:
        actual_atoms = actual_read.complete_inventory(db, page.type_id)
        actual_versions = tuple(GraphVersion(atom.key, atom.revision) for atom in actual_atoms)
        if not page.complete or page.row_versions != actual_versions:
            raise MissingProductionOriginalV1("actual_current_phase_qualification_complete_scope")
        projected = tuple(GraphVersion(mapping[v.key].key, mapping[v.key].revision) if v.key in mapping else v
            for v in actual_versions if v.key not in mapping or mapping[v.key].revision > 0)
        old = prior_pages.get(page.type_id)
        if old is None or not old.complete or projected != old.row_versions:
            raise MissingProductionOriginalV1("exact_phase_qualification_scope_delta")
        pages.append(replace(page, row_versions=projected, epoch=old.epoch))
    return replace(current, read_versions=tuple(versions), query_coverage=tuple(pages))


def _phase_budget_comparison_view_v1(db, *, frame, readers, transition, lease):
    t = _require_phase_transition_v1(db, frame=frame, readers=readers, transition=transition)
    if type(t) in {CompletedPhaseActionTransitionV1,SelectedArtifactPhaseTransitionV2}:
        # Spent model resources remain spent. This is no new model dispatch.
        return lease
    row = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease.lease_id, t.prepare_operation_id)).fetchone()
    if (row is None or row[0] != t.reservation_digest or tuple(sorted(json.loads(row[1]).items())) != t.reservation_ceiling
            or row[2] != "reserved" or row[3] is not None
            or any(lease.reserved.get(dim, 0) < amount for dim, amount in t.reservation_ceiling)):
        raise MissingProductionOriginalV1("actual_still_reserved_original_phase_price_view")
    own = dict(t.reservation_ceiling)
    return replace(lease, reserved={dim: amount - own.get(dim, 0) for dim, amount in lease.reserved.items()})


@contextmanager
def _phase_preparation_transition_v1(db, *, frame, request, phase_selector, installed_readers):
    readers = _readers(installed_readers)
    from .d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v2
    prepared=read_artifact_draft_prepared_v2(db,namespace=phase_selector.task.namespace,issuer=readers.issuer,selector=phase_selector)
    if prepared is None:
        t=_reconstruct_selected_artifact_phase_transition_v2(db,frame=frame,request=request,
            phase_selector=phase_selector,readers=readers)
    else:
        t = _reconstruct_phase_preparation_transition_v1(db, frame=frame, request=request,
            phase_selector=phase_selector, readers=readers)
    _ACTIVE_PHASE_TRANSITIONS[id(t)] = (t, _phase_transition_digest_v1(t))
    try:
        yield t
    finally:
        _ACTIVE_PHASE_TRANSITIONS.pop(id(t), None)


def _phase_history_atom_v1(db, read, *, version, expected_value, producer_operation_id=None):
    from ..graph_types import GraphAtom
    if version.revision == 0:
        if expected_value is not None:
            raise ValueError("phase negative predecessor cannot carry a value")
        return GraphAtom(version.key, 0, {}, False)
    row = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (version.key.token, version.revision)).fetchone()
    if (row is None or row[2] != 1 or json.loads(row[1]) != expected_value
            or producer_operation_id is not None and row[0] != producer_operation_id):
        raise MissingProductionOriginalV1("actual_phase_transition_graph_history_producer")
    read.committed_operation(db, row[0])
    return GraphAtom(version.key, version.revision, expected_value, True)


def _phase_cas_versions_v1(original, key):
    before = tuple(v for v in original["read_versions"] if v.key == key)
    after = tuple(v for v in original["receipt"].write_versions if v.key == key)
    if len(before) != 1 or len(after) != 1 or after[0].revision != before[0].revision + 1:
        raise MissingProductionOriginalV1("actual_exact_phase_transition_cas_versions")
    return before[0], after[0]


def _phase_original_v1(db, read, operation_id, kind):
    original = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, operation_id)
    if original is None or (original["domain"], original["operation_kind"]) != ("d11", kind):
        raise MissingProductionOriginalV1("actual_adopted_phase_transition:" + kind)
    read.original("d11-current:" + original["original_digest"][:48],
        kind="d11.current-" + kind, digest=original["original_digest"])
    return original


def _reconstruct_phase_preparation_transition_v1(db, *, frame, request, phase_selector, readers):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2, artifact_draft_model_ids_v2
    from .d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v2, read_artifact_draft_frozen_v2,
        read_artifact_draft_model_request_v2, _artifact_phase_selection_locator_v2,
        require_current_artifact_phase_group_v2, installed_artifact_draft_workflow_v2)
    from .foreground_cycle_v1 import decode_foreground_job_v1, foreground_cycle_from_wire_v1
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    from .d11_types import job_graph_write
    from .jobs import get_job, _job_from_dict
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d11_offline_originals_v1 import _utc
    graph = readers.current().graph
    if (type(request) is not ConsumePersonalDecisionRequestV1 or type(phase_selector) is not ArtifactDraftPhaseSelectorV2
            or db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()):
        raise TypeError("phase transition requires actual installed Graph and current W01 selectors")
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    if phase_selector.task.namespace != ns or request.decision_ref != phase_selector.decision_ref:
        raise ValueError("phase transition crossed its actual Decision/task namespace")
    located, selection, decision = _artifact_phase_selection_locator_v2(db, phase_selector)
    if located != request:
        raise ValueError("phase transition changed its actual selected preparation locator")
    original = read_adopted_domain_operation_v1(db, ns, request.prepared_candidates_operation_id)
    if original is None or (original["domain"], original["operation_kind"]) != ("d08", PREPARE_OPERATION_V1):
        raise MissingProductionOriginalV1("actual_phase_candidate_preparation_original")
    read.original("d08-current:" + original["original_digest"][:48],
        kind="d08.current-" + PREPARE_OPERATION_V1, digest=original["original_digest"])
    candidates = decode_typed_production_value_v1(original["payload"]["provenance"]["prepared_candidates"],
        PreparedPersonalCandidateSetV1)
    matches = tuple(c for c in candidates.candidates if c.future_identity.action_ref == decision["chosen_action_ref"])
    if len(matches) != 1 or matches[0].eligibility.hard_status != "eligible" or matches[0].price is None:
        raise MissingProductionOriginalV1("actual_selected_eligible_phase_candidate")
    chosen = matches[0]; binding = chosen.binding
    if (type(binding) not in {ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3} or (binding.task, binding.method_ref) !=
            (phase_selector.task, phase_selector.method_ref) or candidates.future_decision_ref != phase_selector.decision_ref
            or candidates.selection_operation_id != selection["receipt"].operation_id):
        raise ValueError("phase transition changed the adopted whole-method binding")
    ids = artifact_draft_model_ids_v2(phase_selector)
    prepared = read_artifact_draft_prepared_v2(db, namespace=ns, issuer=readers.issuer, selector=phase_selector)
    if prepared is None:
        raise MissingProductionOriginalV1("actual_signed_phase_preparation_transition")
    frozen = read_artifact_draft_frozen_v2(db, prepared=prepared, issuer=readers.issuer)
    _require_private_phase_postcondition_commitment_v1(db,selector=phase_selector,binding=binding,
        frozen=frozen,issuer=readers.issuer,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
        installed_bundle=readers.bundle,frame=frame)
    prepare = _phase_original_v1(db, read, ids["prepare"], "prepare_artifact_draft_model_v2")
    read.original(ids["job"], kind="d11.life_c4_phase_prepared", digest=prepared.digest)
    read.original(ids["frozen"], kind="d11.life_c4_phase_frozen", digest=frozen.digest)
    p = prepare["payload"]["provenance"]
    if (set(p) != {"prepared", "frozen_ref", "frozen_digest", "before_cycle", "after_cycle"}
            or p["prepared"] != plain_v1(prepared) or p["frozen_ref"] != prepared.frozen_ref
            or p["frozen_digest"] != frozen.digest or prepared.owner_guard != frame.owner_guard
            or prepared.activation_generation != frame.activation_generation
            or (prepared.installation_id, prepared.manifest_digest) !=
               (readers.bundle.installation_policy.installation_id, readers.bundle.installation_policy.manifest_digest)
            or prepared.actor_ref != frame.envelope.authority.actor
            or prepared.parent_budget_lease_ref != candidates.parent_budget_lease_ref
            or frame.now_utc >= min(frozen.deadline_utc, _utc(prepared.deadline_utc).timestamp())):
        raise MissingProductionOriginalV1("actual_current_phase_preparation_owner_frozen_scope")
    expected_extent = binding.extent if phase_selector.phase_kind == "tone_sample" else binding.full_extent
    if frozen.extent != expected_extent:
        raise ValueError("phase transition changed its Decision-frozen whole-method text extent")
    before_cycle = decode_foreground_job_v1(p["before_cycle"], namespace=ns)
    after_cycle = decode_foreground_job_v1(p["after_cycle"], namespace=ns)
    cycle_key = job_graph_write(before_cycle).key
    if cycle_key.token != phase_selector.task.cycle_job_ref or job_graph_write(after_cycle).key != cycle_key:
        raise ValueError("phase transition changed its original foreground cycle")
    before_version, after_version = _phase_cas_versions_v1(prepare, cycle_key)
    candidate_versions = tuple(v for v in candidates.read_versions if v.key == cycle_key)
    if candidate_versions != (before_version,):
        raise MissingProductionOriginalV1("actual_unbroken_candidate_to_phase_cycle_predecessor")
    before_atom = _phase_history_atom_v1(db, read, version=before_version,
        expected_value=job_graph_write(before_cycle).value)
    _phase_history_atom_v1(db, read, version=after_version, expected_value=job_graph_write(after_cycle).value,
        producer_operation_id=prepared.operation_id)
    before_cont = foreground_cycle_from_wire_v1(before_cycle.continuation)
    after_cont = foreground_cycle_from_wire_v1(after_cycle.continuation)
    if (before_cycle.phase != "running" or before_cycle.lease_holder != prepared.actor_ref
            or after_cycle.phase != "waiting" or after_cycle.lease_holder is not None
            or after_cycle.cancel_epoch != before_cycle.cancel_epoch or type(after_cont.call_plan) is not ForegroundCallPlanV2
            or after_cont.call_plan.phase_group != before_cont.call_plan.phase_group
            or after_cont.call_plan.phase_group.selector != phase_selector
            or after_cycle != replace(before_cycle, phase="waiting", continuation=plain_v1(after_cont),
                wake_condition=plain_v1(after_cont.wait), lease_holder=None, lease_expires_utc=None)):
        raise ValueError("phase preparation is not its exact once cycle wait/release transition")
    require_current_artifact_phase_group_v2(db, namespace=ns, group=after_cont.call_plan.phase_group, issuer=readers.issuer)
    current_cycle = get_job(db, after_cycle.job_id)
    cycle_atom = read.head(db, cycle_key, required=True)
    if current_cycle != after_cycle or cycle_atom.revision != after_version.revision or cycle_atom.value != job_graph_write(after_cycle).value:
        raise MissingProductionOriginalV1("actual_phase_cycle_has_no_unproven_successor")

    quote = readers.resource_issuer.original_signed_quote(db, prepared.quote_id, 1)
    workflow = installed_artifact_draft_workflow_v2(readers.bundle)
    if (canonical_digest(quote) != prepared.quote_digest or prepared.workflow_digest != canonical_digest(plain_v1(workflow))
            or quote.parent_budget_lease_ref != candidates.parent_budget_lease_ref or quote.operation_id != prepared.operation_id
            or quote.work_kind != "artifact_draft_v1" or quote.resource_ref != workflow.provider_config_ref
            or quote.activity_id != before_cycle.activity_id or prepared.activity_id != before_cycle.activity_id
            or quote.deadline_utc != frozen.deadline_utc or quote.valid_until_utc != frozen.deadline_utc
            or set(quote.ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
            or any(amount > workflow.quote_ceiling.get(dim, -1) for dim, amount in quote.ceiling.items())):
        raise MissingProductionOriginalV1("actual_installed_signed_phase_reservation_price")
    from .foreground_call_plan_v1 import ForegroundModelAttemptV2
    from .foreground_cycle_v1 import ForegroundWaitV1
    from ..runtime_contracts import QueryEpoch
    attempt = ForegroundModelAttemptV2("C4", prepared.call_id, None, prepared.operation_id,
        prepared.reservation_digest, prepared.parent_budget_lease_ref, quote.ceiling["input_tokens"],
        quote.ceiling["output_tokens"], "reserved", phase_selector=phase_selector)
    expected_plan = replace(before_cont.call_plan, attempts=(*before_cont.call_plan.attempts, attempt))
    wait = ForegroundWaitV1("d11", "artifact_draft_phase_model_terminal", (),
        QueryEpoch(ns, "foreground:" + before_cycle.job_id, frozen.source_query_epoch),
        before_cont.wait.consume_cursor if before_cont.wait is not None else 0, None)
    if after_cont != replace(before_cont, stage="draft_content", call_plan=expected_plan, wait=wait):
        raise ValueError("phase cycle changed fields outside its actual once physical attempt")
    created = db.execute("SELECT digest,job_id,job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='create'", (*ns.as_tuple, "create:" + prepared.operation_id)).fetchone()
    if created is None or created[0] != prepared.reservation_digest or created[1] != prepared.job_id:
        raise MissingProductionOriginalV1("actual_phase_once_job_create_receipt")
    queued = _job_from_dict(json.loads(created[2]))
    job_key = job_graph_write(queued).key
    expected_job_cont = {"schema": "d11.artifact-draft-phase-model-job.v2", "selector": plain_v1(phase_selector),
        "prepared_digest": prepared.digest}
    if (queued.phase != "queued" or queued.fence or queued.cancel_epoch or queued.lease_holder is not None
            or queued.lease_expires_utc is not None or queued.result_ref is not None or queued.operation_id != prepared.operation_id
            or queued.job_id != prepared.job_id or queued.activity_id != prepared.activity_id
            or queued.budget_ref != prepared.parent_budget_lease_ref or queued.continuation != expected_job_cont
            or prepare["payload"]["writes"] != plain_v1((job_graph_write(queued), job_graph_write(after_cycle)))):
        raise ValueError("phase once create job differs from the actual W01 preparation")
    job_before, job_after = _phase_cas_versions_v1(prepare, job_key)
    if job_before.revision != 0:
        raise ValueError("phase create must have its actual negative Graph predecessor")
    absent = _phase_history_atom_v1(db, read, version=job_before, expected_value=None)
    _phase_history_atom_v1(db, read, version=job_after, expected_value=job_graph_write(queued).value,
        producer_operation_id=prepared.operation_id)
    checkpoint = db.execute("SELECT digest,job_id,job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='checkpoint'", (*ns.as_tuple, prepared.operation_id)).fetchone()
    if (checkpoint is None or checkpoint[0] != canonical_digest(plain_v1(after_cycle))
            or checkpoint[1] != after_cycle.job_id or _job_from_dict(json.loads(checkpoint[2])) != after_cycle):
        raise MissingProductionOriginalV1("actual_phase_cycle_checkpoint_receipt")
    reservation = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone()
    ceiling = tuple(sorted(quote.ceiling.items()))
    expected_reservation = canonical_digest(("d11.artifact-draft-phase-model-reservation.v2", phase_selector,
        frozen.digest, quote, frame.owner_guard))
    if (reservation is None or reservation[0] != prepared.reservation_digest or prepared.reservation_digest != expected_reservation
            or tuple(sorted(json.loads(reservation[1]).items())) != ceiling
            or reservation[2] != "reserved" or reservation[3] is not None):
        raise MissingProductionOriginalV1("actual_unchanged_reserved_phase_once_identity")
    reserve_op = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='reserve'", (*ns.as_tuple, prepared.operation_id)).fetchone()
    if reserve_op is None or reserve_op[:2] != (prepared.reservation_digest, prepared.parent_budget_lease_ref):
        raise MissingProductionOriginalV1("actual_phase_reservation_operation_receipt")
    budget_receipt = json.loads(reserve_op[2])
    if (budget_receipt["operation_id"] != prepared.operation_id or budget_receipt["digest"] != prepared.reservation_digest
            or budget_receipt["lease_id"] != prepared.parent_budget_lease_ref or budget_receipt["status"] != "reserved"):
        raise ValueError("phase reservation receipt differs from its actual once operation")
    actual_job = get_job(db, prepared.job_id)
    producer_originals = [(prepared.operation_id, prepare["original_digest"])]
    acquire_row = read_adopted_domain_operation_v1(db, ns, prepared.acquire_operation_id)
    if acquire_row is not None:
        acquire = _phase_original_v1(db, read, prepared.acquire_operation_id, "acquire_artifact_draft_model_v2")
        a = acquire["payload"]["provenance"]
        if set(a) != {"prepared_digest", "request_digest", "job", "actual_count_proof"} or a["prepared_digest"] != prepared.digest:
            raise ValueError("phase acquire changed its exact preparation/count provenance")
        acquired = _job_from_dict(a["job"])
        request_original = read_artifact_draft_model_request_v2(db, prepared=prepared, issuer=readers.issuer)
        from .d11_life_preparation_v1 import _read
        request_row = _read(db, issuer=readers.issuer, namespace=ns, kind="c4_phase_request", ref=ids["request"])
        read.original(ids["request"], kind="d11.life_c4_phase_request", digest=canonical_digest(request_row[0]))
        from .d11_artifact_draft_model_v1 import (require_saved_artifact_phase_count_original_v2,
            ArtifactDraftModelRequestOriginalV2,artifact_draft_model_from_wire_v2)
        actual_request=artifact_draft_model_from_wire_v2(request_row[0],ArtifactDraftModelRequestOriginalV2)
        require_saved_artifact_phase_count_original_v2(db,prepared=prepared,issuer=readers.issuer,installed_bundle=readers.bundle)
        if a["actual_count_proof"]!=plain_v1(actual_request.actual_count_proof):
            raise ValueError("phase acquire count proof differs from its actual signed original request")
        acquired_receipt = db.execute("SELECT digest,job_id,job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
            "AND operation_id=? AND phase='acquire'", (*ns.as_tuple, prepared.acquire_operation_id)).fetchone()
        fixed = replace(queued, phase="running", fence=1, lease_holder=prepared.worker_subject,
            lease_expires_utc=acquired.lease_expires_utc)
        if (acquired != fixed or acquired.lease_expires_utc is None or actual_job != acquired
                or request_original.digest != a["request_digest"] or request_original.call_id != prepared.call_id
                or request_original.envelope.authority.actor != prepared.worker_subject
                or request_original.envelope.authority.worker_fence != 1
                or request_original.envelope.identity.operation_id != prepared.acquire_operation_id
                or request_original.envelope.parent_budget_lease_ref != prepared.parent_budget_lease_ref
                or not frame.now_utc < _utc(acquired.lease_expires_utc).timestamp() <= frozen.deadline_utc
                or acquired_receipt is None or acquired_receipt[0] != canonical_digest(plain_v1(acquired))
                or acquired_receipt[1] != prepared.job_id or _job_from_dict(json.loads(acquired_receipt[2])) != acquired
                or acquire["payload"]["writes"] != plain_v1((job_graph_write(acquired),))):
            raise MissingProductionOriginalV1("actual_phase_once_acquire_sql_request_receipt")
        acq_before, acq_after = _phase_cas_versions_v1(acquire, job_key)
        if acq_before != job_after:
            raise MissingProductionOriginalV1("actual_unbroken_phase_job_acquire_predecessor")
        _phase_history_atom_v1(db, read, version=acq_before, expected_value=job_graph_write(queued).value,
            producer_operation_id=prepared.operation_id)
        _phase_history_atom_v1(db, read, version=acq_after, expected_value=job_graph_write(acquired).value,
            producer_operation_id=prepared.acquire_operation_id)
        job_after = acq_after
        producer_originals.append((prepared.acquire_operation_id, acquire["original_digest"]))
    elif actual_job != queued:
        raise MissingProductionOriginalV1("actual_phase_job_has_no_unproven_successor")
    current_job_atom = read.head(db, job_key, required=True)
    if current_job_atom.revision != job_after.revision or current_job_atom.value != job_graph_write(actual_job).value:
        raise MissingProductionOriginalV1("actual_exact_phase_current_job_head")
    if (frozen.task_source_ref != before_cont.source_ref or frozen.current_self_ref != prepared.actor_ref
            or (frozen.access_epoch, frozen.delete_epoch) !=
               (frame.envelope.version_guard.access_epoch, frame.envelope.version_guard.delete_epoch)):
        raise MissingProductionOriginalV1("current_phase_frozen_self_task_source_generations")
    for version in frozen.source_read_versions:
        if read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_phase_frozen_other_source_domain_head")
    for source in frozen.sources:
        atom = read.head(db, source.ref, required=True)
        if atom.revision != source.revision or canonical_digest(atom.value) != source.value_digest:
            raise MissingProductionOriginalV1("current_phase_frozen_exact_source_value")
    read.source_family(db, tuple(source.ref for source in frozen.sources), purpose="consolidation")
    checkpoint_projections,checkpoint_origins=_current_artifact_choice_checkpoint_projections_v2(db,read=read,
        selector=phase_selector,readers=readers,prepared_candidates=candidates)
    return PhasePreparationTransitionV1(_PHASE_TRANSITION_KEY, graph=graph, frame=frame, readers=readers,
        request=request, phase_selector=phase_selector, candidate_original_digest=original["original_digest"],
        prepared_candidates=candidates, selected_binding_digest=binding.digest, decision_digest=phase_selector.decision_digest,
        group_identity_digest=after_cont.call_plan.phase_group.identity_digest, frozen_digest=frozen.digest,
        prepare_operation_id=prepared.operation_id, reservation_digest=prepared.reservation_digest,
        reservation_ceiling=ceiling, before_cycle=before_cycle, after_cycle=after_cycle,
        projections=((before_atom, after_version, canonical_digest(cycle_atom.value)),
            (absent, job_after, canonical_digest(current_job_atom.value)),*checkpoint_projections),
        producer_originals=(*producer_originals,*checkpoint_origins))


def _read_plan_phase_preparation_transition_v1(db, *, namespace, phase_selector, installed_readers):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    from .d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v2
    from .d11_types import runtime_job_key
    readers = _readers(installed_readers)
    p = read_artifact_draft_prepared_v2(db, namespace=namespace, issuer=readers.issuer, selector=phase_selector)
    if p is None:
        return production_read_plan_v1((), ())
    ids = artifact_draft_model_ids_v2(phase_selector)
    preparation = read_adopted_domain_operation_v1(db, namespace, p.operation_id)
    if preparation is None:
        raise MissingProductionOriginalV1("actual_phase_transition_prepare_read_plan_original")
    originals = [ids["job"], ids["frozen"], "d11-current:" + preparation["original_digest"][:48]]
    acquired = read_adopted_domain_operation_v1(db, namespace, p.acquire_operation_id)
    if acquired is not None:
        originals.extend(("d11-current:" + acquired["original_digest"][:48], ids["request"]))
    return production_read_plan_v1((), (AtomKey.from_token(phase_selector.task.cycle_job_ref),
        runtime_job_key(*namespace.as_tuple, p.activity_id, p.job_id)), (), originals)


class InstalledPersonalCandidateReadersV1:
    def __init__(self, token, *, graph, bootstrap, bundle, need_qualification_reader,
            candidate_eligibility_reader, phase_price_reader):
        if token is not _INSTALLED:
            raise TypeError("personal candidate readers require their exact W01 installation factory")
        self.graph, self.bootstrap, self.bundle = graph, bootstrap, bundle
        self.issuer = graph._GraphCoordinator__d11_issuer
        self.resource_issuer = graph._GraphCoordinator__d02_issuer
        self.need_qualification_reader = (InstalledCurrentPersonalNeedReaderV1(_INSTALLED, self)
            if need_qualification_reader is None else need_qualification_reader)
        from .personal_candidate_eligibility_v1 import install_current_personal_eligibility_reader_v1
        self.candidate_eligibility_reader = (install_current_personal_eligibility_reader_v1(self)
            if candidate_eligibility_reader is None else candidate_eligibility_reader)
        from .personal_candidate_eligibility_v1 import InstalledCurrentSourceNotePriceReaderV1
        self.phase_price_reader = InstalledCurrentSourceNotePriceReaderV1(self) if phase_price_reader is None else phase_price_reader

    def current(self):
        self.graph._admin(self.bootstrap)
        assembly = self.graph._GraphCoordinator__d04_installed_joint_assembly
        if (assembly is None or assembly.admin_bundle is not self.bundle
                or self.issuer is not self.graph._GraphCoordinator__d11_issuer
                or self.resource_issuer is not self.graph._GraphCoordinator__d02_issuer):
            raise ValueError("candidate reader changed its actual Graph/bootstrap/installed bundle")
        return self


def install_personal_candidate_readers_v1(*, graph, bootstrap, bundle,
        need_qualification_reader=None, candidate_eligibility_reader=None, phase_price_reader=None):
    from ..graph_coordinator import GraphCoordinator
    from ..host.authority_profile import AdminInstallationBundle
    if type(graph) is not GraphCoordinator or type(bundle) is not AdminInstallationBundle:
        raise TypeError("candidate reader factory requires the actual installed Graph and bundle")
    graph._admin(bootstrap)
    if type(graph._GraphCoordinator__d11_issuer) is not D11BudgetJobIssuer or type(graph._GraphCoordinator__d02_issuer) is not D02ResourceIssuer:
        raise TypeError("candidate reader factory requires the actual installed issuers")
    return InstalledPersonalCandidateReadersV1(_INSTALLED, graph=graph, bootstrap=bootstrap, bundle=bundle,
        need_qualification_reader=need_qualification_reader, candidate_eligibility_reader=candidate_eligibility_reader,
        phase_price_reader=phase_price_reader).current()


class InstalledCurrentPersonalNeedReaderV1:
    """Read adopted ingress facts only; this reader never creates C3 work."""
    def __init__(self, token, readers):
        if token is not _INSTALLED:
            raise TypeError("Need reader requires the actual candidate installation factory")
        self.readers = readers

    def __call__(self, *, db, frame, request, _phase_transition=None):
        return read_current_personal_ingress_need_v1(db, frame=frame, request=request,
            installed_readers=self.readers.current(), _phase_transition=_phase_transition)

    def read_plan_inputs_v1(self, *, db, namespace, activity_id, request):
        readers = self.readers.current()
        found = _personal_ingress_need_locator_v1(db, namespace, request)
        if found is None:
            return production_read_plan_v1((), ())
        need, original = found
        from ..domains.d03.self_perspective import self_mapping_key
        from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
        from .d07_execution_v1 import read_prepared_d07_execution_v1
        from .d11_types import runtime_job_key
        from .jobs import get_job
        keys = [version.key for version in original["read_versions"]]
        keys.extend((AtomKey.from_token(need.cycle_job_ref), self_mapping_key(namespace)))
        roots, originals = [need.source_ref], [request.need_qualification_original_ref]
        job = get_job(db, AtomKey.from_token(need.cycle_job_ref).name)
        originals.append(job.operation_id)
        ids = ingress_recall_model_ids_v1(namespace, need.c02_operation_id)
        prepared = read_prepared_d07_execution_v1(db, readers.issuer, namespace, ids["job"])
        if prepared is not None:
            keys.append(runtime_job_key(*namespace.as_tuple, prepared.activity_id, prepared.job_id))
            keys.extend(AtomKey.from_token(row.ref) for row in prepared.read_rows)
            roots.extend(row.ref for row in prepared.read_rows if AtomKey.from_token(row.ref).type_name == "memory.source")
            originals.append(ids["adopt"])
        from .d06_ingress_recall_v1 import LEDGER_TYPES
        return production_read_plan_v1((*LEDGER_TYPES, "d01.persona_activation.v1", "d01.persona_plan.v1",
            "d07.current_interpretation.v1"), keys, roots, originals)


def _personal_ingress_need_locator_v1(db, namespace, request):
    from .d01_production_operations_v1 import table_exists_v1
    from .d06_ingress_recall_v1 import NEED_OPERATION, read_adopted_ingress_recall_need_v1
    from .d07_task_history_v1 import OPERATION as TASK_NO_SEARCH_OPERATION, read_adopted_task_no_search_v1
    if not table_exists_v1(db, "graph_domain_production_originals_v1"):
        return None
    rows = db.execute("SELECT operation_id FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? "
        "AND domain='d07' AND operation_kind IN (?,?) AND 'd07-current:' || substr(original_digest,1,48)=? LIMIT 2",
        (*namespace.as_tuple, NEED_OPERATION, TASK_NO_SEARCH_OPERATION, request.need_qualification_original_ref)).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError("personal Need locator names ambiguous adopted ingress originals")
    original = read_adopted_domain_operation_v1(db, namespace, rows[0][0])
    c02 = original["payload"]["request"]["c02_operation_id"]
    if original["operation_kind"] == TASK_NO_SEARCH_OPERATION:
        actual = read_adopted_task_no_search_v1(db, namespace=namespace, c02_operation_id=c02)
        if actual is None or actual[1]["operation_id"] != original["operation_id"]:
            raise MissingProductionOriginalV1("actual_current_task_no_search_adoption")
        return actual[0].need, original
    need = read_adopted_ingress_recall_need_v1(db, namespace=namespace, c02_operation_id=c02)
    if need is None:
        raise MissingProductionOriginalV1("actual_adopted_personal_ingress_need")
    return need, original


def read_current_personal_ingress_need_v1(db, *, frame, request, installed_readers, _phase_transition=None):
    readers = _readers(installed_readers)
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    from .owner_source_note_need_v1 import read_owner_source_note_need_original_v2, require_current_owner_source_note_need_v1, install_owner_source_note_need_readers_v1
    owner_need = read_owner_source_note_need_original_v2(db,namespace=ns,original_ref=request.need_qualification_original_ref)
    if owner_need is not None:
        if _phase_transition is not None:
            raise ValueError("Owner fixed-recipe Need cannot borrow an Artifact phase transition")
        need_value, _ = owner_need
        from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
        saved_auth = read_owner_source_note_task_authorization_v2(db,namespace=ns,
            original_ref=need_value.authorization_original_ref,issuer=readers.issuer)
        if saved_auth is None: raise MissingProductionOriginalV1("actual_current_Owner_task_authorization_for_candidates")
        auth = saved_auth[0]
        if (request.plan_ref,request.goal_ref) != (need_value.plan_head.key.token,need_value.goal_head.key.token):
            raise ValueError("Owner fixed-recipe Need cannot qualify another Goal or Plan")
        for binding in request.bindings:
            if type(binding) is not SourceNoteCandidateBindingV1 or (binding.project_ref,binding.recipe_ref,binding.source_ref,
                    binding.goal_ref,binding.target_entity_ref,binding.role_binding_ref) != (
                    auth.request.project_ref,auth.request.recipe_ref,auth.request.body_source_ref,need_value.goal_head.key.token,
                    auth.request.target_entity_ref,auth.request.role_binding_ref):
                raise ValueError("Owner task candidates must preserve the exact signed SourceNote authorization tuple")
        return require_current_owner_source_note_need_v1(db,frame=frame,
            original_ref=request.need_qualification_original_ref,installed_readers=install_owner_source_note_need_readers_v1(readers.graph))
    found = _personal_ingress_need_locator_v1(db, ns, request)
    if found is None:
        raise MissingProductionOriginalV1("actual_adopted_personal_ingress_need")
    need, original = found
    from .d06_ingress_recall_v1 import NEED_OPERATION, LEDGER_TYPES
    authenticated = read.original(request.need_qualification_original_ref,
        kind="d07.current-" + original["operation_kind"], digest=original["original_digest"])
    from .d07_task_history_v1 import OPERATION as TASK_NO_SEARCH_OPERATION, require_current_task_no_search_v1
    if original["operation_kind"] == TASK_NO_SEARCH_OPERATION:
        from .d06_ingress_recall_v1 import InstalledIngressRecallReadersV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .d07_task_history_v1 import AdoptCurrentTaskNoSearchRequestV1
        no_search_request = decode_typed_production_value_v1(original["payload"]["request"], AdoptCurrentTaskNoSearchRequestV1)
        typed, actual_authenticated, actual_original = require_current_task_no_search_v1(db, frame=frame,
            request=no_search_request, installed_readers=InstalledIngressRecallReadersV1(
                issuer=readers.issuer, installed_bundle=readers.bundle))
        if typed.need != need or actual_authenticated != authenticated or actual_original["operation_id"] != original["operation_id"]:
            raise ValueError("personal Need changed its actual current-task no-search Source/Owner/Goal/ledger proof")
    # A cycle advances legitimately after Need adoption. Its current job and
    # immutable responsibility are checked below; all other hard heads stay exact.
    for version in original["read_versions"]:
        if version.key.token != need.cycle_job_ref and read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_personal_ingress_need_hard_fact")
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    old_pages = tuple(decode_typed_production_value_v1(row, ProductionQueryCoverageV1)
        for row in original["payload"]["query_coverage"])
    for type_name in LEDGER_TYPES:
        pages = tuple(page for page in old_pages if page.type_id == type_name)
        current = read.complete_inventory(db, type_name)
        if (len(pages) != 1 or not pages[0].complete
                or pages[0].row_versions != tuple(GraphVersion(atom.key, atom.revision) for atom in current)):
            raise MissingProductionOriginalV1("complete_current_personal_ingress_need_ledger")
    from .foreground_cycle_v1 import (foreground_cycle_from_wire_v1,
        require_current_foreground_responsibility_v1, _adopted_c02_v1)
    from .d11_types import job_graph_write
    from .jobs import get_job
    cycle_atom = read.head(db, need.cycle_job_ref, required=True)
    job = get_job(db, AtomKey.from_token(need.cycle_job_ref).name)
    if cycle_atom.value != job_graph_write(job).value:
        raise MissingProductionOriginalV1("actual_current_personal_foreground_job_graph")
    continuation = foreground_cycle_from_wire_v1(job.continuation)
    phase_cycle = None
    if _phase_transition is not None:
        phase_cycle = _require_phase_transition_v1(db, frame=frame, readers=readers,
            transition=_phase_transition).after_cycle
        if job != phase_cycle:
            raise MissingProductionOriginalV1("actual_current_personal_need_phase_cycle")
    creation = read_adopted_domain_operation_v1(db, ns, job.operation_id)
    from .source_note_foreground_v1 import ForegroundSourceNoteContinuationV1, OPERATION as source_note_create
    expected_create = source_note_create if type(continuation) is ForegroundSourceNoteContinuationV1 else "create_foreground_cycle_v2"
    if creation is None or creation["operation_kind"] != expected_create:
        raise MissingProductionOriginalV1("actual_adopted_personal_foreground_responsibility")
    read.original(job.operation_id, kind="d11.current-" + expected_create, digest=creation["original_digest"])
    responsibility = require_current_foreground_responsibility_v1(db, namespace=ns, job=job,
        installed_bundle=readers.bundle, issuer=readers.issuer, owner_guard=frame.owner_guard,
        purpose=frame.envelope.authority.purpose, audiences=frame.envelope.authority.audience, now_utc=frame.now_utc)
    if (responsibility is None or continuation.c02_operation_id != need.c02_operation_id
            or continuation.source_ref != need.source_ref or job.activity_id != frame.envelope.identity.activity_id
            or job.budget_ref != frame.envelope.parent_budget_lease_ref or job.cancel_epoch != need.cancel_generation
            or continuation.cancel_generation != job.cancel_epoch
            or phase_cycle is None and (job.phase != "running" or job.lease_holder != frame.envelope.authority.actor)
            or continuation.responsibility_ref != need.responsibility_ref
            or continuation.responsibility_digest != need.responsibility_digest
            or responsibility.digest != need.responsibility_digest
            or responsibility.c02_operation_id != need.c02_operation_id or responsibility.source_ref != need.source_ref
            or frame.now_utc >= min(need.deadline_utc, responsibility.deadline_utc)):
        raise MissingProductionOriginalV1("current_same_personal_need_c02_source_cycle_responsibility")
    receipt = _adopted_c02_v1(db, ns, need.c02_operation_id)
    if canonical_digest(receipt) != responsibility.c02_receipt_digest:
        raise ValueError("personal Need changed its actual committed C02 receipt")
    focus = read.head(db, need.focus_ref, required=True)
    ticket = read.head(db, need.attention_ticket_ref, required=True)
    if (focus.revision != need.focus_revision or focus.value["primary_ticket_ref"] != need.attention_ticket_ref
            or ticket.revision != need.attention_ticket_revision or not ticket.value["eligible"]
            or not ticket.value["resources_available"] or ticket.value["cancel_refs"]
            or frame.now_utc >= ticket.value["valid_until"] or ticket.value["causal_root"] != need.source_ref):
        raise MissingProductionOriginalV1("current_personal_need_ingress_attention")
    source = read.head(db, need.source_ref, required=True)
    read.source_family(db, (need.source_ref,))
    policy = readers.bundle.d06_recall
    if ((source.revision, canonical_digest(source.value)) != (need.source_revision, need.source_digest)
            or (policy.policy_ref, policy.policy_version, policy.policy_digest) !=
               (need.policy_ref, need.policy_version, need.policy_digest)):
        raise MissingProductionOriginalV1("current_same_personal_need_source_and_installed_policy")
    source_note = type(continuation) is ForegroundSourceNoteContinuationV1
    authorization = None
    if source_note:
        from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1
        saved_authorization = read_source_note_task_authorization_v1(db, namespace=ns,
            original_ref=continuation.authorization_original_ref, issuer=readers.issuer)
        if saved_authorization is None:
            raise MissingProductionOriginalV1("actual_signed_SourceNote_candidate_task_authorization")
        authorization, authorization_original = saved_authorization
        read.original(authorization.original_ref, kind="d11.life_source_note_task_authorization", digest=authorization.digest)
        if (authorization.digest != continuation.authorization_original_digest
                or (request.plan_ref, request.goal_ref) != (authorization.request.plan_ref, authorization.request.goal_ref)):
            raise ValueError("SourceNote candidate Plan/Goal differs from its actual signed task authorization")
    for binding in request.bindings:
        if type(binding) is SourceNoteCandidateBindingV1:
            if not source_note:
                raise ValueError("SourceNote candidate cannot borrow an Artifact or natural foreground responsibility")
            actual = (binding.project_ref, binding.recipe_ref, binding.source_ref, binding.goal_ref,
                binding.target_entity_ref, binding.role_binding_ref)
            frozen = (authorization.request.project_ref, authorization.request.recipe_ref, authorization.request.body_source_ref,
                authorization.request.goal_ref, authorization.request.target_entity_ref, authorization.request.role_binding_ref)
            if actual != frozen:
                raise ValueError("SourceNote candidate body/project/target/role differs from its actual signed task authorization")
        elif type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
            if source_note:
                raise ValueError("Artifact candidate cannot borrow a SourceNote task responsibility")
            if (binding.task.c02_operation_id, binding.task.cycle_job_ref) != (need.c02_operation_id, need.cycle_job_ref):
                raise ValueError("personal candidate changed its actual ingress Need task")
    if need.required_checks or need.missing_items or need.routing in {"partial", "required_checks"}:
        raise MissingProductionOriginalV1("actual_resolved_personal_need_mandatory_facts_and_gaps")
    evaluation, prepared = _require_personal_need_c3_resolution_v1(db, read, readers, request, need, continuation,
        _phase_transition=_phase_transition)
    plan = read.head(db, request.plan_ref, required=True)
    goal = read.head(db, request.goal_ref, required=True)
    # Need keeps only its own current dependencies. A later adopted Decision
    # is unrelated to Need and must not change this qualification commitment.
    from ..domains.d03.self_perspective import self_mapping_key
    keys = {version.key for version in (*original["read_versions"], *evaluation["read_versions"])}
    keys.update((plan.key, goal.key, self_mapping_key(ns)))
    if prepared is not None:
        from .d11_types import runtime_job_key
        keys.add(runtime_job_key(*ns.as_tuple, prepared.activity_id, prepared.job_id))
        keys.update(AtomKey.from_token(row.ref) for row in prepared.read_rows)
    if authorization is not None:
        keys.update(version.key for name, version, digest in authorization.heads)
    versions = tuple(GraphVersion(key, read.head(db, key).revision) for key in sorted(keys, key=lambda key: key.token))
    coverage = tuple(page for page in frame.query_coverage if page.type_id in
        {*LEDGER_TYPES, "d01.persona_activation.v1", "d01.persona_plan.v1", "d07.current_interpretation.v1"})
    return CurrentPersonalNeedQualificationV1(authenticated, GraphVersion(plan.key, plan.revision),
        GraphVersion(goal.key, goal.revision), versions, coverage,
        True, False, (), min(need.deadline_utc, responsibility.deadline_utc))


def _require_personal_need_c3_resolution_v1(db, read, readers, request, need, continuation, *, _phase_transition=None):
    from .d07_ingress_recall_preparation_v1 import (
        ingress_recall_model_ids_v1, read_current_ingress_recall_attempt_v1)
    from .d07_execution_v1 import read_prepared_d07_execution_v1, require_current_d07_content_reads_v1
    from .d07_ingress_recall_result_v1 import read_adopted_ingress_recall_routing_v1, ADOPT_OPERATION
    evaluation_read = read if _phase_transition is None else _PhasePersonalCandidateReadV1(read.frame,
        db=db, readers=readers, transition=_phase_transition)
    evaluation = read_current_personal_value_evaluation_v1(db, evaluation_read, request,
        tuple(binding.candidate_ref for binding in request.bindings))
    strategy = evaluation["payload"]["provenance"].get("method_strategy")
    state = strategy["strategy_state"] if strategy is not None else None
    ids = ingress_recall_model_ids_v1(read.frame.envelope.authority.namespace, need.c02_operation_id)
    prepared = read_prepared_d07_execution_v1(db, readers.issuer, read.frame.envelope.authority.namespace, ids["job"])
    all_c3_attempts = tuple(attempt for attempt in continuation.call_plan.attempts if attempt.slot == "C3")
    scoped_trial = strategy is not None and strategy.get("schema") == "d01.method-strategy-projection.v2" and strategy["selection_basis"] == "scoped_trial"
    if (state == "ST2" or scoped_trial) and (all_c3_attempts or prepared is not None):
        raise MissingProductionOriginalV1("st2_or_scoped_trial_personal_need_rejects_any_actual_c3")
    from .foreground_cycle_v1 import read_observed_foreground_call_plan_v1
    observed = read_observed_foreground_call_plan_v1(db, namespace=read.frame.envelope.authority.namespace,
        continuation=continuation, issuer=readers.issuer, installed_bundle=readers.bundle,
        owner_guard=read.frame.owner_guard)
    attempts = tuple(attempt for attempt in observed.attempts if attempt.slot == "C3" and attempt.call_id == ids["call"])
    if not attempts and prepared is None:
        if need.routing != "no_search":
            raise MissingProductionOriginalV1("actual_personal_need_semantic_resolution_without_new_c3")
        return evaluation, prepared
    if len(attempts) != 1 or prepared is None:
        raise MissingProductionOriginalV1("actual_single_current_personal_need_c3_attempt")
    actual = read_current_ingress_recall_attempt_v1(db, namespace=read.frame.envelope.authority.namespace,
        continuation=continuation, attempt=attempts[0], issuer=readers.issuer)
    if actual != attempts[0] or actual.state != "completed":
        raise MissingProductionOriginalV1("actual_current_completed_personal_need_c3")
    require_current_d07_content_reads_v1(db, prepared, issuer=readers.issuer)
    for row in prepared.read_rows:
        read.head(db, row.ref)
    routing = read_adopted_ingress_recall_routing_v1(db, namespace=read.frame.envelope.authority.namespace,
        c02_operation_id=need.c02_operation_id, issuer=readers.issuer)
    if routing is None:
        raise MissingProductionOriginalV1("actual_adopted_personal_need_c3_resolution")
    adopted = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, ids["adopt"])
    read.original(ids["adopt"], kind="d07.current-" + ADOPT_OPERATION, digest=adopted["original_digest"])
    if (routing["cycle_job_ref"] != need.cycle_job_ref or routing["need_ref"] != request.need_qualification_original_ref
            or routing["need_digest"] != canonical_digest(need) or routing["prepared_digest"] != prepared.digest
            or routing["execution_ref"] != actual.terminal_ref or routing["stop_reason"] != "no_history_needed"
            or routing["required_checks"] or routing["missing_items"] or routing["meaningful_unknowns"]):
        raise MissingProductionOriginalV1("complete_current_personal_need_c3_semantic_resolution")
    return evaluation, prepared


def _readers(readers):
    if type(readers) is not InstalledPersonalCandidateReadersV1:
        raise TypeError("exact installed candidate readers required")
    return readers.current()


def waiting_personal_candidate_stage_v1(frame, kind, request, missing):
    return stage_result_v1(frame, "d08", kind, request, coverage="waiting_for_original",
        missing=missing.missing_inputs, continuation=missing.continuation_ref)


def _current_evidence(db, read, originals, versions, coverage):
    for original in originals:
        read.original(original.original_ref, kind=original.kind, digest=original.original_digest)
        for version in original.read_versions:
            if read.head(db, version.key).revision != version.revision:
                raise MissingProductionOriginalV1("current_candidate_original_read_versions")
    for version in versions:
        if read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_candidate_qualification_heads")
    for page in coverage:
        if (not page.complete or page.epoch.namespace != read.frame.envelope.authority.namespace
                or page.epoch.revision > read.frame.snapshot.epochs[0].revision):
            raise MissingProductionOriginalV1("complete_candidate_negative_scope")
        current = read.complete_inventory(db, page.type_id)
        if tuple(GraphVersion(atom.key, atom.revision) for atom in current) != page.row_versions:
            raise MissingProductionOriginalV1("current_complete_candidate_negative_scope")


def _plan_goal(db, read, request, installed_readers=None):
    from .d08_personal_plan_v1 import _facts
    plan_atom = read.head(db, request.plan_ref, required=True)
    from .d08_project_control_v1 import require_current_project_plan_for_new_work_v1
    require_current_project_plan_for_new_work_v1(db, namespace=read.frame.envelope.authority.namespace,
        plan_ref=plan_atom.key.token, expected_plan_revision=plan_atom.revision)
    goal_atom = read.head(db, request.goal_ref, required=True)
    plan, goal = decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value), _decode_goal(goal_atom.value)
    if (plan_atom.revision != request.expected_plan_revision or goal_atom.revision != request.expected_goal_revision
            or plan.goal_ref != request.goal_ref or plan.goal_revision != goal.revision
            or plan.state != "active" or goal.state != "active"
            or plan.actor_ref != "persona:" + read.frame.envelope.authority.namespace.persona_id):
        raise MissingProductionOriginalV1("current_same_personal_candidate_plan_goal_actor")
    _facts(db, read, plan)
    if {row.candidate_ref for row in request.bindings} != set(plan.candidate_refs):
        raise ValueError("preparation must describe exactly the adopted Plan candidates")
    nodes = {node.node_id: node for node in plan.nodes}
    ready = {node.node_id for node in plan.nodes if node.carried_forward_verified}
    methods = dict(plan.method_candidates)
    candidate_activity=plan_atom.key.owner.subject
    if any(type(b) is ArtifactPhaseCandidateBindingV3 and AtomKey.from_token(b.task.cycle_job_ref).owner.subject!=candidate_activity
            for b in request.bindings):
        if installed_readers is None:raise MissingProductionOriginalV1("actual_installed_reader_for_revised_candidate_activity")
        candidate_activity=actual_personal_candidate_activity_v2(db,namespace=read.frame.envelope.authority.namespace,
            request=request,issuer=installed_readers.issuer)
    for binding in request.bindings:
        if binding.node_id not in nodes:
            raise ValueError("candidate is outside its actual Plan node window")
        node = nodes[binding.node_id]
        if node.owner_ref != plan.actor_ref or not set(node.depends_on) <= ready:
            raise MissingProductionOriginalV1("current_ready_candidate_node")
        if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
            if (node.action_kind != "artifact_draft_v1" or binding.task.namespace != read.frame.envelope.authority.namespace
                    or AtomKey.from_token(binding.task.cycle_job_ref).owner.subject != candidate_activity
                    or methods.get(binding.candidate_ref) != binding.method_ref):
                raise ValueError("artifact candidate changed its real task/node/method binding")
        elif (node.action_kind != "source_note" or binding.goal_ref != request.goal_ref
                or binding.source_ref not in plan.source_refs or binding.candidate_ref in methods):
            raise ValueError("source-note cannot stand in for a CP tone-order method")
    return plan_atom, goal_atom, plan, goal, nodes


def read_current_personal_value_evaluation_v1(db, read, request, candidate_refs, *, installed_readers=None):
    from .owner_source_note_need_v1 import read_owner_source_note_need_original_v2
    owner_need = read_owner_source_note_need_original_v2(db,namespace=read.frame.envelope.authority.namespace,
        original_ref=request.need_qualification_original_ref)
    if owner_need is not None:
        if installed_readers is None: raise MissingProductionOriginalV1("actual_installed_Owner_task_Values_consumer")
        from .owner_source_note_values_v1 import read_current_owner_task_values_evaluation_v1
        evaluation = read_current_owner_task_values_evaluation_v1(db,read=read,request=request,
            candidate_refs=candidate_refs,issuer=installed_readers.issuer)
        if evaluation is None: raise MissingProductionOriginalV1("actual_current_Owner_task_two_child_Value_evaluation")
        return evaluation
    evaluation = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, request.value_evaluation_operation_id)
    if evaluation is None or (evaluation["domain"], evaluation["operation_kind"]) != ("d01", "evaluate_values"):
        raise MissingProductionOriginalV1("actual_current_personal_d01_evaluation")
    for version in evaluation["read_versions"]:
        if read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_personal_d01_evaluation_heads")
    values = evaluation["payload"]["provenance"]["evaluation"]
    if set(values["preferred"]) | set(values["rejected"]) | set(values["unresolved"]) != set(candidate_refs):
        raise ValueError("D01 evaluation differs from the exact current candidate set")
    strategy = evaluation["payload"]["provenance"].get("method_strategy")
    if strategy is not None:
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..domains.d01 import PersonaPlan, _validate_persona_plan, _persona_block, _value_rule
        from .d01_production_operations_v1 import current_method_strategy_projection_v1
        prior = decode_typed_production_value_v1(strategy, MethodStrategyProjectionV1)
        if prior.plan_head.key.token != request.plan_ref or prior.goal_head.key.token != request.goal_ref:
            raise MissingProductionOriginalV1("same_actual_personal_d01_plan_goal_scope")
        atom = read.head(db, prior.persona_head.key, required=True)
        _validate_persona_plan(atom.value)
        persona = PersonaPlan(**{**atom.value, "namespace": NamespaceId(**atom.value["namespace"]),
            "blocks": tuple(_persona_block(row) for row in atom.value["blocks"]),
            "values": tuple(_value_rule(row) for row in atom.value["values"])})
        actual = current_method_strategy_projection_v1(db, read, persona_plan=persona,
            persona_head=GraphVersion(atom.key, atom.revision), plan_head=prior.plan_head,
            candidate_refs=tuple(sorted(candidate_refs)), condition_heads=prior.condition_heads,
            condition_query_epoch=prior.condition_query_epoch)
        if actual != prior:
            raise MissingProductionOriginalV1("current_personal_d01_d07_method_scope")
    return evaluation


def _need(db, read, readers, request, plan_atom, goal_atom, *, _phase_transition=None):
    if readers.need_qualification_reader is None:
        raise MissingProductionOriginalV1("installed_current_personal_need_reader")
    hook = readers.need_qualification_reader
    result = (hook(db=db, frame=read.frame, request=request, _phase_transition=_phase_transition)
        if _phase_transition is not None and type(hook) is InstalledCurrentPersonalNeedReaderV1
        else hook(db=db, frame=read.frame, request=request))
    if type(result) is not CurrentPersonalNeedQualificationV1:
        raise TypeError("installed Need reader must return its exact original-qualified result")
    if _phase_transition is not None:
        result = _phase_projection_evidence_v1(db, frame=read.frame, readers=readers, transition=_phase_transition,
            current=result, prior=_phase_transition.prepared_candidates.need)
    _current_evidence(db, read, (result.original,), result.read_versions, result.query_coverage)
    if (result.original.original_ref != request.need_qualification_original_ref
            or result.plan_head != GraphVersion(plan_atom.key, plan_atom.revision)
            or result.goal_head != GraphVersion(goal_atom.key, goal_atom.revision)
            or not result.query_coverage or not result.complete or result.new_c3_required or result.meaningful_gaps
            or read.frame.now_utc >= result.original_deadline_utc):
        raise MissingProductionOriginalV1("complete_current_personal_need_without_new_c3_or_gaps")
    return result


@dataclass(frozen=True, slots=True)
class PhaseTaskScopeFactsV1:
    original_ref: str
    original_digest: str
    original: "IngressArtifactTaskScopeOriginalV1"
    activity_id: str
    parent_budget_lease_ref: str
    valid_until_utc: str


def _read_phase_task_scope_facts_v1(db, read, readers, binding):
    from .d11_life_preparation_v1 import _read
    from .ingress_artifact_task_scope_v1 import require_task_scope_archive_v1, task_scope_ref_v1
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    from .foreground_cycle_v1 import _adopted_c02_v1, require_current_foreground_responsibility_v1
    from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1
    from .jobs import get_job
    from .d11_types import job_graph_write
    from .d11_offline_originals_v1 import _utc
    from datetime import datetime, timezone
    if type(binding) is not ArtifactPhaseCandidateBindingV3:
        raise TypeError("task scope facts consume only the explicit V3 phase binding")
    ns = read.frame.envelope.authority.namespace
    if binding.task.namespace != ns or binding.activity_scope_ref != task_scope_ref_v1(binding.task.root_registration_ref):
        raise ValueError("V3 phase changed the actual task scope locator")
    raw = _read(db, issuer=readers.issuer, namespace=ns, kind="artifact_task_scope", ref=binding.activity_scope_ref)
    root_row = _read(db, issuer=readers.issuer, namespace=ns, kind="draft_root_capability", ref=binding.task.root_registration_ref)
    if raw is None or root_row is None:
        raise MissingProductionOriginalV1("actual_signed_phase_task_scope_root")
    root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
    installed = readers.bundle.installation_policy
    producer = read_adopted_domain_operation_v1(db, ns, raw[1])
    if producer is None or root_row[1] != raw[1]:
        raise ValueError("phase task scope lost its exact adopted archive producer")
    original = require_task_scope_archive_v1(db, namespace=ns, root=root, producer=producer)
    if plain_v1(original) != raw[0]:
        raise ValueError("phase task scope changed its archived signed bytes")
    if (original.namespace, root.installation_id, root.manifest_digest) != (
            ns, installed.installation_id, installed.manifest_digest):
        raise ValueError("phase task scope changed current installed package or namespace")
    c1 = read_c1_task_intent_original_v1(db, namespace=ns, c02_operation_id=binding.task.c02_operation_id, issuer=readers.issuer)
    c02 = _adopted_c02_v1(db, ns, binding.task.c02_operation_id)
    if (c1 is None or original.c02_operation_id != c02.operation_id
            or (c1.source_ref, c1.source_revision, c1.source_digest) !=
               (original.source_ref, original.source_revision, original.source_digest)):
        raise ValueError("phase task facts changed actual paid C1 or adopted C02")
    read.original(binding.activity_scope_ref, kind="d11.life_artifact_task_scope", digest=canonical_digest(raw[0]))
    read.original(original.c1_intent_ref, kind="d11.life_c1_task_intent", digest=original.c1_intent_digest)
    read.original(root.registration_ref, kind="d11.life_draft_root_capability", digest=canonical_digest(root_row[0]))
    if original.objective_ref is not None:
        read.original(original.objective_ref, kind="d11.life_artifact_task_objective", digest=original.objective_digest)
    source = read.head(db, original.source_ref, required=True)
    read.source_family(db, (original.source_ref,), purpose="consolidation")
    if (source.revision, canonical_digest(source.value)) != (original.source_revision, original.source_digest):
        raise MissingProductionOriginalV1("current_unmodified_phase_task_source")
    job = get_job(db, AtomKey.from_token(binding.task.cycle_job_ref).name)
    cycle = read.head(db, binding.task.cycle_job_ref, required=True)
    if cycle.value != job_graph_write(job).value or job.budget_ref != read.frame.envelope.parent_budget_lease_ref:
        raise ValueError("phase task facts changed the actual current cycle or parent budget")
    responsibility = require_current_foreground_responsibility_v1(db, namespace=ns, job=job,
        installed_bundle=readers.bundle, issuer=readers.issuer, owner_guard=read.frame.owner_guard,
        purpose=read.frame.envelope.authority.purpose, audiences=read.frame.envelope.authority.audience,
        now_utc=read.frame.now_utc)
    if (responsibility is None or responsibility.root_registration_ref != root.registration_ref
            or responsibility.c02_receipt_digest != canonical_digest(c02)
            or responsibility.root_registration_digest != canonical_digest(root_row[0])
            or (responsibility.c02_operation_id, responsibility.source_ref) !=
               (binding.task.c02_operation_id, original.source_ref)):
        raise MissingProductionOriginalV1("actual_current_phase_task_responsibility")
    require_budget_family_admissible(db, job.budget_ref)
    grant = readers.issuer.current_budget_grant(db, job.budget_ref)
    limit = min(_utc(root.valid_until_utc).timestamp(), _utc(job.deadline_utc).timestamp(),
        responsibility.deadline_utc, grant.valid_until_utc)
    if read.frame.now_utc >= limit:
        raise MissingProductionOriginalV1("unexpired_original_phase_task_scope_budget")
    return PhaseTaskScopeFactsV1(binding.activity_scope_ref, canonical_digest(raw[0]), original,
        job.activity_id, job.budget_ref, datetime.fromtimestamp(limit, timezone.utc).isoformat().replace("+00:00", "Z"))


def _artifact_scope(db, read, readers, binding, plan):
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1, DraftRootCapabilityV1, draft_from_wire_v1
    if type(binding) is ArtifactPhaseCandidateBindingV3:
        scope = _read_phase_task_scope_facts_v1(db, read, readers, binding)
        root = scope.original.root
        activity_id, c02_ref = scope.activity_id, scope.original.c02_operation_id
        root_ref, root_digest = root.registration_ref, canonical_digest(plain_v1(root))
        source_ref, source_revision, source_digest = scope.original.source_ref, scope.original.source_revision, scope.original.source_digest
        scope_owner = (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest)
    else:
        scope_raw = _read(db, issuer=readers.issuer, namespace=read.frame.envelope.authority.namespace,
            kind="activity_scope", ref=binding.activity_scope_ref)
        root_raw = _read(db, issuer=readers.issuer, namespace=read.frame.envelope.authority.namespace,
            kind="draft_root_capability", ref=binding.task.root_registration_ref)
        if scope_raw is None or root_raw is None:
            raise MissingProductionOriginalV1("actual_existing_artifact_candidate_scope_root")
        scope = draft_from_wire_v1(scope_raw[0], DraftActivityScopeV1)
        root = draft_from_wire_v1(root_raw[0], DraftRootCapabilityV1)
        read.original(binding.activity_scope_ref, kind="d11.life_activity_scope", digest=canonical_digest(plain_v1(scope)))
        read.original(binding.task.root_registration_ref, kind="d11.life_draft_root_capability", digest=canonical_digest(plain_v1(root)))
        activity_id, c02_ref = scope.activity_id, scope.c02_original_ref
        root_ref, root_digest = scope.root_registration_ref, scope.root_registration_digest
        source_ref, source_revision, source_digest = scope.source.ref, scope.source.revision, scope.source.digest
        scope_owner = (scope.owner_grant_ref, scope.owner_grant_revision, scope.owner_grant_digest)
    guard = read.frame.owner_guard
    if (activity_id != AtomKey.from_token(binding.task.cycle_job_ref).owner.subject
            or c02_ref != binding.task.c02_operation_id
            or root_ref != root.registration_ref or root_digest != canonical_digest(plain_v1(root))
            or scope.parent_budget_lease_ref != read.frame.envelope.parent_budget_lease_ref
            or source_ref not in plan.source_refs or root.source_ref not in plan.source_refs
            or scope_owner != (guard.grant_ref, guard.grant_revision, guard.grant_digest)
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) != (guard.grant_ref, guard.grant_revision, guard.grant_digest)
            or binding.target.root_registration_ref != root.registration_ref
            or binding.target.root_registration_digest != canonical_digest(plain_v1(root))
            or binding.target.root_resource_id != root.resource_id or binding.target.root_identity != root.root_identity
            or binding.target.filename not in root.filenames or binding.target.max_bytes > root.max_bytes):
        raise ValueError("candidate changed its actual signed artifact scope")
    source = read.head(db, source_ref, required=True)
    if source.revision != source_revision or canonical_digest(source.value) != source_digest:
        raise MissingProductionOriginalV1("current_original_artifact_candidate_source")
    if binding.prev_phase_original_ref is not None:
        read.original(binding.prev_phase_original_ref, digest=binding.prev_phase_original_digest)
    if binding.prior_content is not None:
        prior = binding.prior_content
        read.original(prior.verified_original_ref, digest=prior.verified_original_digest)
        previous = read.head(db, prior.source_head.ref, required=True)
        from ..memory_types import SourceRecord
        import hashlib
        record = SourceRecord.from_dict(previous.value)
        if (previous.revision != prior.source_head.version or canonical_digest(previous.value) != prior.source_value_digest
                or hashlib.sha256(record.text.encode()).hexdigest() != prior.verified_readback.content_digest
                or len(record.text.encode()) != prior.verified_readback.content_length):
            raise MissingProductionOriginalV1("actual_verified_previous_phase_source")
        if binding.target.mode == "replace" and (binding.target.filename, binding.target.expected_prior_version,
                binding.target.expected_prior_digest, binding.target.expected_prior_identity, binding.target.expected_prior_effect_marker) != (
                prior.verified_readback.filename, prior.verified_readback.version, prior.verified_readback.content_digest,
                prior.verified_readback.file_identity, prior.verified_readback.effect_marker):
            raise ValueError("candidate replacement changed its actual verified predecessor")
    return scope, root


def prospective_personal_decision_key_v1(namespace, activity_id, selection_operation_id, plan_ref):
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id), DECISION_TYPE,
        "decision:" + canonical_digest((namespace, activity_id, selection_operation_id, plan_ref))[:48])


def prospective_personal_candidate_input_v1(db, read, *, request, binding, plan_atom, goal_atom, need, deadline, installed_readers=None):
    """Actual prospective material explicitly before any Decision adoption."""
    plan = decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value)
    roots = plan.source_refs
    if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3} and binding.prior_content is not None:
        roots = tuple(dict.fromkeys((*roots, binding.prior_content.source_head.ref)))
    records = read.source_family(db, roots, purpose="consolidation")
    shared_pair = None
    if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
        from .method_pair_shared_input_v1 import method_pair_read_inputs_v1, require_current_method_pair_shared_input_v1
        experiment_ref, _ = method_pair_read_inputs_v1(db,
            namespace=read.frame.envelope.authority.namespace, goal_ref=goal_atom.key.token)
        if experiment_ref is not None:
            if installed_readers is None:
                raise MissingProductionOriginalV1('actual_installed_method_pair_prospective_reader')
            shared = require_current_method_pair_shared_input_v1(db, read=read, experiment_ref=experiment_ref,
                goal_ref=goal_atom.key.token, issuer=installed_readers.issuer)
            if shared is None:
                raise MissingProductionOriginalV1('actual_prospective_method_pair_shared_input')
            shared_pair, family = shared
            records.update(family)
    payload = {"schema": "d08.prospective-personal-candidate-input.v1", "binding": plain_v1(binding),
        "plan_head": plain_v1(GraphVersion(plan_atom.key, plan_atom.revision)), "plan_digest": canonical_digest(plan_atom.value),
        "goal_head": plain_v1(GraphVersion(goal_atom.key, goal_atom.revision)), "actor_ref": plan.actor_ref,
        "selection_operation_id": request.selection_operation_id, "future_decision_ref": prospective_personal_decision_key_v1(
            read.frame.envelope.authority.namespace, read.frame.envelope.identity.activity_id, request.selection_operation_id, plan_atom.key.token).token,
        "decision_state": "not_adopted", "need_original_ref": need.original.original_ref,
        "need_original_digest": need.original.original_digest, "parent_budget_lease_ref": read.frame.envelope.parent_budget_lease_ref,
        "deadline_utc": deadline, "sources": [{"ref": ref, "revision": read.head(db, ref, required=True).revision,
            "value_digest": canonical_digest(record.to_dict()), "record": record.to_dict()} for ref, record in sorted(records.items())]}
    if shared_pair is not None:
        payload["method_pair_shared_input"] = plain_v1(shared_pair)
    if type(binding) is ArtifactPhaseCandidateBindingV3:
        from .artifact_phase_postconditions_v1 import require_current_artifact_phase_postcondition_policy_v1
        policy = require_current_artifact_phase_postcondition_policy_v1(db, frame=read.frame, binding=binding,
            goal_ref=goal_atom.key.token, plan_ref=plan_atom.key.token, installed_readers=installed_readers)
        if deadline > policy.original_deadline_utc:
            raise ValueError("prospective V3 input cannot extend its actual pre-decision policy deadline")
        payload["postcondition_policy"] = plain_v1(policy)
    encoded = canonical_serialize(payload)
    if len(encoded.encode()) > 65536:
        raise MissingProductionOriginalV1("bounded_actual_serialized_candidate_input")
    return encoded, canonical_digest(payload)


def prospective_personal_future_identity_v1(namespace, request, binding, plan_atom, deadline, parent_budget):
    activity = (AtomKey.from_token(binding.task.cycle_job_ref).owner.subject
        if type(binding) is ArtifactPhaseCandidateBindingV3 else plan_atom.key.owner.subject)
    if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
        # The prospective identity has no fake adopted Decision revision/digest.
        # This canonical identity tuple is the V2 phase selector's identity tuple.
        marker = canonical_digest({"schema": "d11.artifact-draft-phase-identity.v2", "task": binding.task,
            "plan_ref": plan_atom.key.token, "plan_revision": plan_atom.revision, "plan_digest": canonical_digest(plan_atom.value),
            "method_ref": binding.method_ref, "phase_index": binding.phase_index, "phase_kind": binding.phase_kind})[:40]
        return PersonalCandidateFutureIdentityV1("action:artifact-draft-v2:" + marker, activity,
            "artifact-draft-v2-action-operation:" + marker, "artifact-draft-v2-attempt:" + marker,
            "artifact-draft-v2-effect:" + marker, "artifact-draft-v2-execution-call:" + marker,
            "artifact-draft-v2-prepare:" + marker, "artifact-draft-v2-acquire:" + marker,
            "artifact-draft-v2-call:" + marker, deadline, parent_budget)
    from .d08_source_note_action_v1 import source_note_effect_id_v1, source_note_attempt_id_v1
    operation = "personal-source-note-action:" + canonical_digest((namespace, request.selection_operation_id, binding))[:48]
    marker = canonical_digest((namespace, binding.project_ref, operation))[:48]
    return PersonalCandidateFutureIdentityV1("action:source-note:" + marker, activity, operation,
        source_note_attempt_id_v1(namespace, binding.project_ref, operation),
        source_note_effect_id_v1(namespace, binding.project_ref, operation), None,
        None, None, None, deadline, parent_budget)


def actual_personal_phase_price_ceiling_v1(price, phase_kind):
    """Installed four-dimensional price; this computes bounds, not authority."""
    if type(price) is not CurrentPersonalCandidatePriceV1:
        raise TypeError("phase price requires actual installed prospective evidence")
    from ..model_broker.artifact_draft_v1 import PHASE_TOKEN_CEILINGS_V2
    limits = next(({"input_tokens": inp, "output_tokens": out} for kind, inp, out in PHASE_TOKEN_CEILINGS_V2
        if kind == phase_kind), None)
    if limits is None:
        raise ValueError("only registered generation phases have model prices")
    ceiling = dict(price.quote_ceiling)
    if set(ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}:
        raise MissingProductionOriginalV1("actual_four_dimension_model_token_and_money_price_proof")
    ceiling["input_tokens"] = min(ceiling["input_tokens"], limits["input_tokens"])
    ceiling["output_tokens"] = min(ceiling["output_tokens"], limits["output_tokens"])
    ceiling["model_tokens"] = min(ceiling["model_tokens"], ceiling["input_tokens"] + ceiling["output_tokens"])
    # Monetary ceiling is the actual installed evidence, including an explicitly
    # proven zero-price policy. Missing monetary evidence never becomes zero.
    if (not 1 <= price.input_token_count <= ceiling["input_tokens"] or ceiling["output_tokens"] < 1
            or price.input_token_count + ceiling["output_tokens"] > ceiling["model_tokens"]):
        raise MissingProductionOriginalV1("actual_serialized_phase_input_and_output_fit_total_token_price")
    return ceiling


def _assemble(db, *, frame, request, readers, preparation_operation_id=None, _phase_transition=None, _count_freeze=None, _count_replay_preparation=None):
    from .personal_candidate_eligibility_v1 import bind_actual_personal_candidate_request_v1
    with bind_actual_personal_candidate_request_v1(readers, request, frame):
        return _assemble_current_v1(db, frame=frame, request=request, readers=readers,
            preparation_operation_id=preparation_operation_id, _phase_transition=_phase_transition,
            _count_freeze=_count_freeze, _count_replay_preparation=_count_replay_preparation)

def _assemble_current_v1(db, *, frame, request, readers, preparation_operation_id=None, _phase_transition=None, _count_freeze=None, _count_replay_preparation=None):
    read = (CurrentDomainReadV1(frame) if _phase_transition is None else
        _PhasePersonalCandidateReadV1(frame, db=db, readers=readers, transition=_phase_transition))
    read.check(db)
    preparation_operation_id = preparation_operation_id or frame.envelope.identity.operation_id
    plan_atom, goal_atom, plan, goal, nodes = _plan_goal(db, read, request, installed_readers=readers)
    actual_activity=actual_personal_candidate_activity_v2(db,namespace=frame.envelope.authority.namespace,
        request=request,issuer=readers.issuer)
    if frame.envelope.identity.activity_id != actual_activity:
        raise ValueError("candidate preparation must use the actual qualified task activity")
    evaluation = read_current_personal_value_evaluation_v1(db, read, request, plan.candidate_refs, installed_readers=readers)
    if plan.method_candidates and "method_strategy" not in evaluation["payload"]["provenance"]:
        raise MissingProductionOriginalV1("current_actual_d01_method_strategy")
    need = _need(db, read, readers, request, plan_atom, goal_atom, _phase_transition=_phase_transition)
    require_budget_family_admissible(db, frame.envelope.parent_budget_lease_ref)
    grant = readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    lease = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    prior_candidates = {}
    if _phase_transition is not None:
        lease = _phase_budget_comparison_view_v1(db, frame=frame, readers=readers, transition=_phase_transition, lease=lease)
        prior_candidates = {c.binding.candidate_ref: c for c in _phase_transition.prepared_candidates.candidates}
    values = evaluation["payload"]["provenance"]["evaluation"]
    prepared, quotes = [], []
    for binding in sorted(request.bindings, key=lambda row: row.candidate_ref):
        node = nodes[binding.node_id]
        deadlines = [need.original_deadline_utc, grant.valid_until_utc]
        predicate_deadline=goal.satisfaction_predicate.valid_until
        if type(binding) in {ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}:
            from .artifact_task_continuation_authorization_v2 import resolve_artifact_task_predicate_deadline_v2
            predicate_deadline=resolve_artifact_task_predicate_deadline_v2(db,namespace=frame.envelope.authority.namespace,
                root_registration_ref=binding.task.root_registration_ref,goal_ref=request.goal_ref,
                original_predicate_deadline_utc=predicate_deadline,issuer=readers.issuer,bundle=readers.bundle,
                owner_guard=frame.owner_guard,now_utc=frame.now_utc,parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref)
        if predicate_deadline is not None:deadlines.append(predicate_deadline)
        if goal.deadline_ref is not None:
            observed_deadline = read.head(db, goal.deadline_ref, required=True).value.get("deadline_utc")
            if type(observed_deadline) is str:
                from .d11_offline_originals_v1 import _utc
                observed_deadline = _utc(observed_deadline).timestamp()
            import math
            if type(observed_deadline) not in {int, float} or not math.isfinite(observed_deadline):
                raise MissingProductionOriginalV1("actual_established_personal_goal_deadline")
            deadlines.append(observed_deadline)
        if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
            scope, root = _artifact_scope(db, read, readers, binding, plan)
            from .artifact_task_text_extent_v1 import require_current_artifact_task_text_extent_v1
            require_current_artifact_task_text_extent_v1(db, frame=frame, binding=binding,
                goal_ref=request.goal_ref, installed_readers=readers)
            if type(binding) is ArtifactPhaseCandidateBindingV3:
                from .artifact_phase_postconditions_v1 import require_current_artifact_phase_postcondition_policy_v1
                policy = require_current_artifact_phase_postcondition_policy_v1(db, frame=frame, binding=binding,
                    goal_ref=request.goal_ref, plan_ref=request.plan_ref, installed_readers=readers)
                deadlines.append(policy.original_deadline_utc)
            from .d11_offline_originals_v1 import _utc
            deadlines.extend((_utc(scope.valid_until_utc).timestamp(), _utc(root.valid_until_utc).timestamp()))
            cycle = read.head(db, binding.task.cycle_job_ref, required=True)
            deadlines.append(_utc(cycle.value["deadline_utc"]).timestamp())
        else:
            for ref in (binding.project_ref, binding.recipe_ref, binding.target_entity_ref, binding.role_binding_ref):
                read.head(db, ref, required=True); read.original(ref)
        deadline = min(deadlines)
        if deadline <= frame.now_utc:
            raise MissingProductionOriginalV1("existing_absolute_personal_candidate_deadline")
        if readers.candidate_eligibility_reader is None:
            raise MissingProductionOriginalV1("installed_actual_personal_candidate_eligibility_reader")
        eligibility = readers.candidate_eligibility_reader(db=db, frame=frame, binding=binding, plan=plan, goal=goal, need=need)
        if type(eligibility) is not CurrentPersonalCandidateEligibilityV1:
            raise TypeError("candidate eligibility reader requires its exact non-final evidence")
        if _phase_transition is not None:
            eligibility = _phase_projection_evidence_v1(db, frame=frame, readers=readers, transition=_phase_transition,
                current=eligibility, prior=prior_candidates[binding.candidate_ref].eligibility)
        _current_evidence(db, read, eligibility.originals, eligibility.read_versions, eligibility.query_coverage)
        if (eligibility.candidate_ref, eligibility.node_id, eligibility.parameter_digest) != (binding.candidate_ref, binding.node_id, binding.digest):
            raise ValueError("eligibility original differs from the actual planned parameters")
        status = eligibility.hard_status
        if type(binding) is ArtifactPhaseCandidateBindingV3 and binding.prior_content is not None:
            from ..host.authority_profile import AdminArtifactDraftToolScopeV1,AdminArtifactDraftToolScopeV2
            from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftToolScopeV3
            from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
            tool_scope=readers.bundle.artifact_draft.tool_scope
            if type(tool_scope) in {AdminArtifactDraftToolScopeV2,AdminArtifactDraftToolScopeV3}:cap=tool_scope.maximum_artifact_version
            elif type(tool_scope) is AdminArtifactDraftToolScopeV1:cap=1
            else:raise TypeError("candidate requires its actual installed artifact file scope")
            current_version=binding.prior_content.verified_readback.version
            required=current_version+sum(kind in {"tone_sample","full"}
                for kind in artifact_draft_phase_sequence_v2(binding.method_ref)[binding.phase_index:])
            if required>cap:
                status="REQUIRED_CHECK_UNRESOLVED"
        if node.pending_original_effects or eligibility.pending_original_effects:
            status = "WAIT_ORIGINAL_EFFECT"
        elif node.carried_forward_verified or binding.candidate_ref in values["rejected"]:
            status = "REJECTED"
        # The installed exact prospective recipe producer owns the numeric discriminator contract.
        encoded, prospective_digest = prospective_personal_candidate_input_v1(db, read, request=request,
            binding=binding, plan_atom=plan_atom, goal_atom=goal_atom, need=need, deadline=deadline, installed_readers=readers)
        future = prospective_personal_future_identity_v1(frame.envelope.authority.namespace, request, binding, plan_atom,
            deadline, frame.envelope.parent_budget_lease_ref)
        price, quote = None, None
        if (_count_freeze is not None and status == "eligible"
                and type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}):
            _count_freeze.append((binding, encoded, prospective_digest, future))
            continue
        if status == "eligible":
            if (_count_replay_preparation is not None
                    and type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}):
                from .d02_artifact_phase_price_v1 import read_adopted_personal_phase_count_price_v1
                price = read_adopted_personal_phase_count_price_v1(db, frame=frame, binding=binding,
                    prospective_input_json=encoded, prospective_input_digest=prospective_digest,
                    future_identity=future, adopted_preparation=_count_replay_preparation,
                    installed_readers=readers, phase_transition=_phase_transition)
            else:
                if readers.phase_price_reader is None:
                    raise MissingProductionOriginalV1("installed_actual_personal_candidate_price_reader")
                price = readers.phase_price_reader(db=db, frame=frame, binding=binding, plan=plan, goal=goal, need=need,
                    prospective_input_json=encoded, prospective_input_digest=prospective_digest, future_identity=future)
            if type(price) is not CurrentPersonalCandidatePriceV1:
                raise TypeError("price reader requires actual installed serialized-input evidence")
            if _phase_transition is not None and prior_candidates[binding.candidate_ref].price is not None:
                price = _phase_projection_evidence_v1(db, frame=frame, readers=readers, transition=_phase_transition,
                    current=price, prior=prior_candidates[binding.candidate_ref].price)
            _current_evidence(db, read, (price.original,), price.read_versions, price.query_coverage)
            if (price.candidate_ref, price.parameter_digest, price.serialized_input_digest) != (binding.candidate_ref, binding.digest, prospective_digest):
                raise ValueError("candidate price is not its actual prospective input")
            if price.installed_policy not in frame.installed_policy_refs:
                raise MissingProductionOriginalV1("current_installed_candidate_price_policy_proof")
            ceiling = dict(price.quote_ceiling)
            if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
                from ..model_broker.artifact_draft_v1 import TEMPLATE_VERSION_V2, WORK_KIND
                if price.work_kind != WORK_KIND or price.template_version != TEMPLATE_VERSION_V2:
                    raise MissingProductionOriginalV1("installed_v2_artifact_phase_pricing_policy")
                ceiling = actual_personal_phase_price_ceiling_v1(price, binding.phase_kind)
            elif price.work_kind != "d10.life.source_note.v1":
                raise ValueError("source-note cannot borrow artifact phase pricing")
            if price.work_kind not in grant.allowed_work_kinds:
                raise MissingProductionOriginalV1("actual_existing_candidate_budget_work_kind")
            if node.cost_ceiling and any(amount > dict(node.cost_ceiling).get(dim, -1) for dim, amount in ceiling.items()):
                status = "WAIT_BUDGET"
            if any(amount > grant.max_ceiling.get(dim, -1) or amount > lease.available(dim) for dim, amount in ceiling.items()):
                status = "WAIT_BUDGET"
            quote_ref = "personal-candidate-quote:" + canonical_digest((frame.envelope.authority.namespace,
                preparation_operation_id, binding.digest, prospective_digest))[:48]
            quote = ResourceQuote(quote_ref, 1, *frame.envelope.authority.namespace.as_tuple, future.activity_id,
                future.model_prepare_operation_id or future.action_operation_id, None if future.model_prepare_operation_id else future.effect_id,
                frame.envelope.parent_budget_lease_ref, price.work_kind, "personal-prospect:" + prospective_digest[:48],
                deadline, price.resource_ref, None, (), (), ceiling, None, deadline)
            quotes.append(quote)
        eligibility = replace(eligibility, hard_status=status)
        prepared.append(PreparedPersonalCandidateV1(binding, eligibility, price,
            quote.quote_id if quote else None, canonical_digest(quote) if quote else None,
            tuple(sorted(quote.ceiling.items())) if quote else (), prospective_digest, future))
    guard = frame.owner_guard
    if _count_freeze is not None:
        return tuple(_count_freeze)
    result = PreparedPersonalCandidateSetV1(frame.envelope.authority.namespace, plan.actor_ref,
        preparation_operation_id, request.selection_operation_id,
        prospective_personal_decision_key_v1(frame.envelope.authority.namespace, actual_activity,
            request.selection_operation_id, request.plan_ref).token,
        GraphVersion(plan_atom.key, plan_atom.revision), GraphVersion(goal_atom.key, goal_atom.revision), plan.source_refs,
        frame.snapshot.versions, frame.query_coverage, request.value_evaluation_operation_id, evaluation["original_digest"],
        need, tuple(prepared), frame.envelope.parent_budget_lease_ref, guard.grant_ref, guard.grant_revision, guard.grant_digest,
        frame.envelope.version_guard.access_epoch, frame.envelope.version_guard.delete_epoch)
    return result, tuple(quotes)


def stage_prepare_current_personal_candidates_in_transaction_v1(db, *, frame, request, installed_readers):
    readers = _readers(installed_readers)
    if type(request) is not PrepareCurrentPersonalCandidatesRequestV1:
        raise TypeError("exact current prospective preparation request required")
    try:
        from ..host.authority_profile import AdminArtifactStandingScopeV3
        if type(readers.bundle.artifact_draft.standing_scope) is AdminArtifactStandingScopeV3 and any(
                type(b) is ArtifactPhaseCandidateBindingV3 for b in request.bindings):
            from .artifact_phase_postconditions_v1 import (require_artifact_preparation_completion_v1,
                artifact_candidate_preparation_parent_ref_v1,ArtifactPreparationChildSelectorV1)
            tasks={b.task for b in request.bindings if type(b) is ArtifactPhaseCandidateBindingV3}
            if len(tasks)!=1 or any(type(b) is not ArtifactPhaseCandidateBindingV3 for b in request.bindings):
                raise ValueError("approved artifact preparation must retain one exact whole-method task")
            task=next(iter(tasks));plan_head=GraphVersion(AtomKey.from_token(request.plan_ref),request.expected_plan_revision)
            parent=require_artifact_preparation_completion_v1(db,frame=frame,
                request=ArtifactPreparationChildSelectorV1(artifact_candidate_preparation_parent_ref_v1(task,plan_head),"evaluate"),
                installed_readers=readers)
            if (parent.plan_head!=plan_head or parent.goal_head!=GraphVersion(AtomKey.from_token(request.goal_ref),request.expected_goal_revision)
                    or parent.candidates_digest!=canonical_digest(plain_v1(request.bindings))):
                raise ValueError("final preparation changed the actual completed parent candidates/Goal/Plan")
        prepared, quotes = _assemble(db, frame=frame, request=request, readers=readers)
        from .d05_relationship_revision_v2 import read_current_relationship_preferences_v2
        relationship = read_current_relationship_preferences_v2(db, frame=frame, prepared=prepared, issuer=readers.issuer)
        provenance = {"prepared_candidates": prepared, "relationship_preference": relationship}
        from .d02_artifact_phase_price_v1 import InstalledArtifactPhasePriceReaderV1
        if type(readers.phase_price_reader) is InstalledArtifactPhasePriceReaderV1:
            provenance["artifact_phase_counts"] = tuple(readers.phase_price_reader.count_provenance_for_candidate_v1(
                binding=candidate.binding, prospective_input_digest=candidate.prospective_input_digest)
                for candidate in prepared.candidates if candidate.price is not None
                and type(candidate.binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3})
        stage = stage_result_v1(frame, "d08", PREPARE_OPERATION_V1, request,
            provenance=provenance)
        # All scope/price facts precede signing. No reserve or job is created.
        for quote in quotes:
            readers.resource_issuer.issue_quote(db, quote)
        return stage
    except MissingProductionOriginalV1 as missing:
        return waiting_personal_candidate_stage_v1(frame, PREPARE_OPERATION_V1, request, missing)


def require_current_personal_candidates_v1(db, *, frame, preparation_operation_id, installed_readers,
        for_selected_decision=False):
    return _require_current_personal_candidates_v1(db, frame=frame, preparation_operation_id=preparation_operation_id,
        installed_readers=installed_readers, for_selected_decision=for_selected_decision, _phase_transition=None)


def _require_current_personal_candidates_v1(db, *, frame, preparation_operation_id, installed_readers,
        for_selected_decision, _phase_transition):
    readers = _readers(installed_readers)
    read = (CurrentDomainReadV1(frame) if _phase_transition is None else
        _PhasePersonalCandidateReadV1(frame, db=db, readers=readers, transition=_phase_transition))
    read.check(db)
    original = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, preparation_operation_id)
    if original is None or (original["domain"], original["operation_kind"]) != ("d08", PREPARE_OPERATION_V1):
        raise MissingProductionOriginalV1("actual_adopted_personal_candidate_preparation")
    read.original("d08-current:" + original["original_digest"][:48],
        kind="d08.current-" + PREPARE_OPERATION_V1, digest=original["original_digest"])
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    prepared = decode_typed_production_value_v1(original["payload"]["provenance"]["prepared_candidates"], PreparedPersonalCandidateSetV1)
    request = decode_typed_production_value_v1(original["payload"]["request"], PrepareCurrentPersonalCandidatesRequestV1)
    guard = frame.owner_guard
    if (prepared.namespace != frame.envelope.authority.namespace or prepared.parent_budget_lease_ref != frame.envelope.parent_budget_lease_ref
            or (prepared.owner_grant_ref, prepared.owner_grant_revision, prepared.owner_grant_digest) != (guard.grant_ref, guard.grant_revision, guard.grant_digest)
            or (prepared.access_epoch, prepared.delete_epoch) != (frame.envelope.version_guard.access_epoch, frame.envelope.version_guard.delete_epoch)):
        raise MissingProductionOriginalV1("current_prepared_candidate_owner_source_generations")
    from .personal_candidate_eligibility_v1 import require_actual_owner_candidate_carrier_v1
    owner_carrier = require_actual_owner_candidate_carrier_v1(db, frame=frame, request=request, prepared=prepared, readers=readers)
    for version in prepared.read_versions:
        if owner_carrier is not None and version.key == owner_carrier[0]:
            continue  # The exact complete same-task W01 progress was authenticated above.
        if for_selected_decision and version.key.token == prepared.future_decision_ref and version.revision == 0:
            decision = read.head(db, version.key, required=True)
            history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?", (decision.key.token, decision.revision)).fetchone()
            if history != (prepared.selection_operation_id,):
                raise MissingProductionOriginalV1("actual_expected_personal_decision_adoption")
            continue
        if read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_prepared_candidate_heads")
    # Rebuild current Need, full D01/D07 scope, parameters, policy and price.
    # This is a read; it signs no new quote and acquires no execution identity.
    current, quotes = _assemble(db, frame=frame, request=request, readers=readers,
        preparation_operation_id=prepared.preparation_operation_id, _phase_transition=_phase_transition,
        _count_replay_preparation=prepared)
    if owner_carrier is not None:
        from .personal_candidate_eligibility_v1 import normalize_actual_owner_candidate_set_v1
        current = normalize_actual_owner_candidate_set_v1(current,prepared,owner_carrier)
    comparable = replace(current, read_versions=prepared.read_versions, query_coverage=prepared.query_coverage)
    if comparable != prepared:
        raise MissingProductionOriginalV1("current_exact_personal_candidate_preparation")
    by_ref = {quote.quote_id: quote for quote in quotes}
    for candidate in prepared.candidates:
        if candidate.quote_ref is None:
            continue
        actual = readers.resource_issuer._load_quote(db, candidate.quote_ref, 1)
        if actual != by_ref[candidate.quote_ref] or canonical_digest(actual) != candidate.quote_digest or frame.now_utc >= actual.valid_until_utc:
            raise MissingProductionOriginalV1("current_actual_signed_prospective_candidate_quote")
    from .d05_relationship_revision_v2 import read_current_relationship_preferences_v2
    from ..domains.d05.relationship_revision_v2 import RelationshipPreferenceProjectionV2
    relationship = read_current_relationship_preferences_v2(db, frame=frame, prepared=prepared, issuer=readers.issuer)
    retained = original["payload"]["provenance"].get("relationship_preference")
    if retained is None:
        if relationship.inputs:
            raise MissingProductionOriginalV1("actual_frozen_relationship_candidate_preparation")
    elif decode_typed_production_value_v1(retained, RelationshipPreferenceProjectionV2) != relationship:
        raise MissingProductionOriginalV1("current_frozen_relationship_candidate_projection")
    return prepared, original


def record_personal_candidates_after_cas_v1(db, *, frame, stage, receipt, issuer):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    if type(issuer) is not D11BudgetJobIssuer or receipt.status != "committed" or receipt.operation_id != stage.operation_id:
        raise ValueError("candidate original requires its actual same-transaction committed receipt")
    adopted = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, stage.operation_id)
    if adopted is None or adopted["original_digest"] != stage.original_digest or adopted["payload"]["provenance"] != json.loads(stage.original_payload_json)["provenance"]:
        raise ValueError("candidate preparation original was not adopted by its actual W01 event")
    return ProductionOriginalRefV1("d08.current-" + PREPARE_OPERATION_V1,
        "d08-current:" + stage.original_digest[:48], stage.original_digest, stage.read_versions)


def read_selected_personal_adapter_v1(db, *, frame, request, installed_readers):
    readers=_readers(installed_readers)
    selector=_selected_candidate_phase_selector_v2(db,frame=frame,request=request,readers=readers)
    if selector is not None:
        from .d10_project_checkpoint_v1 import artifact_task_checkpoint_activation_operation_id_v2
        original=read_adopted_domain_operation_v1(db,selector.task.namespace,
            artifact_task_checkpoint_activation_operation_id_v2(selector))
        if original is not None:
            with _phase_preparation_transition_v1(db,frame=frame,request=request,phase_selector=selector,
                    installed_readers=readers) as transition:
                return _read_selected_after_phase_transition(db,frame=frame,request=request,
                    installed_readers=readers,transition=transition)
    return _read_selected_personal_adapter_v1(db, frame=frame, request=request,
        installed_readers=installed_readers, _phase_transition=None)


def _read_selected_after_phase_transition(db, *, frame, request, installed_readers, transition):
    readers = _readers(installed_readers)
    t = _require_phase_transition_v1(db, frame=frame, readers=readers, transition=transition)
    if t.request != request:
        raise ValueError("private phase reader cannot redirect the actual selected candidate")
    return _read_selected_personal_adapter_v1(db, frame=frame, request=request,
        installed_readers=readers, _phase_transition=t)


def _read_selected_personal_adapter_v1(db, *, frame, request, installed_readers, _phase_transition):
    if type(request) is not ConsumePersonalDecisionRequestV1:
        raise TypeError("adapter consumes only a registered Decision/preparation locator")
    prepared, original = _require_current_personal_candidates_v1(db, frame=frame,
        preparation_operation_id=request.prepared_candidates_operation_id, installed_readers=installed_readers,
        for_selected_decision=True, _phase_transition=_phase_transition)
    read = CurrentDomainReadV1(frame)
    decision = read.head(db, request.decision_ref, required=True)
    record = decode_personal_plan_type_v1(DECISION_TYPE, decision.value)
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (decision.key.token, decision.revision)).fetchone()
    if (history is None or history[2] != 1 or json.loads(history[1]) != decision.value or request.decision_ref != prepared.future_decision_ref
            or history[0] != prepared.selection_operation_id):
        raise MissingProductionOriginalV1("actual_same_personal_decision_adoption")
    read.committed_operation(db, history[0])
    if record.chosen_action_ref is None:
        raise MissingProductionOriginalV1("actual_chosen_personal_candidate")
    matches = tuple(row for row in prepared.candidates if row.future_identity.action_ref == record.chosen_action_ref)
    if len(matches) != 1 or matches[0].eligibility.hard_status != "eligible":
        raise ValueError("Decision cannot redirect different or ineligible parameters")
    return prepared, matches[0], original


def personal_candidate_evidence_read_plan_v3(*, read_versions, query_coverage,
        future_decision_ref, preparation_original_digest, evidences):
    """Compose existing evidence locators; no graph/body read or permission is issued.

    Both the real Body recipe and the private whole-EOF metadata preplan use this
    exact all-candidate expansion. A selected candidate alone is insufficient.
    """
    keys = [version.key for version in read_versions]
    keys.append(AtomKey.from_token(future_decision_ref))
    types = [page.type_id for page in query_coverage]
    originals = ["d08-current:" + preparation_original_digest[:48]]
    roots = []
    for original, versions, coverage in evidences:
        originals.append(original.original_ref)
        keys.extend(version.key for version in (*versions, *original.read_versions))
        types.extend(page.type_id for page in coverage)
        roots.extend(version.key.token for version in (*versions, *original.read_versions)
            if version.key.type_name == "memory.source")
    return production_read_plan_v1(types, keys, roots, originals)


def read_plan_personal_candidates_v1(db, *, namespace, activity_id, request, operation_id=None, installed_readers=None, include_eligibility=True):
    types = ["d01.persona_activation.v1", "d01.persona_plan.v1", "d07.current_interpretation.v1"]
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    from .d01_method_learning_v1 import method_trial_read_inputs_v1
    trial_types, trial_keys, trial_roots, trial_originals = method_trial_read_inputs_v1(db, namespace)
    types.extend(trial_types); keys.extend(trial_keys); roots.extend(trial_roots); originals.extend(trial_originals)
    if type(request) is PrepareCurrentPersonalCandidatesRequestV1:
        prepare = request
    elif type(request) in {SelectCurrentPersonalStepRequestV2, ConsumePersonalDecisionRequestV1}:
        original = read_adopted_domain_operation_v1(db, namespace, request.prepared_candidates_operation_id)
        if original is None:
            return production_read_plan_v1(types, keys)
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        prepare = decode_typed_production_value_v1(original["payload"]["request"], PrepareCurrentPersonalCandidatesRequestV1)
        prepared = decode_typed_production_value_v1(original["payload"]["provenance"]["prepared_candidates"], PreparedPersonalCandidateSetV1)
        from .current_method_learning_read_v3 import register_adopted_personal_candidate_preferences_v3
        register_adopted_personal_candidate_preferences_v3(db, namespace=namespace,
            operation_id=request.prepared_candidates_operation_id, original=original,
            decoded_request=prepare, prepared_set=prepared)
        preparation_original_digest = original["original_digest"]
        evidences = [(prepared.need.original, prepared.need.read_versions, prepared.need.query_coverage)]
        for candidate in prepared.candidates:
            for evidence in candidate.eligibility.originals:
                evidences.append((evidence, candidate.eligibility.read_versions, candidate.eligibility.query_coverage))
            if candidate.price is not None:
                evidences.append((candidate.price.original, candidate.price.read_versions, candidate.price.query_coverage))
        evidence_plan = personal_candidate_evidence_read_plan_v3(read_versions=prepared.read_versions,
            query_coverage=prepared.query_coverage, future_decision_ref=prepared.future_decision_ref,
            preparation_original_digest=preparation_original_digest, evidences=evidences)
        types.extend(evidence_plan.fixed_type_ids); keys.extend(evidence_plan.exact_keys)
        roots.extend(evidence_plan.source_roots); originals.extend(evidence_plan.required_original_refs)
    else:
        raise TypeError("unregistered personal candidate read recipe")
    keys.extend(AtomKey.from_token(ref) for ref in (prepare.plan_ref, prepare.goal_ref))
    from .owner_source_note_need_v1 import read_owner_source_note_need_original_v2, read_plan_owner_source_note_need_v1, install_owner_source_note_need_readers_v1, PrepareOwnerSourceNoteNeedRequestV1
    owner_need = read_owner_source_note_need_original_v2(db,namespace=namespace,original_ref=prepare.need_qualification_original_ref)
    if owner_need is not None:
        if installed_readers is None:
            raise MissingProductionOriginalV1("actual_installed_Owner_task_candidate_read_plan")
        value, actual = owner_need
        need_request = decode_typed_production_value_v1(actual['payload']['request'],PrepareOwnerSourceNoteNeedRequestV1)
        need_plan = read_plan_owner_source_note_need_v1(db,namespace=namespace,request=need_request,
            installed_readers=install_owner_source_note_need_readers_v1(installed_readers.graph))
        types.extend(need_plan.fixed_type_ids); keys.extend(need_plan.exact_keys)
        roots.extend(need_plan.source_roots); originals.extend((*need_plan.required_original_refs,prepare.need_qualification_original_ref))
    if any(type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3} for binding in prepare.bindings):
        from .method_pair_shared_input_v1 import method_pair_read_inputs_v1
        _, pair_plan = method_pair_read_inputs_v1(db, namespace=namespace, goal_ref=prepare.goal_ref)
        types.extend(pair_plan.fixed_type_ids); keys.extend(pair_plan.exact_keys)
        roots.extend(pair_plan.source_roots); originals.extend(pair_plan.required_original_refs)
    goal = raw_head_value_v1(db, namespace, AtomKey.from_token(prepare.goal_ref))
    if goal is not None and goal["deadline_ref"] is not None:
        keys.append(AtomKey.from_token(goal["deadline_ref"]))
    plan = raw_head_value_v1(db, namespace, AtomKey.from_token(prepare.plan_ref))
    if plan:
        roots.extend(plan["source_refs"])
        keys.extend(AtomKey.from_token(row["ref"]) for row in plan["fact_versions"])
    from .d05_relationship_revision_v2 import relationship_preferences_read_plan_v2
    relation_plan = relationship_preferences_read_plan_v2(db, namespace=namespace, bindings=prepare.bindings)
    types.extend(relation_plan.fixed_type_ids); keys.extend(relation_plan.exact_keys)
    roots.extend(relation_plan.source_roots); originals.extend(relation_plan.required_original_refs)
    keys.append(prospective_personal_decision_key_v1(namespace, activity_id, prepare.selection_operation_id, prepare.plan_ref))
    originals.append(prepare.need_qualification_original_ref)
    actual_need = _personal_ingress_need_locator_v1(db, namespace, prepare)
    if actual_need is not None:
        from .jobs import get_job
        from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
        from .source_note_foreground_v1 import ForegroundSourceNoteContinuationV1
        current_cycle = get_job(db, AtomKey.from_token(actual_need[0].cycle_job_ref).name)
        current_continuation = foreground_cycle_from_wire_v1(current_cycle.continuation)
        if type(current_continuation) is ForegroundSourceNoteContinuationV1:
            from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1
            saved_authorization = read_source_note_task_authorization_v1(db, namespace=namespace,
                original_ref=current_continuation.authorization_original_ref, issuer=_readers(installed_readers).issuer)
            if saved_authorization is None:
                raise MissingProductionOriginalV1("actual_signed_SourceNote_candidate_authorization_read_plan")
            authorization = saved_authorization[0]
            keys.extend(version.key for name, version, digest in authorization.heads)
            roots.extend(authorization.source_refs)
            originals.extend((authorization.original_ref, authorization.authorization_operation_id, current_cycle.operation_id))
    evaluation = read_adopted_domain_operation_v1(db, namespace, prepare.value_evaluation_operation_id)
    if evaluation is not None:
        keys.extend(version.key for version in evaluation["read_versions"])
    for binding in prepare.bindings:
        if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
            keys.append(AtomKey.from_token(binding.task.cycle_job_ref))
            originals.extend((binding.activity_scope_ref, binding.task.root_registration_ref))
            if type(binding) in {ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
                originals.append(binding.extent_original_ref)
            if type(binding) is ArtifactPhaseCandidateBindingV3:
                originals.append(binding.postcondition_policy_ref)
            if binding.prev_phase_original_ref is not None:
                originals.append(binding.prev_phase_original_ref)
            if binding.prior_content is not None:
                keys.append(AtomKey.from_token(binding.prior_content.source_head.ref))
                roots.append(binding.prior_content.source_head.ref)
                originals.append(binding.prior_content.verified_original_ref)
        else:
            keys.extend(AtomKey.from_token(ref) for ref in (binding.project_ref, binding.recipe_ref, binding.source_ref,
                binding.goal_ref, binding.target_entity_ref, binding.role_binding_ref))
            roots.append(binding.source_ref)
            originals.extend((binding.project_ref, binding.recipe_ref, binding.target_entity_ref, binding.role_binding_ref))
    extra_keys, extra_roots, extra_originals = method_condition_read_inputs_v1(db, namespace, (AtomKey.from_token(prepare.goal_ref),))
    keys.extend(extra_keys); roots.extend(extra_roots); originals.extend(extra_originals)
    if installed_readers is not None:
        readers = _readers(installed_readers)
        from .ingress_artifact_task_scope_v1 import (task_scope_ref_v1, require_task_scope_archive_v1)
        from .d11_life_preparation_v1 import _read
        from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
        for binding in prepare.bindings:
            if type(binding) is not ArtifactPhaseCandidateBindingV3:
                continue
            if binding.activity_scope_ref != task_scope_ref_v1(binding.task.root_registration_ref):
                raise ValueError("V3 candidate read plan changed actual task scope locator")
            raw = _read(db, issuer=readers.issuer, namespace=namespace, kind="artifact_task_scope", ref=binding.activity_scope_ref)
            root = _read(db, issuer=readers.issuer, namespace=namespace, kind="draft_root_capability", ref=binding.task.root_registration_ref)
            if raw is None or root is None:
                continue
            producer = read_adopted_domain_operation_v1(db, namespace, raw[1])
            if producer is None or root[1] != raw[1]:
                raise ValueError("phase task scope read plan lost its actual same producer")
            scope = require_task_scope_archive_v1(db, namespace=namespace,
                root=draft_from_wire_v1(root[0], DraftRootCapabilityV1), producer=producer)
            keys.append(AtomKey.from_token(scope.source_ref)); roots.append(scope.source_ref)
            keys.extend(v.key for v in producer["read_versions"])
            originals.extend((scope.c1_intent_ref, producer["receipt"].operation_id))
            if scope.objective_ref is not None:
                originals.append(scope.objective_ref)
            from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3
            if type(scope) in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3}:
                originals.append(scope.approval_original_ref)
            if type(scope) is IngressArtifactTaskScopeOriginalV3:originals.append(scope.continuation_authorization.original_ref)
            if scope.task_kind=="continue" and type(request) is ConsumePersonalDecisionRequestV1:
                selector=_selected_candidate_phase_selector_from_originals_v2(db,namespace=namespace,request=request,issuer=readers.issuer)
                if selector is not None:
                    from .d10_project_checkpoint_v1 import artifact_task_checkpoint_activation_operation_id_v2
                    activated=read_adopted_domain_operation_v1(db,namespace,artifact_task_checkpoint_activation_operation_id_v2(selector))
                    if activated is not None:
                        originals.append("d10-current:"+activated["original_digest"][:48])
                        keys.extend(v.key for v in activated["read_versions"])
                        keys.extend(v.key for v in activated["receipt"].write_versions)
        from ..host.authority_profile import AdminArtifactStandingScopeV3
        if type(readers.bundle.artifact_draft.standing_scope) is AdminArtifactStandingScopeV3:
            from .artifact_phase_postconditions_v1 import artifact_candidate_preparation_parent_ref_v1,PREPARATION_PARENT_KIND_V1
            tasks={b.task for b in prepare.bindings if type(b) is ArtifactPhaseCandidateBindingV3}
            if len(tasks)==1:
                parent_ref=artifact_candidate_preparation_parent_ref_v1(next(iter(tasks)),
                    GraphVersion(AtomKey.from_token(prepare.plan_ref),prepare.expected_plan_revision))
                parent_row=_read(db,issuer=readers.issuer,namespace=namespace,kind=PREPARATION_PARENT_KIND_V1,ref=parent_ref)
                if parent_row is not None:originals.append(parent_ref)
        from .artifact_task_text_extent_v1 import read_plan_personal_candidate_text_extents_v1
        extent_reads = read_plan_personal_candidate_text_extents_v1(db, namespace=namespace,
            request=prepare, installed_readers=readers)
        types.extend(extent_reads.fixed_type_ids); keys.extend(extent_reads.exact_keys)
        roots.extend(extent_reads.source_roots); originals.extend(extent_reads.required_original_refs)
    if installed_readers is not None:
        readers = _readers(installed_readers)
        # Root's exact installed original readers expand their own known typed
        # proof scopes, never a callback selected by public request payload.
        from .domain_production_contracts_v1 import ProductionReadPlanV1
        for hook in (readers.need_qualification_reader, readers.candidate_eligibility_reader if include_eligibility else None, readers.phase_price_reader):
            expand = getattr(hook, "read_plan_inputs_v1", None)
            if expand is None:
                continue
            extra = expand(db=db, namespace=namespace, activity_id=activity_id, request=prepare)
            if type(extra) is not ProductionReadPlanV1:
                raise TypeError("installed proof reader must expand an exact production read plan")
            types.extend(extra.fixed_type_ids); keys.extend(extra.exact_keys)
            roots.extend(extra.source_roots); originals.extend(extra.required_original_refs)
    return production_read_plan_v1(types, keys, roots, originals)


def freeze_current_personal_phase_count_materials_in_transaction_v1(db, *, frame, request, installed_readers):
    """W01-only read stage: actual eligible candidate input; no price/quote/job."""
    readers = _readers(installed_readers)
    if type(request) is not PrepareCurrentPersonalCandidatesRequestV1:
        raise TypeError("phase count freeze requires the exact personal preparation request")
    return _assemble(db, frame=frame, request=request, readers=readers, _count_freeze=[])

@contextmanager
def _completed_phase_action_transition_v1(db, *, frame, request, phase_selector, installed_readers, model_readers):
    readers = _readers(installed_readers)
    t = _reconstruct_completed_phase_action_transition_v1(db, frame=frame, request=request,
        phase_selector=phase_selector, readers=readers, model_readers=model_readers)
    _ACTIVE_PHASE_TRANSITIONS[id(t)] = (t, _phase_transition_digest_v1(t))
    try:
        yield t
    finally:
        _ACTIVE_PHASE_TRANSITIONS.pop(id(t), None)


def _completed_phase_original_v1(db, read, operation_id, domain, kind):
    original = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, operation_id)
    if original is None or (original["domain"], original["operation_kind"]) != (domain, kind):
        raise MissingProductionOriginalV1("actual_completed_phase_producer:" + kind)
    read.original(domain + "-current:" + original["original_digest"][:48],
        kind=domain + ".current-" + kind, digest=original["original_digest"])
    return original


def _completed_phase_lineage_v1(db, *, namespace, selector, issuer, adoption):
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v2
    from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1, DraftRootCapabilityV1, draft_from_wire_v1
    from .c09_life_originals_v1 import _validate_c4_phase_original_joins_v2
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    from .artifact_task_text_extent_v1 import ArtifactTaskTextExtentOriginalV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    ids = artifact_draft_model_ids_v2(selector)
    wanted = [("c4_phase_" + part, ids[name]) for part, name in
        (("prepared", "job"), ("frozen", "frozen"), ("request", "request"), ("call", "call"),
         ("paid", "paid"), ("result", "result"), ("adopted", "adopt"))]
    wanted.extend((("activity_scope", adoption.activity_scope_ref),
        ("draft_root_capability", selector.task.root_registration_ref),
        ("artifact_task_text_extent", adoption.extent_original_ref)))
    if selector.prev_phase_original_ref is not None:
        wanted.append(("c4_phase_verified", selector.prev_phase_original_ref))
    originals = {}
    for kind, ref in wanted:
        row = _read(db, issuer=issuer, namespace=namespace, kind=kind, ref=ref)
        if row is None:
            raise MissingProductionOriginalV1("actual_completed_phase_signed_lineage:" + kind)
        if kind.startswith("c4_phase_"):
            value = decode_artifact_draft_original_v2(kind, row[0])
        elif kind == "artifact_task_text_extent":
            value = decode_typed_production_value_v1(row[0], ArtifactTaskTextExtentOriginalV1)
        else:
            value = draft_from_wire_v1(row[0], DraftActivityScopeV1 if kind == "activity_scope" else DraftRootCapabilityV1)
        originals[(namespace, kind, ref)] = (row[1], value, row[0], canonical_digest(row[0]))
    _validate_c4_phase_original_joins_v2(db, originals)
    return originals


def _completed_cycle_chain_v1(db, read, *, before, before_version, current, selector, prepared_digest):
    from .foreground_cycle_v1 import decode_foreground_job_v1, artifact_draft_phase_wake_operation_id_v2
    from .d11_types import job_graph_write
    from .jobs import _job_from_dict
    cursor, job, origins = before_version, before, []
    rows = db.execute("SELECT revision,event_id FROM graph_history WHERE token=? AND revision>? AND revision<=? ORDER BY revision",
        (before_version.key.token, before_version.revision, current.revision)).fetchall()
    for revision, op in rows:
        original = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, op)
        if original is None or original["domain"] != "d11" or original["operation_kind"] not in {
                "wake_artifact_draft_cycle_v2", "acquire_foreground_cycle"}:
            raise MissingProductionOriginalV1("actual_completed_cycle_known_causal_successor")
        original = _phase_original_v1(db, read, op, original["operation_kind"])
        p = original["payload"]["provenance"]
        prior = decode_foreground_job_v1(p["before_job"], namespace=read.frame.envelope.authority.namespace)
        after = decode_foreground_job_v1(p["after_job"], namespace=read.frame.envelope.authority.namespace)
        v0, v1 = _phase_cas_versions_v1(original, before_version.key)
        if v0 != cursor or v1.revision != revision or prior != job:
            raise MissingProductionOriginalV1("actual_unbroken_completed_cycle_cas_chain")
        if original["operation_kind"] == "wake_artifact_draft_cycle_v2":
            from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
            ids = artifact_draft_model_ids_v2(selector)
            if (op != artifact_draft_phase_wake_operation_id_v2(selector)
                    or original["payload"]["request"]["selector"] != plain_v1(selector)
                    or p["prepared_digest"] != prepared_digest or p["paid_ref"] != ids["paid"] or p["result_ref"] != ids["result"]
                    or prior.phase != "waiting" or after != replace(prior, phase="queued", wake_condition=None)):
                raise ValueError("completed cycle wake changed its actual phase/call cause")
        else:
            req = original["payload"]["request"]
            if (prior.phase != "queued" or req["job_ref"] != before_version.key.token
                    or after != replace(prior, phase="running", fence=prior.fence + 1,
                        lease_holder=req["holder"], lease_expires_utc=after.lease_expires_utc)
                    or req["holder"] != read.frame.envelope.authority.actor):
                raise ValueError("completed cycle acquisition changed the actual self/once transition")
        if original["payload"]["writes"] != plain_v1((job_graph_write(after),)):
            raise ValueError("completed cycle producer wrote unrelated members")
        _phase_history_atom_v1(db, read, version=v1, expected_value=job_graph_write(after).value, producer_operation_id=op)
        ledger = db.execute("SELECT job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? AND operation_id=? "
            "AND job_id=?", (*read.frame.envelope.authority.namespace.as_tuple, op, after.job_id)).fetchall()
        if len(ledger) != 1 or _job_from_dict(json.loads(ledger[0][0])) != after:
            raise MissingProductionOriginalV1("actual_completed_cycle_sql_once_operation")
        cursor, job = v1, after
        origins.append((op, original["original_digest"]))
    if cursor.revision != current.revision or job_graph_write(job).value != current.value:
        raise MissingProductionOriginalV1("actual_completed_cycle_has_no_unproven_current_head")
    return job, tuple(origins)



def _completed_phase_own_action_body_v1(db, read, *, selector, adoption, issuer):
    from .d08_personal_plan_v1 import PHASE_ACTION_OPERATION_V2, artifact_phase_action_keys_v2
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
    from ..domains.d08.execution import _decode, ActionSchemaRecord, ActionSchema
    from .d11_life_preparation_v1 import _read
    from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1, _refs
    from ..graph_types import GraphAtom
    ns = selector.task.namespace
    ids = artifact_draft_file_ids_v2(selector)
    action_key, cancel_key = artifact_phase_action_keys_v2(selector)
    action_atom = read.head(db, action_key)
    projections, origins = [], []
    if not action_atom.revision:
        body = _read(db, issuer=issuer, namespace=ns, kind="life_body_preparation", ref="life-body:d02-life-body:" + ids["action_operation"])
        if body is not None:
            raise ValueError("phase Body cannot precede its actual Action A")
        return (), ()
    action = _decode("d08.action_intent.v1", action_atom.value)
    origin = _completed_phase_original_v1(db, read, ids["action_operation"], "d08", PHASE_ACTION_OPERATION_V2)
    if (origin["payload"]["request"] != {"selector": plain_v1(selector)}
            or origin["payload"]["provenance"]["artifact_phase_content_adoption"] != plain_v1(adoption)
            or origin["payload"]["provenance"]["final_admission"] is not False
            or action.identity.operation_id != ids["action_operation"] or action.identity.effect_id != ids["effect"]):
        raise ValueError("phase Action A changed the same Decision/content/file scope")
    schema = ActionSchemaRecord.bind(action, ActionSchema(action.schema_id, action.action_kind, False, action.required_checks))
    schema_key = AtomKey(action_key.owner, "d08.action_schema.v1", schema.schema_ref)
    expected_keys = {action_key, schema_key, cancel_key}
    if {v.key for v in origin["receipt"].write_versions} != expected_keys:
        raise ValueError("phase Action A contains foreign receipt members")
    for key in sorted(expected_keys, key=lambda k:k.token):
        before, after = _phase_cas_versions_v1(origin, key)
        current = read.head(db, key, required=True)
        if before.revision != 0 or current.revision != after.revision:
            raise MissingProductionOriginalV1("phase Action A exact original members without later change")
        _phase_history_atom_v1(db, read, version=after, expected_value=current.value, producer_operation_id=ids["action_operation"])
        projections.append((GraphAtom(key, 0, {}, False), after, canonical_digest(current.value)))
    origins.append((origin["receipt"].operation_id, origin["original_digest"]))
    body_operation = "d02-life-body:" + ids["action_operation"]
    body_row = _read(db, issuer=issuer, namespace=ns, kind="life_body_preparation", ref="life-body:" + body_operation)
    if body_row is not None:
        body = life_body_preparation_original_from_wire_v1(body_row[0])
        body_origin = _completed_phase_original_v1(db, read, body_operation, "d02", "prepare_artifact_draft_body")
        reservation_key, settlement_key = _refs(ns, ids["activity_id"], body_operation)
        if (body_row[1] != body_operation or body.action_operation_id != ids["action_operation"]
                or (body.action_intent_ref, body.action_intent_digest, body.activity_id, body.effect_id) !=
                   (action_key.token, canonical_digest(action_atom.value), ids["activity_id"], ids["effect"])
                or {v.key for v in body_origin["receipt"].write_versions} != {reservation_key}
                or canonical_digest(body_origin["receipt"]) != body.receipt_digest
                or body_origin["payload"]["request"]["action_intent_ref"] != action_key.token):
            raise ValueError("phase Body B changed its exact adopted Action A membership")
        v0, v1 = _phase_cas_versions_v1(body_origin, reservation_key)
        current = read.head(db, reservation_key, required=True)
        historical = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (reservation_key.token, v1.revision)).fetchone()
        original_value = None if historical is None or historical[1] != 1 else json.loads(historical[0])
        if (v0.revision != 0 or current.key.token != body.reservation_ref
                or canonical_digest(original_value) != body.reservation_digest):
            raise MissingProductionOriginalV1("actual_phase_Body_B_own_reservation_without_successor")
        _phase_history_atom_v1(db, read, version=v1, expected_value=original_value, producer_operation_id=body_operation)
        read.original("life-body:" + body_operation, kind="d11.life_life_body_preparation", digest=canonical_digest(body_row[0]))
        quote = issuer.resource_issuer.original_signed_quote(db, body.resource_quote_ref, body.resource_quote_version)
        if (canonical_digest(quote) != body.resource_quote_digest or quote.operation_id != body_operation
                or quote.effect_id != ids["effect"] or quote.parent_budget_lease_ref != read.frame.envelope.parent_budget_lease_ref
                or read.frame.now_utc >= quote.valid_until_utc):
            raise MissingProductionOriginalV1("current_original_phase_Body_B_quote")
        projections.append((GraphAtom(reservation_key, 0, {}, False), v1, canonical_digest(original_value)))
        origins.append((body_operation, body_origin["original_digest"]))
    successors, successor_origins = _completed_phase_file_successor_facts_v1(db, namespace=ns,
        selector=selector, adoption=adoption, issuer=issuer, now_utc=read.frame.now_utc,
        owner_guard=read.frame.owner_guard)
    merged = _coalesce_completed_phase_deltas_v1(tuple((GraphVersion(a.key,a.revision),v,d) for a,v,d in projections), successors)
    values = {a.key:a for a,_,_ in projections}
    for old,after,digest in merged:
        actual = read.head(db,after.key,required=True)
        if (actual.revision,canonical_digest(actual.value)) != (after.revision,digest):
            raise MissingProductionOriginalV1("current_exact_completed_phase_file_successor")
        if old.key not in values:
            row=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",(old.key.token,old.revision)).fetchone()
            if old.revision and row is None:raise ValueError("samephase successor lost its exact original predecessor")
            values[old.key]=GraphAtom(old.key,old.revision,json.loads(row[0]) if row else {},bool(row[1]) if row else False)
    return tuple((values[old.key],after,digest) for old,after,digest in merged), (*origins,*successor_origins)



def _reconstruct_completed_phase_action_transition_v1(db, *, frame, request, phase_selector, readers, model_readers):
    from .d11_artifact_draft_model_v1 import (_read_artifact_phase_selected_originals_v2,
        read_artifact_draft_prepared_v2, read_artifact_draft_frozen_v2)
    from .d11_artifact_draft_content_v1 import read_current_adopted_artifact_draft_content_v2
    from .foreground_cycle_v1 import decode_foreground_job_v1, foreground_cycle_from_wire_v1
    from .d11_types import job_graph_write
    from .jobs import get_job, _job_from_dict
    from .d11_offline_originals_v1 import _utc
    from ..memory_types import access_key
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    from ..graph_types import GraphAtom
    graph = readers.current().graph
    if (db is not graph._GraphCoordinator__store._db or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or model_readers.model_runtime is not graph._GraphCoordinator__artifact_draft_model_runtime_v1
            or model_readers.installed_bundle is not readers.bundle):
        raise TypeError("completed phase Action needs exact actual installed W01/model readers")
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    candidates, chosen, candidate_original = _read_artifact_phase_selected_originals_v2(db, selector=phase_selector, issuer=readers.issuer)
    if (request.prepared_candidates_operation_id != candidates.preparation_operation_id
            or request.decision_ref != phase_selector.decision_ref or candidates.namespace != ns):
        raise ValueError("completed phase changed its original selected Decision/preparation")
    read.original("d08-current:" + candidate_original["original_digest"][:48],
        kind="d08.current-" + PREPARE_OPERATION_V1, digest=candidate_original["original_digest"])
    adoption = read_current_adopted_artifact_draft_content_v2(db, frame=frame, selector=phase_selector, installed_readers=model_readers)
    lineage = _completed_phase_lineage_v1(db, namespace=ns, selector=phase_selector, issuer=readers.issuer, adoption=adoption)
    ids = artifact_draft_model_ids_v2(phase_selector)
    prepared = read_artifact_draft_prepared_v2(db, namespace=ns, issuer=readers.issuer, selector=phase_selector)
    frozen = read_artifact_draft_frozen_v2(db, prepared=prepared, issuer=readers.issuer)
    _require_private_phase_postcondition_commitment_v1(db,selector=phase_selector,binding=chosen.binding,
        frozen=frozen,issuer=readers.issuer,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
        installed_bundle=readers.bundle,frame=frame)
    if (prepared.owner_guard != frame.owner_guard or prepared.activation_generation != frame.activation_generation
            or (prepared.installation_id, prepared.manifest_digest) !=
               (readers.bundle.installation_policy.installation_id, readers.bundle.installation_policy.manifest_digest)
            or prepared.actor_ref != frame.envelope.authority.actor or prepared.parent_budget_lease_ref != frame.envelope.parent_budget_lease_ref
            or frame.now_utc >= min(candidates.need.original_deadline_utc, _utc(prepared.deadline_utc).timestamp())):
        raise MissingProductionOriginalV1("current_completed_phase_owner_package_budget_deadline")
    prepare = _phase_original_v1(db, read, prepared.operation_id, "prepare_artifact_draft_model_v2")
    acquire = _phase_original_v1(db, read, prepared.acquire_operation_id, "acquire_artifact_draft_model_v2")
    content = _completed_phase_original_v1(db, read, ids["adopt"], "d06", "adopt_artifact_draft_content_v2")
    before = decode_foreground_job_v1(prepare["payload"]["provenance"]["before_cycle"], namespace=ns)
    after_prepare = decode_foreground_job_v1(prepare["payload"]["provenance"]["after_cycle"], namespace=ns)
    cycle_key = job_graph_write(before).key
    c0, c1 = _phase_cas_versions_v1(prepare, cycle_key)
    if tuple(v for v in candidates.read_versions if v.key == cycle_key) != (c0,):
        raise MissingProductionOriginalV1("actual_completed_phase_candidate_cycle_predecessor")
    old_cycle = _phase_history_atom_v1(db, read, version=c0, expected_value=job_graph_write(before).value)
    _phase_history_atom_v1(db, read, version=c1, expected_value=job_graph_write(after_prepare).value,
        producer_operation_id=prepared.operation_id)
    current_cycle_atom = read.head(db, cycle_key, required=True)
    cycle, cycle_origins = _completed_cycle_chain_v1(db, read, before=after_prepare, before_version=c1,
        current=current_cycle_atom, selector=phase_selector, prepared_digest=prepared.digest)
    if (get_job(db, cycle.job_id) != cycle or cycle.phase != "running" or cycle.lease_holder != prepared.actor_ref
            or cycle.cancel_epoch or cycle.lease_expires_utc is None or frame.now_utc >= _utc(cycle.lease_expires_utc).timestamp()):
        raise MissingProductionOriginalV1("actual_completed_phase_current_running_self_cycle")
    acquired = _job_from_dict(acquire["payload"]["provenance"]["job"])
    completed = replace(acquired, phase="completed", lease_holder=None, lease_expires_utc=None, result_ref=ids["adopt"])
    job_key = job_graph_write(completed).key
    j0, j1 = _phase_cas_versions_v1(prepare, job_key)
    a0, a1 = _phase_cas_versions_v1(acquire, job_key)
    d0, d1 = _phase_cas_versions_v1(content, job_key)
    created = db.execute("SELECT digest,job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='create'", (*ns.as_tuple, "create:" + prepared.operation_id)).fetchone()
    if created is None or created[0] != prepared.reservation_digest:
        raise MissingProductionOriginalV1("actual_completed_phase_job_create_once")
    queued = _job_from_dict(json.loads(created[1]))
    if j0.revision != 0 or a0 != j1 or d0 != a1 or get_job(db, prepared.job_id) != completed:
        raise MissingProductionOriginalV1("actual_unbroken_completed_phase_model_job_chain")
    for version, expected, producer in ((j1, queued, prepared.operation_id), (a1, acquired, prepared.acquire_operation_id),
            (d1, completed, ids["adopt"])):
        _phase_history_atom_v1(db, read, version=version, expected_value=job_graph_write(expected).value, producer_operation_id=producer)
    current_job = read.head(db, job_key, required=True)
    if current_job.revision != d1.revision or current_job.value != job_graph_write(completed).value:
        raise MissingProductionOriginalV1("actual_completed_phase_job_current_head_without_successor")
    checkpoint = db.execute("SELECT digest,job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='checkpoint'", (*ns.as_tuple, ids["adopt"])).fetchone()
    if checkpoint is None or checkpoint[0] != canonical_digest(plain_v1(completed)) or _job_from_dict(json.loads(checkpoint[1])) != completed:
        raise MissingProductionOriginalV1("actual_completed_phase_job_sql_checkpoint")
    projections = [(old_cycle, GraphVersion(cycle_key, current_cycle_atom.revision), canonical_digest(current_cycle_atom.value)),
        (GraphAtom(job_key, 0, {}, False), d1, canonical_digest(current_job.value))]
    source_key = AtomKey.from_token(adoption.content.content.ref)
    own_access = access_key(*ns.as_tuple, source_key.owner.subject)
    if {v.key for v in content["receipt"].write_versions} != {source_key, own_access, job_key}:
        raise ValueError("completed phase content receipt contains foreign Source/Runtime members")
    for key in (source_key, own_access):
        v0, v1 = _phase_cas_versions_v1(content, key)
        atom = read.head(db, key, required=True)
        if v0.revision != 0 or atom.revision != v1.revision:
            raise MissingProductionOriginalV1("actual_completed_phase_source_access_exact_new_member")
        _phase_history_atom_v1(db, read, version=v1, expected_value=atom.value, producer_operation_id=ids["adopt"])
        projections.append((GraphAtom(key, 0, {}, False), v1, canonical_digest(atom.value)))
    paid = lineage[(ns, "c4_phase_paid", ids["paid"])][1]
    from .c09_life_originals_v1 import require_c4_model_cost_original_commit_v1
    require_c4_model_cost_original_commit_v1(db, namespace=ns, operation_id=paid.operation_id)
    cost_key = AtomKey.from_token(paid.cost_ref)
    cost_atom = read.head(db, cost_key, required=True)
    if cost_atom.revision != 1:
        raise MissingProductionOriginalV1("actual_completed_phase_cost_original_without_successor")
    _phase_history_atom_v1(db, read, version=GraphVersion(cost_key, 1), expected_value=cost_atom.value,
        producer_operation_id=paid.operation_id)
    projections.append((GraphAtom(cost_key, 0, {}, False), GraphVersion(cost_key, 1), canonical_digest(cost_atom.value)))
    reservation = db.execute("SELECT digest,state,ceiling_json,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone()
    if reservation is None or reservation[0] != prepared.reservation_digest or reservation[1] != "settled" or reservation[3] is None:
        raise MissingProductionOriginalV1("actual_known_settled_completed_phase_model_cost")
    own, own_origins = _completed_phase_own_action_body_v1(db, read, selector=phase_selector, adoption=adoption, issuer=readers.issuer)
    projections.extend(own)
    cont = foreground_cycle_from_wire_v1(cycle.continuation)
    from .d11_artifact_draft_model_v1 import require_current_artifact_phase_group_v2
    require_current_artifact_phase_group_v2(db, namespace=ns, group=cont.call_plan.phase_group, issuer=readers.issuer)
    producers = ((prepared.operation_id, prepare["original_digest"]), (prepared.acquire_operation_id, acquire["original_digest"]),
        (ids["adopt"], content["original_digest"]), (paid.operation_id, canonical_digest(plain_v1(paid))), *cycle_origins, *own_origins)
    return CompletedPhaseActionTransitionV1(_PHASE_TRANSITION_KEY, graph=graph, frame=frame, readers=readers,
        request=request, phase_selector=phase_selector, candidate_original_digest=candidate_original["original_digest"],
        prepared_candidates=candidates, selected_binding_digest=chosen.binding.digest, decision_digest=phase_selector.decision_digest,
        group_identity_digest=cont.call_plan.phase_group.identity_digest, frozen_digest=frozen.digest, prepare_operation_id=prepared.operation_id,
        reservation_digest=prepared.reservation_digest, reservation_ceiling=tuple(sorted(json.loads(reservation[2]).items())),
        before_cycle=before, after_cycle=cycle, projections=tuple(projections), producer_originals=producers,
        content_adoption_ref=ids["adopt"], content_adoption_digest=canonical_digest(plain_v1(adoption)), paid_original_digest=canonical_digest(plain_v1(paid)))





def _read_plan_completed_phase_action_transition_v1(db, *, namespace, phase_selector, installed_readers):
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v2
    from .d11_artifact_draft_content_v1 import artifact_draft_content_from_wire_v2, ArtifactDraftContentAdoptionV2
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2, artifact_draft_file_ids_v2
    from .d11_types import runtime_job_key
    from .d08_personal_plan_v1 import artifact_phase_action_keys_v2
    from .d02_life_body_preparation_v1 import _refs
    from ..memory_types import access_key
    readers = _readers(installed_readers)
    ids = artifact_draft_model_ids_v2(phase_selector); file_ids = artifact_draft_file_ids_v2(phase_selector)
    p = read_artifact_draft_prepared_v2(db, namespace=namespace, issuer=readers.issuer, selector=phase_selector)
    if p is None:
        raise MissingProductionOriginalV1("actual_completed_phase_prepare_read_plan")
    keys = [AtomKey.from_token(phase_selector.task.cycle_job_ref), runtime_job_key(*namespace.as_tuple, p.activity_id, p.job_id),
        *artifact_phase_action_keys_v2(phase_selector)]
    originals = [ids[name] for name in ("job", "frozen", "request", "call", "paid", "result", "adopt")]
    operations = [p.operation_id, p.acquire_operation_id, ids["adopt"], file_ids["action_operation"], "d02-life-body:" + file_ids["action_operation"]]
    from .artifact_borrowed_source_v3 import artifact_borrowed_recipe_index_v3
    artifact,events=artifact_borrowed_recipe_index_v3(db,namespace=namespace,family="history_index",
        kind="valid_cycle_events",ref=phase_selector.task.cycle_job_ref)
    cycle_rows=tuple((event,)for event in events)if artifact else db.execute(
        "SELECT event_id FROM graph_history WHERE token=? AND valid=1 ORDER BY revision LIMIT 129",
        (phase_selector.task.cycle_job_ref,)).fetchall()
    if len(cycle_rows) > 128:
        raise MissingProductionOriginalV1("bounded_actual_completed_phase_cycle_history")
    operations.extend(row[0] for row in cycle_rows)
    for op in dict.fromkeys(operations):
        original = read_adopted_domain_operation_v1(db, namespace, op)
        if original is not None:
            originals.append(original["domain"] + "-current:" + original["original_digest"][:48])
            keys.extend(v.key for v in original["read_versions"])
            keys.extend(v.key for v in original["receipt"].write_versions)
    roots = []
    row = _read(db, issuer=readers.issuer, namespace=namespace, kind="c4_phase_adopted", ref=ids["adopt"])
    if row is not None:
        a = artifact_draft_content_from_wire_v2(row[0], ArtifactDraftContentAdoptionV2)
        source = AtomKey.from_token(a.content.content.ref)
        keys.extend((source, access_key(*namespace.as_tuple, source.owner.subject)))
        roots.extend(a.content.source_refs)
        originals.extend((a.activity_scope_ref, a.extent_original_ref))
    paid = _read(db, issuer=readers.issuer, namespace=namespace, kind="c4_phase_paid", ref=ids["paid"])
    if paid is not None:
        keys.append(AtomKey.from_token(paid[0]["cost_ref"]))
    body_op = "d02-life-body:" + file_ids["action_operation"]
    body = _read(db, issuer=readers.issuer, namespace=namespace, kind="life_body_preparation", ref="life-body:" + body_op)
    if body is not None:
        originals.append("life-body:" + body_op)
        keys.extend(_refs(namespace, p.activity_id, body_op))
    from .d11_life_preparation_v1 import TABLE, read_prepared_life_by_ref_v1
    artifact,prepared_index=artifact_borrowed_recipe_index_v3(db,namespace=namespace,family="life_index",
        kind="prepared_by_action",ref=file_ids["action_operation"])
    life_rows=tuple((ref,)for ref,_ in prepared_index)if artifact else db.execute(
        "SELECT original_ref FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='prepared' "
        "AND json_extract(payload_json,'$.binding.operation_id')=? LIMIT 2",(*namespace.as_tuple,file_ids["action_operation"])).fetchall()
    if len(life_rows)>1:raise ValueError("phase read plan has conflicting actual Life preparations")
    if life_rows:
        life=read_prepared_life_by_ref_v1(db,namespace=namespace,prepared_original_ref=life_rows[0][0],issuer=readers.issuer)
        b=life.binding
        originals.extend((b.prepared_original_ref,b.plan_original_ref))
        if life.admission_ref is not None:originals.append(life.admission_ref)
        keys.extend(AtomKey.from_token(row.ref) for row in life.read_rows)
        prepare=read_adopted_domain_operation_v1(db,namespace,b.prepare_operation_id)
        if prepare is not None:
            originals.append(prepare['domain']+'-current:'+prepare['original_digest'][:48])
            keys.extend(v.key for v in prepare['receipt'].write_versions)
        adopted=_read(db,issuer=readers.issuer,namespace=namespace,kind='adopted_life',ref=b.artifact_ref)
        if adopted is not None:
            originals.extend((b.artifact_ref,adopted[0]['terminal']['original_ref'],adopted[0]['terminal']['claim']['original_ref']))
            keys.extend(AtomKey.from_token(row['ref']) for row in adopted[0]['write_commitments'])
            from .d11_life_contract_v1 import LifeBodyComponentContractV1
            contract=LifeBodyComponentContractV1(**json.loads(life.plan.body_effect_request_json))
            settlement=AtomKey.from_token(contract.settlement_ref)
            keys.append(settlement)
            producer=db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=1',(settlement.token,)).fetchone()
            effect=read_adopted_domain_operation_v1(db,namespace,producer[0]) if producer else None
            if effect is not None:
                originals.append(effect['domain']+'-current:'+effect['original_digest'][:48])
                keys.extend(v.key for v in effect['read_versions'])
                keys.extend(v.key for v in effect['receipt'].write_versions)
    return production_read_plan_v1((), keys, roots, originals)



def readonly_current_completed_artifact_phase_facts_v1(db, *, namespace, selector, issuer, now_utc,
        owner_guard=None, installed_bundle=None):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    """Actual SQLite facts only. This return value never authorizes execution."""
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2, artifact_draft_file_ids_v2
    from .d11_artifact_draft_model_v1 import _read_artifact_phase_selected_originals_v2, read_artifact_draft_prepared_v2, read_artifact_draft_frozen_v2
    from .d11_artifact_draft_content_v1 import _read_phase_content_adoption_original_v2
    from .foreground_cycle_v1 import decode_foreground_job_v1, foreground_cycle_from_wire_v1
    from .d11_types import job_graph_write
    from .jobs import get_job, _job_from_dict
    from .d11_life_preparation_v1 import _read
    from ..graph_types import GraphAtom
    from ..memory_types import access_key
    from .d11_offline_originals_v1 import _utc
    if not db.in_transaction or selector.task.namespace != namespace or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("completed phase SQL facts require exact namespace and installed signed originals")
    candidates, chosen, _ = _read_artifact_phase_selected_originals_v2(db, selector=selector, issuer=issuer)
    adoption, _, _, _ = _read_phase_content_adoption_original_v2(db, namespace=namespace, selector=selector, issuer=issuer)
    originals = _completed_phase_lineage_v1(db, namespace=namespace, selector=selector, issuer=issuer, adoption=adoption)
    ids = artifact_draft_model_ids_v2(selector); file_ids = artifact_draft_file_ids_v2(selector)
    p = read_artifact_draft_prepared_v2(db, namespace=namespace, issuer=issuer, selector=selector)
    frozen=read_artifact_draft_frozen_v2(db, prepared=p, issuer=issuer)
    if type(chosen.binding) is ArtifactPhaseCandidateBindingV3:
        if owner_guard is None or installed_bundle is None:
            raise MissingProductionOriginalV1("actual_current_V3_postcondition_Owner_installed_facts")
        _require_private_phase_postcondition_commitment_v1(db,selector=selector,binding=chosen.binding,
            frozen=frozen,issuer=issuer,owner_guard=owner_guard,now_utc=now_utc,installed_bundle=installed_bundle)
    if now_utc >= min(candidates.need.original_deadline_utc, _utc(p.deadline_utc).timestamp()):
        raise MissingProductionOriginalV1("current_completed_SQL_phase_original_deadline")
    if owner_guard is not None and p.owner_guard != owner_guard:
        raise MissingProductionOriginalV1("same_current_completed_SQL_phase_owner_guard")
    if installed_bundle is not None and (p.installation_id, p.manifest_digest) != (
            installed_bundle.installation_policy.installation_id, installed_bundle.installation_policy.manifest_digest):
        raise MissingProductionOriginalV1("same_current_completed_SQL_phase_installed_package")
    allowed, producers = [], []
    def current(key):
        row = artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=key.token)
        if row is None:
            return GraphAtom(key, 0, {}, False)
        return GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
    def operation(op, domain, kind):
        value = read_adopted_domain_operation_v1(db, namespace, op)
        if value is None or (value["domain"], value["operation_kind"]) != (domain, kind):
            raise MissingProductionOriginalV1("actual_completed_SQL_phase_producer:" + kind)
        producers.append((op, value["original_digest"]))
        return value
    def history(v, expected, producer):
        row = artifact_model_graph_point_v3(db,('event_id', 'value', 'valid'),token=v.key.token,revision=v.revision)
        if row != (producer, canonical_serialize(expected), 1):
            raise MissingProductionOriginalV1("actual_completed_SQL_phase_history_member")
    def append_delta(key, old, after, expected, producer):
        history(after, expected, producer)
        atom = current(key)
        if not atom.valid or atom.revision != after.revision or atom.value != expected:
            raise MissingProductionOriginalV1("actual_completed_SQL_phase_no_foreign_successor")
        allowed.append((old, after, canonical_digest(expected)))
    prepare = operation(p.operation_id, "d11", "prepare_artifact_draft_model_v2")
    acquire = operation(p.acquire_operation_id, "d11", "acquire_artifact_draft_model_v2")
    content = operation(ids["adopt"], "d06", "adopt_artifact_draft_content_v2")
    acquired = _job_from_dict(acquire["payload"]["provenance"]["job"])
    completed = replace(acquired, phase="completed", lease_holder=None, lease_expires_utc=None, result_ref=ids["adopt"])
    model_key = job_graph_write(completed).key
    q0, q1 = _phase_cas_versions_v1(prepare, model_key)
    a0, a1 = _phase_cas_versions_v1(acquire, model_key)
    d0, d1 = _phase_cas_versions_v1(content, model_key)
    born = db.execute("SELECT job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='create'",
        (*namespace.as_tuple, "create:" + p.operation_id)).fetchone()
    if born is None or q0.revision != 0 or a0 != q1 or d0 != a1 or get_job(db, p.job_id) != completed:
        raise MissingProductionOriginalV1("actual_completed_SQL_phase_model_once_chain")
    history(q1, job_graph_write(_job_from_dict(json.loads(born[0]))).value, p.operation_id)
    history(a1, job_graph_write(acquired).value, p.acquire_operation_id)
    append_delta(model_key, q0, d1, job_graph_write(completed).value, ids["adopt"])
    cycle = decode_foreground_job_v1(prepare["payload"]["provenance"]["after_cycle"], namespace=namespace)
    cycle_key = job_graph_write(cycle).key
    c0, cursor = _phase_cas_versions_v1(prepare, cycle_key)
    if tuple(v for v in candidates.read_versions if v.key == cycle_key) != (c0,):
        raise MissingProductionOriginalV1("actual_completed_SQL_phase_candidate_cycle_predecessor")
    history(cursor, job_graph_write(cycle).value, p.operation_id)
    atom = current(cycle_key)
    rows = db.execute("SELECT revision,event_id FROM graph_history WHERE token=? AND revision>? AND revision<=? ORDER BY revision LIMIT 129",
        (cycle_key.token, cursor.revision, atom.revision)).fetchall()
    if len(rows)>128:
        raise MissingProductionOriginalV1("bounded_completed_SQL_phase_causal_cycle_chain")
    for revision, op in rows:
        raw = read_adopted_domain_operation_v1(db, namespace, op)
        if raw is None or raw["operation_kind"] not in {"wake_artifact_draft_cycle_v2", "acquire_foreground_cycle"}:
            raise MissingProductionOriginalV1("actual_completed_SQL_phase_known_cycle_successor")
        origin = operation(op, "d11", raw["operation_kind"])
        prior = decode_foreground_job_v1(origin["payload"]["provenance"]["before_job"], namespace=namespace)
        after = decode_foreground_job_v1(origin["payload"]["provenance"]["after_job"], namespace=namespace)
        v0,v1 = _phase_cas_versions_v1(origin,cycle_key)
        if v0 != cursor or v1.revision != revision or prior != cycle:
            raise MissingProductionOriginalV1("actual_completed_SQL_phase_exact_cycle_link")
        if raw["operation_kind"] == "wake_artifact_draft_cycle_v2":
            if origin["payload"]["request"]["selector"] != plain_v1(selector) or after != replace(prior,phase="queued",wake_condition=None):
                raise ValueError("SQL completed phase wake changed the exact phase/call cause")
        elif after != replace(prior,phase="running",fence=prior.fence+1,lease_holder=p.actor_ref,lease_expires_utc=after.lease_expires_utc):
            raise ValueError("SQL completed phase acquire changed its registered self")
        history(v1,job_graph_write(after).value,op)
        cycle,cursor=after,v1
    if get_job(db,cycle.job_id)!=cycle or cursor.revision!=atom.revision or atom.value!=job_graph_write(cycle).value:
        raise MissingProductionOriginalV1("actual_completed_SQL_phase_current_cycle")
    allowed.append((c0,cursor,canonical_digest(atom.value)))
    source = AtomKey.from_token(adoption.content.content.ref)
    for key in (source,access_key(*namespace.as_tuple,source.owner.subject)):
        v0,v1=_phase_cas_versions_v1(content,key)
        if v0.revision:
            raise ValueError("SQL completed phase Source/access did not originate from absence")
        append_delta(key,v0,v1,current(key).value,ids["adopt"])
    paid=originals[(namespace,"c4_phase_paid",ids["paid"])][1]
    from .c09_life_originals_v1 import require_c4_model_cost_original_commit_v1
    require_c4_model_cost_original_commit_v1(db,namespace=namespace,operation_id=paid.operation_id)
    cost=AtomKey.from_token(paid.cost_ref); ca=current(cost)
    append_delta(cost,GraphVersion(cost,0),GraphVersion(cost,1),ca.value,paid.operation_id)
    action_key = AtomKey(Owner("activity",*namespace.as_tuple,file_ids["activity_id"]),"d08.action_intent.v1",file_ids["action"])
    action=current(action_key)
    if action.revision:
        from ..domains.d08.execution import _decode,ActionSchemaRecord,ActionSchema
        from .d08_personal_plan_v1 import PHASE_ACTION_OPERATION_V2
        origin=operation(file_ids["action_operation"],"d08",PHASE_ACTION_OPERATION_V2)
        value=_decode("d08.action_intent.v1",action.value)
        schema=ActionSchemaRecord.bind(value,ActionSchema(value.schema_id,value.action_kind,False,value.required_checks))
        keys={action_key,AtomKey(action_key.owner,"d08.action_schema.v1",schema.schema_ref),
            AtomKey(action_key.owner,"d08.action_cancellation.v1",file_ids["action"])}
        if (origin["payload"]["request"] != {"selector":plain_v1(selector)}
                or origin["payload"]["provenance"]["artifact_phase_content_adoption"] != plain_v1(adoption)
                or {v.key for v in origin["receipt"].write_versions} != keys):
            raise ValueError("SQL completed phase Action A has foreign scope/members")
        for key in sorted(keys,key=lambda x:x.token):
            v0,v1=_phase_cas_versions_v1(origin,key)
            if v0.revision:raise ValueError("SQL phase Action cannot replace its original A members")
            append_delta(key,v0,v1,current(key).value,file_ids["action_operation"])
        body_op="d02-life-body:"+file_ids["action_operation"]
        body=_read(db,issuer=issuer,namespace=namespace,kind="life_body_preparation",ref="life-body:"+body_op)
        if body is not None:
            from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1,_refs
            b=life_body_preparation_original_from_wire_v1(body[0]); bo=operation(body_op,"d02","prepare_artifact_draft_body")
            key,_=_refs(namespace,file_ids["activity_id"],body_op); v0,v1=_phase_cas_versions_v1(bo,key)
            if (b.action_intent_ref,b.action_intent_digest,b.effect_id,b.receipt_digest)!=(action_key.token,canonical_digest(action.value),file_ids["effect"],canonical_digest(bo["receipt"])) or v0.revision:
                raise ValueError("SQL completed phase Body B changed its actual A/reservation")
            quote=issuer.resource_issuer.original_signed_quote(db,b.resource_quote_ref,b.resource_quote_version)
            if canonical_digest(quote)!=b.resource_quote_digest or quote.operation_id!=body_op or now_utc>=quote.valid_until_utc:
                raise MissingProductionOriginalV1("current_SQL_completed_phase_Body_quote")
            h=artifact_model_graph_point_v3(db,('value', 'valid'),token=key.token,revision=v1.revision)
            if h is None or h[1]!=1 or canonical_digest(json.loads(h[0]))!=b.reservation_digest:
                raise ValueError("SQL completed phase original Body reservation changed")
            history(v1,json.loads(h[0]),body_op)
            allowed.append((v0,v1,b.reservation_digest))
    successors,successor_origins=_completed_phase_file_successor_facts_v1(db,namespace=namespace,
        selector=selector,adoption=adoption,issuer=issuer,now_utc=now_utc,
        owner_guard=owner_guard,installed_bundle=installed_bundle)
    allowed=_coalesce_completed_phase_deltas_v1(tuple(allowed),successors)
    producers.extend(successor_origins)
    for old,after,digest in allowed:
        atom=current(after.key)
        if (atom.revision,canonical_digest(atom.value),atom.valid)!=(after.revision,digest,True):
            raise MissingProductionOriginalV1("current_SQL_completed_phase_final_exact_member")
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    cont=foreground_cycle_from_wire_v1(cycle.continuation)
    if foreground_artifact_phase_group_identity_v2(cont.call_plan.phase_group.selector)!=foreground_artifact_phase_group_identity_v2(selector):
        raise ValueError("completed SQL phase changed its actually selected whole method group")
    return candidates,chosen,adoption,tuple(allowed),tuple(producers)


def _completed_phase_file_successor_facts_v1(db, *, namespace, selector, adoption, issuer, now_utc,
        owner_guard=None, installed_bundle=None):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    """Authenticate exact installed file predecessors; return facts, never a grant."""
    from .d11_life_preparation_v1 import TABLE, _read, read_prepared_life_by_ref_v1
    from .d11_artifact_draft_content_v1 import _read_actual_phase_file_v2
    from .d11_life_terminal_v1 import read_current_life_job_result_v1
    from .d11_life_adoption_v1 import (_read_signed, verify_life_adoption_commit_v1,
        validate_life_recovery_heads_v1)
    from ..authority_service.d11_life_bridge_v1 import life_bridge_from_wire_v1
    from .d11_types import job_graph_write, runtime_cost_settlement_key
    from .jobs import get_job
    from .d11_offline_originals_v1 import _utc
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
    from ..runtime_contracts import CommitReceipt
    from .d10_offline_tick_execution_v1 import _decode_json
    ids=artifact_draft_file_ids_v2(selector)
    rows=db.execute("SELECT original_ref FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='prepared' "
        "AND json_extract(payload_json,'$.binding.operation_id')=? LIMIT 2",(*namespace.as_tuple,ids['action_operation'])).fetchall()
    if not rows:return (),()
    if len(rows)!=1:raise ValueError('same phase file has conflicting signed preparations')
    prepared=read_prepared_life_by_ref_v1(db,namespace=namespace,prepared_original_ref=rows[0][0],issuer=issuer)
    b,plan=prepared.binding,prepared.plan
    if ((plan.activity_id,plan.operation_id,plan.attempt_id,plan.effect_id,plan.execution_call_id)!=
            (ids['activity_id'],ids['action_operation'],ids['attempt'],ids['effect'],ids['execution_call'])
            or (plan.target,plan.content,plan.activity_scope_ref,plan.activity_scope_digest)!=
                (adoption.target,adoption.content,adoption.activity_scope_ref,adoption.activity_scope_digest)
            or _utc(plan.deadline_utc)>_utc(adoption.original_deadline_utc)
            or now_utc>=min(_utc(b.deadline_utc).timestamp(),_utc(adoption.original_deadline_utc).timestamp())):
        raise ValueError('completed file facts crossed actual phase/content/root/deadline')
    if owner_guard is not None and (b.owner_grant_ref,b.owner_grant_revision,b.owner_grant_digest)!=(
            owner_guard.grant_ref,owner_guard.grant_revision,owner_guard.grant_digest):
        raise ValueError('completed file facts lost current upstream Owner')
    if installed_bundle is not None and (b.installation_id,b.manifest_digest)!=(
            installed_bundle.installation_policy.installation_id,installed_bundle.installation_policy.manifest_digest):
        raise ValueError('completed file facts crossed installed package')
    owner=artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=b.owner_grant_ref)
    if owner is None or (owner[0],canonical_digest(json.loads(owner[1])),owner[2])!=(b.owner_grant_revision,b.owner_grant_digest,1):
        raise ValueError('completed file current Owner original changed')
    from .d11_life_fact_provenance_v1 import life_current_fact_reads_v1
    from .d11_life_preparation_v1 import life_read_matches_v1
    for frozen in life_current_fact_reads_v1(prepared):
        row=artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=frozen.ref)
        if not life_read_matches_v1(frozen,row):raise ValueError('completed file current Source/Actor/permission ancestor changed')
    origin=read_adopted_domain_operation_v1(db,namespace,b.prepare_operation_id)
    if origin is None or (origin['domain'],origin['operation_kind'])!=('d10','prepare_life'):
        raise MissingProductionOriginalV1('actual_signed_samephase_Life_prepare_producer')
    job_key=AtomKey(Owner('activity',*namespace.as_tuple,b.activity_id),'runtime.job',b.job_id)
    v0,v1=_phase_cas_versions_v1(origin,job_key)
    if v0.revision!=0 or v1.revision!=prepared.job_projection_revision or {v.key for v in origin['receipt'].write_versions}!={job_key}:
        raise ValueError('samephase Life prepare has foreign members or predecessor')
    history=artifact_model_graph_point_v3(db,('event_id', 'value', 'valid'),token=job_key.token,revision=v1.revision)
    if history!=(b.prepare_operation_id,prepared.job_projection_json,1):raise ValueError('samephase Life prepare lacks actual historical job')
    deltas=[];producers=[(b.prepare_operation_id,origin['original_digest'])]
    def member(before,after,expected,producer):
        key=after.key
        if key.owner.bot!=namespace.bot_id or key.owner.persona!=namespace.persona_id:
            raise ValueError('samephase file member namespace changed')
        historical=artifact_model_graph_point_v3(db,('event_id', 'value', 'valid'),token=key.token,revision=after.revision)
        current=artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=key.token)
        if historical!=(producer,canonical_serialize(expected),1) or current!=(after.revision,canonical_serialize(expected),1):
            raise MissingProductionOriginalV1('exact_samephase_file_member_without_foreign_successor')
        deltas.append((before,after,canonical_digest(expected)))
    adopted_row=_read(db,issuer=issuer,namespace=namespace,kind='adopted_life',ref=b.artifact_ref)
    if adopted_row is None:
        actual=job_graph_write(get_job(db,b.job_id))
        if canonical_serialize(actual.value)!=prepared.job_projection_json:
            raise MissingProductionOriginalV1('actual_samephase_Life_prepare_running_job')
        member(v0,v1,actual.value,b.prepare_operation_id)
        return tuple(deltas),tuple(producers)
    actual_prepared,terminal,adopted,readback=_read_actual_phase_file_v2(db,namespace=namespace,
        selector=selector,adoption=adoption,result_ref=b.artifact_ref,issuer=issuer)
    bridge=_read_signed(db,namespace,'adoption_bridge',b.execution_id,issuer)
    if bridge is None:raise MissingProductionOriginalV1('actual_samephase_file_signed_adoption_bridge')
    gate=life_bridge_from_wire_v1(bridge[1])
    if actual_prepared!=prepared or gate.binding!=b or gate.terminal!=terminal or gate.prepared_digest!=prepared.digest:
        raise ValueError('samephase file signed terminal/bridge/preparation differ')
    verify_life_adoption_commit_v1(db,gate=gate,issuer=issuer,resource_issuer=issuer.resource_issuer,require_current_metadata=False)
    validate_life_recovery_heads_v1(db,binding=b,prepared_digest=prepared.digest,prepared=prepared,adopted=adopted)
    job,_=read_current_life_job_result_v1(db,job_id=b.job_id,adopted=adopted)
    receipt=_decode_json(adopted['graph_receipt_json'],CommitReceipt)
    from .d11_life_graph_types_v1 import life_fact_writes_v1
    facts=life_fact_writes_v1(prepared,terminal.claim,terminal,readback)
    cost_key=runtime_cost_settlement_key(*namespace.as_tuple,b.activity_id,b.reservation_operation_id)
    expected_keys={w.key for w in facts}|{job_key,cost_key}
    if {v.key for v in receipt.write_versions}!=expected_keys:
        raise ValueError('samephase completed file receipt contains foreign members')
    read_versions={v.key:v for v in receipt.read_versions}
    commitments={row['ref']:row for row in adopted['write_commitments']}
    for after in receipt.write_versions:
        before=read_versions.get(after.key)
        if before is None or after.revision!=before.revision+1:
            raise ValueError('samephase file member lacks precise CAS predecessor')
        row=artifact_model_graph_point_v3(db,('value', 'valid'),token=after.key.token,revision=after.revision)
        expected=json.loads(row[0])
        if commitments.get(after.key.token)!={'ref':after.key.token,'revision':after.revision,'digest':canonical_digest(expected)}:
            raise ValueError('samephase file member lost signed commitment')
        if after.key==job_key:
            if before!=v1 or expected!=job_graph_write(job).value:raise ValueError('samephase file job broke prepare/adopt continuity')
            before=v0
        elif before.revision!=0:raise ValueError('samephase file cannot replace another existing member')
        member(before,after,expected,receipt.operation_id)
    producers.append((receipt.operation_id,canonical_digest(adopted)))
    from .d11_life_contract_v1 import LifeBodyComponentContractV1
    contract=LifeBodyComponentContractV1(**json.loads(plan.body_effect_request_json))
    from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
    raw_body=_read(db,issuer=issuer,namespace=namespace,kind='life_body_preparation',ref='life-body:'+contract.body_prepare_operation_id)
    if raw_body is None:raise MissingProductionOriginalV1('actual_samephase_file_Body_B_original')
    body_original=life_body_preparation_original_from_wire_v1(raw_body[0])
    body_fields=('body_prepare_operation_id','body_quote_ref','body_quote_version','body_quote_digest',
        'resource_quote_ref','resource_quote_version','resource_quote_digest','reservation_ref',
        'settlement_ref','component_id','effect_policy_ref')
    if any(getattr(contract,name)!=getattr(body_original,name) for name in body_fields):
        raise ValueError('samephase file Body contract crossed its signed B original')
    resource=issuer.resource_issuer.original_signed_quote(db,contract.resource_quote_ref,contract.resource_quote_version)
    if canonical_digest(resource)!=contract.resource_quote_digest or resource.effect_id!=b.effect_id:
        raise ValueError('samephase file Body resource quote crossed actual effect')
    settlement=AtomKey.from_token(contract.settlement_ref)
    settled=artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=settlement.token)
    if settled is not None:
        if settled[0]!=1 or settled[2]!=1:raise ValueError('samephase Body settlement has foreign successor')
        recorded=db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=1',(settlement.token,)).fetchone()
        body=read_adopted_domain_operation_v1(db,namespace,recorded[0]) if recorded else None
        expected_request={'component_terminal_ref':terminal.original_ref,'body_quote_ref':contract.body_quote_ref,
            'settlement_operation_ref':receipt.operation_id,'effect_policy_ref':contract.effect_policy_ref}
        if body is None or (body['domain'],body['operation_kind'],body['payload']['request'])!=('d02','apply_body_effect',expected_request):
            raise ValueError('samephase Body settlement has no actual completed terminal producer')
        from ..domains.d02 import BodyDomain,SettlementResult
        result=_decode_json(canonical_serialize(body['payload']['provenance']['settlement']),SettlementResult)
        quote=body['payload']['provenance']['body_quote']
        if (canonical_digest(quote)!=contract.body_quote_digest or result.duplicate or result.overrun or result.unpaid_cost
                or result.reservation.status!='settled' or result.reservation.effect_id!=b.effect_id
                or contract.component_id+'|'+terminal.original_ref not in result.reservation.settled_components):
            raise ValueError('samephase Body settlement is unknown/overrun/foreign component')
        policy=db.execute("SELECT payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_ref=? AND revision=? AND kind='effect'",
            (*namespace.as_tuple,body_original.effect_policy_ref,body_original.effect_policy_revision)).fetchone()
        if policy is None:raise MissingProductionOriginalV1('actual_samephase_Body_effect_policy')
        issuer._signer.verify('d11.d02-production-policy.v1',policy[0],policy[2])
        effect_policy=json.loads(policy[0])
        if canonical_digest(effect_policy)!=policy[1] or policy[1]!=body_original.effect_policy_digest:
            raise ValueError('samephase Body effect changed signed policy')
        reservation_key=AtomKey.from_token(contract.reservation_ref)
        reserved=artifact_model_graph_point_v3(db,('value', 'valid'),token=reservation_key.token,revision=1)
        from ..domains.d02 import BodyState,BodyReservation
        initial=BodyReservation(**json.loads(reserved[0])) if reserved and reserved[1]==1 else None
        if initial is None or canonical_digest(json.loads(reserved[0]))!=body_original.reservation_digest:
            raise ValueError('samephase Body effect lost original reserved B member')
        state_key=BodyDomain.state_write(namespace,result.state).key
        before_state,_=_phase_cas_versions_v1(body,state_key)
        state_row=artifact_model_graph_point_v3(db,('value', 'valid'),token=state_key.token,revision=before_state.revision)
        if state_row is None or state_row[1]!=1:raise ValueError('samephase Body effect has no actual prior state')
        prior_state=_decode_json(state_row[0],BodyState)
        if (effect_policy['profile_id'],effect_policy['component_id'],effect_policy['work_kind'])!=(
                prior_state.profile_id,contract.component_id,resource.work_kind):
            raise ValueError('samephase Body effect policy targets another profile/component/work kind')
        expected_result=BodyDomain().settle_component(prior_state,initial,contract.component_id,
            actual_cost=next(part['fixed_cost'] for part in quote['components'] if part['component_id']==contract.component_id),
            component_receipt=terminal.original_ref)
        expected_result=BodyDomain.apply_settled_work_effect(expected_result,work_kind=effect_policy['work_kind'],
            fatigue_increase=effect_policy['fatigue_increase'],load_increase=effect_policy['load_increase'])
        if expected_result!=result:raise ValueError('samephase Body known settlement differs from exact signed component/policy')
        writes=(BodyDomain.state_write(namespace,result.state),BodyDomain.reservation_write(namespace,b.activity_id,result.reservation),
            BodyDomain.settlement_write(namespace,b.activity_id,settlement.name,result))
        if {v.key for v in body['receipt'].write_versions}!={w.key for w in writes}:
            raise ValueError('samephase Body effect has foreign CAS members')
        for w in writes:
            old,after=_phase_cas_versions_v1(body,w.key)
            if w.key.token==contract.reservation_ref and (old.revision,after.revision)!=(1,2):
                raise ValueError('samephase Body reserved-to-settled chain is not exact')
            if w.key==settlement and old.revision!=0:raise ValueError('samephase Body settlement reused another original')
            member(old,after,w.value,body['receipt'].operation_id)
        producers.append((body['receipt'].operation_id,body['original_digest']))
    return tuple(deltas),tuple(producers)


def _coalesce_completed_phase_deltas_v1(prior, successors):
    """Join authenticated precise CAS facts; reject gaps or parallel successors."""
    result={}
    for before,after,digest in (*prior,*successors):
        if before.key!=after.key or after.revision<=before.revision:
            raise ValueError('completed phase fact is not an exact advancing member')
        previous=result.get(before.key)
        if previous is None:result[before.key]=(before,after,digest)
        elif previous[1]==before:result[before.key]=(previous[0],after,digest)
        elif previous!=(before,after,digest):raise ValueError('completed phase member has a gap or conflicting successor')
    return tuple(result[key] for key in sorted(result,key=lambda k:k.token))


def _require_private_phase_postcondition_commitment_v1(db,*,selector,binding,frozen,issuer,owner_guard,now_utc,installed_bundle,frame=None):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftInputV3
    if type(binding) is not ArtifactPhaseCandidateBindingV3:
        if type(frozen) is ArtifactDraftInputV3:raise ValueError('old candidate cannot borrow another V3 success contract')
        return None
    from .artifact_phase_postconditions_v1 import readonly_current_artifact_phase_postcondition_contract_v1
    contract=readonly_current_artifact_phase_postcondition_contract_v1(db,namespace=selector.task.namespace,
        selector=selector,issuer=issuer,now_utc=now_utc,owner_guard=owner_guard,installed_bundle=installed_bundle)
    if (type(frozen) is not ArtifactDraftInputV3 or (frozen.postcondition_contract_ref,frozen.postcondition_contract_digest)!=
            (contract.original_ref,contract.digest) or (contract.policy_ref,contract.policy_digest)!=
            (binding.postcondition_policy_ref,binding.postcondition_policy_digest)
            or frozen.task_source_ref!=contract.source_head.key.token or contract.source_head not in frozen.source_read_versions
            or frozen.deadline_utc>contract.original_deadline_utc):
        raise ValueError('actual V3 frozen material changed preregistered policy/contract/task Source/deadline')
    if frame is not None:
        from .artifact_phase_postconditions_v1 import POLICY_KIND,CONTRACT_KIND
        read=CurrentDomainReadV1(frame)
        read.original(contract.policy_ref,kind='d11.life_'+POLICY_KIND,digest=contract.policy_digest)
        read.original(contract.original_ref,kind='d11.life_'+CONTRACT_KIND,digest=contract.digest)
        source=read.head(db,contract.source_head.key,required=True)
        if (source.revision,canonical_digest(source.value))!=(contract.source_head.revision,contract.source_value_digest):
            raise ValueError('V3 private phase commitment lost actual current task Source head')
    return contract


@dataclass(frozen=True, slots=True)
class CurrentArtifactTaskChoiceRequestV2:
    task: object

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
        if type(self.task) is not ArtifactDraftTaskSelectorV1:
            raise TypeError("current task choice accepts only its actual task selector")


@dataclass(frozen=True, slots=True)
class CurrentArtifactTaskPredecisionRequestsV2:
    selector: object
    ids: tuple[tuple[str, str], ...]
    goal_head: GraphVersion
    plan_head: GraphVersion
    extent_request: object
    policy_requests: tuple


@dataclass(frozen=True, slots=True)
class CurrentArtifactTaskChoiceMaterialV2:
    selector: object
    ids: tuple[tuple[str, str], ...]
    goal_head: GraphVersion
    plan_head: GraphVersion
    prepare_request: PrepareCurrentPersonalCandidatesRequestV1
    freeze_request: object
    evaluate_request: object


def artifact_task_choice_ids_v2(task, plan_head):
    CurrentArtifactTaskChoiceRequestV2(task)
    if (type(plan_head) is not GraphVersion or plan_head.revision < 1
            or plan_head.key.type_name != PLAN_TYPE or NamespaceId.from_key(plan_head.key) != task.namespace):
        raise ValueError("task choice IDs require their actual positive Plan head")
    marker = canonical_digest((task, plan_head))[:48]
    return {name: "artifact-task-" + prefix + ":" + marker for name, prefix in (
        ("extent", "extent"), ("freeze", "values-freeze"), ("candidates", "values-candidates"),
        ("context", "values-context"), ("evaluate", "values-evaluate"),
        ("prepare", "candidates-prepare"), ("select", "method-select"))}


def _readonly_current_artifact_task_choice_basis_v2(db, *, namespace, request, issuer):
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    from .ingress_artifact_task_scope_v1 import (IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3,
        ArtifactTaskObjectiveV1, task_scope_ref_v1, require_task_scope_archive_v1, _decode)
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1, artifact_task_initial_plan_candidates_v1
    from .artifact_phase_postconditions_v1 import (APPROVAL_KIND_V2,
        _standing_approval_from_wire_v2)
    if (type(request) is not CurrentArtifactTaskChoiceRequestV2 or request.task.namespace != namespace
            or type(issuer) is not D11BudgetJobIssuer):
        raise TypeError("readonly task choice needs the actual task namespace and installed D11 issuer")
    task = request.task
    scope_row = _read(db, issuer=issuer, namespace=namespace, kind="artifact_task_scope",
        ref=task_scope_ref_v1(task.root_registration_ref))
    root_row = _read(db, issuer=issuer, namespace=namespace, kind="draft_root_capability",
        ref=task.root_registration_ref)
    if scope_row is None or root_row is None:
        raise MissingProductionOriginalV1("actual_signed_task_choice_Scope_Root")
    root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
    producer = read_adopted_domain_operation_v1(db, namespace, scope_row[1])
    if producer is None or root_row[1] != scope_row[1]:
        raise MissingProductionOriginalV1("actual_same_task_choice_Scope_Root_producer")
    scope = require_task_scope_archive_v1(db, namespace=namespace, root=root, producer=producer)
    if (type(scope) not in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3} or plain_v1(scope) != scope_row[0]
            or scope.c02_operation_id != task.c02_operation_id or scope.objective_ref is None):
        raise MissingProductionOriginalV1("actual_approved_V2_initial_task_choice_scope")
    approval_row = _read(db, issuer=issuer, namespace=namespace,
        kind=APPROVAL_KIND_V2, ref=scope.approval_original_ref)
    if approval_row is None:
        raise MissingProductionOriginalV1("actual_signed_task_choice_standing_approval")
    approval = _standing_approval_from_wire_v2(approval_row[0])
    if (approval.digest != scope.approval_original_digest or approval.original_ref != scope.approval_original_ref
            or approval.scope_digest != scope.standing_policy_digest):
        raise ValueError("task choice changed its actual approved standing scope")
    objective_row = _read(db, issuer=issuer, namespace=namespace,
        kind="artifact_task_objective", ref=scope.objective_ref)
    if objective_row is None or canonical_digest(objective_row[0]) != scope.objective_digest:
        raise MissingProductionOriginalV1("actual_signed_task_choice_objective")
    objective = _decode(objective_row[0], ArtifactTaskObjectiveV1)
    revision_plan,revision_checkpoint,revision=None,None,None
    if scope.task_kind=="continue":
        revision_plan,revision_checkpoint,revision=_read_current_artifact_task_choice_revision_v2(db,
            namespace=namespace,task=task,scope=scope,objective=objective,issuer=issuer)
        keys=(AtomKey.from_token(objective.goal_ref),AtomKey.from_token(objective.plan_ref))
    else:
        keys = artifact_goal_plan_keys_v1(namespace, c02_operation_id=task.c02_operation_id,
            root_registration_ref=task.root_registration_ref)
        if (objective.initial_c02_operation_id, objective.initial_root_registration_ref,
                objective.goal_ref, objective.plan_ref) != (task.c02_operation_id, task.root_registration_ref,
                keys[0].token, keys[1].token):
            raise ValueError("task choice changed its actual initial Goal/Plan/root")
    atoms = []
    for key in keys[:2]:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (key.token, *namespace.as_tuple)).fetchone()
        if row is None or row[2] != 1:
            raise MissingProductionOriginalV1("actual_active_task_choice_Goal_Plan")
        atoms.append((GraphVersion(key, row[0]), json.loads(row[1])))
    goal_head, goal_value = atoms[0]; plan_head, plan_value = atoms[1]
    goal = _decode_goal(goal_value); plan = decode_personal_plan_type_v1(PLAN_TYPE, plan_value)
    candidates = artifact_task_initial_plan_candidates_v1(task)
    expected_nodes={node_id for _,_,node_id in candidates}
    if revision is not None:
        if plan!=revision_plan or plan_head.revision!=revision_plan.revision:
            raise MissingProductionOriginalV1("actual_current_fixed_revised_task_choice_Plan")
        expected_nodes.update(revision_checkpoint.completed_node_refs)
    if (goal.state != "active" or plan.state != "active" or plan.goal_ref != goal_head.key.token
            or plan.goal_revision != goal_head.revision or plan.actor_ref != "persona:" + namespace.persona_id
            or set(plan.method_candidates) != {(candidate, method) for method, candidate, _ in candidates}
            or set(plan.candidate_refs) != {candidate for _, candidate, _ in candidates}
            or {node.node_id for node in plan.nodes} != expected_nodes
            or {method for method, _, _ in candidates} != set(approval.scope.method_refs)):
        raise MissingProductionOriginalV1("actual_initial_two_method_task_choice_Plan")
    return scope, objective, approval, goal_head, plan_head, candidates


def _artifact_task_predecision_requests_from_basis_v2(db, *, namespace, request, issuer, basis):
    from .artifact_task_text_extent_v1 import (KIND as EXTENT_KIND,
        RegisterArtifactTaskTextExtentRequestV1, require_artifact_task_text_extent_history_v1)
    from .artifact_phase_postconditions_v1 import RegisterArtifactPhasePostconditionPolicyRequestV1
    from .d11_life_preparation_v1 import _read
    scope, objective, approval, goal_head, plan_head, candidates = basis
    rows = db.execute("SELECT original_ref FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? "
        "AND json_extract(payload_json,'$.goal_head.key')=? AND json_extract(payload_json,'$.goal_head.revision')=? "
        "AND json_extract(payload_json,'$.task_c02_operation_id')=? LIMIT 2",
        (*namespace.as_tuple, EXTENT_KIND, goal_head.key.token, goal_head.revision,request.task.c02_operation_id)).fetchall()
    policies = ()
    if rows:
        if len(rows) != 1:
            raise ValueError("task choice extent has ambiguous original registrations")
        ref = rows[0][0]
        saved = _read(db, issuer=issuer, namespace=namespace, kind=EXTENT_KIND, ref=ref)
        extent = require_artifact_task_text_extent_history_v1(db, namespace=namespace,
            original_ref=ref, producing_operation_id=saved[1], raw=saved[0])
        if (extent.goal_head, extent.task_c02_operation_id, extent.objective_ref) != (
                goal_head, request.task.c02_operation_id, scope.objective_ref):
            raise ValueError("task choice extent changed its actual Goal/task/objective")
        from .artifact_task_text_extent_v1 import ArtifactTaskTextExtentOriginalV1,ArtifactTaskTextExtentOriginalV2
        if scope.task_kind=="continue":
            if (type(extent) is not ArtifactTaskTextExtentOriginalV2 or extent.basis.task!=request.task
                    or extent.basis.plan_head!=plan_head or extent.basis.task_scope_digest!=canonical_digest(plain_v1(scope))):
                raise MissingProductionOriginalV1("actual_closed_amended_extent_for_current_revised_choice")
        elif type(extent) is not ArtifactTaskTextExtentOriginalV1:
            raise ValueError("initial task choice cannot borrow an amended extent")
        observer_ref = None
        if approval.observer_bindings:
            if len(approval.observer_bindings) != 1:
                raise ValueError("task choice requires one exact approved installed observer")
            observer_ref = approval.observer_bindings[0][0]
        policies = tuple(RegisterArtifactPhasePostconditionPolicyRequestV1(request.task, goal_head.key.token,
            plan_head.key.token, method, ref, observer_ref) for method, _, _ in candidates)
    return CurrentArtifactTaskPredecisionRequestsV2(request.task,
        tuple(artifact_task_choice_ids_v2(request.task, plan_head).items()), goal_head, plan_head,
        RegisterArtifactTaskTextExtentRequestV1(goal_head.key.token, goal_head.revision), policies)


def _artifact_task_choice_material_from_basis_v2(db, *, namespace, request, issuer, basis):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTextExtentV2, artifact_draft_phase_sequence_v2
    from .artifact_phase_postconditions_v1 import POLICY_KIND, _original
    from .artifact_task_text_extent_v1 import (KIND as EXTENT_KIND,require_artifact_task_text_extent_history_v1,
        ArtifactTaskTextExtentOriginalV2)
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_contract_v1 import DraftFileTargetV1
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    from .d06_ingress_recall_v1 import ingress_recall_need_operation_id_v1, NEED_OPERATION
    from .domain_production_inputs_v1 import FreezeCurrentValuesInputRequestV1
    from ..domains.d01.production_operations_v1 import EvaluateCurrentValuesRequestV1
    scope, objective, approval, goal_head, plan_head, candidates = basis
    pre = _artifact_task_predecision_requests_from_basis_v2(db, namespace=namespace,
        request=request, issuer=issuer, basis=basis)
    if len(pre.policy_requests) != 2:
        raise MissingProductionOriginalV1("actual_registered_task_choice_extent")
    root = scope.root
    prior=None
    target = DraftFileTargetV1(root.resource_id, root.registration_ref, canonical_digest(plain_v1(root)),
        root.root_identity, objective.filename, "create", 0, None, None, None, root.max_bytes)
    if scope.task_kind=="continue":
        original_extent=_read(db,issuer=issuer,namespace=namespace,kind=EXTENT_KIND,
            ref=pre.policy_requests[0].extent_original_ref)
        amended=require_artifact_task_text_extent_history_v1(db,namespace=namespace,
            original_ref=pre.policy_requests[0].extent_original_ref,producing_operation_id=original_extent[1],raw=original_extent[0])
        if type(amended) is not ArtifactTaskTextExtentOriginalV2 or amended.basis.root!=root:
            raise MissingProductionOriginalV1("actual_amended_extent_new_Root_for_replace")
        from .d11_artifact_draft_content_v1 import (artifact_draft_phase_verification_from_wire_v2,
            ArtifactDraftPhaseVerifiedOriginalV2,read_current_artifact_phase_verified_v2)
        from ..model_broker.artifact_draft_v1 import ArtifactDraftPriorContentCommitmentV2
        from ..runtime_contracts import VersionedRef
        saved=_read(db,issuer=issuer,namespace=namespace,kind="c4_phase_verified",ref=amended.basis.previous_verified_original_ref)
        if saved is None:raise MissingProductionOriginalV1("actual_previous_full_file_verified_for_revision_choice")
        previous=artifact_draft_phase_verification_from_wire_v2(saved[0],ArtifactDraftPhaseVerifiedOriginalV2)
        actual=read_current_artifact_phase_verified_v2(db,namespace=namespace,selector=previous.selector,issuer=issuer)
        if (actual.original_ref,actual.digest,actual.source_head,actual.source_value_digest,actual.readback)!=(
                amended.basis.previous_verified_original_ref,amended.basis.previous_verified_original_digest,
                amended.basis.previous_content_head,amended.basis.previous_content_digest,amended.basis.previous_readback):
            raise ValueError("revised candidate changed its actual complete previous file proof")
        readback=actual.readback
        target=DraftFileTargetV1(root.resource_id,root.registration_ref,canonical_digest(plain_v1(root)),root.root_identity,
            objective.filename,"replace",readback.version,readback.content_digest,readback.file_identity,readback.effect_marker,root.max_bytes)
        prior=ArtifactDraftPriorContentCommitmentV2(VersionedRef(actual.source_head.key.token,actual.source_head.revision),
            actual.source_value_digest,actual.original_ref,actual.digest,readback)
    bindings = []
    for policy_request, (method, candidate_ref, node_id) in zip(pre.policy_requests, candidates):
        rows = db.execute("SELECT original_ref FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? "
            "AND json_extract(payload_json,'$.request.task.c02_operation_id')=? "
            "AND json_extract(payload_json,'$.request.task.root_registration_ref')=? "
            "AND json_extract(payload_json,'$.request.plan_ref')=? AND json_extract(payload_json,'$.request.method_ref')=? "
            "AND json_extract(payload_json,'$.plan_head.revision')=? LIMIT 2",
            (*namespace.as_tuple, POLICY_KIND, request.task.c02_operation_id, request.task.root_registration_ref,
             plan_head.key.token, method, plan_head.revision)).fetchall()
        if len(rows) != 1:
            raise MissingProductionOriginalV1("actual_unique_registered_task_choice_method_policy")
        policy, _ = _original(db, namespace=namespace, kind=POLICY_KIND, ref=rows[0][0], issuer=issuer)
        if policy.request != policy_request or (policy.goal_head, policy.plan_head) != (goal_head, plan_head):
            raise ValueError("task choice policy changed actual Source/Goal/Plan/observer selectors")
        saved = _read(db, issuer=issuer, namespace=namespace, kind=EXTENT_KIND,
            ref=policy_request.extent_original_ref)
        extent = require_artifact_task_text_extent_history_v1(db, namespace=namespace,
            original_ref=policy_request.extent_original_ref, producing_operation_id=saved[1], raw=saved[0])
        if scope.task_kind=="continue":
            from .artifact_phase_postconditions_v1 import ArtifactPhasePostconditionPolicyOriginalV2
            if (type(policy) is not ArtifactPhasePostconditionPolicyOriginalV2 or type(extent) is not ArtifactTaskTextExtentOriginalV2
                    or (policy.task_basis_ref,policy.task_basis_digest,policy.amendment_original_ref,policy.amendment_original_digest,
                        policy.rule_source_head,policy.rule_source_digest)!=(extent.basis.original_ref,extent.basis.digest,
                        extent.basis.amendment_original_ref,extent.basis.amendment_original_digest,extent.rule_source_head,extent.rule_source_digest)
                    or (policy.source_head,policy.source_value_digest)!=(extent.basis.amendment_source_head,extent.basis.amendment_source_digest)):
                raise MissingProductionOriginalV1("actual_closed_amended_policy_basis_and_rule_for_revision_choice")
        phase_kind = artifact_draft_phase_sequence_v2(method)[0]
        bindings.append(ArtifactPhaseCandidateBindingV3(candidate_ref=candidate_ref, node_id=node_id,
            task=request.task, method_ref=method, phase_index=0, phase_kind=phase_kind,
            extent=ArtifactDraftTextExtentV2(120, 180) if phase_kind == "tone_sample" else extent.full_extent,
            target=target, prior_content=prior, activity_scope_ref=task_scope_ref_v1(root.registration_ref),
            full_extent=extent.full_extent, extent_original_ref=policy_request.extent_original_ref,
            extent_original_digest=canonical_digest(saved[0]), postcondition_policy_ref=policy.original_ref,
            postcondition_policy_digest=policy.digest))
    need = read_adopted_domain_operation_v1(db, namespace,
        ingress_recall_need_operation_id_v1(namespace, request.task.c02_operation_id))
    if need is None or (need["domain"], need["operation_kind"]) != ("d07", NEED_OPERATION):
        raise MissingProductionOriginalV1("actual_adopted_task_choice_Need")
    ids = artifact_task_choice_ids_v2(request.task, plan_head)
    prepare = PrepareCurrentPersonalCandidatesRequestV1(plan_head.key.token, goal_head.key.token,
        plan_head.revision, goal_head.revision, ids["select"], ids["evaluate"],
        "d07-current:" + need["original_digest"][:48], tuple(bindings))
    return CurrentArtifactTaskChoiceMaterialV2(request.task, tuple(ids.items()), goal_head, plan_head, prepare,
        FreezeCurrentValuesInputRequestV1(ids["candidates"], ids["context"]),
        EvaluateCurrentValuesRequestV1(ids["candidates"], ids["context"]))


def _current_artifact_task_choice_basis_v2(db, *, namespace, request, installed_readers):
    readers = _readers(installed_readers)
    graph = readers.current().graph
    if (db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()):
        raise TypeError("task choice material requires the actual installed Graph readonly snapshot")
    basis = _readonly_current_artifact_task_choice_basis_v2(db, namespace=namespace,
        request=request, issuer=readers.issuer)
    scope, _, approval, _, _, _ = basis
    installation = readers.bundle.installation_policy
    if ((scope.root.installation_id, scope.root.manifest_digest) !=
            (installation.installation_id, installation.manifest_digest)
            or approval.scope != readers.bundle.artifact_draft.standing_scope):
        raise ValueError("task choice changed its actual installed Root and approved standing scope")
    return basis


def readonly_current_artifact_task_predecision_requests_v2(db, *, namespace, request, issuer):
    """Shared signed SQL material for Authority; this function issues no permission."""
    basis = _readonly_current_artifact_task_choice_basis_v2(db, namespace=namespace, request=request, issuer=issuer)
    return _artifact_task_predecision_requests_from_basis_v2(db, namespace=namespace,
        request=request, issuer=issuer, basis=basis)


def readonly_current_artifact_task_choice_material_v2(db, *, namespace, request, issuer):
    """The exact same signed candidate material, independent of Graph reader factories."""
    basis = _readonly_current_artifact_task_choice_basis_v2(db, namespace=namespace, request=request, issuer=issuer)
    return _artifact_task_choice_material_from_basis_v2(db, namespace=namespace,
        request=request, issuer=issuer, basis=basis)


def read_current_artifact_task_predecision_requests_v2(db, *, namespace, request, installed_readers):
    basis = _current_artifact_task_choice_basis_v2(db, namespace=namespace,
        request=request, installed_readers=installed_readers)
    return _artifact_task_predecision_requests_from_basis_v2(db, namespace=namespace,
        request=request, issuer=installed_readers.issuer, basis=basis)


def read_current_artifact_task_choice_material_v2(db, *, namespace, request, installed_readers,
        postcondition_readers=None):
    basis = _current_artifact_task_choice_basis_v2(db, namespace=namespace,
        request=request, installed_readers=installed_readers)
    if postcondition_readers is not None:
        from .artifact_phase_postconditions_v1 import _readers as post_readers
        posts = post_readers(postcondition_readers)
        if posts.graph is not installed_readers.graph or posts.bundle is not installed_readers.bundle:
            raise ValueError("task choice changed its actual installed postcondition readers")
    return _artifact_task_choice_material_from_basis_v2(db, namespace=namespace,
        request=request, issuer=installed_readers.issuer, basis=basis)


def read_plan_current_artifact_task_choice_v2(db, *, namespace, request, installed_readers,
        postcondition_readers=None):
    material = read_current_artifact_task_choice_material_v2(db, namespace=namespace, request=request,
        installed_readers=installed_readers, postcondition_readers=postcondition_readers)
    return read_plan_personal_candidates_v1(db, namespace=namespace,
        activity_id=actual_personal_candidate_activity_v2(db,namespace=namespace,request=material.prepare_request,
            issuer=installed_readers.issuer), request=material.prepare_request,
        operation_id=dict(material.ids)["prepare"], installed_readers=installed_readers)


def require_current_artifact_task_choice_material_v2(db, *, frame, request, installed_readers,
        postcondition_readers=None):
    from .artifact_task_text_extent_v1 import require_current_artifact_task_text_extent_v1
    from .artifact_phase_postconditions_v1 import (require_current_artifact_phase_postcondition_policy_v1,
        authorize_current_task_predecision_v2)
    material = read_current_artifact_task_choice_material_v2(db,
        namespace=frame.envelope.authority.namespace, request=request, installed_readers=installed_readers,
        postcondition_readers=postcondition_readers)
    read = CurrentDomainReadV1(frame); read.check(db)
    _plan_goal(db, read, material.prepare_request, installed_readers=_readers(installed_readers))
    for binding in material.prepare_request.bindings:
        authorize_current_task_predecision_v2(db, frame=frame, task=request.task,
            operation="prepare_personal_candidates_v1", method_ref=binding.method_ref,
            installed_readers=installed_readers if postcondition_readers is None else postcondition_readers)
        _read_phase_task_scope_facts_v1(db, read, _readers(installed_readers), binding)
        require_current_artifact_task_text_extent_v1(db, frame=frame, binding=binding,
            goal_ref=material.goal_head.key.token, installed_readers=installed_readers)
        require_current_artifact_phase_postcondition_policy_v1(db, frame=frame, binding=binding,
            goal_ref=material.goal_head.key.token, plan_ref=material.plan_head.key.token,
            installed_readers=installed_readers if postcondition_readers is None else postcondition_readers)
    return material



def _read_current_artifact_task_choice_revision_v2(db,*,namespace,task,scope,objective,issuer):
    from .d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2,require_artifact_task_plan_revision_original_v2
    from .artifact_task_amendment_v1 import read_current_amendment_v1
    from .jobs import get_job
    from .d11_types import job_graph_write
    revision=read_adopted_domain_operation_v1(db,namespace,artifact_task_plan_revision_operation_id_v2(task))
    plan,checkpoint=require_artifact_task_plan_revision_original_v2(db,namespace=namespace,original=revision)
    actual=read_current_amendment_v1(db,namespace=namespace,root_registration_ref=task.root_registration_ref,issuer=issuer)
    if actual is None:raise MissingProductionOriginalV1("actual_ordinary_amendment_for_revised_choice")
    amendment,ref,_=actual;p=revision["payload"]["provenance"]
    if (scope.task_kind!="continue" or amendment.c02_operation_id!=task.c02_operation_id
            or (amendment.objective_ref,amendment.objective_digest)!=(scope.objective_ref,scope.objective_digest)
            or (p["amendment_original_ref"],p["amendment_original_digest"],p["task_scope_ref"],p["task_scope_digest"])!=
                (ref,canonical_digest(plain_v1(amendment)),amendment.task_scope_ref,amendment.task_scope_digest)
            or (plan.goal_ref,amendment.goal_ref,checkpoint.project_ref)!=(objective.goal_ref,objective.goal_ref,objective.project_ref)
            or (scope.root.resource_id,scope.root.root_identity,amendment.filename)!=(objective.root_resource_id,objective.root_identity,objective.filename)):
        raise ValueError("continued choice changed its exact fixed revision or stable task/file identity")
    for ref,revision_number,digest in ((scope.source_ref,scope.source_revision,scope.source_digest),
            (scope.root.owner_grant_ref,scope.root.owner_grant_revision,scope.root.owner_grant_digest)):
        row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*namespace.as_tuple,ref)).fetchone()
        if row is None or row[2]!=1 or (row[0],canonical_digest(json.loads(row[1])))!=(revision_number,digest):
            raise MissingProductionOriginalV1("current_revised_choice_Source_Owner")
    cycle=get_job(db,AtomKey.from_token(task.cycle_job_ref).name)
    atom=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
        (*namespace.as_tuple,task.cycle_job_ref)).fetchone()
    if ((cycle.bot_id,cycle.persona_id)!=namespace.as_tuple or atom is None or atom[2]!=1
            or json.loads(atom[1])!=job_graph_write(cycle).value):
        raise MissingProductionOriginalV1("actual_current_revised_choice_cycle")
    return plan,checkpoint,revision


def actual_personal_candidate_activity_v2(db,*,namespace,request,issuer):
    if type(request) is not PrepareCurrentPersonalCandidatesRequestV1:
        raise TypeError("actual candidate activity requires its precise preparation request")
    plan_key=AtomKey.from_token(request.plan_ref)
    artifacts=tuple(b for b in request.bindings if type(b) is ArtifactPhaseCandidateBindingV3)
    if not artifacts:return plan_key.owner.subject
    tasks={b.task for b in artifacts}
    if len(tasks)!=1:raise ValueError("one actual task activity cannot mix artifact task selectors")
    task=next(iter(tasks))
    scope,_,_,goal_head,plan_head,_=_readonly_current_artifact_task_choice_basis_v2(db,namespace=namespace,
        request=CurrentArtifactTaskChoiceRequestV2(task),issuer=issuer)
    if scope.task_kind!="continue":return plan_key.owner.subject
    if (plan_head.key.token,plan_head.revision,goal_head.key.token,goal_head.revision)!=(
            request.plan_ref,request.expected_plan_revision,request.goal_ref,request.expected_goal_revision):
        raise ValueError("revised candidate activity changed its actual Plan/Goal head")
    return AtomKey.from_token(task.cycle_job_ref).owner.subject



def readonly_current_artifact_task_choice_checkpoint_delta_v2(db,*,namespace,selector,issuer,prepared_candidates):
    from .d11_life_preparation_v1 import _read
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1,IngressArtifactTaskScopeOriginalV1,_decode
    from .d08_personal_plan_v1 import artifact_task_plan_revision_operation_id_v2,require_artifact_task_plan_revision_original_v2
    from .d10_project_checkpoint_v1 import (artifact_task_checkpoint_activation_operation_id_v2,
        readonly_current_artifact_task_checkpoint_activation_facts_v2)
    from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
    first=replace(selector,phase_index=0,phase_kind=artifact_draft_phase_sequence_v2(selector.method_ref)[0],
        prev_phase_original_ref=None,prev_phase_original_digest=None)
    row=_read(db,issuer=issuer,namespace=namespace,kind="artifact_task_scope",ref=task_scope_ref_v1(first.task.root_registration_ref))
    if row is None:raise MissingProductionOriginalV1("actual_TaskScope_for_selected_checkpoint_delta")
    scope=_decode(row[0],IngressArtifactTaskScopeOriginalV1)
    if scope.task_kind!="continue":return None
    revision=read_adopted_domain_operation_v1(db,namespace,artifact_task_plan_revision_operation_id_v2(first.task))
    plan,_=require_artifact_task_plan_revision_original_v2(db,namespace=namespace,original=revision)
    origin=read_adopted_domain_operation_v1(db,namespace,prepared_candidates.preparation_operation_id)
    if (origin is None or origin["payload"]["provenance"].get("prepared_candidates")!=plain_v1(prepared_candidates)
            or (prepared_candidates.plan_head.key.token,prepared_candidates.plan_head.revision)!=(first.plan_ref,first.plan_revision)
            or canonical_digest(plain_v1(plan))!=first.plan_digest):
        raise ValueError("checkpoint delta changed actual selected preparation or fixed revision")
    activated=read_adopted_domain_operation_v1(db,namespace,artifact_task_checkpoint_activation_operation_id_v2(first))
    if activated is None:return None
    facts=readonly_current_artifact_task_checkpoint_activation_facts_v2(db,namespace=namespace,selector=first,issuer=issuer)
    before,after,digest,operation_id,original_digest,node=facts
    if tuple(v for v in prepared_candidates.read_versions if v.key==before.key)!=(before,):
        raise MissingProductionOriginalV1("exact_prepared_checkpoint_before_selected_revision_activation")
    return facts


def _current_artifact_choice_checkpoint_projections_v2(db,*,read,selector,readers,prepared_candidates):
    facts=readonly_current_artifact_task_choice_checkpoint_delta_v2(db,namespace=selector.task.namespace,
        selector=selector,issuer=readers.issuer,prepared_candidates=prepared_candidates)
    if facts is None:return (),()
    before,after,digest,operation_id,original_digest,_=facts
    row=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",(before.key.token,before.revision)).fetchone()
    if row is None or row[1]!=1:raise MissingProductionOriginalV1("actual_revision_checkpoint_before_history")
    from ..graph_types import GraphAtom
    previous=GraphAtom(before.key,before.revision,json.loads(row[0]),True)
    current=read.head(db,after.key,required=True)
    if current.revision!=after.revision or canonical_digest(current.value)!=digest:
        raise MissingProductionOriginalV1("actual_exact_selected_checkpoint_after_snapshot")
    read.original("d10-current:"+original_digest[:48],kind="d10.current-activate_artifact_task_project_checkpoint_v2",digest=original_digest)
    return ((previous,after,digest),),((operation_id,original_digest),)


def _selected_candidate_phase_selector_from_originals_v2(db,*,namespace,request,issuer):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
    if type(request) is not ConsumePersonalDecisionRequestV1:return None
    origin=read_adopted_domain_operation_v1(db,namespace,request.prepared_candidates_operation_id)
    if origin is None:raise MissingProductionOriginalV1("actual_selected_checkpoint_candidate_preparation")
    candidates=decode_typed_production_value_v1(origin["payload"]["provenance"]["prepared_candidates"],PreparedPersonalCandidateSetV1)
    row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
        (*namespace.as_tuple,request.decision_ref)).fetchone()
    if row is None or row[2]!=1:raise MissingProductionOriginalV1("actual_selected_checkpoint_Decision")
    decision=json.loads(row[1]);chosen=tuple(c for c in candidates.candidates if c.future_identity.action_ref==decision["chosen_action_ref"])
    if len(chosen)!=1 or type(chosen[0].binding) is not ArtifactPhaseCandidateBindingV3:return None
    b=chosen[0].binding
    plan_value=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
        (candidates.plan_head.key.token,candidates.plan_head.revision)).fetchone()
    if plan_value is None or plan_value[1]!=1:raise MissingProductionOriginalV1("actual_selected_checkpoint_Plan_history")
    return ArtifactDraftPhaseSelectorV2(task=b.task,decision_ref=request.decision_ref,decision_revision=row[0],
        decision_digest=canonical_digest(decision),plan_ref=candidates.plan_head.key.token,
        plan_revision=candidates.plan_head.revision,plan_digest=canonical_digest(json.loads(plan_value[0])),
        method_ref=b.method_ref,phase_index=b.phase_index,phase_kind=b.phase_kind,
        prev_phase_original_ref=b.prev_phase_original_ref,prev_phase_original_digest=b.prev_phase_original_digest)


def _selected_candidate_phase_selector_v2(db,*,frame,request,readers):
    return _selected_candidate_phase_selector_from_originals_v2(db,namespace=frame.envelope.authority.namespace,
        request=request,issuer=readers.issuer)


def _reconstruct_selected_artifact_phase_transition_v2(db,*,frame,request,phase_selector,readers):
    from .d11_artifact_draft_model_v1 import _read_artifact_phase_selected_originals_v2,_artifact_phase_selection_locator_v2
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2,artifact_draft_file_ids_v2
    from .d11_life_preparation_v1 import TABLE
    from .jobs import get_job
    from .d11_types import job_graph_write,runtime_job_key
    graph=readers.current().graph
    if db is not graph._GraphCoordinator__store._db or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned():
        raise TypeError("selected transition requires the actual installed Graph transaction")
    read=CurrentDomainReadV1(frame);read.check(db)
    located,selection,decision=_artifact_phase_selection_locator_v2(db,phase_selector)
    if located!=request:raise ValueError("selected transition changed the actual adopted Decision locator")
    candidates,chosen,origin=_read_artifact_phase_selected_originals_v2(db,selector=phase_selector,issuer=readers.issuer)
    ids=artifact_draft_model_ids_v2(phase_selector);file_ids=artifact_draft_file_ids_v2(phase_selector)
    # Absence is proved for every deterministic once member; an orphan is never first preparation.
    references=tuple(ids.values())
    placeholders=",".join("?" for _ in references)
    if (read_adopted_domain_operation_v1(db,phase_selector.task.namespace,ids["prepare"]) is not None
            or db.execute("SELECT 1 FROM "+TABLE+" WHERE bot=? AND persona=? AND original_ref IN ("+placeholders+") LIMIT 1",
                (*phase_selector.task.namespace.as_tuple,*references)).fetchone() is not None
            or db.execute("SELECT 1 FROM runtime_jobs WHERE job_id=?",(ids["job"],)).fetchone() is not None
            or db.execute("SELECT 1 FROM runtime_job_operations WHERE bot_id=? AND persona_id=? AND (job_id=? OR operation_id IN (?,?)) LIMIT 1",
                (*phase_selector.task.namespace.as_tuple,ids["job"],ids["prepare"],"create:"+ids["prepare"])).fetchone() is not None
            or db.execute("SELECT 1 FROM runtime_budget_reservations WHERE operation_id=? LIMIT 1",(ids["prepare"],)).fetchone() is not None
            or db.execute("SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? LIMIT 1",
                (*phase_selector.task.namespace.as_tuple,ids["prepare"])).fetchone() is not None):
        raise MissingProductionOriginalV1("exact_first_phase_model_prepare_job_reservation_all_absent")
    model_key=runtime_job_key(*phase_selector.task.namespace.as_tuple,file_ids["activity_id"],ids["job"])
    if read.head(db,model_key).revision:
        raise MissingProductionOriginalV1("exact_first_phase_model_Graph_job_absent")
    current=read.head(db,phase_selector.task.cycle_job_ref,required=True)
    cycle=get_job(db,AtomKey.from_token(phase_selector.task.cycle_job_ref).name)
    if (current.value!=job_graph_write(cycle).value or cycle.phase!="running" or cycle.lease_holder!=frame.envelope.authority.actor
            or cycle.budget_ref!=frame.envelope.parent_budget_lease_ref):
        raise MissingProductionOriginalV1("actual_running_selected_phase_current_cycle_Self_budget")
    from ..domains.d03.self_perspective import self_mapping_key,SelfIdentityMapping
    mapping_atom=read.head(db,self_mapping_key(phase_selector.task.namespace),required=True)
    mapping=SelfIdentityMapping(**mapping_atom.value)
    if mapping.status!="active" or mapping.self_entity_ref!=frame.envelope.authority.actor:
        raise MissingProductionOriginalV1("actual_current_selected_phase_Self_mapping")
    plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,candidates.plan_head.key,required=True).value)
    _artifact_scope(db,read,readers,chosen.binding,plan)
    require_budget_family_admissible(db,cycle.budget_ref)
    grant=readers.issuer.current_budget_grant(db,cycle.budget_ref);lease=get_budget_lease(db,cycle.budget_ref)
    if lease.state!="active" or frame.now_utc>=min(candidates.need.original_deadline_utc,grant.valid_until_utc):
        raise MissingProductionOriginalV1("actual_current_selected_phase_unextended_budget_deadline")
    projections,checkpoint_origins=_current_artifact_choice_checkpoint_projections_v2(db,read=read,selector=phase_selector,
        readers=readers,prepared_candidates=candidates)
    read.original("d08-current:"+origin["original_digest"][:48],kind="d08.current-"+PREPARE_OPERATION_V1,digest=origin["original_digest"])
    return SelectedArtifactPhaseTransitionV2(_PHASE_TRANSITION_KEY,graph=graph,frame=frame,readers=readers,request=request,
        phase_selector=phase_selector,candidate_original_digest=origin["original_digest"],prepared_candidates=candidates,
        selected_binding_digest=chosen.binding.digest,decision_digest=phase_selector.decision_digest,after_cycle=cycle,
        snapshot_digest=canonical_digest(plain_v1(frame.snapshot)),projections=projections,
        producer_originals=((origin["receipt"].operation_id,origin["original_digest"]),
            (selection["receipt"].operation_id,selection["original_digest"]),*checkpoint_origins))
