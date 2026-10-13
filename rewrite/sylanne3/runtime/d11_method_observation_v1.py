"""D11 actual settled-phase billing observations; no caller-supplied metrics or benefit."""
from dataclasses import dataclass, fields
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d01.method_learning_v1 import (MethodExperimentPlanV1, MethodEvaluationProtocolV1,
    MethodScopedTrialV1, MethodMetricsV1, MethodComparisonObservationV2,
    EXPERIMENT_TYPE, PROTOCOL_TYPE, TRIAL_TYPE, BASELINE_METHOD, TRIAL_METHOD)
from ..graph_types import AtomKey, GraphWrite, owner_grant_key
from ..memory_types import SourceRecord, source_key, access_key, validate_access
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d01_production_operations_v1 import (CurrentDomainReadV1, MissingProductionOriginalV1,
    waiting_stage_v1, production_read_plan_v1)
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .d11_life_preparation_v1 import _read, _record

OPERATION = "observe_method_comparison_v1"
KIND = "method_comparison_observation"
POLICY_SCHEMA = "d11.method-measurement-policy.v1"
ALGORITHM = "treatment_settled_phase_token_sum.v1"
METRICS = ("model_input_tokens", "model_output_tokens")
_READERS_KEY = object()


@dataclass(frozen=True, slots=True)
class MethodMeasurementPolicyV1:
    policy_ref: str
    policy_version: int
    billing_policy_digest: str
    algorithm: str = ALGORITHM
    measured_metrics: tuple[str, ...] = METRICS
    schema: str = POLICY_SCHEMA

    def __post_init__(self):
        if (self.schema != POLICY_SCHEMA or type(self.policy_ref) is not str or not 1 <= len(self.policy_ref) <= 4096
                or type(self.policy_version) is not int or self.policy_version < 1
                or self.algorithm != ALGORITHM or self.measured_metrics != METRICS
                or type(self.billing_policy_digest) is not str or len(self.billing_policy_digest) != 64
                or any(char not in "0123456789abcdef" for char in self.billing_policy_digest)):
            raise ValueError("only the explicit installed treatment settled-token measurement policy is supported")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def method_measurement_policy_from_payload_v1(raw):
    if raw is None:
        return None
    if type(raw) is not dict or set(raw) != {field.name for field in fields(MethodMeasurementPolicyV1)}:
        raise ValueError("closed optional initial method measurement policy required")
    value = dict(raw)
    if type(value["measured_metrics"]) is not list:
        raise ValueError("method measured metrics require the explicit frozen list")
    value["measured_metrics"] = tuple(value["measured_metrics"])
    return MethodMeasurementPolicyV1(**value)


@dataclass(frozen=True, slots=True)
class ObserveMethodComparisonRequestV1:
    experiment_ref: str
    treatment_milestone_ref: str
    baseline_milestone_ref: str

    def __post_init__(self):
        if AtomKey.from_token(self.experiment_ref).type_name != EXPERIMENT_TYPE:
            raise ValueError("actual prospective method experiment selector required")
        if (self.treatment_milestone_ref == self.baseline_milestone_ref
                or any(type(ref) is not str or not 1 <= len(ref) <= 4096
                    for ref in (self.treatment_milestone_ref, self.baseline_milestone_ref))):
            raise ValueError("two distinct actual method milestone originals required")


class InstalledMethodObservationReadersV1:
    def __init__(self, key, *, graph, bundle, issuer):
        if key is not _READERS_KEY:
            raise TypeError("method observations require the actual installed Graph factory")
        self.graph, self.bundle, self.issuer = graph, bundle, issuer

    def current(self):
        assembly = self.graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise MissingProductionOriginalV1("actual_installed_method_measurement_assembly")
        if assembly.admin_bundle is not self.bundle or assembly.installation_policy is not self.bundle.installation_policy:
            raise ValueError("method measurement changed its actual installed assembly")
        policy = self.bundle.method_measurement_policy
        if policy is None:
            raise MissingProductionOriginalV1("actual_installed_method_measurement_policy_and_billing")
        billing = self.bundle.provider_billing_policy_v1
        if (type(policy) is not MethodMeasurementPolicyV1 or billing is None
                or policy.billing_policy_digest != canonical_digest(plain_v1(billing))):
            raise ValueError("method measurement changed its installed typed policy or billing commitment")
        if (billing.namespace, billing.installation_id, billing.manifest_digest) != (
                self.bundle.installation_policy.namespace, self.bundle.installation_policy.installation_id,
                self.bundle.installation_policy.manifest_digest):
            raise ValueError("method measurement billing crossed actual installed identity")
        return policy


def install_method_observation_readers_v1(graph, *, scope, owner_guard, owner_binding=None):
    from ..graph_coordinator import GraphCoordinator
    if type(graph) is not GraphCoordinator:
        raise TypeError("actual GraphCoordinator method observation reader required")
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is None or scope.namespace != assembly.installation_policy.namespace:
        raise MissingProductionOriginalV1("actual_installed_method_observation_namespace")
    return InstalledMethodObservationReadersV1(_READERS_KEY, graph=graph, bundle=assembly.admin_bundle,
        issuer=graph._GraphCoordinator__d11_issuer)


@dataclass(frozen=True, slots=True)
class MethodObservationStageV1:
    stage: object
    memory_stage: object
    observation: MethodComparisonObservationV2


def _actual_head(db, *, read, ref, cls, operation):
    atom = read.head(db, ref, required=True)
    value = decode_typed_production_value_v1(atom.value, cls)
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (atom.key.token, atom.revision)).fetchone()
    if history is None or history[1:] != (canonical_serialize(atom.value), 1):
        raise MissingProductionOriginalV1("actual_method_measurement_head_history")
    original = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, history[0])
    accepted_operations = ({"register_scoped_method_trial_v1", "register_scoped_method_trial_v2"}
        if operation == "register_scoped_method_trial_v1" else
        {"register_method_experiment_v1", "register_method_experiment_v2"}
        if operation == "register_method_experiment_v1" else {operation})
    if (original is None or original["domain"] != "d01" or original["operation_kind"] not in accepted_operations
            or not any(version.key == atom.key and version.revision == atom.revision for version in original["receipt"].write_versions)):
        raise MissingProductionOriginalV1("actual_registered_method_measurement_input:" + operation)
    read.original(ref)
    return atom, value, original


def _actual_pair(db, *, read, request, readers):
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    namespace = read.frame.envelope.authority.namespace
    experiment_atom, experiment, original = _actual_head(db, read=read, ref=request.experiment_ref,
        cls=MethodExperimentPlanV1, operation="register_method_experiment_v1")
    _, trial, _ = _actual_head(db, read=read, ref=experiment.trial_ref,
        cls=MethodScopedTrialV1, operation="register_scoped_method_trial_v1")
    protocol_atom, protocol, _ = _actual_head(db, read=read, ref=experiment.protocol_ref,
        cls=MethodEvaluationProtocolV1, operation="register_method_evaluation_protocol_v1")
    policy = readers.current()
    pins = tuple(item for item in read.frame.installed_policy_refs if item.policy_ref == policy.policy_ref)
    if len(pins) != 1 or (pins[0].revision, pins[0].policy_digest) != (policy.policy_version, policy.digest):
        raise MissingProductionOriginalV1("actual_frame_installed_method_measurement_policy_pin")
    if (experiment.namespace != namespace or trial.namespace != namespace or protocol.namespace != namespace
            or experiment.protocol_digest != canonical_digest(protocol_atom.value)
            or trial.protocol_ref != experiment.protocol_ref or trial.protocol_digest != experiment.protocol_digest
            or experiment.treatment_goal_ref not in trial.goal_refs
            or (protocol.observer_policy_ref, protocol.observer_policy_digest) != (policy.policy_ref, policy.digest)):
        raise ValueError("method experiment changed its real protocol/trial/installed observer")
    if (not protocol.valid_from <= read.frame.now_utc < protocol.valid_until
            or read.frame.now_utc >= experiment.valid_until):
        raise MissingProductionOriginalV1("original_current_method_observation_protocol_deadline")
    pair = tuple(read_current_artifact_task_milestone_v2(db, namespace=namespace,
        original_ref=ref, issuer=readers.issuer) for ref in (request.treatment_milestone_ref, request.baseline_milestone_ref))
    treatment, baseline = pair
    if (treatment.goal_ref, baseline.goal_ref, treatment.selector.method_ref, baseline.selector.method_ref) != (
            experiment.treatment_goal_ref, experiment.baseline_goal_ref, TRIAL_METHOD, BASELINE_METHOD):
        raise ValueError("measurement compared another actual experiment task/method")
    for value in pair:
        read.head(db, value.source_head.key, required=True)
        read.original(value.original_ref, kind="d11.life_artifact_task_milestone_v2", digest=value.digest)
        for ref, digest in value.ordered_phase_originals:
            saved = _read(db, issuer=readers.issuer, namespace=namespace, kind="c4_phase_verified", ref=ref)
            produced = None if saved is None else read_adopted_domain_operation_v1(db, namespace, saved[1])
            if produced is None or produced["receipt"].commit_seq <= original["receipt"].commit_seq:
                raise ValueError("method measurement experiment was not frozen before its outcomes")
            read.original(ref, kind="d11.life_c4_phase_verified", digest=digest)
    return experiment_atom, experiment, pair, policy, original["receipt"].commit_seq


def _measurement_budget_lineage_v1(db, *, read, own_lease_ref, parent_lease_ref, issuer):
    from .budget import get_budget_lease
    namespace = read.frame.envelope.authority.namespace
    if db.execute("SELECT 1 FROM runtime_budget_leases WHERE lease_id=?", (own_lease_ref,)).fetchone() is None:
        raise MissingProductionOriginalV1("actual_method_own_budget_lease")
    own = get_budget_lease(db, own_lease_ref)
    if (own.bot_id, own.persona_id) != namespace.as_tuple:
        raise ValueError("actual method phase budget crossed namespace")
    if own_lease_ref == parent_lease_ref:
        return ()
    lineage, seen, current = [], set(), own_lease_ref
    while current is not None:
        if current in seen:
            raise ValueError("actual method budget lineage is cyclic")
        seen.add(current)
        if db.execute("SELECT 1 FROM runtime_budget_leases WHERE lease_id=?", (current,)).fetchone() is None:
            raise MissingProductionOriginalV1("actual_method_budget_parent_lease")
        lease = get_budget_lease(db, current)
        if len(lineage) >= read.frame.limits.max_query_rows:
            raise MissingProductionOriginalV1("bounded_actual_method_budget_lineage")
        if (lease.bot_id, lease.persona_id, lease.currency) != (*namespace.as_tuple, own.currency):
            raise ValueError("actual method budget ancestry crossed namespace or currency")
        created = db.execute("SELECT operation_id,digest,receipt_json FROM runtime_budget_operations "
            "WHERE bot_id=? AND persona_id=? AND lease_id=? AND phase='create'",
            (*namespace.as_tuple, lease.lease_id)).fetchall()
        grant_row = db.execute("SELECT version FROM runtime_budget_grants WHERE lease_id=? ORDER BY version LIMIT 1",
            (lease.lease_id,)).fetchone()
        if len(created) != 1 or grant_row is None:
            raise MissingProductionOriginalV1("actual_created_and_signed_method_budget_lineage")
        grant, _ = issuer.signed_budget_grant_at_version(db, lease.lease_id, grant_row[0])
        if ((grant.bot_id, grant.persona_id, grant.currency) != (*namespace.as_tuple, own.currency)
                or any(amount > lease.limits.get(name, 0) for name, amount in grant.max_ceiling.items())):
            raise ValueError("actual associated lineage grant changed its created lease identity")
        creation = json.loads(created[0][2])
        if (creation["lease_id"] != lease.lease_id or creation["operation_id"] != created[0][0]
                or creation["digest"] != created[0][1] or creation["status"] != "created"):
            raise ValueError("method budget creation original changed its own identity")
        lineage.append({"lease_ref": lease.lease_id, "parent_lease_ref": lease.parent_id,
            "currency": lease.currency, "creation_operation_id": created[0][0],
            "creation_request_digest": created[0][1], "creation_receipt_digest": canonical_digest(creation),
            "associated_grant_ref": grant.grant_id, "associated_grant_version": grant.version,
            "associated_grant_digest": canonical_digest(plain_v1(grant))})
        if lease.lease_id == parent_lease_ref:
            return tuple(lineage)
        current = lease.parent_id
    raise MissingProductionOriginalV1("actual_method_phase_budget_descendant_of_frozen_experiment")


def _generation_billing_group_v1(db, *, read, milestone, readers, parent_budget_lease_ref, experiment_commit_seq, shared_input):
    from .d11_artifact_draft_content_v1 import artifact_draft_phase_verification_from_wire_v2, ArtifactDraftPhaseVerifiedOriginalV2
    from .d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v2, read_artifact_draft_model_request_v2,
        decode_artifact_draft_original_v2)
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    from ..model_broker.provider_billing_receipt_v1 import verify_provider_billing_receipt_v1
    from dataclasses import asdict
    namespace = read.frame.envelope.authority.namespace
    rows, supports, source_roots = [], [], []
    for ref, digest in milestone.ordered_phase_originals:
        saved = _read(db, issuer=readers.issuer, namespace=namespace, kind="c4_phase_verified", ref=ref)
        if saved is None:
            raise MissingProductionOriginalV1("actual_complete_method_phase_verification")
        verified = artifact_draft_phase_verification_from_wire_v2(saved[0], ArtifactDraftPhaseVerifiedOriginalV2)
        if canonical_digest(saved[0]) != digest:
            raise ValueError("method ordered phase verification changed its actual commitment")
        source_head = read.head(db, verified.source_head.key, required=True)
        if source_head.revision != verified.source_head.revision or canonical_digest(source_head.value) != verified.source_value_digest:
            raise MissingProductionOriginalV1("actual_current_method_phase_output_source")
        source_roots.append(verified.source_head.key.token)
        supports.append(ref)
        if verified.selector.phase_kind not in {"tone_sample", "full"}:
            continue
        selector = verified.content_selector
        prepared = read_artifact_draft_prepared_v2(db, namespace=namespace, issuer=readers.issuer, selector=selector)
        if prepared is None:
            raise MissingProductionOriginalV1("actual_method_generation_preparation")
        preparation = read_adopted_domain_operation_v1(db, namespace, prepared.operation_id)
        if (preparation is None or (preparation["domain"], preparation["operation_kind"]) != ("d11", "prepare_artifact_draft_model_v2")
                or preparation["receipt"].commit_seq <= experiment_commit_seq):
            raise MissingProductionOriginalV1("actual_prospective_experiment_before_generation_preparation")
        lineage = _measurement_budget_lineage_v1(db, read=read, own_lease_ref=prepared.parent_budget_lease_ref,
            parent_lease_ref=parent_budget_lease_ref, issuer=readers.issuer)
        frozen_original = _read(db, issuer=readers.issuer, namespace=namespace,
            kind="c4_phase_frozen", ref=prepared.frozen_ref)
        if frozen_original is None or canonical_digest(frozen_original[0]) != prepared.frozen_digest:
            raise MissingProductionOriginalV1("actual_method_generation_frozen_input")
        frozen = decode_artifact_draft_original_v2("c4_phase_frozen", frozen_original[0])
        if frozen.selector != selector:
            raise ValueError("method generation frozen input changed its actual phase")
        if shared_input is not None:
            task = tuple(value for value in shared_input.tasks if value.goal_head.key.token == milestone.goal_ref)
            common = tuple(source for source in frozen.sources if source.ref == shared_input.common_source_head.key.token)
            if (len(task) != 1 or task[0].c02_operation_id != selector.task.c02_operation_id
                    or len(common) != 1 or (common[0].revision, common[0].value_digest) != (
                        shared_input.common_source_head.revision, shared_input.common_source_digest)):
                raise MissingProductionOriginalV1("actual_paid_phase_consumed_registered_common_method_input")
        read.original(prepared.frozen_ref, kind="d11.life_c4_phase_frozen", digest=prepared.frozen_digest)
        source_roots.extend(source.ref for source in frozen.sources)
        supports.append(prepared.frozen_ref)
        request = read_artifact_draft_model_request_v2(db, prepared=prepared, issuer=readers.issuer)
        if request.envelope.parent_budget_lease_ref != prepared.parent_budget_lease_ref:
            raise ValueError("actual acquired method model request changed its own paying lease")
        ids = artifact_draft_model_ids_v2(selector)
        originals = {kind: _read(db, issuer=readers.issuer, namespace=namespace, kind="c4_phase_" + kind, ref=ids[kind])
            for kind in ("paid", "result")}
        if any(value is None for value in originals.values()):
            raise MissingProductionOriginalV1("actual_method_generation_paid_and_result_originals")
        paid = decode_artifact_draft_original_v2("c4_phase_paid", originals["paid"][0])
        result = decode_artifact_draft_original_v2("c4_phase_result", originals["result"][0])
        observation = result.observation
        if (paid.status != "committed" or paid.call_id != prepared.call_id
                or observation.status != "completed" or observation.call_id != prepared.call_id
                or paid.terminal_receipt_digest != canonical_digest(asdict(result.terminal_receipt))
                or observation.billing_receipt_json is None):
            raise MissingProductionOriginalV1("actual_complete_settled_method_generation_billing")
        bill = verify_provider_billing_receipt_v1(readers.bundle.provider_billing_policy_v1,
            request=request, provider_call_ref=observation.provider_call_ref, response_model=request.model_id,
            usage=dict(observation.usage), raw=json.loads(observation.billing_receipt_json))
        quote = readers.issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, paid.quote_version)
        if (paid.quote_id != prepared.quote_id or canonical_digest(quote) != prepared.quote_digest
                or quote.parent_budget_lease_ref != prepared.parent_budget_lease_ref
                or quote.operation_id != prepared.operation_id):
            raise ValueError("actual settled method quote changed its own original phase and budget")
        reservation = db.execute("SELECT state,actual_json,digest,ceiling_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
            (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone()
        settled = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase='settle'",
            (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchall()
        if reservation is None or reservation[0] != "settled" or len(settled) != 1:
            raise MissingProductionOriginalV1("actual_once_settled_method_phase_reservation")
        if (reservation[2] != prepared.reservation_digest
                or json.loads(reservation[3]) != dict(quote.ceiling)
                or paid.budget_receipt_digest != canonical_digest(json.loads(settled[0][0]))):
            raise ValueError("method measurement changed its original once reservation or paid settlement")
        actual = json.loads(reservation[1])
        if (actual.get("input_tokens"), actual.get("output_tokens"), actual.get("model_microusd")) != (
                bill.input_tokens, bill.output_tokens, bill.final_charged_amount):
            raise ValueError("method billing measurement differs from its actual budget settlement")
        for kind in ("paid", "result"):
            read.original(ids[kind], kind="d11.life_c4_phase_" + kind, digest=canonical_digest(originals[kind][0]))
        supports.extend((ids["paid"], ids["result"], prepared.job_id, ids["request"]))
        read.original(prepared.job_id, kind="d11.life_c4_phase_prepared")
        read.original(ids["request"], kind="d11.life_c4_phase_request")
        rows.append({"call_ref": prepared.call_id, "paid_ref": ids["paid"], "paid_digest": canonical_digest(originals["paid"][0]),
            "result_ref": ids["result"], "result_digest": canonical_digest(originals["result"][0]),
            "provider_receipt_digest": canonical_digest(bill.to_wire()), "evidence_kind": bill.evidence_kind,
            "input_tokens": bill.input_tokens, "output_tokens": bill.output_tokens,
            "lease_ref": prepared.parent_budget_lease_ref, "reservation_operation_id": prepared.operation_id,
            "authorization_basis": "actual_prepared_producer", "budget_lineage": lineage,
            "settlement_receipt_digest": canonical_digest(json.loads(settled[0][0]))})
    calls = tuple(sorted(row["call_ref"] for row in rows))
    if not calls or len(calls) != len(set(calls)) or len(rows) > 8:
        raise ValueError("each actual generation phase has exactly one distinct settled call")
    return tuple(sorted(rows, key=lambda row: row["call_ref"])), calls, tuple(sorted(set(supports))), tuple(sorted(set(source_roots)))


def _measurement_source_identity_v1(namespace, experiment_ref, pair, calls):
    family = "method-billing-family:" + canonical_digest(calls)
    identity = "method-measurement:" + canonical_digest((namespace, experiment_ref,
        tuple(value.digest for value in pair), calls))[:48]
    return family, identity, source_key(*namespace.as_tuple, identity), access_key(*namespace.as_tuple, identity)


def _derive_observation_v1(db, *, read, request, readers):
    experiment_atom, experiment, pair, policy, experiment_commit_seq = _actual_pair(db, read=read, request=request, readers=readers)
    from .method_pair_shared_input_v1 import read_method_pair_shared_input_original_v1
    declared_pair = read_method_pair_shared_input_original_v1(db,
        namespace=read.frame.envelope.authority.namespace, experiment_ref=request.experiment_ref)
    shared_input = None if declared_pair is None else declared_pair[0]
    treatment_rows, treatment_calls, treatment_supports, treatment_sources = _generation_billing_group_v1(db, read=read, milestone=pair[0], readers=readers, parent_budget_lease_ref=experiment.parent_budget_lease_ref, experiment_commit_seq=experiment_commit_seq, shared_input=shared_input)
    baseline_rows, baseline_calls, baseline_supports, baseline_sources = _generation_billing_group_v1(db, read=read, milestone=pair[1], readers=readers, parent_budget_lease_ref=experiment.parent_budget_lease_ref, experiment_commit_seq=experiment_commit_seq, shared_input=shared_input)
    if set(treatment_calls) & set(baseline_calls):
        raise ValueError("baseline and treatment cannot borrow the same actual paid call")
    kinds = {row["evidence_kind"] for row in (*treatment_rows, *baseline_rows)}
    if not kinds <= {"provider_final_charge", "fixture_simulated_charge"}:
        raise MissingProductionOriginalV1("qualified_actual_method_billing_source_scope")
    scope = "LOCAL_FIXTURE" if "fixture_simulated_charge" in kinds else "PRODUCTION"
    namespace = read.frame.envelope.authority.namespace
    family, identity, sk, ak = _measurement_source_identity_v1(namespace, request.experiment_ref, pair, treatment_calls)
    metrics = MethodMetricsV1(None, None, None, None, None, None,
        sum(row["input_tokens"] for row in treatment_rows), sum(row["output_tokens"] for row in treatment_rows), None, None)
    supports = tuple(sorted(set((request.experiment_ref, experiment.trial_ref, experiment.protocol_ref,
        *(value.original_ref for value in pair), *treatment_supports, *baseline_supports))))
    observation = MethodComparisonObservationV2(namespace, request.experiment_ref, canonical_digest(experiment_atom.value),
        pair[0].original_ref, pair[0].digest, pair[1].original_ref, pair[1].digest,
        pair[0].readback.content_digest, pair[1].readback.content_digest, policy.policy_ref, policy.digest,
        metrics, (sk.token,), scope, measurement_family_ref=family, treatment_call_refs=treatment_calls,
        baseline_call_refs=baseline_calls, support_original_refs=supports)
    roots = tuple(dict.fromkeys((*experiment.source_refs, experiment.common_task_source_ref,
        *(value.source_head.key.token for value in pair), *treatment_sources, *baseline_sources)))
    current = read.source_family(db, roots, purpose="consolidation")
    audiences, purposes = set(read.frame.envelope.authority.audience), {"context", "consolidation", "audit"}
    for parent in current.values():
        access = read.head(db, access_key(*namespace.as_tuple, parent.source_id), required=True).value
        audiences.intersection_update(parent.audiences, access["audiences"])
        purposes.intersection_update(parent.purposes, access["purposes"])
    if not audiences or not {"context", "consolidation"} <= purposes:
        raise MissingProductionOriginalV1("actual_measurement_parent_source_scope_intersection")
    text = canonical_serialize({"schema": "d11.actual-phase-billing-measurement.v1", "measurement_kind": observation.measurement_kind,
        "source_scope": scope, "treatment": treatment_rows, "baseline": baseline_rows,
        "metrics": plain_v1(metrics), "measurement_family_ref": family})
    source = SourceRecord(identity, text, read.frame.envelope.authority.actor, "internal", "confirmed", None,
        read.frame.now_utc, family, tuple(sorted(audiences)), tuple(sorted(purposes)),
        tuple(parent.source_id for _, parent in sorted(current.items())), "same_root")
    if read.head(db, sk).revision or read.head(db, ak).revision:
        raise ValueError("method measurement Source already exists; recover its actual original")
    access = {"source_id": identity, "audiences": list(source.audiences), "purposes": list(source.purposes),
        "status": "active", "recorded_at": source.recorded_at}
    validate_access(access)
    return observation, source, access, sk, ak, roots, treatment_rows, baseline_rows


def stage_observe_method_comparison_v1(db, *, frame, request, installed_readers):
    from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA
    from ..domains.d06 import D06DomainProvider, _D06_PROPOSAL_SCHEMA
    if type(request) is not ObserveMethodComparisonRequestV1 or type(installed_readers) is not InstalledMethodObservationReadersV1:
        raise TypeError("selectors-only installed D11 method observation required")
    read = CurrentDomainReadV1(frame)
    try:
        read.check(db)
        observation, source, access, sk, ak, roots, treatment, baseline = _derive_observation_v1(db,
            read=read, request=request, readers=installed_readers)
        provenance = {"method_comparison_observation": observation, "measurement_source": source.to_dict(),
            "measurement_source_access": access, "measurement_parent_source_refs": roots,
            "treatment_phase_billing": treatment, "baseline_phase_billing": baseline}
        primary = stage_result_v1(frame, "d11", OPERATION, request, provenance=provenance,
            proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
        memory = stage_result_v1(frame, "d06", OPERATION, request,
            writes=(GraphWrite(sk, source.to_dict()), GraphWrite(ak, access)), provenance=provenance,
            proposal_schema=_D06_PROPOSAL_SCHEMA,
            proposal_hash=D06DomainProvider().descriptor.request_schema_hash)
        return MethodObservationStageV1(primary, memory, observation)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d11", OPERATION, request, missing)


def method_comparison_observation_ref_v1(value):
    return "method-comparison-observation:" + canonical_digest((value.namespace, value.experiment_ref,
        value.experiment_digest, value.treatment_milestone_digest, value.baseline_milestone_digest,
        value.observer_policy_ref, value.observer_policy_digest))[:48]


def read_plan_method_observation_v1(db, *, namespace, request, installed_readers):
    from .d01_production_operations_v1 import raw_head_value_v1
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    from .d11_artifact_draft_content_v1 import artifact_draft_phase_verification_from_wire_v2, ArtifactDraftPhaseVerifiedOriginalV2
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    if not db.in_transaction or type(request) is not ObserveMethodComparisonRequestV1 or type(installed_readers) is not InstalledMethodObservationReadersV1:
        raise TypeError("transactional actual method measurement read recipe required")
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple), AtomKey.from_token(request.experiment_ref)], [], [request.experiment_ref]
    experiment_raw = raw_head_value_v1(db, namespace, AtomKey.from_token(request.experiment_ref))
    if experiment_raw is None:
        return production_read_plan_v1((), keys, roots, originals)
    experiment = decode_typed_production_value_v1(experiment_raw, MethodExperimentPlanV1)
    for ref in (experiment.trial_ref, experiment.protocol_ref, experiment.treatment_goal_ref, experiment.baseline_goal_ref):
        keys.append(AtomKey.from_token(ref))
        value = raw_head_value_v1(db, namespace, keys[-1])
        if value is not None: roots.extend(value.get("source_refs", ()))
    originals.extend((experiment.trial_ref, experiment.protocol_ref)); roots.extend(experiment.source_refs)
    pair = tuple(read_current_artifact_task_milestone_v2(db, namespace=namespace, original_ref=ref,
        issuer=installed_readers.issuer) for ref in (request.treatment_milestone_ref, request.baseline_milestone_ref))
    treatment_calls = []
    for index, milestone in enumerate(pair):
        originals.append(milestone.original_ref); keys.append(milestone.source_head.key); roots.append(milestone.source_head.key.token)
        originals.extend((milestone.file_result_ref, milestone.full_check_original_ref))
        for ref, _ in milestone.ordered_phase_originals:
            originals.append(ref)
            saved = _read(db, issuer=installed_readers.issuer, namespace=namespace, kind="c4_phase_verified", ref=ref)
            if saved is None: raise MissingProductionOriginalV1("actual_method_measurement_phase_read_inputs")
            verified = artifact_draft_phase_verification_from_wire_v2(saved[0], ArtifactDraftPhaseVerifiedOriginalV2)
            keys.append(verified.source_head.key); roots.append(verified.source_head.key.token)
            if verified.selector.phase_kind not in {"tone_sample", "full"}: continue
            selector = verified.content_selector; ids = artifact_draft_model_ids_v2(selector)
            originals.extend((ids["job"], ids["request"], ids["paid"], ids["result"]))
            from .d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v2, decode_artifact_draft_original_v2
            prepared = read_artifact_draft_prepared_v2(db, namespace=namespace, issuer=installed_readers.issuer, selector=selector)
            if prepared is None: raise MissingProductionOriginalV1("actual_method_measurement_generation_read_inputs")
            frozen_original = _read(db, issuer=installed_readers.issuer, namespace=namespace,
                kind="c4_phase_frozen", ref=prepared.frozen_ref)
            if frozen_original is None: raise MissingProductionOriginalV1("actual_method_measurement_frozen_read_inputs")
            frozen = decode_artifact_draft_original_v2("c4_phase_frozen", frozen_original[0])
            originals.append(prepared.frozen_ref); roots.extend(source.ref for source in frozen.sources)
            if index == 0: treatment_calls.append(prepared.call_id)
    _, _, sk, ak = _measurement_source_identity_v1(namespace, request.experiment_ref, pair, tuple(sorted(treatment_calls)))
    keys.extend((sk, ak))
    return production_read_plan_v1((), keys, roots, originals)


def verify_method_observation_stage_v1(stage):
    from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA
    from ..domains.d06 import D06DomainProvider, _D06_PROPOSAL_SCHEMA
    from .domain_production_contracts_v1 import StagedDomainOperationV1
    if type(stage) is StagedDomainOperationV1:
        if stage.domain != "d11" or stage.operation_kind != OPERATION or stage.coverage == "complete":
            raise ValueError("method measurement missing inputs must remain HOLD")
        return stage
    if type(stage) is not MethodObservationStageV1 or type(stage.observation) is not MethodComparisonObservationV2:
        raise TypeError("exact atomic method observation stage required")
    primary, memory = stage.stage, stage.memory_stage
    if (primary.domain, primary.operation_kind, primary.coverage, memory.domain, memory.operation_kind, memory.coverage) != (
            "d11", OPERATION, "complete", "d06", OPERATION, "complete"):
        raise ValueError("measurement metadata and Source belong to the same complete W01 operation")
    expected = (AtomKey.from_token(stage.observation.source_refs[0]), access_key(*stage.observation.namespace.as_tuple,
        AtomKey.from_token(stage.observation.source_refs[0]).owner.subject))
    writes = tuple(write for proposal in memory.proposals for write in proposal.typed_writes)
    if tuple(write.key for write in writes) != expected:
        raise ValueError("method measurement writes only its derived Source/access")
    for proposal in primary.proposals:
        if proposal.typed_writes or proposal.domain != "d11" or proposal.proposal_schema != D11_PROPOSAL_SCHEMA:
            raise ValueError("method observer never changes jobs, effects, budgets or Persona")
        D11RuntimeProvider().validate(proposal, None)
    for proposal in memory.proposals:
        if proposal.domain != "d06" or proposal.proposal_schema != _D06_PROPOSAL_SCHEMA:
            raise ValueError("method measurement Source stays with the D06 writer")
        D06DomainProvider().validate(proposal, None)
    return stage


def _require_actual_observation_original_v1(db, *, namespace, original_ref, producing_operation_id, raw):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    value = decode_typed_production_value_v1(raw, MethodComparisonObservationV2)
    actual = read_adopted_domain_operation_v1(db, namespace, producing_operation_id)
    if (value.namespace != namespace or method_comparison_observation_ref_v1(value) != original_ref
            or actual is None or (actual["domain"], actual["operation_kind"], actual["payload"]["coverage"]) != ("d11", OPERATION, "complete")
            or actual["payload"]["provenance"].get("method_comparison_observation") != raw):
        raise ValueError("method measurement signature lost its actual complete W01 producer")
    source_ref = value.source_refs[0]
    sk = AtomKey.from_token(source_ref); ak = access_key(*namespace.as_tuple, sk.owner.subject)
    expected = actual["payload"]["provenance"]
    for key, member in ((sk, "measurement_source"), (ak, "measurement_source_access")):
        versions = tuple(version for version in actual["receipt"].write_versions if version.key == key)
        if len(versions) != 1 or versions[0].revision != 1:
            raise ValueError("actual method observation must adopt its Source/access exactly once")
        history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1", (key.token,)).fetchone()
        if history != (producing_operation_id, canonical_serialize(expected[member]), 1):
            raise ValueError("method measurement Source history changed its actual adoption")
    source = SourceRecord.from_dict(expected["measurement_source"])
    if (source.source_kind, source.assertion_status, source.independence, source.provenance_root) != (
            "internal", "confirmed", "same_root", value.measurement_family_ref) or not source.parent_source_ids:
        raise ValueError("derived billing measurements cannot pretend independent observed experiences")
    return value, ProductionOriginalRefV1("d11.life_" + KIND, original_ref, canonical_digest(raw),
        tuple(version for version in actual["receipt"].write_versions if version.key in (sk, ak)))


def record_method_observation_after_cas_v1(db, *, frame, stage, receipt, issuer):
    if type(stage) is not MethodObservationStageV1:
        return ()
    if receipt.status != "committed" or receipt.operation_id != frame.envelope.identity.operation_id:
        raise ValueError("method measurement can be signed only after its actual same-transaction CAS")
    actual = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, receipt.operation_id)
    if actual is None or actual["receipt"] != receipt or actual["original_digest"] != stage.stage.original_digest:
        raise ValueError("method measurement actual W01 original differs from its committed stage")
    raw = actual["payload"]["provenance"]["method_comparison_observation"]
    ref = method_comparison_observation_ref_v1(stage.observation)
    value, _ = _require_actual_observation_original_v1(db, namespace=frame.envelope.authority.namespace,
        original_ref=ref, producing_operation_id=receipt.operation_id, raw=raw)
    return (_record(db, issuer=issuer, namespace=value.namespace, kind=KIND,
        ref=ref, operation_id=receipt.operation_id, value=value),)


def read_current_method_observation_original_ref_v1(db, *, namespace, original_ref, issuer):
    saved = _read(db, issuer=issuer, namespace=namespace, kind=KIND, ref=original_ref)
    if saved is None:
        return None
    _, original = _require_actual_observation_original_v1(db, namespace=namespace,
        original_ref=original_ref, producing_operation_id=saved[1], raw=saved[0])
    return original
