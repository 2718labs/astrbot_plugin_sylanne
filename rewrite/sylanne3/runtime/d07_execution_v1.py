"""D07 actual paid execution transaction bodies, consumed only by W01.

The caller owns the Owner fence, Graph CAS and SQLite transaction. No network,
provider call, native work, BEGIN or COMMIT occurs in this module. Immutable
signed originals are in the shared business database, never a parallel graph.
"""
from __future__ import annotations
from .natural_producer_qualification_v1 import _producer_original_point_v3
from .domain_background_read_v3 import background_json_loads_v3,background_inventory_v3

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
import json

from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ..authority_service.v2_model_egress_wire import to_wire as model_to_wire
from ..domains.d02 import BodyDomain, BodyProfile, BodyReservation, BodyState
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..domains.d06 import source_correction_head_key
from ..domains.d07 import SimulationRequest
from ..domains.d05.relationship_revision_v2 import RelationshipScopeV2
from ..domains.d07.current_issuer_v1 import qualify_current_source_heads_v1
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ..memory_types import SourceRecord, access_key, source_key
from ..model_broker.broker import ModelCallRequest
from ..model_broker.d07_cognition_v1 import (
    D07CognitionInputV1, D07CognitionInstallationV1, D07QualifiedSourceV1,
    FrozenD07CognitionRequestV1, WORK_KIND, TEMPLATE_DIGEST,
    freeze_d07_cognition_request_v1, thaw_d07_cognition_request_v1, parse_d07_cognition_output_v1,
    thaw_d07_ingress_recall_request_v1,
)
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from .budget import reserve_budget, get_budget_lease, require_budget_family_admissible, settle_budget, settle_budget_partial
from .clock import CharacterClockMapping, get_clock_mapping, _mapping_dict
from .d07_current_behavior_v1 import D07CurrentBehaviorStageV1, D07ExecutionOriginalV1, _heads, _json
from .domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionOriginalRefV1
from .d11_types import job_graph_write, cost_settlement_from_runtime, cost_settlement_graph_write
from .issuers import ResourceQuote
from .jobs import PersistentJob, get_job, transition_job, create_job
from .model_cost_settlement import (OriginalModelCostFactV1, prepare_original_model_cost_plan,
    apply_original_model_budget_in_transaction, original_model_budget_measurement,
    original_model_cost_operation_id_v1)

TABLE = "graph_d07_execution_originals_v1"
SIGN_KIND = "d07.execution-original.v1"
KINDS = frozenset({"prepared", "prepare_commit", "request", "call", "result_attempt", "result", "paid_cost",
    "partial_cost", "body_cost", "execution", "adopted", "simulation_request", "simulation_budget", "reflection_request", "reflection_continuation", "general_growth_attention_v1", "accounting_prepared", "semantic_question", "budget_allocation", "budget_closed"})
KINDS = KINDS | frozenset({'joint_external_semantic_basis_v1'})


def install_d07_execution_schema_v1(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL,
        original_ref TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
        signature TEXT NOT NULL, PRIMARY KEY(bot,persona,kind,original_ref))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS {TABLE}_no_{action.lower()}
            BEFORE {action} ON {TABLE}
            BEGIN SELECT RAISE(ABORT,'D07 execution original is immutable'); END""")


def record_d07_original_in_transaction_v1(db, issuer, namespace, kind, ref, payload):
    if not db.in_transaction or kind not in KINDS:
        raise ValueError("D07 registered original requires W01 transaction")
    wire = canonical_serialize(_json(payload))
    digest = canonical_digest(background_json_loads_v3(wire))
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((namespace, kind, ref, digest)))
    from .d07_graph_stages_v1 import read_d07_actual_writer_prior_v3
    actual_writer,prior=read_d07_actual_writer_prior_v3(db,namespace,kind,ref,issuer)
    if not actual_writer:
        prior = read_d07_original_v1(db, issuer, namespace, kind, ref)
    if prior is not None:
        if prior != (background_json_loads_v3(wire), digest):
            raise ValueError("D07 original identity reused with different bytes")
        return digest
    db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)", (*namespace.as_tuple, kind, ref, wire, digest, signature))
    from .d07_graph_stages_v1 import _record_d07_actual_written_original_v3
    _record_d07_actual_written_original_v3(db,namespace,kind,ref,wire,digest,signature)
    from .d07_source_preparation_members_v3 import register_d07_source_preparation_original_v3
    register_d07_source_preparation_original_v3(db,issuer,namespace,kind,ref,wire,digest,signature)
    return digest


def read_d07_original_v1(db, issuer, namespace, kind, ref):
    from .d07_source_preparation_members_v3 import read_bound_d07_source_preparation_original_v3
    handled,original=read_bound_d07_source_preparation_original_v3(db,issuer,namespace,kind,ref)
    if handled:return original
    from ..authority_service.d07_authority_model_source_read_v3 import read_bound_current_d07_authority_original_v3
    authority,original=read_bound_current_d07_authority_original_v3(db,issuer,namespace,kind,ref)
    if authority:return original
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_matches_v3,background_json_digest_v3
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if exists is None:
        return None
    row = _producer_original_point_v3(db,table=TABLE,columns=('payload_json','payload_digest','signature'),
        key_columns=('bot','persona','kind','original_ref'),key=(*namespace.as_tuple,kind,ref),
        legacy_reader=lambda:db.execute(f"SELECT payload_json,payload_digest,signature FROM {TABLE} "
            "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,kind,ref)).fetchone())
    if row is None:
        return None
    raw = background_json_loads_v3(row[0])
    if kind not in KINDS or not background_json_matches_v3(row[0],raw) or background_json_digest_v3(row[0],raw) != row[1]:
        raise ValueError("D07 immutable original bytes changed")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, row[1])), row[2])
    return raw, row[1]


@dataclass(frozen=True, slots=True)
class D07ExecutionReadV1:
    ref: str
    revision: int
    valid: bool
    value_json: str

    def __post_init__(self):
        AtomKey.from_token(self.ref)
        if (type(self.revision) is not int or self.revision < 0 or type(self.valid) is not bool
                or canonical_serialize(background_json_loads_v3(self.value_json)) != self.value_json):
            raise ValueError("D07 exact graph read original required")


@dataclass(frozen=True, slots=True)
class D07PreparedExecutionV1:
    namespace: NamespaceId
    operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    job_id: str
    call_id: str
    execution_id: str
    work_kind: str
    stage_input_digest: str
    frozen_json: str
    read_rows: tuple[D07ExecutionReadV1, ...]
    query_inventory_json: str
    external_content_originals_json: str
    audience: tuple[str, ...]
    purpose: str
    owner_guard_json: str
    owner_authority_json: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_digest: str
    body_policy_id: str
    body_policy_version: int
    body_quote_ref: str
    body_quote_version: int
    body_quote_digest: str
    body_reservation_ref: str
    body_state_ref: str
    body_profile_ref: str
    component_id: str
    clock_mapping_json: str
    clock_original_digest: str
    activation_generation: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    schema: str = "d07.prepared-execution.v1"

    @property
    def digest(self):
        return canonical_digest(asdict(self))

    @property
    def prepare_operation_id(self):
        return "d07-prepare:" + self.operation_id


@dataclass(frozen=True, slots=True, kw_only=True)
class D07RelationshipPreparedV2(D07PreparedExecutionV1):
    semantic_question_ref: str
    semantic_question_digest: str
    cycle_ref: GraphVersion
    cycle_digest: str
    call_plan_digest: str
    c02_operation_id: str
    cancel_generation: int
    schema: str = "d07.relationship-prepared.v2"

    def __post_init__(self):
        if (self.schema != "d07.relationship-prepared.v2" or self.work_kind != "concern"
                or type(self.cycle_ref) is not GraphVersion or self.cycle_ref.revision < 1
                or self.cycle_ref.key.type_name != "runtime.job"
                or NamespaceId.from_key(self.cycle_ref.key) != self.namespace
                or type(self.cancel_generation) is not int or self.cancel_generation < 0
                or not self.semantic_question_ref or not self.c02_operation_id):
            raise ValueError("Relationship C3 requires its actual typed foreground preparation")
        for digest in (self.semantic_question_digest, self.cycle_digest, self.call_plan_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("Relationship C3 lost its exact original commitment")



@dataclass(frozen=True, slots=True, kw_only=True)
class D07ReflectionPreparedV3(D07PreparedExecutionV1):
    reflection_request_ref: str
    reflection_request_digest: str
    reflection_continuation_ref: str
    reflection_continuation_digest: str
    parent_prepared_ref: str
    parent_prepared_digest: str
    parent_execution_ref: str
    parent_execution_digest: str
    checkpoint_ref: GraphVersion
    checkpoint_digest: str
    ticket_id: str
    source_refs: tuple[str, ...]
    parent_budget_lease_ref: str
    parent_grant_digest: str
    original_deadline_utc: float
    cycle_ref: GraphVersion | None = None
    cycle_digest: str | None = None
    call_plan_digest: str | None = None
    c02_operation_id: str | None = None
    cancel_generation: int | None = None
    schema: str = "d07.reflection-prepared.v3"

    def __post_init__(self):
        import math
        if (self.schema != "d07.reflection-prepared.v3" or self.work_kind != "reflection"
                or type(self.checkpoint_ref) is not GraphVersion or self.checkpoint_ref.revision < 1
                or self.checkpoint_ref.key.type_name != "d07.reflection_checkpoint.v1"
                or NamespaceId.from_key(self.checkpoint_ref.key) != self.namespace
                or type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 16
                or len(set(self.source_refs)) != len(self.source_refs)
                or type(self.original_deadline_utc) not in (int, float)
                or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("reflection preparation lost its exact original checkpoint/source/deadline")
        for name in ("reflection_request_ref", "reflection_continuation_ref", "parent_prepared_ref",
                "parent_execution_ref", "ticket_id", "parent_budget_lease_ref"):
            value = getattr(self, name)
            if type(value) is not str or not 1 <= len(value) <= 4096:
                raise ValueError("reflection preparation lost its actual original locator")
        for name in ("reflection_request_digest", "reflection_continuation_digest", "parent_prepared_digest",
                "parent_execution_digest", "checkpoint_digest", "parent_grant_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("reflection preparation lost its exact signed commitment")
        for ref in self.source_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("reflection preparation crossed its exact source namespace")
        group = (self.cycle_ref, self.cycle_digest, self.call_plan_digest, self.c02_operation_id, self.cancel_generation)
        if any(value is not None for value in group):
            if (any(value is None for value in group) or type(self.cycle_ref) is not GraphVersion
                    or self.cycle_ref.revision < 1 or self.cycle_ref.key.type_name != "runtime.job"
                    or NamespaceId.from_key(self.cycle_ref.key) != self.namespace
                    or type(self.cancel_generation) is not int or self.cancel_generation < 0
                    or type(self.c02_operation_id) is not str or not self.c02_operation_id):
                raise ValueError("Self reflection requires its whole exact parentage group")
            for value in (self.cycle_digest, self.call_plan_digest):
                if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                    raise ValueError("Self reflection lost its original cycle/call-plan commitment")

    @property
    def digest(self):
        from ..domains.d01.production_operations_v1 import plain_v1
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class D07IngressRecallPreparedV1:
    """Exact Self C3 original; the upstream Owner guard is a separate constraint."""
    namespace: NamespaceId
    operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    job_id: str
    call_id: str
    execution_id: str
    work_kind: str
    stage_input_digest: str
    frozen_json: str
    read_rows: tuple[D07ExecutionReadV1, ...]
    query_inventory_json: str
    external_content_originals_json: str
    audience: tuple[str, ...]
    purpose: str
    owner_guard_json: str
    self_authority_json: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_digest: str
    body_policy_id: str
    body_policy_version: int
    body_quote_ref: str
    body_quote_version: int
    body_quote_digest: str
    body_reservation_ref: str
    body_state_ref: str
    body_profile_ref: str
    component_id: str
    clock_mapping_json: str
    clock_original_digest: str
    activation_generation: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    need_ref: str
    need_digest: str
    c02_operation_id: str
    cycle_job_ref: str
    responsibility_ref: str
    responsibility_digest: str
    recall_policy_digest: str
    cancel_generation: int
    adoption_operation_id: str
    schema: str = "d07.ingress-recall-prepared.v1"

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.work_kind != "recall_need"
                or self.schema != "d07.ingress-recall-prepared.v1"
                or type(self.cancel_generation) is not int or self.cancel_generation < 0
                or self.adoption_operation_id == self.operation_id):
            raise ValueError("exact Self recall preparation/adoption identities required")
        cycle = AtomKey.from_token(self.cycle_job_ref)
        if cycle.type_name != "runtime.job" or NamespaceId.from_key(cycle) != self.namespace:
            raise ValueError("Self recall preparation crosses its parent cycle")
        for name in ("need_ref", "c02_operation_id", "responsibility_ref", "adoption_operation_id"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError("Self recall preparation lost its actual parent original")
        for name in ("need_digest", "responsibility_digest", "recall_policy_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("Self recall original commitment differs")
        for name in ("self_authority_json", "owner_guard_json"):
            value = getattr(self, name)
            if type(value) is not str or canonical_serialize(background_json_loads_v3(value)) != value:
                raise ValueError("Self and upstream Owner provenance must remain exact and separate")

    @property
    def digest(self):
        return canonical_digest(asdict(self))

    @property
    def prepare_operation_id(self):
        return self.operation_id


@dataclass(frozen=True, slots=True)
class D07IngressRecallExecutionOriginalV1:
    """Actual scoped C3 activity, separate from Owner cognitive behavior."""
    namespace: NamespaceId
    terminal_ref: str
    operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    execution_id: str
    prepared_digest: str
    input_digest: str
    result_digest: str
    need_ref: str
    need_digest: str
    c02_operation_id: str
    cycle_job_ref: str
    started_at: float
    ended_at: float
    time_mapping_ref: str
    time_mapping_version: str
    parent_budget_ref: str
    cost_receipt_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    activation_generation: int
    work_kind: str = "recall_need"
    status: str = "completed"
    schema: str = "d07.ingress-recall-execution.v1"

    def __post_init__(self):
        import math
        if (type(self.namespace) is not NamespaceId
                or self.schema != "d07.ingress-recall-execution.v1"
                or self.work_kind != "recall_need" or self.status != "completed"
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.started_at) not in (int, float) or not math.isfinite(self.started_at)
                or type(self.ended_at) not in (int, float) or not math.isfinite(self.ended_at)
                or self.ended_at < self.started_at):
            raise ValueError("Self C3 requires its actual completed activity/time/generation")
        cycle = AtomKey.from_token(self.cycle_job_ref)
        if cycle.type_name != "runtime.job" or NamespaceId.from_key(cycle) != self.namespace:
            raise ValueError("Self C3 execution crossed its actual parent cycle")
        for name in ("terminal_ref", "operation_id", "activity_id", "effect_id", "attempt_id",
                "execution_id", "need_ref", "c02_operation_id", "time_mapping_ref",
                "time_mapping_version", "parent_budget_ref"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError("Self C3 execution lacks its original identity")
        for name in ("prepared_digest", "input_digest", "result_digest", "need_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("Self C3 execution commitment differs")
        for name in ("cost_receipt_refs", "source_refs"):
            refs = getattr(self, name)
            if (type(refs) is not tuple or not refs or len(refs) > 17 or len(set(refs)) != len(refs)
                    or any(type(ref) is not str or not ref for ref in refs)):
                raise ValueError("Self C3 execution lacks its finite original cost/source refs")
        for ref in self.source_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("Self C3 execution source crosses its actual namespace")


@dataclass(frozen=True, slots=True)
class D07PreparationStageV1:
    frame: CurrentOperationFrameV1
    stage: D07CurrentBehaviorStageV1
    prepared: D07PreparedExecutionV1
    job: PersistentJob
    writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class D07SemanticQuestionV1:
    question_key: str
    question: str
    target_ref: VersionedRef
    source_refs: tuple[str, ...]
    schema: str = "d07.registered-semantic-question.v1"

    def __post_init__(self):
        if (self.schema != "d07.registered-semantic-question.v1" or type(self.target_ref) is not VersionedRef
                or self.target_ref.version < 1 or type(self.source_refs) is not tuple
                or not 1 <= len(self.source_refs) <= 16 or len(set(self.source_refs)) != len(self.source_refs)
                or any(type(v) is not str or not v or len(v) > 1024 for v in (self.question_key, self.question))):
            raise ValueError("D07 exact bounded registered semantic question required")
        if type(self.target_ref.ref) is not str or not self.target_ref.ref or len(self.target_ref.ref) > 4096:
            raise ValueError("D07 semantic target locator differs")
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("D07 semantic question sources must be actual D06 roots")


@dataclass(frozen=True, slots=True, kw_only=True)
class D07RelationshipSemanticQuestionV2(D07SemanticQuestionV1):
    cycle_ref: GraphVersion
    cycle_digest: str
    scope: RelationshipScopeV2
    trigger_original_ref: str
    policy_ref: str
    policy_revision: int
    policy_digest: str
    schema: str = "d07.relationship-semantic-question.v2"

    def __post_init__(self):
        from ..domains.d05.relationship_revision_v2 import RelationshipScopeV2
        from .d05_relationship_revision_v2 import relationship_evaluation_question_scope_v2
        D07SemanticQuestionV1(self.question_key, self.question, self.target_ref, self.source_refs)
        if (self.schema != "d07.relationship-semantic-question.v2" or type(self.scope) is not RelationshipScopeV2
                or type(self.cycle_ref) is not GraphVersion or self.cycle_ref.revision < 1
                or self.cycle_ref.key.type_name != "runtime.job"
                or NamespaceId.from_key(self.cycle_ref.key) != self.scope.namespace
                or self.target_ref != VersionedRef(self.scope.subject_head.key.token, self.scope.subject_head.revision)
                or type(self.policy_revision) is not int or self.policy_revision < 1
                or not self.trigger_original_ref or not self.policy_ref
                or self.question_key != relationship_evaluation_question_scope_v2(
                    self.scope, self.trigger_original_ref, self.policy_ref, self.policy_digest)):
            raise ValueError("Relationship question must bind its exact actual scope/trigger/policy/cycle")
        for digest in (self.cycle_digest, self.policy_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("Relationship question original commitment differs")


def _require_relationship_c3_trigger_parent_v2(db, frame, question, cycle):
    from .foreground_cycle_v1 import _adopted_c02_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    key = AtomKey.from_token(question.trigger_original_ref)
    atom = frame.snapshot.get(key)
    if atom is None or not atom.valid:
        raise MissingProductionOriginalV1("actual_current_relationship_trigger_parent")
    c02 = _adopted_c02_v1(db, question.scope.namespace, cycle.c02_operation_id)
    from .foreground_cycle_v1 import require_actual_c02_cue_source_v1
    cue_key = AtomKey.from_token(cycle.source_ref)
    cue_atom = frame.snapshot.get(cue_key)
    if cue_atom is None or not cue_atom.valid:
        raise MissingProductionOriginalV1('actual_current_relationship_C02_cue')
    cue_version = GraphVersion(cue_key, cue_atom.revision)
    require_actual_c02_cue_source_v1(db, namespace=question.scope.namespace,
        c02_operation_id=cycle.c02_operation_id, source_version=cue_version)
    if key.type_name == "d06.recollection.v1":
        from .domain_production_read_plans_v1 import read_committed_recollection_original_v1
        from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
        from .c04_frozen_association_original_v3 import read_c04_frozen_association_original_v3
        from .c04_product_original_v3 import read_c04_product_request_v3
        read_committed_recollection_original_v1(db, question.scope.namespace, key.token)
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_c04_association_inputs_v3'").fetchone() is None:
            raise MissingProductionOriginalV1("actual_relationship_C04_cue_binding")
        rows = db.execute("SELECT operation_id FROM graph_c04_association_inputs_v3 WHERE bot=? AND persona=? "
            "AND json_extract(work_json,'$.activity_id')=? LIMIT 2", (*question.scope.namespace.as_tuple, atom.value["activity_id"])).fetchall()
        if len(rows) != 1:
            raise MissingProductionOriginalV1("unique_actual_relationship_C04_cue_binding")
        prepared = read_c04_internal_work_prepared_v1(db, question.scope.namespace, rows[0][0])
        if prepared is None:
            raise MissingProductionOriginalV1("actual_relationship_C04_prepared_binding")
        work = read_c04_frozen_association_original_v3(db, question.scope.namespace, prepared.binding)
        request = read_c04_product_request_v3(db, question.scope.namespace, rows[0][0])
        history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?", (key.token, atom.revision)).fetchone()
        committed = db.execute("SELECT activity_id,effect_id FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*question.scope.namespace.as_tuple, history[0])).fetchone()
        cue = None if work is None else next((row for row in work.reads if row.ref == work.cue_source_ref), None)
        if (request is None or work is None or cue is None or work.cue_source_ref != cycle.source_ref
                or (work.activity_id, work.operation_id) != (prepared.binding.activity_id, prepared.binding.operation_id)
                or history[0] != prepared.binding.operation_id or committed != (work.activity_id, request.envelope.identity.effect_id)
                or GraphVersion(AtomKey.from_token(cue.ref), cue.revision) != cue_version):
            raise ValueError("Relationship C04 cue differs from the actual current cycle C02/activity/effect")
    elif key.type_name == "memory.source":
        if GraphVersion(key, atom.revision) != cue_version:
            raise ValueError("Relationship external Source is not this actual frozen C02 cue")
    elif key.type_name == "d03.world_event":
        from ..memory_types import SourceRecord
        from .domain_production_read_plans_v1 import _committed
        from .domain_production_originals_v1 import _receipt
        source = SourceRecord.from_dict(cue_atom.value)
        arrival_operation = "d03-arrival-" + canonical_digest({'namespace':list(question.scope.namespace.as_tuple),
            'source_ref':source.source_id})[:40]
        _committed(db, question.scope.namespace, arrival_operation)
        row = db.execute('SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
            (*question.scope.namespace.as_tuple,arrival_operation)).fetchone()
        arrival = _receipt(background_json_loads_v3(row[0]))
        issuance = db.execute('SELECT source_ref,bundle_digest FROM graph_d03_arrival_issuance_v2 WHERE bot=? AND persona=? AND operation_id=?',
            (*question.scope.namespace.as_tuple,arrival_operation)).fetchone()
        history = db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(key.token,atom.revision)).fetchone()
        from .ingress_observation import read_committed_ingress_identity
        identity = read_committed_ingress_identity(db,question.scope.namespace,source.source_id)
        if identity is None:
            raise MissingProductionOriginalV1('actual_relationship_message_arrival_ingress_identity')
        ingress = background_json_loads_v3(identity.identity_json)
        event_id = 'world:message-arrival-v1:' + canonical_digest({'namespace':question.scope.namespace.as_tuple,
            'platform_ref':ingress['platform_ref'],'conversation_ref':ingress['conversation_ref'],
            'message_id':ingress['message_id'],'source_id':source.source_id})
        if (arrival.operation_id != arrival_operation or arrival.commit_seq < 1 or arrival.commit_seq >= c02.commit_seq
                or issuance != (source.source_id,arrival.operation_digest)
                or GraphVersion(key,atom.revision) not in arrival.write_versions
                or history is None or history[0] != arrival_operation or history[2] != 1 or background_json_loads_v3(history[1]) != atom.value
                or atom.value['kind'] != 'message_received' or atom.value['event_id'] != event_id
                or tuple(atom.value['source_refs']) != (cycle.source_ref,)):
            raise ValueError('Relationship event must be the actual independent D03 arrival preceding this C02 Source consumption')
    else:
        raise MissingProductionOriginalV1("registered_relationship_C3_trigger_parent_kind")


def _require_relationship_semantic_question_v2(db, issuer, frame, question):
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2
    atom = frame.snapshot.get(question.cycle_ref.key)
    job = get_job(db, question.cycle_ref.key.name)
    cycle = foreground_cycle_from_wire_v1(job.continuation)
    if (atom is None or not atom.valid or atom.revision != question.cycle_ref.revision
            or canonical_digest(atom.value) != question.cycle_digest or atom.value != job_graph_write(job).value
            or cycle.call_plan.parent_budget_lease_ref != frame.envelope.parent_budget_lease_ref
            or job.phase in {"completed", "cancelled", "failed"}
            or job.cancel_epoch or frame.now_utc >= datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp()):
        raise ValueError("Relationship C3 question is outside its actual current foreground cycle")
    _require_relationship_c3_trigger_parent_v2(db, frame, question, cycle)
    row = db.execute("SELECT payload_json,payload_digest,signature,revision FROM graph_d05_production_policies_v1 "
        "WHERE bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC LIMIT 1",
        (*question.scope.namespace.as_tuple, question.policy_ref)).fetchone()
    if row is None or (row[1], row[3]) != (question.policy_digest, question.policy_revision):
        raise ValueError("Relationship C3 question policy is not the exact current installed revision")
    issuer._signer.verify("d11.d05-production-policy.v2", row[0], row[2])
    policy = decode_typed_production_value_v1(background_json_loads_v3(row[0]), InstalledRelationshipPolicyV2)
    if policy.namespace != question.scope.namespace or canonical_digest(asdict(policy)) != question.policy_digest:
        raise ValueError("Relationship C3 question lost its signed installed policy")
    policy.rule(question.scope)
    _source_input(frame, policy.policy_source_refs)
    return job, cycle


def record_current_d07_semantic_question_in_transaction_v1(db, issuer, frame, ref, question):
    from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2
    if not db.in_transaction or type(question) not in {D07SemanticQuestionV1, D07RelationshipSemanticQuestionV2, D07MethodGrowthSemanticQuestionV2}:
        raise ValueError("D07 question registration requires actual Owner W01 transaction")
    if type(question) is D07RelationshipSemanticQuestionV2:
        _require_relationship_semantic_question_v2(db, issuer, frame, question)
    elif type(question) is D07MethodGrowthSemanticQuestionV2:
        _require_method_growth_semantic_question_v2(db, issuer, frame, question)
    target = resolve_current_d07_semantic_target_v1(db, issuer, frame, question)
    _source_input(frame, question.source_refs)
    digest = record_d07_original_in_transaction_v1(db, issuer, frame.envelope.authority.namespace,
        "semantic_question", ref, asdict(question))
    return ProductionOriginalRefV1("d07.semantic_question", ref, digest, target.read_versions)


@dataclass(frozen=True, slots=True)
class D07SemanticTargetOriginalV1:
    kind: str
    original_ref: str
    revision: int
    original_digest: str
    value_json: str
    source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]

    def __post_init__(self):
        if (self.kind not in {"graph_head", "d08_joint_plan_intent"} or type(self.original_ref) is not str
                or not self.original_ref or type(self.revision) is not int or self.revision < 1
                or canonical_digest(background_json_loads_v3(self.value_json)) != self.original_digest
                or canonical_serialize(background_json_loads_v3(self.value_json)) != self.value_json
                or type(self.source_refs) is not tuple or type(self.read_versions) is not tuple):
            raise ValueError("D07 exact bounded semantic target original differs")
        if len(self.value_json.encode()) > 8192 or len(self.source_refs) > 16 or len(set(self.source_refs)) != len(self.source_refs):
            raise ValueError("D07 semantic target exceeds installed bounds")
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("D07 semantic target requires actual D06 sources")
        if any(type(v) is not GraphVersion or v.revision < 1 for v in self.read_versions):
            raise ValueError("D07 semantic target current read versions differ")


def read_d07_joint_plan_semantic_target_v1(db, issuer, namespace, target_ref):
    """The only non-Graph semantic target is an actual signed D08 plan intent."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d08_production_operations_v1 import JointPlanIntentOriginalV1
    table = "graph_d08_joint_plan_intents_v1"
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
        raise ValueError("D07 exact signed D08 semantic target unavailable")
    row = db.execute(f"SELECT producing_operation_id,payload_json,payload_digest,signature,source_refs_json FROM {table} "
        "WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, target_ref.ref)).fetchone()
    if row is None:
        raise ValueError("D07 semantic locator is not an installed target original")
    issuer._signer.verify("d11.d08-joint-plan-intent.v1", row[1], row[3])
    raw = background_json_loads_v3(row[1])
    intent = decode_typed_production_value_v1(raw, JointPlanIntentOriginalV1)
    if (canonical_serialize(raw) != row[1] or canonical_digest(raw) != row[2] or intent.revision != target_ref.version
            or tuple(background_json_loads_v3(row[4])) != intent.source_refs):
        raise ValueError("D07 signed D08 exact target revision/content commitment differs")
    original = db.execute("SELECT receipt_json,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, row[0])).fetchone()
    if original is None or original[1] < 1 or background_json_loads_v3(original[0]).get("commit_seq") != original[1]:
        raise ValueError("D07 signed semantic target lost its actual producing Graph operation")
    versions = []
    for ref in intent.current_goal_refs:
        key = AtomKey.from_token(ref)
        goal = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(ref,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone())
        if (NamespaceId.from_key(key) != namespace or key.type_name != "d08.goal.v1" or goal is None
                or goal[2] != 1 or goal[0] < 1 or background_json_loads_v3(goal[1]).get("state") != "active"):
            raise ValueError("D07 signed plan target requires its actual current active goals")
        versions.append(GraphVersion(key, goal[0]))
    return D07SemanticTargetOriginalV1("d08_joint_plan_intent", target_ref.ref, target_ref.version, row[2], row[1], intent.source_refs, tuple(versions))


def resolve_current_d07_semantic_target_v1(db, issuer, frame, question):
    try:
        key = AtomKey.from_token(question.target_ref.ref)
    except (ValueError, TypeError):
        target = read_d07_joint_plan_semantic_target_v1(db, issuer, frame.envelope.authority.namespace, question.target_ref)
        matches = [original for original in frame.observed_originals if original.original_ref == target.original_ref]
        if len(matches) != 1 or matches[0].kind != "d08.joint_plan_intent" or matches[0].original_digest != target.original_digest:
            raise ValueError("D07 exact signed joint-plan target is not in actual current original frame")
        _source_input(frame, target.source_refs)
        if any(frame.snapshot.get(v.key) is None or not frame.snapshot.get(v.key).valid
                or frame.snapshot.get(v.key).revision != v.revision for v in target.read_versions):
            raise ValueError("D07 signed semantic target current goal closure is not guarded")
        return target
    atom = frame.snapshot.get(key)
    if atom is None or not atom.valid or atom.revision != question.target_ref.version:
        raise ValueError("D07 semantic current Graph target is not in authorized frame")
    from ..domains.d03.world_history_v1 import VIEW_TYPE
    if key.type_name==VIEW_TYPE:
        from .d03_world_history_v1 import world_semantic_target_v1
        return world_semantic_target_v1(db,issuer=issuer,frame=frame,question=question,atom=atom)
    return D07SemanticTargetOriginalV1("graph_head", key.token, atom.revision, canonical_digest(atom.value),
        canonical_serialize(atom.value), (), (GraphVersion(key, atom.revision),))


def read_current_d07_semantic_question_v1(db, issuer, namespace, ref):
    row = read_d07_original_v1(db, issuer, namespace, "semantic_question", ref)
    if row is None:
        return None
    raw = row[0]
    if raw.get("schema")=="d07.artifact-phase-observation-question.v1":
        from .artifact_phase_observation_v1 import ArtifactPhaseObservationQuestionV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        return decode_typed_production_value_v1(raw,ArtifactPhaseObservationQuestionV1)
    raw = {**raw, "target_ref": VersionedRef(**raw["target_ref"]), "source_refs": tuple(raw["source_refs"])}
    if raw.get("schema") == "d07.relationship-semantic-question.v2":
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..domains.d05.relationship_revision_v2 import RelationshipScopeV2
        return decode_native_named_d07_value_v2(row[0], D07RelationshipSemanticQuestionV2)
    if raw.get("schema") == "d07.method-growth-semantic-question.v2":
        from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2, method_growth_value_from_wire_v2
        return method_growth_value_from_wire_v2(row[0], D07MethodGrowthSemanticQuestionV2)
    if raw.get("schema")=="d07.general-growth-semantic-question.v1":
        from .d07_general_growth_attention_v1 import D07GeneralGrowthQuestionV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        return decode_typed_production_value_v1(row[0],D07GeneralGrowthQuestionV1)
    return D07SemanticQuestionV1(**raw)


def d07_execution_ids_v1(namespace, operation_id, kind):
    suffix = canonical_digest((namespace, operation_id, kind))[:48]
    return {"job": "d07-job:" + suffix, "call": "d07-call:" + suffix,
        "execution": "d07-execution:" + suffix, "quote": "d07-quote:" + suffix,
        "reservation": "d07-body:" + suffix, "settlement": "d07-settle:" + suffix}


def read_prepared_d07_execution_v1(db, issuer, namespace, job_id):
    row = read_d07_original_v1(db, issuer, namespace, "prepared", job_id)
    if row is None:
        return None
    raw = dict(row[0])
    raw["namespace"] = NamespaceId(**raw["namespace"])
    raw["read_rows"] = tuple(D07ExecutionReadV1(**r) for r in raw["read_rows"])
    raw["audience"] = tuple(raw["audience"])
    if raw.get("schema") == "d07.ingress-recall-prepared.v1":
        value = D07IngressRecallPreparedV1(**raw)
        thaw_d07_ingress_recall_request_v1(background_json_loads_v3(value.frozen_json))
    elif raw.get("schema") in {"d07.prepared-execution.v1", "d07.relationship-prepared.v2"}:
        if raw["schema"] == "d07.relationship-prepared.v2":
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            value = decode_native_named_d07_value_v2(row[0], D07RelationshipPreparedV2)
        else:
            value = D07PreparedExecutionV1(**raw)
        thaw_d07_cognition_request_v1(background_json_loads_v3(value.frozen_json))
    elif raw.get("schema") == "d07.reflection-prepared.v3":
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        value = decode_typed_production_value_v1(row[0], D07ReflectionPreparedV3)
        thaw_d07_cognition_request_v1(background_json_loads_v3(value.frozen_json))
    elif raw.get("schema")=="d07.artifact-observation-prepared.v3":
        from .artifact_phase_observation_execution_v1 import artifact_observation_prepared_from_wire_v3
        value=artifact_observation_prepared_from_wire_v3(row[0])
        thaw_d07_cognition_request_v1(background_json_loads_v3(value.frozen_json))
    elif raw.get("schema") == "d07.general-growth-prepared.v1":
        from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
        from ..model_broker.general_growth_cognition_v1 import thaw_general_growth_cognition_request_v1
        raw["context_source_refs"]=tuple(raw["context_source_refs"])
        raw["support_source_refs"]=tuple(raw["support_source_refs"])
        value=D07GeneralGrowthPreparedV1(**raw)
        thaw_general_growth_cognition_request_v1(background_json_loads_v3(value.frozen_json))
    elif raw.get("schema") == "d07.method-growth-prepared.v2":
        from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2, method_growth_value_from_wire_v2
        value = method_growth_value_from_wire_v2(row[0], D07MethodGrowthPreparedV2)
        thaw_d07_cognition_request_v1(background_json_loads_v3(value.frozen_json))
    else:
        raise ValueError("unregistered actual D07 prepared schema")
    if value.namespace != namespace or value.job_id != job_id or value.digest != row[1]:
        raise ValueError("D07 prepared identity differs")
    return value


def _read_rows(snapshot, versions):
    rows = []
    for version in sorted(versions, key=lambda v: v.key.token):
        atom = snapshot.get(version.key)
        if atom is None or atom.revision != version.revision:
            raise ValueError("D07 current execution read is not in frame")
        rows.append(D07ExecutionReadV1(atom.key.token, atom.revision, atom.valid, canonical_serialize(atom.value)))
    return tuple(rows)


def require_current_d07_content_reads_v1(db, prepared, *, issuer=None):
    if not db.in_transaction:
        raise ValueError("D07 current execution proof requires pinned transaction")
    rows = prepared.read_rows
    inventory = prepared.query_inventory_json
    if issuer is not None:
        committed = read_d07_original_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id)
        if committed is None or committed[0]["prepared_digest"] != prepared.digest:
            raise ValueError("D07 actual prepared Graph commit original missing")
        rows = tuple(D07ExecutionReadV1(**r) for r in committed[0]["post_read_rows"])
        inventory = committed[0]["post_query_inventory_json"]
        for external in background_json_loads_v3(prepared.external_content_originals_json):
            if set(external) != {"kind", "ref", "revision", "digest"} or external["kind"] != "d08_joint_plan_intent":
                raise ValueError("D07 unregistered external content original kind")
            actual = read_d07_joint_plan_semantic_target_v1(db, issuer, prepared.namespace, VersionedRef(external["ref"], external["revision"]))
            if actual.original_digest != external["digest"]:
                raise ValueError("D07 exact signed semantic target changed")
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    from .artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
    named = type(prepared) in {D07RelationshipPreparedV2, D07MethodGrowthPreparedV2,D07ArtifactObservationPreparedV3} or (
        type(prepared) is D07ReflectionPreparedV3 and prepared.cycle_ref is not None)
    if named and issuer is not None:
        from .foreground_call_plan_v1 import require_current_named_c3_cycle_v2
        require_current_named_c3_cycle_v2(db, namespace=prepared.namespace, prepared=prepared, issuer=issuer)
    reflection_lineage=None
    if type(prepared) is D07ReflectionPreparedV3 and issuer is not None:
        from .d07_reflection_execution_v1 import verify_reflection_checkpoint_member_v3
        reflection_lineage=verify_reflection_checkpoint_member_v3(db,prepared=prepared,issuer=issuer)
    for row in rows:
        if (reflection_lineage is not None and reflection_lineage[0]=="adopted_child"
                and row.ref==prepared.checkpoint_ref.key.token):
            if (row.revision!=prepared.checkpoint_ref.revision or not row.valid
                    or canonical_digest(background_json_loads_v3(row.value_json))!=prepared.checkpoint_digest):
                raise ValueError("reflection frozen checkpoint differs from authenticated parent birth")
            continue
        if named and row.ref == prepared.cycle_ref.key.token:
            continue
        if NamespaceId.from_key(AtomKey.from_token(row.ref)) != prepared.namespace:
            raise ValueError("D07 frozen read crosses namespace")
        current = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(row.ref,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (row.ref,)).fetchone())
        if row.revision == 0:
            if row.valid or current is not None:
                raise ValueError("D07 exact negative content read now exists")
        elif (current is None or (current[0], bool(current[2])) != (row.revision, row.valid)
                or canonical_serialize(background_json_loads_v3(current[1])) != row.value_json):
            raise ValueError("D07 actual cognition content became stale")
    for page in background_json_loads_v3(inventory):
        if not page["complete"]:
            raise ValueError("D07 incomplete query cannot prove exact current selection")
        from .domain_background_read_v3 import read_bound_d07_model_seal_query_rows_v3
        handled,current_rows=read_bound_d07_model_seal_query_rows_v3(db,prepared.namespace,page["type_id"])
        if not handled:
            from ..authority_service.d07_authority_model_source_read_v3 import read_bound_current_d07_authority_query_rows_v3
            handled,current_rows=read_bound_current_d07_authority_query_rows_v3(db,prepared.namespace,page["type_id"])
        rows=(list(current_rows) if handled else db.execute(
            "SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
            (*prepared.namespace.as_tuple,page["type_id"])).fetchall())
        expected=[tuple(item) for item in page["rows"]]
        if reflection_lineage is not None and reflection_lineage[0]=="adopted_child":
            expected=[(ref,reflection_lineage[1].revision) if ref==prepared.checkpoint_ref.key.token
                and revision==prepared.checkpoint_ref.revision else (ref,revision) for ref,revision in expected]
        if len(rows) > 128 or rows != expected:
            raise ValueError("D07 actual negative/query selection scope changed")


def _source_input(frame, roots):
    heads = _heads(frame.snapshot)
    qualify_current_source_heads_v1(frame.envelope.authority.namespace, roots, heads,
        audience=frame.envelope.authority.audience[0], purpose=frame.envelope.authority.purpose)
    values = []
    for ref in roots:
        atom = frame.snapshot.get(AtomKey.from_token(ref))
        if atom is None or not atom.valid:
            raise ValueError("D07 model source is unavailable")
        values.append(D07QualifiedSourceV1(VersionedRef(ref, atom.revision), SourceRecord.from_dict(atom.value)))
    return tuple(values)


def freeze_current_d07_stage_v1(frame, stage, workflow, installation_id):
    """Derive the model's question and sources from actual installed stage data."""
    if stage.status != "queued" or stage.envelope != frame.envelope or workflow.work_kind != WORK_KIND:
        raise ValueError("D07 actual queued current stage/workflow required")
    if stage.work_kind == "concern":
        choice = stage.provenance["choice"]
        tickets = tuple(t for t in stage.provenance["tickets"] if t.ticket_id == choice.ticket_id)
        if len(tickets) != 1:
            raise ValueError("D07 actual concern choice is not unique")
        ticket = tickets[0]
        target_ref = ticket.concern_ref or source_key(*frame.envelope.authority.namespace.as_tuple,
            AtomKey.from_token(ticket.source_refs[0]).owner.subject).token
        question = ticket.question_key
        if ticket.concern_ref:
            concern = frame.snapshot.get(AtomKey.from_token(ticket.concern_ref))
            if concern is None or not concern.valid or concern.key.type_name != "d07.concern.v1":
                raise ValueError("D07 chosen concern original unavailable")
            question = "Examine the unresolved concern anchored at " + concern.value["anchor_ref"]
        input = D07CognitionInputV1(frame.envelope.authority.namespace, frame.envelope.identity.activity_id,
            "concern", ticket.question_key, question, target_ref, _source_input(frame, ticket.source_refs))
        semantic = stage.provenance.get("semantic_question")
        if semantic is not None:
            from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2
            from .artifact_phase_observation_v1 import ArtifactPhaseObservationQuestionV1
            if type(semantic) not in {D07SemanticQuestionV1, D07RelationshipSemanticQuestionV2, D07MethodGrowthSemanticQuestionV2, ArtifactPhaseObservationQuestionV1} or set(semantic.source_refs) != set(ticket.source_refs):
                raise ValueError("D07 actual semantic question differs from chosen source scope")
            target = stage.provenance.get("semantic_target")
            if (type(target) is not D07SemanticTargetOriginalV1 or target.original_ref != semantic.target_ref.ref
                    or target.revision != semantic.target_ref.version):
                raise ValueError("D07 exact authenticated semantic target missing from preparation")
            input = replace(input, question_key=semantic.question_key, question=semantic.question,
                target_ref=semantic.target_ref.ref, target_original_json=target.value_json,
                target_original_kind=target.kind, target_original_digest=target.original_digest)
    elif stage.work_kind == "simulation":
        registered = stage.provenance["request"]
        if type(registered) is not SimulationRequest or registered.predictions:
            raise ValueError("D07 simulation intent must not contain fabricated future predictions")
        input = D07CognitionInputV1(frame.envelope.authority.namespace, registered.activity_id, "simulation",
            "simulation:" + frame.envelope.identity.operation_id, "Compare the supplied hypothetical assumptions",
            stage.request.simulation_request_ref, _source_input(frame, registered.snapshot_refs),
            baseline=registered.baseline, alternatives=registered.alternatives, unknowns=registered.unknowns)
        if stage.provenance.get('forecast_mode')=='declared_forecast':
            from .conditioned_self_operations_v1 import build_current_simulation_forecast_context_v1
            context,digest=build_current_simulation_forecast_context_v1(frame,stage)
            input=replace(input,target_original_json=context,target_original_kind='simulation_forecast_context_v1',
                target_original_digest=digest)
    elif stage.work_kind == "reflection":
        request = stage.provenance["reflection_request"]
        checkpoint = frame.snapshot.get(AtomKey.from_token(request["reflection_ref"]))
        if checkpoint is None or not checkpoint.valid or checkpoint.value["status"] != "continue":
            raise ValueError("D07 reflection must wait for a new information trigger")
        input = D07CognitionInputV1(frame.envelope.authority.namespace, frame.envelope.identity.activity_id,
            "reflection", request["question_key"], request["question"], request["reflection_ref"],
            _source_input(frame, tuple(request["source_refs"])), tuple(checkpoint.value["unresolved_slots"]),
            tuple(checkpoint.value["discriminating_refs"]), request["causal_depth"])
    else:
        raise ValueError("unregistered D07 current cognitive work")
    installation = D07CognitionInstallationV1(installation_id, workflow.provider_id, workflow.model_id,
        workflow.provider_config_ref, workflow.provider_config_digest, workflow.max_output_tokens)
    return freeze_d07_cognition_request_v1(input, installation)


def _clock_original(db, issuer, namespace, mapping):
    from .d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE, SIGN_KIND as CLOCK_SIGN_KIND
    row=_producer_original_point_v3(db,table=CLOCK_TABLE,columns=("original_json","original_digest","signature"),
        key_columns=("bot","persona","revision"),key=(*namespace.as_tuple,mapping.version),
        legacy_reader=lambda:db.execute(f"SELECT original_json,original_digest,signature FROM {CLOCK_TABLE} "
            "WHERE bot=? AND persona=? AND revision=?",(*namespace.as_tuple,mapping.version)).fetchone())
    if row is None:
        raise ValueError("D07 role time requires its actual signed Owner clock original")
    wire,digest,signature=row
    from .domain_background_read_v3 import background_verify_signature_v3
    background_verify_signature_v3(issuer._signer,CLOCK_SIGN_KIND,wire,signature)
    raw = background_json_loads_v3(wire)
    if (canonical_digest(raw) != digest or raw["mapping"] != _mapping_dict(mapping)
            or get_clock_mapping(db, mapping.mapping_id, mapping.version) != mapping):
        raise ValueError("D07 actual role clock original differs")
    return digest


@dataclass(frozen=True, slots=True)
class D07ExecutionResourcesV1:
    frame: CurrentOperationFrameV1
    job: PersistentJob
    resource_quote: ResourceQuote
    body_reservation: object
    reservation_digest: str
    body_state_ref: str
    body_profile_ref: str
    component_id: str
    clock_mapping_json: str
    clock_original_digest: str
    content_read_rows: tuple[D07ExecutionReadV1, ...]
    query_inventory_json: str
    writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]


def _prepare_d07_resources_in_transaction_v1(db, *, frame, ids, work_kind, frozen,
        stage_input_digest, job_continuation, original_ref, workflow, lease,
        resource_issuer, body_authority, clock_mapping, clock_digest, policy,
        body_policy_id, body_policy_version):
    """Once-only resources inside the caller's actual held W01 transaction.

    Fixed Owner/Self wrappers provide qualified input and deadline; this kernel
    does not supply an actor, permission, template choice or another write fence.
    """
    envelope, ns = frame.envelope, frame.envelope.authority.namespace
    identity = envelope.identity
    continuation = job_continuation
    deadline = datetime.fromtimestamp(envelope.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    profile_key = BodyDomain.profile_write(policy.profile).key
    state_key = BodyDomain.state_write(ns, policy.initial_state).key
    profile_atom, state_atom = (frame.snapshot.get(key) for key in (profile_key, state_key))
    if (profile_atom is None or not profile_atom.valid or profile_atom.value != _json(asdict(policy.profile))
            or state_atom is None or not state_atom.valid):
        raise ValueError("D07 actual current BodyProfile/BodyState absent")
    state = BodyState(**state_atom.value)
    inventory=tuple((atom.key.token,atom.revision,atom.value,atom.valid)
        for atom in background_inventory_v3(db,ns,"d02.reservation.v1",valid_only=False))
    if len(inventory) > 128:
        raise ValueError("D07 body reservation inventory requires bounded continuation")
    reservations = []
    reads = {v.key: v for v in frame.snapshot.versions}
    for ref, revision, value, valid in inventory:
        key = AtomKey.from_token(ref)
        atom = frame.snapshot.get(key)
        if valid != 1 or atom is None or atom.revision != revision or atom.value != value:
            raise ValueError("D07 full current body reservation inventory must be in Owner frame")
        reservations.append(BodyReservation(**{**atom.value, "settled_components": tuple(atom.value["settled_components"])}))
    job = PersistentJob(ids["job"], identity.operation_id, identity.activity_id, identity.effect_id,
        *ns.as_tuple, original_ref, "queued", "d07." + work_kind, continuation, None, deadline,
        lease.lease_id, ids["quote"], {"executor": "d07.installed-cognition.v1", "policy": workflow.template_version},
        None, None, 0, 0, {}, None)
    settlement_key = AtomKey(Owner("activity", *ns.as_tuple, identity.activity_id), "d02.settlement.v1", ids["settlement"])
    quote = ResourceQuote(ids["quote"], 1, *ns.as_tuple, identity.activity_id, identity.operation_id,
        identity.effect_id, lease.lease_id, WORK_KIND, "d07-input:" + frozen.input_digest[:48],
        envelope.deadline_utc, "d07-resource:" + canonical_digest(workflow.provider_config_ref)[:48],
        job_graph_write(job).key.token, (), (settlement_key.token,), dict(workflow.quote_ceiling), None, envelope.deadline_utc)
    resource_issuer.issue_quote(db, quote)
    db.execute("INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)",
        (*ns.as_tuple, "resource_lease", quote.quote_id, str(quote.version)))
    quoted_envelope = replace(envelope, version_guard=replace(envelope.version_guard,
        resource_lease_versions=(VersionedRef(quote.quote_id, quote.version),)))
    body = body_authority.issue_fixed_quote_and_reservation(db, resource_issuer, quoted_envelope, quote,
        body_policy_id, body_policy_version, state, tuple(reservations), ids["reservation"], identity.effect_id)
    if body.replayed:
        raise ValueError("D07 orphan prior body quote cannot authorize a new execution")
    reservation_digest = canonical_digest({"schema": "d07.execution-reservation.v1", "frozen": frozen,
        "stage_input_digest": stage_input_digest, "job": job, "quote": quote, "body_quote": body.body_quote,
        "clock_digest": clock_digest, "owner_guard": frame.owner_guard})
    reserve_budget(db, lease.lease_id, identity.operation_id, reservation_digest, quote.ceiling)
    # Accounting heads change legitimately at settlement. Only content/query
    # dependencies remain the execution/adoption current-read requirement.
    content_versions = tuple(v for v in frame.snapshot.versions if not v.key.type_name.startswith(("runtime.", "d02.")))
    rows = _read_rows(frame.snapshot, content_versions)
    query = tuple({"type_id": p.type_id, "rows": tuple((v.key.token, v.revision) for v in p.row_versions),
        "complete": p.complete} for p in frame.query_coverage if not p.type_id.startswith(("runtime.", "d02.")))
    for key in (body.reservation_write.key, job_graph_write(job).key, settlement_key):
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)).fetchone() is not None:
            raise ValueError("D07 new execution resource/job/settlement must be truly absent")
        reads[key] = GraphVersion(key, 0)
    updated_envelope = replace(quoted_envelope, version_guard=replace(quoted_envelope.version_guard,
        read_versions=tuple(reads.values())))
    updated_frame = replace(frame, envelope=updated_envelope)
    return D07ExecutionResourcesV1(updated_frame, job, quote, body, reservation_digest,
        state_key.token, profile_key.token, policy.component.component_id,
        canonical_serialize(_mapping_dict(clock_mapping)), clock_digest, rows,
        canonical_serialize(query), (body.reservation_write, job_graph_write(job)), tuple(reads.values()))


def prepare_d07_execution_in_transaction_v1(db, *, frame, stage, workflow, installation_id,
        d11_issuer, resource_issuer, body_authority, clock_mapping, body_policy_id, body_policy_version):
    """Return exact D02 reservation+D11 job writes for one atomic W01 preparation."""
    if (not db.in_transaction or type(frame) is not CurrentOperationFrameV1
            or type(stage) is not D07CurrentBehaviorStageV1 or type(body_authority) is not D02BodyQuoteAuthority
            or type(clock_mapping) is not CharacterClockMapping or stage.envelope.identity.effect_id is None):
        raise ValueError("D07 actual Owner/role-resource preparation required")
    envelope, ns = frame.envelope, frame.envelope.authority.namespace
    identity = envelope.identity
    ids = d07_execution_ids_v1(ns, identity.operation_id, stage.work_kind)
    prior = read_prepared_d07_execution_v1(db, d11_issuer, ns, ids["job"])
    if prior is not None:
        raise ValueError("D07 preparation replay must read its actual operation receipt")
    if (workflow.purpose != "proposal" or not set(envelope.authority.audience) <= set(workflow.audiences)):
        raise ValueError("D07 cognition workflow purpose/audience is unconfigured")
    lease = get_budget_lease(db, envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db, lease.lease_id)
    grant = d11_issuer.current_budget_grant(db, lease.lease_id)
    if (WORK_KIND not in grant.allowed_work_kinds or (lease.bot_id, lease.persona_id) != ns.as_tuple
            or any(v > grant.max_ceiling.get(k, 0) for k, v in workflow.quote_ceiling.items())):
        raise ValueError("D07 explicit signed workflow budget is insufficient")
    frozen = freeze_current_d07_stage_v1(frame, stage, workflow, installation_id)
    clock_digest = _clock_original(db, d11_issuer, ns, clock_mapping)
    clock_mapping.character_at(datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z"))
    policy = body_authority.policy(db, ns, body_policy_id, body_policy_version)
    if policy.work_kind != WORK_KIND:
        raise ValueError("D07 explicitly installed fixed body policy required")
    limits = [envelope.deadline_utc, policy.valid_until,
        datetime.fromisoformat(clock_mapping.valid_until_utc.replace("Z", "+00:00")).timestamp()]
    if stage.work_kind in {"concern", "reflection"}:
        choice = stage.provenance["choice"]
        limits.append(next(t.valid_until for t in stage.provenance["tickets"] if t.ticket_id == choice.ticket_id))
    deadline_upper = min(limits)
    if deadline_upper <= frame.now_utc:
        raise ValueError("D07 current selected ticket/clock/body policy lifetime is exhausted")
    if deadline_upper != envelope.deadline_utc:
        envelope = replace(envelope, deadline_utc=deadline_upper,
            monotonic_deadline=min(envelope.monotonic_deadline, __import__("time").monotonic() + deadline_upper - frame.now_utc))
        frame = replace(frame, envelope=envelope)
        stage = replace(stage, envelope=envelope, proposal=replace(stage.proposal, envelope=envelope))
    deadline = datetime.fromtimestamp(envelope.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    original_ref = "d07-prepared:" + identity.operation_id
    continuation = {"request": _json(stage.request), "input_digest": stage.input_digest,
        "choice": _json(stage.provenance.get("choice")), "original_ref": original_ref,
        "prepared_job_id": ids["job"], "quote_id": ids["quote"], "quote_version": 1,
        "call_id": ids["call"], "work_kind": stage.work_kind}
    if stage.work_kind == "simulation":
        continuation.update({"simulation_request_ref": stage.request.simulation_request_ref,
            "registered_request": _json(stage.provenance["request"]),
            "dedicated_budget_original_ref": stage.provenance["dedicated_budget_original"]})
    if stage.work_kind == "reflection":
        continuation.update(_json(stage.provenance["reflection_request"]))
        continuation["reflection_category"] = stage.request.category
    resources = _prepare_d07_resources_in_transaction_v1(db, frame=frame, ids=ids,
        work_kind=stage.work_kind, frozen=frozen, stage_input_digest=stage.input_digest,
        job_continuation=continuation, original_ref=original_ref, workflow=workflow, lease=lease,
        resource_issuer=resource_issuer, body_authority=body_authority, clock_mapping=clock_mapping,
        clock_digest=clock_digest, policy=policy, body_policy_id=body_policy_id,
        body_policy_version=body_policy_version)
    job, quote, body = resources.job, resources.resource_quote, resources.body_reservation
    reservation_digest, rows = resources.reservation_digest, resources.content_read_rows
    target = stage.provenance.get("semantic_target")
    external_originals = () if target is None or target.kind == "graph_head" else (
        {"kind": target.kind, "ref": target.original_ref, "revision": target.revision, "digest": target.original_digest},)
    prepared = D07PreparedExecutionV1(ns, identity.operation_id, identity.activity_id, identity.effect_id,
        identity.attempt_id, job.job_id, ids["call"], ids["execution"], stage.work_kind, stage.input_digest,
        canonical_serialize(asdict(frozen)), rows, resources.query_inventory_json, canonical_serialize(external_originals), envelope.authority.audience,
        envelope.authority.purpose, canonical_serialize(asdict(frame.owner_guard)), canonical_serialize(asdict(envelope.authority)), quote.quote_id, quote.version,
        canonical_digest(quote), reservation_digest, body_policy_id, body_policy_version, body.body_quote.quote_id,
        body.body_quote_version, canonical_digest(body.body_quote), body.reservation_write.key.token,
        resources.body_state_ref, resources.body_profile_ref, resources.component_id, resources.clock_mapping_json,
        clock_digest, frame.activation_generation, frame.snapshot.epochs[0].revision,
        envelope.version_guard.access_epoch, envelope.version_guard.delete_epoch)
    semantic = stage.provenance.get("semantic_question")
    if type(semantic) is D07RelationshipSemanticQuestionV2:
        _, cycle = _require_relationship_semantic_question_v2(db, d11_issuer, frame, semantic)
        semantic_original = read_d07_original_v1(db, d11_issuer, ns, "semantic_question", stage.request.trigger_original_ref)
        if semantic_original is None or semantic_original[0] != background_json_loads_v3(canonical_serialize(asdict(semantic))):
            raise ValueError("Relationship C3 cannot use an unregistered semantic question")
        from .foreground_call_plan_v1 import ForegroundModelAttemptV1
        # Enforce the same finite whole plan before any actual call can be acquired.
        replace(cycle.call_plan, attempts=(*cycle.call_plan.attempts, ForegroundModelAttemptV1(
            "C3", prepared.call_id, None, prepared.operation_id, prepared.reservation_digest,
            lease.lease_id, quote.ceiling["input_tokens"], quote.ceiling["output_tokens"], "reserved")))
        prepared = D07RelationshipPreparedV2(**{**asdict(prepared), "namespace": ns, "read_rows": rows,
            "schema": "d07.relationship-prepared.v2", "semantic_question_ref": stage.request.trigger_original_ref,
            "semantic_question_digest": semantic_original[1], "cycle_ref": semantic.cycle_ref,
            "cycle_digest": semantic.cycle_digest, "call_plan_digest": canonical_digest(cycle.call_plan),
            "c02_operation_id": cycle.c02_operation_id, "cancel_generation": cycle.cancel_generation})
    from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2, D07MethodGrowthPreparedV2
    if type(semantic) is D07MethodGrowthSemanticQuestionV2:
        _, cycle = _require_method_growth_semantic_question_v2(db, d11_issuer, frame, semantic)
        semantic_original = read_d07_original_v1(db, d11_issuer, ns, "semantic_question", stage.request.trigger_original_ref)
        if semantic_original is None or semantic_original[0] != background_json_loads_v3(canonical_serialize(asdict(semantic))):
            raise ValueError("growth C3 cannot use an unregistered or changed signed semantic question")
        from .foreground_call_plan_v1 import ForegroundModelAttemptV1
        replace(cycle.call_plan, attempts=(*cycle.call_plan.attempts, ForegroundModelAttemptV1(
            "C3", prepared.call_id, None, prepared.operation_id, prepared.reservation_digest,
            lease.lease_id, quote.ceiling["input_tokens"], quote.ceiling["output_tokens"], "reserved")))
        prepared = D07MethodGrowthPreparedV2(**{**asdict(prepared), "namespace": ns, "read_rows": rows,
            "schema": "d07.method-growth-prepared.v2", "semantic_question_ref": stage.request.trigger_original_ref,
            "semantic_question_digest": semantic_original[1], "cycle_ref": semantic.cycle_ref,
            "cycle_digest": semantic.cycle_digest, "call_plan_digest": canonical_digest(cycle.call_plan),
            "proposal_head": semantic.proposal_head, "proposal_digest": semantic.proposal_digest,
            "c02_operation_id": semantic.c02_operation_id, "source_head": semantic.source_head, "source_digest": semantic.source_digest,
            "parent_budget_lease_ref": semantic.parent_budget_lease_ref, "original_deadline_utc": semantic.original_deadline_utc,
            "cancel_generation": cycle.cancel_generation})
    if stage.work_kind == "reflection" and "reflection_continuation" in stage.provenance:
        from .d07_reflection_execution_v1 import reflection_preparation_fields_v3
        fields = reflection_preparation_fields_v3(db, issuer=d11_issuer,
            continuation=stage.provenance["reflection_continuation"],
            continuation_digest=stage.provenance["reflection_continuation_digest"],now_utc=frame.now_utc)
        prepared = D07ReflectionPreparedV3(**{**{name:getattr(prepared,name) for name in prepared.__dataclass_fields__},**fields})
        if prepared.cycle_ref is not None:
            from .foreground_call_plan_v1 import ForegroundModelAttemptV1
            from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
            cycle = foreground_cycle_from_wire_v1(get_job(db,prepared.cycle_ref.key.name).continuation)
            replace(cycle.call_plan,attempts=(*cycle.call_plan.attempts,ForegroundModelAttemptV1(
                "C3",prepared.call_id,None,prepared.operation_id,prepared.reservation_digest,lease.lease_id,
                quote.ceiling["input_tokens"],quote.ceiling["output_tokens"],"reserved")))
    from .artifact_phase_observation_v1 import ArtifactPhaseObservationQuestionV1
    if type(semantic)is ArtifactPhaseObservationQuestionV1:
        from .artifact_phase_observation_execution_v1 import specialize_artifact_observation_prepared_v3
        prepared=specialize_artifact_observation_prepared_v3(db,frame=frame,stage=stage,
            prepared=prepared,quote=quote,issuer=d11_issuer)
    require_current_d07_content_reads_v1(db, prepared)
    updated_frame = resources.frame
    updated_envelope = updated_frame.envelope
    updated_stage = replace(stage, envelope=updated_envelope,
        proposal=replace(stage.proposal, envelope=updated_envelope, required_bundle_parts=("persistent_job",)),
        read_versions=resources.read_versions)
    from ..domains.d01.production_operations_v1 import plain_v1
    from .artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
    payload = plain_v1(prepared) if type(prepared) in {D07ReflectionPreparedV3,D07ArtifactObservationPreparedV3} else asdict(prepared)
    record_d07_original_in_transaction_v1(db, d11_issuer, ns, "prepared", job.job_id, payload)
    record_d07_original_in_transaction_v1(db, d11_issuer, ns, "accounting_prepared", job.job_id,
        {"schema": "d07.accounting-prepared.v1", "prepared_digest": prepared.digest,
         **{name: _json(getattr(prepared, name)) for name in D07_ACCOUNTING_FIELDS}})
    create_job(db, job, job.operation_id, reservation_digest)
    from .d07_source_preparation_members_v3 import register_d07_source_preparation_job_v3
    register_d07_source_preparation_job_v3(db,job)
    return D07PreparationStageV1(updated_frame, updated_stage, prepared, job,
        resources.writes, resources.read_versions)


def verify_current_d07_preparation_stage_v1(db, preparation, service):
    """DB-only independent recheck of the fixed prepared member set before CAS."""
    if not db.in_transaction or type(preparation) is not D07PreparationStageV1:
        raise ValueError("D07 fixed preparation verification needs W01 transaction")
    prepared, frame, stage = preparation.prepared, preparation.frame, preparation.stage
    current = read_prepared_d07_execution_v1(db, service.d11_issuer, prepared.namespace, prepared.job_id)
    if current != prepared or get_job(db, prepared.job_id) != preparation.job:
        raise ValueError("D07 prepared/runtime job original differs")
    if preparation.replayed:
        require_current_d07_content_reads_v1(db, prepared, issuer=service.d11_issuer)
        if preparation.writes:
            raise ValueError("D07 preparation replay must not reapply member writes")
        return
    require_current_d07_content_reads_v1(db, prepared)
    quote = service.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    body_quote = service.body_authority.original_body_quote(db, prepared.body_quote_ref,
        prepared.body_quote_version, quote, prepared.operation_id)
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, prepared.operation_id)).fetchone()
    if (canonical_digest(quote) != prepared.quote_digest or canonical_digest(body_quote) != prepared.body_quote_digest
            or reservation != (prepared.reservation_digest, canonical_serialize(dict(quote.ceiling)), "reserved")
            or preparation.job.phase != "queued" or preparation.job.fence != 0 or preparation.job.cancel_epoch
            or quote.graph_job_ref != job_graph_write(preparation.job).key.token
            or len(preparation.writes) != 2 or preparation.writes[1] != job_graph_write(preparation.job)
            or preparation.writes[0].key.token != prepared.body_reservation_ref
            or preparation.writes[0].value["quote_id"] != prepared.body_quote_ref
            or preparation.writes[0].value["effect_id"] != prepared.effect_id):
        raise ValueError("D07 actual signed quote/reserve/fixed member set differs")
    from .artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3,current_artifact_observation_basis_for_d07_v1
    if type(prepared)is D07ArtifactObservationPreparedV3:
        basis=current_artifact_observation_basis_for_d07_v1(service,db,frame,stage.provenance['semantic_question'])
        if basis!=stage.provenance.get('artifact_observation_basis') or basis.digest!=prepared.observation_basis_digest:
            raise ValueError('observation preparation changed its actual current basis before CAS')
    workflow = service._configured(prepared)
    frozen = freeze_current_d07_stage_v1(frame, stage, workflow, service.bundle.installation_policy.installation_id)
    if canonical_serialize(asdict(frozen)) != prepared.frozen_json or stage.input_digest != prepared.stage_input_digest:
        raise ValueError("D07 exact current source/choice/model wire changed before preparation CAS")
    if stage.work_kind == "concern":
        from .d07_current_behavior_v1 import advance_current_concerns_v1, D07ConcernInputsV1
        provenance = stage.provenance
        checked = advance_current_concerns_v1(frame.envelope, stage.request,
            D07ConcernInputsV1(frame.snapshot, provenance["tickets"], provenance["policy"],
                provenance["issuance_originals"], provenance["trigger"], frame.now_utc, provenance["focus_epoch"]))
        if (checked.proposal.typed_writes != stage.proposal.typed_writes or checked.input_digest != stage.input_digest
                or checked.provenance != {k: v for k, v in stage.provenance.items() if k not in {"semantic_question", "semantic_target", "artifact_observation_basis"}}
                or checked.status != "queued"):
            raise ValueError("D07 installed pure fair choice differs from actual preparation")
        if "semantic_question" in stage.provenance and resolve_current_d07_semantic_target_v1(db, service.d11_issuer,
                frame, stage.provenance["semantic_question"]) != stage.provenance["semantic_target"]:
            raise ValueError("D07 signed semantic target differs before exact preparation CAS")
    elif stage.work_kind == "reflection":
        from .d07_reflection_execution_v1 import read_actual_d07_reflection_request_v1
        actual = read_actual_d07_reflection_request_v1(db, service.d11_issuer, prepared.namespace,
            stage.request.trigger_original_ref)
        if actual is None or asdict(actual) != stage.provenance["reflection_request"]:
            raise ValueError("D07 reflection preparation lost its actual adopted cognition/root depth")
        from .d07_current_behavior_v1 import advance_current_concerns_v1, D07ConcernInputsV1
        provenance = stage.provenance
        checked = advance_current_concerns_v1(frame.envelope, stage.request,
            D07ConcernInputsV1(frame.snapshot, provenance["tickets"], provenance["policy"],
                provenance["issuance_originals"], provenance["trigger"], frame.now_utc, provenance["focus_epoch"]))
        if (checked.proposal.typed_writes != stage.proposal.typed_writes or checked.input_digest != stage.input_digest
                or checked.provenance != {k: v for k, v in provenance.items() if k not in {"reflection_request","reflection_continuation","reflection_continuation_digest"}}
                or checked.status != "queued"):
            raise ValueError("D07 reflection fair preparation choice changed")


def record_d07_preparation_after_cas_v1(db, issuer, preparation, graph_receipt):
    """Seal actual post-prepare content heads after all exact member CAS writes."""
    from .d07_source_preparation_members_v3 import record_bound_d07_source_postcas_v3
    handled,digest=record_bound_d07_source_postcas_v3(db,issuer,preparation,graph_receipt)
    if handled:return digest
    if not db.in_transaction or type(preparation) is not D07PreparationStageV1:
        raise ValueError("D07 prepared closure requires actual same-transaction Graph CAS")
    prepared = preparation.prepared
    if getattr(graph_receipt, "status", None) != "committed":
        raise ValueError("D07 preparation graph receipt did not commit")
    for write in (*preparation.stage.proposal.typed_writes, *preparation.writes):
        row = _producer_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(write.key.token,),legacy_reader=lambda:db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone())
        if row is None or row[1] != 1 or background_json_loads_v3(row[0]) != write.value:
            raise ValueError("D07 fixed preparation member was not adopted")
    rows = []
    for observed in prepared.read_rows:
        row = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(observed.ref,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (observed.ref,)).fetchone())
        rows.append(D07ExecutionReadV1(observed.ref, row[0], bool(row[2]), canonical_serialize(background_json_loads_v3(row[1])))
            if row else observed)
    query = []
    for page in background_json_loads_v3(prepared.query_inventory_json):
        values = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
            (*prepared.namespace.as_tuple, page["type_id"])).fetchall()
        if len(values) > 128:
            raise ValueError("D07 post-prepare query closure exceeds bound")
        query.append({**page, "rows": values})
    value = {"schema": "d07.preparation-commit.v1", "prepared_digest": prepared.digest,
        "prepare_operation_id": prepared.prepare_operation_id, "graph_receipt_digest": canonical_digest(graph_receipt),
        "writes_digest": canonical_digest((*preparation.stage.proposal.typed_writes, *preparation.writes)),
        "post_read_rows": _json(tuple(rows)), "post_query_inventory_json": canonical_serialize(query)}
    return record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id, value)


def record_registered_simulation_request_in_transaction_v1(db, issuer, frame, ref, request):
    """Only W01's actual Owner command may register an unexecuted simulation intent."""
    if (not db.in_transaction or type(frame) is not CurrentOperationFrameV1
            or type(request) is not SimulationRequest or request.predictions
            or request.activity_id != frame.envelope.identity.activity_id or len(request.alternatives) > 2):
        raise ValueError("D07 exact registered hypothetical intent required")
    lease = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db, lease.lease_id)
    if lease.parent_id is None or (lease.bot_id, lease.persona_id) != frame.envelope.authority.namespace.as_tuple:
        raise ValueError("simulation requires an actual dedicated child budget")
    _source_input(frame, request.snapshot_refs)
    grant = issuer.current_budget_grant(db, lease.lease_id)
    budget = {"schema": "d07.dedicated-simulation-budget.v1", "namespace": asdict(frame.envelope.authority.namespace),
        "lease_id": lease.lease_id, "parent_id": lease.parent_id, "grant": asdict(grant),
        "grant_digest": canonical_digest(grant), "owner_guard": asdict(frame.owner_guard)}
    record_d07_original_in_transaction_v1(db, issuer, frame.envelope.authority.namespace, "simulation_budget", lease.lease_id, budget)
    original = {"schema": "d07.registered-simulation-original.v1", "request": asdict(request),
        "request_digest": canonical_digest(request), "dedicated_budget_ref": lease.lease_id,
        "owner_guard": asdict(frame.owner_guard)}
    record_d07_original_in_transaction_v1(db, issuer, frame.envelope.authority.namespace, "simulation_request", ref, original)
    return ProductionOriginalRefV1("d07.simulation_request", ref, canonical_digest(request))


def read_registered_simulation_request_v1(db, issuer, namespace, ref):
    row = read_d07_original_v1(db, issuer, namespace, "simulation_request", ref)
    if row is None:
        raise ValueError("D07 actual registered simulation request missing")
    raw = row[0]["request"]
    result = SimulationRequest(**{**raw, "snapshot_refs": tuple(raw["snapshot_refs"]),
        "alternatives": tuple(raw["alternatives"]), "predictions": tuple(tuple(p) for p in raw["predictions"]),
        "unknowns": tuple(raw["unknowns"])})
    if canonical_digest(result) != row[0]["request_digest"]:
        raise ValueError("D07 signed registered simulation semantic commitment differs")
    return result


def seal_d07_request_in_transaction_v1(db, issuer, prepared, request):
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1,thaw_current_general_growth_prepared_request_v1
    if type(prepared)is D07GeneralGrowthPreparedV1:
        from ..model_broker.general_growth_cognition_v1 import TEMPLATE_DIGEST as GENERAL_TEMPLATE_DIGEST
        frozen=thaw_current_general_growth_prepared_request_v1(prepared)
        template_digest=GENERAL_TEMPLATE_DIGEST
    elif type(prepared) is D07IngressRecallPreparedV1:
        from ..model_broker.d07_cognition_v1 import RECALL_TEMPLATE_DIGEST_V1
        frozen = thaw_d07_ingress_recall_request_v1(background_json_loads_v3(prepared.frozen_json))
        template_digest = RECALL_TEMPLATE_DIGEST_V1
    else:
        frozen = thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))
        template_digest = TEMPLATE_DIGEST
    job = get_job(db, prepared.job_id)
    if (not db.in_transaction or type(request) is not ModelCallRequest or request.call_id != prepared.call_id
            or request.prompt_template_digest != template_digest or request.identity.phase != WORK_KIND
            or dict(request.payload) != background_json_loads_v3(frozen.canonical_wire)
            or request.envelope.authority.namespace != prepared.namespace
            or request.envelope.authority.worker_fence != job.fence
            or request.envelope.authority.actor != job.lease_holder or job.phase != "running"):
        raise ValueError("D07 exact acquired current request required")
    from .reply_model_job import reply_request_wire_v1
    return record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "request", prepared.job_id,
        reply_request_wire_v1(request.envelope, request))


def read_original_d07_request_v1(db, issuer, prepared):
    from .natural_reply_job_v2 import _request_from_wire
    row = read_d07_original_v1(db, issuer, prepared.namespace, "request", prepared.job_id)
    if row is None:
        raise ValueError("D07 acquired request original missing")
    return _request_from_wire(canonical_serialize(row[0]))


def seal_d07_call_in_transaction_v1(db, issuer, prepared, intent):
    request = read_original_d07_request_v1(db, issuer, prepared)
    job = get_job(db, prepared.job_id)
    if (not db.in_transaction or type(intent) is not ModelEgressIntentV1
            or (intent.job_id, intent.call_id, intent.request_digest, intent.binding_digest,
                intent.budget_reservation_operation_id, intent.budget_reservation_digest) !=
               (prepared.job_id, prepared.call_id, request.digest, prepared.digest,
                prepared.operation_id, prepared.reservation_digest)
            or job.phase != "running" or job.fence != intent.worker_fence or job.lease_holder != intent.subject):
        raise ValueError("D07 Authority egress differs from original acquired call")
    return record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "call", prepared.job_id,
        model_to_wire(intent))


def read_current_original_ref_v1(db, namespace, ref, *, issuer):
    rows = db.execute(f"SELECT kind,payload_digest FROM {TABLE} WHERE bot=? AND persona=? AND original_ref=?",
        (*namespace.as_tuple, ref)).fetchall()
    if not rows:
        return None
    if len(rows) > 1:
        # The public preparation locator refers to the content original;
        # fixed accounting siblings share its job ID but do not replace it.
        rows = [r for r in rows if r[0] in {"prepared", "adopted", "simulation_request", "simulation_budget", "semantic_question", "reflection_request", "execution"}]
    if len(rows) != 1:
        raise ValueError("D07 original locator has conflicting kinds")
    kind, digest = rows[0]
    actual = read_d07_original_v1(db, issuer, namespace, kind, ref)
    versions = ()
    if kind == "prepared":
        versions = tuple(GraphVersion(AtomKey.from_token(r["ref"]), r["revision"]) for r in actual[0]["read_rows"])
    elif kind == "simulation_request":
        request = read_registered_simulation_request_v1(db, issuer, namespace, ref)
        digest = canonical_digest(request)
    elif kind == "simulation_budget":
        lease = get_budget_lease(db, ref)
        grant = issuer.current_budget_grant(db, ref)
        raw = actual[0]
        if (lease.parent_id is None or raw["lease_id"] != lease.lease_id or raw["parent_id"] != lease.parent_id
                or raw["grant"] != _json(asdict(grant)) or raw["grant_digest"] != canonical_digest(grant)):
            raise ValueError("D07 dedicated simulation budget current signed original differs")
        return ProductionOriginalRefV1("d11.dedicated-simulation-budget", ref, digest, ())
    elif kind == "adopted":
        raw = actual[0]
        key = AtomKey.from_token(raw["interpretation_ref"])
        row = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(key.token,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone())
        if (row is None or row[2] != 1 or row[0] != raw["interpretation_revision"]
                or canonical_digest(background_json_loads_v3(row[1])) != raw["interpretation_value_digest"]):
            raise ValueError("D07 adopted interpretation current original differs")
        return ProductionOriginalRefV1("d07.actual-adopted-interpretation", ref, raw["interpretation_value_digest"],
            (GraphVersion(key, row[0]),))
    return ProductionOriginalRefV1("d07." + kind, ref, digest, versions)


def stage_actual_d07_interpretation_writes_v1(db, *, prepared, issuer, envelope):
    """Actual model findings become D07 candidates only within exact paid scope."""
    from ..domains.d07 import CurrentInterpretationCandidate, D07DomainProvider, Stance, EvidenceStatus
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1, from_wire
    require_current_d07_content_reads_v1(db, prepared, issuer=issuer)
    from .d07_general_growth_execution_v1 import (D07GeneralGrowthPreparedV1,
        thaw_current_general_growth_prepared_request_v1,parse_current_general_growth_output_v1)
    general=type(prepared)is D07GeneralGrowthPreparedV1
    frozen=(thaw_current_general_growth_prepared_request_v1(prepared)if general
        else thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json)))
    if frozen.input.work_kind == "simulation":
        return (), ()  # Branches already preserve hypothetical eligibility.
    paid = read_d07_original_v1(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    body = read_d07_original_v1(db, issuer, prepared.namespace, "body_cost", prepared.job_id)
    actual = read_d07_original_v1(db, issuer, prepared.namespace, "result", "d07-result:" + prepared.call_id)
    if paid is None or body is None or actual is None or not paid[0]["paid"] or body[0]["unpaid_cost"]:
        raise ValueError("D07 semantic candidates need actual paid scoped model/body originals")
    result = from_wire(actual[0], D07CognitionResultReadV1)
    text = background_json_loads_v3(result.observation.result_json)
    if set(text) != {"text"}:
        raise ValueError("D07 semantic candidate result is not original model text")
    suggestion=(parse_current_general_growth_output_v1(prepared,text["text"],frozen)if general
        else parse_d07_cognition_output_v1(text["text"], frozen))
    source_inputs=(*frozen.input.context_sources,*frozen.input.support_sources)if general else frozen.input.sources
    sources={source.source_ref.ref:source.record for source in source_inputs}
    writes, reads = [], []
    for index, finding in enumerate(suggestion.findings):
        candidate = CurrentInterpretationCandidate("d07-interpretation:" + canonical_digest(
            (prepared.namespace, prepared.call_id, suggestion.output_digest, index))[:48], prepared.activity_id,
            frozen.input.question_key, finding.proposition, Stance(finding.stance), finding.subjective_conviction,
            EvidenceStatus(finding.evidence_status), finding.source_refs,
            tuple(sorted({sources[ref].provenance_root for ref in finding.source_refs})), suggestion.unknowns)
        write = D07DomainProvider.current_interpretation_write(envelope, candidate,
            source_dependencies=tuple(AtomKey.from_token(ref) for ref in finding.source_refs))
        row = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(write.key.token,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone())
        if row is not None:
            if row[2] != 1 or background_json_loads_v3(row[1]) != write.value:
                raise ValueError("D07 model interpretation key conflicts with existing graph")
            continue
        writes.append(write)
        reads.append(GraphVersion(write.key, 0))
    return tuple(writes), tuple(reads)


def record_d07_adopted_interpretations_after_cas_v1(db, issuer, prepared, writes, *, operation_id, receipt):
    """Expose only actual exact Graph adoption, never a self-authenticated DTO."""
    result = read_d07_original_v1(db, issuer, prepared.namespace, "result", "d07-result:" + prepared.call_id)
    if result is None or getattr(receipt, "status", None) != "committed":
        raise ValueError("D07 actual scoped result/Graph adoption receipt missing")
    for write in writes:
        if write.key.type_name != "d07.current_interpretation.v1":
            continue
        current = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(write.key.token,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone())
        history = None if current is None else db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (write.key.token, current[0])).fetchone()
        if (current is None or current[2] != 1 or background_json_loads_v3(current[1]) != write.value
                or history is None or history[0] != operation_id or history[2] != 1 or background_json_loads_v3(history[1]) != write.value):
            raise ValueError("D07 interpretation was not adopted by its actual graph event")
        original = {"schema": "d07.actual-cognition-adoption.v1", "interpretation_ref": write.key.token,
            "interpretation_revision": current[0], "interpretation_value_digest": canonical_digest(write.value),
            "adoption_operation_id": operation_id, "graph_receipt_digest": canonical_digest(receipt),
            "prepared_digest": prepared.digest, "actual_result_digest": result[1], "question_scope": write.value["question_key"],
            "supporting_refs": write.value["source_refs"], "meaningful_unknowns": write.value["meaningful_unknowns"]}
        record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "adopted", write.key.token, original)


def _clock_from_json(value):
    raw = background_json_loads_v3(value)
    return CharacterClockMapping(**{**raw, "character_origin": Decimal(raw["character_origin"]), "rate": Decimal(raw["rate"])})


D07_ACCOUNTING_FIELDS = (
    "namespace", "operation_id", "activity_id", "effect_id", "attempt_id", "job_id", "call_id", "execution_id",
    "work_kind", "stage_input_digest", "quote_id", "quote_version", "quote_digest", "reservation_digest",
    "body_policy_id", "body_policy_version", "body_quote_ref", "body_quote_version", "body_quote_digest",
    "body_reservation_ref", "body_state_ref", "body_profile_ref", "component_id", "clock_mapping_json",
    "clock_original_digest", "activation_generation", "graph_epoch", "access_epoch", "delete_epoch")


class D07AccountingPreparedV1:
    """Strict content-free view of the real prepared identity for paid recovery."""
    def __init__(self, raw):
        self_recall = type(raw) is dict and raw.get("schema") == "d07.ingress-recall-accounting-prepared.v1"
        expected = {"schema", "prepared_digest", *D07_ACCOUNTING_FIELDS}
        if self_recall:
            expected.add("prepare_operation_id")
        if (type(raw) is not dict or set(raw) != expected
                or not self_recall and raw["schema"] != "d07.accounting-prepared.v1"
                or self_recall and (raw["work_kind"] != "recall_need"
                    or raw["prepare_operation_id"] != raw["operation_id"])):
            raise ValueError("D07 exact historical accounting prepared fields required")
        self._raw = raw
        for name in D07_ACCOUNTING_FIELDS:
            setattr(self, name, NamespaceId(**raw[name]) if name == "namespace" else raw[name])
        self.digest = raw["prepared_digest"]
        self.prepare_operation_id = raw["prepare_operation_id"] if self_recall else "d07-prepare:" + self.operation_id


def read_d07_accounting_prepared_v1(db, issuer, namespace, job_id):
    row = read_d07_original_v1(db, issuer, namespace, "accounting_prepared", job_id)
    return None if row is None else D07AccountingPreparedV1(row[0])


def settle_d07_original_model_cost_in_transaction_v1(db, *, prepared, fact, issuer, resource_issuer):
    """Content-free actual settlement survives current source withdrawal."""
    if not db.in_transaction or type(fact) is not OriginalModelCostFactV1:
        raise ValueError("D07 actual independent cost transaction required")
    saved = read_d07_original_v1(db, issuer, prepared.namespace, "call", prepared.job_id)
    accounting = read_d07_original_v1(db, issuer, prepared.namespace, "accounting_prepared", prepared.job_id)
    if (saved is None or saved[0] != model_to_wire(fact.intent) or accounting is None
            or accounting[0]["prepared_digest"] != prepared.digest
            or (fact.intent.job_id, fact.intent.call_id, fact.intent.binding_digest,
                fact.intent.budget_reservation_operation_id) !=
               (prepared.job_id, prepared.call_id, prepared.digest, prepared.operation_id)):
        raise ValueError("D07 actual cost differs from preserved original accounting identity")
    prior = read_d07_original_v1(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    if prior is not None:
        if (prior[0]["terminal_digest"] != canonical_digest(asdict(fact.receipt))
                or prior[0]["prepared_digest"] != prepared.digest):
            raise ValueError("D07 paid cost conflicts with actual original terminal")
        return prior[0], ()
    quote = resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    preparation = read_d07_original_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id)
    graph_preparation = db.execute("SELECT activity_id FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*prepared.namespace.as_tuple, prepared.prepare_operation_id)).fetchone()
    reserved = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, prepared.operation_id)).fetchone()
    reserve_original = db.execute("SELECT digest FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*prepared.namespace.as_tuple, prepared.operation_id)).fetchone()
    if (canonical_digest(quote) != prepared.quote_digest or graph_preparation != (prepared.activity_id,)
            or reserved is None or reserved[0] != prepared.reservation_digest
            or reserved[2] not in {"reserved", "unknown", "partial_unknown", "partial_overrun", "settled", "overrun"}
            or background_json_loads_v3(reserved[1]) != dict(quote.ceiling) or reserve_original != (prepared.reservation_digest,)
            or quote.graph_job_ref != job_graph_write(get_job(db, prepared.job_id)).key.token
            or (quote.operation_id, quote.work_kind, quote.effect_id, quote.parent_budget_lease_ref) !=
               (prepared.operation_id, WORK_KIND, prepared.effect_id, fact.intent.budget_lease_id)
            or dict(quote.ceiling) != dict(fact.intent.budget_ceiling)
            or fact.intent.budget_reservation_digest != prepared.reservation_digest):
        raise ValueError("D07 actual prepared graph/reserve/signed quote original differs")
    known, unknown = original_model_budget_measurement(fact, quote, work_kind=WORK_KIND)
    if known and unknown:
        receipt = settle_budget_partial(db, quote.parent_budget_lease_ref, prepared.operation_id,
            prepared.reservation_digest, known, unknown, execution_revoked=True)
    else:
        receipt = settle_budget(db, quote.parent_budget_lease_ref, prepared.operation_id,
            prepared.reservation_digest, None if unknown else known, execution_revoked=True)
    cost_id = original_model_cost_operation_id_v1(prepared.namespace, prepared.call_id)
    cost = cost_settlement_graph_write(cost_settlement_from_runtime(db, bot_id=prepared.namespace.bot_id,
        persona_id=prepared.namespace.persona_id, activity_id=prepared.activity_id, bundle_operation_id=cost_id,
        effect_id=prepared.effect_id, settlement_id=cost_id, lease_id=quote.parent_budget_lease_ref,
        cost_operation_id=prepared.operation_id, budget_operation_id=prepared.operation_id,
        budget_phase="settle", prior_unknown_ref=None, execution_revoked=True))
    paid = receipt.status in {"settled", "overrun"} and not unknown
    value = {"schema": "d07.paid-model-result.v1", "prepared_digest": prepared.digest,
        "result_ref": "d07-result:" + prepared.call_id, "result_digest": fact.recovery.observation_digest, "cost_ref": cost.key.token,
        "cost_value": cost.value, "budget_receipt": asdict(receipt),
        "unknown_dimensions": unknown, "paid": paid,
        "terminal_digest": canonical_digest(asdict(fact.receipt))}
    ref = prepared.job_id if paid else prepared.job_id + ":" + canonical_digest(value)
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "paid_cost" if paid else "partial_cost", ref, value)
    return value, (cost,)



def settle_d07_paid_result_in_transaction_v1(db, *, prepared, result_read, fact, issuer, resource_issuer,
        holder, fence):
    """Import the actual scoped content after its independent actual settlement."""
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1, to_wire as result_to_wire
    if not db.in_transaction or type(result_read) is not D07CognitionResultReadV1:
        raise ValueError("D07 actual independent result transaction required")
    result_read.require_original(fact.intent, prepared)
    if (fact.recovery.state != "observed" or fact.recovery.content_erased
            or result_read.terminal_receipt != fact.receipt
            or result_read.observation.digest != fact.recovery.observation_digest
            or result_read.observation.usage != fact.recovery.usage or result_read.observation.cost != fact.recovery.cost):
        raise ValueError("D07 actual scoped output differs from the independent cost observation")
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "result",
        "d07-result:" + prepared.call_id, result_to_wire(result_read))
    return settle_d07_original_model_cost_in_transaction_v1(db, prepared=prepared, fact=fact,
        issuer=issuer, resource_issuer=resource_issuer)


def stage_d07_body_cost_in_transaction_v1(db, *, prepared, issuer, resource_issuer, body_authority):
    """Exactly three writes against the current same ledger, without resetting it."""
    if not db.in_transaction:
        raise ValueError("D07 current body settlement needs W01 transaction")
    existing = read_d07_original_v1(db, issuer, prepared.namespace, "body_cost", prepared.job_id)
    if existing is not None:
        return (), (), existing[0]
    paid = read_d07_original_v1(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    if paid is None or not paid[0]["paid"]:
        raise ValueError("D07 current body settlement requires actual fully measured model cost")
    quote = resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    body_quote = body_authority.original_body_quote(db, prepared.body_quote_ref, prepared.body_quote_version,
        quote, prepared.operation_id)
    if canonical_digest(quote) != prepared.quote_digest or canonical_digest(body_quote) != prepared.body_quote_digest:
        raise ValueError("D07 original signed resource/body quote differs")
    keys = (AtomKey.from_token(prepared.body_state_ref), AtomKey.from_token(prepared.body_reservation_ref),
        AtomKey.from_token(quote.d02_settlement_refs[0]))
    reads = []
    values = []
    for key in keys:
        row = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(key.token,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone())
        if key == keys[2]:
            if row is not None:
                raise ValueError("D07 body settlement target exists without original")
            reads.append(GraphVersion(key, 0))
        else:
            if row is None or row[2] != 1:
                raise ValueError("D07 current same body ledger unavailable")
            reads.append(GraphVersion(key, row[0]))
            values.append(background_json_loads_v3(row[1]))
    state = BodyState(**values[0])
    reservation = BodyReservation(**{**values[1], "settled_components": tuple(values[1]["settled_components"])})
    if (state.profile_id != body_quote.profile_id or state.version < body_quote.state_version
            or reservation.quote_id != body_quote.quote_id or reservation.effect_id != prepared.effect_id
            or len(body_quote.components) != 1 or body_quote.components[0].component_id != prepared.component_id
            or body_quote.components[0].duration_rate != 0):
        raise ValueError("D07 current body lineage/reservation differs from original")
    component_ref = "d07-component:" + prepared.call_id
    settlement = BodyDomain().settle_component(state, reservation, prepared.component_id,
        actual_cost=body_quote.components[0].fixed_cost, component_receipt=component_ref)
    if settlement.duplicate:
        raise ValueError("D07 original body component already charged without matching receipt")
    writes = (BodyDomain.state_write(prepared.namespace, settlement.state),
        BodyDomain.reservation_write(prepared.namespace, prepared.activity_id, settlement.reservation),
        BodyDomain.settlement_write(prepared.namespace, prepared.activity_id, keys[2].name, settlement))
    value = {"schema": "d07.fixed-body-cost.v1", "prepared_digest": prepared.digest,
        "terminal_digest": paid[0]["terminal_digest"], "result_digest": paid[0]["result_digest"], "component_ref": component_ref,
        "settlement_ref": writes[2].key.token, "writes_digest": canonical_digest(writes),
        "fixed_cost": body_quote.components[0].fixed_cost, "overrun": settlement.overrun,
        "unpaid_cost": settlement.unpaid_cost}
    return writes, tuple(reads), value


def record_d07_body_cost_after_cas_v1(db, *, prepared, issuer, writes, original):
    if not db.in_transaction or len(writes) != 3:
        raise ValueError("D07 body original requires actual three-write CAS")
    for write in writes:
        row = _producer_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(write.key.token,),legacy_reader=lambda:db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone())
        if row is None or row[1] != 1 or background_json_loads_v3(row[0]) != write.value:
            raise ValueError("D07 body cost graph CAS did not happen")
    if original["writes_digest"] != canonical_digest(writes):
        raise ValueError("D07 body original differs from actual CAS")
    return record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "body_cost", prepared.job_id, original)


def build_actual_ingress_recall_execution_v1(db, *, prepared, result_read, paid, issuer):
    """Pure terminal projection from the genuine scoped read, paid cost and role clock."""
    from ..model_broker.d07_cognition_v1 import parse_d07_ingress_recall_output_v1
    if type(prepared) is not D07IngressRecallPreparedV1 or not db.in_transaction:
        raise ValueError("Self C3 terminal projection requires its current exact prepared original")
    frozen = thaw_d07_ingress_recall_request_v1(background_json_loads_v3(prepared.frozen_json))
    response = background_json_loads_v3(result_read.observation.result_json)
    if set(response) != {"text"} or type(response["text"]) is not str:
        raise ValueError("Self C3 requires the exact observed provider text")
    suggestion = parse_d07_ingress_recall_output_v1(response["text"], frozen)
    if paid["prepared_digest"] != prepared.digest or paid["paid"] is not True or paid["unknown_dimensions"]:
        raise ValueError("Self C3 actual paid cost is incomplete or belongs to another preparation")
    mapping = _clock_from_json(prepared.clock_mapping_json)
    if _clock_original(db, issuer, prepared.namespace, mapping) != prepared.clock_original_digest:
        raise ValueError("Self C3 role clock original changed")
    timing = result_read.timing
    start = float(mapping.character_at(datetime.fromtimestamp(timing.started_at, timezone.utc).isoformat().replace("+00:00", "Z")))
    end = float(mapping.character_at(datetime.fromtimestamp(timing.ended_at, timezone.utc).isoformat().replace("+00:00", "Z")))
    sources = tuple(dict.fromkeys(source.source_ref.ref
        for source in (frozen.input.cue, *frozen.input.known_sources)))
    execution = D07IngressRecallExecutionOriginalV1(prepared.namespace, "d07-terminal:" + prepared.call_id,
        prepared.operation_id, prepared.activity_id, prepared.effect_id, prepared.attempt_id,
        prepared.execution_id, prepared.digest, prepared.stage_input_digest, suggestion.output_digest,
        prepared.need_ref, prepared.need_digest, prepared.c02_operation_id, prepared.cycle_job_ref,
        start, end, mapping.mapping_id, str(mapping.version), get_job(db, prepared.job_id).budget_ref,
        (paid["cost_ref"],), sources, prepared.activation_generation)
    return execution, suggestion


def stage_d07_execution_original_in_transaction_v1(db, *, prepared, issuer, holder, fence):
    """Produce the real activity projection only after actual model and body cost."""
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1, from_wire
    paid = read_d07_original_v1(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    body = read_d07_original_v1(db, issuer, prepared.namespace, "body_cost", prepared.job_id)
    if paid is None or body is None or not paid[0]["paid"] or body[0]["unpaid_cost"]:
        raise ValueError("D07 result cannot be adopted before actual computation/body settlement")
    prior = read_d07_original_v1(db, issuer, prepared.namespace, "execution", "d07-terminal:" + prepared.call_id)
    if prior is not None:
        return decode_d07_execution_original_v1(prior[0]), ()
    result = read_d07_original_v1(db, issuer, prepared.namespace, "result", paid[0]["result_ref"])
    read = from_wire(result[0], D07CognitionResultReadV1)
    terminal_ref = "d07-terminal:" + prepared.call_id
    if type(prepared) is D07IngressRecallPreparedV1:
        execution, _ = build_actual_ingress_recall_execution_v1(db, prepared=prepared,
            result_read=read, paid=paid[0], issuer=issuer)
    else:
        from .d07_general_growth_execution_v1 import (D07GeneralGrowthPreparedV1,
            thaw_current_general_growth_prepared_request_v1,parse_current_general_growth_output_v1)
        general=type(prepared)is D07GeneralGrowthPreparedV1
        frozen=(thaw_current_general_growth_prepared_request_v1(prepared)if general
            else thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json)))
        response = background_json_loads_v3(read.observation.result_json)
        if set(response) != {"text"} or type(response["text"]) is not str:
            raise ValueError("D07 provider exact text response required")
        suggestion=(parse_current_general_growth_output_v1(prepared,response["text"],frozen)if general
            else parse_d07_cognition_output_v1(response["text"], frozen))
        source_inputs=(*frozen.input.context_sources,*frozen.input.support_sources)if general else frozen.input.sources
        causal_depth=prepared.stage_causal_depth if general else frozen.input.causal_depth
        mapping = _clock_from_json(prepared.clock_mapping_json)
        if _clock_original(db, issuer, prepared.namespace, mapping) != prepared.clock_original_digest:
            raise ValueError("D07 actual original role mapping changed")
        start_wall, end_wall = read.timing.started_at, read.timing.ended_at
        start = float(mapping.character_at(datetime.fromtimestamp(start_wall, timezone.utc).isoformat().replace("+00:00", "Z")))
        end = float(mapping.character_at(datetime.fromtimestamp(end_wall, timezone.utc).isoformat().replace("+00:00", "Z")))
        execution = D07ExecutionOriginalV1(terminal_ref, prepared.operation_id, prepared.activity_id,
            prepared.effect_id, prepared.attempt_id, prepared.execution_id, prepared.stage_input_digest,
            suggestion.output_digest, prepared.work_kind, start, end, mapping.mapping_id, str(mapping.version),
            get_job(db, prepared.job_id).budget_ref, (paid[0]["cost_ref"],),
            tuple(s.source_ref.ref for s in source_inputs), prepared.activation_generation,
            suggestion.resolved_slots, suggestion.discriminating_refs, suggestion.predictions, causal_depth)
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "execution", terminal_ref, asdict(execution))
    job = transition_job(db, prepared.job_id, holder, fence, target_phase="completed", result_ref=terminal_ref)
    return execution, (job_graph_write(job),)


def decode_d07_execution_original_v1(raw):
    data = dict(raw)
    if data.get("schema") == "d07.ingress-recall-execution.v1":
        from dataclasses import fields
        if set(data) != {field.name for field in fields(D07IngressRecallExecutionOriginalV1)}:
            raise ValueError("Self C3 execution fields differ from its exact installed schema")
        data["namespace"] = NamespaceId(**data["namespace"])
        for name in ("cost_receipt_refs", "source_refs"):
            data[name] = tuple(data[name])
        return D07IngressRecallExecutionOriginalV1(**data)
    for name in ("cost_receipt_refs", "source_refs", "resolved_slots", "discriminating_refs"):
        data[name] = tuple(data[name])
    data["predictions"] = tuple(tuple(p) for p in data["predictions"])
    return D07ExecutionOriginalV1(**data)


def require_current_method_growth_question_v2(db, *, namespace, question, issuer):
    """Current actual proposal/C02/cycle identity behind the named growth C3."""
    from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2
    from ..domains.d01.method_learning_v1 import MethodTrialProposalV2
    from .d01_method_learning_v1 import trial_question_v2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, _adopted_c02_v1
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from .budget import get_budget_lease, require_budget_family_admissible
    from .jobs import get_job, _utc
    from .d11_types import job_graph_write
    if type(question) is not D07MethodGrowthSemanticQuestionV2:
        raise TypeError("actual signed method growth semantic question required")
    for version, digest in ((question.proposal_head, question.proposal_digest), (question.source_head, question.source_digest)):
        if NamespaceId.from_key(version.key) != namespace:
            raise ValueError("growth question crossed its actual canonical namespace")
        from ..authority_service.model_reply_scope_observation_v3 import read_model_reply_growth_head_commitment_v3
        handled,commitment=read_model_reply_growth_head_commitment_v3(db,namespace=namespace,version=version)
        if handled:
            if commitment is None or commitment!=(version.revision,1,digest):
                raise ValueError("growth question lost its actual current proposal/cue Source head")
        else:
            row = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(version.key.token,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (version.key.token,)).fetchone())
            if row is None or row[2] != 1 or row[0] != version.revision or canonical_digest(background_json_loads_v3(row[1])) != digest:
                raise ValueError("growth question lost its actual current proposal/cue Source head")
    from ..authority_service.model_reply_scope_observation_v3 import read_model_reply_growth_proposal_v3
    handled,raw_value=read_model_reply_growth_proposal_v3(db,namespace=namespace,version=question.proposal_head)
    if not handled:
        raw = _producer_original_point_v3(db,table='graph_atoms',columns=('value',),key_columns=('token',),key=(question.proposal_head.key.token,),legacy_reader=lambda:db.execute("SELECT value FROM graph_atoms WHERE token=?", (question.proposal_head.key.token,)).fetchone())[0]
        raw_value=background_json_loads_v3(raw)
    proposal = decode_typed_production_value_v1(raw_value, MethodTrialProposalV2)
    if (question.question_key != trial_question_v2(question.proposal_head.key.token, question.proposal_digest)
            or (question.target_ref.ref, question.target_ref.version) != (question.proposal_head.key.token, question.proposal_head.revision)
            or set(question.source_refs) != set(proposal.source_refs)):
        raise ValueError("growth semantic question must evaluate its exact already registered trial proposal and Source material")
    from .domain_background_read_v3 import background_json_matches_v3
    history = _producer_original_point_v3(db,table='graph_history',columns=('event_id',),
        key_columns=('token','revision'),key=(question.proposal_head.key.token,question.proposal_head.revision),
        legacy_reader=lambda:db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",
            (question.proposal_head.key.token,question.proposal_head.revision)).fetchone())
    actual = None if history is None else read_adopted_domain_operation_v1(db, namespace, history[0])
    if actual is None or actual["operation_kind"] != "register_method_trial_proposal_v2":
        raise ValueError("growth question cannot use an uncommitted or fabricated preliminary proposal")
    job = get_job(db, question.cycle_ref.key.name)
    current = _producer_original_point_v3(db,table='graph_atoms',columns=('revision','value','valid'),
        key_columns=('token',),key=(question.cycle_ref.key.token,),
        legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (question.cycle_ref.key.token,)).fetchone())
    cycle = foreground_cycle_from_wire_v1(job.continuation)
    if (current is None or current[2] != 1 or not background_json_matches_v3(current[1],job_graph_write(job).value)
            or cycle.c02_operation_id != question.c02_operation_id or cycle.source_ref != question.source_head.key.token
            or job.cancel_epoch or cycle.cancel_generation or job.budget_ref != question.parent_budget_lease_ref):
        raise ValueError("growth question changed its actual C02/cue/parent cycle/budget")
    c02 = _adopted_c02_v1(db, namespace, question.c02_operation_id)
    from .foreground_cycle_v1 import require_actual_c02_cue_source_v1
    require_actual_c02_cue_source_v1(db, namespace=namespace, c02_operation_id=question.c02_operation_id, source_version=question.source_head)
    responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=namespace, job=job, issuer=issuer)
    if responsibility is None or responsibility.mode != "bounded_causal_window_v1":
        raise ValueError("growth preliminary C3 requires its actual independent natural C02 responsibility")
    grant = issuer.current_budget_grant(db, job.budget_ref)
    parent = get_budget_lease(db, job.budget_ref)
    require_budget_family_admissible(db, job.budget_ref)
    if (parent.state != "active" or "d07.cognition" not in grant.allowed_work_kinds
            or question.original_deadline_utc != min(_utc(job.deadline_utc, "deadline_utc").timestamp(), grant.valid_until_utc)):
        raise ValueError("growth preliminary C3 cannot replace its actual original parent/deadline/work authorization")
    return proposal, job, cycle, current[0]


def _require_method_growth_semantic_question_v2(db, issuer, frame, question):
    from .d01_production_operations_v1 import CurrentDomainReadV1
    read = CurrentDomainReadV1(frame); read.check(db)
    proposal, job, cycle, revision = require_current_method_growth_question_v2(db,
        namespace=frame.envelope.authority.namespace, question=question, issuer=issuer)
    current = read.head(db, question.cycle_ref.key, required=True)
    if (current.revision != question.cycle_ref.revision or canonical_digest(current.value) != question.cycle_digest
            or frame.envelope.parent_budget_lease_ref != question.parent_budget_lease_ref
            or frame.now_utc >= question.original_deadline_utc
            or not proposal.valid_from <= frame.now_utc < proposal.valid_until):
        raise ValueError("growth preliminary semantic registration changed its current actual frame/budget/time")
    read.head(db, question.source_head.key, required=True)
    read.head(db, question.proposal_head.key, required=True)
    read.original(question.proposal_head.key.token)
    read.source_family(db, question.source_refs)
    return proposal, cycle

def decode_native_named_d07_value_v2(raw, expected):
    """Exact asdict writer ABI for the four installed named D07 V2 schemas."""
    from dataclasses import fields
    from typing import get_type_hints
    from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2, D07MethodGrowthPreparedV2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .d11_types import runtime_job_key
    variants={D07RelationshipPreparedV2:("d07.relationship-prepared.v2",("cycle_ref",)),
        D07RelationshipSemanticQuestionV2:("d07.relationship-semantic-question.v2",("cycle_ref",)),
        D07MethodGrowthPreparedV2:("d07.method-growth-prepared.v2",("cycle_ref","proposal_head","source_head")),
        D07MethodGrowthSemanticQuestionV2:("d07.method-growth-semantic-question.v2",("cycle_ref","proposal_head","source_head"))}
    if expected not in variants:
        raise TypeError("only exact named D07 V2 writer schemas use the native GraphVersion ABI")
    schema,heads=variants[expected]
    if type(raw) is not dict or set(raw)!={field.name for field in fields(expected)} or raw.get("schema")!=schema:
        raise ValueError("named D07 native original fields/schema differ")
    namespace=(NamespaceId(**raw["namespace"]) if "namespace" in raw else
        NamespaceId(raw["cycle_ref"]["key"]["owner"]["bot"],raw["cycle_ref"]["key"]["owner"]["persona"]))
    hints=get_type_hints(expected)
    decoded={}
    for field in fields(expected):
        value=raw[field.name]
        if field.name in heads:
            decoded[field.name]=decode_native_named_d07_head_v2(value,namespace=namespace,
                c02_operation_id=raw.get("c02_operation_id"),head_kind=field.name)
        elif expected is D07RelationshipSemanticQuestionV2 and field.name=="scope":
            from ..domains.d05.relationship_revision_v2 import RelationshipScopeV2
            if type(value) is not dict or set(value)!={part.name for part in fields(RelationshipScopeV2)}:
                raise ValueError("Relationship native question scope fields differ")
            scope=dict(value)
            scope["namespace"]=NamespaceId(**scope["namespace"])
            scope["subject_head"]=decode_native_named_d07_head_v2(value["subject_head"],
                namespace=scope["namespace"],c02_operation_id=None,head_kind="subject_head")
            scope["context_head"]=(None if value["context_head"] is None else
                decode_native_named_d07_head_v2(value["context_head"],namespace=scope["namespace"],
                    c02_operation_id=None,head_kind="context_head"))
            decoded[field.name]=RelationshipScopeV2(**scope)
        else:
            decoded[field.name]=decode_typed_production_value_v1(value,hints[field.name])
    result=expected(**decoded)
    if canonical_serialize(asdict(result))!=canonical_serialize(raw):
        raise ValueError("named D07 signed native bytes do not roundtrip through their exact writer")
    return result


def decode_native_named_d07_head_v2(raw, *, namespace, c02_operation_id, head_kind):
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    from .d11_types import runtime_job_key
    from ..domains.d01.method_learning_v1 import TRIAL_PROPOSAL_TYPE_V2
    if (type(raw) is not dict or set(raw)!={"key","revision"} or type(raw["key"]) is not dict
            or set(raw["key"])!={"owner","type_name","name"} or type(raw["key"]["owner"]) is not dict
            or set(raw["key"]["owner"])!={"kind","bot","persona","subject"}
            or type(raw["revision"]) is not int or raw["revision"]<1):
        raise ValueError("named D07 native GraphVersion exact field group differs")
    key=AtomKey(Owner(**raw["key"]["owner"]),raw["key"]["type_name"],raw["key"]["name"])
    if NamespaceId.from_key(key)!=namespace or AtomKey.from_token(key.token)!=key:
        raise ValueError("named D07 native head namespace/token roundtrip differs")
    if head_kind=="cycle_ref":
        if c02_operation_id is None:
            tag=key.name.removeprefix("foreground-job:")
            if (key.owner.kind!="activity" or len(tag)!=40 or any(ch not in "0123456789abcdef" for ch in tag)
                    or key.name!="foreground-job:"+tag or key.owner.subject!="foreground-activity:"+tag):
                raise ValueError("named D07 question lost its native stable cycle grouping")
        else:
            activity,job=foreground_cycle_ids_v1(namespace,c02_operation_id)
            if key!=runtime_job_key(*namespace.as_tuple,activity,job):
                raise ValueError("named D07 native cycle owner/subject/name is not its stable C02 job")
    elif head_kind=="proposal_head":
        tag=key.name.removeprefix("method-learning:")
        if (key.type_name!=TRIAL_PROPOSAL_TYPE_V2 or key.owner.kind!="persona" or key.owner.subject is not None
                or len(tag)!=64 or any(ch not in "0123456789abcdef" for ch in tag)
                or key.name!="method-learning:"+tag):
            raise ValueError("growth native proposal has another actual type/owner/subject/key group")
    elif head_kind=="source_head":
        if key!=source_key(*namespace.as_tuple,key.owner.subject or ""):
            raise ValueError("growth native Source head is not its canonical D06 record")
    elif head_kind in {"subject_head","context_head"}:
        owners={"d03.entity_anchor":("persona",),"d03.role_binding":("persona","scene"),
            "d03.world_event":("event",),"memory.source":("event",)}
        allowed={"d03.entity_anchor"} if head_kind=="subject_head" else {"d03.role_binding","d03.world_event","memory.source"}
        if key.type_name not in allowed or key.owner.kind not in owners[key.type_name]:
            raise ValueError("Relationship native scoped head type/owner differs")
        if key.type_name=="memory.source" and key!=source_key(*namespace.as_tuple,key.owner.subject or ""):
            raise ValueError("Relationship native scope Source key is not canonical")
    else:
        raise ValueError("unregistered named D07 native head field")
    return GraphVersion(key,raw["revision"])
