"""Closed C09 inventory codecs for real Life bodies and retained cost facts."""
import hashlib
import json
from dataclasses import asdict

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_erasure_v1 import DomainProductionErasureHold, _json, decode_typed_production_value_v1
from .d11_life_contract_v1 import RegisteredLifePlanV2, RegisteredLifeOutcomeV2, life_from_wire_v1, D11LifeTerminalV1
from .d11_life_preparation_v1 import life_prepared_from_wire_v1
from .d11_life_source_note_v1 import ARTIFACT_SCHEMA

FACT_KINDS = frozenset({"accounting_prepared", "historical_accounting_gate", "historical_accounting_receipt","c4_paid","c4_phase_paid","c4_no_dispatch","c4_phase_no_dispatch"})
C4_KINDS=frozenset({"c4_frozen","c4_prepared","c4_request","c4_call","c4_result","c4_paid","c4_adopted","c4_no_dispatch"})
C4_PHASE_KINDS = frozenset("c4_phase_" + part for part in
    ("frozen", "prepared", "request", "call", "result", "paid", "adopted", "verified", "no_dispatch"))
FOREGROUND_CAUSE_KIND = "foreground_post_c02_cause"
POSTCONDITION_KINDS = frozenset({"artifact_phase_postcondition_policy", "artifact_phase_postcondition_contract", "artifact_phase_assessment", "artifact_standing_predecision_approval", "artifact_candidate_preparation_parent"})


def decode_life_original_content_v1(kind, encoded):
    raw = _json(encoded)
    if kind == 'owner_source_note_values_parent_v1':
        from .owner_source_note_values_v1 import OwnerTaskValuesParentV1
        return decode_typed_production_value_v1(raw,OwnerTaskValuesParentV1)
    if kind == 'owner_source_note_task_responsibility_v2':
        from .owner_source_note_task_contract_v1 import OwnerSourceNoteTaskResponsibilityV2
        return decode_typed_production_value_v1(raw,OwnerSourceNoteTaskResponsibilityV2)
    if kind in {"owner_source_note_task_cause_v1", "owner_source_note_task_authorization_v2"}:
        from .owner_source_note_task_contract_v1 import OwnerTaskCauseV1, OwnerSourceNoteTaskAuthorizationV2
        return decode_typed_production_value_v1(raw, OwnerTaskCauseV1 if kind == "owner_source_note_task_cause_v1" else OwnerSourceNoteTaskAuthorizationV2)
    if kind == "source_note_task_authorization":
        from .source_note_task_authorization_v1 import SourceNoteTaskAuthorizationV1
        return decode_typed_production_value_v1(raw, SourceNoteTaskAuthorizationV1)
    if kind == "source_note_foreground_responsibility":
        from .source_note_foreground_v1 import ForegroundSourceNoteResponsibilityV1
        return decode_typed_production_value_v1(raw, ForegroundSourceNoteResponsibilityV1)
    if kind == "method_comparison_observation":
        from ..domains.d01.method_learning_v1 import MethodComparisonObservationV1, MethodComparisonObservationV2
        cls = MethodComparisonObservationV2 if raw.get("schema") == "d11.method_comparison_observation.v2" else MethodComparisonObservationV1
        return decode_typed_production_value_v1(raw, cls)
    if kind=="artifact_task_amendment":
        from .artifact_task_amendment_v1 import decode_amendment_v1
        return decode_amendment_v1(raw)
    if kind == "artifact_task_continuation_authorization_v2":
        from .artifact_task_continuation_authorization_v2 import decode_continuation_authorization_v2
        return decode_continuation_authorization_v2(raw)
    if kind in {"artifact_task_scope","artifact_task_objective"}:
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1,ArtifactTaskObjectiveV1,_decode as task_decode
        return task_decode(raw,IngressArtifactTaskScopeOriginalV1 if kind=="artifact_task_scope" else ArtifactTaskObjectiveV1)
    if kind == "c1_task_intent":
        from .c1_artifact_task_intent_v1 import C1ArtifactTaskIntentOriginalV1
        return decode_typed_production_value_v1(raw,C1ArtifactTaskIntentOriginalV1)
    if kind == "artifact_task_text_extent":
        from .artifact_task_text_extent_v1 import decode_artifact_task_text_extent_original_v1
        return decode_artifact_task_text_extent_original_v1(raw)
    if kind == 'artifact_task_milestone_v2':
        from .artifact_task_observer_v1 import decode_artifact_task_milestone_v2
        return decode_artifact_task_milestone_v2(raw)
    if kind in POSTCONDITION_KINDS:
        from .artifact_phase_postconditions_v1 import decode_artifact_phase_postcondition_original_v1
        return decode_artifact_phase_postcondition_original_v1(kind, raw)

    if kind in {"c4_no_dispatch", "c4_phase_no_dispatch"}:
        from .d11_artifact_draft_model_v1 import decode_artifact_model_no_dispatch_v1
        return decode_artifact_model_no_dispatch_v1(raw)
    if kind in C4_PHASE_KINDS:
        from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v2
        return decode_artifact_draft_original_v2(kind, raw)
    if kind in C4_KINDS:
        from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1
        return decode_artifact_draft_original_v1(kind,raw)
    if kind == FOREGROUND_CAUSE_KIND:
        from .foreground_cycle_v1 import ForegroundPostC02CauseV1
        value=decode_typed_production_value_v1(raw,ForegroundPostC02CauseV1)
        from ..domains.d01.production_operations_v1 import plain_v1
        if plain_v1(value)!=raw:raise DomainProductionErasureHold("foreground cause original bytes are not their closed canonical variant")
        return value
    if kind == "source_note_action":
        from .d08_source_note_action_v1 import source_note_action_original_from_wire_v1
        return source_note_action_original_from_wire_v1(raw)
    if kind == "draft_action":
        from .d08_life_admission_v1 import draft_action_root_from_wire_v1
        return draft_action_root_from_wire_v1(raw)
    if kind in {"activity_scope", "draft_root_capability"}:
        from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1, DraftRootCapabilityV1, draft_from_wire_v1
        return draft_from_wire_v1(raw, DraftActivityScopeV1 if kind == "activity_scope" else DraftRootCapabilityV1)
    if kind == "draft_observation_admission":
        from .d11_artifact_draft_contract_v1 import DraftObservationAdmissionV1, draft_from_wire_v1
        return draft_from_wire_v1(raw, DraftObservationAdmissionV1)
    if kind == "life_body_preparation":
        from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
        return life_body_preparation_original_from_wire_v1(raw)
    if kind == "action_admission":
        from .d08_life_admission_v1 import LifeActionAdmissionOriginalV1
        return decode_typed_production_value_v1(raw,LifeActionAdmissionOriginalV1)
    if kind == "plan":
        return life_from_wire_v1(raw, RegisteredLifePlanV2)
    if kind == "outcome":
        return life_from_wire_v1(raw, RegisteredLifeOutcomeV2)
    if kind == "prepared":
        return life_prepared_from_wire_v1(raw)
    if kind == "accounting_prepared":
        from .d11_life_accounting_v1 import D11LifeAccountingPreparedV1
        return decode_typed_production_value_v1(raw, D11LifeAccountingPreparedV1)
    if kind == "adoption_bridge":
        from ..authority_service.d11_life_bridge_v1 import life_bridge_from_wire_v1
        return life_bridge_from_wire_v1(raw)
    if kind == "adoption_receipt":
        from .d11_life_adoption_v1 import life_adoption_receipt_from_wire_v1
        return life_adoption_receipt_from_wire_v1(raw)
    if kind == "historical_accounting_gate":
        from ..authority_service.d11_life_historical_accounting_v1 import historical_accounting_from_wire_v1
        return historical_accounting_from_wire_v1(raw)
    if kind == "historical_accounting_receipt":
        from .d11_life_historical_accounting_v1 import historical_accounting_receipt_from_wire_v1
        return historical_accounting_receipt_from_wire_v1(raw)
    if kind == "experience":
        from .d11_life_contract_v1 import D11LifeExecutionBindingV1
        if set(raw) != {"schema","source_ref","source_digest","binding","terminal","adopted_operation_id","experience"} or raw["schema"] != "d11.actual-life-experience-provenance.v1":
            raise DomainProductionErasureHold("Life experience fields differ")
        binding = life_from_wire_v1(raw["binding"],D11LifeExecutionBindingV1)
        terminal = life_from_wire_v1(raw["terminal"],D11LifeTerminalV1)
        from .d10_life_outcome_v2 import life_experience_source_id_v1, life_experience_provenance_ref_v1
        from ..memory_types import source_key
        e=raw["experience"]
        expected={"schema":"d10.actual-life-activity-experience.v1","actual_provenance_ref":life_experience_provenance_ref_v1(binding),
            "activity_id":binding.activity_id,"effect_id":binding.effect_id,"artifact_ref":binding.artifact_ref,
            "artifact_digest":terminal.payload.artifact_digest,"artifact_length":terminal.payload.artifact_length,
            "start_original_ref":terminal.claim.original_ref,"terminal_original_ref":terminal.original_ref,
            "action_outcome_ref":e["action_outcome_ref"],"cost_refs":e["cost_refs"],"actual_cpu_ms":terminal.actual_cpu_ms,
            "started_at_utc":terminal.claim.payload.claimed_at_utc,"completed_at_utc":terminal.payload.completed_at_utc,
            "reality":"real_execution","step":"artifact_draft_v1" if binding.recipe_id == "artifact_draft_v1" else "source_note"}
        if (terminal.binding != binding or terminal.status != "completed" or e != expected
                or raw["source_ref"] != source_key(*binding.namespace.as_tuple,life_experience_source_id_v1(binding)).token):
            raise DomainProductionErasureHold("Life internal experience lacks exact completed activity facts")
        return raw
    if kind == "adopted_life":
        current = raw.get("schema") in {"d11.adopted-life-original.v2","d11.adopted-life-original.v3", "d11.adopted-life-original.v4"}
        expected_fields = {"schema", "namespace", "result_ref", "producing_operation_id", "prepared_digest", "terminal", "source_refs", "graph_receipt_json", "write_commitments"}
        if set(raw) != expected_fields | ({"job_result_binding"} if current else set()):
            raise DomainProductionErasureHold("Life adopted original fields differ")
        terminal = life_from_wire_v1(raw["terminal"], D11LifeTerminalV1)
        if (raw["schema"] not in {"d11.adopted-life-original.v1", "d11.adopted-life-original.v2","d11.adopted-life-original.v3", "d11.adopted-life-original.v4"} or raw["prepared_digest"] != terminal.payload.prepared_digest
                or raw["result_ref"] != terminal.binding.artifact_ref or raw["namespace"] != {
                    "bot_id": terminal.binding.namespace.bot_id, "persona_id": terminal.binding.namespace.persona_id}
                or type(raw["write_commitments"]) is not list
                or any(set(r) != {"ref", "revision", "digest"} for r in raw["write_commitments"])):
            raise DomainProductionErasureHold("Life adopted original identity differs")
        if current:
            from .d11_life_contract_v1 import life_adoption_operation_id_v1, validate_life_job_result_binding_v1
            if raw["producing_operation_id"] != life_adoption_operation_id_v1(terminal.binding):
                raise DomainProductionErasureHold("Life result mapping belongs to another adoption operation")
            if terminal.status == "completed":
                try:
                    validate_life_job_result_binding_v1(raw["job_result_binding"], terminal=terminal)
                    artifact = [row for row in raw["write_commitments"] if row["ref"] == terminal.binding.artifact_ref]
                    mapping = raw["job_result_binding"]
                    if (len(artifact) != 1 or artifact[0]["revision"] != mapping["artifact_revision"]
                            or artifact[0]["digest"] != mapping["artifact_graph_digest"]):
                        raise ValueError("Life result mapping differs from its committed artifact version")
                except (ValueError, TypeError, KeyError) as exc:
                    raise DomainProductionErasureHold("Life completed result mapping differs") from exc
            elif raw["job_result_binding"] is not None:
                raise DomainProductionErasureHold("Life incomplete terminal carries a completed result mapping")
        return raw
    raise DomainProductionErasureHold("unregistered Life original kind")



def validate_foreground_post_c02_cause_row_v1(*,namespace,original_ref,producing_operation_id,raw):
    from .foreground_cycle_v1 import ForegroundPostC02CauseV1,foreground_post_c02_cause_ref_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    value=decode_typed_production_value_v1(raw,ForegroundPostC02CauseV1)
    if (plain_v1(value)!=raw or len(canonical_serialize(raw).encode())>65536
            or value.namespace!=namespace or producing_operation_id!=value.c02_operation_id
            or original_ref!=foreground_post_c02_cause_ref_v1(namespace,value.c02_operation_id)):
        raise DomainProductionErasureHold("foreground cause lost its exact original C02 producer/namespace/locator")
    return value


def require_foreground_post_c02_cause_history_v1(db,cause):
    """Passive occurrence proof; no clock sample or responsibility is reissued."""
    from .foreground_cycle_v1 import ForegroundPostC02CauseV1,_adopted_c02_v1
    from ..graph_store import GraphStore
    from ..memory_types import SourceRecord,source_key,validate_episode,validate_subjective_trace_v2
    from .ingress_observation import read_committed_ingress_identity
    if not db.in_transaction or type(cause) is not ForegroundPostC02CauseV1:
        raise DomainProductionErasureHold("foreground cause history requires its real pinned C02 snapshot")
    ns=cause.namespace;receipt=_adopted_c02_v1(db,ns,cause.c02_operation_id)
    source_key_value=AtomKey.from_token(cause.source_ref)
    if (receipt.status!="committed" or canonical_digest(receipt)!=cause.c02_receipt_digest
            or receipt.commit_seq!=cause.commit_seq
            or not any(v.key==source_key_value and v.revision==cause.source_revision for v in receipt.read_versions)):
        raise DomainProductionErasureHold("foreground cause differs from its actual C02 receipt/Source read member")
    from ..authority_service.model_reply_scope_observation_v3 import read_model_reply_foreground_cause_history_v3
    handled,metadata=read_model_reply_foreground_cause_history_v3(db,cause=cause,receipt=receipt)
    if handled:
        # The exact signed-cause observer validates the real Source stream and
        # the complete episode/trace originals, then returns only these joins.
        # No synthetic SourceRecord or partial trace stands in for validation.
        source_id,ingress_operation_id,event_versions,episode_sources,trace_episode=metadata
        if (source_key(*ns.as_tuple,source_id)!=source_key_value
                or ingress_operation_id!=cause.ingress_operation_id):
            raise DomainProductionErasureHold("foreground cause has no same-Source actual ingress original")
        if event_versions!=receipt.write_versions:
            raise DomainProductionErasureHold("foreground cause actual C02 Graph event differs from its receipt")
        episodes=tuple(v for v in receipt.write_versions if v.key.type_name=="memory.episode.v1")
        traces=tuple(v for v in receipt.write_versions if v.key.type_name=="memory.subjective_trace.v2")
        if len(episodes)!=1 or len(traces)!=1:
            raise DomainProductionErasureHold("foreground cause needs the real C02 episode/trace pair")
        if cause.source_ref not in episode_sources or trace_episode!=episodes[0].key.token:
            raise DomainProductionErasureHold("foreground cause C02 episode/trace belongs to another original Source")
        return receipt
    source_row=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
        (cause.source_ref,cause.source_revision)).fetchone()
    if source_row is None or source_row[1]!=1 or canonical_digest(_json(source_row[0]))!=cause.source_digest:
        raise DomainProductionErasureHold("foreground cause lost its original immutable Source")
    source=SourceRecord.from_dict(_json(source_row[0]))
    ingress=read_committed_ingress_identity(db,ns,source.source_id)
    if (source_key(*ns.as_tuple,source.source_id)!=source_key_value or ingress is None
            or _json(ingress.identity_json)["operation_id"]!=cause.ingress_operation_id):
        raise DomainProductionErasureHold("foreground cause has no same-Source actual ingress original")
    event=db.execute("SELECT revisions FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*ns.as_tuple,receipt.activity_id,cause.c02_operation_id)).fetchone()
    if event is None or GraphStore._version_rows(event[0])!=receipt.write_versions:
        raise DomainProductionErasureHold("foreground cause actual C02 Graph event differs from its receipt")
    episodes=tuple(v for v in receipt.write_versions if v.key.type_name=="memory.episode.v1")
    traces=tuple(v for v in receipt.write_versions if v.key.type_name=="memory.subjective_trace.v2")
    if len(episodes)!=1 or len(traces)!=1:
        raise DomainProductionErasureHold("foreground cause needs the real C02 episode/trace pair")
    values=[]
    for version,validator in ((episodes[0],validate_episode),(traces[0],validate_subjective_trace_v2)):
        row=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (version.key.token,version.revision)).fetchone()
        if NamespaceId.from_key(version.key)!=ns or row is None or row[0]!=cause.c02_operation_id or row[2]!=1:
            raise DomainProductionErasureHold("foreground cause lost exact same-operation episode/trace history")
        value=_json(row[1]);validator(value);values.append(value)
    if cause.source_ref not in values[0]["source_refs"] or values[1]["episode_ref"]!=episodes[0].key.token:
        raise DomainProductionErasureHold("foreground cause C02 episode/trace belongs to another original Source")
    return receipt



def require_foreground_cause_outbox_original_v1(db,*,namespace,producer_operation_id,original_ref,original_digest,event_kind):
    """Require the real durable locator event, never a fresh scheduling cause."""
    if event_kind not in {"foreground_post_c02_cause_available","artifact_draft_root_registered"}:
        raise DomainProductionErasureHold("unregistered foreground cause event kind")
    from .domain_production_contracts_v1 import ProductionOutboxStageV1,ProductionOriginalRefV1
    kind=FOREGROUND_CAUSE_KIND if event_kind=="foreground_post_c02_cause_available" else "draft_root_capability"
    event=ProductionOutboxStageV1(namespace,producer_operation_id,"d11",event_kind,
        ProductionOriginalRefV1("d11.life_"+kind,original_ref,original_digest))
    from ..authority_service.model_reply_scope_observation_v3 import model_reply_scope_point_v3
    row=model_reply_scope_point_v3(db,table='graph_domain_production_outbox_v1',
        columns=('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state'),
        key_columns=('bot','persona','dedupe_key'),key=(*namespace.as_tuple,event.dedupe_key),
        legacy_reader=lambda:db.execute("SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state FROM "
            "graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
            (*namespace.as_tuple,event.dedupe_key)).fetchone())
    if (row is None or row[:5]!=(producer_operation_id,"d11",event_kind,original_ref,original_digest)
            or row[5] not in {"pending","consumed"}):
        raise DomainProductionErasureHold("foreground cause has no exact same-producer durable outbox locator")
    return event.dedupe_key


def read_foreground_post_c02_cause_original_v1(db,*,namespace,issuer,original_ref):
    from .d11_life_preparation_v1 import _read
    original=_read(db,issuer=issuer,namespace=namespace,kind=FOREGROUND_CAUSE_KIND,ref=original_ref)
    if original is None:raise DomainProductionErasureHold("actual signed post-C02 cause absent; cold readers cannot create it")
    cause=validate_foreground_post_c02_cause_row_v1(namespace=namespace,original_ref=original_ref,
        producing_operation_id=original[1],raw=original[0])
    require_foreground_post_c02_cause_history_v1(db,cause)
    require_foreground_cause_outbox_original_v1(db,namespace=namespace,producer_operation_id=cause.c02_operation_id,
        original_ref=original_ref,original_digest=canonical_digest(original[0]),event_kind="foreground_post_c02_cause_available")
    return cause



def validate_foreground_responsibility_create_history_v1(db,*,namespace,job):
    """Read the exact create occurrence; V1 never acquires new responsibility."""
    from .jobs import PersistentJob,_utc
    from .foreground_cycle_v1 import (ForegroundCycleContinuationV1,ForegroundCycleContinuationV2,
        ForegroundResponsibilityV1,foreground_cycle_from_wire_v1,foreground_responsibility_ref_v1,decode_foreground_job_v1)
    from .d11_types import job_graph_write
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    if not db.in_transaction or type(namespace) is not NamespaceId or type(job) is not PersistentJob:
        raise DomainProductionErasureHold("foreground responsibility archive needs its real pinned namespace/job")
    current=decode_foreground_job_v1(plain_v1(job),namespace=namespace)
    cont=foreground_cycle_from_wire_v1(current.continuation)
    if type(cont) is ForegroundCycleContinuationV1:return None
    if type(cont) is not ForegroundCycleContinuationV2:
        raise DomainProductionErasureHold("unregistered foreground historical continuation")
    original=read_adopted_domain_operation_v1(db,namespace,current.operation_id)
    if original is None or (original["domain"],original["operation_kind"])!=("d11","create_foreground_cycle_v2"):
        raise DomainProductionErasureHold("V2 responsibility has no actual new create W01 original")
    provenance=original["payload"]["provenance"]
    if set(provenance)!={"before_job","after_job","reply_allocation","foreground_responsibility"} or provenance["before_job"] is not None:
        raise DomainProductionErasureHold("V2 responsibility create provenance is not its exact closed producer")
    responsibility=decode_typed_production_value_v1(provenance["foreground_responsibility"],ForegroundResponsibilityV1)
    if (plain_v1(responsibility)!=provenance["foreground_responsibility"]
            or len(canonical_serialize(provenance["foreground_responsibility"]).encode())>65536):
        raise DomainProductionErasureHold("foreground responsibility has noncanonical original fields")
    if any(value is not None for value in (responsibility.task_deadline_original_ref,
            responsibility.task_deadline_original_digest,responsibility.task_deadline_utc)):
        raise DomainProductionErasureHold("foreground independent task deadline original codec is not installed")
    created=decode_foreground_job_v1(provenance["after_job"],namespace=namespace)
    born=foreground_cycle_from_wire_v1(created.continuation)
    if (type(born) is not ForegroundCycleContinuationV2 or created.phase!="queued" or created.fence!=0
            or (current.job_id,current.operation_id,current.activity_id,current.budget_ref,current.deadline_utc)!=
               (created.job_id,created.operation_id,created.activity_id,created.budget_ref,created.deadline_utc)
            or (cont.responsibility_ref,cont.responsibility_digest)!=(born.responsibility_ref,born.responsibility_digest)
            or (born.responsibility_ref,born.responsibility_digest)!=
               (foreground_responsibility_ref_v1(namespace,responsibility.c02_operation_id),responsibility.digest)
            or (responsibility.namespace,responsibility.ingress_operation_id,responsibility.c02_operation_id,
                responsibility.source_ref,responsibility.source_revision,responsibility.parent_budget_lease_ref)!=
               (namespace,born.ingress_operation_id,born.c02_operation_id,born.source_ref,born.source_revision,created.budget_ref)
            or _utc(created.deadline_utc,"deadline_utc").timestamp()!=responsibility.deadline_utc):
        raise DomainProductionErasureHold("foreground responsibility changed its original selector/job/absolute deadline")
    key=job_graph_write(created).key
    versions=tuple(v for v in original["receipt"].write_versions if v.key==key)
    if len(versions)!=1:raise DomainProductionErasureHold("foreground responsibility lost actual create job CAS member")
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3
    history=_producer_original_point_v3(db,table='graph_history',columns=('event_id','value','valid'),
        key_columns=('token','revision'),key=(key.token,versions[0].revision),
        legacy_reader=lambda:db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (key.token,versions[0].revision)).fetchone())
    if(history is None or history[0]!=created.operation_id or history[2]!=1
            or not background_json_matches_v3(history[1],job_graph_write(created).value)):
        raise DomainProductionErasureHold("foreground responsibility lost immutable actual create job history")
    for ref,digest in ((responsibility.source_ref,responsibility.source_digest),
            (responsibility.self_mapping_ref,responsibility.self_mapping_digest),
            (responsibility.owner_guard.grant_ref,responsibility.owner_guard.grant_digest)):
        reads=tuple(v for v in original["read_versions"] if v.key.token==ref)
        if len(reads)!=1:raise DomainProductionErasureHold("foreground responsibility lost actual Source/self/Owner read member")
        from ..authority_service.model_reply_scope_observation_v3 import read_model_reply_responsibility_history_v3
        handled,commitment=read_model_reply_responsibility_history_v3(db,namespace=namespace,
            responsibility=responsibility,original=original,version=reads[0],expected_digest=digest)
        if handled:
            if commitment is None or commitment[:2]!=(1,digest):
                raise DomainProductionErasureHold("foreground responsibility original Source/self/Owner bytes differ")
            original_value=commitment[2]
        else:
            row=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",(ref,reads[0].revision)).fetchone()
            if row is None or row[1]!=1 or canonical_digest(_json(row[0]))!=digest:
                raise DomainProductionErasureHold("foreground responsibility original Source/self/Owner bytes differ")
            original_value=_json(row[0])
        if ref==responsibility.source_ref and reads[0].revision!=responsibility.source_revision:
            raise DomainProductionErasureHold("foreground responsibility original Source version differs")
        if ref==responsibility.owner_guard.grant_ref and reads[0].revision!=responsibility.owner_guard.grant_revision:
            raise DomainProductionErasureHold("foreground responsibility original Owner version differs")
        if ref==responsibility.self_mapping_ref:
            from ..domains.d03.self_perspective import SelfIdentityMapping
            mapping=decode_typed_production_value_v1(original_value,SelfIdentityMapping)
            if original["payload"]["authority"]["actor"]!=mapping.self_entity_ref:
                raise DomainProductionErasureHold("foreground responsibility actual create actor differs from original self")
    from .foreground_call_plan_v1 import ForegroundReplyAllocationV1
    allocation=decode_typed_production_value_v1(provenance["reply_allocation"],ForegroundReplyAllocationV1)
    if ((allocation.namespace,allocation.c02_operation_id,allocation.parent_lease_ref,allocation.child_lease_id)!=
            (namespace,responsibility.c02_operation_id,responsibility.parent_budget_lease_ref,born.call_plan.protected_reply_lease_ref)):
        raise DomainProductionErasureHold("foreground responsibility changed its actual original protected reply allocation")
    return responsibility,original,created


def _read_archive_parent_grant_v1(db, lease_id, version):
    from .issuers import _decode_grant
    from ..authority_service.model_reply_scope_observation_v3 import model_reply_scope_point_v3
    from .domain_background_read_v3 import background_json_matches_v3
    row=model_reply_scope_point_v3(db,table='runtime_budget_grants',columns=('grant_json','signature'),
        key_columns=('lease_id','version'),key=(lease_id,version),legacy_reader=lambda:db.execute(
            "SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?",(lease_id,version)).fetchone())
    if row is None:
        raise DomainProductionErasureHold("foreground archive exact parent grant version is absent")
    grant=_decode_grant(row[0])
    if (not background_json_matches_v3(row[0],asdict(grant)) or (grant.lease_id,grant.version)!=(lease_id,version)
            or type(row[1]) is not str or len(row[1])!=64 or any(c not in "0123456789abcdef" for c in row[1])):
        raise DomainProductionErasureHold("foreground archive parent grant exact schema/identity differs")
    return grant


def _read_archive_life_original_v1(db, namespace, kind, ref):
    from .domain_production_erasure_v1 import TABLE_COLUMNS,validate_domain_production_row_v1
    from .d11_life_preparation_v1 import TABLE
    from ..authority_service.model_reply_scope_observation_v3 import model_reply_scope_point_v3
    from .domain_background_read_v3 import background_json_loads_v3
    row=model_reply_scope_point_v3(db,table=TABLE,columns=TABLE_COLUMNS[TABLE],
        key_columns=('bot','persona','kind','original_ref'),key=(*namespace.as_tuple,kind,ref),
        legacy_reader=lambda:db.execute("SELECT * FROM "+TABLE+" WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
            (*namespace.as_tuple,kind,ref)).fetchone())
    if row is None:
        raise DomainProductionErasureHold("foreground archive actual registered original is absent")
    if type(row[5]) is not str:
        # These responsibility/cause/root originals are normal metadata DTOs.
        # Preserve the existing complete codec, digest, closure and row checks.
        row=(*row[:5],canonical_serialize(background_json_loads_v3(row[5])),*row[6:])
    selected_kind,selected_ref,raw,_=validate_domain_production_row_v1(TABLE,TABLE_COLUMNS[TABLE],row)
    if (selected_kind,selected_ref)!=(kind,ref):
        raise DomainProductionErasureHold("foreground archive registered original locator differs")
    return raw,row[4]


def validate_owner_task_responsibility_archive_closure_v2(db, *, namespace, job):
    """Verify the passive Owner Submit/Create lineage; never restore current rights."""
    from ..domains.d01.production_operations_v1 import plain_v1
    from .owner_source_note_task_contract_v1 import (
        OwnerSourceNoteTaskContinuationV2, OwnerSourceNoteTaskResponsibilityV2,
        OwnerSourceNoteTaskAuthorizationV2, owner_source_note_task_from_wire_v1,
        owner_source_note_task_ids_v1, RESPONSIBILITY_KIND)
    from .owner_source_note_task_execution_v1 import decode_owner_source_note_task_job_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_types import job_graph_write
    from .jobs import _job_dict, _utc
    job = decode_owner_source_note_task_job_v1(_job_dict(job), namespace=namespace)
    cont = owner_source_note_task_from_wire_v1(dict(job.continuation), OwnerSourceNoteTaskContinuationV2)
    raw, create_id = _read_archive_life_original_v1(db, namespace, RESPONSIBILITY_KIND, cont.responsibility_ref)
    responsibility = owner_source_note_task_from_wire_v1(raw, OwnerSourceNoteTaskResponsibilityV2)
    auth_raw, submit_id = _read_archive_life_original_v1(db, namespace, "owner_source_note_task_authorization_v2", cont.authorization_original_ref)
    auth = owner_source_note_task_from_wire_v1(auth_raw, OwnerSourceNoteTaskAuthorizationV2)
    cause_raw, cause_id = _read_archive_life_original_v1(db, namespace, "owner_source_note_task_cause_v1", auth.cause.original_ref)
    created = read_adopted_domain_operation_v1(db, namespace, create_id)
    submitted = read_adopted_domain_operation_v1(db, namespace, submit_id)
    ids = owner_source_note_task_ids_v1(namespace, auth.cause.owner_operation_id)
    if (created is None or submitted is None or (created["domain"], created["operation_kind"]) != ("d11", "create_owner_source_note_task_v1")
            or (submitted["domain"], submitted["operation_kind"]) != ("d08", "submit_owner_source_note_task_v1")
            or (create_id, submit_id, cause_id) != (ids["create_operation_id"], auth.cause.owner_operation_id, auth.cause.owner_operation_id)
            or cause_raw != plain_v1(auth.cause) or submitted["payload"]["provenance"]["owner_task_authorization"] != auth_raw
            or created["payload"]["provenance"]["owner_task_responsibility"] != raw
            or created["receipt"].commit_seq <= submitted["receipt"].commit_seq
            or (responsibility.namespace, responsibility.owner_operation_id, responsibility.authorization_original_ref,
                responsibility.authorization_original_digest, responsibility.cause_original_ref, responsibility.cause_original_digest,
                responsibility.owner_guard, responsibility.parent_budget_lease_ref, responsibility.original_deadline_utc, responsibility.source_refs) !=
               (namespace, auth.cause.owner_operation_id, auth.original_ref, auth.digest, auth.cause.original_ref, auth.cause.digest,
                auth.cause.owner_guard, auth.cause.parent_budget_lease_ref, auth.cause.original_deadline_utc, auth.source_refs)
            or (cont.responsibility_ref, cont.responsibility_digest, cont.authorization_original_ref, cont.authorization_original_digest,
                cont.cause_original_ref, cont.cause_original_digest, cont.source_refs) !=
               (ids["responsibility_ref"], responsibility.digest, auth.original_ref, auth.digest, auth.cause.original_ref, auth.cause.digest, auth.source_refs)
            or (job.job_id, job.activity_id, job.operation_id, job.budget_ref, _utc(job.deadline_utc, "deadline").timestamp()) !=
               (ids["job_id"], ids["activity_id"], ids["create_operation_id"], auth.cause.parent_budget_lease_ref, auth.cause.original_deadline_utc)):
        raise DomainProductionErasureHold("Owner task archive loses its exact actual Submit/Create/cause/root lineage")
    initial = decode_owner_source_note_task_job_v1(created["payload"]["provenance"]["after_job"], namespace=namespace)
    initial_cont = owner_source_note_task_from_wire_v1(dict(initial.continuation), OwnerSourceNoteTaskContinuationV2)
    if ((initial.job_id, initial.activity_id, initial.operation_id, initial.budget_ref, _utc(initial.deadline_utc, "deadline").timestamp()) !=
            (ids["job_id"], ids["activity_id"], ids["create_operation_id"], auth.cause.parent_budget_lease_ref, auth.cause.original_deadline_utc)
            or (initial_cont.responsibility_ref, initial_cont.responsibility_digest, initial_cont.authorization_original_ref,
                initial_cont.authorization_original_digest, initial_cont.cause_original_ref, initial_cont.cause_original_digest, initial_cont.source_refs) !=
               (ids["responsibility_ref"], responsibility.digest, auth.original_ref, auth.digest, auth.cause.original_ref, auth.cause.digest, auth.source_refs)
            or created["payload"]["authority"]["actor"] != responsibility.self_entity_ref
            or responsibility.self_mapping_head not in created["read_versions"]):
        raise DomainProductionErasureHold("Owner task archive initial job or actual Creator Self binding differs")
    mapping = db.execute("SELECT value,valid,event_bot,event_persona FROM graph_history WHERE token=? AND revision=?",
        (responsibility.self_mapping_head.key.token, responsibility.self_mapping_head.revision)).fetchone()
    if (mapping is None or mapping[1:] != (1, *namespace.as_tuple)
            or canonical_digest(_json(mapping[0])) != responsibility.self_mapping_digest
            or _json(mapping[0])["self_entity_ref"] != responsibility.self_entity_ref):
        raise DomainProductionErasureHold("Owner task archive lost its actual historical Self mapping commitment")
    initial_write = job_graph_write(initial)
    from ..graph_types import GraphVersion
    if created["receipt"].write_versions != (GraphVersion(initial_write.key, 1),):
        raise DomainProductionErasureHold("Owner task archive creation must write exactly its initial job")
    members = [(initial_write.key.token, 1, canonical_digest(initial_write.value), ids["create_operation_id"], created["receipt"].activity_id)]
    for name, version, digest in auth.heads:
        if name in {"goal", "plan"}:
            if version not in submitted["receipt"].write_versions:
                raise DomainProductionErasureHold("Owner task archive Goal/Plan are not its actual Submit members")
            members.append((version.key.token, version.revision, digest, submit_id, submitted["receipt"].activity_id))
    for token, revision, digest, operation_id, activity_id in members:
        row = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?", (token, revision)).fetchone()
        if row is None or row[1:] != (1, *namespace.as_tuple, activity_id, operation_id) or canonical_digest(_json(row[0])) != digest:
            raise DomainProductionErasureHold("Owner task archive lost a genuine producing history member")
    grant = _read_archive_parent_grant_v1(db, auth.cause.parent_budget_lease_ref, auth.cause.parent_grant_version)
    if ((grant.grant_id, grant.bot_id, grant.persona_id, canonical_digest(grant)) !=
            (auth.cause.parent_grant_id, *namespace.as_tuple, auth.cause.parent_grant_digest)
            or auth.cause.original_deadline_utc > grant.valid_until_utc):
        raise DomainProductionErasureHold("Owner task archive exceeded its actual frozen signed parent grant")
    from .domain_production_contracts_v1 import ProductionOutboxStageV1, ProductionOriginalRefV1
    original = ProductionOriginalRefV1("d08.current-submit_owner_source_note_task_v1",
        "d08-current:" + submitted["original_digest"][:48], submitted["original_digest"])
    event = ProductionOutboxStageV1(namespace, submit_id, "d11", "owner_source_note_task_submitted_v1", original)
    row = db.execute("SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
        (*namespace.as_tuple, event.dedupe_key)).fetchone()
    if row is None or row[:5] != (submit_id, "d11", event.event_kind, original.original_ref, original.original_digest) or row[5] not in {"pending", "consumed"}:
        raise DomainProductionErasureHold("Owner task archive lost its actual same-Submit durable locator event")
    return responsibility


def validate_foreground_responsibility_archive_closure_v1(db,*,namespace,job):
    if job.continuation.get("schema") == "d11.foreground-source-note-continuation.v1":
        from .source_note_foreground_v1 import validate_source_note_responsibility_archive_v1
        return validate_source_note_responsibility_archive_v1(db, namespace=namespace, job=job)

    """Complete passive SQL lineage; preserved signatures do not become current authority."""
    from .foreground_cycle_v1 import _adopted_c02_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
    from ..authority_service.current_foreground_activity_v1 import DraftRootRegistrationRequestV1
    from .jobs import _utc
    values=validate_foreground_responsibility_create_history_v1(db,namespace=namespace,job=job)
    if values is None:return None
    responsibility,original,created=values
    c02=_adopted_c02_v1(db,namespace,responsibility.c02_operation_id)
    if (canonical_digest(c02),c02.commit_seq)!=(responsibility.c02_receipt_digest,responsibility.c02_commit_seq):
        raise DomainProductionErasureHold("foreground responsibility changed its actual C02 receipt")
    grant=_read_archive_parent_grant_v1(db,responsibility.parent_budget_lease_ref,responsibility.parent_grant_version)
    if ((grant.grant_id,grant.bot_id,grant.persona_id,canonical_digest(grant))!=
            (responsibility.parent_grant_id,*namespace.as_tuple,responsibility.parent_grant_digest)
            or responsibility.deadline_utc>grant.valid_until_utc):
        raise DomainProductionErasureHold("foreground responsibility exceeded its actual original signed parent grant")
    if responsibility.mode=="bounded_causal_window_v1":
        cause_original=_read_archive_life_original_v1(db,namespace,FOREGROUND_CAUSE_KIND,responsibility.cause_original_ref)
        cause=validate_foreground_post_c02_cause_row_v1(namespace=namespace,original_ref=responsibility.cause_original_ref,
            producing_operation_id=cause_original[1],raw=cause_original[0])
        require_foreground_post_c02_cause_history_v1(db,cause)
        require_foreground_cause_outbox_original_v1(db,namespace=namespace,producer_operation_id=cause.c02_operation_id,
            original_ref=responsibility.cause_original_ref,original_digest=canonical_digest(cause_original[0]),
            event_kind="foreground_post_c02_cause_available")
        from ..domains.d01.production_operations_v1 import plain_v1
        if ((cause.installation_id,cause.manifest_digest,cause.ingress_operation_id,cause.c02_operation_id,
                cause.source_ref,cause.source_revision,cause.source_digest,cause.c02_receipt_digest,cause.commit_seq,
                cause.foreground_policy_digest,cause.deadline_policy_digest,cause.cause_frozen_at_utc)!=
               (responsibility.installation_id,responsibility.manifest_digest,responsibility.ingress_operation_id,
                responsibility.c02_operation_id,responsibility.source_ref,responsibility.source_revision,responsibility.source_digest,
                responsibility.c02_receipt_digest,responsibility.c02_commit_seq,responsibility.foreground_policy_digest,
                responsibility.deadline_policy_digest,responsibility.cause_frozen_at_utc)
                or (responsibility.cause_original_digest,responsibility.cause_operation_id,responsibility.cause_commit_seq)!=
                   (canonical_digest(plain_v1(cause)),cause.c02_operation_id,cause.commit_seq)):
            raise DomainProductionErasureHold("foreground responsibility lost its original natural causal transition")
    else:
        root_original=_read_archive_life_original_v1(db,namespace,"draft_root_capability",responsibility.root_registration_ref)
        if root_original is None:raise DomainProductionErasureHold("draft responsibility actual signed root original absent")
        root=draft_from_wire_v1(root_original[0],DraftRootCapabilityV1)
        setup=read_adopted_domain_operation_v1(db,namespace,responsibility.root_setup_operation_id)
        if setup is not None and (setup["domain"],setup["operation_kind"])==("d10","derive_ingress_artifact_task_scope_v1"):
            from .ingress_artifact_task_scope_v1 import require_task_scope_archive_v1
            task=require_task_scope_archive_v1(db,namespace=namespace,root=root,producer=setup)
            if (root_original[1]!=responsibility.root_setup_operation_id
                    or task.c02_operation_id!=responsibility.c02_operation_id
                    or (task.source_ref,task.source_revision,task.source_digest)!=(responsibility.source_ref,
                        responsibility.source_revision,responsibility.source_digest)
                    or task.cause_frozen_at_utc!=responsibility.cause_frozen_at_utc
                    or (responsibility.cause_original_ref,responsibility.cause_original_digest,responsibility.cause_operation_id,
                        responsibility.cause_commit_seq,responsibility.root_registration_digest)!=(root.registration_ref,
                        canonical_digest(root_original[0]),root_original[1],setup["receipt"].commit_seq,canonical_digest(root_original[0]))
                    or (root.installation_id,root.manifest_digest,root.source_ref)!=(responsibility.installation_id,
                        responsibility.manifest_digest,responsibility.source_ref)
                    or (root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)!=(responsibility.owner_guard.grant_ref,
                        responsibility.owner_guard.grant_revision,responsibility.owner_guard.grant_digest)
                    or responsibility.deadline_utc>_utc(root.valid_until_utc,"valid_until_utc").timestamp()):
                raise DomainProductionErasureHold("Self task responsibility changed its actual immutable root/cause")
            require_foreground_cause_outbox_original_v1(db,namespace=namespace,producer_operation_id=root_original[1],
                original_ref=root.registration_ref,original_digest=canonical_digest(root_original[0]),event_kind="artifact_draft_root_registered")
            return responsibility
        if (setup is None or (setup["domain"],setup["operation_kind"])!=("d10","register_artifact_draft_root")
                or root_original[1]!=responsibility.root_setup_operation_id):
            raise DomainProductionErasureHold("draft responsibility lacks its actual formal Owner setup W01 producer")
        provenance=setup["payload"]["provenance"]
        if set(provenance)!={"draft_root_request","draft_root_capability","cause_frozen_at_utc","clock_sample_digest"}:
            raise DomainProductionErasureHold("draft setup cause provenance differs from its exact original variant")
        request=decode_typed_production_value_v1(provenance["draft_root_request"],DraftRootRegistrationRequestV1)
        if (provenance["draft_root_capability"]!=root_original[0] or type(provenance["cause_frozen_at_utc"]) is not float
                or provenance["cause_frozen_at_utc"]!=responsibility.cause_frozen_at_utc
                or type(provenance["clock_sample_digest"]) is not str or len(provenance["clock_sample_digest"])!=64
                or any(c not in "0123456789abcdef" for c in provenance["clock_sample_digest"])
                or (request.namespace,request.operation_id,request.source_ref,request.resource_id,request.filenames,
                    request.max_bytes,request.valid_until_utc)!=
                   (namespace,responsibility.root_setup_operation_id,responsibility.source_ref,root.resource_id,
                    root.filenames,root.max_bytes,root.valid_until_utc)
                or (responsibility.cause_original_ref,responsibility.cause_original_digest,responsibility.cause_operation_id,
                    responsibility.cause_commit_seq,responsibility.root_registration_digest)!=
                   (root.registration_ref,canonical_digest(root_original[0]),responsibility.root_setup_operation_id,
                    setup["receipt"].commit_seq,canonical_digest(root_original[0]))
                or (root.installation_id,root.manifest_digest,root.source_ref)!=(responsibility.installation_id,
                    responsibility.manifest_digest,responsibility.source_ref)
                or (root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)!=
                   (responsibility.owner_guard.grant_ref,responsibility.owner_guard.grant_revision,responsibility.owner_guard.grant_digest)
                or responsibility.deadline_utc>_utc(root.valid_until_utc,"valid_until_utc").timestamp()):
            raise DomainProductionErasureHold("draft responsibility changed its actual root setup/cause/deadline original")
        require_foreground_cause_outbox_original_v1(db,namespace=namespace,producer_operation_id=responsibility.root_setup_operation_id,
            original_ref=root.registration_ref,original_digest=canonical_digest(root_original[0]),event_kind="artifact_draft_root_registered")
    return responsibility


def read_original_foreground_responsibility_for_c09_v1(db,*,namespace,job,issuer):
    """Authenticate the same passive lineage with the actual installed issuer."""
    from .issuers import D11BudgetJobIssuer
    from .d11_life_preparation_v1 import _read
    if type(issuer) is not D11BudgetJobIssuer:
        raise DomainProductionErasureHold("actual installed D11 original issuer required")
    if job.continuation.get("schema") == "d11.foreground-source-note-continuation.v1":
        from .source_note_foreground_v1 import read_source_note_responsibility_original_v1
        return read_source_note_responsibility_original_v1(db, namespace=namespace, job=job, issuer=issuer)
    responsibility=validate_foreground_responsibility_archive_closure_v1(db,namespace=namespace,job=job)
    if responsibility is None:
        return None
    grant,_=issuer.signed_budget_grant_at_version(db,responsibility.parent_budget_lease_ref,responsibility.parent_grant_version)
    if canonical_digest(grant)!=responsibility.parent_grant_digest:
        raise DomainProductionErasureHold("foreground authenticated parent grant differs from passive lineage")
    if responsibility.mode=="bounded_causal_window_v1":
        cause=read_foreground_post_c02_cause_original_v1(db,namespace=namespace,issuer=issuer,original_ref=responsibility.cause_original_ref)
        from ..domains.d01.production_operations_v1 import plain_v1
        if canonical_digest(plain_v1(cause))!=responsibility.cause_original_digest:
            raise DomainProductionErasureHold("foreground authenticated cause differs from passive lineage")
    else:
        root=_read(db,issuer=issuer,namespace=namespace,kind="draft_root_capability",ref=responsibility.root_registration_ref)
        if (root is None or root[1]!=responsibility.root_setup_operation_id
                or canonical_digest(root[0])!=responsibility.root_registration_digest):
            raise DomainProductionErasureHold("foreground authenticated root differs from passive lineage")
    return responsibility


def life_original_content_projection_v1(kind,raw):
    """Expose only declared embedded body schemas for C09 reference traversal."""
    if kind in {"c4_no_dispatch", "c4_phase_no_dispatch"}:
        from .d11_artifact_draft_model_v1 import decode_artifact_model_no_dispatch_v1
        decode_artifact_model_no_dispatch_v1(raw)
        return {"schema": raw["schema"], "financial_original_digest": canonical_digest(raw)}
    if kind in {"c4_request", "c4_phase_request"}:
        from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1, decode_artifact_draft_original_v2
        from .natural_reply_job_v2 import _request_from_wire
        from ..domains.d01.production_operations_v1 import plain_v1
        decoder = decode_artifact_draft_original_v2 if kind == "c4_phase_request" else decode_artifact_draft_original_v1
        value=decoder(kind,raw)
        return {**raw,"decoded_model_request":plain_v1(_request_from_wire(value.request_json))}
    return raw


def validate_c4_life_original_row_v1(kind,*,namespace,original_ref,producing_operation_id,raw):
    """Exact row identities for the seven registered technical variants."""
    from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
    from .model_cost_settlement import original_model_cost_operation_id_v1
    if kind not in C4_KINDS:raise DomainProductionErasureHold("unregistered C4 SQL original kind")
    if kind == "c4_no_dispatch":
        from .d11_artifact_draft_model_v1 import decode_artifact_model_no_dispatch_v1
        value = decode_artifact_model_no_dispatch_v1(raw)
        if (value.namespace, value.original_ref, value.cost_commit.operation_id) != (namespace, original_ref, producing_operation_id):
            raise DomainProductionErasureHold("no-dispatch SQL producer identity differs")
        return value
    value=decode_artifact_draft_original_v1(kind,raw)
    if kind=="c4_paid":
        marker=value.call_id.removeprefix("artifact-draft-call:")
        if (not value.call_id.startswith("artifact-draft-call:") or len(marker)!=40 or any(c not in "0123456789abcdef" for c in marker)
                or original_ref!="artifact-draft-paid:"+marker
                or producing_operation_id!=value.operation_id or value.operation_id!=original_model_cost_operation_id_v1(namespace,value.call_id)
                or NamespaceId.from_key(AtomKey.from_token(value.cost_ref))!=namespace):
            raise DomainProductionErasureHold("C4 financial SQL original crossed actual cost namespace/operation")
        return value
    if kind=="c4_call":
        from ..graph_coordinator import namespace_ref
        if value.namespace!=namespace_ref(namespace) or original_ref!=value.call_id or producing_operation_id!=value.acquire_operation_id:
            raise DomainProductionErasureHold("C4 call SQL original crossed actual model namespace/acquire")
        return value
    if kind=="c4_request":
        from .natural_reply_job_v2 import _request_from_wire
        from ..model_broker.artifact_draft_v1 import artifact_draft_from_wire_v1,ArtifactDraftInputV1
        request=_request_from_wire(value.request_json)
        frozen=artifact_draft_from_wire_v1(dict(request.payload)["input"],ArtifactDraftInputV1)
        selector=frozen.selector
    else:
        selector=value.request.selector if kind=="c4_result" else value.selector
    if selector.namespace!=namespace:raise DomainProductionErasureHold("C4 SQL original crossed business namespace")
    ids=artifact_draft_model_ids_v1(selector)
    expected_ref={"c4_frozen":ids["frozen"],"c4_prepared":ids["job"],"c4_request":ids["request"],
        "c4_result":ids["result"],"c4_adopted":ids["adopt"]}[kind]
    expected_op=(ids["prepare"] if kind in {"c4_frozen","c4_prepared"} else ids["acquire"] if kind=="c4_request"
        else ids["adopt"] if kind=="c4_adopted" else original_model_cost_operation_id_v1(namespace,ids["call"]))
    if (original_ref,producing_operation_id)!=(expected_ref,expected_op):
        raise DomainProductionErasureHold("C4 SQL original lost its exact stage predecessor/selector identity")
    return value


def validate_c4_phase_life_original_row_v2(kind, *, namespace, original_ref, producing_operation_id, raw):
    from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v2
    from ..model_broker.artifact_draft_v1 import (artifact_draft_model_ids_v2,
        artifact_draft_from_wire_v2, artifact_draft_input_from_wire_v2, artifact_draft_phase_original_ref_v2)
    from .model_cost_settlement import original_model_cost_operation_id_v1
    if kind not in C4_PHASE_KINDS:
        raise DomainProductionErasureHold("unregistered C4 phase SQL original kind")
    if kind == "c4_phase_no_dispatch":
        from .d11_artifact_draft_model_v1 import decode_artifact_model_no_dispatch_v1
        value = decode_artifact_model_no_dispatch_v1(raw)
        if (value.namespace, value.original_ref, value.cost_commit.operation_id) != (namespace, original_ref, producing_operation_id):
            raise DomainProductionErasureHold("no-dispatch SQL producer identity differs")
        return value
    value = decode_artifact_draft_original_v2(kind, raw)
    if kind == "c4_phase_paid":
        marker = value.call_id.removeprefix("artifact-draft-v2-call:")
        if (not value.call_id.startswith("artifact-draft-v2-call:") or len(marker) != 40
                or any(c not in "0123456789abcdef" for c in marker)
                or original_ref != "artifact-draft-v2-paid:" + marker
                or producing_operation_id != value.operation_id
                or value.operation_id != original_model_cost_operation_id_v1(namespace, value.call_id)
                or NamespaceId.from_key(AtomKey.from_token(value.cost_ref)) != namespace):
            raise DomainProductionErasureHold("C4 phase paid original crossed actual financial scope")
        return value
    if kind == "c4_phase_call":
        from ..graph_coordinator import namespace_ref
        marker = value.call_id.removeprefix("artifact-draft-v2-call:")
        if (value.namespace != namespace_ref(namespace) or original_ref != value.call_id
                or producing_operation_id != value.acquire_operation_id
                or not value.call_id.startswith("artifact-draft-v2-call:") or len(marker) != 40
                or any(c not in "0123456789abcdef" for c in marker)):
            raise DomainProductionErasureHold("C4 phase call original crossed actual acquire scope")
        return value
    if kind == "c4_phase_request":
        from .natural_reply_job_v2 import _request_from_wire
        request = _request_from_wire(value.request_json)
        selector = artifact_draft_input_from_wire_v2(dict(request.payload)["input"]).selector
    else:
        selector = value.request.selector if kind == "c4_phase_result" else value.selector
    if selector.task.namespace != namespace:
        raise DomainProductionErasureHold("C4 phase SQL original crossed business namespace")
    if kind == "c4_phase_verified":
        phase_ref = artifact_draft_phase_original_ref_v2(selector)
        if (original_ref, producing_operation_id) != (phase_ref + ":verified", phase_ref + ":verify"):
            raise DomainProductionErasureHold("C4 verified original lost independent producer identity")
        return value
    ids = artifact_draft_model_ids_v2(selector)
    expected_ref = {"c4_phase_frozen": ids["frozen"], "c4_phase_prepared": ids["job"],
        "c4_phase_request": ids["request"], "c4_phase_result": ids["result"], "c4_phase_adopted": ids["adopt"]}[kind]
    expected_op = (ids["prepare"] if kind in {"c4_phase_frozen", "c4_phase_prepared"}
        else ids["acquire"] if kind == "c4_phase_request" else ids["adopt"] if kind == "c4_phase_adopted"
        else original_model_cost_operation_id_v1(namespace, ids["call"]))
    if (original_ref, producing_operation_id) != (expected_ref, expected_op):
        raise DomainProductionErasureHold("C4 phase SQL original lost exact selector/stage identities")
    return value


def _validate_c4_paid_member_v1(db,namespace,paid):
    actual=require_c4_model_cost_original_commit_v1(db,namespace=namespace,operation_id=paid.operation_id)
    if actual!=paid:raise DomainProductionErasureHold("C4 signed paid original differs from actual financial receipt")


def require_c4_model_cost_original_commit_v1(db,*,namespace,operation_id):
    """Recognize existing real model-cost receipt ABI, never generalize commits."""
    from .d11_types import RuntimeCostSettlement,runtime_cost_settlement_key
    from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1
    from .model_cost_settlement import original_model_cost_operation_id_v1
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise DomainProductionErasureHold("C4 financial originals need the actual pinned namespace transaction")
    row=db.execute("SELECT activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple,operation_id)).fetchone()
    if row is None:raise DomainProductionErasureHold("C4 actual model cost operation absent")
    raw=_json(row[3])
    if (set(raw)!={"original_model_cost","original_intent_digest","terminal_receipt_digest","quote_id","quote_version","work_kind","accounting_attempt_id"}
            or raw["work_kind"]!="artifact_draft_v1"):
        raise DomainProductionErasureHold("C4 actual financial receipt has another unregistered ABI")
    paid=decode_artifact_draft_original_v1("c4_paid",raw["original_model_cost"])
    if (paid.operation_id!=operation_id or paid.commit_seq!=row[2] or paid.operation_id!=original_model_cost_operation_id_v1(namespace,paid.call_id)
            or (raw["terminal_receipt_digest"],raw["quote_id"],raw["quote_version"])!=(paid.terminal_receipt_digest,paid.quote_id,paid.quote_version)):
        raise DomainProductionErasureHold("C4 actual financial receipt changed original identity/terminal")
    event=db.execute("SELECT revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple,row[0],operation_id)).fetchone()
    if event is None:raise DomainProductionErasureHold("C4 actual model cost Graph event absent")
    from ..graph_store import GraphStore
    versions=tuple(v for v in GraphStore._version_rows(event[0]) if v.key.token==paid.cost_ref)
    if len(versions)!=1 or event[1]!=paid.graph_epoch:
        raise DomainProductionErasureHold("C4 paid original lost its actual financial CAS member")
    history=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (paid.cost_ref,versions[0].revision)).fetchone()
    if history is None or history[0]!=paid.operation_id or history[2]!=1:
        raise DomainProductionErasureHold("C4 paid original lost immutable financial history")
    cost=decode_typed_production_value_v1(_json(history[1]),RuntimeCostSettlement)
    budget=db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase='settle'",
        (cost.lease_id,cost.cost_operation_id)).fetchone()
    if (budget is None or canonical_digest(_json(budget[0]))!=paid.budget_receipt_digest
            or (cost.bot_id,cost.persona_id,cost.bundle_operation_id,cost.settlement_id,cost.activity_id,cost.effect_id)!=
                (*namespace.as_tuple,paid.operation_id,paid.operation_id,row[0],row[1])
            or paid.cost_ref!=runtime_cost_settlement_key(*namespace.as_tuple,row[0],paid.operation_id).token
            or cost.budget_phase!="settle" or cost.budget_operation_id!=cost.cost_operation_id
            or cost.budget_receipt_digest!=hashlib.sha256(budget[0].encode()).hexdigest()):
        raise DomainProductionErasureHold("C4 paid original lost actual spent/unconfirmed reservation facts")
    from .budget import BudgetReceipt
    receipt=decode_typed_production_value_v1(_json(budget[0]),BudgetReceipt)
    if (receipt.operation_id,receipt.lease_id,receipt.status)!=(cost.cost_operation_id,cost.lease_id,cost.status):
        raise DomainProductionErasureHold("C4 financial Graph history differs from its actual budget receipt")
    return paid


def _validate_c4_prepared_history_v1(db, namespace, prepared, frozen, *, phase=False):
    """Passive prepared/job/R/quote/reservation lineage; no live budget or permit issuance."""
    from .jobs import get_job, _job_from_dict, _utc
    from .d11_types import job_graph_write
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1, decode_foreground_job_v1
    from .issuers import _decode_quote
    from ..domains.d01.production_operations_v1 import plain_v1
    task = prepared.selector.task if phase else prepared.selector
    prepare_kind = "prepare_artifact_draft_model_v2" if phase else "prepare_artifact_draft_model"
    origin=read_adopted_domain_operation_v1(db,namespace,prepared.operation_id)
    if (origin is None or (origin["domain"],origin["operation_kind"])!=("d11",prepare_kind)
            or origin["payload"]["provenance"]["prepared"]!=plain_v1(prepared)):
        raise DomainProductionErasureHold("C4 prepared lost its actual same-CAS producer")
    cycle=get_job(db,foreground_cycle_ids_v1(namespace,task.c02_operation_id)[1])
    responsibility=validate_foreground_responsibility_archive_closure_v1(db,namespace=namespace,job=cycle)
    continuation=foreground_cycle_from_wire_v1(cycle.continuation)
    if (responsibility is None or prepared.namespace!=namespace
            or (prepared.parent_budget_lease_ref,task.root_registration_ref)!=(
                responsibility.parent_budget_lease_ref,responsibility.root_registration_ref)
            or task.cycle_job_ref!=job_graph_write(cycle).key.token
            or _utc(prepared.deadline_utc,"deadline_utc").timestamp()>responsibility.deadline_utc):
        raise DomainProductionErasureHold("C4 prepared crossed actual cycle/R/C02/parent/deadline")
    attempts=tuple(value for value in continuation.call_plan.attempts if value.call_id==prepared.call_id)
    if (len(attempts)!=1 or (attempts[0].slot,attempts[0].original_call_id,attempts[0].reservation_operation_id,
            attempts[0].reservation_digest,attempts[0].budget_lease_ref)!=(
                "C4",None,prepared.operation_id,prepared.reservation_digest,prepared.parent_budget_lease_ref)):
        raise DomainProductionErasureHold("C4 prepared lost its actual inherited call-plan slot")
    if phase:
        from .foreground_call_plan_v1 import ForegroundModelAttemptV2
        if type(attempts[0]) is not ForegroundModelAttemptV2 or attempts[0].phase_selector != prepared.selector:
            raise DomainProductionErasureHold("C4 phase prepared lost its actual typed physical attempt")
    quote_row=db.execute("SELECT quote_json,signature FROM runtime_resource_quotes WHERE quote_id=? AND version=1",
        (prepared.quote_id,)).fetchone()
    if quote_row is None:
        raise DomainProductionErasureHold("C4 prepared actual original quote is absent")
    quote=_decode_quote(quote_row[0])
    if (canonical_serialize(asdict(quote))!=quote_row[0] or canonical_digest(quote)!=prepared.quote_digest
            or type(quote_row[1]) is not str or len(quote_row[1])!=64 or any(c not in "0123456789abcdef" for c in quote_row[1])
            or (quote.bot_id,quote.persona_id,quote.activity_id,quote.operation_id,quote.effect_id,quote.parent_budget_lease_ref,
                quote.work_kind,quote.quote_id,quote.version)!=(
                    *namespace.as_tuple,prepared.activity_id,prepared.operation_id,None,prepared.parent_budget_lease_ref,
                    "artifact_draft_v1",prepared.quote_id,1)
            or quote.valid_until_utc!=_utc(prepared.deadline_utc,"deadline_utc").timestamp()
            or (attempts[0].input_ceiling,attempts[0].output_ceiling)!=(quote.ceiling["input_tokens"],quote.ceiling["output_tokens"])):
        raise DomainProductionErasureHold("C4 prepared original quote differs from its inherited slot/parent")
    reservation=db.execute("SELECT digest,ceiling_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (prepared.parent_budget_lease_ref,prepared.operation_id)).fetchone()
    if reservation!=(prepared.reservation_digest,canonical_serialize(dict(quote.ceiling))):
        raise DomainProductionErasureHold("C4 prepared lost its original parent bucket reservation")
    row=db.execute("SELECT digest,job_id,job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='create'",(*namespace.as_tuple,"create:"+prepared.operation_id)).fetchone()
    if row is None or row[:2]!=(prepared.reservation_digest,prepared.job_id):
        raise DomainProductionErasureHold("C4 prepared actual original model job is absent")
    born=_job_from_dict(_json(row[2]));current=get_job(db,prepared.job_id)
    fields_to_keep=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref",
        "work_kind","continuation","deadline_utc","budget_ref","resource_ref","operator_versions")
    if (plain_v1(born)!=_json(row[2]) or born.phase!="queued" or born.fence or born.cancel_epoch
            or any(getattr(born,name)!=getattr(current,name) for name in fields_to_keep)
            or (born.job_id,born.operation_id,born.activity_id,born.bot_id,born.persona_id,born.budget_ref,born.deadline_utc)!=
                (prepared.job_id,prepared.operation_id,prepared.activity_id,*namespace.as_tuple,prepared.parent_budget_lease_ref,prepared.deadline_utc)):
        raise DomainProductionErasureHold("C4 prepared model job changed its immutable parent/task occurrence")
    version=tuple(v for v in origin["receipt"].write_versions if v.key==job_graph_write(born).key)
    if (len(version)!=1 or db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (version[0].key.token,version[0].revision)).fetchone()!=(prepared.operation_id,canonical_serialize(job_graph_write(born).value),1)):
        raise DomainProductionErasureHold("C4 prepared model job lost its actual original Graph CAS member")
    after_cycle=decode_foreground_job_v1(origin["payload"]["provenance"]["after_cycle"],namespace=namespace)
    if phase:
        from .foreground_call_plan_v1 import ForegroundCallPlanV2
        plan = foreground_cycle_from_wire_v1(after_cycle.continuation).call_plan
        if type(plan) is not ForegroundCallPlanV2 or plan.phase_group.selector != prepared.selector:
            raise DomainProductionErasureHold("C4 phase preparation lost its actual same-CAS method group")
    if (after_cycle.job_id!=cycle.job_id or foreground_cycle_from_wire_v1(after_cycle.continuation).responsibility_digest!=responsibility.digest
            or prepared.actor_ref!=frozen.current_self_ref):
        raise DomainProductionErasureHold("C4 preparation borrowed another actual responsibility/self")


def _require_c4_paid_parent_bucket_v1(db, namespace, prepared, paid):
    from .d11_types import RuntimeCostSettlement
    rows=db.execute("SELECT value FROM graph_history WHERE token=? AND event_id=? AND valid=1",
        (paid.cost_ref,paid.operation_id)).fetchall()
    if len(rows)!=1:
        raise DomainProductionErasureHold("C4 paid original has no unique actual financial member")
    cost=decode_typed_production_value_v1(_json(rows[0][0]),RuntimeCostSettlement)
    if (cost.bot_id,cost.persona_id,cost.lease_id,cost.cost_operation_id)!=(
            *namespace.as_tuple,prepared.parent_budget_lease_ref,prepared.operation_id):
        raise DomainProductionErasureHold("C4 financial original settled another parent/reservation bucket")


def _validate_c4_original_joins_v1(db,originals):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
    from .natural_reply_job_v2 import _request_from_wire
    from .model_cost_settlement import original_model_cost_operation_id_v1
    for (ns,kind,ref),(op,value,raw,digest) in originals.items():
        validate_c4_original_join_row_v2(db,ns=ns,kind=kind,ref=ref,op=op,value=value,raw=raw,digest=digest,
            read_original=originals.get,
            read_prepared_by_call=lambda space,part,call: _legacy_unique_prepared_row_v2(originals,space,part,call))


def _validate_c4_content_original_joins_v1(db, ns, value, prepared, frozen, paid_row, result_row, originals, *, phase=False):
    result = result_row[1]
    task_selector = value.selector.task if phase else value.selector
    source=_c4_adopted_source_v1(db,ns,value,phase=phase)
    scope_row=originals.get((ns,"activity_scope",value.activity_scope_ref))
    root_row=originals.get((ns,"draft_root_capability",task_selector.root_registration_ref))
    if scope_row is None or root_row is None or scope_row[0]!=value.adoption_operation_id or scope_row[3]!=value.activity_scope_digest:
        raise DomainProductionErasureHold("C4 adopted content lost its actual same-CAS scope/root originals")
    scope,root=scope_row[1],root_row[1]
    if ((scope.actor_ref,scope.activity_id,scope.c02_original_ref,scope.parent_budget_lease_ref,scope.source)!=
            (prepared.actor_ref,prepared.activity_id,task_selector.c02_operation_id,prepared.parent_budget_lease_ref,value.task_source)
            or (scope.root_registration_ref,scope.root_registration_digest)!=(root.registration_ref,root_row[3])
            or (root.registration_ref,root_row[3],root.root_identity,root.resource_id,root.filenames)!=
               (frozen.target.root_registration_ref,frozen.target.root_registration_digest,frozen.target.root_identity,
                frozen.target.root_resource_id,(frozen.target.filename,))
            or (scope.owner_grant_ref,scope.owner_grant_revision,scope.owner_grant_digest)!=
               (root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)):
        raise DomainProductionErasureHold("C4 adopted scope lost its exact self/task/Owner/registered target")
    from datetime import datetime
    deadline=datetime.fromisoformat(value.original_deadline_utc.replace("Z","+00:00"))
    if deadline>min(datetime.fromisoformat(s.replace("Z","+00:00")) for s in (scope.valid_until_utc,root.valid_until_utc)):
        raise DomainProductionErasureHold("C4 adopted content extended its actual parent scope deadline")
    expected_parents=tuple(AtomKey.from_token(s.ref).owner.subject for s in sorted(frozen.sources,key=lambda s:s.ref))
    task=next(s for s in frozen.sources if s.ref==frozen.task_source_ref)
    if (source.parent_source_ids!=expected_parents
            or value.content.source_refs!=(value.content.content.ref,*(s.ref for s in frozen.sources))
            or (value.task_source.ref,value.task_source.revision,value.task_source.digest)!=(task.ref,task.revision,task.value_digest)
            or value.original_deadline_utc!=prepared.deadline_utc):
        raise DomainProductionErasureHold("C4 authored content changed the complete original parent/task/deadline closure")
    if ((value.prepared_digest,value.content.content_digest,value.target)!=(prepared.digest,
            hashlib.sha256(source.text.encode()).hexdigest(),frozen.target)
        or (value.paid_original_digest,value.result_original_digest,value.model_terminal_digest)!=
            (paid_row[3],result_row[3],canonical_digest(result.terminal_receipt))):
        raise DomainProductionErasureHold("C4 adopted Source lost exact paid/frozen/readback associations")
    from ..model_broker.artifact_draft_v1 import parse_artifact_draft_output_v1, parse_artifact_draft_output_v2
    body=_json(result.observation.result_json)
    if type(body) is not dict or set(body)!={"text"}:raise DomainProductionErasureHold("C4 adopted result has no exact provider text envelope")
    output=(parse_artifact_draft_output_v2 if phase else parse_artifact_draft_output_v1)(body["text"],frozen)
    if output.needs_clarification or output.draft_text!=source.text:
        raise DomainProductionErasureHold("C4 authored Source differs from its actual paid model output")
    if phase:
        if paid_row[1].status != "committed":
            raise DomainProductionErasureHold("C4 phase authored content has no known committed actual cost")
        previous_ref, previous_digest = value.selector.prev_phase_original_ref, value.selector.prev_phase_original_digest
        if previous_ref is not None:
            previous = originals.get((ns, "c4_phase_verified", previous_ref))
            if (previous is None or previous[3] != previous_digest
                    or previous[1].selector.task != value.selector.task
                    or previous[1].selector.method_ref != value.selector.method_ref
                    or previous[1].selector.phase_index != value.selector.phase_index - 1):
                raise DomainProductionErasureHold("C4 phase authored Source lost its actual independently verified prefix")
        if frozen.prior_content is not None:
            prior = originals.get((ns, "c4_phase_verified", frozen.prior_content.verified_original_ref))
            if (prior is None or prior[3] != frozen.prior_content.verified_original_digest
                    or prior[1].source_head.key.token != frozen.prior_content.source_head.ref
                    or prior[1].source_head.revision != frozen.prior_content.source_head.version
                    or prior[1].source_value_digest != frozen.prior_content.source_value_digest
                    or prior[1].readback != frozen.prior_content.verified_readback):
                raise DomainProductionErasureHold("C4 phase prior input lost its actual independently verified Source/readback")
        from .artifact_task_text_extent_v1 import require_artifact_task_text_extent_history_v1
        extent_row = originals.get((ns, "artifact_task_text_extent", value.extent_original_ref))
        if extent_row is None or extent_row[3] != value.extent_original_digest:
            raise DomainProductionErasureHold("C4 phase authored Source lost its exact registered whole-task extent")
        extent = require_artifact_task_text_extent_history_v1(db, namespace=ns, original_ref=value.extent_original_ref,
            producing_operation_id=extent_row[0], raw=extent_row[2])
        if ((value.extent, extent.full_extent, extent.task_c02_operation_id,
                extent.task_source_head.key.token, extent.task_source_head.revision, extent.task_source_digest) != (
                frozen.extent, value.full_extent, task_selector.c02_operation_id,
                frozen.task_source_ref, value.task_source.revision, value.task_source.digest)):
            raise DomainProductionErasureHold("C4 phase authored Source changed its actual task/registered full extent")


def _validate_c4_phase_original_joins_v2(db, originals):
    from ..model_broker.artifact_draft_v1 import (artifact_draft_model_ids_v2,
        artifact_draft_from_wire_v2, artifact_draft_input_from_wire_v2)
    from .natural_reply_job_v2 import _request_from_wire
    from .model_cost_settlement import original_model_cost_operation_id_v1
    for (ns,kind,ref),(op,value,raw,digest) in originals.items():
        validate_c4_phase_original_join_row_v3(db,ns=ns,kind=kind,ref=ref,op=op,value=value,raw=raw,digest=digest,
            read_original=originals.get,
            read_prepared_by_call=lambda space,part,call: _legacy_unique_prepared_row_v2(originals,space,part,call))


def _validate_c4_phase_verified_joins_v2(db, *, namespace, original_ref, producing_operation_id, raw, originals):
    from .d11_artifact_draft_content_v1 import require_artifact_draft_phase_verified_history_v2
    from .d11_life_contract_v1 import D11LifeTerminalV1, D11DraftTerminalV1, life_from_wire_v1
    from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
    from .artifact_task_text_extent_v1 import require_artifact_task_text_extent_history_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2, artifact_draft_model_ids_v2, ArtifactDraftInputV3
    from ..graph_types import GraphVersion
    value = require_artifact_draft_phase_verified_history_v2(db, namespace=namespace, original_ref=original_ref,
        producing_operation_id=producing_operation_id, raw=raw)
    adoption_row = originals.get((namespace, "c4_phase_adopted", value.content_adoption_ref))
    readback_row = originals.get((namespace, "adopted_life", value.readback_original_ref))
    extent_row = originals.get((namespace, "artifact_task_text_extent", value.extent_original_ref))
    if (adoption_row is None or readback_row is None or extent_row is None
            or (adoption_row[3], readback_row[3], extent_row[3]) != (
                value.content_adoption_digest, value.readback_original_digest, value.extent_original_digest)):
        raise DomainProductionErasureHold("C4 phase verified original lost actual adopted content/file/extent predecessors")
    adoption = adoption_row[1]
    terminal = life_from_wire_v1(readback_row[2]["terminal"], D11LifeTerminalV1)
    if type(terminal) is not D11DraftTerminalV1 or terminal.status != "completed":
        raise DomainProductionErasureHold("C4 phase verified readback is not the actual completed file effect")
    prepared_row = originals.get((namespace, "prepared", terminal.binding.prepared_original_ref))
    if prepared_row is None:
        raise DomainProductionErasureHold("C4 phase verified readback lost actual signed Life preparation")
    prepared = prepared_row[1]
    readback = require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
    from .d11_offline_originals_v1 import _utc
    ids = artifact_draft_file_ids_v2(value.content_selector)
    plan = prepared.plan
    if ((plan.operation_id, plan.attempt_id, plan.effect_id, plan.execution_call_id) != (
                ids["action_operation"], ids["attempt"], ids["effect"], ids["execution_call"])
            or (plan.target, plan.content, plan.activity_scope_ref, plan.activity_scope_digest) != (
                adoption.target, adoption.content, adoption.activity_scope_ref, adoption.activity_scope_digest)
            or _utc(plan.deadline_utc).timestamp() > _utc(adoption.original_deadline_utc).timestamp()
            or value.readback != readback
            or (readback.content_digest, readback.content_length, readback.root_registration_digest) != (
                adoption.content.content_digest, adoption.content.content_length, adoption.target.root_registration_digest)):
        raise DomainProductionErasureHold("C4 phase verified file/readback changed its actual Source/target/once effect")
    if ((value.content_selector, value.source_head, value.source_value_digest, value.extent, value.full_extent,
            value.extent_original_ref, value.extent_original_digest, value.original_deadline_utc) != (
            adoption.selector, GraphVersion(AtomKey.from_token(adoption.content.content.ref), adoption.content.content.revision),
            adoption.content.content.digest, adoption.extent, adoption.full_extent,
            adoption.extent_original_ref, adoption.extent_original_digest, adoption.original_deadline_utc)):
        raise DomainProductionErasureHold("C4 phase verified original changed adopted Source head/extent/deadline")
    model_ids = artifact_draft_model_ids_v2(value.content_selector)
    frozen_row = originals.get((namespace, 'c4_phase_frozen', model_ids['frozen']))
    if frozen_row is None:
        raise DomainProductionErasureHold('C4 phase verified lost its actual generation frozen material')
    contract = None
    if type(frozen_row[1]) is ArtifactDraftInputV3:
        from .d11_artifact_draft_model_v1 import require_artifact_phase_frozen_contract_history_v3
        contract = require_artifact_phase_frozen_contract_history_v3(db, namespace=namespace, frozen=frozen_row[1])
    if not value.selector.generation:
        from .artifact_phase_postconditions_v1 import (ASSESSMENT_KIND, artifact_phase_assessment_original_ref_v1,
            require_artifact_phase_assessment_history_v1)
        from .d11_artifact_draft_content_v1 import _require_actual_artifact_phase_assessment_v1
        if contract is None or len(value.postcondition_originals) != 1:
            raise DomainProductionErasureHold('C4 method check lost its actual preregistered contract and assessment')
        proof = value.postcondition_originals[0]
        if (proof.kind, proof.original_ref) != (ASSESSMENT_KIND, artifact_phase_assessment_original_ref_v1(value.selector)):
            raise DomainProductionErasureHold('C4 method check changed its deterministic assessment locator')
        assessment_row = originals.get((namespace, ASSESSMENT_KIND, proof.original_ref))
        if assessment_row is None or assessment_row[3] != proof.original_digest:
            raise DomainProductionErasureHold('C4 method check lost actual signed assessment bytes')
        assessment = require_artifact_phase_assessment_history_v1(db, namespace=namespace, original_ref=proof.original_ref,
            producing_operation_id=assessment_row[0], raw=assessment_row[2])
        _require_actual_artifact_phase_assessment_v1(selector=value.selector, content_selector=value.content_selector,
            contract=contract, assessment=assessment, adoption=adoption, file_result_ref=value.readback_original_ref,
            file_result_digest=value.readback_original_digest, readback=readback)
        if proof.read_versions != (assessment.source_head,):
            raise DomainProductionErasureHold('C4 method check changed actual assessment Source commitment')
    extent = require_artifact_task_text_extent_history_v1(db, namespace=namespace,
        original_ref=value.extent_original_ref, producing_operation_id=extent_row[0], raw=extent_row[2])
    if (extent.full_extent, extent.task_c02_operation_id, extent.task_source_head.key.token,
            extent.task_source_head.revision, extent.task_source_digest) != (
            value.full_extent, value.selector.task.c02_operation_id, adoption.task_source.ref,
            adoption.task_source.revision, adoption.task_source.digest):
        raise DomainProductionErasureHold("C4 phase verified extent belongs to another registered task")
    if value.prev_verified_original_ref is not None:
        previous = originals.get((namespace, "c4_phase_verified", value.prev_verified_original_ref))
        if (previous is None or previous[3] != value.prev_verified_original_digest
                or previous[1].selector.task != value.selector.task
                or previous[1].selector.method_ref != value.selector.method_ref
                or previous[1].selector.phase_index != value.selector.phase_index - 1):
            raise DomainProductionErasureHold("C4 phase verified lost its actual immediately preceding method original")
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    from ..domains.d03.self_perspective import self_mapping_key, SelfIdentityMapping
    actual = read_adopted_domain_operation_v1(db, namespace, producing_operation_id)
    guard = decode_typed_production_value_v1(actual["payload"]["owner_guard"], ProductionOwnerGuardV1)
    mapping_versions = tuple(version for version in actual["read_versions"] if version.key == self_mapping_key(namespace))
    if len(mapping_versions) != 1:
        raise DomainProductionErasureHold("C4 verified original lost its actual independent self-mapping read")
    row = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
        (mapping_versions[0].key.token, mapping_versions[0].revision)).fetchone()
    if row is None or row[1] != 1 or canonical_digest(_json(row[0])) != value.current_self_digest:
        raise DomainProductionErasureHold("C4 verified original changed its actual historical self-mapping bytes")
    mapping = decode_typed_production_value_v1(_json(row[0]), SelfIdentityMapping)
    if (mapping.status != "active" or value.actor_ref != mapping.self_entity_ref or value.owner_guard != guard
            or actual["payload"]["authority"]["actor"] != value.actor_ref):
        raise DomainProductionErasureHold("C4 verified original changed actual independent Owner/self producer")


def _c4_adopted_source_v1(db,namespace,adopted, *, phase=False):
    from ..memory_types import SourceRecord
    row=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (adopted.content.content.ref,adopted.content.content.revision)).fetchone()
    if row is None or row[0]!=adopted.adoption_operation_id or row[2]!=1 or canonical_digest(_json(row[1]))!=adopted.content.content.digest:
        raise DomainProductionErasureHold("C4 authored Source lacks its actual immutable adoption member")
    source=SourceRecord.from_dict(_json(row[1]))
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1, artifact_draft_model_ids_v2
    from ..memory_types import source_key
    if (source.source_kind!="authored" or source.assertion_status!="unknown"
            or len(source.text.encode())!=adopted.content.content_length or source.recorded_at!=adopted.recorded_at_utc
            or source.source_id!=(artifact_draft_model_ids_v2 if phase else artifact_draft_model_ids_v1)(adopted.selector)["source"]
            or source_key(*namespace.as_tuple,source.source_id).token!=adopted.content.content.ref):
        raise DomainProductionErasureHold("C4 authored Source reality/length/original identity differs")
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d03.self_perspective import self_mapping_key,SelfIdentityMapping
    production=read_adopted_domain_operation_v1(db,namespace,adopted.adoption_operation_id)
    if production is None:raise DomainProductionErasureHold("C4 authored content lost its actual D06 CAS original")
    if phase and (production["domain"], production["operation_kind"]) != ("d06", "adopt_artifact_draft_content_v2"):
        raise DomainProductionErasureHold("C4 phase authored Source has another actual producer")
    versions=tuple(v for v in production["read_versions"] if v.key==self_mapping_key(namespace))
    if len(versions)!=1:raise DomainProductionErasureHold("C4 authored content lost its actual read self mapping")
    mapping_row=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
        (versions[0].key.token,versions[0].revision)).fetchone()
    if mapping_row is None or mapping_row[1]!=1:raise DomainProductionErasureHold("C4 original self mapping history absent")
    mapping=decode_typed_production_value_v1(_json(mapping_row[0]),SelfIdentityMapping)
    if (mapping.status!="active" or source.speaker_id!=mapping.persona_ref
            or production["payload"]["authority"]["actor"]!=mapping.self_entity_ref
            or not any(v.key.token==adopted.content.content.ref and v.revision==adopted.content.content.revision
                for v in production["receipt"].write_versions)):
        raise DomainProductionErasureHold("C4 authored content lost its actual self identity and original write member")
    return source


def validate_draft_self_life_original_join_v1(db,*,gate,originals,operation_id):
    from ..authority_service.d11_life_bridge_v1 import D11DraftSelfAdoptionBridgeV2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    if type(gate) is not D11DraftSelfAdoptionBridgeV2:raise DomainProductionErasureHold("exact draft self bridge required")
    b=gate.binding;ns=b.namespace
    prepared=originals.get((ns,"prepared",b.prepared_original_ref))
    scope=originals.get((ns,"activity_scope",gate.activity_scope_ref))
    root=originals.get((ns,"draft_root_capability",b.root_registration_ref))
    if (prepared is None or prepared[1].binding!=b or prepared[1].digest!=gate.prepared_digest
            or scope is None or scope[3]!=b.activity_scope_digest or scope[1].actor_ref!=gate.current_self.self_entity_ref
            or root is None or root[3]!=b.root_registration_digest
            or (scope[1].root_registration_ref,scope[1].root_registration_digest)!=(b.root_registration_ref,b.root_registration_digest)
            or (gate.current_self.owner_authorization_revision,gate.current_self.owner_authorization_head,
                gate.current_self.owner_minimum_revocation_revision,gate.current_self.owner_revocation_epoch)!=
               (gate.owner_authority.guard.authorization_revision,gate.owner_authority.guard.authorization_head,
                gate.owner_authority.guard.minimum_revocation_revision,gate.owner_authority.guard.minimum_revocation_epoch)):
        raise DomainProductionErasureHold("draft self bridge lost actual self/upstreamOwner/root/scope/prepared originals")
    production=read_adopted_domain_operation_v1(db,ns,operation_id)
    if (production is None or production["payload"]["authority"]["actor"]!=gate.current_self.self_entity_ref
            or production["receipt"].operation_id!=operation_id):
        raise DomainProductionErasureHold("draft self adoption has no actual same-self final CAS original")


def validate_life_stage_row_v1(columns, row, *, authority_namespace=None):
    from .domain_production_erasure_v1 import TABLE_COLUMNS
    expected = TABLE_COLUMNS["graph_d11_life_artifact_stage_v1"]
    if tuple(columns) != expected or len(row) != len(expected):
        raise DomainProductionErasureHold("Life stage columns differ")
    data = dict(zip(columns, row))
    ns = NamespaceId(data["bot"], data["persona"])
    if authority_namespace is not None:
        from ..graph_coordinator import namespace_ref
        if namespace_ref(ns) != authority_namespace:
            raise DomainProductionErasureHold("Life stage namespace differs")
    blob = data["artifact_bytes"]
    if (type(blob) is not bytes or not 1 <= len(blob) <= 262144
            or len(blob) != data["artifact_length"] or hashlib.sha256(blob).hexdigest() != data["artifact_digest"]):
        raise DomainProductionErasureHold("Life stage durable bytes/length/hash differ")
    value = _json(blob.decode("utf-8"))
    from .d11_life_contract_v1 import RECIPE_ID, life_artifact_ref_v1
    from ..memory_types import SourceRecord
    if (set(value) != {"schema", "recipe_id", "recipe_version", "activity_id", "effect_id", "attempt_id", "source_ref", "source_revision", "source_digest", "source_record"}
            or value["schema"] != ARTIFACT_SCHEMA or value["recipe_id"] != RECIPE_ID or value["recipe_version"] != 1
            or data["artifact_ref"] != life_artifact_ref_v1(ns, value["effect_id"])
            or canonical_digest(value["source_record"]) != value["source_digest"]
            or AtomKey.from_token(value["source_ref"]).type_name != "memory.source"
            or NamespaceId.from_key(AtomKey.from_token(value["source_ref"])) != ns):
        raise DomainProductionErasureHold("Life stage complete source artifact fields differ")
    SourceRecord.from_dict(value["source_record"])
    return "artifact_stage", data["artifact_ref"], value, data["artifact_digest"]


def life_stage_dispositions_v1(columns, rows, *, affected, affected_operations, nested_hits, source_ids, authority_namespace):
    result = []
    for row in rows:
        _, ref, raw, _ = validate_life_stage_row_v1(columns, row, authority_namespace=authority_namespace)
        data = dict(zip(columns, row))
        removed = (raw["source_ref"] in affected or ref in affected or data["adopted_operation_id"] in affected_operations
            or nested_hits(raw, affected, source_ids))
        result.append("derived_removed" if removed else "preserved_exact")
    return tuple(result)


def validate_life_original_joins_v1(db):
    from .d11_life_preparation_v1 import TABLE
    from .domain_production_erasure_v1 import TABLE_COLUMNS, validate_domain_production_row_v1
    from .d11_life_accounting_v1 import life_accounting_original_ref_v1
    from .d11_life_adoption_v1 import validate_life_adoption_composite_v1
    from .d11_life_historical_accounting_v1 import validate_life_historical_accounting_composite_v1
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is None:
        return
    originals={}
    for row in db.execute("SELECT bot,persona,kind,original_ref,producing_operation_id,payload_json,payload_digest,signature FROM "+TABLE):
        kind,ref,raw,digest=validate_domain_production_row_v1(TABLE,TABLE_COLUMNS[TABLE],row)
        originals[(NamespaceId(row[0],row[1]),kind,ref)]=(row[4],decode_life_original_content_v1(kind,row[5]),raw,digest)
    _validate_c4_original_joins_v1(db,originals)
    _validate_c4_phase_original_joins_v2(db, originals)
    for (ns,kind,ref),(op,value,raw,digest) in originals.items():
        validate_life_original_join_row_v2(db,ns=ns,kind=kind,ref=ref,op=op,value=value,raw=raw,digest=digest,
            read_original=originals.get)


class _LifeOriginalPointLookupV2:
    __slots__=('read_original',)

    def __init__(self,read_original): self.read_original=read_original

    def get(self,key): return self.read_original(key)


def validate_life_original_join_row_v2(db, *, ns, kind, ref, op, value, raw, digest, read_original):
    """One actual Life original plus exact indexed historical joins; no namespace collection."""
    from .d11_life_preparation_v1 import TABLE
    from .domain_production_erasure_v1 import TABLE_COLUMNS, validate_domain_production_row_v1
    from .d11_life_accounting_v1 import life_accounting_original_ref_v1
    from .d11_life_adoption_v1 import validate_life_adoption_composite_v1
    from .d11_life_historical_accounting_v1 import validate_life_historical_accounting_composite_v1
    originals = _LifeOriginalPointLookupV2(read_original)
    if kind == 'artifact_task_continuation_authorization_v2':
        from .artifact_task_continuation_authorization_v2 import require_continuation_authorization_history_v2
        checked = require_continuation_authorization_history_v2(db, namespace=ns,
            original_ref=ref, producing_operation_id=op, raw=raw)
        if checked != value:
            raise DomainProductionErasureHold('continuation authorization differs from exact signed original')
        return None
    if kind == 'artifact_task_milestone_v2':
        from .artifact_task_observer_v1 import require_artifact_task_milestone_history_v2
        require_artifact_task_milestone_history_v2(db, namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw)
        return None
    if kind in POSTCONDITION_KINDS:
        from .artifact_phase_postconditions_v1 import require_artifact_phase_postcondition_history_v1
        require_artifact_phase_postcondition_history_v1(db, namespace=ns, kind=kind, original_ref=ref, producing_operation_id=op, raw=raw)
        return None
    if kind == 'artifact_task_text_extent':
        from .artifact_task_text_extent_v1 import require_artifact_task_text_extent_history_v1
        require_artifact_task_text_extent_history_v1(db, namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw)
        return None
    if kind == 'artifact_task_amendment':
        from .artifact_task_amendment_v1 import amendment_original_ref_v1, require_amendment_history_v1
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from .ingress_artifact_task_scope_v1 import require_task_scope_archive_v1, ArtifactTaskObjectiveV1
        from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
        producer = read_adopted_domain_operation_v1(db, ns, op)
        if producer is None:
            raise DomainProductionErasureHold('amendment lost actual task CAS')
        p = producer['payload']['provenance']
        root = draft_from_wire_v1(p['draft_root_capability'], DraftRootCapabilityV1)
        scope = require_task_scope_archive_v1(db, namespace=ns, root=root, producer=producer)
        objective = decode_typed_production_value_v1(p['artifact_task_objective'], ArtifactTaskObjectiveV1)
        if value.namespace != ns or ref != amendment_original_ref_v1(value):
            raise DomainProductionErasureHold('task amendment crossed original namespace or ref')
        require_amendment_history_v1(db, value=value, producer=producer, scope=scope, objective=objective)
        return None
    if kind in {'artifact_task_scope', 'artifact_task_objective'}:
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from .ingress_artifact_task_scope_v1 import require_task_scope_archive_v1, task_scope_ref_v1, task_objective_ref_v1
        producer = read_adopted_domain_operation_v1(db, ns, op)
        if producer is None:
            raise DomainProductionErasureHold('task original lost its actual W01 producer')
        from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
        root = draft_from_wire_v1(producer['payload']['provenance']['draft_root_capability'], DraftRootCapabilityV1)
        scope = require_task_scope_archive_v1(db, namespace=ns, root=root, producer=producer)
        if kind == 'artifact_task_scope' and (ref != task_scope_ref_v1(root.registration_ref) or value != scope) or (kind == 'artifact_task_objective' and ref != task_objective_ref_v1(value)):
            raise DomainProductionErasureHold('task original identity differs from actual producer')
        return None
    if kind == 'c1_task_intent':
        from .c1_artifact_task_intent_v1 import validate_c1_task_original_row_v1, require_c1_task_original_history_v1
        validate_c1_task_original_row_v1(namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw)
        require_c1_task_original_history_v1(db, value)
        return None
    if kind == FOREGROUND_CAUSE_KIND:
        validate_foreground_post_c02_cause_row_v1(namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw)
        require_foreground_post_c02_cause_history_v1(db, value)
        require_foreground_cause_outbox_original_v1(db, namespace=ns, producer_operation_id=op, original_ref=ref, original_digest=digest, event_kind='foreground_post_c02_cause_available')
        return None
    if kind == 'prepared':
        admission = originals.get((ns, 'action_admission', value.admission_ref))
        if admission is None or admission[0] != value.prepare_operation_id or admission[3] != value.admission_digest or (admission[1].binding_digest != value.binding.digest) or (admission[1].plan_digest != value.binding.plan_digest):
            raise DomainProductionErasureHold('Life prepared body lost its exact signed action admission')
    if kind == 'experience':
        terminal = life_from_wire_v1(raw['terminal'], D11LifeTerminalV1)
        adopted = originals.get((ns, 'adopted_life', terminal.binding.artifact_ref))
        if adopted is None or adopted[0] != raw['adopted_operation_id'] or adopted[2]['terminal'] != raw['terminal']:
            raise DomainProductionErasureHold('Life internal experience lost its genuine terminal adoption')
        history = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND event_id=? LIMIT 2', (raw['source_ref'], op)).fetchmany(2)
        if len(history) != 1 or history[0][1] != 1 or canonical_digest(_json(history[0][0])) != raw['source_digest']:
            raise DomainProductionErasureHold('Life internal experience lacks its real D10 source history')
        source = _json(history[0][0])
        if source['source_kind'] != 'internal' or source['assertion_status'] != 'confirmed' or source['text'] != canonical_serialize(raw['experience']) or (source['purposes'] != ['context', 'consolidation']):
            raise DomainProductionErasureHold('Life activity Source facts or permission differ')
        if adopted[2]['schema'] == 'd11.adopted-life-original.v4':
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            from .d10_life_progress_provenance_v1 import validate_life_progress_provenance_history_v1, life_experience_access_dependencies_v1
            from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
            production = read_adopted_domain_operation_v1(db, ns, op)
            prepared = originals.get((ns, 'prepared', terminal.binding.prepared_original_ref))
            if production is None or prepared is None:
                raise DomainProductionErasureHold('Life progress lacks its actual historical production/prepared original')
            progress = decode_typed_production_value_v1(production['payload']['provenance']['actual_progress'], LifeProgressHeadV1)
            validate_life_progress_provenance_history_v1(db, prepared=prepared[1], terminal=terminal, progress=progress, production=production)
            from ..memory_types import SourceRecord, source_key, access_key
            record = SourceRecord.from_dict(source)
            parent = AtomKey.from_token(prepared[1].plan.input_source.ref)
            if record.parent_source_ids != (parent.owner.subject,) or raw['source_ref'] != source_key(*ns.as_tuple, record.source_id).token:
                raise DomainProductionErasureHold('Life historical source lost its exact typed parent')
            access = access_key(*ns.as_tuple, record.source_id)
            access_row = db.execute('SELECT value,valid,event_id,dependencies FROM graph_history WHERE token=? AND revision=1', (access.token,)).fetchone()
            dependencies = life_experience_access_dependencies_v1(prepared[1], AtomKey.from_token(raw['source_ref']))
            from .d11_life_fact_provenance_v1 import life_current_fact_reads_v1
            current_reads = life_current_fact_reads_v1(prepared[1])
            expected_deps = tuple(sorted(((key.token, 1 if key.type_name in {'memory.source', 'd11.life_fact_eligibility.v1'} and key.token not in {row.ref for row in current_reads} else next((row.revision for row in current_reads if row.ref == key.token))) for key in dependencies)))
            expected_access = canonical_serialize({'source_id': record.source_id, 'audiences': list(record.audiences), 'purposes': list(record.purposes), 'status': 'active', 'recorded_at': record.recorded_at})
            if not any((v.key == access and v.revision == 1 for v in production['receipt'].write_versions)) or access_row is None or access_row[:3] != (expected_access, 1, op) or (tuple(sorted((tuple(pair) for pair in json.loads(access_row[3])))) != expected_deps) or (db.execute('SELECT dependencies FROM graph_history WHERE token=? AND revision=1 AND event_id=?', (raw['source_ref'], op)).fetchone() != ('[]',)):
                raise DomainProductionErasureHold('Life historical experience source/access ownership differs')
        return None
    if kind not in {'adoption_bridge', 'adoption_receipt', 'historical_accounting_gate', 'historical_accounting_receipt'}:
        return None
    adoption = kind.startswith('adoption_')
    gate = originals.get((ns, 'adoption_bridge' if adoption else 'historical_accounting_gate', ref))
    receipt = originals.get((ns, 'adoption_receipt' if adoption else 'historical_accounting_receipt', ref))
    if gate is None or receipt is None or gate[0] != op or (receipt[0] != op):
        raise DomainProductionErasureHold('Life actual gate and receipt lost same-operation join')
    if kind.endswith('receipt'):
        return None
    accounting = originals.get((ns, 'accounting_prepared', life_accounting_original_ref_v1(value.binding)))
    if accounting is None or accounting[1].binding != value.binding or accounting[1].prepared_digest != value.prepared_digest:
        raise DomainProductionErasureHold('Life gate lost its signed content-free preparation')
    if adoption:
        adopted = originals.get((ns, 'adopted_life', value.binding.artifact_ref))
        if adopted is None or adopted[0] != op:
            raise DomainProductionErasureHold('Life adoption lost actual signed adopted original')
        from ..authority_service.d11_life_bridge_v1 import D11DraftSelfAdoptionBridgeV2
        if type(value) is D11DraftSelfAdoptionBridgeV2:
            validate_draft_self_life_original_join_v1(db, gate=value, originals=originals, operation_id=op)
        validate_life_adoption_composite_v1(db, gate=value, result=receipt[2], adopted=adopted[1])
    else:
        if accounting[3] != value.accounting_original_digest:
            raise DomainProductionErasureHold('Life historical accounting cost commitment differs')
        validate_life_historical_accounting_composite_v1(db, gate=value, result=receipt[2])


def _legacy_unique_prepared_row_v2(originals,namespace,kind,call_id):
    matches=(row for (space,part,ref),row in originals.items() if space==namespace and part==kind and row[1].call_id==call_id)
    first=next(matches,None)
    if next(matches,None) is not None:
        raise DomainProductionErasureHold('actual C4 call has ambiguous prepared parent buckets')
    return first


def _optional_one_prepared_value_v2(row): return () if row is None else (row[1],)
def _optional_one_prepared_row_v2(row): return () if row is None else (row,)


def validate_c4_original_join_row_v2(db, *, ns, kind, ref, op, value, raw, digest, read_original, read_prepared_by_call):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
    from .natural_reply_job_v2 import _request_from_wire
    from .model_cost_settlement import original_model_cost_operation_id_v1
    originals = _LifeOriginalPointLookupV2(read_original)
    if kind in {"c4_no_dispatch", "c4_phase_no_dispatch"}:
        validate_c4_no_dispatch_original_joins_v1(db, namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw)
        return None
    if kind not in C4_KINDS:
        return None
    validate_c4_life_original_row_v1(kind, namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw)
    if kind == 'c4_paid':
        _validate_c4_paid_member_v1(db, ns, value)
        selected = _optional_one_prepared_value_v2(read_prepared_by_call(ns, 'c4_prepared', value.call_id))
        if len(selected) > 1:
            raise DomainProductionErasureHold('C4 paid original has ambiguous prepared parent buckets')
        if selected:
            _require_c4_paid_parent_bucket_v1(db, ns, selected[0], value)
        return None
    if kind == 'c4_frozen':
        prepared = originals.get((ns, 'c4_prepared', artifact_draft_model_ids_v1(value.selector)['job']))
        if prepared is None or prepared[1].frozen_ref != ref or prepared[1].frozen_digest != value.digest:
            raise DomainProductionErasureHold('C4 frozen body lacks actual same-task prepared seal')
        return None
    if kind == 'c4_call':
        matches = _optional_one_prepared_row_v2(read_prepared_by_call(ns, 'c4_prepared', value.call_id))
        if len(matches) != 1:
            raise DomainProductionErasureHold('C4 call lacks unique actual prepared original')
        prepared = matches[0][1]
    else:
        selector = value.request.selector if kind == 'c4_result' else value.selector if kind in {'c4_prepared', 'c4_adopted'} else None
        if selector is None:
            request = _request_from_wire(value.request_json)
            from ..model_broker.artifact_draft_v1 import artifact_draft_from_wire_v1, ArtifactDraftInputV1
            selector = artifact_draft_from_wire_v1(dict(request.payload)['input'], ArtifactDraftInputV1).selector
        selected = originals.get((ns, 'c4_prepared', artifact_draft_model_ids_v1(selector)['job']))
        if selected is None:
            raise DomainProductionErasureHold('C4 original lost actual prepared predecessor')
        prepared = selected[1]
    ids = artifact_draft_model_ids_v1(prepared.selector)
    frozen_row = originals.get((ns, 'c4_frozen', prepared.frozen_ref))
    if frozen_row is None or frozen_row[1].digest != prepared.frozen_digest:
        raise DomainProductionErasureHold('C4 original lost exact complete frozen input')
    frozen = frozen_row[1]
    if kind == 'c4_prepared':
        if (prepared.actor_ref, prepared.selector, prepared.frozen_digest) != (frozen.current_self_ref, frozen.selector, frozen.digest):
            raise DomainProductionErasureHold('C4 prepared crossed actual frozen self/task')
        _validate_c4_prepared_history_v1(db, ns, prepared, frozen)
        return None
    request_row = originals.get((ns, 'c4_request', ids['request']))
    if request_row is None or request_row[1].prepared_digest != prepared.digest:
        raise DomainProductionErasureHold('C4 original lost actual acquired model request')
    request = _request_from_wire(request_row[1].request_json)
    if dict(request.payload) != frozen.wire or request.envelope.authority.actor != prepared.worker_subject or (request.call_id, request.identity.operation_id) != (prepared.call_id, prepared.acquire_operation_id):
        raise DomainProductionErasureHold('C4 acquired request changed frozen input/actual TLS worker')
    if kind == 'c4_request':
        return None
    call_row = originals.get((ns, 'c4_call', prepared.call_id))
    if call_row is None:
        raise DomainProductionErasureHold('C4 original lost actual sealed Core model call')
    intent = call_row[1]
    if (intent.binding_digest, intent.request_digest, intent.call_id, intent.job_id, intent.subject, intent.budget_reservation_operation_id, intent.budget_reservation_digest) != (prepared.digest, request.digest, prepared.call_id, prepared.job_id, prepared.worker_subject, prepared.operation_id, prepared.reservation_digest):
        raise DomainProductionErasureHold('C4 Core call changed prepared/request/once reservation')
    if kind == 'c4_call':
        return None
    paid_row = originals.get((ns, 'c4_paid', ids['paid']))
    if paid_row is None:
        raise DomainProductionErasureHold('C4 result/adoption lacks actual financial original')
    paid = paid_row[1]
    _require_c4_paid_parent_bucket_v1(db, ns, prepared, paid)
    result_row = originals.get((ns, 'c4_result', ids['result']))
    if result_row is None:
        raise DomainProductionErasureHold('C4 adoption lost actual paired result original')
    result = result_row[1]
    if (result.request.binding_digest, result.request.model_request_digest, result.terminal_receipt.call_id, canonical_digest(asdict(result.terminal_receipt))) != (prepared.digest, request.digest, prepared.call_id, paid.terminal_receipt_digest) or paid.operation_id != original_model_cost_operation_id_v1(ns, prepared.call_id):
        raise DomainProductionErasureHold('C4 result/terminal differs from actual once financial original')
    if kind == 'c4_result':
        return None
    _validate_c4_content_original_joins_v1(db, ns, value, prepared, frozen, paid_row, result_row, originals)


def validate_c4_phase_original_join_row_v3(db, *, ns, kind, ref, op, value, raw, digest, read_original, read_prepared_by_call):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2, artifact_draft_from_wire_v2, artifact_draft_input_from_wire_v2
    from .natural_reply_job_v2 import _request_from_wire
    from .model_cost_settlement import original_model_cost_operation_id_v1
    originals = _LifeOriginalPointLookupV2(read_original)
    if kind in {"c4_no_dispatch", "c4_phase_no_dispatch"}:
        validate_c4_no_dispatch_original_joins_v1(db, namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw)
        return None
    if kind not in C4_PHASE_KINDS:
        return None
    validate_c4_phase_life_original_row_v2(kind, namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw)
    if kind == 'c4_phase_paid':
        _validate_c4_paid_member_v1(db, ns, value)
        parents = _optional_one_prepared_value_v2(read_prepared_by_call(ns, 'c4_phase_prepared', value.call_id))
        if len(parents) > 1:
            raise DomainProductionErasureHold('C4 phase paid original has ambiguous parent reservations')
        if parents:
            _require_c4_paid_parent_bucket_v1(db, ns, parents[0], value)
        return None
    if kind == 'c4_phase_frozen':
        from ..model_broker.artifact_draft_v1 import ArtifactDraftInputV3
        if type(value) is ArtifactDraftInputV3:
            from .d11_artifact_draft_model_v1 import require_artifact_phase_frozen_contract_history_v3
            require_artifact_phase_frozen_contract_history_v3(db, namespace=ns, frozen=value)
        parent = originals.get((ns, 'c4_phase_prepared', artifact_draft_model_ids_v2(value.selector)['job']))
        if parent is None or (parent[1].frozen_ref, parent[1].frozen_digest) != (ref, value.digest):
            raise DomainProductionErasureHold('C4 phase frozen body has no actual prepared seal')
        return None
    if kind == 'c4_phase_verified':
        _validate_c4_phase_verified_joins_v2(db, namespace=ns, original_ref=ref, producing_operation_id=op, raw=raw, originals=originals)
        return None
    if kind == 'c4_phase_call':
        parents = _optional_one_prepared_value_v2(read_prepared_by_call(ns, 'c4_phase_prepared', value.call_id))
        if len(parents) != 1:
            raise DomainProductionErasureHold('C4 phase call has no unique actual prepared parent')
        prepared = parents[0]
    else:
        if kind == 'c4_phase_request':
            request = _request_from_wire(value.request_json)
            selector = artifact_draft_input_from_wire_v2(dict(request.payload)['input']).selector
        else:
            selector = value.request.selector if kind == 'c4_phase_result' else value.selector
        parent = originals.get((ns, 'c4_phase_prepared', artifact_draft_model_ids_v2(selector)['job']))
        if parent is None:
            raise DomainProductionErasureHold('C4 phase original lost its actual prepared predecessor')
        prepared = parent[1]
    ids = artifact_draft_model_ids_v2(prepared.selector)
    frozen_row = originals.get((ns, 'c4_phase_frozen', prepared.frozen_ref))
    if frozen_row is None or frozen_row[1].digest != prepared.frozen_digest:
        raise DomainProductionErasureHold('C4 phase original lost its exact frozen body')
    frozen = frozen_row[1]
    if kind == 'c4_phase_prepared':
        if (prepared.actor_ref, prepared.selector, prepared.frozen_digest) != (frozen.current_self_ref, frozen.selector, frozen.digest):
            raise DomainProductionErasureHold('C4 phase prepared changed frozen task/self')
        _validate_c4_prepared_history_v1(db, ns, prepared, frozen, phase=True)
        return None
    request_row = originals.get((ns, 'c4_phase_request', ids['request']))
    if request_row is None or request_row[1].prepared_digest != prepared.digest:
        raise DomainProductionErasureHold('C4 phase original lost acquired request seal')
    request = _request_from_wire(request_row[1].request_json)
    if dict(request.payload) != frozen.wire or request.envelope.authority.actor != prepared.worker_subject or (request.call_id, request.identity.operation_id) != (prepared.call_id, prepared.acquire_operation_id):
        raise DomainProductionErasureHold('C4 phase request changed frozen body/actual TLS worker')
    if kind == 'c4_phase_request':
        return None
    call_row = originals.get((ns, 'c4_phase_call', prepared.call_id))
    if call_row is None:
        raise DomainProductionErasureHold('C4 phase original lost actual sealed Core call')
    intent = call_row[1]
    if (intent.binding_digest, intent.request_digest, intent.call_id, intent.job_id, intent.subject, intent.budget_reservation_operation_id, intent.budget_reservation_digest) != (prepared.digest, request.digest, prepared.call_id, prepared.job_id, prepared.worker_subject, prepared.operation_id, prepared.reservation_digest):
        raise DomainProductionErasureHold('C4 phase call changed original request/reservation/TLS subject')
    if kind == 'c4_phase_call':
        return None
    paid_row = originals.get((ns, 'c4_phase_paid', ids['paid']))
    if paid_row is None:
        raise DomainProductionErasureHold('C4 phase result has no actual paid original')
    paid = paid_row[1]
    _validate_c4_paid_member_v1(db, ns, paid)
    _require_c4_paid_parent_bucket_v1(db, ns, prepared, paid)
    result_row = originals.get((ns, 'c4_phase_result', ids['result']))
    if result_row is None:
        raise DomainProductionErasureHold('C4 phase content lost its actual paired result')
    result = result_row[1]
    if (result.request.selector, result.request.binding_digest, result.request.model_request_digest, result.terminal_receipt.call_id, canonical_digest(asdict(result.terminal_receipt))) != (prepared.selector, prepared.digest, request.digest, prepared.call_id, paid.terminal_receipt_digest) or paid.operation_id != original_model_cost_operation_id_v1(ns, prepared.call_id):
        raise DomainProductionErasureHold('C4 phase result lost actual once financial terminal')
    if kind == 'c4_phase_adopted':
        _validate_c4_content_original_joins_v1(db, ns, value, prepared, frozen, paid_row, result_row, originals, phase=True)


def validate_c4_no_dispatch_original_joins_v1(db, *, namespace, original_ref, producing_operation_id, raw, issuer=None):
    from ..domains.d01.production_operations_v1 import plain_v1
    from .d11_artifact_draft_model_v1 import decode_artifact_model_no_dispatch_v1
    from ..authority_service.v2_model_egress_contract import ModelNoDispatchWitnessV1
    from ..authority_service.v2_model_egress_wire import from_wire
    from .model_cost_settlement import original_model_cost_operation_id_v1
    from .d11_types import RuntimeCostSettlement
    from ..graph_types import AtomKey
    value = decode_artifact_model_no_dispatch_v1(raw)
    witness = from_wire(json.loads(value.witness_json), ModelNoDispatchWitnessV1)
    if issuer is not None: witness.require_signature_v1(issuer._signer)
    commit = value.cost_commit
    if (value.namespace != namespace or value.original_ref != original_ref or commit.operation_id != producing_operation_id
            or commit.operation_id != original_model_cost_operation_id_v1(namespace, commit.call_id)):
        raise ValueError("C09 no-dispatch record producer identity differs")
    cost = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1", (commit.cost_ref,)).fetchone()
    receipt = db.execute("SELECT commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, producing_operation_id)).fetchone()
    if cost is None or cost[0] != producing_operation_id or cost[2] != 1 or receipt is None or receipt[0] != commit.commit_seq:
        raise ValueError("C09 no-dispatch record lacks its real cost/CAS history")
    cost_value = RuntimeCostSettlement(**json.loads(cost[1]))
    if (cost_value.status != "settled" or cost_value.actual != {unit: 0 for unit, _ in witness.request.intent.budget_ceiling}
            or cost_value.unconfirmed or cost_value.lease_id != witness.request.intent.budget_lease_id
            or cost_value.budget_receipt_digest != commit.budget_receipt_digest
            or json.loads(receipt[1])["original_model_no_dispatch_cost"] != plain_v1(commit)):
        raise ValueError("C09 no-dispatch record lost its original exact zero budget settlement")
    history_rows = tuple(db.execute("SELECT token,value FROM graph_history WHERE event_bot=? AND event_persona=? AND event_id=?",
        (*namespace.as_tuple, producing_operation_id)))
    if len(history_rows) != 2:
        raise ValueError("C09 no-dispatch original cost/job bundle has another member set")
    job_rows = tuple((value_json,) for token, value_json in history_rows if AtomKey.from_token(token).type_name == "runtime.job")
    if len(job_rows) != 1:
        raise ValueError("C09 no-dispatch cost lacks its one same-CAS cancelled job")
    from .d11_types import RuntimeJobValue
    job_value = RuntimeJobValue(**json.loads(job_rows[0][0]))
    if (job_value.job_id != witness.request.intent.job_id or job_value.phase != "cancelled"
            or job_value.result_ref is not None or job_value.operation_id != witness.request.intent.budget_reservation_operation_id):
        raise ValueError("C09 no-dispatch cancelled job lineage differs")
    return value



def require_c4_no_dispatch_cost_original_commit_v1(db, *, namespace, operation_id):
    from .model_cost_settlement import OriginalModelNoDispatchCostCommitV1, original_model_cost_operation_id_v1
    from .d11_types import RuntimeCostSettlement, runtime_cost_settlement_key
    from .budget import BudgetReceipt
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise DomainProductionErasureHold("no-dispatch financial original needs its actual pinned namespace transaction")
    row = db.execute("SELECT activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id)).fetchone()
    if row is None: raise DomainProductionErasureHold("actual no-dispatch cost CAS absent")
    raw = _json(row[3])
    if set(raw) != {"original_model_no_dispatch_cost", "original_intent_digest", "no_dispatch_witness_digest",
            "quote_id", "quote_version", "work_kind", "accounting_attempt_id", "no_dispatch_cancellation_basis"} or raw["work_kind"] != "artifact_draft_v1":
        raise DomainProductionErasureHold("no-dispatch financial receipt has another exact ABI")
    paid = OriginalModelNoDispatchCostCommitV1(**raw["original_model_no_dispatch_cost"])
    if (paid.schema != "sylanne.d11.original-model-no-dispatch-cost-commit.v1" or paid.status != "committed"
            or paid.operation_id != operation_id or paid.commit_seq != row[2]
            or operation_id != original_model_cost_operation_id_v1(namespace, paid.call_id)
            or (paid.witness_digest, paid.quote_id, paid.quote_version) !=
                (raw["no_dispatch_witness_digest"], raw["quote_id"], raw["quote_version"])
            or paid.cost_ref != runtime_cost_settlement_key(*namespace.as_tuple, row[0], operation_id).token):
        raise DomainProductionErasureHold("no-dispatch financial original identity differs")
    event = db.execute("SELECT revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, row[0], operation_id)).fetchone()
    from ..graph_store import GraphStore
    versions = () if event is None else GraphStore._version_rows(event[0])
    if len(versions) != 2 or event[1] != paid.graph_epoch:
        raise DomainProductionErasureHold("no-dispatch financial original lost its exact cost/job CAS")
    cost_versions = tuple(v for v in versions if v.key.token == paid.cost_ref)
    job_versions = tuple(v for v in versions if v.key.type_name == "runtime.job")
    if len(cost_versions) != 1 or len(job_versions) != 1 or cost_versions[0].revision != 1:
        raise DomainProductionErasureHold("no-dispatch cost/job member set differs")
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (paid.cost_ref, cost_versions[0].revision)).fetchone()
    if history is None or history[0] != operation_id or history[2] != 1:
        raise DomainProductionErasureHold("no-dispatch actual financial history absent")
    cost = decode_typed_production_value_v1(_json(history[1]), RuntimeCostSettlement)
    receipt_row = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase='settle'",
        (cost.lease_id, cost.cost_operation_id)).fetchone()
    if receipt_row is None: raise DomainProductionErasureHold("no-dispatch original settle receipt absent")
    receipt = decode_typed_production_value_v1(_json(receipt_row[0]), BudgetReceipt)
    if ((cost.bot_id, cost.persona_id, cost.activity_id, cost.effect_id, cost.bundle_operation_id, cost.settlement_id,
            cost.budget_phase, cost.budget_operation_id, cost.status, cost.execution_revoked) !=
            (*namespace.as_tuple, row[0], row[1], operation_id, operation_id, "settle", cost.cost_operation_id, "settled", True)
            or receipt.status != "settled" or receipt.operation_id != cost.cost_operation_id or receipt.lease_id != cost.lease_id
            or canonical_digest(_json(receipt_row[0])) != paid.budget_receipt_digest
            or cost.budget_receipt_digest != paid.budget_receipt_digest or cost.unconfirmed or cost.prior_unknown_ref is not None
            or not cost.actual or set(cost.actual) != set(cost.ceiling) or any(cost.actual.values())
            or not set(cost.actual) <= {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}):
        raise DomainProductionErasureHold("no-dispatch cost is not the exact original zero model settlement")
    return paid

