"""Installed current reader for the finite D10 structured-experience lane."""
from datetime import datetime
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d03.context import WorldEvent
from ..domains.d03.self_perspective import SelfIdentityMapping, SelfPerspective, self_mapping_key
from ..domains.d06.structured_experience_v1 import (
    EncodeCurrentStructuredExperienceRequestV1, StructuredExperienceInputsV1,
    compile_current_structured_experience_v1, structured_experience_output_keys_v1,
    verify_d06_structured_experience_stage_v1,
)
from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
from ..domains.d10.offline_interval import OfflineSimulatedOccurrenceV1
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..memory_types import SourceRecord
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1, raw_head_value_v1, waiting_stage_v1
from .issuers import D11BudgetJobIssuer


class InstalledD06StructuredExperienceReadersV1:
    def __init__(self, *, issuer, resource_issuer, body_quote_authority):
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError("structured memory requires this installation's actual D11 issuer")
        self.issuer = issuer
        self.resource_issuer = resource_issuer
        self.body_quote_authority = body_quote_authority

    def read_current(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        ns = frame.envelope.authority.namespace
        adopted = read_adopted_domain_operation_v1(db, ns, request.causal_operation_id)
        if adopted is None or adopted["domain"] != "d10" or adopted["operation_kind"] not in {"advance_life", "advance_offline"}:
            raise MissingProductionOriginalV1("actual_adopted_d10_internal_experience_bundle")
        source_atom = read.head(db, request.source_ref, required=True)
        writes = tuple(version for version in adopted["receipt"].write_versions if version.key == source_atom.key)
        history = db.execute("SELECT event_bot,event_persona,event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (source_atom.key.token, source_atom.revision)).fetchone()
        if (len(writes) != 1 or writes[0].revision != source_atom.revision or history is None
                or history[:3] != (*ns.as_tuple, request.causal_operation_id) or history[4] != 1
                or json.loads(history[3]) != source_atom.value):
            raise ValueError("structured source is not an actual immutable member of the adopted D10 composite")
        source = SourceRecord.from_dict(source_atom.value)
        family = read.source_family(db, (request.source_ref,), purpose="consolidation")
        actual_life = (adopted["operation_kind"] == "advance_life"
            and source.source_kind == "internal" and source.assertion_status == "confirmed")
        if source.speaker_id != "persona:" + ns.persona_id or (source.assertion_status != "unknown" and not actual_life):
            raise ValueError("structured internal source cannot claim a new external fact or another actor")
        mapping_atom = read.head(db, self_mapping_key(ns), required=True)
        mapping = decode_typed_production_value_v1(mapping_atom.value, SelfIdentityMapping)
        active = tuple(atom for atom in frame.snapshot.atoms if atom.valid and atom.key.type_name == "d01.persona_activation.v1"
            and atom.value["head_id"] == mapping.role_head_id and atom.value["graph_incarnation"] == mapping.graph_incarnation)
        if mapping.status != "active" or mapping.persona_ref != source.speaker_id or len(active) != 1:
            raise MissingProductionOriginalV1("actual_current_certified_role_self_mapping")
        certification = read.original(mapping.certification_ref, kind="d03.current_self_identity")
        perspectives = tuple(atom for atom in read.complete_inventory(db, "d03.self_perspective.v1") if atom.valid
            and atom.value["identity_mapping_ref"] == mapping_atom.key.token
            and atom.value["role_head_id"] == mapping.role_head_id
            and atom.value["self_entity_ref"] == mapping.self_entity_ref)
        if len(perspectives) != 1:
            raise MissingProductionOriginalV1("unique_actual_structured_experience_scene_perspective")
        perspective = decode_typed_production_value_v1(perspectives[0].value, SelfPerspective)
        event_key, memory_key = structured_experience_output_keys_v1(ns, request.source_ref)
        if adopted["operation_kind"] == "advance_life":
            progress = decode_typed_production_value_v1(adopted["payload"]["provenance"]["actual_progress"], LifeProgressHeadV1)
            from ..graph_types import Owner
            progress_key = AtomKey(Owner("activity", *ns.as_tuple, progress.activity_id), "d10.life_progress.v1", progress.effect_id)
            progress_versions = tuple(version for version in adopted["receipt"].write_versions if version.key == progress_key)
            progress_history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
                (progress_key.token, progress_versions[0].revision)).fetchone() if len(progress_versions) == 1 else None
            if (progress_history is None or progress_history[0] != request.causal_operation_id or progress_history[2] != 1
                    or json.loads(progress_history[1]) != plain_v1(progress)):
                raise ValueError("structured life source has no exact actual D10 progress member")
            if actual_life:
                from .d06_life_activity_lineage_v1 import qualify_current_life_activity_v1
                activity = qualify_current_life_activity_v1(db, frame=frame, source_atom=source_atom,
                    adopted=adopted, progress=progress, installed_readers=self)
                from .d06_internal_life_episode_v2 import compile_internal_life_episode_v2
                return compile_internal_life_episode_v2(db, frame=frame, request=request,
                    activity=activity, mapping=mapping, perspective=perspective,
                    mapping_ref=mapping_atom.key.token, perspective_ref=perspectives[0].key.token)
            else:
                expected = "d10-life-experience:" + canonical_digest((progress.activity_id, progress.effect_id))[:48]
                if source.source_id != expected or source.source_kind != ("simulated" if progress.reality == "role_simulation" else "internal"):
                    raise ValueError("life experience source identity/reality differs from the actual causal result")
                parents = tuple(family.get(ref) for ref in progress.source_refs)
                if any(parent is None for parent in parents) or len(parents) != 2:
                    raise MissingProductionOriginalV1("actual_life_start_end_source_permission_closure")
                start, end = parents[0].occurred_at, parents[1].occurred_at
                reality = "simulated" if progress.reality == "role_simulation" else "host_observed"
            kind = "d10_internal_life_step_completed"
        else:
            outputs = adopted["payload"]["provenance"]["observed_prefix"]["outputs"]
            occurrences = tuple(decode_typed_production_value_v1(value, OfflineSimulatedOccurrenceV1) for value in outputs)
            matching = tuple(item for item in occurrences if "d10-offline-experience:" + canonical_digest(item.occurrence_id)[:48] == source.source_id)
            if len(matching) != 1 or source.source_kind != "simulated" or canonical_serialize(plain_v1(matching[0])) != source.text:
                raise ValueError("offline experience is not the exact adopted simulated occurrence")
            from ..graph_types import Owner
            occurrence_key = AtomKey(Owner("activity", *ns.as_tuple, adopted["receipt"].activity_id),
                "d10.offline_simulated_occurrence.v1", matching[0].occurrence_id)
            occurrence_versions = tuple(version for version in adopted["receipt"].write_versions if version.key == occurrence_key)
            occurrence_history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
                (occurrence_key.token, occurrence_versions[0].revision)).fetchone() if len(occurrence_versions) == 1 else None
            if (occurrence_history is None or occurrence_history[0] != request.causal_operation_id or occurrence_history[2] != 1
                    or json.loads(occurrence_history[1]) != {**plain_v1(matching[0]), "schema": "d10.offline_simulated_occurrence.v1"}):
                raise ValueError("structured offline source has no exact actual D10 occurrence member")
            start = end = datetime.fromisoformat(matching[0].scheduled_at_utc.replace("Z", "+00:00")).timestamp()
            reality, kind = "simulated", "d10_offline_simulated_occurrence"
        if start is None or end is None or start > end or end > frame.now_utc:
            raise MissingProductionOriginalV1("actual_bounded_structured_experience_occurrence_interval")
        event = WorldEvent(event_key.owner.subject, kind, ((mapping.self_entity_ref, "internal_role_actor"),),
            start, end, source.recorded_at, perspective.scene_ref, (request.source_ref,), reality)
        prior_event, prior_episode = read.head(db, event_key), read.head(db, memory_key)
        episode = {"episode_id": memory_key.owner.subject, "source_refs": [request.source_ref], "event_ref": event_key.token}
        duplicate = bool(prior_event.revision or prior_episode.revision)
        if duplicate and (not prior_event.valid or not prior_episode.valid or prior_event.value != plain_v1(event)
                or prior_episode.value != episode):
            raise ValueError("structured experience identity already has another or incomplete adopted episode/event")
        causal = read.original(request.causal_operation_id, digest=adopted["original_digest"])
        return StructuredExperienceInputsV1(source, event, causal, certification, mapping_atom.key.token, perspectives[0].key.token, duplicate)


def read_plan_current_d06_structured_experience_v1(db, *, namespace, activity_id, operation_kind, request):
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or operation_kind != "encode_structured_experience" or type(request) is not EncodeCurrentStructuredExperienceRequestV1):
        raise ValueError("unregistered exact structured memory read plan")
    keys = [owner_grant_key(*namespace.as_tuple), self_mapping_key(namespace), AtomKey.from_token(request.source_ref),
        *structured_experience_output_keys_v1(namespace, request.source_ref)]
    originals = [request.causal_operation_id, request.source_ref]
    mapping = raw_head_value_v1(db, namespace, self_mapping_key(namespace))
    if mapping:
        originals.append(mapping["certification_ref"])
    from .d06_life_activity_lineage_v1 import life_activity_read_inputs_v1
    life_keys, life_originals = life_activity_read_inputs_v1(db, namespace, request.source_ref)
    keys.extend(life_keys)
    originals.extend(life_originals)
    if life_keys:
        from .d06_internal_life_episode_v2 import internal_life_episode_keys_v2
        keys.extend(internal_life_episode_keys_v2(namespace, request.source_ref))
    return production_read_plan_v1(("d01.persona_activation.v1", "d03.self_perspective.v1"), keys,
        (request.source_ref,), originals)


def stage_encode_current_structured_experience_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD06StructuredExperienceReadersV1:
        raise TypeError("exact installed structured memory readers required")
    try:
        inputs = installed_readers.read_current(db, frame, request)
        from .d06_internal_life_episode_v2 import InternalLifeEpisodeStageV2
        if type(inputs) is InternalLifeEpisodeStageV2:
            return inputs
        stage = compile_current_structured_experience_v1(frame, request, inputs)
    except MissingProductionOriginalV1 as missing:
        stage = waiting_stage_v1(frame, "d06", "encode_structured_experience", request, missing)
    return verify_d06_structured_experience_stage_v1(stage)
