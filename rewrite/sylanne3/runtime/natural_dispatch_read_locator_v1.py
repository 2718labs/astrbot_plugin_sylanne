"""Pure metadata projection of actual typed Natural producer inputs.

The result selects originals. It issues no locator witness, Source grant, Work,
deadline, or persisted record. The actual W01 producer must bind the returned
recipe to its original EOFs, selected-history provenance, and committed bundle.
"""
from __future__ import annotations

from ..graph_types import AtomKey, GraphReceipt
from ..memory_types import source_key
from ..runtime_contracts import DomainBundle, VersionedRef
from .dispatch_admission import DispatchAdmissionReceiptV1, namespace_of

RECIPE_SCHEMA_V1 = "sylanne.natural_dispatch_read_locator_recipe.v1"


class NaturalDispatchReadLocatorHold(RuntimeError):
    """The actual producer inputs do not supply this closed metadata recipe."""


def _ref(value):
    return {"ref": value.ref, "version": value.version}


def _refs(values):
    return [_ref(value) for value in values]


def _source_refs(namespace, values):
    """Filter Source tokens; retain other typed dependencies in evidence fields."""
    result = {}
    for value in values:
        try:
            key = AtomKey.from_token(value.ref)
        except (TypeError, ValueError):
            continue
        if key.type_name != "memory.source":
            continue
        if key != source_key(*namespace.as_tuple, key.owner.subject or "") or value.version < 1:
            raise NaturalDispatchReadLocatorHold("noncanonical or nonpositive Source locator")
        previous = result.setdefault(value.ref, value)
        if previous.version != value.version:
            raise NaturalDispatchReadLocatorHold("one selected Source has conflicting original versions")
    return tuple(result.values())


def _source_version(namespace, ref, versions):
    matches = tuple(value for value in versions if value.key.token == ref)
    if len(matches) != 1:
        raise NaturalDispatchReadLocatorHold("actual original Source version is absent or ambiguous")
    value = VersionedRef(ref, matches[0].revision)
    if _source_refs(namespace, (value,)) != (value,):
        raise NaturalDispatchReadLocatorHold("actual original root is not a canonical Source")
    return value


def _part_metadata(part):
    return {
        "kind": part.kind, "ref": _ref(part.ref),
        "dependencies": _refs(part.dependencies), "audience_ref": _ref(part.audience_ref),
        "access_ref": None if part.access_ref is None else _ref(part.access_ref),
        "expires_at_utc": part.expires_at_utc,
    }


def _selection_metadata(selection, multiple_blocks):
    result = {
        "schema": selection.schema, "window_digest": selection.window_digest,
        "order_watermark": selection.order_watermark,
        "coverage": [list(row) for row in selection.coverage],
        "gaps": [list(row) for row in selection.gaps],
        "source_dependencies": _refs(selection.source_dependencies),
        "scene_ref": _ref(selection.scene_ref),
        "audience_ref": _ref(selection.audience_ref),
        "conversation_ref": selection.conversation_ref,
        "expires_at_utc": selection.expires_at_utc,
        "access_epoch": selection.access_epoch, "deletion_epoch": selection.deletion_epoch,
        "activation_generation": selection.activation_generation,
        "raw_turn_refs": _refs(selection.raw_turn_refs),
        "selected_slice_digest": selection.selected_slice_digest,
        "policy_ref": selection.policy_ref, "policy_digest": selection.policy_digest,
    }
    if multiple_blocks:
        result.update(
            block_refs=_refs(selection.block_refs),
            page_cursors=[list(row) for row in selection.page_cursors],
            collection_snapshot_commitment=selection.collection_snapshot_commitment,
        )
    else:
        result["block_ref"] = None if selection.block_ref is None else _ref(selection.block_ref)
    return result


def _natural_frozen_profile_v1(generation):
    from .natural_reply_job_v2 import SavedNaturalPreparationV2
    from ..model_broker.natural_reply import FrozenNaturalReplyRequestV2, NaturalReplyInputV2
    from ..model_broker.natural_reply_history_v3 import FrozenNaturalReplyRequestV3, NaturalReplyInputV3
    from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4, NaturalReplyInputV4
    from ..model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6, NaturalReplyInputV6
    from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7, NaturalReplyInputV7
    from ..runtime_contracts import NaturalReplyGenerationOriginalSealV2
    from .natural_original_v3 import NaturalReplyGenerationOriginalSealV3
    from .natural_original_v4 import NaturalReplyGenerationOriginalSealV4
    from .natural_original_v6 import NaturalReplyGenerationOriginalSealV6
    from .natural_original_v7 import NaturalReplyGenerationOriginalSealV7

    if (type(generation) is not SavedNaturalPreparationV2 or generation.stage != "generation"
            or generation.state != "terminal"):
        raise NaturalDispatchReadLocatorHold("actual committed Natural producer inputs required")
    frozen = generation.frozen
    frozen_type = type(frozen)
    profiles = {
        FrozenNaturalReplyRequestV2: (NaturalReplyInputV2, NaturalReplyGenerationOriginalSealV2, "v2"),
        FrozenNaturalReplyRequestV3: (NaturalReplyInputV3, NaturalReplyGenerationOriginalSealV3, "v3"),
        FrozenNaturalReplyRequestV4: (NaturalReplyInputV4, NaturalReplyGenerationOriginalSealV4, "v4"),
        FrozenNaturalReplyRequestV6: (NaturalReplyInputV6, NaturalReplyGenerationOriginalSealV6, "v6"),
        FrozenNaturalReplyRequestV7: (NaturalReplyInputV7, NaturalReplyGenerationOriginalSealV7, "v7"),
    }
    if frozen_type not in profiles:
        raise NaturalDispatchReadLocatorHold("unsupported exact Natural frozen type")
    input_type, seal_type, version = profiles[frozen_type]
    input = frozen.input
    seal = generation.seal
    if type(input) is not input_type or type(seal) is not seal_type:
        raise NaturalDispatchReadLocatorHold("Natural frozen input/seal exact types differ")
    if version != "v2":
        pairs = {
            "v3": (("sylanne.d09.frozen_natural_request.v3", "sylanne.d09.context_reply_input.v3"),),
            "v4": (
                ("sylanne.d09.frozen_natural_request.v4", "sylanne.d09.context_reply_input.v4"),
                ("sylanne.d09.frozen_natural_request.v5", "sylanne.d09.context_reply_input.v5"),
            ),
            "v6": (("sylanne.d09.frozen_natural_request.v6", "sylanne.d09.context_reply_input.v6"),),
            "v7": (("sylanne.d09.frozen_natural_request.v7", "sylanne.d09.context_reply_input.v7"),),
        }
        if (frozen.schema, input.schema) not in pairs[version]:
            raise NaturalDispatchReadLocatorHold("unsupported explicit Natural schema pair")
        version = frozen.schema.rsplit(".", 1)[1]
    elif input.stable_history:
        raise NaturalDispatchReadLocatorHold(
            "V2 stable history has no selected-history lineage commitment; actual producer proof required"
        )

    if (seal.schema != "sylanne.d09.natural_generation_seal." + version
            or seal.template_version != "sylanne.d09.context_reply_input." + version):
        raise NaturalDispatchReadLocatorHold("Natural frozen/schema/template original pair differs")

    return frozen, frozen_type, input, seal, version


def project_natural_dispatch_frozen_metadata_v1(generation, *, admission):
    """Pure metadata of the exact saved input; supplies no Source or Work grant."""
    frozen, frozen_type, input, seal, version = _natural_frozen_profile_v1(generation)
    from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4
    from ..model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6
    from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7
    if type(admission) is not DispatchAdmissionReceiptV1:
        raise NaturalDispatchReadLocatorHold("actual typed admission required for original audience")
    value=admission.admission
    plan=input.plan
    namespace=plan.namespace
    if (namespace_of(value)!=namespace or value.audience!=(plan.audience_id,)
            or value.scene_ref!=plan.scene_id or value.destination_ref!=plan.audience_id):
        raise NaturalDispatchReadLocatorHold("saved Natural metadata audience/scene differs")
    ingress = _source_version(namespace, seal.source_ref, generation.read_versions)
    if input.question.ref != ingress:
        raise NaturalDispatchReadLocatorHold("actual question is not its generation ingress Source")
    groups = []

    def group(name, refs, *, purpose="expression", profile="material_expression_256", index=None):
        sources = _source_refs(namespace, refs)
        groups.append({
            "group": name, "index": index, "purpose": purpose, "audience": list(value.audience),
            "source_versions": _refs(sources),
            "source_walk_profile": profile,
        })

    group("generation_ingress", (ingress,), purpose="context", profile="dispatch_context_32")
    group("question", (input.question.ref, *input.question.dependencies))
    unit_metadata = []
    d06_sources = set()
    d06_versions = {}
    for index, unit in enumerate(plan.units):
        if unit.purpose != "expression" or unit.audience_ref != plan.audience_id:
            raise NaturalDispatchReadLocatorHold("actual plan unit purpose/audience differs")
        sources = _source_refs(namespace, unit.source_refs)
        if len(sources) != len(unit.source_refs):
            raise NaturalDispatchReadLocatorHold("qualified plan unit has non-Source lineage")
        group("plan_unit", unit.source_refs, profile="producer_expression_256", index=index)
        unit_metadata.append({
            "basis_id": unit.basis_id, "kind": unit.kind.value,
            "d06_claim_kind": unit.d06_claim_kind,
            "source_refs": _refs(unit.source_refs), "access_refs": _refs(unit.access_refs),
            "correction_refs": _refs(unit.correction_refs),
            "audience_ref": unit.audience_ref, "purpose": unit.purpose,
            "expires_at_utc": unit.expires_at_utc,
            "qualification_ref": None if unit.qualification_ref is None else _ref(unit.qualification_ref),
            "qualification_digest": unit.qualification_digest,
        })
        if unit.d06_claim_kind is not None:
            d06_sources.update(ref.ref for ref in unit.source_refs)
            for ref in (*unit.source_refs, *unit.access_refs, *unit.correction_refs):
                previous = d06_versions.setdefault(ref.ref, ref.version)
                if previous != ref.version:
                    raise NaturalDispatchReadLocatorHold("D06 unit closure repeats a changed version")

    stable = []
    for index, part in enumerate(input.stable_history):
        stable.append(_part_metadata(part))
        group("stable_history", part.dependencies, index=index)
    selection_metadata = None
    recent = []
    details = []
    stable_turns = []
    joins = ["saved_generation_full_original_eof", "actual_bundle_admission_four_write_commit",
             "question_current_ingress_material_expression", "each_plan_unit_actual_qualification"]
    if version != "v2":
        selection = input.history_selection
        multiple = frozen_type in (FrozenNaturalReplyRequestV6, FrozenNaturalReplyRequestV7)
        selection_metadata = _selection_metadata(selection, multiple)
        group("history_source_dependencies", selection.source_dependencies)
        joins.append("actual_selected_d13_window_policy_slice_and_dependency_originals")
        selected_blocks = selection.block_refs if multiple else (
            () if selection.block_ref is None else (selection.block_ref,)
        )
        for part in input.stable_history:
            if part.ref not in selected_blocks or not set(part.dependencies) <= set(selection.source_dependencies):
                raise NaturalDispatchReadLocatorHold("selected stable block dependency metadata differs")
        if input.stable_history:
            joins.append("each_selected_block_full_dependency_and_paid_original_join")
        for index, item in enumerate(input.recent_history):
            turn = item.turn
            recent.append({
                "sequence": turn.sequence, "source_ref": _ref(turn.source_ref),
                "access_ref": _ref(turn.access_ref), "raw_ref": _ref(turn.raw_ref),
                "audience_ref": _ref(turn.audience_ref), "conversation_ref": turn.conversation_ref,
                "trusted_utc": turn.trusted_utc, "completion_ref": _ref(item.completion_ref),
            })
            group("recent_history", (turn.source_ref, turn.access_ref, turn.raw_ref, item.completion_ref),
                  index=index)
        if frozen_type in (FrozenNaturalReplyRequestV4, FrozenNaturalReplyRequestV6, FrozenNaturalReplyRequestV7):
            for index, item in enumerate(input.detail_history):
                details.append({
                    "sequence": item.sequence, "source_ref": _ref(item.source_ref),
                    "expires_at_utc": item.expires_at_utc,
                })
                group("detail_history", (item.source_ref,), index=index)
        if frozen_type is FrozenNaturalReplyRequestV7:
            for item in input.stable_turns:
                stable_turns.append({
                    "block_index": item.block_index, "sequence": item.sequence,
                    "block_ref": _ref(input.stable_history[item.block_index].ref),
                })
            joins.append("v7_selected_block_complete_stable_timeline_original")

    return {
        "variant":version,
        "generation_parent_original_id":generation.parent_original_id,
        "generation_original_operation_id":seal.original_operation_id,
        "generation_job_id":seal.job_id,"generation_c02_operation_id":seal.c02_operation_id,
        "generation_original_header":{
            "graph_epoch":generation.graph_epoch,"access_epoch":generation.access_epoch,
            "deletion_epoch":generation.deletion_epoch,"worker_fence":generation.worker_fence,
            "state":generation.state},
        "commitments":{
            "frozen_input_digest":frozen.frozen_input_digest,
            "qualified_units_digest":frozen.qualified_units_digest,
            "model_request_digest":frozen.model_request_digest,
            "stable_prefix_digest":frozen.stable_prefix_digest,
            **({"semantic_projection_digest":frozen.semantic_projection_digest}
                if frozen_type is FrozenNaturalReplyRequestV7 else {}),
            "original_graph_guard_digest":seal.original_graph_guard_digest,
            "generation_terminal_receipt_digest":generation.terminal_receipt_digest,
            "generation_terminal_output_digest":generation.terminal_output_digest,
            "generation_typed_request_digest":generation.typed_request_digest},
        "plan":{
            "namespace":{"bot_id":namespace.bot_id,"persona_id":namespace.persona_id},
            "plan_ref":_ref(plan.plan_ref),"scene_ref":_ref(plan.scene_ref),
            "audience_ref":_ref(plan.audience_ref),"scene_id":plan.scene_id,
            "audience_id":plan.audience_id,"valid_until_utc":plan.valid_until_utc,
            "final_activity_id":plan.final_activity_id,"final_operation_id":plan.final_operation_id,
            "final_effect_id":plan.final_effect_id,"promise_grants":_refs(plan.promise_grants),
            "units":unit_metadata},
        "frozen_at_utc":input.frozen_at_utc,"expires_at_utc":input.expires_at_utc,
        "question":_part_metadata(input.question),"stable_history":stable,
        "history_selection":selection_metadata,"recent_history":recent,
        "detail_history":details,"stable_turns":stable_turns,
        "source_groups":groups,
        "expected_scoped_d06_projection":{
            "source_roots":sorted(d06_sources),
            "versions":[{"ref":ref,"version":version}for ref,version in sorted(d06_versions.items())]},
        "required_producer_joins":joins,
    }


def project_natural_dispatch_admitted_sources_v1(evidence, *, admission, original_graph_reads):
    """Derive only from actual typed candidate and actual producer event reads."""
    from .dispatch_candidate import NaturalDispatchCandidateEvidenceV2
    if type(evidence) is not NaturalDispatchCandidateEvidenceV2 or type(admission) is not DispatchAdmissionReceiptV1:
        raise NaturalDispatchReadLocatorHold("actual typed candidate/admission required")
    namespace=namespace_of(admission.admission)
    if (evidence.operation_id,evidence.effect_id)!=(admission.admission.operation_id,admission.admission.effect_id):
        raise NaturalDispatchReadLocatorHold("actual admitted Source selector identity differs")
    refs=tuple(_source_version(namespace,ref,original_graph_reads)for ref in evidence.source_refs)
    return {"group":"admitted_action","index":None,"purpose":"expression",
        "audience":list(admission.admission.audience),"source_versions":_refs(refs),
        "source_walk_profile":"dispatch_expression_32"}


def extract_natural_dispatch_read_locator_recipe_v1(
    generation: SavedNaturalPreparationV2, *,
    evidence: NaturalDispatchCandidateEvidenceV2,
    admission: DispatchAdmissionReceiptV1,
    bundle: DomainBundle,
    graph_receipt: GraphReceipt,
):
    """Project only metadata already present in the actual producer objects.

    Call only from the actual Natural admission/outbox W01 producer. Typed input
    alone is not proof: the caller must consume its private same-transaction
    producer witness and selected-history originals before issuing a locator.
    No caller-supplied roots or purpose override is accepted.
    """
    from .dispatch_candidate import NaturalDispatchCandidateEvidenceV2
    frozen, frozen_type, input, seal, version = _natural_frozen_profile_v1(generation)
    if (type(evidence) is not NaturalDispatchCandidateEvidenceV2
            or type(admission) is not DispatchAdmissionReceiptV1
            or type(bundle) is not DomainBundle or type(graph_receipt) is not GraphReceipt
            or graph_receipt.status != "committed"):
        raise NaturalDispatchReadLocatorHold("actual committed Natural producer inputs required")
    plan = input.plan
    namespace = plan.namespace
    identity = bundle.envelope.identity
    value = admission.admission
    if (namespace != seal.namespace or namespace != bundle.envelope.authority.namespace
            or namespace_of(value) != namespace
            or identity.activity_id != plan.final_activity_id
            or (value.activity_id, value.operation_id, value.effect_id, value.attempt_id)
                != (identity.activity_id, identity.operation_id, identity.effect_id, identity.attempt_id)
            or (evidence.operation_id, evidence.effect_id) != (identity.operation_id, identity.effect_id)
            or value.batch_digest != evidence.batch_digest
            or value.payload_digest != evidence.payload_digest
            or value.action_intent_digest != evidence.action_digest
            or value.action_schema_digest != evidence.schema_digest
            or value.grant_digest != evidence.grant_digest
            or seal.original_operation_id != evidence.generation_original_operation_id
            or generation.parent_original_id != seal.c02_operation_id
            or frozen.frozen_input_digest != seal.frozen_input_digest
            or frozen.qualified_units_digest != seal.qualified_units_digest
            or frozen.model_request_digest != seal.model_request_digest
            or value.audience != (plan.audience_id,) or value.scene_ref != plan.scene_id
            or value.destination_ref != plan.audience_id
            or value.segment_index != 0
            or graph_receipt.epoch.bot != namespace.bot_id
            or graph_receipt.epoch.persona != namespace.persona_id
            or graph_receipt.epoch.revision != admission.graph_epoch):
        raise NaturalDispatchReadLocatorHold("actual Natural producer/admission/frozen joins differ")

    ordered_refs = (evidence.action_ref, evidence.schema_ref, evidence.grant_ref, evidence.batch_ref)
    expected_types = (
        "d08.action_intent.v1", "d08.action_schema.v1",
        "d08.communication_intent_grant.v1",
        ("d09.natural_verified_segment_batch.v2", "d09.natural_verified_segment_batch.v3"),
    )
    writes = {}
    for proposal in bundle.proposals:
        for write in proposal.typed_writes:
            token = write.key.token
            if token in ordered_refs:
                if token in writes:
                    raise NaturalDispatchReadLocatorHold("duplicate actual Natural producer write")
                writes[token] = write
    candidate_writes = []
    for index, token in enumerate(ordered_refs):
        if token not in writes:
            raise NaturalDispatchReadLocatorHold("actual paired Natural producer write is absent")
        write = writes[token]
        expected = expected_types[index]
        if ((write.key.type_name not in expected if type(expected) is tuple else write.key.type_name != expected)
                or (write.key.owner.bot, write.key.owner.persona) != namespace.as_tuple
                or write.key.owner.kind != "activity" or write.key.owner.subject != identity.activity_id):
            raise NaturalDispatchReadLocatorHold("Natural producer write selector differs")
        matches = tuple(row for row in graph_receipt.revisions if row.key == write.key)
        if len(matches) != 1 or matches[0].revision < 1:
            raise NaturalDispatchReadLocatorHold("actual producing graph write revision is absent")
        candidate_writes.append({"ref": token, "version": matches[0].revision})
    # Read only named metadata fields of the actual writes; never copy their Body.
    action = writes[evidence.action_ref].value
    batch = writes[evidence.batch_ref].value
    grant = writes[evidence.grant_ref].value
    paid = batch["paid_review"]
    segment = batch["segment"]
    if ((batch["activity_id"], batch["operation_id"], batch["effect_id"])
                != (identity.activity_id, identity.operation_id, identity.effect_id)
            or action["action_id"] != value.action_ref
            or tuple(action["source_refs"]) != evidence.source_refs
            or tuple(bundle.envelope.source_qualification.source_refs) != evidence.source_refs
            or batch["source_ref"]["ref"] not in evidence.source_refs
            or batch["scene_id"] != plan.scene_id or batch["audience_id"] != plan.audience_id
            or batch["batch_digest"] != evidence.batch_digest
            or paid["generation_original_operation_id"] != seal.original_operation_id
            or paid["review_original_operation_id"] != evidence.review_original_operation_id
            or paid["receipt_digest"] != evidence.paid_review_digest
            or segment["segment_id"] != evidence.segment_id
            or segment["payload_digest"] != evidence.payload_digest or segment["position"] != 0):
        raise NaturalDispatchReadLocatorHold("actual action/batch metadata differs")

    # The leaf D08 grant has exactly one position-zero segment even when the
    # paid semantic roster selected a later child. No output Body is inspected.
    granted = grant["segment_grants"]
    if (len(granted) != 1 or granted[0]["position"] != 0
            or (granted[0]["segment_id"], granted[0]["effect_id"], granted[0]["payload_digest"])
                != (evidence.segment_id, identity.effect_id, evidence.payload_digest)):
        raise NaturalDispatchReadLocatorHold("actual Natural child grant is not a single exact leaf")
    semantic_child = None
    if batch["schema"] == "d09.natural_verified_segment_batch.v3":
        if version not in ("v5", "v6", "v7"):
            raise NaturalDispatchReadLocatorHold("semantic batch has no supported exact frozen profile")
        manifest = batch["semantic_manifest"]
        roster = manifest["segments"]
        selected_index = manifest["selected_index"]
        if (type(selected_index) is not int or not 0 <= selected_index < len(roster)
                or manifest["plan_ref"] != _ref(plan.plan_ref)
                or (manifest["root_operation_id"], manifest["root_effect_id"])
                    != (plan.final_operation_id, plan.final_effect_id)):
            raise NaturalDispatchReadLocatorHold("actual semantic roster parent metadata differs")
        selected = roster[selected_index]
        if ((selected["operation_id"], selected["effect_id"], selected["segment_id"],
                selected["payload_digest"], selected["position"])
                != (identity.operation_id, identity.effect_id, evidence.segment_id,
                    evidence.payload_digest, selected_index)):
            raise NaturalDispatchReadLocatorHold("actual committed semantic child metadata differs")
        semantic_child = {
            "selected_index": selected_index,
            "root_operation_id": manifest["root_operation_id"],
            "root_effect_id": manifest["root_effect_id"],
            "plan_ref": {"ref": manifest["plan_ref"]["ref"], "version": manifest["plan_ref"]["version"]},
            "generation_output_digest": paid["generation_output_digest"],
            "roster": [{name: part[name] for name in
                       ("operation_id", "effect_id", "segment_id", "position", "payload_digest")}
                      for part in roster],
        }
    elif batch["schema"] == "d09.natural_verified_segment_batch.v2":
        if (identity.operation_id, identity.effect_id) != (
                plan.final_operation_id, plan.final_effect_id):
            raise NaturalDispatchReadLocatorHold("nonsemantic Natural identity differs from its plan parent")
    else:
        raise NaturalDispatchReadLocatorHold("unsupported exact Natural batch metadata schema")

    frozen_metadata = project_natural_dispatch_frozen_metadata_v1(generation,admission=admission)
    groups = list(frozen_metadata["source_groups"])
    groups.insert(1, project_natural_dispatch_admitted_sources_v1(
        evidence,admission=admission,original_graph_reads=bundle.envelope.version_guard.read_versions))
    joins = list(frozen_metadata["required_producer_joins"])
    if semantic_child is not None:
        joins.insert(4,"actual_paid_whole_output_and_roster_child_original")

    paid_fields = (
        "generation_original_operation_id", "generation_call_id",
        "generation_model_call_request_digest", "generation_terminal_receipt_digest",
        "generation_output_digest", "generation_reservation_operation_id",
        "review_original_operation_id", "review_call_id",
        "review_model_call_request_digest", "review_terminal_receipt_digest",
        "review_output_digest", "review_reservation_operation_id", "parent_budget_lease_id",
        "review_policy_version", "current_graph_guard_digest", "receipt_digest",
    )
    return {**frozen_metadata,
        'schema': RECIPE_SCHEMA_V1,
        'kind': "unsealed_producer_metadata_recipe",
        'namespace': {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id},
        'commitments': {**frozen_metadata["commitments"],
            "candidate_digest":value.candidate_digest,
            "admission_receipt_digest":admission.receipt_digest,"request_digest":value.request_digest},
        'committed_selection': {
            "operation_id": identity.operation_id, "activity_id": identity.activity_id,
            "effect_id": identity.effect_id, "attempt_id": identity.attempt_id,
            "admission_ref": value.admission_ref, "candidate_writes": candidate_writes,
            "admission_graph_revision": admission.graph_revision,
            "graph_epoch": graph_receipt.epoch.revision,
            "graph_incarnation": value.graph_incarnation,
            "original_utc_deadline": value.utc_deadline,
            "clock_policy_ref": value.clock_policy_ref, "clock_policy_digest": value.clock_policy_digest,
            "bundle_source_refs": list(bundle.envelope.source_qualification.source_refs),
            "access_epoch": evidence.access_epoch, "delete_epoch": evidence.delete_epoch,
            "query_epoch": evidence.query_epoch,
        },
        'admission': {
            "schema": value.schema, "purpose": value.purpose, "audience": list(value.audience),
            "account_ref": value.account_ref, "destination_ref": value.destination_ref,
            "scene_ref": value.scene_ref, "action_ref": value.action_ref,
            "segment_index": value.segment_index,
        },
        'action': {"identity": {name: action["identity"][name] for name in
                                ("activity_id", "effect_id", "attempt_id", "phase",
                                 "operation_id", "canonical_input_digest")},
                   **{name: action[name] for name in
                     ("action_id", "action_kind", "target_ref", "purpose")},
                   "source_refs": list(action["source_refs"])},
        'batch': {
            "schema": batch["schema"], "scene_id": batch["scene_id"], "audience_id": batch["audience_id"],
            "source_ref": {"ref": batch["source_ref"]["ref"], "version": batch["source_ref"]["version"]},
            "valid_until": batch["valid_until"],
            "cancellation_epoch": batch["cancellation_epoch"], "batch_digest": batch["batch_digest"],
            "segment_id": segment["segment_id"], "payload_digest": segment["payload_digest"],
            "segment_position": segment["position"], "segment_count": len(granted),
            "paid_review": {name: paid[name] for name in paid_fields},
        },
        'semantic_child': semantic_child,
        'source_groups': groups,
        'required_producer_joins': joins
    }
