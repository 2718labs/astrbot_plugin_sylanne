"""Durable original generation/review preparations for natural reply v2.

W01 calls these helpers only inside its graph transaction. They store no
readiness flag, never call a model, and never authorize a D11 send.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from ..contracts import canonical_json
from ..domains.d09 import ClaimKind
from ..domains.d09.natural_reply import NaturalExpressionPlanV2, QualifiedExpressionUnitV2
from ..graph_types import AtomKey, GraphVersion, Owner
from ..model_broker.broker import ModelCallRequest
from ..model_broker.context_reply import ContextReplyPartV1
from ..model_broker.natural_reply import (
    FrozenNaturalReplyRequestV2, NaturalReplyInputV2,
    NaturalReplyInstallationV2, TEMPLATE_DIGEST as GENERATION_TEMPLATE_DIGEST,
    freeze_natural_reply_request_v2,
)
from ..model_broker.natural_review import (
    FrozenNaturalReplyReviewV1, NaturalReviewInstallationV1,
    REVIEW_TEMPLATE_DIGEST, REVIEW_TEMPLATE_DIGEST_V2, INPUT_SCHEMA_V2,
    freeze_natural_reply_review_v1,
)
from ..runtime_contracts import (
    AuthorityContext, CommandEnvelope, OperationIdentity,
    NamespaceId, NaturalReplyGenerationOriginalSealV2,
    NaturalReplyReviewOriginalSealV2, QueryEpoch, SourceQualification,
    VersionGuard, VersionedRef,
    canonical_digest, canonical_serialize,
)
from ..model_broker.natural_reply_history_v3 import FrozenNaturalReplyRequestV3, thaw_natural_reply_request_v3
from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4, thaw_natural_reply_request_v4
from .natural_original_v4 import NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4
from .natural_original_v6 import NaturalReplyGenerationOriginalSealV6,NaturalReplyReviewOriginalSealV6
from ..model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6,thaw_natural_reply_request_v6
from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7,thaw_natural_reply_request_v7
from .natural_original_v7 import NaturalReplyGenerationOriginalSealV7,NaturalReplyReviewOriginalSealV7
from .natural_original_v3 import (
    NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3,
    natural_generation_template_digest, refreeze_natural_generation,
)
from .jobs import JobConflict, PersistentJob, get_job


class NaturalReplyJobHold(RuntimeError):
    """The original paid-call identity cannot be used safely."""


_TABLES = {
    "generation": "graph_natural_generation_preparations_v2",
    "review": "graph_natural_review_preparations_v2",
}


def _table(stage: str) -> str:
    try:
        return _TABLES[stage]
    except KeyError:
        raise ValueError("natural stage must be generation or review") from None


def natural_job_ids_v2(
    namespace: NamespaceId, parent_original_id: str, stage: str,
) -> tuple[str, str, str, str, str]:
    _table(stage)
    digest = canonical_digest({
        "schema": "sylanne.natural-original-identity.v2",
        "namespace": namespace.as_tuple, "parent": parent_original_id,
        "stage": stage,
    })[:48]
    prefix = f"natural-{stage}-"
    return tuple(prefix + kind + ":" + digest for kind in (
        "job", "origin", "acquire", "call", "reservation",
    ))


def natural_graph_guard_digest_v2(
    namespace: NamespaceId, read_versions: tuple[GraphVersion, ...],
    query_epochs: tuple[QueryEpoch, ...], *, graph_epoch: int,
    access_epoch: int, deletion_epoch: int,
) -> str:
    if (type(namespace) is not NamespaceId or type(read_versions) is not tuple
            or not read_versions or type(query_epochs) is not tuple
            or not query_epochs or any(type(item) is not GraphVersion
                                      for item in read_versions)
            or any(type(item) is not QueryEpoch for item in query_epochs)
            or any(type(value) is not int or value < 0 for value in (
                graph_epoch, access_epoch, deletion_epoch))):
        raise ValueError("typed natural current read barrier required")
    versions = tuple(sorted((row.key.token, row.revision) for row in read_versions))
    queries = tuple(sorted((row.scope_ref, row.revision) for row in query_epochs))
    if (len({ref for ref, _ in versions}) != len(versions)
            or len({ref for ref, _ in queries}) != len(queries)
            or any((row.key.owner.bot, row.key.owner.persona) != namespace.as_tuple
                   for row in read_versions)
            or any(row.namespace != namespace for row in query_epochs)):
        raise ValueError("natural read barrier crosses scope or repeats a key")
    return canonical_digest({
        "schema": "sylanne.natural-current-guard.v2",
        "namespace": namespace, "read_versions": versions,
        "query_epochs": queries, "graph_epoch": graph_epoch,
        "access_epoch": access_epoch, "deletion_epoch": deletion_epoch,
    })


def install_schema(db) -> None:
    for table in _TABLES.values():
        db.execute(f"""CREATE TABLE IF NOT EXISTS {table} (
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            parent_original_id TEXT NOT NULL,
            job_id TEXT NOT NULL UNIQUE,
            original_operation_id TEXT NOT NULL UNIQUE,
            seal_json TEXT NOT NULL, frozen_json TEXT NOT NULL,
            read_versions_json TEXT NOT NULL, query_epochs_json TEXT NOT NULL,
            graph_epoch INTEGER NOT NULL, access_epoch INTEGER NOT NULL,
            deletion_epoch INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('queued','acquired','terminal')),
            worker_fence INTEGER, typed_request_digest TEXT,
            typed_request_wire TEXT, terminal_receipt_digest TEXT,
            terminal_output_digest TEXT,
            PRIMARY KEY(bot,persona,parent_original_id)
        )""")


@dataclass(frozen=True, slots=True)
class SavedNaturalPreparationV2:
    stage: str
    parent_original_id: str
    seal: NaturalReplyGenerationOriginalSealV2 | NaturalReplyReviewOriginalSealV2
    frozen: FrozenNaturalReplyRequestV2 | FrozenNaturalReplyReviewV1
    read_versions: tuple[GraphVersion, ...]
    query_epochs: tuple[QueryEpoch, ...]
    graph_epoch: int
    access_epoch: int
    deletion_epoch: int
    state: str
    typed_request_digest: str | None
    worker_fence: int | None
    terminal_receipt_digest: str | None
    terminal_output_digest: str | None


@dataclass(frozen=True, slots=True)
class SavedNaturalCallBindingV2:
    request: ModelCallRequest
    typed_request_digest: str
    worker_fence: int


def _envelope_from_wire_v3(raw) -> CommandEnvelope:
    envelope_raw = raw["envelope"]
    authority = dict(envelope_raw["authority"])
    authority["namespace"] = NamespaceId(**authority["namespace"])
    guard = dict(envelope_raw["version_guard"])
    guard["read_versions"] = tuple(GraphVersion(
        AtomKey(Owner(**item["key"]["owner"]),
                item["key"]["type_name"], item["key"]["name"]),
        item["revision"],
    ) for item in guard["read_versions"])
    guard["query_epochs"] = tuple(QueryEpoch(
        NamespaceId(**item["namespace"]), item["scope_ref"], item["revision"],
    ) for item in guard["query_epochs"])
    for name in ("source_grant_refs", "focus_lease_versions",
                 "resource_lease_versions"):
        guard[name] = tuple(_ref(item) for item in guard[name])
    qualification = dict(envelope_raw["source_qualification"])
    qualification["source_refs"] = tuple(qualification["source_refs"])
    envelope = CommandEnvelope(
        envelope_raw["schema"],
        OperationIdentity(**envelope_raw["identity"]),
        AuthorityContext(**authority), VersionGuard(**guard),
        SourceQualification(**qualification),
        tuple(envelope_raw["input_refs"]),
        envelope_raw["parent_budget_lease_ref"],
        envelope_raw["deadline_utc"], envelope_raw["monotonic_deadline"],
        envelope_raw["character_interval_ref"],
        tuple(envelope_raw["causation"]),
    )
    return envelope


def _request_from_wire(wire: str, *, prepared_value=None, prepared_originals=None) -> ModelCallRequest:
    from .reply_model_job import reply_request_wire_v1

    raw = json.loads(wire)if prepared_value is None else prepared_value
    envelope = _envelope_from_wire_v3(raw)
    request = ModelCallRequest(
        envelope, raw["call_id"], raw["provider_id"], raw["model_id"],
        frozenset(raw["required_capabilities"]), raw["privacy_tier"],
        raw["prompt_template_digest"], raw["payload"],
        raw["timeout_seconds"], raw["max_output_tokens"],
        _prepared_payload_eof_v3=None if prepared_originals is None else prepared_originals.payload_eof_v3(raw,envelope),
    )
    if (canonical_serialize(reply_request_wire_v1(envelope, request)) != wire if prepared_value is None else reply_request_wire_v1(envelope, request) != raw):
        raise ValueError("typed natural call wire differs")
    return request


def _ref(raw: dict) -> VersionedRef:
    return VersionedRef(**raw)


def _part(raw: dict) -> ContextReplyPartV1:
    return ContextReplyPartV1(
        raw["kind"], _ref(raw["ref"]), _ref(raw["audience_ref"]),
        raw["expires_at_utc"], raw["text"],
        tuple(_ref(item) for item in raw["dependencies"]),
        _ref(raw["access_ref"]) if raw["access_ref"] is not None else None,
    )


def _unit(raw: dict) -> QualifiedExpressionUnitV2:
    fields = dict(raw)
    fields["kind"] = ClaimKind(fields["kind"])
    for name in ("qualification_ref",):
        fields[name] = _ref(fields[name]) if fields[name] is not None else None
    for name in ("source_refs", "access_refs", "correction_refs"):
        fields[name] = tuple(_ref(item) for item in fields[name])
    for name in ("self_description_hypotheses", "semantic_constraints",
                 "evidence_span", "direct_quote_span", "negation_cue_span"):
        if fields[name] is not None:
            fields[name] = tuple(fields[name])
    return QualifiedExpressionUnitV2(**fields)


def _generation_frozen(raw: dict,*,prepared_originals=None) -> FrozenNaturalReplyRequestV2:
    if prepared_originals is not None:
        from .dispatch_initial_source_read_v3 import PreparedNaturalOriginalsV3
        if type(prepared_originals)is not PreparedNaturalOriginalsV3:
            from .dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
            require_actual_authority_natural_original_v3(prepared_originals)
        return prepared_originals.frozen_v3(raw)
    if raw.get("schema") == "sylanne.d09.frozen_natural_request.v7":
        return thaw_natural_reply_request_v7(raw)
    if raw.get("schema") == "sylanne.d09.frozen_natural_request.v6":
        return thaw_natural_reply_request_v6(raw)
    if raw.get("schema") in {"sylanne.d09.frozen_natural_request.v4",
                              "sylanne.d09.frozen_natural_request.v5"}:
        return thaw_natural_reply_request_v4(raw)
    if raw.get("schema") == "sylanne.d09.frozen_natural_request.v3":
        return thaw_natural_reply_request_v3(raw)
    input_raw = raw["input"]
    plan_raw = input_raw["plan"]
    plan = NaturalExpressionPlanV2(
        NamespaceId(**plan_raw["namespace"]), _ref(plan_raw["plan_ref"]),
        _ref(plan_raw["scene_ref"]), _ref(plan_raw["audience_ref"]),
        tuple(plan_raw["required_slots"]),
        tuple(plan_raw["allowed_speech_acts"]),
        tuple(_ref(item) for item in plan_raw["promise_grants"]),
        tuple(_unit(item) for item in plan_raw["units"]),
        plan_raw["valid_until_utc"],
        plan_raw["final_activity_id"],
        plan_raw["final_operation_id"],
        plan_raw["final_effect_id"],
        plan_raw["scene_id"],
        plan_raw["audience_id"],
    )
    input = NaturalReplyInputV2(
        _part(input_raw["question"]), plan,
        tuple(_part(item) for item in input_raw["stable_history"]),
        input_raw["frozen_at_utc"], input_raw["expires_at_utc"],
    )
    expected = freeze_natural_reply_request_v2(
        input, NaturalReplyInstallationV2(**raw["installation"]),
    )
    if canonical_serialize(asdict(expected)) != canonical_serialize(raw):
        raise NaturalReplyJobHold("frozen natural generation request differs")
    return expected


def _review_frozen(
    raw: dict, generation: NaturalReplyGenerationOriginalSealV2, *, prepared_originals=None,
) -> FrozenNaturalReplyReviewV1:
    if prepared_originals is not None:
        from .dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
        require_actual_authority_natural_original_v3(prepared_originals)
        frozen=prepared_originals.frozen_v3(raw)
        if (prepared_originals.stage!='review' or frozen.generation_frozen_input_digest!=generation.frozen_input_digest
                or frozen.qualified_units_digest!=generation.qualified_units_digest):
            raise NaturalReplyJobHold('Authority review differs from its actual generation original')
        return frozen
    payload = json.loads(raw["canonical_input"])
    output = {
        "schema": payload.get("generation_output_schema", "sylanne.d09.context_reply_output.v2"),
        "body": payload["body"], "units": payload["units"],
    }
    if payload.get("schema") == "sylanne.d09.natural_review_input.v2":
        output["semantic_segments"] = payload["semantic_segments"]
    basis = tuple(_unit(item["source_unit"])
                  for item in payload["qualified_basis"])
    grants = tuple(payload["qualified_basis"][0]["promise_grant_refs"])
    expected = freeze_natural_reply_review_v1(
        generation, output, basis, grants,
        payload["review_policy_version"],
        NaturalReviewInstallationV1(**raw["installation"]),
    )
    if canonical_serialize(asdict(expected)) != canonical_serialize(raw):
        raise NaturalReplyJobHold("frozen natural review request differs")
    return expected


def _seal(stage: str, raw: dict):
    data = dict(raw)
    data["namespace"] = NamespaceId(**data["namespace"])
    classes = {
        ("generation", "sylanne.d09.natural_generation_seal.v2"): NaturalReplyGenerationOriginalSealV2,
        ("generation", "sylanne.d09.natural_generation_seal.v3"): NaturalReplyGenerationOriginalSealV3,
        ("generation", "sylanne.d09.natural_generation_seal.v4"): NaturalReplyGenerationOriginalSealV4,
        ("generation", "sylanne.d09.natural_generation_seal.v5"): NaturalReplyGenerationOriginalSealV4,
        ("generation", "sylanne.d09.natural_generation_seal.v6"): NaturalReplyGenerationOriginalSealV6,
        ("generation", "sylanne.d09.natural_generation_seal.v7"): NaturalReplyGenerationOriginalSealV7,
        ("review", "sylanne.d09.natural_review_seal.v2"): NaturalReplyReviewOriginalSealV2,
        ("review", "sylanne.d09.natural_review_seal.v3"): NaturalReplyReviewOriginalSealV3,
        ("review", "sylanne.d09.natural_review_seal.v4"): NaturalReplyReviewOriginalSealV4,
        ("review", "sylanne.d09.natural_review_seal.v5"): NaturalReplyReviewOriginalSealV4,
        ("review", "sylanne.d09.natural_review_seal.v6"): NaturalReplyReviewOriginalSealV6,
        ("review", "sylanne.d09.natural_review_seal.v7"): NaturalReplyReviewOriginalSealV7,
    }
    cls = classes[(stage, data["schema"])]
    return cls(**data)


def save_original_preparation(
    db, *, stage: str, namespace: NamespaceId,
    parent_original_id: str,
    seal: NaturalReplyGenerationOriginalSealV2 | NaturalReplyReviewOriginalSealV2,
    frozen: FrozenNaturalReplyRequestV2 | FrozenNaturalReplyReviewV1,
    read_versions: tuple[GraphVersion, ...],
    query_epochs: tuple[QueryEpoch, ...], graph_epoch: int,
    access_epoch: int, deletion_epoch: int, job: PersistentJob,
) -> SavedNaturalPreparationV2:
    """Insert one pre-call original row after W01 reserves budget and D11 job."""
    table = _table(stage)
    if not db.in_transaction:
        raise NaturalReplyJobHold("natural preparation requires graph write tx")
    install_schema(db)
    ids = natural_job_ids_v2(namespace, parent_original_id, stage)
    guard = natural_graph_guard_digest_v2(
        namespace, read_versions, query_epochs, graph_epoch=graph_epoch,
        access_epoch=access_epoch, deletion_epoch=deletion_epoch,
    )
    if (type(job) is not PersistentJob
            or get_job(db, job.job_id) != job
            or (job.bot_id, job.persona_id) != namespace.as_tuple
            or (job.job_id, job.operation_id, job.budget_ref,
                job.phase, job.work_kind) != (
                seal.job_id, seal.original_operation_id,
                seal.parent_budget_lease_id, "queued", "natural_" + stage)
            or (seal.job_id, seal.original_operation_id,
                seal.acquire_operation_id, seal.call_id,
                seal.reservation_operation_id) != ids
            or seal.namespace != namespace
            or seal.original_graph_guard_digest != guard):
        raise NaturalReplyJobHold("natural original job, budget or read guard differs")
    if stage == "generation":
        if ((type(seal), type(frozen)) not in ((NaturalReplyGenerationOriginalSealV2, FrozenNaturalReplyRequestV2), (NaturalReplyGenerationOriginalSealV3, FrozenNaturalReplyRequestV3), (NaturalReplyGenerationOriginalSealV4, FrozenNaturalReplyRequestV4), (NaturalReplyGenerationOriginalSealV7, FrozenNaturalReplyRequestV7), (NaturalReplyGenerationOriginalSealV6, FrozenNaturalReplyRequestV6))
                or seal.c02_operation_id != parent_original_id
                or seal.frozen_input_digest != frozen.frozen_input_digest
                or seal.qualified_units_digest != frozen.qualified_units_digest
                or seal.model_request_digest != frozen.model_request_digest
                or seal.installation_id != frozen.installation.installation_id
                or seal.provider_config_digest
                != frozen.installation.provider_config_digest
                or refreeze_natural_generation(frozen) != frozen):
            raise NaturalReplyJobHold("natural generation seal differs")
        if (type(seal) is NaturalReplyGenerationOriginalSealV4
                and (seal.schema == "sylanne.d09.natural_generation_seal.v5")
                    != (frozen.schema == "sylanne.d09.frozen_natural_request.v5")):
            raise NaturalReplyJobHold("generation seal and frozen semantic versions differ")
    else:
        if (type(seal) not in (NaturalReplyReviewOriginalSealV2, NaturalReplyReviewOriginalSealV3, NaturalReplyReviewOriginalSealV4, NaturalReplyReviewOriginalSealV6, NaturalReplyReviewOriginalSealV7)
                or type(frozen) is not FrozenNaturalReplyReviewV1
                or seal.generation_frozen_input_digest
                != frozen.generation_frozen_input_digest
                or seal.generation_output_digest != frozen.generation_output_digest
                or seal.qualified_units_digest != frozen.qualified_units_digest
                or seal.review_frozen_input_digest != frozen.digest
                or seal.model_request_digest != frozen.wire_digest
                or seal.review_policy_version != frozen.review_policy_version
                or seal.installation_id != frozen.installation.installation_id
                or seal.provider_config_digest
                != frozen.installation.provider_config_digest):
            raise NaturalReplyJobHold("natural review seal differs")
        original = read_original_preparation(
            db, namespace, parent_original_id, "generation",
        )
        if (original is None or original.state != "terminal"
                or original.terminal_output_digest != seal.generation_output_digest
                or original.seal.original_operation_id
                != seal.generation_original_operation_id
                or (type(original.seal), type(seal)) not in ((NaturalReplyGenerationOriginalSealV2, NaturalReplyReviewOriginalSealV2),
                        (NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3),
                        (NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4),
                        (NaturalReplyGenerationOriginalSealV7,NaturalReplyReviewOriginalSealV7), (NaturalReplyGenerationOriginalSealV6,NaturalReplyReviewOriginalSealV6))
                or original.seal.call_id != seal.generation_call_id
                or original.seal.frozen_input_digest
                != seal.generation_frozen_input_digest
                or original.seal.qualified_units_digest
                != seal.qualified_units_digest
                or original.seal.parent_budget_lease_id
                != seal.parent_budget_lease_id
                or _review_frozen(asdict(frozen), original.seal) != frozen):
            raise NaturalReplyJobHold("review lacks original observed generation result")
        if ((original.seal.schema in {"sylanne.d09.natural_generation_seal.v5","sylanne.d09.natural_generation_seal.v6","sylanne.d09.natural_generation_seal.v7"})
                != (seal.schema in {"sylanne.d09.natural_review_seal.v5","sylanne.d09.natural_review_seal.v6","sylanne.d09.natural_review_seal.v7"})
                or (seal.schema in {"sylanne.d09.natural_review_seal.v5","sylanne.d09.natural_review_seal.v6","sylanne.d09.natural_review_seal.v7"})
                   != (json.loads(frozen.canonical_input).get("schema") == INPUT_SCHEMA_V2)):
            raise NaturalReplyJobHold("generation and review semantic versions differ")
    db.execute(
        f"INSERT INTO {table} (bot,persona,parent_original_id,job_id,"
        "original_operation_id,seal_json,frozen_json,read_versions_json,"
        "query_epochs_json,graph_epoch,access_epoch,deletion_epoch,state) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'queued')",
        namespace.as_tuple + (
            parent_original_id, seal.job_id, seal.original_operation_id,
            canonical_serialize(asdict(seal)), canonical_serialize(asdict(frozen)),
            canonical_serialize([{"key": row.key.token, "revision": row.revision}
                                 for row in read_versions]),
            canonical_serialize([asdict(row) for row in query_epochs]),
            graph_epoch, access_epoch, deletion_epoch,
        ),
    )
    saved = read_original_preparation(db, namespace, parent_original_id, stage)
    if saved is None:
        raise NaturalReplyJobHold("natural original preparation missing")
    return saved


def read_original_preparation(
    db, namespace: NamespaceId, parent_original_id: str, stage: str, *, prepared_originals=None,
) -> SavedNaturalPreparationV2 | None:
    """Read and fully recompute an original row inside the current graph tx."""
    table = _table(stage)
    if not db.in_transaction:
        raise NaturalReplyJobHold("natural original read requires graph tx")
    if prepared_originals is None:
        from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_natural_original_v3
        handled,original=read_bound_authority_natural_original_v3(db,namespace,parent_original_id,stage)
        if handled:prepared_originals=original
    if prepared_originals is None:
        row = db.execute(
            f"SELECT seal_json,frozen_json,read_versions_json,query_epochs_json,"
            "graph_epoch,access_epoch,deletion_epoch,state,typed_request_digest,"
            "worker_fence,typed_request_wire,terminal_receipt_digest,"
            "terminal_output_digest FROM " + table +
            " WHERE bot=? AND persona=? AND parent_original_id=?",
            namespace.as_tuple + (parent_original_id,),
        ).fetchone()
    else:
        from .dispatch_initial_source_read_v3 import PreparedNaturalOriginalsV3
        if type(prepared_originals)is not PreparedNaturalOriginalsV3:
            from .dispatch_initial_source_read_v3 import require_actual_authority_natural_original_v3
            require_actual_authority_natural_original_v3(prepared_originals)
        row=prepared_originals.require_for_v3(db,namespace,parent_original_id,stage)
        saved=prepared_originals.saved_v3(db,namespace,parent_original_id,stage)
        if saved is not None:return saved
    if row is None:
        return None
    try:
        if prepared_originals is None and any(canonical_json(json.loads(wire)) != wire for wire in row[:4]):
            raise ValueError("noncanonical original row")
        seal = _seal(stage, (json.loads(row[0])if prepared_originals is None else prepared_originals.json_v3("seal_json")))
        versions = tuple(GraphVersion(AtomKey.from_token(item["key"]), item["revision"])
                         for item in (json.loads(row[2])if prepared_originals is None else prepared_originals.json_v3("read_versions_json")))
        queries = tuple(QueryEpoch(NamespaceId(**item["namespace"]),
                                   item["scope_ref"], item["revision"])
                        for item in (json.loads(row[3])if prepared_originals is None else prepared_originals.json_v3("query_epochs_json")))
        if stage == "generation":
            frozen = _generation_frozen((json.loads(row[1])if prepared_originals is None else prepared_originals.json_v3("frozen_json")),prepared_originals=prepared_originals)
            if (type(seal), type(frozen)) not in (
                    (NaturalReplyGenerationOriginalSealV2, FrozenNaturalReplyRequestV2),
                    (NaturalReplyGenerationOriginalSealV3, FrozenNaturalReplyRequestV3), (NaturalReplyGenerationOriginalSealV4, FrozenNaturalReplyRequestV4), (NaturalReplyGenerationOriginalSealV7, FrozenNaturalReplyRequestV7), (NaturalReplyGenerationOriginalSealV6, FrozenNaturalReplyRequestV6)):
                raise ValueError("generation original seal/frozen version differs")
            if (type(seal) is NaturalReplyGenerationOriginalSealV4
                    and (seal.schema == "sylanne.d09.natural_generation_seal.v5")
                        != (frozen.schema == "sylanne.d09.frozen_natural_request.v5")):
                raise ValueError("generation original semantic version differs")
        else:
            original = read_original_preparation(
                db, namespace, parent_original_id, "generation",
            )
            if original is None or original.state != "terminal":
                raise ValueError("generation result missing")
            frozen = _review_frozen((json.loads(row[1])if prepared_originals is None else prepared_originals.json_v3("frozen_json")), original.seal,prepared_originals=prepared_originals)
            if (original.terminal_output_digest != seal.generation_output_digest
                    or original.seal.original_operation_id
                    != seal.generation_original_operation_id
                    or (type(original.seal), type(seal)) not in ((NaturalReplyGenerationOriginalSealV2, NaturalReplyReviewOriginalSealV2),
                        (NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3),
                        (NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4),
                        (NaturalReplyGenerationOriginalSealV7,NaturalReplyReviewOriginalSealV7), (NaturalReplyGenerationOriginalSealV6,NaturalReplyReviewOriginalSealV6))
                or original.seal.call_id != seal.generation_call_id
                    or original.seal.parent_budget_lease_id
                    != seal.parent_budget_lease_id):
                raise ValueError("review and generation original identity differ")
            if ((original.seal.schema in {"sylanne.d09.natural_generation_seal.v5","sylanne.d09.natural_generation_seal.v6","sylanne.d09.natural_generation_seal.v7"})
                    != (seal.schema in {"sylanne.d09.natural_review_seal.v5","sylanne.d09.natural_review_seal.v6","sylanne.d09.natural_review_seal.v7"})
                    or (seal.schema in {"sylanne.d09.natural_review_seal.v5","sylanne.d09.natural_review_seal.v6","sylanne.d09.natural_review_seal.v7"})
                       != (json.loads(frozen.canonical_input).get("schema") == INPUT_SCHEMA_V2)):
                raise ValueError("review and generation semantic versions differ")
        ids = natural_job_ids_v2(namespace, parent_original_id, stage)
        guard = natural_graph_guard_digest_v2(
            namespace, versions, queries, graph_epoch=row[4],
            access_epoch=row[5], deletion_epoch=row[6],
        )
        frozen_wire = (frozen.canonical_wire if stage == "generation"
                       else frozen.canonical_wire)
        expected_wire_digest = (sha256(frozen_wire.encode("utf-8")).hexdigest() if prepared_originals is None else
                                prepared_originals.digest_v3("frozen_wire"))
        expected_frozen_digest = (frozen.frozen_input_digest if stage == "generation"
                                  else frozen.digest)
        job = get_job(db, seal.job_id)
        if (seal.namespace != namespace
                or (seal.job_id, seal.original_operation_id,
                    seal.acquire_operation_id, seal.call_id,
                    seal.reservation_operation_id) != ids
                or job is None or job.work_kind != "natural_" + stage
                or job.operation_id != seal.original_operation_id
                or seal.original_graph_guard_digest != guard
                or seal.model_request_digest != expected_wire_digest
                or seal.installation_id != frozen.installation.installation_id
                or seal.provider_config_digest
                != frozen.installation.provider_config_digest
                or (stage == "generation" and (
                    seal.c02_operation_id != parent_original_id
                    or seal.frozen_input_digest != expected_frozen_digest
                    or seal.qualified_units_digest != frozen.qualified_units_digest))
                or (stage == "review" and (
                    seal.review_frozen_input_digest != expected_frozen_digest
                    or seal.generation_output_digest != frozen.generation_output_digest
                    or seal.qualified_units_digest != frozen.qualified_units_digest
                    or seal.review_policy_version != frozen.review_policy_version))
                or row[7] not in {"queued", "acquired", "terminal"}
                or (row[7] == "queued" and any(item is not None for item in row[8:]))
                or (row[7] != "queued" and (any(item is None for item in row[8:10])
                    or prepared_originals is None and row[10] is None))
                or (row[7] == "acquired" and any(item is not None for item in row[11:]))
                or (row[7] == "terminal" and (row[11] is None or row[12] is None))):
            raise ValueError("natural saved identity differs")
        if row[7] != "queued":
            request = _request_from_wire(row[10],prepared_value=None if prepared_originals is None else prepared_originals.json_v3("typed_request_wire"),prepared_originals=prepared_originals)
            expected_template = (natural_generation_template_digest(frozen) if stage == "generation"
                                 else (REVIEW_TEMPLATE_DIGEST_V2 if json.loads(frozen.canonical_input).get("schema") == INPUT_SCHEMA_V2
                                       else REVIEW_TEMPLATE_DIGEST))
            if (type(row[9]) is not int or row[9] < 1
                    or (request.digest if prepared_originals is None else prepared_originals.digest_v3("typed_request")) != row[8]
                    or request.identity.operation_id != seal.acquire_operation_id
                    or request.call_id != seal.call_id
                    or request.provider_id != frozen.installation.provider_id
                    or request.model_id != frozen.installation.model_id
                    or request.max_output_tokens
                    != frozen.installation.max_output_tokens
                    or request.prompt_template_digest != expected_template
                    or (dict(request.payload) != json.loads(frozen.canonical_wire) if prepared_originals is None else
                        not prepared_originals.require_payload_v3(request.payload))):
                raise ValueError("natural typed paid call binding differs")
            if prepared_originals is not None:
                from .dispatch_initial_source_read_v3 import PreparedAuthorityNaturalOriginalsV3
                if type(prepared_originals)is PreparedAuthorityNaturalOriginalsV3:
                    prepared_originals.qualify_call_binding_v3(request)
    except (KeyError, TypeError, ValueError, IndexError, JobConflict) as exc:
        raise NaturalReplyJobHold("saved natural preparation is invalid") from exc
    return SavedNaturalPreparationV2(
        stage, parent_original_id, seal, frozen, versions, queries,
        row[4], row[5], row[6], row[7], row[8], row[9], row[11], row[12],
    )


def bind_original_call(
    db, saved: SavedNaturalPreparationV2, job: PersistentJob,
    request: ModelCallRequest,
) -> str:
    """Bind the real typed paid request in the same acquire graph tx."""
    from .reply_model_job import reply_request_wire_v1

    if not db.in_transaction or saved.state != "queued":
        raise NaturalReplyJobHold("natural acquire requires queued graph tx")
    if read_original_preparation(
            db, saved.seal.namespace, saved.parent_original_id,
            saved.stage) != saved:
        raise NaturalReplyJobHold("natural original changed before acquire")
    seal, frozen = saved.seal, saved.frozen
    if (type(request) is not ModelCallRequest
            or type(job) is not PersistentJob
            or get_job(db, job.job_id) != job
            or (job.job_id, job.operation_id, job.phase,
                job.budget_ref, job.work_kind) != (
                seal.job_id, seal.original_operation_id, "running",
                seal.parent_budget_lease_id, "natural_" + saved.stage)
            or job.fence < 1
            or request.call_id != seal.call_id
            or request.identity.operation_id != seal.acquire_operation_id
            or request.provider_id != frozen.installation.provider_id
            or request.model_id != frozen.installation.model_id
            or request.max_output_tokens != frozen.installation.max_output_tokens
            or request.prompt_template_digest != (
                natural_generation_template_digest(frozen) if saved.stage == "generation"
                else (REVIEW_TEMPLATE_DIGEST_V2 if json.loads(frozen.canonical_input).get("schema") == INPUT_SCHEMA_V2
                                       else REVIEW_TEMPLATE_DIGEST))
            or dict(request.payload) != json.loads(frozen.canonical_wire)):
        raise NaturalReplyJobHold("natural typed paid call differs from frozen wire")
    wire = canonical_serialize(reply_request_wire_v1(request.envelope, request))
    table = _table(saved.stage)
    changed = db.execute(
        f"UPDATE {table} SET state='acquired',worker_fence=?,"
        "typed_request_digest=?,typed_request_wire=? "
        "WHERE bot=? AND persona=? AND parent_original_id=? AND state='queued' "
        "AND seal_json=?",
        (job.fence, request.digest, wire) + seal.namespace.as_tuple + (
            saved.parent_original_id, canonical_serialize(asdict(seal))),
    ).rowcount
    if changed != 1:
        raise NaturalReplyJobHold("natural original acquire CAS differed")
    return request.digest


def read_original_call_binding(
    db, saved: SavedNaturalPreparationV2,
) -> SavedNaturalCallBindingV2 | None:
    """Expose the original typed paid-call identity under the same graph tx."""
    if not db.in_transaction or type(saved) is not SavedNaturalPreparationV2:
        raise NaturalReplyJobHold("natural paid-call read requires graph tx")
    current = read_original_preparation(
        db, saved.seal.namespace, saved.parent_original_id, saved.stage,
    )
    if current is None or current != saved:
        raise NaturalReplyJobHold("natural original changed before paid-call read")
    if current.state == "queued":
        return None
    table = _table(saved.stage)
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_natural_original_v3
    handled,original=read_bound_authority_natural_original_v3(db,saved.seal.namespace,saved.parent_original_id,saved.stage)
    if handled:
        request=original.call_binding_v3(db,saved.seal.namespace,saved.parent_original_id,saved.stage)
        return SavedNaturalCallBindingV2(request,current.typed_request_digest,current.worker_fence)
    row = db.execute(
        f"SELECT typed_request_wire FROM {table} "
        "WHERE bot=? AND persona=? AND parent_original_id=?",
        saved.seal.namespace.as_tuple + (saved.parent_original_id,),
    ).fetchone()
    if row is None:
        raise NaturalReplyJobHold("natural typed paid-call row missing")
    request = _request_from_wire(row[0])
    return SavedNaturalCallBindingV2(
        request, current.typed_request_digest, current.worker_fence,
    )


def record_terminal(
    db, saved: SavedNaturalPreparationV2, job: PersistentJob, *,
    terminal_receipt_digest: str, output_digest: str,
) -> None:
    """CAS acquired→terminal beside D11 completed, after W01 checks paid facts."""
    if not db.in_transaction or saved.state != "acquired":
        raise NaturalReplyJobHold("natural terminal requires acquired graph tx")
    if read_original_preparation(
            db, saved.seal.namespace, saved.parent_original_id,
            saved.stage) != saved:
        raise NaturalReplyJobHold("natural original changed before terminal")
    seal = saved.seal
    durable = get_job(db, seal.job_id)
    if (type(job) is not PersistentJob or job != durable
            or job.phase != "completed"
            or (job.job_id, job.operation_id, job.budget_ref,
                job.work_kind) != (
                seal.job_id, seal.original_operation_id,
                seal.parent_budget_lease_id, "natural_" + saved.stage)
            or any(type(item) is not str or len(item) != 64
                   or any(ch not in "0123456789abcdef" for ch in item)
                   for item in (terminal_receipt_digest, output_digest))):
        raise NaturalReplyJobHold("natural terminal lacks completed original job")
    table = _table(saved.stage)
    changed = db.execute(
        f"UPDATE {table} SET state='terminal',terminal_receipt_digest=?,"
        "terminal_output_digest=? WHERE bot=? AND persona=? "
        "AND parent_original_id=? AND state='acquired' "
        "AND typed_request_digest=?",
        (terminal_receipt_digest, output_digest)
        + seal.namespace.as_tuple
        + (saved.parent_original_id, saved.typed_request_digest),
    ).rowcount
    if changed != 1:
        raise NaturalReplyJobHold("natural original terminal CAS differed")


__all__ = [
    "NaturalReplyJobHold", "SavedNaturalPreparationV2", "install_schema",
    "SavedNaturalCallBindingV2", "REVIEW_TEMPLATE_DIGEST",
    "natural_job_ids_v2", "natural_graph_guard_digest_v2",
    "save_original_preparation", "read_original_preparation",
    "bind_original_call", "read_original_call_binding", "record_terminal",
]
