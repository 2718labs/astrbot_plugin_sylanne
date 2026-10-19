"""Durable, content-complete identity for a first-ingress encoding request.

This module is a storage primitive.  The graph coordinator must qualify the
current job, source, budget, and trusted request issuer before inserting a row.
Nothing here grants permission to call a provider.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from ..memory_types import SourceRecord
    from ..model_broker.broker import ModelCallRequest
    from ..runtime_contracts import NamespaceId


class EncodingCallConflict(RuntimeError):
    """One job or call identity was reused with different content."""


@dataclass(frozen=True, slots=True)
class CommittedEncodingBaselineV1:
    """Historical D04 graph identity to freeze before a new model acquire."""

    baseline_ref: str
    baseline_revision: int
    operation_id: str
    bundle_digest: str
    graph_incarnation: str
    graph_epoch: int

    def __post_init__(self) -> None:
        from ..graph_types import AtomKey

        key = AtomKey.from_token(self.baseline_ref)
        if key.type_name != "d04.encoding_baseline.v1":
            raise ValueError("D04 encoding baseline graph token required")
        if (type(self.baseline_revision) is not int or self.baseline_revision < 1
                or type(self.graph_epoch) is not int or self.graph_epoch < 1
                or any(type(value) is not str or not value for value in (
                    self.operation_id, self.bundle_digest, self.graph_incarnation))):
            raise ValueError("committed D04 baseline identity is incomplete")


@dataclass(frozen=True)
class EncodingCallBinding:
    namespace: NamespaceId
    job_id: str
    source_id: str
    source_revision: int
    access_revision: int
    budget_lease_id: str
    budget_reservation_operation_id: str
    binding_digest: str
    model_request_digest: str
    call_id: str
    request_json: str

    @property
    def request(self) -> Mapping[str, Any]:
        return json.loads(self.request_json)


@dataclass(frozen=True)
class EncodingRequestIssueV1:
    """Legacy fixture output. It is never a production egress authorization."""

    request: ModelCallRequest
    provider_config_ref: str
    provider_config_digest: str


@dataclass(frozen=True, slots=True)
class EncodingRequestIssueV2:
    """Pure request construction; graph, budget and egress admission stay external."""

    request: ModelCallRequest
    provider_config_ref: str
    provider_config_digest: str


def binding_to_json(binding: EncodingCallBinding) -> str:
    from ..runtime_contracts import canonical_serialize

    _validate_binding_content(binding)
    return canonical_serialize(asdict(binding))


def binding_from_json(value: str) -> EncodingCallBinding:
    from ..runtime_contracts import NamespaceId

    data = json.loads(value)
    data["namespace"] = NamespaceId(**data["namespace"])
    binding = EncodingCallBinding(**data)
    _validate_binding_content(binding)
    if binding_to_json(binding) != value:
        raise EncodingCallConflict("frozen encoding binding is not canonical")
    return binding


def install_schema(db) -> None:
    intent_columns = {row[1] for row in db.execute(
        "PRAGMA table_info(graph_job_acquire_intents_v2)")}
    if intent_columns and "encoding_binding_json" not in intent_columns:
        db.execute("ALTER TABLE graph_job_acquire_intents_v2 "
                   "ADD COLUMN encoding_binding_json TEXT")
    if intent_columns:
        db.execute("DROP TRIGGER IF EXISTS graph_job_acquire_intent_no_update_v2")
        db.execute("""
            CREATE TRIGGER graph_job_acquire_intent_no_update_v2
            BEFORE UPDATE ON graph_job_acquire_intents_v2
            WHEN NOT (
                OLD.encoding_binding_json IS NOT NULL
                AND NEW.encoding_binding_json IS NULL
                AND EXISTS (
                    SELECT 1 FROM runtime_encoding_call_redactions_v1 AS r
                    WHERE r.bot=OLD.bot AND r.persona=OLD.persona
                    AND r.acquire_operation_id=OLD.acquire_operation_id
                )
                AND NEW.bot IS OLD.bot AND NEW.persona IS OLD.persona
                AND NEW.acquire_operation_id IS OLD.acquire_operation_id
                AND NEW.request_digest IS OLD.request_digest
                AND NEW.job_id IS OLD.job_id
                AND NEW.original_operation_id IS OLD.original_operation_id
                AND NEW.actor IS OLD.actor AND NEW.fixed_now_utc IS OLD.fixed_now_utc
                AND NEW.lease_seconds IS OLD.lease_seconds
                AND NEW.expected_job_revision IS OLD.expected_job_revision
                AND NEW.expected_fence IS OLD.expected_fence
                AND NEW.expected_cancel_epoch IS OLD.expected_cancel_epoch
                AND NEW.fence_attempt_id IS OLD.fence_attempt_id
                AND NEW.requirements_json IS OLD.requirements_json
                AND NEW.anchor_json IS OLD.anchor_json
                AND NEW.graph_revision IS OLD.graph_revision
                AND NEW.graph_epoch IS OLD.graph_epoch
            )
            BEGIN SELECT RAISE(ABORT, 'job acquire intent is immutable'); END
        """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_encoding_call_bindings_v1(
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            job_id TEXT NOT NULL, call_id TEXT NOT NULL,
            source_id TEXT NOT NULL, source_revision INTEGER NOT NULL,
            access_revision INTEGER NOT NULL,
            budget_lease_id TEXT NOT NULL,
            budget_reservation_operation_id TEXT NOT NULL,
            binding_digest TEXT NOT NULL,
            model_request_digest TEXT NOT NULL,
            request_json TEXT NOT NULL,
            PRIMARY KEY(bot,persona,job_id),
            UNIQUE(bot,persona,call_id),
            FOREIGN KEY(job_id) REFERENCES runtime_jobs(job_id)
        )
    """)
    db.execute("""
        CREATE TRIGGER IF NOT EXISTS runtime_encoding_call_bindings_no_update_v1
        BEFORE UPDATE ON runtime_encoding_call_bindings_v1
        BEGIN SELECT RAISE(ABORT, 'encoding call binding is immutable'); END
    """)
    # D12 closure cleanup must eventually be able to purge source-bearing
    # request JSON. Normal write admission has no delete operation.
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_encoding_call_redactions_v1(
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            acquire_operation_id TEXT NOT NULL, job_id TEXT NOT NULL,
            source_id TEXT NOT NULL, call_id TEXT NOT NULL,
            binding_digest TEXT NOT NULL, model_request_digest TEXT NOT NULL,
            deletion_operation_id TEXT NOT NULL,
            PRIMARY KEY(bot,persona,acquire_operation_id)
        )
    """)
    db.execute("""
        CREATE TRIGGER IF NOT EXISTS runtime_encoding_call_redactions_no_update_v1
        BEFORE UPDATE ON runtime_encoding_call_redactions_v1
        BEGIN SELECT RAISE(ABORT, 'encoding call redaction is immutable'); END
    """)
    db.execute("""
        CREATE TRIGGER IF NOT EXISTS runtime_encoding_call_redactions_no_delete_v1
        BEFORE DELETE ON runtime_encoding_call_redactions_v1
        BEGIN SELECT RAISE(ABORT, 'encoding call redaction is immutable'); END
    """)


def prepare_binding(
    namespace: NamespaceId, job_id: str, source: SourceRecord,
    source_revision: int, access_revision: int, budget_lease_id: str,
    budget_reservation_operation_id: str, request: ModelCallRequest,
    *, prompt_template_version: str, provider_config_ref: str,
    provider_config_digest: str,
    production_context=None,
    baseline: CommittedEncodingBaselineV1 | None = None,
) -> EncodingCallBinding:
    """Freeze all request inputs. Caller must independently qualify their origin."""
    from ..graph_types import AtomKey, GraphVersion
    from ..memory_types import SourceRecord, access_key, source_key
    from ..model_broker.broker import ModelCallRequest
    from ..model_broker.first_ingress_encoding import (
        FIRST_INGRESS_ENCODING_TEMPLATE_VERSION, ENCODING_TEMPLATE_VERSIONS,
        build_first_ingress_encoding_payload,
    )
    from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

    if (type(request) is not ModelCallRequest or type(namespace) is not NamespaceId
            or type(source) is not SourceRecord):
        raise TypeError("typed namespace, source and model request are required")
    if baseline is not None:
        if production_context is None or type(baseline) is not CommittedEncodingBaselineV1:
            raise ValueError("V3 baseline needs a production issue context")
        baseline_key = AtomKey.from_token(baseline.baseline_ref)
        if (NamespaceId.from_key(baseline_key) != namespace
                or request.envelope.version_guard.read_versions.count(
                    GraphVersion(baseline_key, baseline.baseline_revision)) != 1):
            raise ValueError("V3 request must guard the committed D04 baseline")
    source_id = source.source_id
    source_atom = source_key(*namespace.as_tuple, source_id)
    access_atom = access_key(*namespace.as_tuple, source_id)
    source_ref = source_atom.token
    if any(type(value) is not str or not value for value in (
            job_id, source_id, budget_lease_id,
            budget_reservation_operation_id, prompt_template_version,
            provider_config_ref)):
        raise ValueError("binding identities and template version must be nonempty")
    if any(type(value) is not int or value < 1
           for value in (source_revision, access_revision)):
        raise ValueError("binding needs committed source and access revisions")
    if (type(provider_config_digest) is not str
            or len(provider_config_digest) != 64
            or any(char not in "0123456789abcdef" for char in provider_config_digest)):
        raise ValueError("provider config digest must be lowercase SHA-256")
    if (request.envelope.authority.namespace != namespace
            or request.envelope.source_qualification.source_refs != (source_ref,)
            or request.envelope.parent_budget_lease_ref != budget_lease_id
            or request.envelope.input_refs != (source_ref,)):
        raise ValueError("model request differs from source or budget identity")
    guard_versions = {
        item.key: item.revision
        for item in request.envelope.version_guard.read_versions
    }
    if (guard_versions.get(source_atom) != source_revision
            or guard_versions.get(access_atom) != access_revision
            or request.envelope.authority.purpose not in source.purposes
            or not set(request.envelope.authority.audience).issubset(source.audiences)):
        raise ValueError("model request lost source version or access scope")
    expected_payload, expected_template_digest = build_first_ingress_encoding_payload(source,template_version=prompt_template_version)
    if (dict(request.payload) != expected_payload
            or request.prompt_template_digest != expected_template_digest
            or prompt_template_version not in ENCODING_TEMPLATE_VERSIONS):
        raise ValueError("model request differs from fixed first-ingress template")
    frozen = {
        "schema": ("sylanne.first-ingress-encoding-call.v3"
                   if baseline is not None else
                   "sylanne.first-ingress-encoding-call.v2"
                   if production_context is not None else
                   "sylanne.first-ingress-encoding-call.v1"),
        "namespace": list(namespace.as_tuple),
        "job_id": job_id,
        "source_id": source_id,
        "source_revision": source_revision,
        "access_revision": access_revision,
        "budget_lease_id": budget_lease_id,
        "budget_reservation_operation_id": budget_reservation_operation_id,
        "call_id": request.call_id,
        "model_request_digest": request.digest,
        "envelope": json.loads(canonical_serialize(request.envelope)),
        "provider_id": request.provider_id,
        "model_id": request.model_id,
        "provider_config_ref": provider_config_ref,
        "provider_config_digest": provider_config_digest,
        "required_capabilities": sorted(request.required_capabilities),
        "privacy_tier": request.privacy_tier,
        "prompt_template_digest": request.prompt_template_digest,
        "prompt_template_version": prompt_template_version,
        "payload": dict(request.payload),
        "timeout_seconds": float(request.timeout_seconds),
        "max_output_tokens": request.max_output_tokens,
    }
    if production_context is not None:
        if (request.envelope.identity.operation_id
                != production_context.acquire_operation_id
                or request.envelope.identity.phase != "encode"
                or request.envelope.authority.purpose != "consolidation"
                or production_context.job.work_kind != "d06.encode_source"
                or production_context.job.operation_id
                != budget_reservation_operation_id
                or production_context.job.budget_ref != budget_lease_id
                or request.envelope.monotonic_deadline
                != production_context.monotonic_deadline
                or request.envelope.character_interval_ref
                != production_context.character_interval_ref
                or request.envelope.deadline_utc != production_context.deadline_utc):
            raise ValueError("production encoding request lost original job or clock context")
        frozen.update({
            "acquire_operation_id": production_context.acquire_operation_id,
            "original_operation_id": production_context.job.operation_id,
            "work_kind": production_context.job.work_kind,
            "worker_fence": production_context.job.fence,
            "worker_lease_expires_utc": production_context.job.lease_expires_utc,
            "clock_epoch": production_context.clock_epoch,
        })
    if baseline is not None:
        frozen["baseline"] = asdict(baseline)
    request_json = canonical_serialize(frozen)
    if len(request_json.encode("utf-8")) > 131_072:
        raise ValueError("encoding request exceeds durable binding limit")
    return EncodingCallBinding(
        namespace, job_id, source_id, source_revision, access_revision,
        budget_lease_id, budget_reservation_operation_id,
        canonical_digest(frozen), request.digest, request.call_id, request_json,
    )


def load_binding(db, namespace: NamespaceId, job_id: str) -> EncodingCallBinding | None:
    from ..runtime_contracts import canonical_digest

    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3
    from ..runtime_contracts import canonical_serialize
    columns=('source_id','source_revision','access_revision','budget_lease_id',
        'budget_reservation_operation_id','binding_digest','model_request_digest','call_id','request_json')
    row = _producer_original_point_v3(db,table='runtime_encoding_call_bindings_v1',columns=columns,
        key_columns=('bot','persona','job_id'),key=namespace.as_tuple+(job_id,),legacy_reader=lambda:db.execute(
            'SELECT '+','.join(columns)+' FROM runtime_encoding_call_bindings_v1 WHERE bot=? AND persona=? AND job_id=?',
            namespace.as_tuple+(job_id,)).fetchone())
    if row is None:
        return None
    if type(row[-1]) is not str:
        row=(*row[:-1],canonical_serialize(background_json_loads_v3(row[-1])))
    binding = EncodingCallBinding(namespace, job_id, *row)
    _validate_binding_content(binding)
    return binding


def _validate_binding_content(binding: EncodingCallBinding) -> None:
    from ..graph_types import AtomKey
    from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

    request = binding.request
    schema = request.get("schema")
    if schema not in {"sylanne.first-ingress-encoding-call.v1",
                      "sylanne.first-ingress-encoding-call.v2",
                      "sylanne.first-ingress-encoding-call.v3"}:
        raise EncodingCallConflict("unknown encoding request binding schema")
    if schema in {"sylanne.first-ingress-encoding-call.v2",
                  "sylanne.first-ingress-encoding-call.v3"}:
        try:
            envelope = request["envelope"]
            identity = envelope["identity"]
            authority = envelope["authority"]
            if (type(request["acquire_operation_id"]) is not str
                    or not request["acquire_operation_id"]
                    or request["acquire_operation_id"] != identity["operation_id"]
                    or type(request["original_operation_id"]) is not str
                    or not request["original_operation_id"]
                    or request["original_operation_id"]
                    != request["budget_reservation_operation_id"]
                    or request["work_kind"] != "d06.encode_source"
                    or type(request["clock_epoch"]) is not str
                    or not request["clock_epoch"]
                    or type(request["worker_lease_expires_utc"]) is not str
                    or not request["worker_lease_expires_utc"]
                    or type(request["worker_fence"]) is not int
                    or request["worker_fence"] < 1
                    or request["worker_fence"] != authority["worker_fence"]
                    or authority["purpose"] != "consolidation"
                    or "activity" not in authority["owner_scope"]
                    or identity["phase"] != "encode"
                    or type(envelope["character_interval_ref"]) is not str
                    or not envelope["character_interval_ref"]
                    or type(envelope["monotonic_deadline"]) not in (int, float)
                    or not math.isfinite(envelope["monotonic_deadline"])):
                raise ValueError("production context differs")
        except (KeyError, TypeError, ValueError) as exc:
            raise EncodingCallConflict("production encoding context is incomplete") from exc
    if schema == "sylanne.first-ingress-encoding-call.v3":
        try:
            baseline = CommittedEncodingBaselineV1(**request["baseline"])
            baseline_key = AtomKey.from_token(baseline.baseline_ref)
            guarded = request["envelope"]["version_guard"]["read_versions"]
            if (NamespaceId.from_key(baseline_key) != binding.namespace
                    or sum(item["key"] == json.loads(canonical_serialize(
                        baseline_key)) and item["revision"] == baseline.baseline_revision
                           for item in guarded) != 1):
                raise ValueError("baseline guard differs")
        except (KeyError, TypeError, ValueError) as exc:
            raise EncodingCallConflict("V3 committed baseline identity differs") from exc
    elif "baseline" in request:
        raise EncodingCallConflict("legacy binding cannot claim a D04 baseline")
    try:
        model_digest = canonical_digest({
            "envelope": request["envelope"],
            "call_id": request["call_id"],
            "provider_id": request["provider_id"],
            "model_id": request["model_id"],
            "purpose": request["envelope"]["authority"]["purpose"],
            "required_capabilities": request["required_capabilities"],
            "privacy_tier": request["privacy_tier"],
            "template": request["prompt_template_digest"],
            "payload": request["payload"],
            "timeout_seconds": request["timeout_seconds"],
            "max_output_tokens": request["max_output_tokens"],
        })
    except (KeyError, TypeError, ValueError) as exc:
        raise EncodingCallConflict("encoding model request is incomplete") from exc
    if (canonical_digest(request) != binding.binding_digest
            or request.get("namespace") != list(binding.namespace.as_tuple)
            or request.get("job_id") != binding.job_id
            or request.get("call_id") != binding.call_id
            or request.get("source_id") != binding.source_id
            or request.get("source_revision") != binding.source_revision
            or request.get("access_revision") != binding.access_revision
            or request.get("budget_lease_id") != binding.budget_lease_id
            or request.get("budget_reservation_operation_id")
            != binding.budget_reservation_operation_id
            or request.get("model_request_digest") != binding.model_request_digest
            or model_digest != binding.model_request_digest):
        raise EncodingCallConflict("encoding request binding content is inconsistent")


def insert_binding(db, binding: EncodingCallBinding) -> EncodingCallBinding:
    """Insert inside the coordinator's graph transaction, or replay exactly."""
    if type(binding) is not EncodingCallBinding:
        raise TypeError("typed encoding call binding required")
    _validate_binding_content(binding)
    if db.execute(
        "SELECT 1 FROM runtime_encoding_call_redactions_v1 "
        "WHERE bot=? AND persona=? AND source_id=? LIMIT 1",
        binding.namespace.as_tuple + (binding.source_id,),
    ).fetchone():
        raise EncodingCallConflict("erased source cannot regain an encoding request")
    if db.execute(
        "SELECT 1 FROM runtime_encoding_call_redactions_v1 "
        "WHERE bot=? AND persona=? AND call_id=? LIMIT 1",
        binding.namespace.as_tuple + (binding.call_id,),
    ).fetchone():
        raise EncodingCallConflict("erased call ID cannot be reused")
    prior = load_binding(db, binding.namespace, binding.job_id)
    if prior is not None:
        if prior != binding:
            raise EncodingCallConflict("encoding job already has a different request")
        return prior
    other = db.execute(
        "SELECT job_id FROM runtime_encoding_call_bindings_v1 "
        "WHERE bot=? AND persona=? AND call_id=?",
        binding.namespace.as_tuple + (binding.call_id,),
    ).fetchone()
    if other is not None:
        raise EncodingCallConflict("encoding call ID already belongs to another job")
    db.execute(
        "INSERT INTO runtime_encoding_call_bindings_v1"
        "(bot,persona,job_id,call_id,source_id,source_revision,access_revision,"
        "budget_lease_id,budget_reservation_operation_id,binding_digest,"
        "model_request_digest,request_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        binding.namespace.as_tuple + (binding.job_id, binding.call_id,
            binding.source_id, binding.source_revision, binding.access_revision,
            binding.budget_lease_id, binding.budget_reservation_operation_id,
            binding.binding_digest, binding.model_request_digest,
            binding.request_json),
    )
    return binding


def _redact_source_binding_content_in_transaction(
    db, namespace: NamespaceId, source_id: str, deletion_operation_id: str,
) -> int:
    """D12-only storage facet. Caller must hold the graph lock and verified barrier.

    This primitive intentionally has no coordinator entrypoint until the D12
    fence-bound cleanup authority exists. The caller owns commit/rollback.
    """
    from ..runtime_contracts import NamespaceId

    if not db.in_transaction:
        raise RuntimeError("encoding redaction requires an existing graph transaction")
    if type(namespace) is not NamespaceId or any(
            type(value) is not str or not value
            for value in (source_id, deletion_operation_id)):
        raise ValueError("redaction requires exact namespace, source and deletion identity")
    prior = db.execute(
        "SELECT DISTINCT deletion_operation_id FROM runtime_encoding_call_redactions_v1 "
        "WHERE bot=? AND persona=? AND source_id=?",
        namespace.as_tuple + (source_id,),
    ).fetchall()
    if any(row[0] != deletion_operation_id for row in prior):
        raise EncodingCallConflict("source redaction belongs to another deletion")
    intent_rows = db.execute(
        "SELECT acquire_operation_id,job_id,encoding_binding_json "
        "FROM graph_job_acquire_intents_v2 WHERE bot=? AND persona=? "
        "AND encoding_binding_json IS NOT NULL",
        namespace.as_tuple,
    ).fetchall()
    matching = []
    for operation_id, job_id, frozen_json in intent_rows:
        binding = binding_from_json(frozen_json)
        if binding.source_id != source_id:
            continue
        if binding.namespace != namespace or binding.job_id != job_id:
            raise EncodingCallConflict("source redaction found a mismatched intent")
        matching.append((operation_id, binding))
    bound_rows = db.execute(
        "SELECT job_id FROM runtime_encoding_call_bindings_v1 "
        "WHERE bot=? AND persona=? AND source_id=?",
        namespace.as_tuple + (source_id,),
    ).fetchall()
    for (job_id,) in bound_rows:
        bound = load_binding(db, namespace, job_id)
        if not any(binding == bound for _, binding in matching):
            raise EncodingCallConflict("bound request has no matching frozen intent")
    for operation_id, binding in matching:
        db.execute(
            "INSERT INTO runtime_encoding_call_redactions_v1"
            "(bot,persona,acquire_operation_id,job_id,source_id,call_id,"
            "binding_digest,model_request_digest,deletion_operation_id) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            namespace.as_tuple + (operation_id, binding.job_id,
                binding.source_id, binding.call_id, binding.binding_digest,
                binding.model_request_digest, deletion_operation_id),
        )
        db.execute(
            "UPDATE graph_job_acquire_intents_v2 SET encoding_binding_json=NULL "
            "WHERE bot=? AND persona=? AND acquire_operation_id=? "
            "AND encoding_binding_json=?",
            namespace.as_tuple + (operation_id, binding_to_json(binding)),
        )
    db.execute(
        "DELETE FROM runtime_encoding_call_bindings_v1 "
        "WHERE bot=? AND persona=? AND source_id=?",
        namespace.as_tuple + (source_id,),
    )
    return len(matching)
