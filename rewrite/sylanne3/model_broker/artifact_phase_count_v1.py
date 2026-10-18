"""Closed artifact-phase count contracts and the shared Chat Completions body.

These values confer no model, source, budget or egress authority. Only the
actual installed provider and its protected counter identity are accepted.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import math

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .artifact_draft_v1 import TEMPLATE_VERSION_V2

POLICY_SCHEMA = "sylanne.artifact-phase-count-policy.v1"
REQUEST_SCHEMA = "sylanne.artifact-phase-count-request.v1"
EVIDENCE_SCHEMA = "sylanne.artifact-phase-count-evidence.v1"
SIGNING_DOMAIN = (EVIDENCE_SCHEMA + "\0").encode()
FIXTURE_PROVIDER = "sylanne.local.phase-counter-fixture.v1"
FIXTURE_MODEL = "finite-ascii-char-v1"
FIXTURE_RULE_ID = "sylanne.fixture.ascii-char-chat.two-message.v1"
# Historical fixture identity is retained only to reject production impersonation.


def _text(value, label):
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError("phase count " + label + " must be bounded text")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("phase count requires an actual SHA-256 commitment")


def _integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 9_000_000_000_000_000:
        raise ValueError("phase count integer quantity is invalid")


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError("phase count requires its original finite time")


@dataclass(frozen=True, slots=True)
class ArtifactPhaseCountPolicyV1:
    source_scope: str
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    profile_id: str
    provider_id: str
    model_id: str
    model_revision: str
    provider_config_digest: str
    template_version: str
    counter_policy_id: str
    counter_policy_version: int
    executable: str
    program_sha256: str
    counter_public_key_hex: str
    tokenizer_path: str
    tokenizer_sha256: str
    applicability_path: str
    applicability_sha256: str
    encoding_rule_id: str
    encoding_rule_sha256: str
    timeout_seconds: int = 60
    schema: str = POLICY_SCHEMA

    def __post_init__(self):
        if (self.schema != POLICY_SCHEMA or self.source_scope != "production"
                or type(self.namespace) is not NamespaceId or self.template_version != TEMPLATE_VERSION_V2):
            raise ValueError("closed installed phase counter identity required")
        for name in ("installation_id", "profile_id", "provider_id", "model_id", "model_revision",
                "counter_policy_id", "executable", "tokenizer_path", "applicability_path", "encoding_rule_id"):
            _text(getattr(self, name), name)
        for name in ("manifest_digest", "provider_config_digest", "program_sha256", "counter_public_key_hex",
                "tokenizer_sha256", "applicability_sha256", "encoding_rule_sha256"):
            _digest(getattr(self, name))
        _integer(self.counter_policy_version, 1)
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 300:
            raise ValueError("phase counter timeout is outside its installed bound")
        for path in (self.executable, self.tokenizer_path, self.applicability_path):
            if not path.startswith("/") or any(part in {".", ".."} for part in path.split("/")):
                raise ValueError("phase counter assets require exact installed absolute Linux paths")
        if (self.provider_id == FIXTURE_PROVIDER
                or self.model_id == FIXTURE_MODEL or self.encoding_rule_id == FIXTURE_RULE_ID):
            raise ValueError("production phase counting rejects the finite fixture identity")

    @property
    def digest(self):
        return canonical_digest(self)


def artifact_phase_counter_policy_from_payload_v1(value):
    """Only the authenticated profile loader may call this parser."""
    if value is None:
        return None
    if type(value) is not dict or set(value) != {f.name for f in fields(ArtifactPhaseCountPolicyV1)}:
        raise ValueError("installed phase counter policy fields differ")
    policy = ArtifactPhaseCountPolicyV1(**{**value, "namespace": NamespaceId(**value["namespace"])})
    return policy


def artifact_phase_provider_request_v1(request, *, billing_policy=None):
    """The exact create() body shared by counting and the actual phase sender."""
    from .artifact_draft_v1 import artifact_draft_provider_messages_v2
    from .provider_billing_receipt_v1 import provider_billing_request_metadata_v1
    return {"model": request.model_id, "messages": artifact_draft_provider_messages_v2(request),
        "stream": False, "max_completion_tokens": request.max_output_tokens,
        **provider_billing_request_metadata_v1(billing_policy, request)}


def phase_provider_wire_digest_v1(provider_request_json):
    if type(provider_request_json) is not str or len(provider_request_json.encode()) > 131072:
        raise ValueError("phase counter requires bounded provider request material")
    raw = json.loads(provider_request_json)
    if (type(raw) is not dict or set(raw) not in ({"model", "messages", "stream", "max_completion_tokens"},
            {"model", "messages", "stream", "max_completion_tokens", "metadata"})
            or canonical_serialize(raw) != provider_request_json or raw["stream"] is not False
            or type(raw["messages"]) is not list or len(raw["messages"]) != 2
            or any(type(message) is not dict for message in raw["messages"])
            or [message.get("role") for message in raw["messages"]] != ["system", "user"]
            or any(set(message) != {"role", "content"} or type(message["content"]) is not str
                for message in raw["messages"])):
        raise ValueError("phase counter wire differs from the exact two-message Chat Completions body")
    _text(raw["model"], "model"); _integer(raw["max_completion_tokens"], 1)
    if raw["max_completion_tokens"] > 2000:
        raise ValueError("phase counting cannot enlarge the original output ceiling")
    if "metadata" in raw and (type(raw["metadata"]) is not dict
            or set(raw["metadata"]) != {"sylanne_call_id", "sylanne_request_digest", "sylanne_billing_contract"}
            or any(type(value) is not str or not value for value in raw["metadata"].values())):
        raise ValueError("phase counter billing metadata differs from the sender")
    return hashlib.sha256(provider_request_json.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ArtifactPhaseCountRequestV1:
    input_kind: str
    policy_digest: str
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    profile_id: str
    provider_id: str
    model_id: str
    model_revision: str
    provider_config_digest: str
    template_version: str
    candidate_parameter_digest: str
    frozen_material_digest: str
    provider_request_json: str
    provider_wire_digest: str
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    source_versions: tuple[tuple[str, int, str], ...]
    read_versions: tuple[tuple[str, int], ...]
    query_coverage_digest: str
    budget_scope_digest: str
    access_epoch: int
    delete_epoch: int
    activation_generation: int
    original_deadline_utc: float
    nonce: str
    frozen_at_utc: float
    schema: str = REQUEST_SCHEMA

    def __post_init__(self):
        if (self.schema != REQUEST_SCHEMA or self.input_kind not in {"prospective", "actual"}
                or type(self.namespace) is not NamespaceId or self.template_version != TEMPLATE_VERSION_V2):
            raise ValueError("phase count request requires its distinct prospective or actual kind")
        for name in ("installation_id", "profile_id", "provider_id", "model_id", "model_revision", "owner_grant_ref"):
            _text(getattr(self, name), name)
        for name in ("policy_digest", "manifest_digest", "provider_config_digest", "candidate_parameter_digest",
                "frozen_material_digest", "provider_wire_digest", "owner_grant_digest", "query_coverage_digest", "budget_scope_digest"):
            _digest(getattr(self, name))
        if phase_provider_wire_digest_v1(self.provider_request_json) != self.provider_wire_digest:
            raise ValueError("phase count request changed its actual provider wire")
        if json.loads(self.provider_request_json)["model"] != self.model_id:
            raise ValueError("phase count request selected another provider model")
        _integer(self.owner_grant_revision, 1); _integer(self.activation_generation, 1)
        _integer(self.access_epoch); _integer(self.delete_epoch)
        _time(self.original_deadline_utc); _time(self.frozen_at_utc)
        if self.frozen_at_utc >= self.original_deadline_utc:
            raise ValueError("phase count cannot refresh its original expired deadline")
        if type(self.nonce) is not str or len(self.nonce) != 32 or any(c not in "0123456789abcdef" for c in self.nonce):
            raise ValueError("phase count requires its exact fresh nonce commitment")
        for versions, length in ((self.source_versions, 3), (self.read_versions, 2)):
            if type(versions) is not tuple or not versions or len(versions) > 1024 or versions != tuple(sorted(versions)):
                raise ValueError("phase count requires canonical current source and Graph read versions")
            if len({item[0] for item in versions}) != len(versions):
                raise ValueError("phase count read commitments repeat a source or head")
            for item in versions:
                if type(item) is not tuple or len(item) != length:
                    raise ValueError("phase count version commitment shape differs")
                _text(item[0], "read ref"); _integer(item[1], 1 if length == 3 else 0)
                if length == 3:
                    _digest(item[2])

    @property
    def digest(self):
        return canonical_digest(self)

    @property
    def scope_digest(self):
        return canonical_digest({"namespace": self.namespace, "owner_grant_ref": self.owner_grant_ref,
            "owner_grant_revision": self.owner_grant_revision, "owner_grant_digest": self.owner_grant_digest,
            "source_versions": self.source_versions, "read_versions": self.read_versions,
            "query_coverage_digest": self.query_coverage_digest, "budget_scope_digest": self.budget_scope_digest,
            "access_epoch": self.access_epoch, "delete_epoch": self.delete_epoch,
            "activation_generation": self.activation_generation})

@dataclass(frozen=True, slots=True)
class ArtifactPhaseCountEvidenceV1:
    source_scope: str
    input_kind: str
    request_digest: str
    policy_digest: str
    provider_wire_digest: str
    candidate_parameter_digest: str
    frozen_material_digest: str
    scope_digest: str
    original_deadline_utc: float
    nonce: str
    counted_at_utc: float
    token_evidence: str
    lower_tokens: int
    upper_tokens: int
    program_sha256: str
    tokenizer_sha256: str
    applicability_sha256: str
    encoding_rule_sha256: str
    schema: str = EVIDENCE_SCHEMA

    def __post_init__(self):
        if (self.schema != EVIDENCE_SCHEMA or self.source_scope != "production"
                or self.input_kind not in {"prospective", "actual"}
                or self.token_evidence not in {"exact_model_input", "bounded_model_input"}):
            raise ValueError("phase count evidence scope, kind or model-input proof differs")
        for name in ("request_digest", "policy_digest", "provider_wire_digest", "candidate_parameter_digest",
                "frozen_material_digest", "scope_digest", "program_sha256", "tokenizer_sha256",
                "applicability_sha256", "encoding_rule_sha256"):
            _digest(getattr(self, name))
        _integer(self.lower_tokens); _integer(self.upper_tokens, 1)
        _time(self.original_deadline_utc); _time(self.counted_at_utc)
        if (self.lower_tokens > self.upper_tokens or self.counted_at_utc >= self.original_deadline_utc
                or self.token_evidence == "exact_model_input" and self.lower_tokens != self.upper_tokens
                or type(self.nonce) is not str or len(self.nonce) != 32
                or any(c not in "0123456789abcdef" for c in self.nonce)):
            raise ValueError("phase count evidence bound, nonce or original deadline is invalid")


def artifact_phase_count_request_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ArtifactPhaseCountRequestV1)}:
        raise ValueError("phase count request fields differ")
    return ArtifactPhaseCountRequestV1(**{**raw, "namespace": NamespaceId(**raw["namespace"]),
        "source_versions": tuple(tuple(item) for item in raw["source_versions"]),
        "read_versions": tuple(tuple(item) for item in raw["read_versions"])})


def artifact_phase_count_evidence_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ArtifactPhaseCountEvidenceV1)}:
        raise ValueError("phase count evidence fields differ")
    return ArtifactPhaseCountEvidenceV1(**raw)


def require_phase_count_request_policy_v1(policy, request):
    if type(policy) is not ArtifactPhaseCountPolicyV1 or type(request) is not ArtifactPhaseCountRequestV1:
        raise TypeError("exact installed phase counter policy and frozen request required")
    if (request.policy_digest, request.namespace, request.installation_id, request.manifest_digest,
            request.profile_id, request.provider_id, request.model_id, request.model_revision,
            request.provider_config_digest, request.template_version) != (policy.digest, policy.namespace,
            policy.installation_id, policy.manifest_digest, policy.profile_id, policy.provider_id,
            policy.model_id, policy.model_revision, policy.provider_config_digest, policy.template_version):
        raise ValueError("phase counter request selected another installed identity")


def artifact_phase_prospective_provider_request_v1(*, model_id, prospective_input_json, max_output_tokens):
    """Hypothetical quotation material; never an actual adopted model request."""
    from .artifact_draft_v1 import SYSTEM_MESSAGE_V2
    material = json.loads(prospective_input_json)
    if (type(material) is not dict or material.get("schema") != "d08.prospective-personal-candidate-input.v1"
            or material.get("decision_state") != "not_adopted"
            or canonical_serialize(material) != prospective_input_json):
        raise ValueError("phase prospective count must retain its unadopted candidate material")
    body = {"model": model_id, "messages": [{"role": "system", "content": SYSTEM_MESSAGE_V2},
        {"role": "user", "content": prospective_input_json}], "stream": False,
        "max_completion_tokens": max_output_tokens}
    phase_provider_wire_digest_v1(canonical_serialize(body))
    return body