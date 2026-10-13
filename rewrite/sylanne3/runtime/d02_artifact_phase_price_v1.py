"""Owner-adopted, source-free artifact phase pricing from the protected V3 slot."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import secrets
import time
import json
import math

from ..domains.d01.production_operations_v1 import plain_v1, require_locator_v1, stage_result_v1
from ..graph_types import GraphVersion, owner_grant_key
from ..host.authority_profile import AdminArtifactDraftPolicyV3, is_installed_artifact_draft_phase_slot_v2
from ..model_broker.artifact_draft_v1 import TEMPLATE_VERSION_V2, WORK_KIND
from ..model_broker.artifact_phase_count_v1 import ArtifactPhaseCountRequestV1
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1, table_exists_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionPolicyRefV1, StagedDomainOperationV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1

POLICY_KIND = "artifact_phase_price"
PRODUCER_KIND = "register_artifact_phase_price_policy"
OPERATION_KIND = "input:" + PRODUCER_KIND
SIGN_KIND = "d11.d02-production-policy.v1"
TABLE = "graph_d02_production_policies_v1"
DIMENSIONS = frozenset({"input_tokens", "output_tokens", "model_tokens", "model_microusd"})


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("artifact phase policy requires an actual digest")


@dataclass(frozen=True, slots=True)
class RegisterCurrentArtifactPhasePricePolicyRequestV1:
    policy_ref: str
    expected_revision: int
    installation_id: str
    manifest_digest: str
    profile_id: str
    provider_config_digest: str
    template_version: str

    def __post_init__(self):
        for value in (self.policy_ref, self.installation_id, self.profile_id):
            require_locator_v1(value, "phase price policy selector")
        _digest(self.manifest_digest); _digest(self.provider_config_digest)
        if (type(self.expected_revision) is not int or self.expected_revision < 0
                or self.template_version != TEMPLATE_VERSION_V2):
            raise ValueError("phase price request requires its exact V2 template and revision CAS")


@dataclass(frozen=True, slots=True)
class ArtifactPhasePricePolicyV1:
    policy_ref: str
    revision: int
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    profile_id: str
    producing_operation_id: str
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    work_kind: str
    template_version: str
    provider_id: str
    model_id: str
    provider_config_ref: str
    provider_config_digest: str
    workflow_digest: str
    resource_ref: str
    quote_ceiling: tuple[tuple[str, int], ...]
    max_output_tokens: int
    valid_until_utc: float
    counting_policy_ref: str
    counting_policy_version: str
    counting_mode: str
    schema: str = "d02.artifact-phase-price-policy.v1"

    def __post_init__(self):
        if (self.schema != "d02.artifact-phase-price-policy.v1" or type(self.namespace) is not NamespaceId
                or type(self.revision) is not int or self.revision < 1
                or type(self.owner_grant_revision) is not int or self.owner_grant_revision < 1
                or self.work_kind != WORK_KIND or self.template_version != TEMPLATE_VERSION_V2
                or type(self.quote_ceiling) is not tuple or self.quote_ceiling != tuple(sorted(self.quote_ceiling))
                or set(dict(self.quote_ceiling)) != DIMENSIONS or len(self.quote_ceiling) != 4
                or any(type(amount) is not int or amount < 0 for _, amount in self.quote_ceiling)
                or type(self.max_output_tokens) is not int or self.max_output_tokens < 1
                or type(self.valid_until_utc) not in (int, float) or not math.isfinite(self.valid_until_utc)
                or self.valid_until_utc <= 0 or self.counting_mode not in {"unavailable", "signed_phase_counter"}):
            raise ValueError("closed protected artifact phase price policy required")
        for name in ("policy_ref", "installation_id", "profile_id", "producing_operation_id", "owner_grant_ref",
                "provider_id", "model_id", "provider_config_ref", "resource_ref", "counting_policy_ref", "counting_policy_version"):
            require_locator_v1(getattr(self, name), name)
        for name in ("manifest_digest", "owner_grant_digest", "provider_config_digest", "workflow_digest"):
            _digest(getattr(self, name))
        ceiling = dict(self.quote_ceiling)
        if (ceiling["input_tokens"] > 10000 or ceiling["output_tokens"] > 2000
                or self.max_output_tokens > ceiling["output_tokens"]
                or ceiling["model_tokens"] > 12000):
            raise ValueError("phase price policy exceeds its original finite token ceilings")


def _installed_bundle(installed_readers):
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    from .d08_personal_candidate_v1 import InstalledPersonalCandidateReadersV1
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    if type(installed_readers) is InstalledD02ProductionReadersV1:
        graph = installed_readers.role_clock_reader.graph
    elif type(installed_readers) is InstalledPersonalCandidateReadersV1:
        graph = installed_readers.current().graph
    elif type(installed_readers) is InstalledArtifactDraftModelReadersV1:
        runtime = installed_readers.model_runtime
        if runtime is None:
            raise MissingProductionOriginalV1("actual_installed_phase_model_runtime")
        graph = runtime.graph
        graph._admin(runtime.bootstrap)
        if (runtime is not graph._GraphCoordinator__artifact_draft_model_runtime_v1
                or runtime.bundle is not installed_readers.installed_bundle):
            raise ValueError("actual phase counter model runtime or bundle identity changed")
    else:
        raise TypeError("phase price requires actual installed D02, candidate or phase model readers")
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or type(assembly.admin_bundle.artifact_draft) is not AdminArtifactDraftPolicyV3:
        raise MissingProductionOriginalV1("installed_actual_v3_artifact_phase_workflow")
    bundle = assembly.admin_bundle
    workflow = bundle.artifact_draft.phase_model_workflow
    if (not is_installed_artifact_draft_phase_slot_v2(bundle, workflow)
            or installed_readers.issuer is not graph._GraphCoordinator__d11_issuer):
        raise ValueError("phase price installation/signer identity changed")
    return bundle, workflow


def _derive_policy(db, *, frame, request, installed_readers):
    if type(request) is not RegisterCurrentArtifactPhasePricePolicyRequestV1:
        raise TypeError("exact selector-only phase price request required")
    read = CurrentDomainReadV1(frame); read.check(db)
    bundle, workflow = _installed_bundle(installed_readers)
    installation = bundle.installation_policy
    if ((request.installation_id, request.manifest_digest, request.profile_id, request.provider_config_digest,
            request.template_version) != (installation.installation_id, installation.manifest_digest,
            bundle.tls_profile.profile_id, workflow.provider_config_digest, workflow.template_version)
            or installation.namespace != frame.envelope.authority.namespace):
        raise ValueError("phase price selectors differ from the actual protected installation")
    if not table_exists_v1(db, TABLE):
        raise MissingProductionOriginalV1("installed_d02_production_policy_schema")
    prior = db.execute("SELECT max(revision) FROM " + TABLE + " WHERE bot=? AND persona=? AND policy_ref=?",
        (*installation.namespace.as_tuple, request.policy_ref)).fetchone()[0] or 0
    if prior != request.expected_revision:
        raise MissingProductionOriginalV1("current_artifact_phase_price_policy_revision_cas")
    guard = frame.owner_guard
    ceiling = dict(workflow.quote_ceiling)
    if set(ceiling) != DIMENSIONS:
        raise ValueError("phase workflow requires actual four-dimensional price ceilings")
    ceiling["output_tokens"] = min(ceiling["output_tokens"], workflow.max_output_tokens)
    ceiling["model_tokens"] = min(ceiling["model_tokens"], ceiling["input_tokens"] + ceiling["output_tokens"])
    deadline = min(installation.root_grant.valid_until_utc, bundle.artifact_draft.standing_scope.valid_until_utc)
    if frame.now_utc >= deadline:
        raise MissingProductionOriginalV1("current_unexpired_artifact_phase_price_installation")
    configured_counter = getattr(bundle, "artifact_phase_counter", None)
    counter = _installed_phase_count_policy_v1(installed_readers) if configured_counter is not None else None
    return ArtifactPhasePricePolicyV1(request.policy_ref, prior + 1, installation.namespace,
        installation.installation_id, installation.manifest_digest, bundle.tls_profile.profile_id,
        frame.envelope.identity.operation_id, guard.grant_ref, guard.grant_revision, guard.grant_digest,
        workflow.work_kind, workflow.template_version, workflow.provider_id, workflow.model_id,
        workflow.provider_config_ref, workflow.provider_config_digest, canonical_digest(plain_v1(workflow)),
        workflow.provider_config_ref, tuple(sorted(ceiling.items())), workflow.max_output_tokens, deadline,
        "artifact-phase-counter:" + counter.digest if counter is not None else "d02.artifact-phase-counter:unavailable",
        str(counter.counter_policy_version) if counter is not None else "unavailable.v1",
        "signed_phase_counter" if counter is not None else "unavailable")


def stage_register_current_artifact_phase_price_policy_in_transaction_v1(db, *, frame, request, installed_readers):
    policy = _derive_policy(db, frame=frame, request=request, installed_readers=installed_readers)
    return stage_result_v1(frame, "d02", OPERATION_KIND, request,
        provenance={"artifact_phase_price_policy": policy})


def record_current_artifact_phase_price_policy_after_commit_v1(db, *, frame, request, stage, actual_receipt, installed_readers):
    if (type(stage) is not StagedDomainOperationV1 or type(actual_receipt) is not CommitReceipt
            or actual_receipt.status != "committed" or stage.domain != "d02" or stage.operation_kind != OPERATION_KIND
            or stage.operation_id != actual_receipt.operation_id or stage.activity_id != actual_receipt.activity_id
            or stage.namespace != frame.envelope.authority.namespace):
        raise ValueError("phase policy requires its actual same-transaction adoption")
    actual = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*stage.namespace.as_tuple, stage.operation_id)).fetchone()
    if actual != (actual_receipt.operation_digest, actual_receipt.activity_id, actual_receipt.effect_id, actual_receipt.commit_seq):
        raise ValueError("phase policy receipt differs from its actual bundle")
    policy = _derive_policy(db, frame=frame, request=request, installed_readers=installed_readers)
    payload = json.loads(stage.original_payload_json)
    if (payload["request"] != plain_v1(request)
            or payload["provenance"]["artifact_phase_price_policy"] != plain_v1(policy)
            or canonical_digest(payload) != stage.original_digest):
        raise ValueError("phase policy stage differs from its protected post-CAS derivation")
    encoded = canonical_serialize(plain_v1(policy)); digest = canonical_digest(plain_v1(policy))
    signature = installed_readers.issuer._signer.sign(SIGN_KIND, encoded)
    db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (*policy.namespace.as_tuple, policy.policy_ref, policy.revision, POLICY_KIND, policy.profile_id,
         None, None, encoded, digest, signature))
    return (ProductionOriginalRefV1("d02.installed_policy", policy.policy_ref, digest),)

def read_current_artifact_phase_price_policy_v1(db, *, frame, installed_readers, policy_ref=None):
    """Authenticate the latest same-grant installed policy and its real adoption."""
    read = CurrentDomainReadV1(frame); read.check(db)
    bundle, workflow = _installed_bundle(installed_readers)
    installation = bundle.installation_policy
    if not table_exists_v1(db, TABLE):
        raise MissingProductionOriginalV1("installed_artifact_phase_price_policy")
    rows = db.execute("SELECT policy_ref,revision,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=?" + (" AND policy_ref=?" if policy_ref is not None else "") +
        " ORDER BY policy_ref,revision DESC", (*installation.namespace.as_tuple, POLICY_KIND,
            *((policy_ref,) if policy_ref is not None else ()))).fetchall()
    latest = {}
    for row in rows:
        latest.setdefault(row[0], row)
    if len(latest) != 1:
        raise MissingProductionOriginalV1("unique_actual_artifact_phase_price_policy")
    ref, revision, encoded, digest, signature = next(iter(latest.values()))
    installed_readers.issuer._signer.verify(SIGN_KIND, encoded, signature)
    raw = json.loads(encoded)
    if canonical_serialize(raw) != encoded or canonical_digest(raw) != digest:
        raise ValueError("artifact phase signed policy original changed")
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    policy = decode_typed_production_value_v1(raw, ArtifactPhasePricePolicyV1)
    guard = frame.owner_guard
    if ((policy.policy_ref, policy.revision, policy.namespace, policy.installation_id, policy.manifest_digest,
            policy.profile_id, policy.owner_grant_ref, policy.owner_grant_revision, policy.owner_grant_digest,
            policy.workflow_digest, policy.provider_config_digest) != (ref, revision,
            frame.envelope.authority.namespace, installation.installation_id, installation.manifest_digest,
            bundle.tls_profile.profile_id, guard.grant_ref, guard.grant_revision, guard.grant_digest,
            canonical_digest(plain_v1(workflow)), workflow.provider_config_digest)
            or frame.now_utc >= policy.valid_until_utc):
        raise MissingProductionOriginalV1("current_same_grant_unexpired_artifact_phase_price_policy")
    pin = ProductionPolicyRefV1(ref, revision, digest)
    if pin not in frame.installed_policy_refs:
        raise MissingProductionOriginalV1("current_installed_artifact_phase_price_policy_pin")
    original = read.original(ref, kind="d02.installed_policy", digest=digest)
    adopted = read_adopted_domain_operation_v1(db, policy.namespace, policy.producing_operation_id)
    if (adopted is None or (adopted["domain"], adopted["operation_kind"]) != ("d02", OPERATION_KIND)
            or adopted["payload"]["provenance"].get("artifact_phase_price_policy") != raw):
        raise MissingProductionOriginalV1("actual_adopted_artifact_phase_price_policy")
    return policy, pin, original


class InstalledArtifactPhasePriceReaderV1:
    """Default production reader. Missing actual counter remains missing."""
    def __init__(self, readers, count_materials=()):
        from .d08_personal_candidate_v1 import InstalledPersonalCandidateReadersV1
        if type(readers) is not InstalledPersonalCandidateReadersV1:
            raise TypeError("phase price reader requires the actual candidate installation")
        self.readers = readers.current()
        from ..model_broker.artifact_phase_count_v1 import ArtifactPhaseCountRequestV1
        if (type(count_materials) is not tuple or len(count_materials) > 6
                or any(type(item) is not tuple or len(item) != 2 or type(item[0]) is not ArtifactPhaseCountRequestV1
                    or type(item[1]) is not str or canonical_serialize(json.loads(item[1])) != item[1]
                    for item in count_materials)):
            raise TypeError("phase price reader accepts only bounded signed count material tuples")
        self.count_materials = count_materials

    def read_plan_inputs_v1(self, *, db, namespace, activity_id, request):
        self.readers.current()
        refs = ()
        if table_exists_v1(db, TABLE):
            refs = tuple(row[0] for row in db.execute("SELECT DISTINCT policy_ref FROM " + TABLE +
                " WHERE bot=? AND persona=? AND kind=? ORDER BY policy_ref LIMIT 2",
                (*namespace.as_tuple, POLICY_KIND)).fetchall())
        if len(refs) > 1:
            raise MissingProductionOriginalV1("unique_actual_artifact_phase_price_policy")
        return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple),), (), refs)

    def __call__(self, *, db, frame, binding, plan, goal, need, prospective_input_json,
            prospective_input_digest, future_identity):
        from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
        if type(binding) not in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3} or binding.phase_kind not in {"tone_sample", "full"}:
            raise ValueError("artifact phase pricing cannot price another candidate/template")
        self.readers.current()
        policy, pin, original = read_current_artifact_phase_price_policy_v1(db, frame=frame,
            installed_readers=self.readers)
        if (type(prospective_input_json) is not str or canonical_serialize(json.loads(prospective_input_json)) != prospective_input_json
                or canonical_digest(json.loads(prospective_input_json)) != prospective_input_digest):
            raise ValueError("phase counter must bind the actual serialized prospective input")
        material = json.loads(prospective_input_json)
        _require_v3_phase_count_basis_v1(db, frame=frame, binding=binding, material=material,
            original_deadline_utc=future_identity.deadline_utc, installed_readers=self.readers)
        if (material.get("binding") != plain_v1(binding)
                or material.get("deadline_utc") != future_identity.deadline_utc
                or material.get("parent_budget_lease_ref") != future_identity.parent_budget_lease_ref
                or frame.now_utc >= future_identity.deadline_utc):
            raise ValueError("phase count material differs from current candidate parameters")
        if policy.counting_mode == "unavailable":
            raise MissingProductionOriginalV1("installed_actual_artifact_phase_serialized_input_counter")
        selected = tuple(item for item in self.count_materials if item[0].input_kind == "prospective"
            and item[0].candidate_parameter_digest == binding.digest
            and item[0].frozen_material_digest == prospective_input_digest)
        if len(selected) != 1:
            raise MissingProductionOriginalV1("actual_signed_current_prospective_phase_count")
        count_request, encoded_envelope = selected[0]
        return read_current_artifact_phase_price_with_count_v1(db, frame=frame, binding=binding,
            prospective_input_json=prospective_input_json, prospective_input_digest=prospective_input_digest,
            future_identity=future_identity, count_request=count_request, envelope=json.loads(encoded_envelope),
            installed_readers=self.readers)

    def count_provenance_for_candidate_v1(self, *, binding, prospective_input_digest):
        """W01 seals these exact signed bytes in its existing candidate stage."""
        selected = tuple(item for item in self.count_materials if item[0].input_kind == "prospective"
            and item[0].candidate_parameter_digest == binding.digest
            and item[0].frozen_material_digest == prospective_input_digest)
        if len(selected) != 1:
            raise MissingProductionOriginalV1("actual_signed_current_prospective_phase_count")
        return {"count_request": plain_v1(selected[0][0]), "signed_envelope": json.loads(selected[0][1])}


def install_artifact_phase_price_reader_v1(*, readers, count_materials=()):
    return InstalledArtifactPhasePriceReaderV1(readers, count_materials)

def _phase_count_scope_v1(frame):
    sources = tuple(sorted((atom.key.token, atom.revision, canonical_digest(atom.value))
        for atom in frame.snapshot.atoms if atom.key.type_name == "memory.source" and atom.valid))
    reads = tuple(sorted((version.key.token, version.revision) for version in frame.snapshot.versions))
    coverage = canonical_digest(tuple({"type_id": page.type_id, "row_versions": page.row_versions,
        "complete": page.complete, "continuation_ref": page.continuation_ref} for page in frame.query_coverage))
    return sources, reads, coverage


def _installed_phase_count_policy_v1(installed_readers):
    from ..model_broker.artifact_phase_count_v1 import ArtifactPhaseCountPolicyV1
    bundle, workflow = _installed_bundle(installed_readers)
    policy = getattr(bundle, "artifact_phase_counter", None)
    if policy is None:
        raise MissingProductionOriginalV1("installed_actual_artifact_phase_serialized_input_counter")
    if type(policy) is not ArtifactPhaseCountPolicyV1:
        raise TypeError("phase prices reject unknown installed counter policies")
    if policy.source_scope == "LOCAL_FIXTURE":
        _phase_count_allows_fixture_v1(installed_readers)
    if (policy.namespace, policy.installation_id, policy.manifest_digest, policy.profile_id,
            policy.provider_id, policy.model_id, policy.provider_config_digest, policy.template_version) != (
            bundle.installation_policy.namespace, bundle.installation_policy.installation_id,
            bundle.installation_policy.manifest_digest, bundle.tls_profile.profile_id, workflow.provider_id,
            workflow.model_id, workflow.provider_config_digest, workflow.template_version):
        raise ValueError("phase counter policy differs from the actual installed workflow")
    return policy


def freeze_artifact_phase_count_request_in_transaction_v1(db, *, frame, binding, input_kind,
        frozen_material_digest, provider_request_json, original_deadline_utc, nonce, installed_readers):
    """Freeze only current authorized material; execute the counter after tx exit."""
    from ..model_broker.artifact_phase_count_v1 import ArtifactPhaseCountRequestV1, phase_provider_wire_digest_v1
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    if type(binding) not in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
        raise TypeError("phase counter freezes its exact artifact candidate binding")
    read = CurrentDomainReadV1(frame); read.check(db)
    policy = _installed_phase_count_policy_v1(installed_readers)
    if policy.namespace != frame.envelope.authority.namespace or binding.task.namespace != policy.namespace:
        raise ValueError("phase counter cannot cross its actual namespace/task installation")
    sources, reads, coverage = _phase_count_scope_v1(frame)
    read.source_family(db, tuple(ref for ref, _, _ in sources), purpose="consolidation")
    provider = json.loads(provider_request_json)
    user = json.loads(provider["messages"][1]["content"])
    if input_kind == "prospective":
        if (user.get("schema") != "d08.prospective-personal-candidate-input.v1"
                or user.get("decision_state") != "not_adopted" or user.get("binding") != plain_v1(binding)
                or canonical_digest(user) != frozen_material_digest or user.get("deadline_utc") != original_deadline_utc):
            raise ValueError("phase prospective count changed its actual candidate material")
    elif input_kind == "actual":
        if (user.get("schema") != "sylanne.artifact-draft-phase-input.v2"
                or user.get("input_digest") != frozen_material_digest
                or canonical_digest(user.get("input")) != frozen_material_digest
                or type(user["input"].get("deadline_utc")) not in (int, float)
                or user["input"]["deadline_utc"] < original_deadline_utc):
            raise ValueError("actual phase count changed its independently frozen model input")
    else:
        raise ValueError("unrecognized artifact phase count purpose")
    frozen = None
    if input_kind == "actual":
        from ..model_broker.artifact_draft_v1 import artifact_draft_input_from_wire_v2
        frozen = artifact_draft_input_from_wire_v2(user["input"])
        if user != frozen.wire or frozen.digest != frozen_material_digest:
            raise ValueError("actual phase count must use the closed current frozen input wire")
    _require_v3_phase_count_basis_v1(db, frame=frame, binding=binding,
        material=user if input_kind == "prospective" else None, frozen=frozen,
        original_deadline_utc=original_deadline_utc, installed_readers=installed_readers)
    if (original_deadline_utc > frame.envelope.deadline_utc or frame.now_utc >= original_deadline_utc
            or provider["model"] != policy.model_id):
        raise ValueError("phase count cannot extend the actual model/deadline scope")
    guard = frame.owner_guard
    return ArtifactPhaseCountRequestV1(input_kind, policy.digest, policy.namespace, policy.installation_id,
        policy.manifest_digest, policy.profile_id, policy.provider_id, policy.model_id, policy.model_revision,
        policy.provider_config_digest, policy.template_version, binding.digest, frozen_material_digest,
        provider_request_json, phase_provider_wire_digest_v1(provider_request_json), guard.grant_ref,
        guard.grant_revision, guard.grant_digest, sources, reads, coverage,
        _current_phase_count_budget_scope_v1(db, frame=frame, installed_readers=installed_readers)[0],
        frame.envelope.version_guard.access_epoch, frame.envelope.version_guard.delete_epoch,
        frame.activation_generation, original_deadline_utc, nonce, frame.now_utc)


def require_current_artifact_phase_count_in_transaction_v1(db, *, frame, binding, count_request,
        envelope, frozen_material_digest, provider_request_json, original_deadline_utc, input_kind,
        installed_readers):
    """Current short acceptance; caller still owns its budget and final CAS."""
    from ..model_broker.artifact_phase_count_v1 import phase_provider_wire_digest_v1
    from ..authority_service.artifact_phase_counter_v1 import verify_artifact_phase_count_envelope_v1
    read = CurrentDomainReadV1(frame); read.check(db)
    policy = _installed_phase_count_policy_v1(installed_readers)
    evidence = verify_artifact_phase_count_envelope_v1(policy, count_request, envelope, now_utc=frame.now_utc,
        allow_local_fixture=_phase_count_allows_fixture_v1(installed_readers))
    sources, reads, coverage = _phase_count_scope_v1(frame)
    from ..model_broker.artifact_draft_v1 import artifact_draft_input_from_wire_v2
    user = json.loads(json.loads(provider_request_json)["messages"][1]["content"])
    _require_v3_phase_count_basis_v1(db, frame=frame, binding=binding,
        material=user if input_kind == "prospective" else None,
        frozen=artifact_draft_input_from_wire_v2(user["input"]) if input_kind == "actual" else None,
        original_deadline_utc=original_deadline_utc, installed_readers=installed_readers)
    guard = frame.owner_guard
    if (count_request.input_kind, count_request.candidate_parameter_digest, count_request.frozen_material_digest,
            count_request.provider_request_json, count_request.provider_wire_digest, count_request.owner_grant_ref,
            count_request.owner_grant_revision, count_request.owner_grant_digest, count_request.source_versions,
            count_request.read_versions, count_request.query_coverage_digest, count_request.access_epoch,
            count_request.delete_epoch, count_request.activation_generation, count_request.original_deadline_utc) != (
            input_kind, binding.digest, frozen_material_digest, provider_request_json,
            phase_provider_wire_digest_v1(provider_request_json), guard.grant_ref, guard.grant_revision,
            guard.grant_digest, sources, reads, coverage, frame.envelope.version_guard.access_epoch,
            frame.envelope.version_guard.delete_epoch, frame.activation_generation, original_deadline_utc):
        raise MissingProductionOriginalV1("current_same_owner_source_read_scope_and_phase_count")
    read.source_family(db, tuple(ref for ref, _, _ in sources), purpose="consolidation")
    from .budget import get_budget_lease, require_budget_family_admissible
    require_budget_family_admissible(db, frame.envelope.parent_budget_lease_ref)
    grant = installed_readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    lease = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    if (frame.now_utc >= grant.valid_until_utc or count_request.budget_scope_digest !=
            _current_phase_count_budget_scope_v1(db, frame=frame, installed_readers=installed_readers)[0]):
        raise MissingProductionOriginalV1("current_original_phase_count_budget_scope_and_deadline")
    return policy, evidence, grant, lease


def read_current_artifact_phase_price_with_count_v1(db, *, frame, binding, prospective_input_json,
        prospective_input_digest, future_identity, count_request, envelope, installed_readers):
    from ..domains.d08.personal_candidate_v1 import CurrentPersonalCandidatePriceV1
    from ..model_broker.artifact_phase_count_v1 import artifact_phase_prospective_provider_request_v1
    from ..model_broker.artifact_draft_v1 import PHASE_TOKEN_CEILINGS_V2
    policy, pin, original = read_current_artifact_phase_price_policy_v1(db, frame=frame,
        installed_readers=installed_readers)
    counter = _installed_phase_count_policy_v1(installed_readers)
    if (policy.counting_mode != "signed_phase_counter" or policy.counting_policy_ref != "artifact-phase-counter:" + counter.digest
            or policy.counting_policy_version != str(counter.counter_policy_version)):
        raise MissingProductionOriginalV1("current_adopted_actual_phase_counter_price_policy")
    input_limit, output_limit = next((inp, out) for kind, inp, out in PHASE_TOKEN_CEILINGS_V2 if kind == binding.phase_kind)
    ceiling = dict(policy.quote_ceiling)
    ceiling["input_tokens"] = min(ceiling["input_tokens"], input_limit)
    ceiling["output_tokens"] = min(ceiling["output_tokens"], output_limit, policy.max_output_tokens)
    ceiling["model_tokens"] = min(ceiling["model_tokens"], ceiling["input_tokens"] + ceiling["output_tokens"])
    provider = artifact_phase_prospective_provider_request_v1(model_id=policy.model_id,
        prospective_input_json=prospective_input_json, max_output_tokens=ceiling["output_tokens"])
    _, evidence, grant, lease = require_current_artifact_phase_count_in_transaction_v1(db, frame=frame,
        binding=binding, count_request=count_request, envelope=envelope, frozen_material_digest=prospective_input_digest,
        provider_request_json=canonical_serialize(provider), original_deadline_utc=future_identity.deadline_utc,
        input_kind="prospective", installed_readers=installed_readers)
    if (evidence.upper_tokens > ceiling["input_tokens"]
            or evidence.upper_tokens + ceiling["output_tokens"] > ceiling["model_tokens"]
            or policy.work_kind not in grant.allowed_work_kinds
            or any(amount > grant.max_ceiling.get(dimension, -1) or amount > lease.available(dimension)
                for dimension, amount in ceiling.items())):
        raise MissingProductionOriginalV1("actual_current_phase_count_and_four_dimension_budget_fit")
    return CurrentPersonalCandidatePriceV1(original, binding.candidate_ref, binding.digest, pin, (), (),
        policy.work_kind, policy.template_version, policy.resource_ref, tuple(sorted(ceiling.items())),
        prospective_input_digest, evidence.upper_tokens, policy.counting_policy_ref,
        policy.counting_policy_version + ":" + evidence.token_evidence + ":prospective")


def require_final_artifact_phase_counts_in_transaction_v1(db, *, frame, binding, initial_request,
        initial_envelope, final_request, final_envelope, frozen_material_digest, provider_request_json,
        original_deadline_utc, quote_ceiling, installed_readers):
    from ..authority_service.artifact_phase_counter_v1 import require_independent_actual_phase_counts_v1
    from ..model_broker.artifact_draft_v1 import PHASE_TOKEN_CEILINGS_V2
    counter, evidence, grant, lease = require_current_artifact_phase_count_in_transaction_v1(db, frame=frame,
        binding=binding, count_request=final_request, envelope=final_envelope,
        frozen_material_digest=frozen_material_digest, provider_request_json=provider_request_json,
        original_deadline_utc=original_deadline_utc, input_kind="actual", installed_readers=installed_readers)
    initial, final = require_independent_actual_phase_counts_v1(counter, initial_request=initial_request,
        initial_envelope=initial_envelope, final_request=final_request, final_envelope=final_envelope,
        now_utc=frame.now_utc, allow_local_fixture=_phase_count_allows_fixture_v1(installed_readers))
    price, _, _ = read_current_artifact_phase_price_policy_v1(db, frame=frame, installed_readers=installed_readers)
    ceiling = dict(quote_ceiling)
    limits = next({"input_tokens": inp, "output_tokens": out} for kind, inp, out in PHASE_TOKEN_CEILINGS_V2
        if kind == binding.phase_kind)
    if (set(ceiling) != DIMENSIONS
            or any(type(amount) is not int or amount < 0 or amount > dict(price.quote_ceiling)[dimension]
                or amount > grant.max_ceiling.get(dimension, -1) or amount > lease.available(dimension)
                for dimension, amount in ceiling.items())
            or any(ceiling[dimension] > amount for dimension, amount in limits.items())
            or evidence.upper_tokens > ceiling["input_tokens"]
            or evidence.upper_tokens + ceiling["output_tokens"] > ceiling["model_tokens"]
            or json.loads(provider_request_json)["max_completion_tokens"] > ceiling["output_tokens"]
            or price.work_kind not in grant.allowed_work_kinds):
        raise MissingProductionOriginalV1("final_actual_phase_count_and_original_four_dimension_quote_fit")
    return initial, final

def _current_phase_count_budget_scope_v1(db, *, frame, installed_readers):
    from .budget import get_budget_lease, require_budget_family_admissible
    ref = frame.envelope.parent_budget_lease_ref
    require_budget_family_admissible(db, ref)
    grant = installed_readers.issuer.current_budget_grant(db, ref)
    lease = get_budget_lease(db, ref)
    digest = canonical_digest({"parent_budget_lease_ref": ref, "grant": plain_v1(grant),
        "lease": plain_v1(lease), "resource_versions": frame.envelope.version_guard.resource_lease_versions})
    return digest, grant, lease

@dataclass(frozen=True, slots=True)
class ArtifactPhaseCountPairV1:
    initial_request: "ArtifactPhaseCountRequestV1"
    initial_envelope_json: str
    final_request: "ArtifactPhaseCountRequestV1"
    final_envelope_json: str
    frozen_stage_digest: str

    def __post_init__(self):
        from ..model_broker.artifact_phase_count_v1 import ArtifactPhaseCountRequestV1
        if type(self.initial_request) is not ArtifactPhaseCountRequestV1 or type(self.final_request) is not ArtifactPhaseCountRequestV1:
            raise TypeError("actual phase count pair requires exact frozen requests")
        _digest(self.frozen_stage_digest)
        for value in (self.initial_envelope_json, self.final_envelope_json):
            if type(value) is not str or canonical_serialize(json.loads(value)) != value:
                raise ValueError("actual phase count pair requires its original canonical signed envelopes")


def _actual_phase_count_stage_commitment_v1(stage, provider_request_json):
    from .d11_artifact_draft_model_v1 import ArtifactDraftModelStageV2
    if type(stage) is not ArtifactDraftModelStageV2 or stage.model_request is None or stage.before_job is None:
        raise TypeError("actual counter requires the real pure once acquisition stage")
    return canonical_digest({"frame": plain_v1(stage.frame), "stage": plain_v1(stage.stage),
        "prepared_digest": stage.prepared.digest, "frozen_digest": stage.frozen.digest,
        "before_job": plain_v1(stage.before_job), "expected_job": plain_v1(stage.job),
        "model_request_digest": stage.model_request.digest, "provider_request_json": provider_request_json})


def double_count_frozen_artifact_phase_stage_outside_transaction_v1(runtime, *, frozen_stage,
        initial_request, installed_readers):
    """Execute actual pinned program twice; never acquire/save the stage here."""
    from ..model_broker.artifact_phase_count_v1 import artifact_phase_provider_request_v1
    from ..authority_service.artifact_phase_counter_v1 import (InstalledArtifactPhaseCounterCommandV1,
        require_independent_actual_phase_counts_v1)
    runtime._current()
    graph = runtime.graph
    store = graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned():
        raise ValueError("actual phase counting must occur outside Graph locks and transactions")
    policy = _installed_phase_count_policy_v1(installed_readers)
    bundle, _ = _installed_bundle(installed_readers)
    body = canonical_serialize(artifact_phase_provider_request_v1(frozen_stage.model_request,
        billing_policy=bundle.provider_billing_policy_v1))
    if initial_request.input_kind != "actual" or initial_request.provider_request_json != body:
        raise ValueError("actual phase counter cannot consume prospective or another frozen body")
    commitment = _actual_phase_count_stage_commitment_v1(frozen_stage, body)
    command = InstalledArtifactPhaseCounterCommandV1(policy)
    from .first_ingress_v2 import trusted_upper
    clock = graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    initial = command.count_outside_graph_transaction_v1(db=store._db, request=initial_request, now_utc=trusted_upper(clock),
        allow_local_fixture=_phase_count_allows_fixture_v1(installed_readers))
    # Reconstruct from the same immutable actual stage, not the first program's output.
    rebuilt = canonical_serialize(artifact_phase_provider_request_v1(frozen_stage.model_request,
        billing_policy=bundle.provider_billing_policy_v1))
    if rebuilt != body or _actual_phase_count_stage_commitment_v1(frozen_stage, rebuilt) != commitment:
        raise ValueError("independent actual phase body reconstruction changed its frozen stage")
    final_request = replace(initial_request, nonce=secrets.token_hex(16))
    clock = graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    final = command.count_outside_graph_transaction_v1(db=store._db, request=final_request, now_utc=trusted_upper(clock),
        allow_local_fixture=_phase_count_allows_fixture_v1(installed_readers))
    clock = graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    require_independent_actual_phase_counts_v1(policy, initial_request=initial_request, initial_envelope=initial,
        final_request=final_request, final_envelope=final, now_utc=trusted_upper(clock),
        allow_local_fixture=_phase_count_allows_fixture_v1(installed_readers))
    return ArtifactPhaseCountPairV1(initial_request, canonical_serialize(initial), final_request,
        canonical_serialize(final), commitment)


def verify_frozen_artifact_phase_count_pair_in_transaction_v1(db, *, frozen_stage, count_pair,
        installed_readers, now_utc):
    """Fresh clock applies to acceptance only; preserve old model and stage wire."""
    from ..model_broker.artifact_phase_count_v1 import artifact_phase_provider_request_v1
    from ..authority_service.artifact_phase_counter_v1 import require_independent_actual_phase_counts_v1
    if type(count_pair) is not ArtifactPhaseCountPairV1:
        raise TypeError("final acquisition consumes only its actual closed count pair")
    bundle, _ = _installed_bundle(installed_readers)
    policy = _installed_phase_count_policy_v1(installed_readers)
    body = canonical_serialize(artifact_phase_provider_request_v1(frozen_stage.model_request,
        billing_policy=bundle.provider_billing_policy_v1))
    if (count_pair.frozen_stage_digest != _actual_phase_count_stage_commitment_v1(frozen_stage, body)
            or count_pair.initial_request.provider_request_json != body):
        raise ValueError("final phase counter pair does not belong to the original exact acquisition stage")
    initial, final = require_independent_actual_phase_counts_v1(policy, initial_request=count_pair.initial_request,
        initial_envelope=json.loads(count_pair.initial_envelope_json), final_request=count_pair.final_request,
        final_envelope=json.loads(count_pair.final_envelope_json), now_utc=now_utc,
        allow_local_fixture=_phase_count_allows_fixture_v1(installed_readers))
    # This temporary current view is never saved or written into a request/model.
    current_frame = replace(frozen_stage.frame, now_utc=now_utc)
    read = CurrentDomainReadV1(current_frame); read.check(db)
    sources, reads, coverage = _phase_count_scope_v1(current_frame)
    request = count_pair.final_request
    guard = current_frame.owner_guard
    if (request.scope_digest != canonical_digest({"namespace": current_frame.envelope.authority.namespace,
            "owner_grant_ref": guard.grant_ref, "owner_grant_revision": guard.grant_revision,
            "owner_grant_digest": guard.grant_digest, "source_versions": sources, "read_versions": reads,
            "query_coverage_digest": coverage,
            "budget_scope_digest": _current_phase_count_budget_scope_v1(db, frame=current_frame, installed_readers=installed_readers)[0],
            "access_epoch": current_frame.envelope.version_guard.access_epoch,
            "delete_epoch": current_frame.envelope.version_guard.delete_epoch,
            "activation_generation": current_frame.activation_generation})
            or request.frozen_material_digest != frozen_stage.frozen.digest
            or request.original_deadline_utc != frozen_stage.model_request.envelope.deadline_utc):
        raise MissingProductionOriginalV1("final_phase_counter_current_owner_source_budget_read_scope")
    read.source_family(db, tuple(ref for ref, _, _ in sources), purpose="consolidation")
    return initial, final

_PHASE_COUNT_MATERIAL_KEY = object()
_ACTIVE_PHASE_COUNT_MATERIALS_V2 = {}


@dataclass(frozen=True, slots=True, init=False)
class _ForegroundArtifactPhaseCountMaterialV2:
    runtime: object
    issued: object
    operation: object
    request: object
    scope: object
    frame: object
    base_stage: object
    stage: object
    binding: object
    readers: object
    process_lease: object
    count_pair: ArtifactPhaseCountPairV1

    def __init__(self, token, **values):
        if token is not _PHASE_COUNT_MATERIAL_KEY:
            raise TypeError("phase count material is issued only by its actual outside W01 producer")
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, values[name])


def _freeze_foreground_phase_count_material_in_transaction_v2(runtime, db, *, issued, operation,
        request, scope, external_originals, now_utc, process_lease, capability):
    from datetime import datetime
    from ..runtime_contracts import (AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch,
        RUNTIME_SCHEMA, SourceQualification, VersionGuard)
    from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
    from .budget import get_budget_lease, require_budget_family_admissible
    from .d11_artifact_draft_model_v1 import freeze_actual_artifact_phase_count_stage_in_transaction_v2
    evidence = require_foreground_activity_issuance_v1(issued, runtime.graph, scope)
    selector = evidence.request
    issuer = runtime.graph._GraphCoordinator__d11_issuer
    grant = issuer.current_budget_grant(db, selector.parent_budget_lease_ref)
    lease = get_budget_lease(db, grant.lease_id)
    require_budget_family_admissible(db, grant.lease_id)
    if lease.state != "active" or grant.valid_until_utc <= now_utc:
        raise MissingProductionOriginalV1("original_active_artifact_phase_count_budget")
    _, epoch = runtime.graph._v2_graph_stamp(selector.namespace)
    versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
        "AND ref='current' AND kind IN ('scheme','operator','policy')", selector.namespace.as_tuple).fetchall())
    if set(versions) != {"scheme", "operator", "policy"}:
        raise MissingProductionOriginalV1("actual_foreground_phase_count_guard_heads")
    deadline = min(selector.requested_deadline_utc, grant.valid_until_utc,
        datetime.fromisoformat(evidence.valid_until_utc.replace("Z", "+00:00")).timestamp())
    authority = AuthorityContext(evidence.current_self.self_entity_ref, operation.domain, capability,
        selector.namespace, tuple(sorted(runtime.graph._GraphCoordinator__leases[process_lease][5])),
        selector.purpose, selector.audiences, grant.policy_ref, evidence.current_self.activation_generation)
    envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(selector.activity_id, None, selector.operation_id,
        operation.operation_kind, selector.operation_id, canonical_digest({"input_refs": []})), authority,
        VersionGuard((), (QueryEpoch(selector.namespace, "namespace", epoch.revision),), evidence.access_epoch,
            evidence.delete_epoch, runtime.graph._GraphCoordinator__store._registry.catalogue_hash,
            versions["scheme"], versions["operator"], versions["policy"], (), (), ()),
        SourceQualification((), "derived", None, now_utc, "inference", "ineligible", None, "not_applicable"),
        (), selector.parent_budget_lease_ref, deadline, time.monotonic() + deadline - now_utc,
        "foreground-current:" + selector.operation_id, ())
    if runtime._active_foreground_issuance_v1 is not None or runtime._active_foreground_process_lease_v1 is not None:
        raise ValueError("another actual foreground compilation is already active")
    runtime._active_foreground_issuance_v1 = issued
    runtime._active_foreground_process_lease_v1 = process_lease
    try:
        frame, compiled, readers = runtime.compile_foreground_in_transaction(db, operation=operation,
            request=request, envelope=envelope, scope=scope, issued=issued, now_utc=now_utc,
            external_originals=external_originals)
        frame, stage, binding = freeze_actual_artifact_phase_count_stage_in_transaction_v2(db,
            frame=frame, request=request, installed_readers=readers)
        if stage != compiled:
            raise ValueError("phase count freeze differs from the actual readonly installed compiler")
        from ..model_broker.artifact_phase_count_v1 import artifact_phase_provider_request_v1
        body = canonical_serialize(artifact_phase_provider_request_v1(stage.model_request,
            billing_policy=readers.installed_bundle.provider_billing_policy_v1))
        count_request = freeze_artifact_phase_count_request_in_transaction_v1(db, frame=frame,
            binding=binding, input_kind="actual", frozen_material_digest=stage.frozen.digest,
            provider_request_json=body, original_deadline_utc=stage.model_request.envelope.deadline_utc,
            nonce=secrets.token_hex(16), installed_readers=readers)
        return frame, stage, binding, readers, count_request
    finally:
        runtime._active_foreground_issuance_v1 = None
        runtime._active_foreground_process_lease_v1 = None


@contextmanager
def artifact_phase_counts_for_foreground_fence_v2(runtime, *, issued, operation, request, scope,
        external_originals, now_utc):
    """Actual Self fence producer: readonly freeze, outside counts, same-stage CAS."""
    from .d11_artifact_draft_model_v1 import AcquireArtifactDraftModelRequestV2
    from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
    runtime._current()
    if operation.operation_kind != "acquire_artifact_draft_model_v2" or type(request) is not AcquireArtifactDraftModelRequestV2:
        raise TypeError("outside phase count producer serves only actual V2 once acquisition")
    graph = runtime.graph
    store = graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned():
        raise ValueError("phase count producer enters outside the Graph transaction and lock")
    if getattr(runtime, "_active_artifact_phase_count_material_v2", None) is not None:
        raise ValueError("an original phase count fence is already active")
    evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
    process_lease, capability = graph.grant(runtime._bootstrap, actor=evidence.current_self.self_entity_ref,
        issuer_domain=operation.domain, namespace=evidence.request.namespace,
        domains=evidence.allowed_write_domains, activation_generation=evidence.current_self.activation_generation,
        operation_id=evidence.request.operation_id)
    material = None
    try:
        with store._lock:
            store._db.execute("BEGIN")
            try:
                frame, stage, binding, readers, count_request = _freeze_foreground_phase_count_material_in_transaction_v2(
                    runtime, store._db, issued=issued, operation=operation, request=request, scope=scope,
                    external_originals=external_originals, now_utc=now_utc,
                    process_lease=process_lease, capability=capability)
            finally:
                store._db.rollback()
        pair = double_count_frozen_artifact_phase_stage_outside_transaction_v1(runtime,
            frozen_stage=stage, initial_request=count_request, installed_readers=readers)
        base_stage = stage
        from .d11_artifact_draft_model_v1 import seal_counted_artifact_phase_stage_v2
        from .first_ingress_v2 import trusted_upper
        seal_now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            graph._GraphCoordinator__scene_clock_policy))
        with store._lock:
            store._db.execute("BEGIN")
            try:
                stage = seal_counted_artifact_phase_stage_v2(store._db, frozen_stage=base_stage,
                    count_pair=pair, installed_readers=readers, now_utc=seal_now)
            finally:
                store._db.rollback()
        material = _ForegroundArtifactPhaseCountMaterialV2(_PHASE_COUNT_MATERIAL_KEY, runtime=runtime,
            issued=issued, operation=operation, request=request, scope=scope, frame=frame, base_stage=base_stage, stage=stage,
            binding=binding, readers=readers, process_lease=process_lease, count_pair=pair)
        _ACTIVE_PHASE_COUNT_MATERIALS_V2[id(material)] = material
        runtime._active_artifact_phase_count_material_v2 = material
        yield material
    finally:
        if material is not None:
            _ACTIVE_PHASE_COUNT_MATERIALS_V2.pop(id(material), None)
        runtime._active_artifact_phase_count_material_v2 = None
        runtime._active_artifact_phase_count_stage_v2 = None
        graph.release_authority_lease(runtime._bootstrap, process_lease)


def require_artifact_phase_count_material_for_foreground_v2(runtime, db, *, issued, operation,
        request, scope, now_utc):
    from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
    from .d11_artifact_draft_model_v1 import seal_counted_artifact_phase_stage_v2
    material = getattr(runtime, "_active_artifact_phase_count_material_v2", None)
    if (type(material) is not _ForegroundArtifactPhaseCountMaterialV2
            or _ACTIVE_PHASE_COUNT_MATERIALS_V2.get(id(material)) is not material
            or material.runtime is not runtime or material.issued is not issued or material.scope != scope
            or material.operation != operation or material.request != request
            or db is not runtime.graph._GraphCoordinator__store._db or not db.in_transaction
            or not runtime.graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError("final phase acquisition requires its exact live private counted fence material")
    evidence = require_foreground_activity_issuance_v1(issued, runtime.graph, scope)
    runtime.graph._authorize(material.process_lease, material.frame.envelope.authority,
        frozenset(evidence.allowed_write_domains))
    stage = seal_counted_artifact_phase_stage_v2(db, frozen_stage=material.base_stage,
        count_pair=material.count_pair, installed_readers=material.readers, now_utc=now_utc)
    if stage != material.stage:
        raise ValueError("actual count validator substituted the original frozen stage")
    return material

_PERSONAL_COUNT_MATERIAL_KEY = object()
_ACTIVE_PERSONAL_COUNT_MATERIALS_V1 = {}


@dataclass(frozen=True, slots=True, init=False)
class _OwnerPersonalPhaseCountMaterialV1:
    runtime: object
    operation_id: str
    request: object
    scope: object
    readers: object
    command_deadline_utc: float
    count_materials: tuple

    def __init__(self, token, **values):
        if token is not _PERSONAL_COUNT_MATERIAL_KEY:
            raise TypeError("personal phase counts originate only in the actual Owner fence producer")
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, values[name])


def _freeze_personal_phase_count_frame_in_transaction_v1(runtime, db, *, authority, operation,
        request, operation_id, activity_id, audience_ref, parent_budget_lease_ref, scope, owner, guard,
        external_originals, now_utc, process_lease, capability):
    from ..runtime_contracts import (AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch,
        RUNTIME_SCHEMA, SourceQualification, VersionGuard)
    from .budget import get_budget_lease, require_budget_family_admissible
    from .domain_production_registry_v1 import installed_readers_for_operation_v1
    from .domain_production_read_plans_v1 import (read_plan_current_domain_operation_v1,
        read_current_domain_command_identity_v1, read_current_domain_policy_refs_v1, read_current_domain_original_refs_v1)
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    from .d08_personal_candidate_v1 import freeze_current_personal_phase_count_materials_in_transaction_v1
    graph = runtime.graph
    ns = authority.namespace
    budget = get_budget_lease(db, parent_budget_lease_ref)
    grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, parent_budget_lease_ref)
    require_budget_family_admissible(db, parent_budget_lease_ref)
    if (budget.state != "active" or grant.valid_until_utc <= now_utc
            or (budget.bot_id, budget.persona_id) != ns.as_tuple):
        raise MissingProductionOriginalV1("actual_personal_phase_count_parent_budget")
    _, epoch = graph._v2_graph_stamp(ns)
    versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
        "AND ref='current' AND kind IN ('scheme','operator','policy')", ns.as_tuple).fetchall())
    if set(versions) != {"scheme", "operator", "policy"}:
        raise MissingProductionOriginalV1("actual_personal_phase_count_guard_heads")
    readers = installed_readers_for_operation_v1(graph, operation, scope=scope, owner_guard=guard)
    identity = read_current_domain_command_identity_v1(db, namespace=ns, operation_kind=operation.operation_kind,
        request=request, requested_activity_id=activity_id, requested_audience_ref=audience_ref,
        installed_readers=readers, operation_id=operation_id)
    deadline = min(now_utc + 60.0, grant.valid_until_utc)
    actual_authority = AuthorityContext(authority.actor, operation.domain, capability, ns,
        tuple(sorted(graph._GraphCoordinator__leases[process_lease][5])), identity.purpose,
        (identity.audience_ref,), grant.policy_ref, authority.activation_generation)
    envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(activity_id, identity.effect_id, operation_id,
        operation.operation_kind, operation_id, canonical_digest({"input_refs": []})), actual_authority,
        VersionGuard((), (QueryEpoch(ns, "namespace", epoch.revision),), owner.access_epoch, owner.delete_epoch,
            graph._GraphCoordinator__store._registry.catalogue_hash, versions["scheme"], versions["operator"],
            versions["policy"], (), (), ()),
        SourceQualification((), "derived", None, now_utc, "inference", "ineligible", None, "not_applicable"),
        (), parent_budget_lease_ref, deadline, time.monotonic() + deadline - now_utc,
        "domain-current:" + operation_id, ())
    plan = read_plan_current_domain_operation_v1(db, namespace=ns, activity_id=activity_id,
        domain=operation.domain, operation_kind=operation.operation_kind, request=request, operation_id=operation_id,
        now_utc=now_utc, audiences=envelope.authority.audience,
        life_d04_before_capture_policy=graph._GraphCoordinator__life_d04_before_capture_policy,
        personal_candidate_readers=readers)
    policies = read_current_domain_policy_refs_v1(db, namespace=ns, plan=plan, installed_readers=readers)
    originals = read_current_domain_original_refs_v1(db, namespace=ns, plan=plan, installed_readers=readers,
        authenticated_external_originals=external_originals)
    frame = freeze_domain_production_frame_v1(graph, db, envelope=envelope, current_owner=owner, scope=scope,
        plan=plan, now_utc=now_utc, observed_originals=originals, installed_policy_refs=policies)
    material = freeze_current_personal_phase_count_materials_in_transaction_v1(db, frame=frame,
        request=request, installed_readers=readers)
    policy, _, _ = read_current_artifact_phase_price_policy_v1(db, frame=frame, installed_readers=readers)
    from ..model_broker.artifact_draft_v1 import PHASE_TOKEN_CEILINGS_V2
    from ..model_broker.artifact_phase_count_v1 import artifact_phase_prospective_provider_request_v1
    count_requests = []
    for binding, encoded, input_digest, future in material:
        output_limit = next(out for kind, _, out in PHASE_TOKEN_CEILINGS_V2 if kind == binding.phase_kind)
        output = min(dict(policy.quote_ceiling)["output_tokens"], policy.max_output_tokens, output_limit)
        body = artifact_phase_prospective_provider_request_v1(model_id=policy.model_id,
            prospective_input_json=encoded, max_output_tokens=output)
        count_requests.append(freeze_artifact_phase_count_request_in_transaction_v1(db, frame=frame,
            binding=binding, input_kind="prospective", frozen_material_digest=input_digest,
            provider_request_json=canonical_serialize(body), original_deadline_utc=future.deadline_utc,
            nonce=secrets.token_hex(16), installed_readers=readers))
    return frame, readers, tuple(count_requests)


@contextmanager
def personal_phase_counts_for_owner_fence_v1(runtime, *, authority, operation, request, operation_id,
        activity_id, audience_ref, parent_budget_lease_ref, scope, owner, guard, external_originals, now_utc):
    """Actual Owner preparation producer; quote facts precede the short W01 CAS."""
    from .d08_personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1
    from ..authority_service.artifact_phase_counter_v1 import InstalledArtifactPhaseCounterCommandV1
    from .first_ingress_v2 import trusted_upper
    runtime._current()
    if (operation.operation_kind != "prepare_personal_candidates_v1"
            or type(request) is not PrepareCurrentPersonalCandidatesRequestV1):
        raise TypeError("personal counter producer serves only actual candidate preparation")
    graph = runtime.graph
    store = graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned():
        raise ValueError("personal counter producer starts outside Graph locks and transactions")
    if getattr(runtime, "_active_personal_phase_count_material_v1", None) is not None:
        raise ValueError("another actual personal count fence is active")
    process_lease, capability = graph.grant(runtime._bootstrap, actor=authority.actor, issuer_domain=operation.domain,
        namespace=authority.namespace, domains=(operation.domain, "d11"),
        activation_generation=authority.activation_generation, operation_id=operation_id)
    prior_readers = getattr(runtime, "_personal_candidate_readers_v1", None)
    prior_price_reader = None
    readers = material = None
    try:
        with store._lock:
            store._db.execute("BEGIN")
            try:
                frame, readers, requests = _freeze_personal_phase_count_frame_in_transaction_v1(runtime,
                    store._db, authority=authority, operation=operation, request=request, operation_id=operation_id,
                    activity_id=activity_id, audience_ref=audience_ref, parent_budget_lease_ref=parent_budget_lease_ref,
                    scope=scope, owner=owner, guard=guard, external_originals=external_originals,
                    now_utc=now_utc, process_lease=process_lease, capability=capability)
            finally:
                store._db.rollback()
        policy = _installed_phase_count_policy_v1(readers)
        command = InstalledArtifactPhaseCounterCommandV1(policy)
        counted = []
        for count_request in requests:
            clock = graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
            envelope = command.count_outside_graph_transaction_v1(db=store._db, request=count_request,
                now_utc=trusted_upper(clock), allow_local_fixture=_phase_count_allows_fixture_v1(readers))
            counted.append((count_request, canonical_serialize(envelope)))
        prior_price_reader = readers.phase_price_reader
        readers.phase_price_reader = install_artifact_phase_price_reader_v1(readers=readers, count_materials=tuple(counted))
        runtime._personal_candidate_readers_v1 = readers
        material = _OwnerPersonalPhaseCountMaterialV1(_PERSONAL_COUNT_MATERIAL_KEY, runtime=runtime,
            operation_id=operation_id, request=request, scope=scope, readers=readers,
            command_deadline_utc=frame.envelope.deadline_utc, count_materials=tuple(counted))
        _ACTIVE_PERSONAL_COUNT_MATERIALS_V1[id(material)] = material
        runtime._active_personal_phase_count_material_v1 = material
        yield material
    finally:
        if material is not None:
            _ACTIVE_PERSONAL_COUNT_MATERIALS_V1.pop(id(material), None)
            readers.phase_price_reader = prior_price_reader
        runtime._active_personal_phase_count_material_v1 = None
        runtime._personal_candidate_readers_v1 = prior_readers
        graph.release_authority_lease(runtime._bootstrap, process_lease)


def original_personal_phase_count_deadline_v1(runtime, *, operation_id):
    material = getattr(runtime, "_active_personal_phase_count_material_v1", None)
    if material is None:
        return None
    if (type(material) is not _OwnerPersonalPhaseCountMaterialV1
            or _ACTIVE_PERSONAL_COUNT_MATERIALS_V1.get(id(material)) is not material
            or material.runtime is not runtime or material.operation_id != operation_id):
        raise ValueError("personal preparation lost its original actual counted fence deadline")
    return material.command_deadline_utc

def read_adopted_personal_phase_count_price_v1(db, *, frame, binding, prospective_input_json,
        prospective_input_digest, future_identity, adopted_preparation, installed_readers, phase_transition=None):
    """Authenticate original prospective price; current qualification remains W01's.

    A historical count is not a new actual provider count or a budget grant.
    Only an actual adopted preparation and proven own transitions can use it.
    """
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1, CurrentPersonalCandidatePriceV1, PREPARE_OPERATION_V1
    from .d08_personal_candidate_v1 import _require_phase_transition_v1, _PhasePersonalCandidateReadV1
    from ..model_broker.artifact_phase_count_v1 import (artifact_phase_count_request_from_wire_v1,
        artifact_phase_prospective_provider_request_v1)
    from ..authority_service.artifact_phase_counter_v1 import verify_artifact_phase_count_envelope_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_contracts_v1 import ProductionQueryCoverageV1
    from ..model_broker.artifact_draft_v1 import PHASE_TOKEN_CEILINGS_V2
    from .budget import get_budget_lease, require_budget_family_admissible
    if type(adopted_preparation) is not PreparedPersonalCandidateSetV1:
        raise TypeError("historical prospective price needs the actual typed adopted preparation")
    read = CurrentDomainReadV1(frame); read.check(db)
    origin = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace,
        adopted_preparation.preparation_operation_id)
    if (origin is None or (origin["domain"], origin["operation_kind"]) != ("d08", PREPARE_OPERATION_V1)
            or origin["payload"]["provenance"]["prepared_candidates"] != plain_v1(adopted_preparation)):
        raise MissingProductionOriginalV1("actual_adopted_W01_prospective_count_preparation")
    read.original("d08-current:" + origin["original_digest"][:48],
        kind="d08.current-" + PREPARE_OPERATION_V1, digest=origin["original_digest"])
    qualified_read = read
    if phase_transition is not None:
        t = _require_phase_transition_v1(db, frame=frame, readers=installed_readers, transition=phase_transition)
        if t.prepared_candidates != adopted_preparation:
            raise ValueError("historical counter projection changed its actual adopted preparation")
        qualified_read = _PhasePersonalCandidateReadV1(frame, db=db, readers=installed_readers, transition=t)
    for version in adopted_preparation.read_versions:
        if version.key.token == adopted_preparation.future_decision_ref and version.revision == 0:
            head = read.head(db, version.key)
            if head.revision > 0:
                event = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",
                    (head.key.token, head.revision)).fetchone()
                if event != (adopted_preparation.selection_operation_id,):
                    raise MissingProductionOriginalV1("actual_same_selected_decision_for_historical_count")
                continue
        if qualified_read.head(db, version.key).revision != version.revision:
            raise MissingProductionOriginalV1("current_hard_head_for_historical_phase_count")
    old_pages = tuple(decode_typed_production_value_v1(row, ProductionQueryCoverageV1)
        for row in origin["payload"]["query_coverage"])
    for page in old_pages:
        actual = qualified_read.complete_inventory(db, page.type_id)
        if not page.complete or tuple(GraphVersion(atom.key, atom.revision) for atom in actual) != page.row_versions:
            raise MissingProductionOriginalV1("complete_current_hard_scope_for_historical_phase_count")
    prior = next((candidate.price for candidate in adopted_preparation.candidates
        if candidate.binding == binding), None)
    if type(prior) is not CurrentPersonalCandidatePriceV1:
        raise MissingProductionOriginalV1("actual_prior_typed_prospective_phase_price")
    rows = origin["payload"]["provenance"].get("artifact_phase_counts", ())
    selected = tuple(row for row in rows if row["count_request"]["candidate_parameter_digest"] == binding.digest
        and row["count_request"]["frozen_material_digest"] == prospective_input_digest)
    if len(selected) != 1:
        raise MissingProductionOriginalV1("actual_adopted_signed_historical_prospective_phase_count")
    request = artifact_phase_count_request_from_wire_v1(selected[0]["count_request"])
    counter = _installed_phase_count_policy_v1(installed_readers)
    evidence = verify_artifact_phase_count_envelope_v1(counter, request, selected[0]["signed_envelope"], now_utc=frame.now_utc,
        allow_local_fixture=_phase_count_allows_fixture_v1(installed_readers))
    policy, pin, original = read_current_artifact_phase_price_policy_v1(db, frame=frame, installed_readers=installed_readers)
    inp, out = next((i, o) for kind, i, o in PHASE_TOKEN_CEILINGS_V2 if kind == binding.phase_kind)
    ceiling = dict(policy.quote_ceiling)
    ceiling["input_tokens"] = min(ceiling["input_tokens"], inp)
    ceiling["output_tokens"] = min(ceiling["output_tokens"], out, policy.max_output_tokens)
    ceiling["model_tokens"] = min(ceiling["model_tokens"], ceiling["input_tokens"] + ceiling["output_tokens"])
    wire = canonical_serialize(artifact_phase_prospective_provider_request_v1(model_id=policy.model_id,
        prospective_input_json=prospective_input_json, max_output_tokens=ceiling["output_tokens"]))
    reads = tuple(sorted((v.key.token, v.revision) for v in origin["read_versions"]))
    coverage = canonical_digest(tuple({"type_id": page.type_id, "row_versions": page.row_versions,
        "complete": page.complete, "continuation_ref": page.continuation_ref} for page in old_pages))
    _require_v3_phase_count_basis_v1(db, frame=frame, binding=binding,
        material=json.loads(prospective_input_json), original_deadline_utc=future_identity.deadline_utc,
        installed_readers=installed_readers)
    guard = frame.owner_guard
    if ((request.input_kind, request.provider_request_json, request.frozen_material_digest, request.candidate_parameter_digest,
            request.owner_grant_ref, request.owner_grant_revision, request.owner_grant_digest, request.read_versions,
            request.query_coverage_digest, request.access_epoch, request.delete_epoch, request.activation_generation,
            request.original_deadline_utc) != ("prospective", wire, prospective_input_digest, binding.digest,
            guard.grant_ref, guard.grant_revision, guard.grant_digest, reads, coverage,
            frame.envelope.version_guard.access_epoch, frame.envelope.version_guard.delete_epoch,
            frame.activation_generation, future_identity.deadline_utc)
            or policy.counting_mode != "signed_phase_counter" or policy.counting_policy_ref != "artifact-phase-counter:" + counter.digest
            or policy.counting_policy_version != str(counter.counter_policy_version) or set(ceiling) != DIMENSIONS
            or evidence.upper_tokens > ceiling["input_tokens"] or evidence.upper_tokens + ceiling["output_tokens"] > ceiling["model_tokens"]):
        raise MissingProductionOriginalV1("current_policy_and_original_W01_phase_counter_proof")
    for ref, revision, digest in request.source_versions:
        head = read.head(db, ref, required=True)
        if head.revision != revision or canonical_digest(head.value) != digest:
            raise MissingProductionOriginalV1("current_original_prospective_counter_source")
    read.source_family(db, tuple(ref for ref, _, _ in request.source_versions), purpose="consolidation")
    require_budget_family_admissible(db, frame.envelope.parent_budget_lease_ref)
    grant = installed_readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    lease = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    if (frame.envelope.parent_budget_lease_ref != adopted_preparation.parent_budget_lease_ref
            or future_identity.parent_budget_lease_ref != adopted_preparation.parent_budget_lease_ref
            or lease.state != "active" or frame.now_utc >= grant.valid_until_utc
            or policy.work_kind not in grant.allowed_work_kinds
            or any(amount > grant.max_ceiling.get(dim, -1) for dim, amount in ceiling.items())):
        raise MissingProductionOriginalV1("current_historical_counter_original_grant_family_and_deadline")
    from ..authority_service.artifact_phase_counter_v1 import verify_installed_artifact_phase_counter_assets_v1
    verify_installed_artifact_phase_counter_assets_v1(counter)
    current = CurrentPersonalCandidatePriceV1(original, binding.candidate_ref, binding.digest, pin, (), (),
        policy.work_kind, policy.template_version, policy.resource_ref, tuple(sorted(ceiling.items())),
        prospective_input_digest, evidence.upper_tokens, policy.counting_policy_ref,
        policy.counting_policy_version + ":" + evidence.token_evidence + ":prospective")
    if current != prior:
        raise MissingProductionOriginalV1("current_installed_and_prior_actual_prospective_count_price_identity")
    return current

def _phase_count_allows_fixture_v1(installed_readers):
    """Derived private qualification only; callers cannot turn on a fixture flag."""
    bundle, _ = _installed_bundle(installed_readers)
    policy = getattr(bundle, "artifact_phase_counter", None)
    if policy is None or policy.source_scope == "production":
        return False
    from ..host.authority_profile import require_artifact_phase_fixture_qualification_v1
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    from .d08_personal_candidate_v1 import InstalledPersonalCandidateReadersV1
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    if type(installed_readers) is InstalledArtifactDraftModelReadersV1:
        model_runtime = installed_readers.model_runtime
    elif type(installed_readers) is InstalledPersonalCandidateReadersV1:
        model_runtime = installed_readers.current().graph._GraphCoordinator__artifact_draft_model_runtime_v1
    elif type(installed_readers) is InstalledD02ProductionReadersV1:
        model_runtime = installed_readers.role_clock_reader.graph._GraphCoordinator__artifact_draft_model_runtime_v1
    else:
        raise TypeError("fixture counter requires its real installed reader identity")
    if model_runtime is None or model_runtime.bundle is not bundle:
        raise ValueError("fixture counter has no actual bound model runtime/client grant")
    require_artifact_phase_fixture_qualification_v1(bundle, client_grant=model_runtime.client_grant)
    return True

def read_current_artifact_phase_reservation_ceiling_v1(db, *, frame, selector, chosen, installed_readers):
    """Fresh installed phase maximum for the existing once reservation.

    Prospective candidate prices ranked the whole method. This ceiling is
    derived again for the actual generation phase; actual input fit is proved
    separately by the two acquisition counts before any provider admission.
    """
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2, artifact_draft_phase_token_limits_v2
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    from ..domains.d08.personal_plan_v1 import PLAN_TYPE, decode_personal_plan_type_v1
    from .d11_artifact_draft_model_v1 import (_read_artifact_phase_selected_originals_v2,
        _current_artifact_phase_parameters_v2)
    from .artifact_task_text_extent_v1 import require_current_artifact_task_text_extent_v1
    from .d08_personal_candidate_v1 import InstalledPersonalCandidateReadersV1
    from .budget import get_budget_lease, require_budget_family_admissible
    from ..authority_service.artifact_phase_counter_v1 import verify_installed_artifact_phase_counter_assets_v1
    if type(selector) is not ArtifactDraftPhaseSelectorV2 or not selector.generation:
        raise TypeError("generation phase reservation needs its exact adopted selector")
    read = CurrentDomainReadV1(frame); read.check(db)
    policy, _, _ = read_current_artifact_phase_price_policy_v1(db, frame=frame, installed_readers=installed_readers)
    counter = _installed_phase_count_policy_v1(installed_readers)
    verify_installed_artifact_phase_counter_assets_v1(counter)
    prepared, actual_chosen, _ = _read_artifact_phase_selected_originals_v2(db,
        selector=selector, issuer=installed_readers.issuer)
    if (chosen != actual_chosen or type(chosen.binding) not in {ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}
            or policy.counting_mode != "signed_phase_counter"
            or policy.counting_policy_ref != "artifact-phase-counter:" + counter.digest
            or policy.counting_policy_version != str(counter.counter_policy_version)):
        raise MissingProductionOriginalV1("actual_selected_whole_method_and_installed_phase_price")
    plan_atom = read.head(db, selector.plan_ref, required=True)
    plan = decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value)
    if (plan_atom.revision != selector.plan_revision or canonical_digest(plan_atom.value) != selector.plan_digest
            or plan.actor_ref != "persona:" + selector.task.namespace.persona_id
            or dict(plan.method_candidates).get(chosen.binding.candidate_ref) != selector.method_ref
            or plan.goal_ref != prepared.goal_head.key.token or plan.state != "active"
            or selector.task.namespace != frame.envelope.authority.namespace):
        raise MissingProductionOriginalV1("current_exact_whole_method_commitment_for_phase_price")
    runtime = installed_readers.model_runtime
    personal = getattr(runtime.graph._GraphCoordinator__domain_production_runtime_v1,
        "_personal_candidate_readers_v1", None)
    if type(personal) is not InstalledPersonalCandidateReadersV1:
        raise MissingProductionOriginalV1("actual_personal_whole_method_extent_reader")
    require_current_artifact_task_text_extent_v1(db, frame=frame, binding=chosen.binding,
        goal_ref=plan.goal_ref, installed_readers=personal.current())
    if type(chosen.binding) is ArtifactPhaseCandidateBindingV3:
        post_readers = _installed_phase_postcondition_readers_for_count_v1(installed_readers)
        from .artifact_phase_postconditions_v1 import read_current_artifact_phase_postcondition_contract_v1
        contract = read_current_artifact_phase_postcondition_contract_v1(db, frame=frame, selector=selector,
            installed_readers=post_readers)
        if (contract.policy_ref, contract.policy_digest) != (
                chosen.binding.postcondition_policy_ref, chosen.binding.postcondition_policy_digest):
            raise ValueError("actual phase price changed its precommitted rubric contract")
    extent, _, _ = _current_artifact_phase_parameters_v2(db, selector=selector, chosen=chosen,
        issuer=installed_readers.issuer)
    if selector.phase_kind == "full" and extent != chosen.binding.full_extent:
        raise ValueError("full phase price cannot expand or inherit the sample text extent")
    limits = artifact_draft_phase_token_limits_v2(selector)
    ceiling = dict(policy.quote_ceiling)
    ceiling["input_tokens"] = min(ceiling["input_tokens"], limits["input_tokens"])
    ceiling["output_tokens"] = min(ceiling["output_tokens"], limits["output_tokens"], policy.max_output_tokens)
    ceiling["model_tokens"] = min(ceiling["model_tokens"], ceiling["input_tokens"] + ceiling["output_tokens"])
    node = next((node for node in plan.nodes if node.node_id == chosen.binding.node_id), None)
    if node is None or (node.cost_ceiling and any(amount > dict(node.cost_ceiling).get(dim, -1)
            for dim, amount in ceiling.items())):
        raise MissingProductionOriginalV1("original_whole_method_node_cost_ceiling_for_actual_phase")
    require_budget_family_admissible(db, frame.envelope.parent_budget_lease_ref)
    grant = installed_readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    lease = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    if (frame.envelope.parent_budget_lease_ref != prepared.parent_budget_lease_ref
            or lease.state != "active" or frame.now_utc >= min(grant.valid_until_utc, chosen.future_identity.deadline_utc)
            or policy.work_kind not in grant.allowed_work_kinds
            or set(ceiling) != DIMENSIONS
            or any(amount > grant.max_ceiling.get(dim, -1) or amount > lease.available(dim)
                for dim, amount in ceiling.items())):
        raise MissingProductionOriginalV1("actual_current_four_dimension_phase_root_budget")
    return tuple(sorted(ceiling.items()))


def read_actual_counted_artifact_phase_quote_v1(db, *, frozen_stage, count_pair, installed_readers, now_utc):
    """The original signed reserved quote, qualified by this actual count pair.

    This reader cannot issue another quote, reserve more money or enlarge an
    existing reservation. Final acquisition remains the owner's once operation.
    """
    from .d11_artifact_draft_model_v1 import validate_frozen_artifact_phase_count_stage_in_transaction_v2
    validated = validate_frozen_artifact_phase_count_stage_in_transaction_v2(db, frozen_stage=frozen_stage,
        count_pair=count_pair, installed_readers=installed_readers, now_utc=now_utc)
    if validated is not frozen_stage:
        raise ValueError("actual counted phase quote substituted the original once stage")
    quote = installed_readers.resource_issuer.original_signed_quote(db, frozen_stage.prepared.quote_id, 1)
    if canonical_digest(quote) != frozen_stage.prepared.quote_digest:
        raise ValueError("actual counted phase quote lost its original signed identity")
    return quote

def _installed_phase_postcondition_readers_for_count_v1(installed_readers):
    from .artifact_phase_postconditions_v1 import install_artifact_phase_postcondition_readers_v1
    from .d08_personal_candidate_v1 import InstalledPersonalCandidateReadersV1
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    bundle, _ = _installed_bundle(installed_readers)
    if type(installed_readers) is InstalledPersonalCandidateReadersV1:
        graph = installed_readers.current().graph
        model_readers = InstalledArtifactDraftModelReadersV1(installed_readers.issuer, bundle,
            graph._GraphCoordinator__artifact_draft_model_runtime_v1)
    elif type(installed_readers) is InstalledArtifactDraftModelReadersV1:
        graph = installed_readers.model_runtime.graph
        model_readers = installed_readers
    elif type(installed_readers) is InstalledD02ProductionReadersV1:
        graph = installed_readers.role_clock_reader.graph
        model_readers = InstalledArtifactDraftModelReadersV1(installed_readers.issuer, bundle,
            graph._GraphCoordinator__artifact_draft_model_runtime_v1)
    else:
        raise TypeError("postcondition count basis requires its actual installed reader composition")
    return install_artifact_phase_postcondition_readers_v1(graph=graph,
        bootstrap=graph._GraphCoordinator__domain_production_runtime_v1._bootstrap,
        bundle=bundle, model_readers=model_readers)


def _require_v3_phase_count_basis_v1(db, *, frame, binding, installed_readers,
        original_deadline_utc, material=None, frozen=None):
    from ..domains.d08.personal_candidate_v1 import (
        ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3)
    from ..model_broker.artifact_draft_v1 import ArtifactDraftInputV2, ArtifactDraftInputV3
    if type(binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2}:
        if frozen is not None and type(frozen) is not ArtifactDraftInputV2:
            raise ValueError("legacy phase count cannot borrow a V3 postcondition contract")
        return None
    if type(binding) is not ArtifactPhaseCandidateBindingV3:
        raise TypeError("unregistered phase count binding variant")
    from .artifact_phase_postconditions_v1 import (
        require_current_artifact_phase_postcondition_policy_v1,
        read_current_artifact_phase_postcondition_contract_v1)
    readers = _installed_phase_postcondition_readers_for_count_v1(installed_readers)
    if material is not None:
        from .d11_life_preparation_v1 import _read
        from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
        scope_row = _read(db, issuer=readers.issuer, namespace=binding.task.namespace,
            kind="artifact_task_scope", ref=task_scope_ref_v1(binding.task.root_registration_ref))
        if scope_row is not None and scope_row[0].get("schema") == "d11.ingress-artifact-task-scope.v2":
            from .artifact_phase_postconditions_v1 import authorize_current_task_predecision_v2
            authorize_current_task_predecision_v2(db, frame=frame, task=binding.task,
                operation="prepare_personal_candidates_v1", method_ref=binding.method_ref, installed_readers=readers)
    contract = None
    if frozen is not None:
        if type(frozen) is not ArtifactDraftInputV3:
            raise ValueError("V3 binding requires its exact frozen V3 contract fields")
        contract = read_current_artifact_phase_postcondition_contract_v1(db, frame=frame,
            selector=frozen.selector, installed_readers=readers)
        if (frozen.postcondition_contract_ref, frozen.postcondition_contract_digest,
                contract.policy_ref, contract.policy_digest) != (contract.original_ref, contract.digest,
                binding.postcondition_policy_ref, binding.postcondition_policy_digest):
            raise ValueError("actual counted V3 input changed its current whole-method contract/policy chain")
        goal_ref, plan_ref = contract.goal_head.key.token, contract.plan_head.key.token
    elif material is not None:
        if material.get("binding") != plain_v1(binding):
            raise ValueError("prospective V3 count changed its committed rubric selector")
        goal_ref, plan_ref = material["goal_head"]["key"], material["plan_head"]["key"]
    else:
        raise TypeError("V3 count needs actual prospective material or frozen contract input")
    policy = require_current_artifact_phase_postcondition_policy_v1(db, frame=frame, binding=binding,
        goal_ref=goal_ref, plan_ref=plan_ref, installed_readers=readers)
    if material is not None and material.get("postcondition_policy") != plain_v1(policy):
        raise ValueError("V3 prospective count must contain its actual pre-decision policy original")
    if original_deadline_utc > policy.original_deadline_utc or (contract is not None
            and original_deadline_utc > contract.original_deadline_utc):
        raise ValueError("V3 count cannot extend its precommitted policy or contract deadline")
    sources, _, _ = _phase_count_scope_v1(frame)
    expected_source = (policy.source_head.key.token, policy.source_head.revision, policy.source_value_digest)
    if expected_source not in sources:
        raise MissingProductionOriginalV1("actual_V3_policy_task_source_in_count_scope")
    if contract is not None and (contract.source_head, contract.source_value_digest) != (
            policy.source_head, policy.source_value_digest):
        raise ValueError("V3 contract changed its pre-decision original task source")
    return policy, contract