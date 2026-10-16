"""Exact producer-backed natural expression over existing adopted Graph heads.

No Graph writes or permission issuance occur here. Host original RPCs run
outside Graph SQL. Authority consumers reread their own installed journals.
Only live private observations can qualify a candidate for W01/D09 use.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, fields
import json
import math
import sqlite3

from ..contracts import canonical_json
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion
from ..memory_types import SourceRecord, source_key, access_key, validate_access
from ..runtime_contracts import NamespaceId, FenceScope, VersionedRef, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d06 import source_correction_head_key
from ..domains.d09 import ClaimKind
from ..domains.d09.natural_reply import QualifiedExpressionUnitV2

C04_KIND = "c04_current_interpretation_v1"
DRAFT_KIND = "d11_draft_terminal_v1"
_KEY = object()
_LIVE = {}


@dataclass(frozen=True, slots=True)
class ProducerExpressionContextV1:
    namespace: NamespaceId
    c02_operation_id: str
    audience_id: str
    expires_at_utc: float
    access_epoch: int
    deletion_epoch: int
    source_refs: tuple[VersionedRef, ...]
    access_refs: tuple[VersionedRef, ...]
    correction_refs: tuple[VersionedRef, ...]
    read_versions: tuple[GraphVersion, ...]
    producer_digest: str


@dataclass(frozen=True, slots=True)
class C04InterpretationExpressionCandidateV1:
    context: ProducerExpressionContextV1
    interpretation_ref: VersionedRef
    interpretation_json: str
    prepare_operation_id: str
    adoption_operation_id: str
    binding_digest: str
    adoption_plan_digest: str
    policy_mode: str
    schema: str = "d09.c04-interpretation-expression-candidate.v1"

    @property
    def qualification_digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class D11DraftExpressionCandidateV1:
    context: ProducerExpressionContextV1
    result_ref: str
    fact_ref: VersionedRef
    provenance_ref: VersionedRef
    eligibility_ref: VersionedRef
    readback_json: str
    binding_digest: str
    terminal_digest: str
    schema: str = "d09.d11-draft-expression-candidate.v1"

    @property
    def qualification_digest(self):
        return canonical_digest(plain_v1(self))


CANDIDATE_TYPES = (C04InterpretationExpressionCandidateV1, D11DraftExpressionCandidateV1)


@dataclass(frozen=True, slots=True, init=False)
class _VerifiedProducerObservationV1:
    origin: str
    owner: object
    scope: object
    namespace: NamespaceId
    c02_operation_id: str
    c04_ref: VersionedRef | None
    draft_result_ref: str | None
    c04_proof: object
    c04_verified: object
    life_claim: object
    life_terminal: object
    issuer: object
    current_self: object

    def __init__(self, key, **values):
        if key is not _KEY or set(values) != {field.name for field in fields(self)}:
            raise TypeError("producer observation comes only from an installed observer")
        for name, value in values.items():
            object.__setattr__(self, name, value)


def _producer_json_loads_v3(value):
    from .domain_background_read_v3 import BackgroundJSONColumnV3
    from .current_method_learning_read_v3 import MethodJSONColumnV3
    if type(value)in(BackgroundJSONColumnV3,MethodJSONColumnV3):return value.json_v3()
    return json.loads(value)


def _head(db, namespace, ref):
    key = ref if type(ref) is AtomKey else AtomKey.from_token(ref)
    if NamespaceId.from_key(key) != namespace:
        raise ValueError("producer head crossed namespace")
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    authority=_authority_attachment_owner_v3(db)
    if authority is not None:
        if authority.namespace!=namespace:raise ValueError('Authority producer head crossed namespace')
        return authority.projection.get(key)
    full=_current_host_producer_full_v3(db,namespace)
    if full is not None and key.type_name=='memory.source':
        material=full.source_material
        if material is None:raise ValueError('producer Source plaintext was not prepared')
        record=material.source_record_for_v3(db=db,prepared_full_read=full,namespace=namespace,
            source_ref=key.token,audiences=material.audiences,purpose='expression')
        witness=material.witnesses[key.token]
        return GraphAtom(key,witness.revision,record.to_dict(),witness.valid)
    row = _producer_original_point_v3(db, table='graph_atoms', columns=('revision', 'value', 'valid'), key_columns=('token', 'bot', 'persona'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2]))((key.token, *namespace.as_tuple)), legacy_reader=lambda: db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                     (key.token, *namespace.as_tuple)).fetchone())
    if row is None:return GraphAtom(key,0,{},False)
    from .domain_background_read_v3 import BackgroundJSONColumnV3
    from .current_method_learning_read_v3 import MethodJSONColumnV3
    original=row[1]if type(row[1])in(BackgroundJSONColumnV3,MethodJSONColumnV3)else None
    return GraphAtom(key,row[0],_producer_json_loads_v3(row[1]),bool(row[2]),_canonical_original=original)


def _positive(db, namespace, ref):
    atom = _head(db, namespace, ref)
    if atom.revision < 1 or not atom.valid:
        raise ValueError("actual current producer member is absent or invalidated")
    return atom


def _version(atom):
    return VersionedRef(atom.key.token, atom.revision)


def _c04_locator(db, namespace, c02_operation_id, ref):
    prepared=_HOST_PRODUCER_BINDING_V3.get()
    if prepared is not None:
        require_prepared_host_natural_producers_v3(prepared)
        if (namespace!=prepared.reader.namespace or c02_operation_id!=prepared.parent_original_id
                or ref!=prepared.selectors.c04_ref or prepared.c04 is None):raise ValueError('C04 producer original was not selected by this Work')
        if _head(db,namespace,ref.ref)!=prepared.c04[0]:raise ValueError('prepared C04 interpretation head changed')
        return prepared.c04
    if type(ref) is not VersionedRef or AtomKey.from_token(ref.ref).type_name != "d07.current_interpretation.v1":
        raise TypeError("exact existing interpretation locator required")
    atom = _positive(db, namespace, ref.ref)
    history = _producer_original_point_v3(db, table='graph_history', columns=('event_id', 'value', 'valid'), key_columns=('token', 'revision'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1]))((ref.ref, ref.version)), legacy_reader=lambda: db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
                         (ref.ref, ref.version)).fetchone())
    return read_c04_expression_originals_from_history_v4(db, namespace, c02_operation_id, ref, atom, history)


def read_c04_expression_originals_from_history_v4(db, namespace, c02_operation_id, ref, atom, history):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
    from .c04_frozen_association_original_v3 import read_c04_frozen_association_original_v4
    from .c04_ingress_preparation_v4 import ADOPT_OPERATION, PREPARE_OPERATION
    from .c04_self_scope_v4 import ingress_c04_ids_v4
    from .c04_v3_contracts import C04AdoptionPlanV3, C04AdoptionReceiptV3, canonical_v3_digest
    from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
    """Original-only structural joins; caller authenticates the historical member."""
    if (type(ref) is not VersionedRef or type(atom) is not GraphAtom
            or atom.key.token != ref.ref or atom.key.type_name != "d07.current_interpretation.v1"
            or NamespaceId.from_key(atom.key) != namespace or atom.revision != ref.version
            or not atom.valid or history is None or history[2] != 1 or _producer_json_loads_v3(history[1]) != atom.value):
        raise ValueError("C04 original interpretation member differs from its exact history")
    adopted = read_adopted_domain_operation_v1(db, namespace, history[0])
    if adopted is None or (adopted["domain"], adopted["operation_kind"]) != ("d06", ADOPT_OPERATION):
        raise ValueError("interpretation has no actual Self C04 adoption")
    p = adopted["payload"]["provenance"]
    prepared = read_c04_internal_work_prepared_v1(db, namespace, p["prepare_operation_id"])
    if prepared is None:
        raise ValueError("C04 original preparation is absent")
    work = read_c04_frozen_association_original_v4(db, namespace, prepared.binding)
    if work is None:
        raise ValueError("C04 actual frozen input is absent")
    actual_c03 = read_adopted_ingress_c03_selection_v1(
        db, namespace=namespace, c02_operation_id=c02_operation_id)
    ids = ingress_c04_ids_v4(namespace, c02_operation_id, work.c03_selection_original_digest)
    if (actual_c03 is None or actual_c03[0] != work.direct_selection
            or actual_c03[1]["original_digest"] != work.c03_selection_original_digest
            or work.direct_selection.c02_operation_id != c02_operation_id
            or (prepared.binding.operation_id, history[0]) != (ids["prepare"], ids["adopt"])
            or p["adoption_operation_id"] != history[0]
            or p["binding_digest"] != prepared.binding.binding_digest
            or GraphVersion(atom.key, atom.revision) not in adopted["receipt"].write_versions):
        raise ValueError("C04 prepare/adopt/C03 identities do not join")
    preparation = read_adopted_domain_operation_v1(db, namespace, ids["prepare"])
    if (preparation is None or preparation["operation_kind"] != PREPARE_OPERATION
            or preparation["payload"]["provenance"]["prepared_digest"] != prepared.prepared_digest
            or preparation["payload"]["provenance"]["self_scope_digest"] != work.self_scope_digest):
        raise ValueError("C04 preparation lacks its actual Foreground producer")
    row = _producer_original_point_v3(db, table='graph_c04_adoptions_v3', columns=('bundle_digest', 'plan_json', 'receipt_json'), key_columns=('bot', 'persona', 'operation_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2]))((*namespace.as_tuple, ids['adopt'])), legacy_reader=lambda: db.execute("SELECT bundle_digest,plan_json,receipt_json FROM graph_c04_adoptions_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, ids["adopt"])).fetchone())
    if row is None:
        raise ValueError("C04 paid adoption plan is absent")
    plan, receipt = C04AdoptionPlanV3.from_json(row[1]), C04AdoptionReceiptV3.from_json(row[2])
    receipt.validate_plan(plan)
    if (row[0] != adopted["receipt"].operation_digest
            or plan.operation_id != ids["adopt"] or plan.input_digest != work.input_digest
            or p["plan_digest"] != plan.plan_digest
            or plan.d07_interpretation_digest != canonical_v3_digest(atom.value)
            or not any(member.ref == ref.ref and member.value_digest == canonical_v3_digest(atom.value)
                       for member in plan.writes)):
        raise ValueError("C04 interpretation differs from the actual adopted plan")
    row = _producer_original_point_v3(db, table='graph_c04_adoption_provenance_v3', columns=('original_json', 'original_digest'), key_columns=('bot', 'persona', 'operation_id'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2]))((*namespace.as_tuple, ids['prepare'])), legacy_reader=lambda: db.execute("SELECT original_json,original_digest FROM graph_c04_adoption_provenance_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, ids["prepare"])).fetchone())
    if row is None:
        raise ValueError("C04 adopted interpretation provenance is absent")
    provenance = _producer_json_loads_v3(row[0])
    if (canonical_json(provenance) != row[0] or canonical_digest(provenance) != row[1]
            or provenance["schema"] != "c04.adopted-current-interpretation-original.v4"
            or provenance["prepare_operation_id"] != ids["prepare"]
            or provenance["adoption_operation_id"] != ids["adopt"]
            or provenance["binding_digest"] != prepared.binding.binding_digest
            or provenance["plan_digest"] != plan.plan_digest
            or provenance["receipt_digest"] != canonical_digest(adopted["receipt"])):
        raise ValueError("C04 actual normalized provenance differs")
    return atom, prepared, work, plan, provenance, preparation, adopted


def _draft_locator(db, namespace, c02_operation_id, result_ref, issuer):
    prepared=_HOST_PRODUCER_BINDING_V3.get()
    if prepared is not None:
        require_prepared_host_natural_producers_v3(prepared)
        if (namespace!=prepared.reader.namespace or c02_operation_id!=prepared.parent_original_id
                or result_ref!=prepared.selectors.draft_result_ref or issuer is not prepared.reader.graph._GraphCoordinator__d11_issuer
                or prepared.draft is None):raise ValueError('draft original was not selected by this Work')
        return prepared.draft
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_preparation_v1 import read_prepared_life_v1, _read
    from .d11_life_contract_v1 import D11LifeTerminalV1, D11DraftTerminalV1, life_from_wire_v1
    from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
    from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1, draft_from_wire_v1
    adopted = read_adopted_life_original_v1(db, namespace=namespace, result_ref=result_ref, issuer=issuer)
    if adopted is None:
        raise ValueError("actual signed adopted draft result is absent")
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    if type(terminal) is not D11DraftTerminalV1 or terminal.status != "completed":
        raise ValueError("unknown or incomplete file result cannot qualify completion")
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if prepared is None:
        raise ValueError("actual signed draft preparation is absent")
    readback = require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
    row = _read(db, namespace=namespace, issuer=issuer, kind="activity_scope",
                ref=prepared.plan.activity_scope_ref)
    if row is None:
        raise ValueError("actual signed draft activity scope is absent")
    activity = draft_from_wire_v1(row[0], DraftActivityScopeV1)
    if (activity.c02_original_ref != c02_operation_id
            or canonical_digest(plain_v1(activity)) != prepared.plan.activity_scope_digest
            or activity.activity_id != terminal.binding.activity_id
            or activity.source.ref != prepared.plan.input_source.ref):
        raise ValueError("draft completion belongs to another current C02 activity")
    return prepared, terminal, adopted, readback, activity


def _host_stamp(graph, scope):
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort
    if type(graph) is not GraphCoordinator or type(scope) is not FenceScope:
        raise TypeError("actual installed Graph and held fence required")
    port, store = graph._GraphCoordinator__content_fence_v2, graph._GraphCoordinator__store
    if type(port) is not V2FencePort or store._db.in_transaction:
        raise ValueError("producer RPC observation must be outside Graph SQL")
    if port.validate_fence(scope) != scope.permit:
        raise ValueError("actual held fence validation changed")
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(scope.namespace)
    if (metadata.graph_revision != scope.graph_revision or epoch != scope.graph_epoch
            or not graph._anchor_matches(metadata.requirements, scope.pinned_anchor)):
        raise ValueError("held fence Graph stamp changed")


@contextmanager
def observe_natural_producers_for_fence_v1(
    graph, *, scope, c02_operation_id, c04_ref=None, draft_result_ref=None,
):
    """Observe protected originals via installed ports, never caller callbacks."""
    from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from .c04_product_lifecycle_v3 import c04_terminal_proof_from_inspection_v3
    from ..host.d11_life_port_v1 import InstalledD11LifePortV1
    _host_stamp(graph, scope)
    store, ns, issuer = graph._GraphCoordinator__store, scope.namespace, graph._GraphCoordinator__d11_issuer
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            c04 = _c04_locator(db, ns, c02_operation_id, c04_ref) if c04_ref is not None else None
            draft = _draft_locator(db, ns, c02_operation_id, draft_result_ref, issuer) if draft_result_ref is not None else None
        finally:
            db.rollback()
    proof = verified = claim = terminal = None
    if c04 is not None:
        port = graph._GraphCoordinator__c04_authority_port_v3
        if type(port) is not InstalledC04AuthorityPortV3:
            raise TypeError("actual installed C04 Authority port required")
        proof = c04_terminal_proof_from_inspection_v3(port.inspect(c04[1].binding))
        if proof is None:
            raise ValueError("actual C04 terminal is unresolved")
        verified = port.verify_terminal(proof)
    if draft is not None:
        port = InstalledD11LifePortV1(graph._GraphCoordinator__content_fence_v2)
        claim, terminal = port.read_d11_life_original_v1(binding=draft[0].binding)
        if terminal != draft[1] or claim != terminal.claim:
            raise ValueError("paired original Life journal differs from adopted result")
    from ..host.self_identity_current_port import InstalledCurrentSelfIdentityPort
    self_port = graph._GraphCoordinator__self_identity_port
    if type(self_port) is not InstalledCurrentSelfIdentityPort:
        raise TypeError("producer expression needs the actual paired current Self port")
    current_self = self_port.current_self_identity(namespace=ns,
        authority_namespace=scope.authority_namespace, request_operation_id=scope.operation_id,
        permit=scope.permit)
    if (current_self is None or current_self.permit != scope.permit
            or current_self.request_operation_id != scope.operation_id
            or current_self.graph_revision != scope.graph_revision
            or current_self.graph_epoch != scope.graph_epoch.revision):
        raise ValueError("producer expression lacks its actual current Self/stamp")
    _host_stamp(graph, scope)
    observed = _VerifiedProducerObservationV1(_KEY, origin="host", owner=graph, scope=scope,
        namespace=ns, c02_operation_id=c02_operation_id, c04_ref=c04_ref,
        draft_result_ref=draft_result_ref, c04_proof=proof, c04_verified=verified,
        life_claim=claim, life_terminal=terminal, issuer=issuer, current_self=current_self)
    _LIVE[id(observed)] = observed
    try:
        yield observed
    finally:
        _LIVE.pop(id(observed), None)


@contextmanager
def observe_authority_natural_producers_v1(
    *, fences, credential, subject, permit, namespace, c02_operation_id,
    graph_db, c04_ref=None, draft_result_ref=None, model_service=None, model_intent=None,
):
    """Independent installed Authority originals, before its Graph read BEGIN.

    graph_db is the actual pinned model verifier connection. This context only
    reads it and leaves it outside a transaction for protected journal reads.
    """
    from ..authority_service.v2_fence_service import AuthorityV2FenceService
    from ..authority_service.internal_work_service import AuthorityInternalWorkService
    from ..authority_service.d11_life_service_v1 import AuthorityD11LifeServiceV1
    from .c04_product_lifecycle_v3 import c04_terminal_proof_from_inspection_v3
    if type(fences) is not AuthorityV2FenceService or type(graph_db) is not sqlite3.Connection or graph_db.in_transaction:
        raise TypeError("actual installed Authority fence and idle pinned Graph reader required")
    fences.validate_fence(credential=credential, subject=subject, permit=permit)
    life = fences.core._execution_redaction_d11_life_services_v1.get(fences.namespace)
    if draft_result_ref is not None and (
            type(life) is not AuthorityD11LifeServiceV1 or life.bridge.core is not fences.core
            or life.fences is not fences or life.namespace != namespace):
        raise ValueError("actual installed Life verifier required for a draft producer")
    graph_db.execute("BEGIN")
    try:
        c04 = _c04_locator(graph_db, namespace, c02_operation_id, c04_ref) if c04_ref is not None else None
    finally:
        graph_db.rollback()
    reader = service = None
    if c04 is not None:
        from ..authority_service.c04_current_execution_v3 import InstalledC04CurrentReaderV3
        service = fences.core._execution_redaction_c04_services.get(fences.namespace, {}).get(c04[1].binding.algorithm_ref)
        if (type(service) is not AuthorityInternalWorkService
                or not service.accepts_installed_binding(c04[1].binding)
                or service.journal is not fences.execution):
            raise ValueError("actual installed C04 producer verifier required")
        reader = service._installed_current_reader_v3
        if (type(reader) is not InstalledC04CurrentReaderV3 or reader.namespace != namespace
                or reader.foreground_observer is None
                or reader.foreground_observer.self_identity._core is not fences.core
                or reader.foreground_observer.self_identity._fences is not fences):
            raise ValueError("C04 producer verifier lost its actual installed Self composition")
    if c04 is None and draft_result_ref is None:
        raise ValueError("producer observation must select an actual installed producer")
    issuer = reader.foreground_observer.issuer if reader is not None else life.issuer
    path = reader.graph_path if reader is not None else life.graph_path
    self_service = reader.foreground_observer.self_identity if reader is not None else life.draft_self_identity
    if draft_result_ref is not None and reader is not None and (
            life.graph_path != path or life.issuer is not issuer or life.draft_self_identity is not self_service):
        raise ValueError("C04 and draft producers crossed their installed Graph/issuer/Self")
    database = graph_db.execute("PRAGMA database_list").fetchall()
    from pathlib import Path
    if len(database) != 1 or Path(database[0][2]).resolve() != path.resolve():
        raise ValueError("producer reader changed its installed business database")
    from ..authority_service.v2_self_identity_service import AuthorityV2SelfIdentityService
    from ..authority_service.v2_self_identity_contract import SelfIdentityCurrentRequestV1
    if type(self_service) is not AuthorityV2SelfIdentityService:
        raise ValueError("producer Self read lost its actual installed service")
    if permit.operation == "model_egress":
        from ..authority_service.natural_model_self_v1 import read_natural_model_self_v1
        current_self = read_natural_model_self_v1(self_service=self_service,
            model_service=model_service, credential=credential, subject=subject,
            permit=permit, intent=model_intent)
    else:
        if subject != self_service._read_subject or model_service is not None or model_intent is not None:
            raise ValueError("producer Self read is not the actual installed Host subject")
        current_self = self_service.current(credential=credential, subject=subject,
            request=SelfIdentityCurrentRequestV1(permit.authority_id, fences.namespace, namespace,
                self_service._installation_id, self_service._manifest_digest, permit.operation_id, permit))
        if current_self is None:
            raise ValueError("producer current Self was replaced or revoked")
    graph_db.execute("BEGIN")
    try:
        draft = _draft_locator(graph_db, namespace, c02_operation_id, draft_result_ref, issuer) if draft_result_ref is not None else None
    finally:
        graph_db.rollback()
    proof = verified = claim = terminal = None
    if c04 is not None:
        binding = c04[1].binding
        service = fences.core._execution_redaction_c04_services.get(fences.namespace, {}).get(binding.algorithm_ref)
        if (type(service) is not AuthorityInternalWorkService
                or not service.installed_runtime_verified
                or not service.accepts_installed_binding(binding)
                or service.journal is not fences.execution):
            raise ValueError("actual installed C04 journal/build verifier required")
        proof = c04_terminal_proof_from_inspection_v3(service.inspect(binding))
        if proof is None:
            raise ValueError("original C04 protected terminal is absent")
        verified = service.verify_original_internal_work_terminal(proof)
    if draft is not None:
        claim, terminal = life.read_d11_life_original_v1(draft[0].binding)
        if terminal != draft[1] or claim != terminal.claim:
            raise ValueError("independent protected Life original differs")
    fences.validate_fence(credential=credential, subject=subject, permit=permit)
    observed = _VerifiedProducerObservationV1(_KEY, origin="authority", owner=graph_db, scope=permit,
        namespace=namespace, c02_operation_id=c02_operation_id, c04_ref=c04_ref,
        draft_result_ref=draft_result_ref, c04_proof=proof, c04_verified=verified,
        life_claim=claim, life_terminal=terminal, issuer=issuer, current_self=current_self)
    _LIVE[id(observed)] = observed
    try:
        yield observed
    finally:
        _LIVE.pop(id(observed), None)


def _require_observation(db, observation):
    if (type(observation) is not _VerifiedProducerObservationV1
            or _LIVE.get(id(observation)) is not observation
            or not db.in_transaction):
        raise TypeError("live actual original observation inside the held-fence read required")
    if observation.origin == "host":
        graph = observation.owner
        if db is not graph._GraphCoordinator__store._db or not graph._GraphCoordinator__store._lock._is_owned():
            raise ValueError("producer read requires the actual held Graph lock/connection")
        metadata, epoch = graph._v2_graph_stamp(observation.namespace)
        if metadata.graph_revision != observation.scope.graph_revision or epoch != observation.scope.graph_epoch:
            full=_current_host_producer_full_v3(db,observation.namespace)
            from .current_graph_full_read_v3 import PreparedCurrentGraphFullWriteViewV3
            if (type(full)is not PreparedCurrentGraphFullWriteViewV3
                    or full.facts.writer_scope is not observation.scope
                    or full.facts.before_stamp[0].graph_revision!=observation.scope.graph_revision
                    or full.facts.before_stamp[1]!=observation.scope.graph_epoch
                    or full.facts.after_stamp!=(metadata,epoch)):
                raise ValueError("producer observation Graph stamp changed without actual writer facts")
    else:
        if observation.owner is not db:
            raise ValueError("Authority producer read changed its installed database")
        metadata = db.execute("SELECT graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                              observation.namespace.as_tuple).fetchone()
        epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                           observation.namespace.as_tuple).fetchone()
        if metadata != (observation.current_self.graph_revision,) or epoch != (observation.current_self.graph_epoch,):
            raise ValueError("independent producer observation Graph stamp changed before SQL")


def _source_closure(db, snapshot, namespace, roots, audience):
    current=_source_closure_from_host_material_v3(db,snapshot,namespace,roots,audience)
    if current is not None:return current
    refs, accesses, corrections, reads = {}, {}, {}, {}
    active, done = set(), set()
    def visit(ref):
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise ValueError("producer Source is not canonical in its namespace")
        if ref in active:
            raise ValueError("producer Source ancestry is cyclic")
        if ref in done:
            return
        if len(active) + len(done) >= 256:
            raise ValueError("producer expression Source closure exceeds its bound")
        source = _positive(db, namespace, key)
        access = _positive(db, namespace, access_key(*namespace.as_tuple, key.owner.subject))
        correction = _head(db, namespace, source_correction_head_key(namespace, key.owner.subject))
        record = SourceRecord.from_dict(source.value)
        validate_access(access.value)
        if (correction.revision != 0 or correction.valid
                or record.source_id != key.owner.subject or access.value["source_id"] != key.owner.subject
                or access.value["status"] != "active"
                or audience not in record.audiences or audience not in access.value["audiences"]
                or "expression" not in record.purposes or "expression" not in access.value["purposes"]):
            raise ValueError("producer Source/ancestor lacks current expression permission")
        for atom in (source, access, correction):
            if snapshot.get(atom.key) != atom:
                raise ValueError("producer Source closure is not in the exact current snapshot")
            reads[atom.key.token] = GraphVersion(atom.key, atom.revision)
        refs[source.key.token], accesses[access.key.token] = _version(source), _version(access)
        corrections[correction.key.token] = _version(correction)
        active.add(ref)
        for parent in record.parent_source_ids:
            visit(source_key(*namespace.as_tuple, parent).token)
        active.remove(ref)
        done.add(ref)
    for root in roots:
        visit(root)
    return tuple(tuple(group[ref] for ref in sorted(group)) for group in (refs, accesses, corrections, reads))


def _context(db, snapshot, observed, audience, expires, now, roots, members, digest):
    full=_current_host_producer_full_v3(db,observed.namespace)
    if ((type(snapshot) is not GraphSnapshot if full is None else snapshot is not full.projection) or not audience or type(expires) not in (int, float)
            or not math.isfinite(expires) or not now < expires):
        raise ValueError("current producer expression snapshot/audience/expiry required")
    ns = observed.namespace
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    if (rights is None or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != ns.as_tuple
            or epoch != (snapshot.epochs[0].revision,)):
        raise ValueError("producer expression current barriers differ")
    sources, access, correction, reads = _source_closure(db, snapshot, ns, roots, audience)
    versions = {row.key: row for row in reads}
    for member in members:
        if not _prepared_producer_member_matches_v3(db,ns,snapshot,member):
            raise ValueError("producer member is missing from its actual current prepared attachment")
        versions[member.key] = GraphVersion(member.key, member.revision)
    return ProducerExpressionContextV1(ns, observed.c02_operation_id, audience, float(expires),
        rights[0], rights[1], sources, access, correction,
        tuple(versions[key] for key in sorted(versions, key=lambda key:key.token)), digest)


def _current_self(db, observed, expected_actor, activation_generation):
    from ..domains.d03.self_perspective import self_mapping_key
    atom = _positive(db, observed.namespace, self_mapping_key(observed.namespace))
    from ..domains.d03.self_identity_qualification import self_identity_mapping_from_current
    current = observed.current_self
    from ..authority_service.natural_model_self_v1 import _NaturalModelSelfV1
    mapping = (current.mapping if type(current) is _NaturalModelSelfV1
               else self_identity_mapping_from_current(current))
    permit = observed.scope.permit if observed.origin == "host" else observed.scope
    if (current.namespace != observed.namespace or current.permit != permit
            or current.request_operation_id != permit.operation_id
            or current.activation_generation != activation_generation
            or current.self_entity_ref != expected_actor
            or atom.value != plain_v1(mapping)):
        raise ValueError("producer expression changed its actual registered Core Self projection")
    return atom


def c04_expression_original_projection_v4(*,atom,prepared,work,plan,provenance,preparation,adopted,
        proof,cpu,body,policy,self_atom,child,child_atom,audience_id,valid_until_utc):
    """Pure original producer predicate; it creates no observation or permission."""
    from .c04_result_adoption_v3 import select_c04_result_v3
    from .c04_v3_contracts import GraphHeadV3, canonical_v3_digest
    from .d07_current_behavior_v1 import prepare_current_association_interpretation_v3
    from ..authority_service.installed_c04_executor_v3 import decode_completed_c04_output_v4
    from .jobs import _utc
    from .d11_types import job_graph_write
    binding=prepared.binding;proof_digest=canonical_digest(proof)
    if proof.binding!=binding or proof.terminal.status!="completed":
        raise ValueError("C04 original proof differs from its prepared binding or completion")
    result=decode_completed_c04_output_v4(binding,proof.terminal);result.validate_input(work)
    if (cpu is None or body is None or cpu.binding_digest != binding.binding_digest
            or cpu.prepared_digest != prepared.prepared_digest or cpu.proof_digest != proof_digest
            or cpu.status != "completed" or cpu.budget_receipt_status != "settled"
            or not cpu.component_completed or cpu.actual_cpu_ms != proof.terminal.actual_cpu_ms
            or cpu.budget_lease_id != binding.parent_budget_lease_ref
            or cpu.terminal_receipt_digest != proof.terminal_receipt_digest
            or body.binding_digest != binding.binding_digest or body.proof_digest != cpu.proof_digest
            or body.component_receipt_ref != proof.terminal.component_receipt_ref
            or plan.result_digest != result.result_digest
            or plan.terminal_receipt_digest != "sha256:" + proof.terminal_receipt_digest
            or plan.d02_settlement_digest != "sha256:" + canonical_digest(asdict(body))
            or plan.d11_settlement_digest != "sha256:" + canonical_digest(asdict(cpu))):
        raise ValueError("C04 actual paid Body/CPU adoption differs")
    # The actual installer currently installs this exact mode. Semantic adoption
    # modes require their own concrete installed original reader before enabling.
    if policy.mode != "recollection_presence":
        raise ValueError("installed semantic interpretation producer is not in this finite path")
    originals = provenance["interpretation"]
    heads = tuple(GraphHeadV3(**row) for row in originals["source_heads"])
    _, selection = select_c04_result_v3(work, result, focus_epoch=work.selection_ticket.focus_epoch)
    issued = prepare_current_association_interpretation_v3(
        work, result, selection.selection_ticket, heads, (), policy,
        binding_digest=binding.binding_digest, execution_id=binding.execution_id,
        activation_generation=binding.activation_generation)
    expected = {"schema": "d07.current_interpretation.v1", **plain_v1(issued.candidate)}
    if (atom.value != expected or plain_v1(issued.provenance_payload) != originals
            or atom.key.name != issued.candidate.interpretation_id
            or plan.d07_interpretation_digest != canonical_v3_digest(expected)
            or audience_id != work.audience):
        raise ValueError("C04 exact interpretation projection differs from its actual producer")
    p = preparation["payload"]["provenance"]
    if (child.phase != "completed" or child.cancel_epoch or child.fence != 1
            or child.continuation.get("adoption_plan_digest") != plan.plan_digest
            or child_atom.value != job_graph_write(child).value):
        raise ValueError("C04 actual completed product job differs")
    deadline = min(valid_until_utc, _utc(child.deadline_utc, "deadline").timestamp(),
                   _utc(p["after_parent"]["deadline_utc"], "deadline").timestamp())
    roots = tuple(issued.candidate.source_refs)
    digest = canonical_digest({
        "adopted": adopted["original_digest"], "prepared": prepared.prepared_digest,
        "plan": plan.plan_digest, "provenance": provenance,
        "proof": proof_digest, "self": self_atom.value,
    })
    return dict(roots=roots, deadline=deadline, producer_digest=digest, interpretation_ref=_version(atom),
        interpretation_json=canonical_json(atom.value), prepare_operation_id=binding.operation_id,
        adoption_operation_id=plan.operation_id, binding_digest=binding.binding_digest,
        adoption_plan_digest=plan.plan_digest, policy_mode=policy.mode)



def read_current_c04_expression_candidate_v1(
    db, *, observed, snapshot, audience_id, valid_until_utc, now_utc,
):
    _require_observation(db, observed)
    if observed.c04_ref is None:
        raise ValueError("C04 expression was not independently observed")
    from .c04_v3_contracts import GraphHeadV3
    from .c04_interpretation_policy_v3 import read_installed_c04_interpretation_policy_v3
    from ..authority_service.internal_work_service import AuthorityInternalWorkVerifiedReceiptV1
    from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1
    from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
    from .jobs import get_job
    atom, prepared, work, plan, provenance, preparation, adopted = _c04_locator(
        db, observed.namespace, observed.c02_operation_id, observed.c04_ref)
    proof, verified, binding = observed.c04_proof, observed.c04_verified, prepared.binding
    if (proof.binding != binding or type(verified) is not AuthorityInternalWorkVerifiedReceiptV1
            or verified.proof_digest != canonical_digest(proof)
            or verified.operation_id != binding.operation_id or verified.input_digest != binding.input_digest
            or verified.terminal_receipt_digest != proof.terminal_receipt_digest
            or verified.actual_cpu_ms != proof.terminal.actual_cpu_ms
            or verified.status != "completed" or not verified.component_completed):
        raise ValueError("C04 actual independent original verification differs")
    cpu=read_c04_cpu_cost_original_v1(db,observed.namespace,binding.operation_id)
    body=read_c04_body_cost_original_v1(db,observed.namespace,binding.operation_id)
    policy,_=read_installed_c04_interpretation_policy_v3(db,observed.namespace,prepared,
        installation_id=work.direct_selection.installation_id,manifest_digest=work.direct_selection.manifest_digest)
    for row in provenance["interpretation"]["source_heads"]:
        source=GraphHeadV3(**row)
        if AtomKey.from_token(source.ref).type_name=="memory.source":
            current=_positive(db,observed.namespace,source.ref)
            if current.revision!=source.revision or current.value!=source.value:
                raise ValueError("C04 interpreted Source changed after its actual adoption")
    p=preparation["payload"]["provenance"]
    self_atom=_current_self(db,observed,p["initiating_self"],binding.activation_generation)
    child=get_job(db,AtomKey.from_token(p["child_job_ref"]).name)
    child_atom=_positive(db,observed.namespace,p["child_job_ref"])
    projection=c04_expression_original_projection_v4(atom=atom,prepared=prepared,work=work,plan=plan,
        provenance=provenance,preparation=preparation,adopted=adopted,proof=proof,cpu=cpu,body=body,policy=policy,
        self_atom=self_atom,child=child,child_atom=child_atom,audience_id=audience_id,valid_until_utc=valid_until_utc)
    context=_context(db,snapshot,observed,audience_id,projection["deadline"],now_utc,
        projection["roots"],(atom,self_atom,child_atom),projection["producer_digest"])
    return C04InterpretationExpressionCandidateV1(context,**{name:value for name,value in projection.items()
        if name not in {"roots","deadline","producer_digest"}})


def draft_expression_original_projection_v4(*,prepared,terminal,adopted,readback,activity,
        self_atom,fact,proof,eligibility,result_ref,audience_id,valid_until_utc):
    """Pure original completed-file assertion; it grants no present write rights."""
    from .d11_offline_originals_v1 import _utc
    if audience_id not in prepared.plan.audiences:
        raise ValueError("draft result was not admitted for this expression audience")
    deadline = min(valid_until_utc, _utc(prepared.plan.deadline_utc).timestamp(),
                   _utc(activity.valid_until_utc).timestamp())
    roots = tuple(dict.fromkeys((*adopted["source_refs"], *prepared.plan.content.source_refs)))
    digest = canonical_digest({"adopted": adopted, "prepared": prepared.digest,
        "claim": terminal.claim.claim_digest, "terminal": terminal.terminal_digest,
        "readback": plain_v1(readback), "self": self_atom.value})
    return dict(roots=roots, deadline=deadline, producer_digest=digest, result_ref=result_ref,
        fact_ref=_version(fact), provenance_ref=_version(proof), eligibility_ref=_version(eligibility),
        readback_json=canonical_json(plain_v1(readback)), binding_digest=terminal.binding.digest,
        terminal_digest=terminal.terminal_digest)



def read_current_draft_expression_candidate_v1(
    db, *, observed, snapshot, audience_id, valid_until_utc, now_utc,
):
    _require_observation(db, observed)
    if observed.draft_result_ref is None:
        raise ValueError("draft expression was not independently observed")
    from .d11_life_fact_provenance_v1 import (
        require_current_life_fact_eligibility_v1, life_fact_auxiliary_key_v1,
        life_current_fact_reads_v1, PROVENANCE_TYPE, ELIGIBILITY_TYPE,
    )
    prepared, terminal, adopted, readback, activity = _draft_locator(
        db, observed.namespace, observed.c02_operation_id, observed.draft_result_ref, observed.issuer)
    if terminal != observed.life_terminal or terminal.claim != observed.life_claim:
        raise ValueError("draft independent protected journal original changed")
    fact_keys = require_current_life_fact_eligibility_v1(
        db, prepared=prepared, terminal=terminal, adopted=adopted)
    fact = _positive(db, observed.namespace, terminal.binding.artifact_ref)
    proof = _positive(db, observed.namespace, life_fact_auxiliary_key_v1(fact.key, PROVENANCE_TYPE))
    eligibility = _positive(db, observed.namespace, life_fact_auxiliary_key_v1(fact.key, ELIGIBILITY_TYPE))
    members = {atom.key: atom for atom in (fact, proof, eligibility)}
    from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
    for key in fact_keys:
        if key.type_name == "d08.action_outcome.v1":
            keys = life_outcome_read_keys_v1(terminal.binding, prepared.plan.action_intent.ref)
        else:
            keys = (key, life_fact_auxiliary_key_v1(key, PROVENANCE_TYPE),
                    life_fact_auxiliary_key_v1(key, ELIGIBILITY_TYPE))
        for member in keys:
            atom = _positive(db, observed.namespace, member)
            members[atom.key] = atom
    for frozen in life_current_fact_reads_v1(prepared):
        atom = _head(db, observed.namespace, frozen.ref)
        members[atom.key] = atom
    self_atom = _current_self(db, observed, activity.actor_ref, terminal.binding.activation_generation)
    members[self_atom.key] = self_atom
    projection=draft_expression_original_projection_v4(prepared=prepared,terminal=terminal,adopted=adopted,
        readback=readback,activity=activity,self_atom=self_atom,fact=fact,proof=proof,eligibility=eligibility,
        result_ref=observed.draft_result_ref,audience_id=audience_id,valid_until_utc=valid_until_utc)
    context=_context(db,snapshot,observed,audience_id,projection["deadline"],now_utc,
        projection["roots"],tuple(members.values()),projection["producer_digest"])
    return D11DraftExpressionCandidateV1(context,**{name:value for name,value in projection.items()
        if name not in {"roots","deadline","producer_digest"}})


def producer_expression_unit_v1(candidate):
    """Pure exact projection. Callers must first establish actual original trust."""
    if type(candidate) not in CANDIDATE_TYPES:
        raise TypeError("closed producer candidate type required")
    c = candidate.context
    common = dict(source_refs=c.source_refs, access_refs=c.access_refs,
        correction_refs=c.correction_refs, audience_ref=c.audience_id,
        purpose="expression", expires_at_utc=c.expires_at_utc,
        qualification_digest=candidate.qualification_digest, direct_quote=False,
        speaker_id="persona:" + c.namespace.persona_id, attribution_required=False)
    if type(candidate) is C04InterpretationExpressionCandidateV1:
        value = _producer_json_loads_v3(candidate.interpretation_json)
        return QualifiedExpressionUnitV2(
            basis_id="basis:c04-interpretation:" + candidate.qualification_digest,
            kind=ClaimKind.SUBJECTIVE_JUDGMENT, qualified_text=value["proposition"],
            qualification_ref=candidate.interpretation_ref,
            content_reality="subjective_interpretation", stance=value["stance"],
            uncertainty=canonical_json({"subjective_conviction": value["subjective_conviction"],
                "evidence_status": value["evidence_status"],
                "meaningful_unknowns": value["meaningful_unknowns"]}),
            semantic_constraints=("preserve_subjective_stance_and_all_unknowns",
                                  "recollection_selection_does_not_confirm_external_truth"),
            d06_claim_kind=C04_KIND, **common)
    value = _producer_json_loads_v3(candidate.readback_json)
    text = ("文件 " + value["filename"] + " 的第 " + str(value["version"]) +
            " 版已在 " + value["verified_at_utc"] + " 验证完成写入；内容摘要为 " +
            value["content_digest"] + "。")
    return QualifiedExpressionUnitV2(
        basis_id="basis:d11-draft:" + candidate.qualification_digest,
        kind=ClaimKind.INTERNAL_ACTIVITY, qualified_text=text,
        qualification_ref=candidate.eligibility_ref,
        content_reality="verified_internal_activity",
        semantic_constraints=("completed_at_the_original_readback_time_only",
                              "no_claim_of_unchanged_current_file_or_new_write_permission"),
        d06_claim_kind=DRAFT_KIND, **common)


def recompute_producer_expression_unit_v1(
    db, *, observed, candidate, snapshot, current_reads, audience_id,
    access_epoch, deletion_epoch, now_utc,
):
    """Rejoin actual producers and compare every qualified field under one fence."""
    if type(candidate) not in CANDIDATE_TYPES or type(current_reads) is not tuple:
        raise TypeError("closed producer candidate and actual current read set required")
    fn = (read_current_c04_expression_candidate_v1
          if type(candidate) is C04InterpretationExpressionCandidateV1
          else read_current_draft_expression_candidate_v1)
    rebuilt = fn(db, observed=observed, snapshot=snapshot, audience_id=audience_id,
        valid_until_utc=candidate.context.expires_at_utc, now_utc=now_utc)
    if (rebuilt != candidate
            or (rebuilt.context.access_epoch, rebuilt.context.deletion_epoch) != (access_epoch, deletion_epoch)
            or any(row not in current_reads for row in rebuilt.context.read_versions)):
        raise ValueError("producer expression original, qualifiers or current read closure changed")
    return producer_expression_unit_v1(rebuilt)


def producer_expression_read_inputs_v1(db, *, observed):
    """Bound exact metadata keys and Source roots before building the snapshot."""
    _require_observation(db, observed)
    from ..domains.d03.self_perspective import self_mapping_key
    keys = {self_mapping_key(observed.namespace)}
    roots = set()
    if observed.c04_ref is not None:
        atom, prepared, work, plan, provenance, preparation, adopted = _c04_locator(
            db, observed.namespace, observed.c02_operation_id, observed.c04_ref)
        keys.update((atom.key, AtomKey.from_token(preparation["payload"]["provenance"]["child_job_ref"])))
        roots.update(atom.value["source_refs"])
        semantic = provenance["interpretation"].get("adoption_original")
        if semantic is not None:
            roots.update((*semantic["supporting_refs"], *semantic["counter_refs"]))
    if observed.draft_result_ref is not None:
        from .d11_life_fact_provenance_v1 import (
            life_fact_auxiliary_key_v1, life_current_fact_reads_v1, PROVENANCE_TYPE, ELIGIBILITY_TYPE)
        from .d11_life_graph_types_v1 import life_role_segment_key_v1
        from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
        prepared, terminal, adopted, _, _ = _draft_locator(
            db, observed.namespace, observed.c02_operation_id, observed.draft_result_ref, observed.issuer)
        for fact in (AtomKey.from_token(terminal.binding.artifact_ref),
                     life_role_segment_key_v1(terminal.binding, "start"),
                     life_role_segment_key_v1(terminal.binding, "end")):
            keys.update((fact, life_fact_auxiliary_key_v1(fact, PROVENANCE_TYPE),
                         life_fact_auxiliary_key_v1(fact, ELIGIBILITY_TYPE)))
        keys.update(life_outcome_read_keys_v1(terminal.binding, prepared.plan.action_intent.ref))
        keys.update(AtomKey.from_token(row.ref) for row in life_current_fact_reads_v1(prepared))
        roots.update((*adopted["source_refs"], *prepared.plan.content.source_refs))
    return tuple(sorted(keys, key=lambda key:key.token)), tuple(sorted(roots))


# Qualification candidates are reconstructed, never separately persisted.
def _read_natural_preparation(db, namespace, parent_original_id, stage):
    from .natural_reply_job_v2 import read_original_preparation
    return read_original_preparation(db, namespace, parent_original_id, stage)


_NATURAL_FRAME = ContextVar("sylanne_natural_producer_verification_v1", default=None)
_FRAME_KEY = object()
_FRAMES = {}
_SOURCE_KINDS = frozenset({"attributed_report", "confirmed_external_fact"})


@dataclass(frozen=True, slots=True)
class NaturalProducerSelectorsV1:
    c04_ref: VersionedRef | None
    draft_result_ref: str | None

    @property
    def empty(self):
        return self.c04_ref is None and self.draft_result_ref is None


@dataclass(frozen=True, slots=True, init=False)
class _NaturalProducerFrameV1:
    db: object
    namespace: NamespaceId
    parent_original_id: str
    selectors: NaturalProducerSelectorsV1
    observation: object
    frozen_units: tuple | None
    graph: object
    scope: object
    phase: str | None
    origin: str

    def __init__(self, key, db, namespace, parent, selectors, observation, frozen_units,
                 *, graph=None, scope=None, phase=None, origin="authority"):
        if key is not _FRAME_KEY:
            raise TypeError("natural producer frame requires its actual installed observation")
        for name, value in (("db", db), ("namespace", namespace), ("parent_original_id", parent),
                ("selectors", selectors), ("observation", observation), ("frozen_units", frozen_units),
                ("graph", graph), ("scope", scope), ("phase", phase), ("origin", origin)):
            object.__setattr__(self, name, value)


def _unit_kinds(units):
    if type(units) is not tuple:
        raise TypeError("frozen natural units must be an exact tuple")
    allowed = _SOURCE_KINDS | {C04_KIND, DRAFT_KIND}
    if any(type(unit) is not QualifiedExpressionUnitV2 or unit.d06_claim_kind not in allowed for unit in units):
        raise ValueError("natural basis has an unqualified or unknown producer kind")
    return tuple(unit.d06_claim_kind for unit in units)


def _draft_result_from_eligibility(db, namespace, ref):
    from .d11_life_fact_provenance_v1 import (
        decode_life_fact_auxiliary_v1, life_fact_auxiliary_key_v1, ELIGIBILITY_TYPE, PROVENANCE_TYPE)
    from .d11_life_contract_v1 import D11DraftExecutionBindingV1, draft_artifact_ref_v1
    if type(ref) is not VersionedRef or AtomKey.from_token(ref.ref).type_name != ELIGIBILITY_TYPE:
        raise TypeError("draft basis needs its exact current eligibility locator")
    eligibility_atom = _positive(db, namespace, ref.ref)
    if eligibility_atom.revision != ref.version:
        raise ValueError("frozen draft eligibility version changed")
    eligibility = decode_life_fact_auxiliary_v1(ELIGIBILITY_TYPE, eligibility_atom.value)
    proof_atom = _positive(db, namespace, eligibility.provenance_ref)
    if (proof_atom.revision != eligibility.provenance_revision
            or canonical_digest(proof_atom.value) != eligibility.provenance_digest):
        raise ValueError("draft eligibility lost its exact producer proof")
    proof = decode_life_fact_auxiliary_v1(PROVENANCE_TYPE, proof_atom.value)
    b = proof.binding
    if (type(b) is not D11DraftExecutionBindingV1 or b.namespace != namespace
            or eligibility.fact_ref != proof.fact_ref or proof.fact_ref != b.artifact_ref
            or b.artifact_ref != draft_artifact_ref_v1(namespace, b.effect_id)
            or life_fact_auxiliary_key_v1(AtomKey.from_token(b.artifact_ref), ELIGIBILITY_TYPE) != eligibility_atom.key):
        raise ValueError("draft eligibility changed its deterministic actual result")
    return b.artifact_ref


def frozen_natural_producer_selectors_v1(db, *, namespace, frozen):
    units = frozen.input.plan.units
    _unit_kinds(units)
    c04 = tuple(unit for unit in units if unit.d06_claim_kind == C04_KIND)
    drafts = tuple(unit for unit in units if unit.d06_claim_kind == DRAFT_KIND)
    if len(c04) > 1 or len(drafts) > 1:
        raise ValueError("sealed natural scope has duplicate producer families")
    c04_ref = c04[0].qualification_ref if c04 else None
    if c04 and (type(c04_ref) is not VersionedRef
                or AtomKey.from_token(c04_ref.ref).type_name != "d07.current_interpretation.v1"):
        raise ValueError("sealed C04 unit lost its actual interpretation locator")
    result_ref = (_draft_result_from_eligibility(db, namespace, drafts[0].qualification_ref)
                  if drafts else None)
    return NaturalProducerSelectorsV1(c04_ref, result_ref)


def _has_named_producer_original_owner_v3(db):
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .domain_background_read_v3 import _active_v3
    return (_authority_attachment_owner_v3(db)is not None or _active_v3(db)is not None
        or _host_producer_attachment_owner_v3(db)is not None)


def fresh_natural_producer_selectors_v1(db, *, namespace, parent_original_id, issuer):
    from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
    from .c04_self_scope_v4 import ingress_c04_ids_v4
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_life_preparation_v1 import TABLE, _read
    from .d11_artifact_draft_content_v1 import (
        artifact_draft_content_from_wire_v1, ArtifactDraftContentAdoptionV1)
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
    from .d11_life_contract_v1 import draft_artifact_ref_v1
    c04_ref = result_ref = None
    selection = read_adopted_ingress_c03_selection_v1(
        db, namespace=namespace, c02_operation_id=parent_original_id)
    if selection is not None and selection[0].selected_source_ref is not None:
        ids = ingress_c04_ids_v4(namespace, parent_original_id, selection[1]["original_digest"])
        adopted = read_adopted_domain_operation_v1(db, namespace, ids["adopt"])
        if adopted is None or adopted["operation_kind"] != "adopt_ingress_c04_v1":
            raise ValueError("selected recall is awaiting its actual C04 adoption")
        refs = tuple(row for row in adopted["receipt"].write_versions
                     if row.key.type_name == "d07.current_interpretation.v1")
        if len(refs) != 1:
            raise ValueError("actual C04 adoption has no unique interpretation member")
        c04_ref = VersionedRef(refs[0].key.token, refs[0].revision)
    rows = (_fresh_signed_draft_refs_v3(db,namespace,parent_original_id,issuer)
        if _has_named_producer_original_owner_v3(db) else db.execute("SELECT original_ref FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='c4_adopted' "
        "AND json_extract(payload_json,'$.selector.c02_operation_id')=? ORDER BY original_ref LIMIT 2",
        (*namespace.as_tuple, parent_original_id)).fetchall())
    if len(rows) > 1:
        raise ValueError("natural completion has more than one actual artifact task")
    if rows:
        row = _read(db, namespace=namespace, issuer=issuer, kind="c4_adopted", ref=rows[0][0])
        if row is None:
            raise ValueError("selected artifact content lacks its actual signed adoption")
        content = artifact_draft_content_from_wire_v1(row[0], ArtifactDraftContentAdoptionV1)
        if (content.selector.namespace != namespace or content.selector.c02_operation_id != parent_original_id
                or row[1] != content.adoption_operation_id):
            raise ValueError("selected artifact content changed its C02 producer")
        ids = artifact_draft_file_ids_v1(namespace, c02_operation_id=parent_original_id,
                                        root_registration_ref=content.selector.root_registration_ref)
        result_ref = draft_artifact_ref_v1(namespace, ids["effect"])
        _draft_locator(db, namespace, parent_original_id, result_ref, issuer)
    return NaturalProducerSelectorsV1(c04_ref, result_ref)


@contextmanager
def _bind_natural_frame(db, namespace, parent, selectors, observation, frozen_units,
                        *, graph=None, scope=None, phase=None, origin="authority"):
    frame = _NaturalProducerFrameV1(_FRAME_KEY, db, namespace, parent, selectors, observation, frozen_units,
        graph=graph, scope=scope, phase=phase, origin=origin)
    _FRAMES[id(frame)] = frame
    token = _NATURAL_FRAME.set(frame)
    try:
        yield frame
    finally:
        _NATURAL_FRAME.reset(token)
        _FRAMES.pop(id(frame), None)


def _natural_frame(db=None, namespace=None):
    frame = _NATURAL_FRAME.get()
    if (type(frame) is not _NaturalProducerFrameV1 or _FRAMES.get(id(frame)) is not frame
            or db is not None and frame.db is not db
            or namespace is not None and frame.namespace != namespace
            or not frame.db.in_transaction):
        raise ValueError("producer basis has no actual live verification context")
    if not frame.selectors.empty:
        _require_observation(frame.db, frame.observation)
    return frame




@contextmanager
def host_natural_producer_context_v1(graph, *, scope, parent_original_id, phase):
    prepared=_HOST_PRODUCER_BINDING_V3.get()
    if prepared is not None:
        if parent_original_id!=prepared.parent_original_id:raise ValueError('producer handoff changed original C02')
        with _renew_prepared_host_natural_producer_scope_v3(graph,scope=scope,prepared=prepared,phase=phase)as frame:
            yield frame
        return
    from ..runtime_storage_v3 import runtime_storage_v3
    if runtime_storage_v3(graph._GraphCoordinator__store._db)is not None:
        raise ValueError('V3 Host producer requires its actual same-Work prepared originals')
    if phase not in {"prepare", "frozen"}:
        raise ValueError("closed natural producer phase required")
    store = graph._GraphCoordinator__store
    if store._db.in_transaction:
        raise ValueError("natural producer observation must precede Graph SQL")
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            saved = _read_natural_preparation(db, scope.namespace, parent_original_id, "generation")
            if saved is None:
                if phase != "prepare" or scope.operation != "write":
                    raise ValueError("frozen natural producer scope has no actual generation original")
                selectors = fresh_natural_producer_selectors_v1(
                    db, namespace=scope.namespace, parent_original_id=parent_original_id,
                    issuer=graph._GraphCoordinator__d11_issuer)
                frozen_units = None
            else:
                selectors = frozen_natural_producer_selectors_v1(db, namespace=scope.namespace, frozen=saved.frozen)
                frozen_units = saved.frozen.input.plan.units
        finally:
            db.rollback()
    if selectors.empty:
        with _bind_natural_frame(db, scope.namespace, parent_original_id, selectors, None, frozen_units,
                graph=graph, scope=scope, phase=phase, origin="host") as frame:
            yield frame
    else:
        with observe_natural_producers_for_fence_v1(
            graph, scope=scope, c02_operation_id=parent_original_id,
            c04_ref=selectors.c04_ref, draft_result_ref=selectors.draft_result_ref,
        ) as observed:
            with _bind_natural_frame(db, scope.namespace, parent_original_id, selectors, observed, frozen_units,
                    graph=graph, scope=scope, phase=phase, origin="host") as frame:
                yield frame


@contextmanager
def authority_natural_producer_context_v1(
    db, *, fences, credential, subject, permit, namespace, parent_original_id,
    model_service=None, model_intent=None,
):
    if db.in_transaction:
        raise ValueError("independent producer observation must precede Graph SQL")
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    actual=_authority_attachment_owner_v3(db)
    if actual is not None:
        if actual.producer_context is None or actual.parent_original_id!=parent_original_id or actual.namespace!=namespace:
            raise ValueError('Authority natural producer context is not its actual observed same-Work input')
        yield actual.producer_frame
        return
    db.execute("BEGIN")
    try:
        saved = _read_natural_preparation(db, namespace, parent_original_id, "generation")
        if saved is None:
            raise ValueError("independent natural producer has no actual sealed generation")
        selectors = frozen_natural_producer_selectors_v1(db, namespace=namespace, frozen=saved.frozen)
        frozen_units = saved.frozen.input.plan.units
    finally:
        db.rollback()
    if selectors.empty:
        with _bind_natural_frame(db, namespace, parent_original_id, selectors, None, frozen_units) as frame:
            yield frame
    else:
        with observe_authority_natural_producers_v1(
            fences=fences, credential=credential, subject=subject, permit=permit,
            namespace=namespace, c02_operation_id=parent_original_id, graph_db=db,
            c04_ref=selectors.c04_ref, draft_result_ref=selectors.draft_result_ref,
            model_service=model_service, model_intent=model_intent,
        ) as observed:
            with _bind_natural_frame(db, namespace, parent_original_id, selectors, observed, frozen_units) as frame:
                yield frame


def natural_basis_snapshot_v1(db, *, namespace, snapshot, units=()):
    """Add exact producer members and Source ancestry, preserving absence proofs."""
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    authority=_authority_attachment_owner_v3(db)
    if authority is not None:
        if authority.namespace!=namespace or snapshot is not authority.projection or authority.source_material is None:
            raise ValueError('Authority natural basis crossed its actual projection/Source material')
        _natural_frame(db,namespace)
        return snapshot
    prepared=_HOST_PRODUCER_BINDING_V3.get()
    if prepared is not None:
        from .current_graph_full_read_v3 import require_bound_graph_full_read_v3,CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3
        actual,query=require_bound_graph_full_read_v3(prepared.reader.graph,db,namespace,
            required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3}))
        if snapshot is not actual:raise ValueError('producer basis lost its actual FULL projection')
        require_prepared_host_natural_producers_v3(prepared)
        _natural_frame(db,namespace)
        return snapshot
    frame = _natural_frame(db, namespace)
    keys, roots = (producer_expression_read_inputs_v1(db, observed=frame.observation)
                   if not frame.selectors.empty else ((), ()))
    atoms = {atom.key: atom for atom in snapshot.atoms}
    roots = set(roots)
    for unit in units:
        roots.update(ref.ref for ref in unit.source_refs)
        if unit.qualification_ref is not None:
            keys = (*keys, AtomKey.from_token(unit.qualification_ref.ref))
    def add(key):
        atom = _head(db, namespace, key)
        old = atoms.get(atom.key)
        if old is not None and old != atom:
            raise ValueError("natural producer member changed in the current snapshot")
        atoms[atom.key] = atom
        return atom
    for key in keys:
        add(key)
    pending, seen = list(sorted(roots)), set()
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if len(seen) >= 256:
            raise ValueError("natural producer Source ancestry exceeds its bound")
        seen.add(ref)
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise ValueError("natural basis crossed the actual namespace Source family")
        source = add(key)
        if not source.valid:
            raise ValueError("natural basis Source is unavailable")
        record = SourceRecord.from_dict(source.value)
        add(access_key(*namespace.as_tuple, record.source_id))
        add(source_correction_head_key(namespace, record.source_id))
        pending.extend(source_key(*namespace.as_tuple, parent).token for parent in record.parent_source_ids)
    return GraphSnapshot(tuple(atoms.values()), snapshot.epochs)


def read_live_producer_candidates_v1(db, *, snapshot, audience_id, expires_at_utc, now_utc):
    frame = _natural_frame(db)
    values = []
    if frame.selectors.c04_ref is not None:
        values.append(read_current_c04_expression_candidate_v1(db, observed=frame.observation,
            snapshot=snapshot, audience_id=audience_id, valid_until_utc=expires_at_utc, now_utc=now_utc))
    if frame.selectors.draft_result_ref is not None:
        values.append(read_current_draft_expression_candidate_v1(db, observed=frame.observation,
            snapshot=snapshot, audience_id=audience_id, valid_until_utc=expires_at_utc, now_utc=now_utc))
    return tuple(values)


def _natural_source_expression_kwargs_v3(namespace):
    frame=_natural_frame(namespace=namespace)
    from ..authority_service.current_authority_graph_read_v3 import authority_source_expression_kwargs_v3
    actual=authority_source_expression_kwargs_v3(frame.db,namespace)
    if actual is not None:return actual
    prepared=_HOST_PRODUCER_BINDING_V3.get()
    return{}if prepared is None else _host_source_expression_kwargs_v3(prepared.reader.db,namespace)


def source_candidate_for_frozen_unit_v1(snapshot, *, namespace, unit, access_epoch, deletion_epoch):
    from ..domains.d06.qualified_expression import (
        QualifiedExpressionRequest, SourceTextSpan, prepare_qualified_expression_unit)
    if unit.d06_claim_kind not in _SOURCE_KINDS or not unit.source_refs or unit.evidence_span is None:
        raise ValueError("sealed Source basis lacks its finite original qualification")
    span = lambda value: None if value is None else SourceTextSpan(*value)
    request = QualifiedExpressionRequest(unit.source_refs[0].ref, unit.d06_claim_kind,
        SourceTextSpan(*unit.evidence_span), span(unit.direct_quote_span),
        unit.qualified_text if unit.direct_quote else None, span(unit.negation_cue_span))
    return prepare_qualified_expression_unit(snapshot, namespace=namespace, request=request,
        audiences=(unit.audience_ref,), access_epoch=access_epoch,
        deletion_epoch=deletion_epoch, valid_until=unit.expires_at_utc,
        **_natural_source_expression_kwargs_v3(namespace))


def frozen_natural_basis_candidates_v1(db, *, plan, snapshot, access_epoch, deletion_epoch, now_utc):
    frame = _natural_frame(db, plan.namespace)
    _unit_kinds(plan.units)
    if frame.frozen_units is not None and frame.frozen_units != plan.units:
        raise ValueError("frozen natural recovery cannot change or add a basis")
    candidates = []
    for unit in plan.units:
        if unit.d06_claim_kind in _SOURCE_KINDS:
            candidate = source_candidate_for_frozen_unit_v1(snapshot, namespace=plan.namespace,
                unit=unit, access_epoch=access_epoch, deletion_epoch=deletion_epoch)
        else:
            fn = (read_current_c04_expression_candidate_v1 if unit.d06_claim_kind == C04_KIND
                  else read_current_draft_expression_candidate_v1)
            candidate = fn(db, observed=frame.observation, snapshot=snapshot,
                audience_id=plan.audience_id, valid_until_utc=unit.expires_at_utc, now_utc=now_utc)
            if producer_expression_unit_v1(candidate) != unit:
                raise ValueError("sealed producer unit differs from its actual current original")
        if candidate.qualification_digest != unit.qualification_digest:
            raise ValueError("sealed natural basis qualification changed")
        candidates.append(candidate)
    return tuple(candidates)


def verify_live_producer_candidate_v1(candidate, unit, *, snapshot, current_reads,
                                     access_epoch, deletion_epoch, now_utc):
    frame = _natural_frame(namespace=candidate.context.namespace)
    rebuilt = recompute_producer_expression_unit_v1(frame.db, observed=frame.observation,
        candidate=candidate, snapshot=snapshot, current_reads=current_reads,
        audience_id=unit.audience_ref, access_epoch=access_epoch, deletion_epoch=deletion_epoch,
        now_utc=now_utc)
    if rebuilt != unit:
        raise ValueError("producer unit changed its exact original projection")
    return candidate.context.read_versions


def producer_candidate_read_versions_v1(candidates):
    return tuple(dict.fromkeys(row for candidate in candidates if type(candidate) in CANDIDATE_TYPES
                               for row in candidate.context.read_versions))


def assert_live_frozen_producer_basis_v1(frozen, *, now_utc):
    units = frozen.input.plan.units
    kinds = _unit_kinds(units)
    if not any(kind in {C04_KIND, DRAFT_KIND} for kind in kinds):
        return ()
    frame = _natural_frame(namespace=frozen.input.plan.namespace)
    db = frame.db
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                       frame.namespace.as_tuple).fetchone()
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                        frame.namespace.as_tuple).fetchone()
    if epoch is None or rights is None:
        raise ValueError("producer current barriers are absent")
    from ..graph_types import NamespaceEpoch
    snapshot = natural_basis_snapshot_v1(db, namespace=frame.namespace,
        snapshot=GraphSnapshot((), (NamespaceEpoch(*frame.namespace.as_tuple, epoch[0]),)), units=units)
    candidates = frozen_natural_basis_candidates_v1(db, plan=frozen.input.plan, snapshot=snapshot,
        access_epoch=rights[0], deletion_epoch=rights[1], now_utc=now_utc)
    from ..domains.d08.natural_plan import _verify_d06_units_current
    _verify_d06_units_current(frozen.input.plan, snapshot, candidates,
        access_epoch=rights[0], deletion_epoch=rights[1], now_utc=now_utc)
    return producer_candidate_read_versions_v1(candidates)


def source_expression_unit_v1(candidate, *, basis_id, audience_id):
    """Project the unchanged external Source qualifier into the existing unit."""
    versions = {row.key.token: row.revision for row in candidate.read_versions}
    span = candidate.evidence_span
    return QualifiedExpressionUnitV2(
        basis_id, ClaimKind.REPORTED_CLAIM if candidate.claim_kind == "attributed_report" else ClaimKind.EXTERNAL_FACT,
        candidate.source_excerpt, None,
        tuple(VersionedRef(ref, versions[ref]) for ref in candidate.lineage_source_refs),
        tuple(VersionedRef(row.key.token, row.revision) for row in candidate.read_versions
              if row.key.type_name == "memory.access"),
        tuple(VersionedRef(row.key.token, row.revision) for row in candidate.read_versions
              if row.key.type_name == "d06.source_correction_head.v1"),
        audience_id, "expression", candidate.valid_until,
        speaker_id=candidate.speaker_id,
        content_reality="external_report" if candidate.claim_kind == "attributed_report" else "external_observation",
        qualification_digest=candidate.qualification_digest,
        occurred_at=candidate.occurred_at, learned_at=candidate.learned_at,
        source_kind=candidate.source_kind, assertion_status=candidate.assertion_status,
        d06_claim_kind=candidate.claim_kind, attribution_required=candidate.attribution_required,
        polarity_status=candidate.polarity_status, source_excerpt=candidate.source_excerpt,
        evidence_span=(span.start, span.end))


def fresh_c04_report_candidate_v1(db, *, snapshot, audience_id, expires_at_utc,
                                   access_epoch, deletion_epoch):
    frame = _natural_frame(db)
    if frame.selectors.c04_ref is None:
        return ()
    atom, *_ = _c04_locator(db, frame.namespace, frame.parent_original_id, frame.selectors.c04_ref)
    refs = tuple(atom.value["source_refs"])
    if len(refs) != 1:
        raise ValueError("current installed C04 report needs one selected Source")
    source = _positive(db, frame.namespace, refs[0])
    record = SourceRecord.from_dict(source.value)
    if record.source_kind not in {"reported", "observed"}:
        return ()
    from ..domains.d06.qualified_expression import (
        QualifiedExpressionRequest, SourceTextSpan, prepare_qualified_expression_unit)
    return (prepare_qualified_expression_unit(snapshot, namespace=frame.namespace,
        request=QualifiedExpressionRequest(refs[0], "attributed_report", SourceTextSpan(0, len(record.text))),
        audiences=(audience_id,), access_epoch=access_epoch,
        deletion_epoch=deletion_epoch, valid_until=expires_at_utc,
        **({}if _HOST_PRODUCER_BINDING_V3.get()is None else _host_source_expression_kwargs_v3(db,frame.namespace))),)


def natural_model_parent_original_v1(db, *, intent):
    """Read the one actual sealed natural parent; other model families are untouched."""
    from .jobs import get_job
    job = get_job(db, intent.job_id)
    if job.work_kind not in {"natural_generation", "natural_review"}:
        return None
    namespace = NamespaceId(job.bot_id, job.persona_id)
    stage = "generation" if job.work_kind == "natural_generation" else "review"
    table = "graph_natural_generation_preparations_v2" if stage == "generation" else "graph_natural_review_preparations_v2"
    rows = db.execute("SELECT parent_original_id FROM " + table +
        " WHERE bot=? AND persona=? AND job_id=? LIMIT 2", (*namespace.as_tuple, job.job_id)).fetchall()
    if len(rows) != 1:
        raise ValueError("natural model lost its unique actual sealed parent")
    saved = _read_natural_preparation(db, namespace, rows[0][0], stage)
    if (saved is None or saved.seal.call_id != intent.call_id
            or saved.seal.acquire_operation_id != intent.operation_id):
        raise ValueError("natural model intent differs from its actual sealed operation")
    return namespace, rows[0][0]


# Local attachment reads belong to the originating FULL Work, never a new grant.
from weakref import WeakKeyDictionary, WeakSet
from types import MappingProxyType
_HOST_PRODUCER_READERS_V3=WeakSet()
_HOST_PRODUCERS_V3=WeakKeyDictionary()
_HOST_PRODUCER_BINDING_V3=ContextVar('sylanne_host_natural_producer_v3',default=None)
_HOST_PRODUCER_READING_V3=ContextVar('sylanne_host_natural_producer_reading_v3',default=None)


class _ProducerAttachmentNeededV3(Exception):
    def __init__(self,request):self.request=request


class _HostProducerAttachmentV3:
    def __init__(self,owner,request):
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3
        if type(owner)is _OrdinaryFullReadV3:
            owner.prefinal._actual()
            if owner.work.state is not owner or owner.work.operation is not owner.operation:
                raise ValueError('actual same-Work host attachment owner required')
        else:
            from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphReadWorkV3,require_actual_authority_graph_attachment_owner_v3
            if type(owner)is AuthorityGraphReadWorkV3:
                require_actual_authority_graph_attachment_owner_v3(owner,db=owner.db)
            else:
                from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3
                if type(owner) is ContactHostStageReadWorkV3:
                    from .contact_host_source_v3 import require_contact_host_work_v3
                    require_contact_host_work_v3(owner,db=owner.db)
                else:
                    from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
                    if type(owner) is ContactDomainSourceReadV3:
                        from .contact_domain_source_v3 import require_contact_domain_work_v3
                        require_contact_domain_work_v3(owner,db=owner.db)
                    else:
                        from .current_method_learning_read_v3 import require_actual_method_learning_attachment_owner_v3
                        from .owner_goal_projection_receipt_read_v1 import GoalProjectionReceiptReadWorkV1,require_goal_projection_receipt_read_work_v1
                        if type(owner) is GoalProjectionReceiptReadWorkV1:
                            require_goal_projection_receipt_read_work_v1(owner,db=owner.db)
                        else:
                            require_actual_method_learning_attachment_owner_v3(owner,db=owner.db)
        self.owner,self.request=owner,request
        self.table,self.columns,self.key_columns,self.key=request
        self.where=' AND '.join(name+'=?' for name in self.key_columns)
        self.phase='metadata';self.column=None;self.json_columns={};self.metadata=None
        self.complete=False;self.row=None;self.pending=[];self.parts=[];self.stream=None;self.encoded={}
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        owner=self.owner;owner.prefinal.require_current(meter=meter)
        if self.phase=='metadata':
            mapped=self.table in ('graph_atoms','graph_history') and 'value' in self.columns
            json_names=tuple(name for name in self.columns if name.endswith('_json') or name in
                ('value','reads','revisions','invalidated','dependencies','typed_request_wire'))
            self.json_names=json_names
            metadata=tuple(name for name in self.columns if name not in json_names)
            if mapped:metadata=(*metadata,'value_cell_id')
            self.metadata_columns=tuple(dict.fromkeys((*self.key_columns,*metadata)))
            self.metadata=_runtime_bounded_fixed_row_v3(owner.db,meter,self.table,self.metadata_columns,self.where,self.key)
            if self.metadata is None:self.row=None;self.complete=True;return
            self.small=dict(zip(self.metadata_columns,self.metadata))
            if self.table=='runtime_jobs':
                from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
                from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3
                from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
                if type(owner) not in {AuthorityGraphReadWorkV3,ContactHostStageReadWorkV3,ContactDomainSourceReadV3} or (self.small.get('bot_id'),self.small.get('persona_id'))!=owner.namespace.as_tuple:
                    raise ValueError('Authority job canonical body crossed its actual namespace')
            self.pending=list(json_names)
            self.phase='columns';return
        if self.phase=='columns':
            if self.column is not None:
                if self.column.advance(meter):
                    self.json_columns[self.column.column]=self.column
                    self.stream=CanonicalValueStreamV3(self.column.require_v3(owner));self.parts=[]
                    self.phase='wire'
                return
            if self.pending:
                name=self.pending.pop(0);cell=self.small.get('value_cell_id') if name=='value' else None
                if cell is None:
                    from .c09_paged_sql_v2 import _quote
                    row=owner.db.execute('SELECT typeof('+_quote(name)+'),length(CAST('+_quote(name)+' AS BLOB)) FROM '+_quote(self.table)+' WHERE '+self.where,self.key).fetchone()
                    meter.charge_read(16)
                    if row is None:raise ValueError('producer original column disappeared')
                    if row[0]=='null':self.encoded[name]=None;return
                    if row[0]!='text':raise ValueError('producer JSON attachment is not actual TEXT')
                self.column=DispatchOriginalJSONReadV3(owner,table=self.table,column=name,
                    key_columns=self.key_columns,key=self.key,cell_id=cell);return
            self.row=tuple(self.encoded[name] if name in self.encoded else self.small[name] for name in self.columns)
            self.complete=True;return
        if self.phase=='wire':
            fragment=self.stream.read_fragment(meter)
            if fragment:
                owner.operation.retain(len(fragment)+128);self.parts.append(fragment)
            if self.stream.complete:
                if self.stream.hash.hexdigest()!=self.column.sha256:
                    raise ValueError('producer canonical attachment differs from its actual column EOF')
                size=sum(map(len,self.parts));owner.operation.retain(size*2+1024)
                encoded=b''.join(self.parts).decode('ascii')
                if not hasattr(self,'encoded'):self.encoded={}
                self.encoded[self.column.column]=encoded
                self.column=None;self.stream=None;self.parts=[];self.phase='columns'
    def require_row_v3(self,owner,meter):
        if self.owner is not owner or not self.complete:raise ValueError('actual complete producer attachment required')
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        current=_runtime_bounded_fixed_row_v3(owner.db,meter,self.table,self.metadata_columns,self.where,self.key)
        if current!=self.metadata:raise ValueError('producer original row identity changed')
        return self.row


def _host_producer_attachment_owner_v3(db):
    owner=_HOST_PRODUCER_READING_V3.get()
    if owner is not None:
        if type(owner)is not _HostNaturalProducerPreparationV3 or owner not in _HOST_PRODUCER_READERS_V3:
            raise ValueError('actual originating producer reader required')
        reader=owner.reader
    else:
        prepared=_HOST_PRODUCER_BINDING_V3.get()
        if prepared is None:return None
        require_prepared_host_natural_producers_v3(prepared)
        owner=prepared;reader=prepared.reader
    if reader.db is not db or reader.operation.closed:raise ValueError('producer attachment database/operation changed')
    return owner


def _read_host_natural_attachment_v3(db,*,table,columns,key_columns,key):
    owner=_host_producer_attachment_owner_v3(db)
    if owner is None:return False,None
    original_columns=tuple(columns);original_keys=dict(zip(key_columns,key))
    if table=='graph_atoms':
        key=(original_keys['token'],*owner.reader.namespace.as_tuple)
        key_columns=('token','bot','persona');columns=('revision','value','valid')
    elif table=='graph_history':
        key=(original_keys['token'],original_keys['revision']);key_columns=('token','revision')
        columns=('event_id','value','valid','event_bot','event_persona','event_session','dependencies')
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    if request[:3] not in _HOST_ATTACHMENT_SHAPES_V3:
        raise ValueError('unregistered fixed producer original read')
    if table in ('graph_atoms','graph_history','graph_dependencies'):
        atom=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom)!=owner.reader.namespace:raise ValueError('producer attachment crossed namespace')
    else:
        if tuple(key[:2])!=owner.reader.namespace.as_tuple:raise ValueError('producer original crossed namespace')
    task=owner.attachments.get(request)
    if task is None:
        if type(owner)is PreparedHostNaturalProducersV3:raise ValueError('producer original was not prepared by this Work')
        raise _ProducerAttachmentNeededV3(request)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as actual:
        row=task.require_row_v3(owner.reader,actual)
    if row is None:return True,None
    if table in ('graph_atoms','graph_history'):
        data=dict(zip(columns,row))
        if table=='graph_atoms':data.update(token=key[0],bot=key[1],persona=key[2])
        else:data.update(token=key[0],revision=key[1])
        if any(data.get(name)!=value for name,value in original_keys.items()):
            raise ValueError('producer current/history event identity differs')
        return True,tuple(data[name]for name in original_columns)
    return True,row


_HOST_C04_WIRES_V3=WeakKeyDictionary()


class PreparedHostC04WireOriginalV3:
    def __init__(self,issuer,owner,attachment,column):
        if (issuer is not _KEY or type(owner)is not _HostNaturalProducerPreparationV3
                or owner not in _HOST_PRODUCER_READERS_V3
                or type(attachment)is not _HostProducerAttachmentV3
                or attachment.owner is not owner.reader or not attachment.complete
                or owner.attachments.get(attachment.request)is not attachment):
            raise ValueError('actual same-Work completed C04 wire attachment required')
        body=attachment.json_columns.get(column)
        if body is None or attachment.encoded.get(column)is None:
            raise ValueError('C04 wire column has no complete canonical original')
        self.owner,self.attachment,self.column=owner,attachment,column
        self.parsed_value=body.require_v3(owner.reader)
        self.wire=attachment.encoded[column]
        self.sha256,self.byte_count=body.sha256,body.byte_count
        self.column_original=(body,body.owner,body.table,body.column,body.key,body.sha256,body.byte_count,body._frozen_value)
        self.prefinal=owner.reader.prefinal
        _HOST_C04_WIRES_V3[self]=self._identity()
    def _identity(self):
        return (self.owner,self.attachment,self.column,self.parsed_value,self.wire,
            self.sha256,self.byte_count,self.prefinal,self.column_original)
    def require_for_v4(self,owner):
        if (_HOST_C04_WIRES_V3.get(self)!=self._identity() or owner is not self.owner
                or owner not in _HOST_PRODUCER_READERS_V3
                or owner.reader.prefinal is not self.prefinal
                or owner.attachments.get(self.attachment.request)is not self.attachment
                or self.attachment.encoded.get(self.column)is not self.wire
                or self.attachment.json_columns.get(self.column)is not self.column_original[0]):
            raise ValueError('C04 wire original lost its actual attachment/Work')
        from .dispatch_initial_source_read_v3 import _COLUMNS
        body=self.column_original[0]
        if (not body.complete or _COLUMNS.get(body)!=self.column_original[1:]
                or body.operation is not owner.reader.operation):
            raise ValueError('C04 wire column lost its canonical EOF original')
        self.prefinal._actual()
        return self


def _actual_host_c04_wire_v3(progress,wire):
    matches=[(task,column)for task in progress.attachments.values()
        if type(task)is _HostProducerAttachmentV3
        for column,value in task.encoded.items()if value is wire]
    if len(matches)!=1:
        raise ValueError('C04 typed request must identify one actual completed wire column')
    task,column=matches[0]
    return PreparedHostC04WireOriginalV3(_KEY,progress,task,column)


class PreparedHostNaturalProducersV3:
    def __init__(self,issuer,producer):
        if issuer is not _KEY or producer not in _HOST_PRODUCER_READERS_V3 or producer.phase!='publish':
            raise TypeError('actual completed host producer issuer required')
        self.reader,self.prefinal,self.scope=producer.reader,producer.reader.prefinal,producer.reader.fence.scope
        self.parent_original_id,self.phase=producer.parent_original_id,producer.request_phase
        self.selectors,self.saved=producer.selectors,producer.saved
        self.c04,self.draft,self.observation=producer.c04,producer.draft,producer.observation
        self.attachments=MappingProxyType(dict(producer.attachments));self.roots=tuple(sorted(producer.roots))
        self.keys=tuple(sorted(producer.keys,key=lambda value:value.token))
        self.c04_decoder_owner,self.c04_decodes=producer,tuple(producer.c04_decodes)
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        from .source_correction_read_v3 import _heap
        dictionaries=(() if self.c04 is None else (self.c04[0].value,self.c04[4],self.c04[5],self.c04[6]))
        dictionaries+=(() if self.draft is None else (self.draft[2],))
        self.reader.operation.retain(_heap(dictionaries)+65536)
        self.frozen_local_dictionaries=tuple(_freeze_value_v3(value)for value in dictionaries)
        _HOST_PRODUCERS_V3[self]=self._identity()
    def _identity(self):
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        dictionaries=(() if self.c04 is None else (self.c04[0].value,self.c04[4],self.c04[5],self.c04[6]))
        dictionaries+=(() if self.draft is None else (self.draft[2],))
        if tuple(_freeze_value_v3(value)for value in dictionaries)!=self.frozen_local_dictionaries:
            raise ValueError('producer local original member was altered after complete EOF')
        return (self.reader,self.prefinal,self.scope,self.parent_original_id,self.phase,self.selectors,self.saved,
            self.c04,self.draft,self.observation,tuple((key,value.request,value.row,value.metadata)for key,value in self.attachments.items()),self.roots,self.keys,self.frozen_local_dictionaries,self.c04_decoder_owner,self.c04_decodes)
    def require_for(self,prefinal,actual_entry):
        require_prepared_host_natural_producers_v3(self,prefinal=prefinal)
        if actual_entry is not prefinal.actual_entry or actual_entry.c02_operation_id!=self.parent_original_id:
            raise ValueError('producer roots lost their actual C02 entry')
        return self.roots


def require_prepared_host_natural_producers_v3(prepared,*,reader=None,prefinal=None,scope=None):
    if type(prepared)is not PreparedHostNaturalProducersV3 or _HOST_PRODUCERS_V3.get(prepared)!=prepared._identity():
        raise ValueError('actual private prepared host producer originals required')
    actual=prepared.reader
    if (actual.work.state is not actual or actual.work.operation is not actual.operation or actual.operation.closed
            or reader is not None and reader is not actual or prefinal is not None and prefinal is not prepared.prefinal
            or scope is not None and scope is not prepared.scope):
        raise ValueError('prepared producer changed originating Work/scope/selection')
    prepared.prefinal._actual()
    return prepared


class _HostNaturalProducerPreparationV3:
    def __init__(self,reader,*,parent_original_id,phase):
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3
        if (type(reader)is not _OrdinaryFullReadV3 or reader.prefinal is None
                or reader.work.state is not reader or reader.work.operation is not reader.operation
                or phase not in ('prepare','frozen') or type(parent_original_id)is not str or not parent_original_id
                or reader.prefinal.actual_entry.c02_operation_id!=parent_original_id):
            raise ValueError('actual originating natural producer Work/census/entry required')
        reader.prefinal._actual()
        self.reader,self.parent_original_id,self.request_phase=reader,parent_original_id,phase
        self.phase='saved';self.complete=False;self.prepared=None;self.saved_reader=None;self.saved=None
        self.attachments={};self.attachment=None;self.c04=self.draft=self.observation=None
        self.selectors=None;self.roots=set();self.keys=set();self.key_queue=[]
        self.c04_decode=None;self.c04_decodes=[]
        reader.operation.retain(131072);_HOST_PRODUCER_READERS_V3.add(self)
    def advance(self,*,meter=None):return advance_host_natural_producer_preparation_v3(self,meter=meter)


def release_host_natural_producer_payload_v3(progress):
    """Revoke the Work-owned issuer before releasing its storage lease."""
    prepared=progress.prepared
    if prepared is not None:
        _HOST_PRODUCERS_V3.pop(prepared,None)
        prepared.c04_decoder_owner=None
        prepared.c04_decodes=()
        prepared.attachments=MappingProxyType({})
        prepared.saved=prepared.c04=prepared.draft=prepared.observation=None
        prepared.frozen_local_dictionaries=()
    drivers=tuple(progress.c04_decodes)+(() if progress.c04_decode is None else(progress.c04_decode,))
    for driver in drivers:
        _HOST_C04_WIRES_V3.pop(driver.wire_original,None)
    _HOST_PRODUCER_READERS_V3.discard(progress)
    progress.prepared=progress.saved_reader=progress.saved=progress.attachment=None
    progress.c04=progress.draft=progress.observation=progress.c04_decode=None
    progress.c04_decodes.clear()
    progress.attachments.clear()


def begin_host_natural_producer_preparation_v3(reader,*,parent_original_id,phase):
    return _HostNaturalProducerPreparationV3(reader,parent_original_id=parent_original_id,phase=phase)


def _observe_prepared_host_natural_producers_v3(progress,*,scope=None):
    graph=progress.reader.graph
    scope=progress.reader.fence.scope if scope is None else scope
    ns=scope.namespace
    _host_stamp(graph,scope)
    proof=verified=claim=terminal=None
    if progress.c04 is not None:
        from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
        from .c04_product_lifecycle_v3 import c04_terminal_proof_from_inspection_v3
        port=graph._GraphCoordinator__c04_authority_port_v3
        if type(port)is not InstalledC04AuthorityPortV3:raise TypeError('actual installed C04 authority port required')
        proof=c04_terminal_proof_from_inspection_v3(port.inspect(progress.c04[1].binding))
        if proof is None:raise ValueError('actual C04 protected terminal is unresolved')
        verified=port.verify_terminal(proof)
    if progress.draft is not None:
        from ..host.d11_life_port_v1 import InstalledD11LifePortV1
        port=InstalledD11LifePortV1(graph._GraphCoordinator__content_fence_v2)
        claim,terminal=port.read_d11_life_original_v1(binding=progress.draft[0].binding)
        if terminal!=progress.draft[1] or claim!=terminal.claim:raise ValueError('paired Life journal differs from adopted result')
    from ..host.self_identity_current_port import InstalledCurrentSelfIdentityPort
    self_port=graph._GraphCoordinator__self_identity_port
    if type(self_port)is not InstalledCurrentSelfIdentityPort:raise TypeError('actual paired Self port required')
    current=self_port.current_self_identity(namespace=ns,authority_namespace=scope.authority_namespace,
        request_operation_id=scope.operation_id,permit=scope.permit)
    if (current is None or current.permit!=scope.permit or current.request_operation_id!=scope.operation_id
            or current.graph_revision!=scope.graph_revision or current.graph_epoch!=scope.graph_epoch.revision):
        raise ValueError('producer observation lost original Self/stamp')
    _host_stamp(graph,scope)
    return _VerifiedProducerObservationV1(_KEY,origin='host',owner=graph,scope=scope,namespace=ns,
        c02_operation_id=progress.parent_original_id,c04_ref=progress.selectors.c04_ref,
        draft_result_ref=progress.selectors.draft_result_ref,c04_proof=proof,c04_verified=verified,
        life_claim=claim,life_terminal=terminal,issuer=graph._GraphCoordinator__d11_issuer,current_self=current)


def advance_host_natural_producer_preparation_v3(progress,*,meter=None):
    if type(progress)is not _HostNaturalProducerPreparationV3 or progress not in _HOST_PRODUCER_READERS_V3 or progress.complete:
        raise ValueError('actual unfinished natural producer Work required')
    reader=progress.reader;reader.prefinal._actual()
    if progress.phase=='protected_observation':
        if meter is not None or reader.db.in_transaction:raise ValueError('protected producer RPC must run outside local SQL quantum')
        if not progress.selectors.empty:progress.observation=_observe_prepared_host_natural_producers_v3(progress)
        else:_host_stamp(reader.graph,reader.fence.scope)
        progress.phase='publish';return progress
    if meter is None:raise ValueError('actual same-Work producer SQL quantum required')
    reader.prefinal.require_current(meter=meter)
    if progress.attachment is not None:
        if reader.db.in_transaction:raise ValueError('producer attachment retained a SQL transaction')
        reader.db.execute('BEGIN')
        try:progress.attachment.advance(meter)
        finally:reader.db.rollback()
        if progress.attachment.complete:
            progress.attachments[progress.attachment.request]=progress.attachment;progress.attachment=None
        return progress
    if progress.c04_decode is not None:
        reader.db.execute('BEGIN')
        try:
            original=progress.c04_decode.wire_original
            original.attachment.require_row_v3(reader,meter)
            progress.c04_decode.advance(meter=meter)
        finally:reader.db.rollback()
        if progress.c04_decode.complete:
            progress.c04_decodes.append(progress.c04_decode);progress.c04_decode=None
        return progress
    from .c04_direct_seed_v4 import bind_prepared_c04_decodes_v4, PreparedC04DecodeRequiredV4
    if reader.db.in_transaction:raise ValueError('producer phase must not inherit a SQL transaction')
    typed_binding=bind_prepared_c04_decodes_v4(progress,tuple(progress.c04_decodes))
    typed_binding.__enter__()
    token=_HOST_PRODUCER_READING_V3.set(progress)
    try:
        reader.db.execute('BEGIN')
        if progress.phase=='saved':
            from .dispatch_initial_source_read_v3 import begin_host_natural_saved_original_read_v3
            if progress.saved_reader is None:
                progress.saved_reader=begin_host_natural_saved_original_read_v3(reader,parent_original_id=progress.parent_original_id)
            elif progress.saved_reader.advance(meter):
                progress.saved=progress.saved_reader.require_v3(reader)
                if progress.request_phase=='frozen' and progress.saved is None:raise ValueError('frozen producer has no actual saved generation')
                progress.phase='selectors'
        elif progress.phase=='selectors':
            issuer=reader.graph._GraphCoordinator__d11_issuer
            progress.selectors=(fresh_natural_producer_selectors_v1(reader.db,namespace=reader.namespace,
                parent_original_id=progress.parent_original_id,issuer=issuer) if progress.saved is None else
                frozen_natural_producer_selectors_v1(reader.db,namespace=reader.namespace,frozen=progress.saved.frozen))
            progress.phase='c04'
        elif progress.phase=='c04':
            if progress.selectors.c04_ref is not None:
                progress.c04=_c04_locator(reader.db,reader.namespace,progress.parent_original_id,progress.selectors.c04_ref)
                progress.roots.update(progress.c04[0].value['source_refs'])
                semantic=progress.c04[4]['interpretation'].get('adoption_original')
                if semantic is not None:progress.roots.update((*semantic['supporting_refs'],*semantic['counter_refs']))
                progress.keys.update((progress.c04[0].key,AtomKey.from_token(progress.c04[5]['payload']['provenance']['child_job_ref'])))
            progress.phase='c04_costs'
        elif progress.phase=='c04_costs':
            if progress.c04 is not None:
                from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
                from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1
                from .c04_interpretation_policy_v3 import read_installed_c04_interpretation_policy_v3
                prepared,work=progress.c04[1:3]
                cpu=read_c04_cpu_cost_original_v1(reader.db,reader.namespace,prepared.binding.operation_id)
                body=read_c04_body_cost_original_v1(reader.db,reader.namespace,prepared.binding.operation_id)
                if cpu is None or body is None:raise ValueError('C04 actual settled cost originals absent')
                read_installed_c04_interpretation_policy_v3(reader.db,reader.namespace,prepared,
                    installation_id=work.direct_selection.installation_id,manifest_digest=work.direct_selection.manifest_digest)
            progress.phase='draft'
        elif progress.phase=='draft':
            if progress.selectors.draft_result_ref is not None:
                issuer=reader.graph._GraphCoordinator__d11_issuer
                progress.draft=_draft_locator(reader.db,reader.namespace,progress.parent_original_id,progress.selectors.draft_result_ref,issuer)
                prepared,terminal,adopted,_,_=progress.draft
                progress.roots.update((*adopted['source_refs'],*prepared.plan.content.source_refs))
                from .d11_life_fact_provenance_v1 import life_fact_auxiliary_key_v1,life_current_fact_reads_v1,PROVENANCE_TYPE,ELIGIBILITY_TYPE
                from .d11_life_graph_types_v1 import life_role_segment_key_v1
                from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
                for fact in (AtomKey.from_token(terminal.binding.artifact_ref),life_role_segment_key_v1(terminal.binding,'start'),life_role_segment_key_v1(terminal.binding,'end')):
                    progress.keys.update((fact,life_fact_auxiliary_key_v1(fact,PROVENANCE_TYPE),life_fact_auxiliary_key_v1(fact,ELIGIBILITY_TYPE)))
                progress.keys.update(life_outcome_read_keys_v1(terminal.binding,prepared.plan.action_intent.ref))
                progress.keys.update(AtomKey.from_token(row.ref) for row in life_current_fact_reads_v1(prepared) if AtomKey.from_token(row.ref).type_name!='memory.source')
            from ..domains.d03.self_perspective import self_mapping_key
            if not progress.selectors.empty:progress.keys.add(self_mapping_key(reader.namespace))
            progress.key_queue=list(sorted(progress.keys,key=lambda key:key.token));progress.phase='members'
        elif progress.phase=='members':
            if progress.key_queue:
                _head(reader.db,reader.namespace,progress.key_queue[0]);progress.key_queue.pop(0)
            else:
                progress.key_queue=list(sorted(progress.keys,key=lambda key:key.token));progress.phase='dependencies'
        elif progress.phase=='dependencies':
            if progress.key_queue:
                _producer_original_many_v3(reader.db,table='graph_dependencies',columns=('dependency_token','dependency_revision'),
                    key_columns=('dependent_token',),key=(progress.key_queue[0].token,),order_column='dependency_token',legacy_reader=None)
                progress.key_queue.pop(0)
            else:progress.phase='protected_observation'
        elif progress.phase=='publish':
            progress.prepared=PreparedHostNaturalProducersV3(_KEY,progress);progress.complete=True
        else:raise ValueError('natural producer preparation phase differs')
    except PreparedC04DecodeRequiredV4 as needed:
        from .c04_direct_seed_v4 import begin_prepared_c04_decode_v4
        original=_actual_host_c04_wire_v3(progress,needed.wire)
        progress.c04_decode=begin_prepared_c04_decode_v4(
            progress,wire_original=original,expected=needed.expected)
    except _ProducerAttachmentNeededV3 as needed:
        progress.attachment=(_HostProducerMetadataScanV3(reader,needed.request) if len(needed.request)==5 else _HostProducerAttachmentV3(reader,needed.request))
    finally:
        reader.db.rollback()
        _HOST_PRODUCER_READING_V3.reset(token)
        typed_binding.__exit__(None,None,None)
    return progress


@contextmanager
def bind_prepared_host_natural_producer_context_v3(graph,*,scope,prepared):
    require_prepared_host_natural_producers_v3(prepared,reader=prepared.reader,scope=scope)
    if prepared.reader.graph is not graph:raise ValueError('prepared producer belongs to another Graph')
    _host_stamp(graph,scope)
    observed=prepared.observation
    if observed is not None:_LIVE[id(observed)]=observed
    from .c04_direct_seed_v4 import bind_prepared_c04_decodes_v4
    typed_binding=bind_prepared_c04_decodes_v4(prepared.c04_decoder_owner,prepared.c04_decodes)
    typed_binding.__enter__()
    token=_HOST_PRODUCER_BINDING_V3.set(prepared)
    try:
        with _bind_natural_frame(prepared.reader.db,scope.namespace,prepared.parent_original_id,prepared.selectors,
                observed,None if prepared.saved is None else prepared.saved.frozen.input.plan.units,
                graph=graph,scope=scope,phase=prepared.phase,origin='host') as frame:
            yield frame
    finally:
        _HOST_PRODUCER_BINDING_V3.reset(token)
        typed_binding.__exit__(None,None,None)
        if observed is not None:_LIVE.pop(id(observed),None)

_HOST_ATTACHMENT_SHAPES_V3=frozenset((('graph_contact_segment_originals_v1',('bot','persona','contact_id','segment_index','operation_id','effect_id','payload_json','payload_digest','signature'),('bot','persona','contact_id','segment_index')),('graph_contact_effect_originals_v1',('payload_json','payload_digest','signature'),('bot','persona','kind','original_ref')),('graph_contact_effect_accounting_attempts_v1',('origin_digest','fact_digest','request_json','state'),('bot','persona','operation_id')),('graph_owner_domain_attempts_v3',('request_digest','attempt_id','permit_json'),('bot','persona','operation_id')),('runtime_budget_reservations',('digest','ceiling_json','actual_json','state'),('lease_id','operation_id')),('graph_atoms', ('revision', 'valid'), ('token',)), ('graph_atoms', ('revision', 'value', 'valid'), ('token',)), ('graph_atoms', ('revision', 'value', 'valid'), ('token', 'bot', 'persona')), ('graph_atoms', ('value',), ('token',)), ('graph_bundle_operations', ('activity_id',), ('bot', 'persona', 'operation_id')), ('graph_bundle_operations', ('digest',), ('bot', 'persona', 'operation_id')), ('graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq'), ('bot', 'persona', 'operation_id')), ('graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq', 'receipt_json'), ('bot', 'persona', 'operation_id')), ('graph_bundle_operations', ('digest', 'commit_seq'), ('bot', 'persona', 'operation_id')), ('graph_c04_adoption_provenance_v3', ('original_json', 'original_digest'), ('bot', 'persona', 'operation_id')), ('graph_c04_adoptions_v3', ('bundle_digest', 'plan_json', 'receipt_json'), ('bot', 'persona', 'operation_id')), ('graph_c04_association_inputs_v3', ('binding_digest', 'input_digest', 'algorithm_build_digest', 'work_json'), ('bot', 'persona', 'operation_id')), ('graph_c04_encoding_baselines_v3', ('joint_operation_id', 'original_json', 'original_digest', 'proof_json', 'proof_digest', 'as_known_at_json', 'historical_closure_digest', 'read_versions_json', 'read_versions_digest', 'encoding_receipt_digest', 'joint_receipt_digest', 'numeric_original_ref', 'numeric_original_revision', 'record_digest'), ('bot', 'persona', 'encoding_operation_id', 'source_ref')), ('graph_c04_internal_work_prepared_v1', ('binding_digest', 'prepared_digest', 'prepared_json'), ('bot', 'persona', 'operation_id')), ('graph_d04_joint_advances_v2', ('evidence_digest',), ('bot', 'persona', 'operation_id')), ('graph_d04_joint_advances_v2', ('evidence_json', 'evidence_digest', 'bundle_digest'), ('bot', 'persona', 'operation_id')), ('graph_d04_joint_numeric_originals_v1', ('numeric_receipt_json', 'numeric_receipt_digest', 'verification_json', 'verification_digest'), ('bot', 'persona', 'operation_id')), ('graph_d04_joint_numeric_originals_v1', ('numeric_receipt_json', 'numeric_receipt_digest', 'verification_json', 'verification_digest', 'evidence_digest'), ('bot', 'persona', 'operation_id')), ('graph_d04_joint_output_originals_v1', ('evidence_digest', 'original_json', 'original_digest', 'write_set_digest'), ('bot', 'persona', 'operation_id')), ('graph_d04_originals_v3', ('payload_json', 'payload_digest'), ('bot', 'persona', 'kind', 'original_ref')), ('graph_d11_life_originals_v1', ('payload_json', 'payload_digest', 'producing_operation_id'), ('bot', 'persona', 'kind', 'original_ref')), ('graph_d11_life_originals_v1', ('producing_operation_id', 'payload_json', 'payload_digest', 'signature'), ('bot', 'persona', 'kind', 'original_ref')), ('graph_domain_production_originals_v1', ('domain', 'operation_kind', 'request_digest', 'original_digest', 'original_payload_json', 'read_versions_json', 'bundle_digest', 'receipt_json', 'receipt_digest'), ('bot', 'persona', 'operation_id')), ('graph_events', ('reads', 'revisions', 'epoch_revision'), ('bot', 'persona', 'session', 'event_id')), ('graph_events', ('reads', 'revisions', 'epoch_revision', 'invalidated'), ('bot', 'persona', 'session', 'event_id')), ('graph_events', ('revisions', 'invalidated', 'epoch_revision'), ('bot', 'persona', 'session', 'event_id')), ('graph_history', ('dependencies',), ('token', 'revision', 'event_id')), ('graph_history', ('event_id', 'value', 'valid'), ('token', 'revision')), ('graph_history', ('value', 'valid'), ('token', 'revision')), ('graph_history', ('value', 'valid'), ('token', 'revision', 'event_bot', 'event_persona', 'event_session', 'event_id')), ('graph_history', ('value', 'valid', 'event_bot', 'event_persona', 'event_id'), ('token', 'revision'))))


_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset({
    ('runtime_budget_leases',('lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json','reserved_json','unconfirmed_json','version','state'),('lease_id',)),
    ('runtime_budget_grants',('grant_json','signature'),('lease_id','version')),
    ('runtime_budget_operations',('receipt_json',),('bot_id','persona_id','operation_id','phase')),
    ('runtime_budget_operations',('digest','lease_id','receipt_json'),('bot_id','persona_id','operation_id','phase')),
    ('runtime_budget_reservations',('state','digest'),('lease_id','operation_id')),
    ('runtime_budget_reservations',('ceiling_json','state','actual_json'),('lease_id','operation_id')),
    ('graph_original_model_cost_attempts_v1',('state','attempt_id'),('bot','persona','call_id')),
})


def _producer_original_point_v3(db,*,table,columns,key_columns,key,legacy_reader):
    from ..authority_service.named_joint_binding_body_v1 import named_joint_core_point_v1
    named, row = named_joint_core_point_v1(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if named:return row
    from .current_life_numeric_accounting_v3 import numeric_accounting_current_point_v3
    numeric,row=numeric_accounting_current_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if numeric:return row
    from .contact_domain_source_work_v3 import contact_domain_original_point_v3
    contact,row = contact_domain_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if contact:
        return row
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    handled,row=read_bound_method_learning_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:return row
    from .domain_background_read_v3 import read_bound_background_graph_attachment_v3
    original_columns=tuple(columns);original_keys=dict(zip(key_columns,key))
    actual_columns,actual_keys,actual_key=original_columns,tuple(key_columns),tuple(key)
    if table=='graph_atoms':
        atom=AtomKey.from_token(original_keys['token']);namespace=NamespaceId.from_key(atom)
        actual_columns=('revision','value','valid');actual_keys=('token','bot','persona');actual_key=(atom.token,*namespace.as_tuple)
    elif table=='graph_history':
        actual_columns=('event_id','value','valid','event_bot','event_persona','event_session','dependencies')
        actual_keys=('token','revision');actual_key=(original_keys['token'],original_keys['revision'])
    background,row=read_bound_background_graph_attachment_v3(db,table=table,columns=actual_columns,
        key_columns=actual_keys,key=actual_key)
    if background:
        if row is None:return None
        if table in('graph_atoms','graph_history'):
            data=dict(zip(actual_columns,row));data.update(zip(actual_keys,actual_key))
            if any(data.get(name)!=value for name,value in original_keys.items()):return None
            return tuple(data[name]for name in original_columns)
        return row
    from .contact_host_stage_work_v3 import contact_host_original_point_v3
    handled,row=contact_host_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:return row
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
    handled,row=read_bound_authority_graph_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:return row
    handled,row=_read_host_natural_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    return row if handled else legacy_reader()


_HOST_ATTACHMENT_SHAPES_V3 = _HOST_ATTACHMENT_SHAPES_V3 | frozenset({
    ("graph_owner_goal_cancellation_projections_v1",("bot","persona","operation_id","goal_ref","root_registration_ref","core_original_ref","core_original_digest","observation_json","observation_digest","receipt_json","receipt_digest","signature"),("bot","persona","goal_ref","root_registration_ref")),
    ("graph_events",("digest",),("bot","persona","session","event_id")),
    ("graph_owner_domain_attempts_v3",("request_digest","attempt_id","anchor_json","graph_revision","graph_epoch","permit_json","receipt_json"),("bot","persona","operation_id")),
})

_HOST_ATTACHMENT_SCANS_V3=frozenset({
    ('graph_d11_life_originals_v1',('original_ref',),('bot','persona','kind'),'original_ref'),
    ('graph_d04_originals_v3',('original_ref',),('bot','persona','kind'),'original_ref'),
    ('graph_dependencies',('dependency_token','dependency_revision'),('dependent_token',),'dependency_token'),
    ('graph_d04_joint_advance_members_v2',('checkpoint_ref','process_id','role_start','role_end'),('bot','persona','operation_id'),'checkpoint_ref')})


class _HostProducerMetadataScanV3:
    def __init__(self,reader,request):
        self.owner,self.request=reader,request
        self.table,self.columns,self.key_columns,self.key,self.order_column=request
        self.where=' AND '.join(name+'=?'for name in self.key_columns)
        self.after=None;self.rows=[];self.complete=False;self.row=None;self.metadata=None
    def advance(self,meter):
        from .c09_paged_sql_v2 import _quote
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        self.owner.prefinal.require_current(meter=meter)
        where=self.where;params=self.key
        if self.after is not None:where+=' AND '+_quote(self.order_column)+'>?';params=(*params,self.after)
        # MIN uses the registered family index; no value/payload predicate or body read.
        sql='SELECT length(CAST(MIN('+_quote(self.order_column)+') AS BLOB)) FROM '+_quote(self.table)+' WHERE '+where
        meter.require_available(1024);length=self.owner.db.execute(sql,params).fetchone()[0];meter.charge_read(8)
        if length is None:self.row=tuple(self.rows);self.metadata=(len(self.rows),self.after);self.complete=True;return
        meter.require_available(length+1024);self.owner.operation.retain(length*8+4096)
        value=self.owner.db.execute('SELECT MIN('+_quote(self.order_column)+') FROM '+_quote(self.table)+' WHERE '+where,params).fetchone()[0]
        meter.charge_read(len(value.encode('utf-8')))
        point=_runtime_bounded_fixed_row_v3(self.owner.db,meter,self.table,self.columns,
            self.where+' AND '+_quote(self.order_column)+'=?',(*self.key,value))
        if point is None or self.after is not None and value<=self.after:raise ValueError('producer indexed family scan changed')
        self.owner.operation.retain(1024+sum(len(v)*8 if type(v)is str else 32 for v in point))
        self.rows.append(point);self.after=value
    def require_row_v3(self,owner,meter):
        if self.owner is not owner or not self.complete:raise ValueError('producer whole metadata family EOF required')
        owner.prefinal._actual()
        return self.row


def _producer_original_many_v3(db,*,table,columns,key_columns,key,order_column,legacy_reader):
    from .artifact_borrowed_source_v3 import read_bound_artifact_borrowed_dependencies_v3
    artifact,rows=read_bound_artifact_borrowed_dependencies_v3(db,table=table,columns=columns,
        key_columns=key_columns,key=key,order_column=order_column)
    if artifact:return rows
    from .current_life_numeric_native_read_v3 import read_bound_native_numeric_dependencies_v3
    native,rows=read_bound_native_numeric_dependencies_v3(db,table=table,columns=columns,
        key_columns=key_columns,key=key,order_column=order_column)
    if native:return rows
    from .domain_background_read_v3 import read_bound_background_graph_attachment_rows_v3
    background,rows=read_bound_background_graph_attachment_rows_v3(db,table=table,columns=columns,
        key_columns=key_columns,key=key,order_column=order_column)
    if background:return rows
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_rows_v3
    handled,row=read_bound_authority_graph_attachment_rows_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,order_column=order_column)
    if handled:return row
    owner=_host_producer_attachment_owner_v3(db)
    if owner is None:return legacy_reader()
    shape=(table,tuple(columns),tuple(key_columns),order_column)
    if shape not in _HOST_ATTACHMENT_SCANS_V3:raise ValueError('unregistered original metadata scan')
    if table=='graph_dependencies':
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=owner.reader.namespace:raise ValueError('producer dependency scan crossed namespace')
    elif tuple(key[:2])!=owner.reader.namespace.as_tuple:raise ValueError('producer family scan crossed namespace')
    request=(table,tuple(columns),tuple(key_columns),tuple(key),order_column)
    task=owner.attachments.get(request)
    if task is None:
        if type(owner)is PreparedHostNaturalProducersV3:raise ValueError('producer family scan was not prepared')
        raise _ProducerAttachmentNeededV3(request)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as actual:return task.require_row_v3(owner.reader,actual)


def _fresh_signed_draft_refs_v3(db,namespace,parent_original_id,issuer):
    refs=_producer_original_many_v3(db,table='graph_d11_life_originals_v1',columns=('original_ref',),
        key_columns=('bot','persona','kind'),key=(*namespace.as_tuple,'c4_adopted'),order_column='original_ref',legacy_reader=None)
    from .d11_life_preparation_v1 import _read
    matched=[]
    for (ref,)in refs:
        original=_read(db,namespace=namespace,issuer=issuer,kind='c4_adopted',ref=ref)
        if original is None:raise ValueError('actual signed draft adoption disappeared')
        if original[0]['selector']['c02_operation_id']==parent_original_id:matched.append((ref,))
    if len(matched)>1:raise ValueError('natural completion has more than one actual artifact task')
    return matched


def _series_adoption_refs_v3(db,namespace,operation_id):
    refs=_producer_original_many_v3(db,table='graph_d04_originals_v3',columns=('original_ref',),
        key_columns=('bot','persona','kind'),key=(*namespace.as_tuple,'series_adoption'),order_column='original_ref',legacy_reader=None)
    from .d04_appraisal_driver_v3 import read_d04_original_v3
    result=[]
    for (ref,)in refs:
        row=read_d04_original_v3(db,namespace,'series_adoption',ref)
        if row is None:raise ValueError('actual series adoption disappeared')
        if row[0]['operation_id']==operation_id:result.append((ref,))
    return result

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset({
    ("graph_d07_attention_issuance_v1", ("source_ref", "c02_operation_id", "bundle_digest"), ("bot", "persona", "operation_id")),
    ("graph_d07_execution_originals_v1", ("payload_json", "payload_digest", "signature"), ("bot", "persona", "kind", "original_ref")),
    ("graph_d10_production_inputs_v1", ("kind", "producing_operation_id", "payload_json", "payload_digest", "signature"), ("bot", "persona", "original_ref")),
    ("graph_d08_joint_node_originals_v1", ("kind", "producing_operation_id", "payload_json", "payload_digest", "signature"), ("bot", "persona", "original_ref")),
    ("graph_d08_joint_node_originals_v1", ("payload_json",), ("bot", "persona", "original_ref")),
    ('graph_atoms',('revision','value','valid'),('token','bot','persona')),
    ('graph_history',('event_id','value','valid','event_bot','event_persona','event_session','dependencies'),('token','revision')),
    ('graph_recovery_metadata_v2', ('schema', 'requirements_json', 'graph_revision'), ('bot', 'persona')),
    ('graph_first_ingress_identity_v1', ('source_ref', 'platform_ref', 'conversation_ref', 'sender_ref', 'message_id', 'visibility', 'identity_json', 'content_fingerprint', 'learned_at', 'bundle_digest'), ('bot', 'persona', 'operation_id')),
    ('graph_first_ingress_intents_v2', ('identity_json',), ('bot', 'persona', 'operation_id')),
    ('graph_first_ingress_c02_committed_seals_v2', ('schema', 'bundle_digest', 'bundle_json'), ('bot', 'persona', 'operation_id')),
    ('graph_owner_issue_operations_v1', ('operation_id', 'request_digest', 'grant_id', 'grant_digest', 'graph_incarnation', 'graph_access_epoch', 'graph_epoch', 'graph_receipt_digest', 'proof_json'), ('bot', 'persona')),
    ('graph_scene_binding_receipts_v1', ('receipt_json',), ('bot', 'persona', 'operation_id')),
    ('graph_d13_inbound_turn_attempts_v1', ('c02_operation_id', 'receipt_json'), ('bot', 'persona', 'ingress_operation_id')),
    ('graph_d13_core_wire_evidence_v1', ('evidence_digest', 'selector_json', 'envelope_json'), ('bot', 'persona', 'frame_intent_id')),
    ('graph_d13_core_wire_evidence_v1', ('frame_intent_id', 'selector_json', 'envelope_json'), ('bot', 'persona', 'frame_intent_id')),
    ('runtime_jobs', ('job_id', 'operation_id', 'activity_id', 'effect_id', 'bot_id', 'persona_id', 'snapshot_ref', 'phase', 'work_kind', 'continuation_json', 'wake_condition_json', 'deadline_utc', 'budget_ref', 'resource_ref', 'operator_versions_json', 'lease_holder', 'lease_expires_utc', 'fence', 'cancel_epoch', 'usage_json', 'result_ref'), ('job_id',)),
    ('graph_d13_paid_intent_originals_v1', ('operation_id', 'original_json', 'original_digest'), ('bot', 'persona', 'job_ref')),
    ('graph_d13_paid_call_originals_v1', ('call_id', 'original_json', 'original_digest'), ('bot', 'persona', 'job_ref')),
    ('runtime_budget_reservations', ('digest',), ('lease_id', 'operation_id')),
    ('runtime_resource_quotes',('quote_json','signature'),('quote_id','version')),
    ('graph_natural_generation_scopes_v2',('original_seal_digest','proof_json'),('bot','persona','parent_original_id')),
})


def _current_host_producer_full_v3(db,namespace):
    prepared=_HOST_PRODUCER_BINDING_V3.get()
    if prepared is None:return None
    require_prepared_host_natural_producers_v3(prepared)
    from .current_graph_full_read_v3 import(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3,
        require_bound_graph_full_read_proof_for_db_v3,CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3)
    full=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
        required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3}))
    if type(full)not in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3):raise ValueError('actual ordinary producer FULL required')
    base=full.base if type(full)is PreparedCurrentGraphFullWriteViewV3 else full
    if base.work is not prepared.reader.work or base.prepared_producer_members is not prepared:
        raise ValueError('producer attachments changed originating FULL Work')
    return full


def _source_closure_from_host_material_v3(db,snapshot,namespace,roots,audience):
    full=_current_host_producer_full_v3(db,namespace)
    if full is None:return None
    if snapshot is not full.projection or full.source_material is None:raise ValueError('producer Source closure lost actual FULL/body qualification')
    refs={};access={};corrections={};reads={}
    for root in roots:
        lineage,versions=full.source_material.source_family_for_v3(db=db,prepared_full_read=full,
            namespace=namespace,source_ref=root,audiences=(audience,))
        for version in versions:
            reads[version.key.token]=version
            value=VersionedRef(version.key.token,version.revision)
            if version.key.type_name=='memory.source':refs[value.ref]=value
            elif version.key.type_name=='memory.access':access[value.ref]=value
            elif version.key.type_name=='d06.source_correction_head.v1':corrections[value.ref]=value
    return tuple(tuple(group[key]for key in sorted(group))for group in(refs,access,corrections,reads))


def _prepared_producer_member_matches_v3(db,namespace,snapshot,member):
    full=_current_host_producer_full_v3(db,namespace)
    if full is None:return snapshot.get(member.key)==member
    if snapshot is not full.projection:raise ValueError('producer member lost actual FULL projection')
    prepared=_HOST_PRODUCER_BINDING_V3.get()
    if member.key in prepared.keys:return _head(db,namespace,member.key)==member
    return full.projection.get(member.key)==member


@contextmanager
def _renew_prepared_host_natural_producer_scope_v3(graph,*,scope,prepared,phase):
    require_prepared_host_natural_producers_v3(prepared)
    if graph is not prepared.reader.graph or scope.namespace!=prepared.reader.namespace or phase not in('prepare','frozen'):
        raise ValueError('producer handoff changed installed Graph/namespace/phase')
    if prepared.phase=='prepare' and scope is not prepared.scope:
        raise ValueError('borrowed admin producer must retain its original write scope')
    _host_stamp(graph,scope)
    with graph._GraphCoordinator__store._lock:
        db=prepared.reader.db
        if db.in_transaction:raise ValueError('producer handoff must precede business SQL')
        db.execute('BEGIN')
        try:
            _current_host_producer_full_v3(db,scope.namespace)
            from ..runtime_storage_v3 import runtime_storage_quantum_v3
            with runtime_storage_quantum_v3(db)as meter:
                for task in prepared.attachments.values():task.require_row_v3(prepared.reader,meter)
        finally:db.rollback()
    observed=None if prepared.selectors.empty else _observe_prepared_host_natural_producers_v3(prepared,scope=scope)
    if observed is not None:_LIVE[id(observed)]=observed
    try:
        with _bind_natural_frame(db,scope.namespace,prepared.parent_original_id,prepared.selectors,observed,
                None if prepared.saved is None else prepared.saved.frozen.input.plan.units,
                graph=graph,scope=scope,phase=phase,origin='host')as frame:yield frame
    finally:
        if observed is not None:_LIVE.pop(id(observed),None)


def _host_source_expression_kwargs_v3(db,namespace):
    full=_current_host_producer_full_v3(db,namespace)
    if full is None or full.source_material is None:raise ValueError('actual producer Source expression material required')
    return dict(prepared_source_material=full.source_material,prepared_full_read=full,db=db)

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('d11_c04_cpu_cost_originals_v1', ('original_json', 'original_digest'), ('bot', 'persona', 'operation_id')), ('d02_c04_body_cost_originals_v1', ('original_json', 'original_digest'), ('bot', 'persona', 'operation_id')), ('graph_c04_code_policy_originals_v3', ('payload_json', 'payload_digest'), ('bot', 'persona', 'operation_id'))))

# Authority current consumer fixed original points; each body is read to canonical EOF.
_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_bundle_operations', ('activity_id', 'commit_seq', 'receipt_json'), ('bot', 'persona', 'operation_id')), ('graph_bundle_operations', ('activity_id', 'effect_id', 'receipt_json'), ('bot', 'persona', 'operation_id')), ('graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq', 'receipt_json'), ('bot', 'persona', 'operation_id')), ('graph_context_reply_acquires_v2', ('state', 'request_digest', 'anchor_json', 'graph_revision', 'graph_epoch'), ('bot', 'persona', 'acquire_operation_id')), ('graph_dependencies', ('dependency_revision',), ('dependent_token', 'dependency_token')), ('graph_events', ('digest', 'reads', 'revisions', 'epoch_revision'), ('bot', 'persona', 'session', 'event_id')), ('graph_events', ('event_id',), ('bot', 'persona', 'session', 'event_id')), ('graph_events', ('reads', 'revisions', 'epoch_revision'), ('bot', 'persona', 'session', 'event_id')), ('graph_events', ('revisions', 'epoch_revision'), ('bot', 'persona', 'session', 'event_id')), ('graph_job_acquire_intents_v2', ('graph_revision', 'graph_epoch'), ('bot', 'persona', 'acquire_operation_id')), ('graph_natural_generation_terminals_v2', ('terminal_receipt_digest', 'output_digest', 'output_receipt_json', 'state'), ('bot', 'persona', 'original_operation_id')), ('graph_natural_review_terminals_v2', ('terminal_receipt_digest', 'output_digest', 'output_receipt_json', 'state'), ('bot', 'persona', 'original_operation_id')), ('graph_post_c02_reply_model_acquires_v1', ('state', 'request_digest', 'attempt_id', 'anchor_json', 'graph_revision', 'graph_epoch'), ('bot', 'persona', 'acquire_operation_id', 'original_operation_id')), ('graph_recovery_metadata_v2', ('requirements_json', 'graph_revision'), ('bot', 'persona')), ('graph_recovery_metadata_v2', ('schema', 'requirements_json', 'graph_revision'), ('bot', 'persona')), ('runtime_budget_operations', ('operation_id',), ('bot_id', 'persona_id', 'operation_id', 'phase')), ('runtime_budget_reservations', ('digest', 'ceiling_json', 'state'), ('lease_id', 'operation_id')), ('runtime_budget_reservations', ('state',), ('lease_id', 'operation_id')), ('runtime_ingress_issuance', ('source_qualification_json', 'policy_json'), ('bot', 'persona', 'operation_id'))))

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_first_ingress_c02_committed_seals_v2', ('schema', 'bundle_digest', 'evidence_json', 'quote_json'), ('bot', 'persona', 'operation_id')), ('graph_bundle_operations', ('digest', 'activity_id', 'receipt_json'), ('bot', 'persona', 'operation_id')), ('graph_bundle_operations', ('receipt_json',), ('bot', 'persona', 'operation_id')), ('graph_c02_cost_attempts_v1', ('state',), ('bot', 'persona', 'operation_id')), ('runtime_budget_reservations', ('state',), ('lease_id', 'operation_id')), ('runtime_budget_operations', ('operation_id',), ('bot_id', 'persona_id', 'operation_id', 'phase')), ('graph_dependencies', ('dependency_revision',), ('dependent_token', 'dependency_token'))))

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_d13_outbound_observations_v1', ('source_ref', 'batch_ref', 'observation_json', 'original_json', 'original_digest'), ('bot', 'persona', 'final_operation_id', 'observation_digest')),))
_HOST_ATTACHMENT_SCANS_V3=_HOST_ATTACHMENT_SCANS_V3|frozenset((('graph_d13_outbound_observations_v1', ('final_operation_id',), ('bot', 'persona', 'slot_ref', 'observation_digest'), 'final_operation_id'),))

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_post_c02_reply_model_preparations_v1', ('c02_operation_id', 'source_ref', 'c02_receipt_digest', 'source_id', 'source_revision', 'access_revision', 'attention_ticket_id', 'focus_revision', 'audience', 'state', 'acquire_operation_id', 'actor', 'worker_fence', 'call_id', 'model_request_digest', 'binding_digest', 'envelope_json', 'request_json'), ('bot', 'persona', 'c02_operation_id', 'source_ref')),))

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_events', ('epoch_revision', 'revisions'), ('bot', 'persona', 'session', 'event_id')),))

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_context_reply_preparations_v2', ('seal_json', 'frozen_request_json', 'read_versions_json', 'query_epoch_json', 'graph_epoch', 'access_epoch', 'delete_epoch', 'state'), ('bot', 'persona', 'c02_operation_id', 'source_ref')),))

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_recovery_metadata_v2', ('requirements_json',), ('bot', 'persona')),))

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_context_reply_call_bindings_v2', ('acquire_operation_id', 'call_id', 'worker_fence', 'original_seal_digest', 'frozen_request_digest', 'model_call_request_digest', 'model_call_request_json'), ('bot', 'persona', 'original_operation_id')),))

_HOST_ATTACHMENT_SHAPES_V3=_HOST_ATTACHMENT_SHAPES_V3|frozenset((('graph_events', ('digest', 'epoch_revision'), ('bot', 'persona', 'session', 'event_id')),))


# Fixed Contact immutable-original families share the existing whole-column EOF reader.
_HOST_ATTACHMENT_SHAPES_V3 = _HOST_ATTACHMENT_SHAPES_V3 | frozenset({
    ("graph_contact_expression_plan_originals_v2",("bot","persona","contact_id","payload_json","payload_digest","signature"),("bot","persona","contact_id")),
    ("graph_contact_model_originals_v2",("payload_json","payload_digest","signature"),("bot","persona","kind","original_ref")),
    ("runtime_budget_reservations",("digest","ceiling_json","state"),("lease_id","operation_id")),
    ("graph_bundle_operations",("receipt_json","activity_id","commit_seq"),("bot","persona","operation_id")),
    ("runtime_budget_operations",("receipt_json",),("bot_id","persona_id","operation_id","phase")),
    ("graph_events",("revisions","invalidated","epoch_revision"),("bot","persona","session","event_id")),
    ("graph_bundle_operations",("receipt_json",),("bot","persona","operation_id")),
    ("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq","receipt_json"),("bot","persona","operation_id")),
    ("graph_original_model_cost_attempts_v1",("state","attempt_id"),("bot","persona","call_id")),
    ("graph_events",("reads","revisions","epoch_revision"),("bot","persona","session","event_id")),
    ("runtime_budget_operations",("digest",),("bot_id","persona_id","operation_id","phase")),
})

_HOST_ATTACHMENT_SHAPES_V3 = _HOST_ATTACHMENT_SHAPES_V3 | frozenset({
    ('graph_events',('epoch_revision',),('bot','persona','session','event_id')),
    ('runtime_budget_grants',('grant_json','signature'),('lease_id','version')),
    ('graph_d10_production_inputs_v1',('kind','producing_operation_id','payload_json','payload_digest','signature'),('bot','persona','original_ref')),
    ('graph_contact_prospective_originals_v1',('bot','persona','contact_id','birth_operation_id','payload_json','payload_digest','signature','original_ref'),('bot','persona','original_ref')),
    ('graph_contact_prospective_originals_v1',('bot','persona','contact_id','birth_operation_id','payload_json','payload_digest','signature','original_ref'),('bot','persona','contact_id')),
    ('graph_owner_domain_attempts_v3',('request_digest','attempt_id','graph_revision','graph_epoch','permit_json','receipt_json'),('bot','persona','operation_id')),
    ('runtime_resource_quotes',('status',),('quote_id','version')),
    ('graph_domain_production_outbox_v1',('causal_operation_id','event_kind','original_ref','original_digest','state'),('bot','persona','dedupe_key')),
    ('graph_recovery_metadata_v2',('requirements_json','graph_revision'),('bot','persona')),
})

_HOST_ATTACHMENT_SHAPES_V3 = _HOST_ATTACHMENT_SHAPES_V3 | frozenset({
    ("runtime_budget_reservations",("state",),("lease_id","operation_id")),
    ("graph_atoms",("value","valid"),("token",)),
})

_HOST_ATTACHMENT_SHAPES_V3 = _HOST_ATTACHMENT_SHAPES_V3 | frozenset({
    ('graph_events',('reads','revisions','invalidated','epoch_revision'),('bot','persona','session','event_id')),
})

_HOST_ATTACHMENT_SHAPES_V3 = _HOST_ATTACHMENT_SHAPES_V3 | frozenset((("graph_atoms",("revision","value","valid"),("token",)),("graph_atoms",("value","valid"),("token",)),("runtime_budget_operations",("receipt_json",),("bot_id","persona_id","operation_id","phase")),("graph_atoms",("revision",),("token",)),("graph_atoms",("revision",),("token",)),("graph_bundle_operations",("receipt_json","commit_seq"),("bot","persona","operation_id")),("graph_atoms",("value","valid"),("token",)),("runtime_budget_operations",("receipt_json",),("bot_id","persona_id","operation_id","phase"))))


_HOST_ATTACHMENT_SHAPES_V3 = _HOST_ATTACHMENT_SHAPES_V3 | frozenset({('runtime_jobs',('job_id','operation_id','activity_id','bot_id','persona_id','work_kind','phase','deadline_utc','lease_expires_utc','budget_ref'),('job_id',))})

# Exact InternalLife originals share the metered complete-column reader.
_HOST_ATTACHMENT_SHAPES_V3 = _HOST_ATTACHMENT_SHAPES_V3 | frozenset({
    ('graph_internal_life_content_originals_v1', ('payload_json','payload_digest','signature'),
        ('bot','persona','kind','original_ref')),
    ('graph_internal_life_worker_originals_v2', ('payload_json','payload_digest','signature'),
        ('bot','persona','kind','job_id')),
    ('runtime_budget_operations', ('digest',), ('bot_id','persona_id','operation_id','phase')),
    ("graph_atoms", ("value",), ("token",)),
    ("graph_d11_life_originals_v1", ("producing_operation_id", "payload_json", "payload_digest", "signature"), ("bot", "persona", "kind", "original_ref")),
    ("graph_events", ("reads", "revisions", "epoch_revision", "invalidated"), ("bot", "persona", "session", "event_id")),
    ("graph_bundle_fences_v2", ("permit_json", "pre_graph_revision", "pre_graph_epoch", "post_graph_revision", "post_graph_epoch", "finish_request_id", "finish_request_digest"), ("bot", "persona", "operation_id")),
    ("runtime_budget_operations", ("digest", "lease_id", "resolution_binding_json"), ("bot_id", "persona_id", "operation_id", "phase")),
    ("graph_d11_life_originals_v1", ("producing_operation_id", "payload_json", "payload_digest", "signature"), ("bot", "persona", "kind", "original_ref")),
    ("runtime_budget_operations", ("receipt_json",), ("bot_id", "persona_id", "operation_id", "phase")),
    ("runtime_budget_reservations", ("digest", "ceiling_json"), ("lease_id", "operation_id")),
    ("runtime_budget_operations", ("digest", "lease_id", "receipt_json"), ("bot_id", "persona_id", "operation_id", "phase")),
    ("runtime_budget_reservations", ("ceiling_json", "state", "actual_json"), ("lease_id", "operation_id")),
    ("d02_body_quotes_v1", ("quote_version", "policy_id", "policy_version", "operation_id", "resource_quote_digest", "body_quote_json", "signature"), ("bot", "persona", "quote_id")),
})
_HOST_ATTACHMENT_SCANS_V3 = _HOST_ATTACHMENT_SCANS_V3 | frozenset({
    ('graph_dependencies', ('dependency_token','dependency_revision'), ('dependent_token',), 'dependency_token'),
})
