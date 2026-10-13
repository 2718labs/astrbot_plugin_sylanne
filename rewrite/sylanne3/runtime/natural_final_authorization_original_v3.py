"""Same-transaction originals of the actual natural final authorization inputs."""
from dataclasses import asdict
from weakref import WeakSet
import json
from ..runtime_contracts import canonical_digest,canonical_serialize

_TOKEN=object()
_WITNESSES=WeakSet()
SCHEMA='sylanne.natural_final_authorization_original.v3'
SCHEMA_V4='sylanne.natural_final_authorization_original.v4'


class _NaturalFinalAuthorizationWitnessV3:
    def __init__(self,token,*,coordinator,db,bundle,evidence,graph_receipt,scope,admission,request,payload):
        if token is not _TOKEN:raise TypeError("installed natural final original capture required")
        self.coordinator=coordinator;self.db=db;self.bundle=bundle;self.evidence=evidence
        self.graph_receipt=graph_receipt;self.scope=scope;self.admission=admission;self.request=request
        self.schema=payload['schema']
        self.raw=canonical_serialize(payload);self.digest=canonical_digest(payload);self.used=False
        _WITNESSES.add(self)
    def consume_for(self,coordinator,db,bundle,evidence,graph_receipt,v2_write,admission,request):
        from ..authority_service.v2_contract import to_wire
        if (self not in _WITNESSES or self.used or self.coordinator is not coordinator or self.db is not db
                or not db.in_transaction or self.bundle is not bundle or self.evidence is not evidence
                or self.graph_receipt is not graph_receipt or self.admission!=admission or self.request!=request
                or v2_write is None or v2_write[0].graph_revision!=self.scope.graph_revision
                or v2_write[1]!=self.scope.graph_epoch
                or json.loads(v2_write[4])!=to_wire(self.scope.permit)):
            raise ValueError("natural final original witness crossed its actual transaction/fence/admission")
        self.used=True;_WITNESSES.discard(self)
        return {'schema':self.schema,'payload':json.loads(self.raw),'original_digest':self.digest}


def _capture_natural_final_authorization_original_v3(*,coordinator,db,bundle,evidence,graph_receipt,
        scope,clock_reading,clock_policy,owner_guard,current_effect,effect_snapshot,
        route,snapshot,query,projection,checks,now_utc,admission,request):
    """Called by the installed Graph callback after the existing issuer succeeds.

    This records the already verified objects; it performs no authorization,
    clock refresh, current guard lookup, grant issuance or snapshot recovery.
    """
    from ..authority_service.v2_contract import to_wire
    from ..runtime_contracts import FenceScope,DomainBundle,CheckReceipt
    from ..graph_types import GraphSnapshot,GraphReceipt
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from .dispatch_admission import DispatchAdmissionReceiptV1
    if (not db.in_transaction or type(scope) is not FenceScope or type(bundle) is not DomainBundle
            or type(snapshot) is not GraphSnapshot or type(graph_receipt) is not GraphReceipt
            or type(owner_guard) is not OwnerAuthorizationGuardV1 or type(admission) is not DispatchAdmissionReceiptV1
            or type(checks) is not tuple or any(type(check) is not CheckReceipt for check in checks)
            or admission.admission.check_receipts!=checks or admission.admission.request_digest!=canonical_digest(request)
            or query.revision!=graph_receipt.epoch.revision or snapshot.epochs!=(graph_receipt.epoch,)
            or graph_receipt.epoch.revision!=scope.graph_epoch.revision+1
            or admission.graph_revision!=scope.graph_revision+1 or admission.graph_epoch!=query.revision
            or admission.admission.candidate_digest!=evidence.digest
            or admission.admission.operation_id!=bundle.envelope.identity.operation_id):
        raise ValueError("actual verified natural final inputs differ from committed admission")
    owner_row=db.execute("SELECT operation_id,request_digest,grant_id,grant_digest,graph_incarnation,"
        "graph_access_epoch,graph_epoch,graph_receipt_digest,proof_json FROM graph_owner_issue_operations_v1 "
        "WHERE bot=? AND persona=?",scope.namespace.as_tuple).fetchone()
    if owner_row is None or owner_row[2]!=admission.admission.owner_head_ref or owner_row[6]>scope.graph_epoch.revision:
        raise ValueError("natural final original has no matching original Owner issue epoch")
    payload={
        'schema':SCHEMA,'namespace':asdict(scope.namespace),'identity':asdict(bundle.envelope.identity),
        'candidate_digest':evidence.digest,'bundle_digest':bundle.digest,
        'graph_receipt':asdict(graph_receipt),'graph_receipt_commitment':canonical_digest(graph_receipt),
        'admission_ref':admission.admission.admission_ref,'admission_digest':admission.admission.digest,
        'admission_receipt_digest':admission.receipt_digest,'request_digest':canonical_digest(request),
        'scope':{'namespace':asdict(scope.namespace),'authority_namespace':scope.authority_namespace,
            'generation':scope.generation,'operation':scope.operation,'operation_id':scope.operation_id,
            'permit':to_wire(scope.permit),'pinned_anchor':asdict(scope.pinned_anchor),
            'graph_epoch':asdict(scope.graph_epoch),'graph_revision':scope.graph_revision},
        'owner_guard':asdict(owner_guard),'clock_reading':asdict(clock_reading),'clock_policy':asdict(clock_policy),
        'now_utc':now_utc,'current_effect':asdict(current_effect),'effect_snapshot':to_wire(effect_snapshot),
        'route':asdict(route),'snapshot_versions':[(atom.key.token,atom.revision,atom.valid) for atom in snapshot.atoms],
        'snapshot_epochs':[asdict(epoch) for epoch in snapshot.epochs],'snapshot_commitment':canonical_digest(snapshot),
        'query':asdict(query),'projection':{'namespace':asdict(projection.namespace),'graph_epoch':projection.graph_epoch,
            'coverage':projection.coverage,'missing_sources':projection.missing_sources,'digest':projection.digest,
            'role_bindings':[(atom.key.token,atom.revision) for atom in projection.role_bindings],
            'boundary_rules':[(atom.key.token,atom.revision) for atom in projection.boundary_rules]},
        'checks_digest':canonical_digest(checks),
        'owner_issue_original':dict(zip(('operation_id','request_digest','grant_id','grant_digest','graph_incarnation',
            'graph_access_epoch','graph_epoch','graph_receipt_digest','proof_json'),owner_row,strict=True)),
    }
    return _NaturalFinalAuthorizationWitnessV3(_TOKEN,coordinator=coordinator,db=db,bundle=bundle,evidence=evidence,
        graph_receipt=graph_receipt,scope=scope,admission=admission,request=request,payload=payload)


def _capture_natural_final_authorization_original_v4(*, clock_original, effect_observation,
        budget_original, catalogue_original, **inputs):
    """Consume the successful producers' same-operation originals, never reread time."""
    from ..host.v2_fence_port import _VerifiedIngressClockOriginalV4
    from ..authority_service.v2_contract import NaturalFinalEffectObservationReadV4
    from ..authority_service.c09_natural_final_budget_v4 import _NaturalFinalBudgetOriginalV4
    from ..domains.d03.context import _NaturalFinalContextCatalogueOriginalV4
    coordinator, db = inputs['coordinator'], inputs['db']
    scope, checks = inputs['scope'], inputs['checks']
    if (type(clock_original) is not _VerifiedIngressClockOriginalV4
            or type(effect_observation) is not NaturalFinalEffectObservationReadV4
            or type(budget_original) is not _NaturalFinalBudgetOriginalV4
            or type(catalogue_original) is not _NaturalFinalContextCatalogueOriginalV4):
        raise TypeError("actual natural final clock/Core/budget/catalogue originals required")
    observed = effect_observation.observation
    if (observed.permit != scope.permit or observed.anchor != scope.pinned_anchor
            or observed.installation_id != inputs['owner_guard'].installation_id
            or observed.target_effect_id != inputs['bundle'].envelope.identity.effect_id
            or effect_observation.current_effect != inputs['current_effect']
            or effect_observation.effect_snapshot != inputs['effect_snapshot']):
        raise ValueError("Core natural final observation crossed its actual permit/Owner/effect")
    metadata, epoch = coordinator._v2_graph_stamp(scope.namespace)
    barrier = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", scope.namespace.as_tuple).fetchone()
    if (barrier is None or metadata.graph_revision != scope.graph_revision
            or epoch.revision != inputs['query'].revision):
        raise ValueError("natural final original lost its actual transaction barrier")
    validation, uses = clock_original.consume_for(
        port=coordinator._GraphCoordinator__content_fence_v2,
        reading=inputs['clock_reading'], policy=inputs['clock_policy'], basis_now=inputs['now_utc'])
    budget = budget_original.consume_for(db, inputs['bundle'], inputs['evidence'],
        scope, checks, inputs['now_utc'])
    context = coordinator._GraphCoordinator__dispatch_admission_issuer._context
    catalogue = catalogue_original.consume_for(provider=context, receipt=checks[0], db=db, scope=scope)
    witness = _capture_natural_final_authorization_original_v3(**inputs)
    payload = json.loads(witness.raw)
    payload.update(schema=SCHEMA_V4, clock_validation=validation, clock_uses=uses,
        effect_observation={'original_ref':effect_observation.original_ref,
            'original_digest':effect_observation.original_digest,
            'authority_namespace':scope.authority_namespace, 'operation_id':scope.operation_id,
            'observation_kind':observed.observation_kind},
        budget_observation=budget, context_catalogue=catalogue,
        graph_barrier={'graph_incarnation':metadata.requirements.graph_incarnation,
            'access_epoch':barrier[0], 'delete_epoch':barrier[1],
            'graph_revision':metadata.graph_revision, 'graph_epoch':epoch.revision})
    witness.schema = SCHEMA_V4
    witness.raw = canonical_serialize(payload)
    witness.digest = canonical_digest(payload)
    return witness
