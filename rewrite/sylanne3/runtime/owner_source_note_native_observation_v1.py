"""Read actual Owner-task Native originals; observations never dispatch or retry."""
from dataclasses import dataclass
from contextlib import contextmanager
import asyncio

from ..host.v2_fence_port import V2FenceOutcomeUnknown

from .d01_production_operations_v1 import MissingProductionOriginalV1
from .owner_source_note_life_v1 import owner_source_note_life_ids_v1, read_owner_source_note_registered_plan_v1
from .d11_life_preparation_v1 import read_prepared_life_by_ref_v1, life_ids_v1
from .d11_life_contract_v1 import D11LifeClaimV1, D11LifeTerminalV1, life_from_wire_v1, life_adoption_operation_id_v1
from .d11_life_terminal_v1 import read_adopted_life_original_v1


@dataclass(frozen=True, slots=True)
class OwnerSourceNoteNativeObservationV1:
    authorization_original_ref: str
    authorization_original_digest: str
    state: str
    prepared_original_ref: str | None
    effect_id: str | None
    claim_original_ref: str | None
    terminal_original_ref: str | None
    terminal_status: str | None
    adoption_operation_id: str | None
    adoption_finished: bool
    actual_cpu_ms: int | None
    reason_code: str | None
    schema: str = 'd11.owner-source-note-native-observation.v1'


def _prepared(db, *, authorization, issuer):
    auth=authorization;ids=owner_source_note_life_ids_v1(auth)
    from .d11_life_preparation_v1 import _read
    if _read(db,issuer=issuer,namespace=auth.cause.namespace,kind='plan',ref=ids['plan_ref']) is None:
        return None
    plan=read_owner_source_note_registered_plan_v1(db,authorization=auth,issuer=issuer)
    prepared=read_prepared_life_by_ref_v1(db,namespace=auth.cause.namespace,
        prepared_original_ref=life_ids_v1(plan)['prepared'],issuer=issuer)
    if prepared is None:return None
    b=prepared.binding
    heads={name:(head,digest) for name,head,digest in auth.heads}
    if (prepared.plan!=plan or (b.namespace,b.installation_id,b.activity_id,b.operation_id,b.effect_id,
            b.attempt_id,b.parent_budget_lease_ref,b.plan_original_ref)!=(auth.cause.namespace,auth.cause.installation_id,
            ids['activity_id'],ids['action_operation_id'],ids['effect_id'],ids['attempt_id'],auth.cause.parent_budget_lease_ref,ids['plan_ref'])
            or (plan.project.ref,plan.recipe.ref,plan.input_source.ref,plan.input_source.revision,plan.input_source.digest)!=
                (auth.request.project_ref,auth.request.recipe_ref,auth.request.body_source_ref,
                 heads['body_source'][0].revision,heads['body_source'][1])):
        raise ValueError('Owner Native observation changed its actual authorized execution binding')
    return prepared


def read_adopted_owner_source_note_native_v1(db, *, authorization, issuer, expected_status=None):
    """Authenticate one adopted Native fact and its actual atomic cost/job receipt."""
    prepared=_prepared(db,authorization=authorization,issuer=issuer)
    if prepared is None:return None
    b=prepared.binding
    adopted=read_adopted_life_original_v1(db,namespace=b.namespace,result_ref=b.artifact_ref,issuer=issuer)
    if adopted is None:return None
    terminal=life_from_wire_v1(adopted['terminal'],D11LifeTerminalV1)
    if terminal.binding!=b or expected_status is not None and terminal.status!=expected_status:
        raise ValueError('Owner Native adopted terminal differs from its exact original binding/status')
    from .d11_life_adoption_v1 import _read_signed, verify_life_adoption_commit_v1
    from ..authority_service.d11_life_bridge_v1 import life_bridge_from_wire_v1
    saved=_read_signed(db,b.namespace,'adoption_bridge',b.execution_id,issuer)
    if saved is None:raise MissingProductionOriginalV1('actual_Owner_Native_adoption_bridge')
    gate=life_bridge_from_wire_v1(saved[1])
    if gate.binding!=b or gate.terminal!=terminal or saved[0]!=life_adoption_operation_id_v1(b):
        raise ValueError('Owner Native adoption bridge changed its genuine terminal')
    receipt=verify_life_adoption_commit_v1(db,gate=gate,issuer=issuer,
        resource_issuer=issuer.resource_issuer,require_current_metadata=False)
    if receipt is None:raise MissingProductionOriginalV1('actual_Owner_Native_atomic_adoption_receipt')
    return prepared,terminal,adopted,gate,receipt


@contextmanager
def _read_snapshot(store):
    with store._lock:
        db=store._db
        owns_transaction=not db.in_transaction
        if owns_transaction:db.execute('BEGIN')
        try:
            yield db
        finally:
            if owns_transaction:db.rollback()


def _unknown(auth,prepared,reason,*,claim=None,terminal=None,adoption_id=None):
    return OwnerSourceNoteNativeObservationV1(auth.original_ref,auth.digest,'unknown',
        prepared.binding.prepared_original_ref,prepared.binding.effect_id,
        None if claim is None else claim.original_ref,None if terminal is None else terminal.original_ref,
        None if terminal is None else terminal.status,adoption_id,False,
        None if terminal is None else terminal.actual_cpu_ms,reason)


def read_owner_source_note_native_observation_v1(graph, bootstrap, *, authorization_original_ref):
    """Use within the caller's actual current Owner read fence; never manufacture proof."""
    from ..graph_coordinator import GraphCoordinator
    from ..host.d11_life_port_v1 import InstalledD11LifePortV1
    from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
    if type(graph) is not GraphCoordinator:raise TypeError('actual installed Owner Native Graph required')
    graph._admin(bootstrap)
    bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    ns=bundle.installation_policy.namespace;store=graph._GraphCoordinator__store;issuer=graph._GraphCoordinator__d11_issuer
    with _read_snapshot(store) as db:
        saved=read_owner_source_note_task_authorization_v2(db,namespace=ns,
            original_ref=authorization_original_ref,issuer=issuer)
        if saved is None:raise MissingProductionOriginalV1('actual_Owner_task_for_Native_observation')
        auth=saved[0];prepared=_prepared(db,authorization=auth,issuer=issuer)
    if prepared is None:
        return OwnerSourceNoteNativeObservationV1(auth.original_ref,auth.digest,'not_prepared',
            None,None,None,None,None,None,False,None,None)
    port=InstalledD11LifePortV1(graph._GraphCoordinator__content_fence_v2)
    try:
        claim,terminal=port.read_d11_life_original_v1(binding=prepared.binding)
    except (V2FenceOutcomeUnknown,ConnectionError,TimeoutError,asyncio.IncompleteReadError):
        with _read_snapshot(store) as db:
            current=read_owner_source_note_task_authorization_v2(db,namespace=ns,
                original_ref=authorization_original_ref,issuer=issuer)
            if current is None or current[0]!=auth or _prepared(db,authorization=auth,issuer=issuer)!=prepared:
                raise ValueError('Owner Native originals changed during unavailable Core observation')
        return _unknown(auth,prepared,'native_original_read_unavailable')
    if claim is not None and (type(claim) is not D11LifeClaimV1 or claim.binding!=prepared.binding
            or claim.payload.prepared_digest!=prepared.digest):
        raise ValueError('Owner Native observed claim differs from actual signed preparation')
    if terminal is not None and (type(terminal) is not D11LifeTerminalV1
            or terminal.binding!=prepared.binding or terminal.claim!=claim):
        raise ValueError('Owner Native observed terminal differs from actual Core claim')
    with _read_snapshot(store) as db:
        current=read_owner_source_note_task_authorization_v2(db,namespace=ns,
            original_ref=authorization_original_ref,issuer=issuer)
        if current is None or current[0]!=auth or _prepared(db,authorization=auth,issuer=issuer)!=prepared:
            raise ValueError('Owner Native originals changed during original observation')
        adopted=read_adopted_owner_source_note_native_v1(db,authorization=auth,issuer=issuer)
    finished=False;adoption_id=None
    if adopted is not None:
        if adopted[1]!=terminal:raise ValueError('Owner Native Graph adoption differs from actual Core terminal')
        adoption_id=life_adoption_operation_id_v1(prepared.binding)
        try:
            finished=port.life_adoption_bridge_v1(binding=prepared.binding,action='status',gate=adopted[3])=='finished'
        except (V2FenceOutcomeUnknown,ConnectionError,TimeoutError,asyncio.IncompleteReadError):
            return _unknown(auth,prepared,'native_adoption_status_unavailable',claim=claim,terminal=terminal,adoption_id=adoption_id)
    state=('prepared' if claim is None else 'claimed_pending') if terminal is None else terminal.status
    return OwnerSourceNoteNativeObservationV1(auth.original_ref,auth.digest,state,prepared.binding.prepared_original_ref,
        prepared.binding.effect_id,None if claim is None else claim.original_ref,
        None if terminal is None else terminal.original_ref,None if terminal is None else terminal.status,
        adoption_id,finished,None if terminal is None else terminal.actual_cpu_ms,
        None if terminal is None else terminal.payload.reason_code)
