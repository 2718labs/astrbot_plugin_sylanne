"""Installed Contact sender reads and the closed current-P2 entry.

The original final write reader stays strict. Its qualifications cannot be
relabelled as a dispatch-fence qualification; until the independent private
P2 witness is implemented this writer refuses before P0, accounting or send.
"""
from dataclasses import dataclass
import json

from ..graph_store import ProductionGraphStore
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_serialize
from .contact_final_stage_v3 import verify_contact_final_committed_v3
from .dispatch_admission import load_request
from .domain_production_originals_v1 import read_adopted_domain_operation_v1


@dataclass(frozen=True, slots=True)
class InstalledContactFinalClaimWriterV3:
    graph: object
    port: object
    clock_policy: object
    route_port: object
    issuer_id: str

    def __call__(self, *args, **kwargs):
        raise RuntimeError("Contact claim requires its closed current P2 SQL witness; HOLD")

    def require_current_entry(self, graph, authority, lease, original):
        if graph is not self.graph:
            raise ValueError("Contact writer crossed its installed coordinator")
        # Explicit product gate, not a configuration flag or a test authority.
        # The original six checks belong to another permit/stage. Neither
        # same-head comparisons nor a caller marker can issue this witness.
        raise RuntimeError("installed current Contact P2 provider qualification unavailable; HOLD")

    def prepare_contact_for_handoff(self, graph, claimed, handoff_id, original):
        raise RuntimeError("Contact own-claimed P2 qualification contract is not installed; HOLD")


def register_contact_dispatch_final_claim_writer_v3(graph, bootstrap, *, route_port=None, issuer_id=None):
    from ..host.authority_profile import AdminIngressClockPolicy
    from ..host.installed_dispatch_route import InstalledDispatchRoutePort
    graph._admin(bootstrap)
    port = graph._GraphCoordinator__content_fence_v2
    clock_policy = graph._GraphCoordinator__dispatch_clock_policy
    if (not isinstance(graph._GraphCoordinator__store, ProductionGraphStore)
            or port is None or type(clock_policy) is not AdminIngressClockPolicy
            or type(route_port) is not InstalledDispatchRoutePort
            or route_port._coordinator is not graph
            or type(issuer_id) is not str or not issuer_id
            or not callable(getattr(port, "read_ingress_clock", None))):
        raise RuntimeError("installed Contact final claim dependencies unavailable; HOLD")
    return InstalledContactFinalClaimWriterV3(graph, port, clock_policy, route_port, issuer_id)


def _identity_locked(graph, namespace, operation_id):
    from ..host.contact_dispatch_driver_v3 import OriginalContactDispatchV3
    db = graph._GraphCoordinator__store._db
    original = read_adopted_domain_operation_v1(db, namespace, operation_id)
    if original is None or original['operation_kind'] != 'prepare_contact_dispatch_v3':
        raise ValueError("actual Contact3 adopted original is absent")
    row = db.execute('SELECT receipt_json FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*namespace.as_tuple, operation_id)).fetchone()
    if row is None or not row[0]:
        raise ValueError("actual Contact3 Owner receipt is absent")
    result = json.loads(row[0])
    if (canonical_serialize(result) != row[0]
            or result.get('operation_id') != operation_id
            or result.get('original_digest') != original['original_digest']
            or result.get('coverage') != 'complete'):
        raise ValueError("actual Contact3 saved result differs")
    proof = original['payload']['provenance']
    issued = load_request(db, namespace, proof['admission_ref'])
    if issued is None:
        raise ValueError("actual Contact3 dispatch command is absent")
    receipt, request = issued
    operation = original['receipt']
    if (operation.outbox_refs != (proof['outbox_ref'],)
            or receipt.receipt_digest != proof['admission_receipt_digest']
            or len(operation.write_versions) != 11
            or {(row['ref'], row['revision']) for row in proof['write_commitments']}
               != {(v.key.token, v.revision) for v in operation.write_versions}):
        raise ValueError("actual Contact3 original eleven-member receipt differs")
    # Identity-only recovery can survive an added dispatch claim. It never
    # releases text or authorizes a send. Every original member still has its
    # exact producing history; current content permission is checked separately.
    for member in proof['write_commitments']:
        history = db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',
            (member['ref'], member['revision'])).fetchone()
        if history is None or history[0] != operation_id or history[2] != 1:
            raise ValueError("actual Contact3 producing member history is absent")
    batch = tuple(v.key.token for v in operation.write_versions if v.key.type_name == 'd09.contact_verified_batch.v3')
    if len(batch) != 1:
        raise ValueError("actual Contact3 whole batch identity is absent")
    return OriginalContactDispatchV3(namespace, operation_id, proof['outbox_ref'],
        batch[0], request, receipt, operation), result


def read_committed_contact_dispatch_v3(graph, authority, lease, operation_id):
    if type(operation_id) is not str or not operation_id:
        raise ValueError("actual Contact operation ID required")
    graph._authorize(lease, authority, frozenset({'d08', 'd09', 'd10', 'd11'}))
    store = graph._GraphCoordinator__store
    if not isinstance(store, ProductionGraphStore) or graph._GraphCoordinator__content_fence_v2 is None:
        raise RuntimeError("installed Contact current read fence unavailable")
    def read():
        db = store._db
        db.execute('BEGIN')
        try:
            return _identity_locked(graph, authority.namespace, operation_id)[0]
        finally:
            db.rollback()
    return graph._read_v2(authority, read)


def get_contact_dispatch_text_segment_v3(graph, authority, lease, request):
    from ..host.astrbot_dispatch import ResolvedTextPayload
    from .contact_batch_current_v3 import require_current_contact_batch_v3
    from .first_ingress_v2 import trusted_upper
    graph._authorize(lease, authority, frozenset({'d08', 'd09', 'd10', 'd11'}))
    port, store = graph._GraphCoordinator__content_fence_v2, graph._GraphCoordinator__store
    if not isinstance(store, ProductionGraphStore) or port is None:
        raise RuntimeError("installed Contact current content fence unavailable")
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__dispatch_clock_policy))
    def read():
        db = store._db
        db.execute('BEGIN')
        try:
            original, result = _identity_locked(graph, authority.namespace, request.operation_id)
            if request != original.request or request.segment_index != 0 or request.segment_count != 1:
                raise ValueError("Contact single original command differs; whole batch HOLD")
            verify_contact_final_committed_v3(db, namespace=authority.namespace, result=result,
                issuer=graph._GraphCoordinator__d11_issuer, graph=graph)
            original.admission.admission.require_current(now)
            batch, _, _ = require_current_contact_batch_v3(db, namespace=authority.namespace,
                batch_ref=original.batch_ref, operation_id=original.operation_id,
                generation=request.activation_generation,
                graph_incarnation=original.admission.admission.graph_incarnation)
            if len(batch.content.segments) != 1 or now >= batch.content.valid_until:
                raise ValueError("Contact whole batch scope/deadline differs")
            segment = batch.content.segments[0].segment
            account = json.loads(original.admission.admission.account_ref)
            destination = json.loads(original.admission.admission.destination_ref)
            return ResolvedTextPayload(segment.body.encode('utf-8'), (), segment.claim_uses,
                request.namespace, *account, *destination, batch.content.scene_id)
        finally:
            db.rollback()
    return graph._read_v2(authority, read)


def commit_contact_dispatch_final_claim_v3(graph, *args, **kwargs):
    raise RuntimeError("Contact current P2 closed SQL witness is not installed; HOLD")
