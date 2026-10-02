"""Private Contact SQL projections under the original installed write fence.

This does not extend CurrentDomainRead or the generic production witness. A
reader expires with its exact concrete installed stage, transaction and phase.
The tentative phase is a real GraphStore SAVEPOINT; post-CAS is not COMMIT.
"""
from contextlib import contextmanager
from dataclasses import dataclass, replace
import json

from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion
from ..runtime_contracts import QueryEpoch, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionQueryCoverageV1

_PHASES = frozenset({'pre_e', 'provisional_e_plus_1', 'post_cas_e_plus_1'})
_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class _ContactProjectionWitnessV1:
    runtime: object
    graph: object
    db: object
    scope: object
    material: object
    phase: str
    receipt: object
    bundle: object


def _require(witness, db):
    from .contact_final_stage_v1 import _ContactFinalMaterialV1
    from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    from ..graph_coordinator import GraphCoordinator
    from ..runtime_contracts import FenceScope
    if (type(witness) is not _ContactProjectionWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or type(witness.runtime) is not InstalledDomainOperationRuntimeV1
            or type(witness.graph) is not GraphCoordinator or witness.runtime.graph is not witness.graph
            or type(witness.material) is not _ContactFinalMaterialV1
            or type(witness.scope) is not FenceScope or witness.phase not in _PHASES
            or db is not witness.db or db is not witness.graph._GraphCoordinator__store._db
            or not db.in_transaction or not witness.graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError('Contact private reader lost its installed stage/SQL lock/transaction')
    witness.runtime._current()
    m, scope = witness.material, witness.scope
    from .contact_final_stage_v1 import require_installed_contact_material_v1, _RECEIPTS, _require_contact_deadline_v1
    require_installed_contact_material_v1(m)
    _require_contact_deadline_v1(m)
    if witness.bundle is not m.final_bundle:
        raise ValueError('Contact projection bundle differs from its actual installed stage')
    frame, ns = m.frame, scope.namespace
    stamp, epoch = witness.graph._v2_graph_stamp(ns)
    offset = int(witness.phase != 'pre_e')
    if (m.runtime is not witness.runtime or m.scope is not scope
            or m.operation.operation_kind != 'prepare_contact_dispatch'
            or m.request.segment_index != 0 or type(m.request.segment_index) is not int
            or scope.operation != 'write' or scope.permit.operation != 'write'
            or scope.permit.operation_id != scope.operation_id
            or scope.permit.pinned_anchor != scope.pinned_anchor
            or frame.envelope.authority.namespace != ns
            or frame.activation_generation != scope.generation
            or frame.envelope.authority.activation_generation != scope.generation
            or frame.snapshot.epochs != (scope.graph_epoch,)
            or stamp.graph_revision != scope.graph_revision
            or epoch.revision != scope.graph_epoch.revision + offset
            or not witness.graph._anchor_matches(stamp.requirements, scope.pinned_anchor)
            or frame.envelope.identity.operation_id != m.content.segments[0].operation_id
            or frame.envelope.identity.effect_id != m.content.segments[0].segment.effect_id
            or frame.envelope.identity.activity_id != m.content.activity_id):
        raise ValueError('Contact private reader original R/E, permit, stage or identity differs')
    if offset:
        receipt = witness.receipt
        proof = _RECEIPTS.get((id(m), witness.phase))
        if proof is None or proof[0] is not receipt:
            raise ValueError('Contact projection receipt was not issued by its actual stage')
        expected = tuple(w.key for _, w in m.provisional_writes) if witness.phase == 'provisional_e_plus_1' else tuple(
            w.key for p in witness.bundle.proposals for w in p.typed_writes)
        if (receipt is None or receipt.status != 'committed' or receipt.epoch != epoch
                or len(expected) != len(set(expected))
                or len(receipt.revisions) != len(expected)
                or {v.key for v in receipt.revisions} != set(expected)
                or any(type(v.revision) is not int or v.revision != 1 for v in receipt.revisions)):
            raise ValueError('Contact private reader has no exact actual E+1 Graph receipt')
        event = db.execute('SELECT digest,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',
            (*ns.as_tuple, m.content.activity_id, proof[1])).fetchone()
        if event != (proof[2], epoch.revision):
            raise ValueError('Contact projection actual event identity differs')
        for version in receipt.revisions:
            row = db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',
                (version.key.token, version.revision)).fetchone()
            actual = next(w for _,w in m.provisional_writes if w.key == version.key)
            if row is None or row[0] != proof[1] or row[2] != 1 or canonical_serialize(json.loads(row[1])) != canonical_serialize(actual.value):
                raise ValueError('Contact projection actual member history differs')
    elif witness.receipt is not None or witness.bundle is not None:
        raise ValueError('Contact pre-E reader cannot carry a projected receipt')
    return witness


def _actual_frame(witness, db):
    _require(witness, db)
    original = witness.material.frame
    ns = witness.scope.namespace
    _, epoch = witness.graph._v2_graph_stamp(ns)
    atoms = {}
    limits = original.limits
    def load(key):
        if key in atoms:
            return
        if len(atoms) >= limits.max_graph_heads:
            raise MissingProductionOriginalV1('bounded_complete_contact_projection')
        row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
            (key.token, *ns.as_tuple)).fetchone()
        atoms[key] = GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])) if row else GraphAtom(key, 0, {}, False)
    pages = []
    for page in original.query_coverage:
        rows = db.execute('SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? '
            'ORDER BY token LIMIT ?', (*ns.as_tuple, page.type_id, limits.max_query_rows + 1)).fetchall()
        if len(rows) > limits.max_query_rows:
            raise MissingProductionOriginalV1('complete_current_contact_inventory:' + page.type_id)
        versions = tuple(GraphVersion(AtomKey.from_token(token), revision) for token, revision in rows)
        for version in versions:
            load(version.key)
        pages.append(ProductionQueryCoverageV1(QueryEpoch(ns, 'namespace', epoch.revision), page.type_id,
            versions, True, None))
    for atom in original.snapshot.atoms:
        load(atom.key)
    snapshot = GraphSnapshot(tuple(sorted(atoms.values(), key=lambda a:a.key.token)), (epoch,))
    # New SQL materialization, never a rewritten FenceScope or a relaxed generic
    # frame freezer. Only the private active witness permits this E+1 frame.
    envelope = replace(original.envelope, version_guard=replace(original.envelope.version_guard,
        read_versions=snapshot.versions, query_epochs=(QueryEpoch(ns, 'all', epoch.revision),)))
    return CurrentOperationFrameV1(envelope, snapshot, original.now_utc, original.owner_guard,
        original.activation_generation, tuple(pages), original.installed_policy_refs,
        original.observed_originals, limits)


class _CurrentContactProjectionReadV1(CurrentDomainReadV1):
    def __init__(self, witness, db):
        self._witness = witness
        super().__init__(_actual_frame(witness, db))

    @property
    def phase(self):
        return self._witness.phase

    def check(self, db):
        _require(self._witness, db)
        return super().check(db)

    def head(self, db, key, *, required=False):
        _require(self._witness, db)
        return super().head(db, key, required=required)

    def complete_inventory(self, db, type_name):
        _require(self._witness, db)
        return super().complete_inventory(db, type_name)

    def source_family(self, db, roots, **kwargs):
        _require(self._witness, db)
        return super().source_family(db, roots, **kwargs)

    def committed_operation(self, db, operation_id):
        _require(self._witness, db)
        return super().committed_operation(db, operation_id)


def require_contact_projection_read_v1(read, db, *, phases):
    if type(read) is not _CurrentContactProjectionReadV1 or read.phase not in phases:
        raise ValueError('Contact provider requires its private installed SQL projection phase')
    _require(read._witness, db)
    read.check(db)
    return read


@contextmanager
def _contact_projection_read_v1(material, db, *, phase, receipt=None, bundle=None):
    witness = _ContactProjectionWitnessV1(material.runtime, material.runtime.graph, db,
        material.scope, material, phase, receipt, bundle)
    if phase not in _PHASES:
        raise ValueError('unregistered Contact SQL projection phase')
    _ACTIVE[id(witness)] = witness
    try:
        _require(witness, db)
        yield _CurrentContactProjectionReadV1(witness, db)
    finally:
        _ACTIVE.pop(id(witness), None)
