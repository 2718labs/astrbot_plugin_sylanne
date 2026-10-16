"""Explicit Owner pairing of one real input with two existing artifact tasks.

The immutable W01 production original is the authorization. No Source ancestry
is rewritten, and authorization alone is not evidence of model consumption.
"""
from dataclasses import dataclass

from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d01_production_operations_v1 import MissingProductionOriginalV1, production_read_plan_v1

OPERATION = 'register_method_experiment_v2'


@dataclass(frozen=True, slots=True)
class MethodPairTaskBindingV1:
    goal_head: GraphVersion
    goal_digest: str
    objective_ref: str
    objective_digest: str
    c02_operation_id: str
    task_source_ref: str
    root_registration_ref: str


@dataclass(frozen=True, slots=True)
class MethodPairSharedInputOriginalV1:
    namespace: NamespaceId
    operation_id: str
    experiment_ref: str
    experiment_digest: str
    owner_guard: ProductionOwnerGuardV1
    common_source_head: GraphVersion
    common_source_digest: str
    common_access_head: GraphVersion
    common_access_digest: str
    tasks: tuple[MethodPairTaskBindingV1, ...]
    parent_budget_lease_ref: str
    valid_until_utc: float
    schema: str = 'd01.method-pair-shared-input.v1'

    def __post_init__(self):
        if (self.schema != 'd01.method-pair-shared-input.v1' or type(self.namespace) is not NamespaceId
                or type(self.owner_guard) is not ProductionOwnerGuardV1 or type(self.tasks) is not tuple
                or len(self.tasks) != 2 or any(type(t) is not MethodPairTaskBindingV1 for t in self.tasks)
                or len({t.goal_head.key for t in self.tasks}) != 2
                or len({t.c02_operation_id for t in self.tasks}) != 2):
            raise ValueError('shared method input needs two distinct actual task causes')
        for head, kind in ((self.common_source_head, 'memory.source'), (self.common_access_head, 'memory.access'),
                *((t.goal_head, 'd08.goal.v1') for t in self.tasks)):
            if type(head) is not GraphVersion or head.revision < 1 or head.key.type_name != kind or NamespaceId.from_key(head.key) != self.namespace:
                raise ValueError('shared method input crossed its actual positive heads')
        for digest in (self.experiment_digest, self.common_source_digest, self.common_access_digest,
                *(d for t in self.tasks for d in (t.goal_digest, t.objective_digest))):
            if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('shared method input requires exact immutable commitments')

    @property
    def digest(self):
        return canonical_digest(self)


def build_method_pair_shared_input_v1(db, *, read, experiment, issuer):
    from ..domains.d08.execution import _decode_goal
    from ..memory_types import access_key
    from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
    ns = read.frame.envelope.authority.namespace
    source = read.head(db, experiment.common_task_source_ref, required=True)
    access = read.head(db, access_key(*ns.as_tuple, source.value['source_id']), required=True)
    for audience in read.frame.envelope.authority.audience:
        for purpose in ('context', 'consolidation'):
            read.source_family(db, (source.key.token,), purpose=purpose, audience=audience)
    tasks = []
    for ref in (experiment.treatment_goal_ref, experiment.baseline_goal_ref):
        atom = read.head(db, ref, required=True)
        goal = _decode_goal(atom.value)
        objective_ref, objective = require_artifact_task_objective_original_v1(db, namespace=ns,
            goal_ref=ref, goal=goal, issuer=issuer)
        read.original(objective_ref, kind='d11.life_artifact_task_objective', digest=canonical_digest(objective))
        if (goal.state != 'active' or goal.progress_refs or experiment.valid_until > objective['valid_until_utc']
                or objective['source_ref'] not in goal.reason_refs):
            raise ValueError('paired input must precede both actual task outcomes and retain their deadlines')
        read.source_family(db, goal.reason_refs, purpose='consolidation')
        if objective['source_ref'] not in experiment.source_refs:
            raise ValueError('paired experiment must retain both real task Sources in its provenance')
        prior = db.execute("SELECT 1 FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND "
            "((kind='c4_prepared' AND json_extract(payload_json,'$.selector.c02_operation_id')=?) OR "
            "(kind='c4_phase_prepared' AND json_extract(payload_json,'$.selector.task.c02_operation_id')=?)) LIMIT 1",
            (*ns.as_tuple, objective['initial_c02_operation_id'], objective['initial_c02_operation_id'])).fetchone()
        if prior is not None:
            raise ValueError('shared task input must be authorized before either C4 generation is prepared')
        tasks.append(MethodPairTaskBindingV1(GraphVersion(atom.key, atom.revision), canonical_digest(atom.value),
            objective_ref, canonical_digest(objective), objective['initial_c02_operation_id'],
            objective['source_ref'], objective['initial_root_registration_ref']))
    from ..domains.d01.method_learning_v1 import method_learning_key_v1, EXPERIMENT_TYPE
    return MethodPairSharedInputOriginalV1(ns, read.frame.envelope.identity.operation_id,
        method_learning_key_v1(ns, EXPERIMENT_TYPE, experiment.experiment_id).token, canonical_digest(experiment),
        read.frame.owner_guard, GraphVersion(source.key, source.revision), canonical_digest(source.value),
        GraphVersion(access.key, access.revision), canonical_digest(access.value), tuple(tasks),
        experiment.parent_budget_lease_ref, experiment.valid_until)


def read_method_pair_shared_input_original_v1(db, *, namespace, experiment_ref):
    """Authenticate an existing V2 producer; legacy experiments return None."""
    import json
    row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
        (experiment_ref, *namespace.as_tuple)).fetchone()
    if row is None or row[2] != 1:
        raise MissingProductionOriginalV1('actual_current_method_pair_experiment')
    history = db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',
        (experiment_ref, row[0])).fetchone()
    if history is None or history[1:] != row[1:]:
        raise MissingProductionOriginalV1('actual_method_pair_experiment_history')
    original = read_adopted_domain_operation_v1(db, namespace, history[0])
    if original is None or original['domain'] != 'd01':
        raise MissingProductionOriginalV1('actual_method_pair_registered_original')
    if original['operation_kind'] != OPERATION:
        return None
    value = decode_typed_production_value_v1(original['payload']['provenance']['shared_input'], MethodPairSharedInputOriginalV1)
    key = AtomKey.from_token(experiment_ref)
    experiment = json.loads(row[1])
    if (value.namespace != namespace or value.operation_id != history[0] or value.experiment_ref != experiment_ref
            or value.experiment_digest != canonical_digest(experiment)
            or original['receipt'].write_versions != (GraphVersion(key, row[0]),)
            or tuple(t.goal_head.key.token for t in value.tasks) != (experiment['treatment_goal_ref'], experiment['baseline_goal_ref'])
            or value.common_source_head.key.token != experiment['common_task_source_ref']):
        raise ValueError('shared input differs from its actual immutable experiment producer')
    return value, original


def require_current_method_pair_shared_input_v1(db, *, read, experiment_ref, goal_ref, issuer):
    """Return the real Source family to add to C4 input, never synthetic ancestry."""
    from ..domains.d08.execution import _decode_goal
    from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
    saved = read_method_pair_shared_input_original_v1(db, namespace=read.frame.envelope.authority.namespace,
        experiment_ref=experiment_ref)
    if saved is None:
        return None
    pair, original = saved
    read.original(experiment_ref)
    selected = tuple(t for t in pair.tasks if t.goal_head.key.token == goal_ref)
    if (len(selected) != 1 or pair.owner_guard != read.frame.owner_guard
            or read.frame.now_utc >= pair.valid_until_utc
            or pair.parent_budget_lease_ref != read.frame.envelope.parent_budget_lease_ref):
        raise ValueError('current C4 pair differs from its actual Owner, task, Root or deadline')
    for version, digest in ((pair.common_source_head, pair.common_source_digest), (pair.common_access_head, pair.common_access_digest)):
        atom = read.head(db, version.key, required=True)
        if atom.revision != version.revision or canonical_digest(atom.value) != digest:
            raise MissingProductionOriginalV1('actual_current_unchanged_common_method_input')
    task = selected[0]
    goal = _decode_goal(read.head(db, goal_ref, required=True).value)
    ref, objective = require_artifact_task_objective_original_v1(db, namespace=pair.namespace,
        goal_ref=goal_ref, goal=goal, issuer=issuer)
    if (ref, canonical_digest(objective)) != (task.objective_ref, task.objective_digest):
        raise ValueError('paired C4 switched its authenticated task objective')
    read.original(ref, kind='d11.life_artifact_task_objective', digest=task.objective_digest)
    family = read.source_family(db, (pair.common_source_head.key.token,), purpose='consolidation')
    for audience in read.frame.envelope.authority.audience:
        read.source_family(db, (pair.common_source_head.key.token,), purpose='context', audience=audience)
    return pair, family


def method_pair_read_inputs_v1(db, *, namespace, goal_ref):
    """Bounded locators only; the current reader authenticates every used input."""
    from ..domains.d01.method_learning_v1 import EXPERIMENT_TYPE
    from .domain_background_read_v3 import background_inventory_v3
    rows = background_inventory_v3(db, namespace, EXPERIMENT_TYPE, valid_only=True)
    keys, roots, originals, matches = [], [], [], []
    for atom in rows:
        ref, raw = atom.key.token, atom.value
        if goal_ref not in (raw['treatment_goal_ref'], raw['baseline_goal_ref']):
            continue
        saved = read_method_pair_shared_input_original_v1(db, namespace=namespace, experiment_ref=ref)
        if saved is None:
            continue
        pair, _ = saved
        matches.append(ref)
        keys.extend((AtomKey.from_token(ref), pair.common_source_head.key, pair.common_access_head.key))
        roots.append(pair.common_source_head.key.token)
        originals.extend((ref, *(t.objective_ref for t in pair.tasks)))
        keys.extend(t.goal_head.key for t in pair.tasks)
    if len(matches) > 1:
        raise MissingProductionOriginalV1('unique_actual_method_pair_for_task')
    return (matches[0] if matches else None), production_read_plan_v1((EXPERIMENT_TYPE,), keys, roots, originals)


_PAIR_READERS_KEY = object()


class InstalledMethodPairOwnerReadersV2:
    def __init__(self, key, *, base_readers, owner_binding, generation):
        if key is not _PAIR_READERS_KEY:
            raise TypeError('method pair registration requires its actual Owner fence factory')
        self.base_readers = base_readers
        self.issuer, self.owner_guard = base_readers.issuer, base_readers.owner_guard
        self.owner_binding, self.generation = owner_binding, generation

    def require_owner_frame(self, frame):
        from ..graph_types import owner_grant_key
        owner, authority = self.owner_binding, frame.envelope.authority
        if (authority.actor != owner.actor or 'workbench.create' not in owner.capabilities
                or frame.owner_guard.grant_ref != owner_grant_key(*authority.namespace.as_tuple).token
                or (frame.owner_guard.grant_revision, frame.owner_guard.grant_digest) != (owner.grant_revision, owner.grant_digest)
                or frame.owner_guard.owner_head_digest != self.owner_guard.authorization_head.removeprefix('sha256:')
                or frame.activation_generation != self.generation or authority.activation_generation != self.generation
                or authority.purpose not in owner.purposes or not set(authority.audience) <= owner.audiences):
            raise ValueError('method pair changed this actual Owner lease and current authority scope')


def install_method_pair_owner_readers_v2(graph, *, scope, owner_guard, owner_binding):
    from ..graph_coordinator import GraphCoordinator, OwnerLeaseBindingV1
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from .d01_production_operations_v1 import InstalledD01ProductionReadersV1
    if (type(graph) is not GraphCoordinator or type(owner_guard) is not OwnerAuthorizationGuardV1
            or type(owner_binding) is not OwnerLeaseBindingV1
            or not any(binding is owner_binding for binding in graph._GraphCoordinator__owner_leases.values())
            or owner_guard.namespace != scope.namespace or owner_binding.namespace != scope.namespace
            or owner_guard.authorization_head != owner_binding.authorization_head
            or owner_guard.authorization_revision != owner_binding.authorization_revision
            or owner_guard.pending_revoke_operation_id is not None):
        raise ValueError('method pair requires this invocation actual current Owner binding')
    return InstalledMethodPairOwnerReadersV2(_PAIR_READERS_KEY,
        base_readers=InstalledD01ProductionReadersV1(issuer=graph._GraphCoordinator__d11_issuer, owner_guard=owner_guard),
        owner_binding=owner_binding, generation=scope.generation)
