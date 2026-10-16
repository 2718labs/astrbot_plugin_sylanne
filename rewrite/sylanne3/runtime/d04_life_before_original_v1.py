"""Prospective Life before-state capture from actual authored D04 history.

The companion lives in the existing signed Life-original store. Its state rows
are already inside the real prepared digest consumed by the independent claim.
It records temporal/state association, never an identified causal effect.
"""
from dataclasses import dataclass
import json
import math
import sqlite3
import weakref

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d04.authored_lineage_v3 import (
    CHECKPOINT_TYPE, decode_authored_numeric_checkpoint_v2,
    decode_authored_feeling_state_v1, decode_authored_mood_state_v1,
    validate_authored_joint_predecessor_v3,
)
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d04_root_original_store_v3 import read_d04_root_original_v3
from .joint_numeric_component import _authored_predecessor_original
from .d11_life_preparation_v1 import TABLE, _read, _record, life_ids_v1

KIND = 'd04_before_v1'
SCHEMA = 'd04.life-before-original.v1'
MAX_MEMBERS = 16
MAX_ROWS = 128
MAX_BYTES = 262144
_STAGES = {}
_CURRENT = {}


def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError('Life D04 before reference is invalid')


def _sha(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Life D04 before commitment is invalid')


@dataclass(frozen=True, slots=True)
class D04LifeBeforeCapturePolicyV1:
    """Installed explicit root selection; this public shape grants no authority."""
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    root_operation_id: str

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId:
            raise TypeError('Life before policy needs its installed namespace')
        for value in (self.installation_id, self.manifest_digest, self.root_operation_id):
            _text(value)


@dataclass(frozen=True, slots=True)
class D04LifeBeforeRowV1:
    ref: str
    revision: int
    digest: str

    def __post_init__(self):
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError('Life before needs an actual positive graph revision')
        _sha(self.digest)


@dataclass(frozen=True, slots=True)
class D04LifeBeforeMemberV1:
    checkpoint: D04LifeBeforeRowV1
    state: D04LifeBeforeRowV1
    cursor: float
    root_digest: str
    predecessor_receipt_digest: str

    def __post_init__(self):
        if (type(self.checkpoint) is not D04LifeBeforeRowV1
                or type(self.state) is not D04LifeBeforeRowV1
                or AtomKey.from_token(self.checkpoint.ref).type_name != CHECKPOINT_TYPE
                or AtomKey.from_token(self.state.ref).type_name not in {
                    'd04.authored_feeling_state.v1', 'd04.authored_mood_state.v1'}
                or type(self.cursor) not in (int, float) or not math.isfinite(self.cursor)):
            raise ValueError('Life before member is not a closed authored D04 pair')
        _sha(self.root_digest); _sha(self.predecessor_receipt_digest)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class D04LifeBeforeOriginalV1:
    namespace: NamespaceId
    original_ref: str
    root_operation_id: str
    root_digest: str
    prepare_operation_id: str
    execution_id: str
    activity_id: str
    binding_digest: str
    prepared_digest: str
    installation_id: str
    manifest_digest: str
    captured_at_utc: float
    activation_generation: int
    graph_incarnation: str
    before_graph_revision: int
    before_graph_epoch: int
    members: tuple[D04LifeBeforeMemberV1, ...]
    context_rows: tuple[D04LifeBeforeRowV1, ...]
    source_roots: tuple[str, ...]
    schema: str = SCHEMA
    selection_scope: str = 'explicit_installed_root_complete_inventory'
    assertion_scope: str = 'authenticated_state_before_execution_not_identified_causation'

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.schema != SCHEMA
                or self.selection_scope != 'explicit_installed_root_complete_inventory'
                or self.assertion_scope != 'authenticated_state_before_execution_not_identified_causation'
                or type(self.members) is not tuple or not 1 <= len(self.members) <= MAX_MEMBERS
                or any(type(v) is not D04LifeBeforeMemberV1 for v in self.members)
                or type(self.context_rows) is not tuple or len(self.context_rows) > MAX_ROWS
                or any(type(v) is not D04LifeBeforeRowV1 for v in self.context_rows)
                or type(self.source_roots) is not tuple or len(self.source_roots) > 32
                or self.source_roots != tuple(sorted(set(self.source_roots)))):
            raise ValueError('Life before original closed shape differs')
        for name in ('original_ref', 'root_operation_id', 'prepare_operation_id', 'execution_id',
                     'activity_id', 'installation_id', 'manifest_digest', 'graph_incarnation'):
            _text(getattr(self, name))
        for name in ('root_digest', 'binding_digest', 'prepared_digest'):
            _sha(getattr(self, name))
        if (type(self.captured_at_utc) not in (int, float) or not math.isfinite(self.captured_at_utc)
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or any(type(v) is not int or v < 0 for v in (self.before_graph_revision, self.before_graph_epoch))
                or self.original_ref != life_d04_before_ref_v1(self.namespace, self.execution_id)):
            raise ValueError('Life before original identity/time differs')
        rows = tuple(row for member in self.members for row in (member.checkpoint, member.state)) + self.context_rows
        if len({row.ref for row in rows}) != len(rows):
            raise ValueError('Life before rows repeat')
        for ref in (*(row.ref for row in rows), *self.source_roots):
            if NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace:
                raise ValueError('Life before crosses namespace')
        if any(AtomKey.from_token(ref).type_name != 'memory.source' for ref in self.source_roots):
            raise ValueError('Life before source roots are not sources')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def life_d04_before_ref_v1(namespace, execution_id):
    _text(execution_id)
    return 'd04-life-before:' + canonical_digest((namespace, execution_id))[:48]


def decode_life_d04_before_original_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if len(canonical_serialize(raw).encode('utf-8')) > MAX_BYTES:
        raise ValueError('Life before original exceeds its finite wire limit')
    return decode_typed_production_value_v1(raw, D04LifeBeforeOriginalV1)


def _current_inventory(db, namespace, policy):
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(policy) is not D04LifeBeforeCapturePolicyV1 or policy.namespace != namespace):
        raise ValueError('Life before requires its actual installed root and SQL transaction')
    root = read_d04_root_original_v3(db, namespace=namespace, operation_id=policy.root_operation_id)
    refs = tuple(sorted(ref for ref, _, _ in json.loads(root.output_json)['rows']
                        if AtomKey.from_token(ref).type_name == CHECKPOINT_TYPE))
    if not 1 <= len(refs) <= MAX_MEMBERS or len(set(refs)) != len(refs):
        raise ValueError('Life before root checkpoint inventory exceeds bound or repeats')
    pairs, context, sources = [], set(), set()
    for ref in refs:
        row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?', (ref,)).fetchone()
        if row is None or row[2] != 1:
            raise MissingProductionOriginalV1('current_life_d04_checkpoint')
        cp = decode_authored_numeric_checkpoint_v2(json.loads(row[1]))
        sr = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?', (cp.graph_state.ref,)).fetchone()
        if sr is None or sr[2] != 1:
            raise MissingProductionOriginalV1('current_life_d04_state')
        state = (decode_authored_feeling_state_v1 if cp.block.kind == 'feeling'
                 else decode_authored_mood_state_v1)(json.loads(sr[1]))
        validate_authored_joint_predecessor_v3(cp, state, row[0])
        if (state.root_operation_id != policy.root_operation_id or sr[0] != state.revision
                or cp.namespace != namespace.as_tuple):
            raise ValueError('Life before changed its explicit authored root/state')
        pairs.append((ref, row, cp, sr, state))
        sources.update(state.historical_source_refs if cp.block.kind == 'feeling' else state.source_refs)
        context.update(state.active_driver_refs)
        context.update(getattr(state, 'interpretation_refs', ()))
    if len(context) > MAX_ROWS or len(sources) > 32:
        raise MissingProductionOriginalV1('bounded_life_before_context')
    return root, pairs, tuple(sorted(context)), tuple(sorted(sources))


def life_d04_before_read_inputs_v1(db, *, namespace, policy):
    """Unqualified finite read-plan locators; capture authenticates every row."""
    root, pairs, context, sources = _current_inventory(db, namespace, policy)
    keys = tuple(AtomKey.from_token(ref) for ref in (
        *(ref for ref, _, cp, _, _ in pairs), *(cp.graph_state.ref for _, _, cp, _, _ in pairs), *context))
    # Root history is privately verified below, not a generic Life original.
    return keys, sources, ()


def life_d04_before_current_read_inputs_v1(db, *, namespace, episode_ref):
    """Unqualified Source locators; the current reader authenticates originals.

    Historical D04 rows need not remain the current D04 head after execution.
    Missing companions keep ordinary content usable but cannot pass our reader.
    """
    from .d06_internal_life_episode_v2 import EPISODE, PROVENANCE, decode_internal_life_value_v2
    from .d11_life_product_adapter_v1 import raw_life_original_v1
    key = AtomKey.from_token(episode_ref)
    if (not db.in_transaction or key.type_name != EPISODE
            or NamespaceId.from_key(key) != namespace):
        raise ValueError('Life before read-plan requires its actual Episode namespace')
    from .d01_production_operations_v1 import raw_head_value_v1
    raw_proof = raw_head_value_v1(db,namespace,AtomKey(key.owner,PROVENANCE,'record'))
    if raw_proof is None:
        raise MissingProductionOriginalV1('actual_life_episode_provenance')
    proof = decode_internal_life_value_v2(PROVENANCE, raw_proof)
    if proof.episode.episode_ref != episode_ref or proof.event.namespace != namespace:
        raise ValueError('Life before Episode read-plan identity differs')
    ref = life_d04_before_ref_v1(namespace, proof.event.activity.execution_id)
    raw = raw_life_original_v1(db, namespace, KIND, ref)
    if raw is None:
        return (), (), ()
    value = decode_life_d04_before_original_v1(raw)
    if value.namespace != namespace or value.original_ref != ref:
        raise ValueError('Life before read-plan companion scope differs')
    return (), value.source_roots, ()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _LifeBeforeCaptureV1:
    policy: D04LifeBeforeCapturePolicyV1
    prepare_operation_id: str
    execution_id: str
    activity_id: str
    captured_at_utc: float
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    root_digest: str
    members: tuple
    context_rows: tuple
    source_roots: tuple


def capture_life_d04_before_in_tx_v1(db, *, frame, request, issuer, policy):
    from .d11_life_preparation_v1 import PrepareCurrentLifeRequestV1, read_registered_life_plan_v2
    from .d04_series_initial_original_v1 import d04_series_original_read_scope_v1
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    if (type(request) is not PrepareCurrentLifeRequestV1
            or frame.envelope.identity.phase != 'prepare_life'
            or frame.envelope.identity.operation_id != request.prepare_operation_id):
        raise ValueError('Life before capture requires the real preparation command')
    plan = read_registered_life_plan_v2(db, namespace=ns, issuer=issuer, original_ref=request.plan_original_ref)
    if plan is None:
        raise MissingProductionOriginalV1('actual_life_plan_before_capture')
    ids = life_ids_v1(plan)
    if (request.prepare_operation_id != 'd11-life-prepare:' + plan.operation_id
            or db.execute('SELECT 1 FROM runtime_jobs WHERE job_id=?',
                (ids['job'],)).fetchone() is not None
            or db.execute('SELECT 1 FROM ' + TABLE + ' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
                (*ns.as_tuple, 'prepared', ids['prepared'])).fetchone() is not None):
        raise ValueError('Life before cannot be captured after preparation or execution')
    root, pairs, context, sources = _current_inventory(db, ns, policy)
    members = []
    with d04_series_original_read_scope_v1(db):
        for ref, row, cp, sr, state in pairs:
            for target in (ref, cp.graph_state.ref): read.head(db, target, required=True)
            root_digest, receipt_digest = _authored_predecessor_original(db, ns, ref, row[0], cp, state)
            if root_digest != root.original_digest:
                raise ValueError('Life before actual authored root history differs')
            members.append(D04LifeBeforeMemberV1(
                D04LifeBeforeRowV1(ref, row[0], canonical_digest(json.loads(row[1]))),
                D04LifeBeforeRowV1(cp.graph_state.ref, sr[0], canonical_digest(json.loads(sr[1]))),
                cp.cursor, root_digest, receipt_digest))
    context_rows = tuple(D04LifeBeforeRowV1(ref, atom.revision, canonical_digest(atom.value))
                         for ref in context for atom in (read.head(db, ref, required=True),))
    if sources: read.source_family(db, sources)
    metadata = db.execute('SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?', ns.as_tuple).fetchone()
    if metadata is None: raise ValueError('Life before current Graph metadata absent')
    stage = _LifeBeforeCaptureV1(policy, request.prepare_operation_id, ids['execution'], plan.activity_id,
        frame.now_utc, json.loads(metadata[0])['graph_incarnation'], metadata[1], frame.snapshot.epochs[0].revision,
        root.original_digest, tuple(members), context_rows, sources)
    identity = id(stage)
    _STAGES[identity] = (weakref.ref(stage, lambda _: _STAGES.pop(identity, None)), db, frame)
    return stage


def _verify_prepared_rows(value, prepared):
    from datetime import datetime, timezone
    b = prepared.binding
    if ((value.namespace, value.prepare_operation_id, value.execution_id, value.activity_id,
         value.binding_digest, value.prepared_digest, value.installation_id, value.manifest_digest,
         value.activation_generation) != (b.namespace, b.prepare_operation_id, b.execution_id, b.activity_id,
         b.digest, prepared.digest, b.installation_id, b.manifest_digest, b.activation_generation)):
        raise ValueError('Life before differs from its actual signed preparation')
    frozen = {row.ref: row for row in prepared.read_rows}
    for row in (*value.context_rows, *(r for m in value.members for r in (m.checkpoint, m.state))):
        saved = frozen.get(row.ref)
        if saved is None or not saved.valid or saved.revision != row.revision or canonical_digest(json.loads(saved.value_json)) != row.digest:
            raise ValueError('Life before row was not frozen into the actual claim preparation')
    if json.loads(prepared.requirements_json)['graph_incarnation'] != value.graph_incarnation:
        raise ValueError('Life before preparation Graph incarnation differs')
    if datetime.fromtimestamp(value.captured_at_utc, timezone.utc).isoformat().replace('+00:00', 'Z') != prepared.prepared_at_utc:
        raise ValueError('Life before capture is not its actual preparation time')


def _verify_before_history(db, value, prepared):
    from .d04_series_initial_original_v1 import d04_series_original_read_scope_v1
    root = read_d04_root_original_v3(db, namespace=value.namespace, operation_id=value.root_operation_id)
    root_refs = tuple(sorted(ref for ref, _, _ in json.loads(root.output_json)['rows']
                            if AtomKey.from_token(ref).type_name == CHECKPOINT_TYPE))
    if (root.original_digest != value.root_digest
            or tuple(member.checkpoint.ref for member in value.members) != root_refs):
        raise ValueError('Life before lost the complete explicit root inventory')
    frozen = {row.ref: row for row in prepared.read_rows}
    for row in (*value.context_rows, *(r for m in value.members for r in (m.checkpoint, m.state))):
        actual = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
                            (row.ref, row.revision)).fetchone()
        if (actual is None or actual[1] != 1 or actual[0] != frozen[row.ref].value_json
                or canonical_digest(json.loads(actual[0])) != row.digest):
            raise ValueError('Life before exact historical value is missing or changed')
    sources, context = set(), set()
    with d04_series_original_read_scope_v1(db):
        for member in value.members:
            cp = decode_authored_numeric_checkpoint_v2(json.loads(frozen[member.checkpoint.ref].value_json))
            state = (decode_authored_feeling_state_v1 if cp.block.kind == 'feeling'
                     else decode_authored_mood_state_v1)(json.loads(frozen[member.state.ref].value_json))
            validate_authored_joint_predecessor_v3(cp, state, member.checkpoint.revision)
            if (cp.graph_state.ref != member.state.ref or state.revision != member.state.revision
                    or cp.cursor != member.cursor or state.root_operation_id != value.root_operation_id
                    or _authored_predecessor_original(db, value.namespace, member.checkpoint.ref,
                        member.checkpoint.revision, cp, state) != (member.root_digest, member.predecessor_receipt_digest)):
                raise ValueError('Life before authenticated predecessor lineage differs')
            sources.update(state.historical_source_refs if cp.block.kind == 'feeling' else state.source_refs)
            context.update(state.active_driver_refs)
            context.update(getattr(state, 'interpretation_refs', ()))
    if tuple(sorted(sources)) != value.source_roots or tuple(sorted(context)) != tuple(row.ref for row in value.context_rows):
        raise ValueError('Life before original context/source closure differs')


def record_life_d04_before_after_cas_v1(db, *, stage, prepared, graph_receipt, issuer):
    from ..runtime_contracts import CommitReceipt
    from .d11_life_preparation_v1 import read_prepared_life_v1
    issued = _STAGES.get(id(stage))
    if (issued is None or issued[0]() is not stage or issued[1] is not db or not db.in_transaction
            or type(graph_receipt) is not CommitReceipt
            or prepared.prepare_operation_id != stage.prepare_operation_id
            or graph_receipt.status != 'committed' or graph_receipt.operation_id != stage.prepare_operation_id):
        raise ValueError('Life before needs this exact capture and same-transaction CAS')
    frame = issued[2]
    b = prepared.binding
    actual = db.execute('SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
        (*b.namespace.as_tuple, b.prepare_operation_id)).fetchone()
    if actual != (graph_receipt.operation_digest, graph_receipt.commit_seq):
        raise ValueError('Life before requires its actual same-transaction Graph bundle receipt')
    if read_prepared_life_v1(db, binding=b, issuer=issuer) != prepared:
        raise ValueError('Life before requires the final actual committed prepared original')
    value = D04LifeBeforeOriginalV1(b.namespace, life_d04_before_ref_v1(b.namespace, b.execution_id),
        stage.policy.root_operation_id, stage.root_digest, b.prepare_operation_id, stage.execution_id,
        stage.activity_id, b.digest, prepared.digest, stage.policy.installation_id, stage.policy.manifest_digest,
        stage.captured_at_utc, frame.activation_generation, stage.graph_incarnation, stage.graph_revision,
        stage.graph_epoch, stage.members, stage.context_rows, stage.source_roots)
    _verify_prepared_rows(value, prepared)
    _verify_before_history(db, value, prepared)
    result = _record(db, issuer=issuer, namespace=b.namespace, kind=KIND, ref=value.original_ref,
        operation_id=b.prepare_operation_id, value=value)
    _STAGES.pop(id(stage), None)
    return result


def read_life_d04_before_original_v1(db, *, prepared, issuer, required=True):
    """Authenticated historical original, not current-use authorization."""
    b = prepared.binding
    ref = life_d04_before_ref_v1(b.namespace, b.execution_id)
    saved = _read(db, issuer=issuer, namespace=b.namespace, kind=KIND, ref=ref)
    if saved is None:
        if required: raise MissingProductionOriginalV1('authenticated_life_execution_before_d04_state')
        return None
    value = decode_life_d04_before_original_v1(saved[0])
    if saved[1] != b.prepare_operation_id: raise ValueError('Life before producer differs')
    _verify_prepared_rows(value, prepared)
    _verify_before_history(db, value, prepared)
    return value


def require_life_d04_before_for_claim_v1(db, *, prepared, issuer, required=False):
    value = read_life_d04_before_original_v1(db, prepared=prepared, issuer=issuer, required=required)
    if value is None: return None
    for row in (*value.context_rows, *(r for m in value.members for r in (m.checkpoint, m.state))):
        actual = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?', (row.ref,)).fetchone()
        if actual is None or actual[0] != row.revision or actual[2] != 1 or canonical_digest(json.loads(actual[1])) != row.digest:
            raise ValueError('Life before D04 changed before first claim')
    return value


def _read_current_life_d04_before_and_cause_v1(db, *, frame, request, installed_readers):
    """One current lineage read, joined to its historical before in this transaction."""
    from .d06_internal_life_encoding_v1 import read_current_internal_life_encoding_cause_v1
    from .d11_life_preparation_v1 import read_prepared_life_by_ref_v1
    cause = read_current_internal_life_encoding_cause_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    prepared = read_prepared_life_by_ref_v1(db, namespace=frame.envelope.authority.namespace,
        prepared_original_ref=cause.prepared_original_ref, issuer=installed_readers.issuer)
    if prepared is None: raise MissingProductionOriginalV1('actual_life_preparation')
    value = read_life_d04_before_original_v1(db, prepared=prepared, issuer=installed_readers.issuer)
    activity = cause.occurrence.event.activity
    if (value.execution_id != activity.execution_id or value.captured_at_utc > activity.started_at
            or value.activation_generation != frame.activation_generation):
        raise ValueError('Life before temporal/execution/current generation differs')
    read = CurrentDomainReadV1(frame)
    if value.source_roots: read.source_family(db, value.source_roots)
    identity = id(value)
    _CURRENT[identity] = (weakref.ref(value, lambda _: _CURRENT.pop(identity, None)), db, frame,
                         cause.occurrence.episode.episode_ref, canonical_digest(plain_v1(cause.occurrence)))
    return cause, value


def read_current_life_d04_before_v1(db, *, frame, request, installed_readers):
    """Actual current Episode/Source/Owner lineage, then historical before state."""
    _, value = _read_current_life_d04_before_and_cause_v1(
        db, frame=frame, request=request, installed_readers=installed_readers)
    return value


def require_current_life_d04_before_qualification_v1(value, *, db, frame):
    """For the future private numerical producer, never a decoded DTO gate."""
    issued = _CURRENT.get(id(value))
    if (issued is None or issued[0]() is not value or issued[1] is not db
            or issued[2] is not frame or not db.in_transaction):
        raise ValueError('Life before was not authenticated in this actual current frame')
    CurrentDomainReadV1(frame).check(db)
    return issued[3:]
