"""Exact ordinary-growth policy/history metadata on the registered Source Work.

The metadata owner below cannot disclose a claim or issue a growth capability.
Every column is selected by the actual namespace history recipe and advances on
its existing Method Work. The production qualifier consumes this history only
after the same Work has qualified its selected Source family.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from ..contracts import Event, Scope
from ..graph_types import AtomKey, GraphVersion, Owner
from ..runtime_contracts import canonical_digest, NamespaceId
from ..domains.d01.ordinary_cumulative_growth_v1 import (
    OrdinaryCumulativeGrowthPolicyV1, OrdinaryContinuityAnchorV1,
    OrdinaryHistoryCoverageV1, OrdinaryContinuityAssessmentV1, OrdinaryDeepGrowthAdoptionV1,
    ordinary_history_metrics_v1, changed_ordinary_blocks_v1, POLICY_KIND, ASSESSMENT_KIND,
    DEEP_ADOPTION_KIND, ANCHOR_TYPE, BASIS_KIND, OrdinaryContinuityBasisOriginalV1,
    OrdinaryCounterScopeBindingV1, OrdinaryModelContentLocatorV1, ordinary_continuity_question_key_v1,
    ordinary_basis_semantics_v1, ordinary_cumulative_payload_digest_v1)
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d01_ordinary_origin_v3 import OrdinaryHeadCommitmentV3, validate_ordinary_initial_v3, validate_ordinary_adoption_v3
from .d01_production_operations_v1 import MissingProductionOriginalV1
from .d01_general_growth_v1 import AdoptCurrentGeneralGrowthRequestV1

REGISTER = "register_ordinary_cumulative_growth_policy_v1"
ASSESS = "assess_ordinary_continuity_v1"
ADOPT = "adopt_ordinary_deep_growth_v1"
OPERATION_KINDS = frozenset({REGISTER, ASSESS, ADOPT})
CONTINUITY_CONSUMERS = OPERATION_KINDS | {"adopt_growth", "adopt_general_growth_v1", "adopt_single_event_growth_v1"}
ORIGINAL_TYPES = {BASIS_KIND: OrdinaryContinuityBasisOriginalV1, POLICY_KIND: OrdinaryCumulativeGrowthPolicyV1,
    ASSESSMENT_KIND: OrdinaryContinuityAssessmentV1, DEEP_ADOPTION_KIND: OrdinaryDeepGrowthAdoptionV1}
_OWNERS = WeakKeyDictionary()
_OWNER_ISSUER = object()
_ISSUED_OWNERS = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class RegisterOrdinaryCumulativeGrowthPolicyRequestV1:
    policy: OrdinaryCumulativeGrowthPolicyV1
    def __post_init__(self):
        if type(self.policy) is not OrdinaryCumulativeGrowthPolicyV1:
            raise TypeError("ordinary policy installation requires the exact explicit Owner policy")


@dataclass(frozen=True, slots=True)
class AssessOrdinaryContinuityRequestV1:
    policy_ref: str
    growth_request: AdoptCurrentGeneralGrowthRequestV1
    phase: str
    interpretation_ref: str | None
    def __post_init__(self):
        from ..domains.d01.production_operations_v1 import require_locator_v1
        require_locator_v1(self.policy_ref, "ordinary policy")
        if type(self.growth_request) is not AdoptCurrentGeneralGrowthRequestV1 or self.phase not in {"ordinary_screen", "deep_review"}:
            raise TypeError("ordinary assessment retains the exact current General growth request and phase")
        if self.interpretation_ref is not None: require_locator_v1(self.interpretation_ref, "ordinary continuity cognition")


@dataclass(frozen=True, slots=True)
class AdoptOrdinaryDeepGrowthRequestV1:
    assessment_ref: str
    growth_request: AdoptCurrentGeneralGrowthRequestV1
    def __post_init__(self):
        from ..domains.d01.production_operations_v1 import require_locator_v1
        require_locator_v1(self.assessment_ref, "ordinary deep assessment")
        if type(self.growth_request) is not AdoptCurrentGeneralGrowthRequestV1:
            raise TypeError("ordinary deep adoption retains its exact General proposal and trials")


OPERATIONS = {REGISTER: (RegisterOrdinaryCumulativeGrowthPolicyRequestV1, "workbench.activate"),
    ASSESS: (AssessOrdinaryContinuityRequestV1, "workbench.activate"),
    ADOPT: (AdoptOrdinaryDeepGrowthRequestV1, "workbench.activate")}


def _actual_reader_v1(reader):
    from .current_method_learning_read_v3 import (_MethodLearningReadV3,
        require_actual_method_learning_attachment_owner_v3)
    if type(reader) is not _MethodLearningReadV3:
        raise ValueError("ordinary continuity requires its exact registered Source Work")
    if reader.operation_kind not in CONTINUITY_CONSUMERS:
        from .d07_ordinary_continuity_cognition_v1 import (ordinary_continuity_source_operation_v1,
            require_actual_ordinary_continuity_metadata_reader_v1)
        if not ordinary_continuity_source_operation_v1(reader.operation_kind):
            raise ValueError("ordinary continuity metadata escaped its finite registered consumers")
        require_actual_ordinary_continuity_metadata_reader_v1(reader)
    require_actual_method_learning_attachment_owner_v3(reader, db=reader.db)
    return reader


class _CurrentOrdinaryOriginOwnerV1:
    def __init__(self, issuer, reader):
        if issuer is not _OWNER_ISSUER: raise TypeError("actual ordinary continuity metadata issuer required")
        r = _actual_reader_v1(reader)
        self.reader, self.db, self.namespace, self.operation = r, r.db, r.namespace, r.operation
        self.origin_signer = r.graph._GraphCoordinator__d11_issuer._signer
        self.origin_history, self.origin_support_readsets, self.origin_columns = {}, {}, []
        self.columns, self.selected_columns = {}, set()
        self.fixed_rows, self.fixed_tasks, self.selected_fixed = {}, {}, set()
        self.graph_stamp, self.epochs, self.owner_binding = r.graph_stamp, r.authority_epochs, r.owner_binding
        self.history_result = None
        self.body_scope = None
        self.content = {}
        self.content_reserved = 0
        _ISSUED_OWNERS[self] = (r, r.operation, r.work, self.graph_stamp, self.epochs, self.owner_binding)
    def require_current_v1(self):
        r = _actual_reader_v1(self.reader)
        if (_ISSUED_OWNERS.get(self) != (r, r.operation, r.work, self.graph_stamp, self.epochs, self.owner_binding)
                or r.graph_stamp != self.graph_stamp or r.authority_epochs != self.epochs
                or r.owner_binding != self.owner_binding):
            raise ValueError("ordinary history lost its actual Work, Owner or metadata snapshot")
        r.require_current()
        return self
    @contextmanager
    def quantum_v3(self):
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        self.require_current_v1()
        with runtime_storage_quantum_v3(self.db) as meter:
            self.reader.require_current(meter=meter)
            yield meter


def is_current_ordinary_origin_owner_v1(owner):
    return type(owner) is _CurrentOrdinaryOriginOwnerV1 and owner in _ISSUED_OWNERS


def require_current_ordinary_origin_owner_v1(owner):
    if not is_current_ordinary_origin_owner_v1(owner):
        raise ValueError("ordinary history has no actual private metadata owner")
    return owner.require_current_v1()


def _owner_v1(db, namespace):
    from .current_method_learning_read_v3 import _method_active
    r = _method_active(db)
    if r is None or r.namespace != namespace:
        raise ValueError("ordinary continuity is outside its actual bound Source Work")
    _actual_reader_v1(r)
    owner = _OWNERS.get(r)
    if owner is None:
        owner = _CurrentOrdinaryOriginOwnerV1(_OWNER_ISSUER, r); _OWNERS[r] = owner
    return owner.require_current_v1()


def _column_identity_v1(table, column, key_columns, key, profile, cell_id, signed_header):
    return (table, column, tuple(key_columns), tuple(key), profile, cell_id, signed_header)


def read_current_ordinary_metadata_column_v1(owner, *, table, column, key_columns, key, profile,
        cell_id=None, signed_header=None):
    """Only the actual history recipe may select a bounded original column."""
    require_current_ordinary_origin_owner_v1(owner)
    identity = _column_identity_v1(table, column, key_columns, key, profile, cell_id, signed_header)
    table_columns = {"graph_role_init_receipts_v1": {"receipt_json"}, "graph_history": {"value"},
        "graph_events": {"reads", "epoch_reads", "revisions", "invalidated"},
        "graph_bundle_operations": {"receipt_json"},
        "graph_d01_production_inputs_v1": {"payload_json", "source_refs_json"},
        "graph_d07_execution_originals_v1": {"payload_json"},
        "graph_domain_production_originals_v1": {"original_payload_json", "receipt_json", "read_versions_json"}}
    if table not in table_columns or column not in table_columns[table]:
        raise ValueError("ordinary continuity metadata left its fixed original columns")
    if table == "graph_history":
        if (tuple(key_columns) != ("token", "revision") or NamespaceId.from_key(AtomKey.from_token(key[0])) != owner.namespace
                or type(key[1]) is not int or key[1] < 1):
            raise ValueError("ordinary history column has another exact namespace/version")
    elif tuple(key[:2]) != owner.namespace.as_tuple:
        raise ValueError("ordinary original column crosses its actual namespace")
    owner.selected_columns.add(identity)
    task = owner.columns.get(identity)
    if task is None or not task.complete:
        from .current_method_learning_read_v3 import _need_method_input
        _need_method_input(owner.reader, ("ordinary_cumulative_metadata", identity))
    return task.column


class _OrdinaryCumulativeMetadataTaskV1:
    def __init__(self, reader, identity):
        owner = _OWNERS.get(reader)
        if owner is None or identity not in owner.selected_columns:
            raise ValueError("ordinary metadata task has no real selected history column")
        require_current_ordinary_origin_owner_v1(owner)
        from .d01_ordinary_origin_read_v3 import OrdinaryOriginColumnV3
        self.owner, self.identity, self.complete = owner, identity, False
        table, column, key_columns, key, profile, cell_id, signed_header = identity
        self.column = OrdinaryOriginColumnV3(owner, table=table, column=column, key_columns=key_columns,
            key=key, profile=profile, cell_id=cell_id, signed_header=signed_header)
        owner.columns[identity] = self
    def advance(self, meter):
        require_current_ordinary_origin_owner_v1(self.owner)
        self.complete = self.column.advance(meter)
        if self.complete and self.column not in self.owner.origin_columns:
            self.owner.origin_columns.append(self.column)
        return self.complete


def create_current_ordinary_cumulative_metadata_task_v1(reader, identity):
    owner = _OWNERS.get(reader)
    if owner is None: raise ValueError("ordinary metadata issuer has no actual Work")
    if len(identity) == 5 and identity[0] == "fixed":
        task = owner.fixed_tasks.get(identity)
        return task if task is not None else _OrdinaryFixedMetadataTaskV1(owner, identity)
    task = owner.columns.get(identity)
    return task if task is not None else _OrdinaryCumulativeMetadataTaskV1(reader, identity)


def _fixed_v1(owner, table, columns, where, args):
    from .d01_ordinary_origin_read_v3 import _fixed
    return _fixed(owner, table, columns, where, args)


def _signed_metadata_v1(owner, ref, expected_kind):
    from .d01_production_operations_v1 import TABLE
    row = _fixed_v1(owner, TABLE, ("kind", "producing_operation_id", "payload_digest", "signature"),
        "bot=? AND persona=? AND original_ref=?", (*owner.namespace.as_tuple, ref))
    if row is None or row[0] != expected_kind:
        raise MissingProductionOriginalV1("actual_signed_ordinary_original:" + ref)
    profile = {POLICY_KIND: "ordinary_cumulative_policy", ASSESSMENT_KIND: "ordinary_continuity_assessment",
        DEEP_ADOPTION_KIND: "ordinary_deep_adoption"}[expected_kind]
    column = read_current_ordinary_metadata_column_v1(owner, table=TABLE, column="payload_json",
        key_columns=("bot", "persona", "original_ref"), key=(*owner.namespace.as_tuple, ref),
        profile=profile, signed_header=row)
    if column.semantic_digest != row[2] or not column.signature_verified:
        raise ValueError("ordinary original signature/full canonical EOF differs")
    original = ProductionOriginalRefV1("d01." + expected_kind, ref, row[2])
    bundle = _fixed_v1(owner, "graph_bundle_operations", ("digest", "commit_seq"),
        "bot=? AND persona=? AND operation_id=?", (*owner.namespace.as_tuple, row[1]))
    if bundle is None or type(bundle[1]) is not int or bundle[1] < 1:
        raise ValueError("ordinary signed original has no actual successful producing W01")
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(column.metadata, ORIGINAL_TYPES[expected_kind])
    _require_signed_ordinary_producer_v1(owner, ref, value, row)
    return value, original, row[1]


def read_current_ordinary_policy_metadata_v1(db, *, namespace, policy_ref=None):
    owner = _owner_v1(db, namespace)
    if policy_ref is not None: return _signed_metadata_v1(owner, policy_ref, POLICY_KIND)[:2]
    rows, cursor = [], ""
    while True:
        row = _fixed_v1(owner, "graph_d01_production_inputs_v1", ("original_ref",),
            "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
            (*namespace.as_tuple, POLICY_KIND, cursor))
        if row is None: break
        if len(rows) == 128: raise MissingProductionOriginalV1("complete_ordinary_policy_inventory_bound")
        cursor = row[0]; rows.append(_signed_metadata_v1(owner, cursor, POLICY_KIND)[:2])
    if not rows: raise MissingProductionOriginalV1("installed_ordinary_cumulative_growth_policy")
    if len({policy.policy_id for policy, _ in rows}) != 1:
        raise ValueError("ordinary cumulative policy installation has conflicting global policy identities")
    version = max(policy.policy_version for policy, _ in rows)
    latest = tuple(value for value in rows if value[0].policy_version == version)
    if len(latest) != 1: raise ValueError("ordinary cumulative policy latest version is ambiguous")
    return latest[0]


@dataclass(frozen=True, slots=True)
class _OrdinaryCumulativeHistoryV1:
    anchor: OrdinaryContinuityAnchorV1
    current: OrdinaryHeadCommitmentV3
    transitions: tuple
    coverage: OrdinaryHistoryCoverageV1
    support_source_refs: tuple[str, ...]
    owner: object


_DEDICATED_TRANSITIONS = frozenset({"migrate_semantic_identity_v3", "adopt_current_method_strategy_v1",
    "adopt_current_conditioned_self_v1", "rollback_current_conditioned_strategy_v1", "adopt_growth"})


def _unchanged_dedicated_transition_v1(owner, before, after, members, operation_kind):
    """Authenticate the actual producer and every same-event write; retain no claim."""
    from .d01_ordinary_origin_read_v3 import _column, _event, _versions
    from .domain_production_originals_v1 import _receipt
    if operation_kind not in _DEDICATED_TRANSITIONS or changed_ordinary_blocks_v1(before.blocks, after.blocks):
        raise MissingProductionOriginalV1("actual_unchanged_ordinary_dedicated_transition")
    op = members[0].event_id; ns = owner.namespace
    h = _fixed_v1(owner, "graph_domain_production_originals_v1",
        ("domain", "operation_kind", "original_digest", "bundle_digest", "receipt_digest"),
        "bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, op))
    if h is None or h[:2] != ("d01", operation_kind):
        raise ValueError("ordinary carry transition has another actual D01 producer")
    from .domain_production_registry_v1 import installed_operation_v1
    if installed_operation_v1(operation_kind).domain != "d01":
        raise ValueError("ordinary carry is not an installed dedicated D01 producer")
    key = (*ns.as_tuple, op)
    pc = _column(owner, "graph_domain_production_originals_v1", "original_payload_json", ("bot", "persona", "operation_id"), key, "ordinary_unchanged_producer")
    p = pc.metadata
    receipt = _receipt(_column(owner, "graph_domain_production_originals_v1", "receipt_json",
        ("bot", "persona", "operation_id"), key, "activation").metadata)
    reads = _column(owner, "graph_domain_production_originals_v1", "read_versions_json",
        ("bot", "persona", "operation_id"), key, "activation").metadata
    bundle = _fixed_v1(owner, "graph_bundle_operations", ("digest", "activity_id", "effect_id", "commit_seq"),
        "bot=? AND persona=? AND operation_id=?", key)
    if (pc.semantic_digest != h[2] or canonical_digest(receipt) != h[4]
            or p["schema"] != "d01.current-" + operation_kind + ".v1" or p["coverage"] != "complete"
            or p["missing_inputs"] or p["continuation_ref"] is not None
            or receipt.status != "committed" or receipt.operation_id != op
            or (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq) != bundle
            or h[3] != receipt.operation_digest or _versions(p["read_versions"]) != receipt.read_versions
            or tuple(GraphVersion(AtomKey.from_token(k), rev) for k, rev in reads) != receipt.read_versions):
        raise ValueError("ordinary carry original lost its actual successful W01 receipt")
    identity = p["identity"]
    event = Event(Scope(*ns.as_tuple, identity["activity_id"]), op, p["now_utc"], "domain_bundle", {"bundle_digest": h[3]})
    actual_event = _event(owner, event)
    if (actual_event.recorded_digest != event.digest or actual_event.reads != receipt.read_versions
            or actual_event.revisions != receipt.write_versions):
        raise ValueError("ordinary carry original differs from its actual full Graph event")
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    writes = tuple(p["writes"])
    expected = {v.key: v.revision for v in receipt.write_versions}
    if len(writes) != len(expected): raise ValueError("ordinary carry typed writes are incomplete")
    for index, write in enumerate(writes):
        wkey = decode_typed_production_value_v1(write["key"], AtomKey)
        if wkey not in expected: raise ValueError("ordinary carry contains a foreign write")
        member, column = _dedicated_metadata_member_v1(owner, wkey, expected[wkey], event)
        if (member.value_digest != pc.commitments[("writes", index, "value")]
                or member.event_scope != event.scope or member.event_id != op):
            raise ValueError("ordinary carry actual write/history/full commitment differs")
    if (after.plan_ref not in receipt.write_versions or after.activation_ref not in receipt.write_versions
            or before.plan_ref not in receipt.read_versions or before.activation_ref not in receipt.read_versions):
        raise ValueError("ordinary carry did not CAS both protected predecessor and successor heads")
    return (before, after, operation_kind, h[2], h[4], actual_event.recorded_digest)


def read_current_ordinary_cumulative_history_v1(db, *, namespace):
    owner = _owner_v1(db, namespace)
    from .persona_growth_birth_v1 import current_persona_birth_control_v1
    from .d01_ordinary_origin_read_v3 import _initial, _head, _adoption
    control = current_persona_birth_control_v1(db, namespace=namespace)
    if control.semantic_version > 1024:
        raise MissingProductionOriginalV1("complete_ordinary_history_exceeds_existing_head_bound")
    initial = _initial(owner); previous = validate_ordinary_initial_v3(initial)
    anchor = OrdinaryContinuityAnchorV1("initial", ProductionOriginalRefV1("d01.role_initialization.v1",
        initial.receipt["operation_id"], initial.receipt_digest), previous, initial.receipt_digest)
    transitions, roots = [], []
    for revision in range(2, control.semantic_version + 1):
        following, members = _head(owner, revision, revision)
        operation = _fixed_v1(owner, "graph_domain_production_originals_v1", ("operation_kind",),
            "bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, members[0].event_id))
        if operation is None: raise MissingProductionOriginalV1("actual_ordinary_history_transition_original")
        kind = operation[0]
        if kind in {"adopt_general_growth_v1", "adopt_single_event_growth_v1"} or kind == "adopt_growth" and changed_ordinary_blocks_v1(previous.blocks, following.blocks):
            adopted = _adoption(owner, previous, following, members)
            selections, _ = validate_ordinary_adoption_v3(previous, adopted)
            roots.extend(v.source.key.token for v in selections)
            transition = (previous, following, kind, adopted.original_digest,
                canonical_digest(adopted.receipt), adopted.event.recorded_digest)
        elif kind == ADOPT:
            deep, original, producing_op = _signed_metadata_v1(owner, "ordinary-deep:" + members[0].event_id, DEEP_ADOPTION_KIND)
            if (producing_op != members[0].event_id or deep.base_head != previous or deep.successor_head != following
                    or deep.prior_anchor != anchor):
                raise ValueError("ordinary deep anchor lost its actual previous chain or signed successor")
            total, count, digest = ordinary_history_metrics_v1(anchor.head, previous, tuple(transitions))
            if (deep.history.transition_count, deep.history.ordinary_change_count, deep.history.chain_digest) != (total, count, digest):
                raise ValueError("ordinary deep anchor skipped a preceding actual transition")
            marker_key = ordinary_deep_anchor_key_v1(namespace, producing_op)
            from .d01_ordinary_origin_read_v3 import _history
            marker_member, marker = _history(owner, marker_key, 1, "ordinary_deep_anchor")
            if (marker_member.event_id != producing_op or marker.metadata["operation_id"] != producing_op
                    or marker.metadata["assessment_original"]["original_ref"] != deep.assessment_original.original_ref
                    or marker_key not in {v.key for v in deep.activation_receipt.write_versions}):
                raise ValueError("ordinary deep signed anchor has no actual same-W01 marker")
            anchor = OrdinaryContinuityAnchorV1("deep", original, following, canonical_digest(deep.activation_receipt))
            from .d01_ordinary_origin_read_v3 import _column
            deep_roots = _column(owner, "graph_d01_production_inputs_v1", "source_refs_json",
                ("bot", "persona", "original_ref"), (*namespace.as_tuple, original.original_ref), "activation")
            roots.extend(deep_roots.metadata); transitions = []
            previous = following; continue
        else:
            transition = _unchanged_dedicated_transition_v1(owner, previous, following, members, kind)
        transitions.append(transition); previous = following
    current, _ = _head(owner, control.semantic_version, control.activation_version.revision)
    if (current != previous or current.head_id != control.head_id or current.plan_ref != control.persona_head_version):
        raise ValueError("ordinary cumulative history did not reach its actual protected current Persona head")
    total, count, digest = ordinary_history_metrics_v1(anchor.head, current, tuple(transitions))
    coverage = OrdinaryHistoryCoverageV1(anchor.head.head_id, current.head_id, total, count, digest,
        (current.plan_ref, current.activation_ref), (owner.graph_stamp[1],))
    result = _OrdinaryCumulativeHistoryV1(anchor, current, tuple(transitions), coverage, tuple(dict.fromkeys(roots)), owner)
    owner.history_result = result
    return result


def ordinary_deep_anchor_key_v1(namespace, operation_id):
    return AtomKey(Owner("persona", *namespace.as_tuple), ANCHOR_TYPE, "ordinary-deep:" + operation_id)


def release_current_ordinary_cumulative_metadata_v1(reader):
    owner = _OWNERS.pop(reader, None)
    if owner is None: return
    _ISSUED_OWNERS.pop(owner, None)
    owner.columns.clear(); owner.selected_columns.clear(); owner.origin_columns.clear()
    owner.fixed_rows.clear(); owner.fixed_tasks.clear(); owner.selected_fixed.clear()
    owner.origin_history.clear(); owner.origin_support_readsets.clear(); owner.history_result = None
    owner.content.clear(); owner.body_scope = None
    for identity, entry in tuple(_STAGE_BINDINGS.items()):
        if entry[1] is owner: _STAGE_BINDINGS.pop(identity, None)
    for proof in tuple(_QUALIFICATIONS):
        if proof.owner is owner: _QUALIFICATIONS.pop(proof, None)
    for value in tuple(_PREPARED_BASES):
        if value.owner is owner:
            _PREPARED_BASES.pop(value, None)
            value.content = {}
    for value in tuple(_BASIS_LOCATORS):
        if value.owner is owner:
            _BASIS_LOCATORS.pop(value, None)
            value.basis_projection = {}


def require_current_ordinary_selected_body_v1(reader, table, key):
    """Exact Method point hook, after this history's complete Source ALL."""
    owner = _OWNERS.get(reader)
    if owner is None or owner.body_scope is None:
        return False
    owner.require_current_v1()
    frame, history, roots = owner.body_scope
    if table != "graph_history" or len(key) != 2:
        return False
    token, revision = key
    item = owner.origin_history.get((token, revision))
    if item is None or item[0].ref.key.type_name != "d01.persona_plan.v1":
        return False
    from .d01_production_operations_v1 import CurrentDomainReadV1
    read = CurrentDomainReadV1(frame); read.check(owner.db)
    if roots: read.source_family(owner.db, roots, purpose="consolidation")
    return True


def create_current_ordinary_model_body_stream_v1(owner, *, key, ensure_ascii, reserve):
    """The sole claim-retaining history profile, issued after exact Source ALL."""
    if not require_current_ordinary_selected_body_v1(owner.reader, "graph_history", key):
        raise ValueError("ordinary model Body stream has no exact qualified selected head")
    from .d01_ordinary_origin_stream_v3 import OrdinaryOriginMetadataStreamV3
    from ..domains.d01.ordinary_cumulative_growth_v1 import ordinary_block_v1
    frame, history, _ = owner.body_scope
    heads = (history.anchor.head, history.current, *(h for row in history.transitions for h in row[:2]))
    selected = next(h for h in heads if (h.plan_ref.key.token, h.plan_ref.revision) == tuple(key))
    indices = frozenset(i for i, block in enumerate(selected.blocks) if ordinary_block_v1(block))
    class _OrdinaryModelBodyStreamV1(OrdinaryOriginMetadataStreamV3):
        def _retains(self, path):
            if not path: return True
            if path[0] == "blocks":
                if len(path) <= 2: return True
                return path[2] in self._BLOCK_FIELDS or path[2] == "claim" and path[1] in indices
            return path[0] in {"plan_id", "namespace", "version", "authored"}
    return _OrdinaryModelBodyStreamV1(profile="plan", ensure_ascii=ensure_ascii, reserve=reserve)


def read_current_ordinary_history_body_v1(read, history):
    """Read only ordinary claims; other blocks retain their measured boundaries."""
    if type(history) is not _OrdinaryCumulativeHistoryV1:
        raise TypeError("actual private ordinary history required")
    owner = require_current_ordinary_origin_owner_v1(history.owner)
    read.check(owner.db)
    if (read.frame.envelope.authority.namespace != owner.namespace
            or owner.history_result is not history):
        raise ValueError("ordinary claim read crossed its selected same-Work history")
    roots = history.support_source_refs
    if roots: read.source_family(owner.db, roots, purpose="consolidation")
    owner.body_scope = (read.frame, history, roots)
    heads = (history.anchor.head, history.current, *(h for row in history.transitions for h in row[:2]))
    from .d01_ordinary_origin_read_v3 import _column
    from .source_correction_read_v3 import _heap
    from ..domains.d01.ordinary_cumulative_growth_v1 import ordinary_block_v1
    for head in heads:
        selected = (head.plan_ref.key.token, head.plan_ref.revision)
        if selected in owner.content: continue
        if not require_current_ordinary_selected_body_v1(owner.reader, "graph_history", selected):
            raise ValueError("ordinary claim has no selected Source-qualified actual head")
        measured = owner.origin_history.get(selected)
        if measured is None:
            raise ValueError("ordinary claim history has no actual measured immutable member")
        column = _column(owner, "graph_history", "value", ("token", "revision"), selected,
            "ordinary_model_plan_body", cell_id=measured[1].cell.cell_id if measured[1].cell is not None else None)
        if column.semantic_digest != head.plan_value_digest:
            raise ValueError("ordinary model selected Body differs from its whole sealed plan EOF")
        column.reserve(_heap(column.metadata))
        value = {**column.metadata, "blocks": [dict(item) for item in column.metadata["blocks"]]}
        for index, block in enumerate(head.blocks):
            item = value["blocks"][index]
            if (item["block_id"], item["kind"], item["plasticity"]) != (block.block_id, block.kind, block.plasticity):
                raise ValueError("ordinary model Body structure differs from its measured selection")
            if ordinary_block_v1(block):
                if canonical_digest(item["claim"]) != block.claim_digest:
                    raise ValueError("ordinary model claim differs from its exact source-qualified commitment")
            elif "claim" in item:
                raise ValueError("ordinary model stream retained an unselected dedicated claim")
            item["claim_protocol"], item["claim_digest"] = block.claim_protocol, block.claim_digest
        value["values_digest"] = head.values_digest
        owner.content[selected] = value
        retained = _heap(owner.content)
        if retained > owner.content_reserved:
            owner.operation.retain(retained - owner.content_reserved)
            owner.content_reserved = retained
    def plan(head):
        return owner.content[(head.plan_ref.key.token, head.plan_ref.revision)]
    return {"anchor": plan(history.anchor.head), "current": plan(history.current),
        "history": tuple({"before": plan(before), "after": plan(after), "operation_kind": kind,
            "original_digest": original, "receipt_digest": receipt, "event_digest": event}
            for before, after, kind, original, receipt, event in history.transitions)}


_BASIS_ISSUER = object()
_PREPARED_BASES = WeakKeyDictionary()


class _PreparedOrdinaryContinuityBasisV1:
    def __init__(self, issuer, owner, frame, growth_request, candidate, basis, content, prior_c3_call_ids,
                 *, basis_original=None, committed=False, phase="ordinary_screen", trigger_assessment_original=None):
        if issuer is not _BASIS_ISSUER: raise TypeError("actual ordinary continuity basis issuer required")
        self.owner, self.frame, self.growth_request, self.candidate = owner, frame, growth_request, candidate
        self.basis, self.content, self.prior_c3_call_ids = basis, content, tuple(prior_c3_call_ids)
        self.basis_original = basis_original or ProductionOriginalRefV1("d01." + BASIS_KIND,
            "ordinary-basis:" + canonical_digest(ordinary_basis_semantics_v1(basis))[:48], ordinary_cumulative_payload_digest_v1(basis))
        self.committed, self.phase = committed, phase
        self.trigger_assessment_original = trigger_assessment_original
        self.current_read_versions = frame.envelope.version_guard.read_versions
        self.valid_until_utc = min(frame.envelope.deadline_utc, basis.original_deadline_utc)
        self.question_key = ordinary_continuity_question_key_v1(self.basis_original, basis, phase, trigger_assessment_original)
        _PREPARED_BASES[self] = (owner, frame, growth_request, candidate, basis, self.basis_original,
            owner.reader.operation, owner.graph_stamp, owner.epochs, committed, phase, trigger_assessment_original, canonical_digest(content))
    def require_current_v1(self, *, committed=False):
        owner = require_current_ordinary_origin_owner_v1(self.owner)
        expected = (owner, self.frame, self.growth_request, self.candidate, self.basis, self.basis_original,
            owner.reader.operation, owner.graph_stamp, owner.epochs, self.committed, self.phase, self.trigger_assessment_original, canonical_digest(self.content))
        if (_PREPARED_BASES.get(self) != expected or committed and not self.committed
                or canonical_digest(self.candidate.typed_writes) != self.basis.candidate_write_digest):
            raise ValueError("ordinary continuity basis left its exact actual issuing Work")
        from .d01_production_operations_v1 import CurrentDomainReadV1
        read = CurrentDomainReadV1(self.frame); read.check(owner.db)
        if not _ordinary_now_v1(owner) < self.valid_until_utc:
            raise MissingProductionOriginalV1("ordinary_basis_original_fixed_deadline_elapsed")
        roots = tuple(dict.fromkeys((*self.basis.support_source_refs, *self.basis.context_source_refs)))
        if roots: read.source_family(owner.db, roots, purpose="consolidation")
        return self


def _current_counter_binding_v1(db, read, proposal, counter_original):
    from .current_method_learning_read_v3 import read_bound_current_general_owner_type_metadata_v1
    ns = read.frame.envelope.authority.namespace
    rows, complete = read_bound_current_general_owner_type_metadata_v1(db, namespace=ns,
        type_id="d07.current_interpretation.v1", limit=129)
    pages = tuple(p for p in read.frame.query_coverage if p.type_id == "d07.current_interpretation.v1")
    if (not complete or len(rows) > 128 or len(pages) != 1 or not pages[0].complete
            or pages[0].row_versions != tuple(GraphVersion(v.key, v.revision) for v in rows)
            or pages[0].epoch.revision != read.frame.snapshot.epochs[0].revision):
        raise MissingProductionOriginalV1("complete_current_ordinary_continuity_counter_domain")
    scope = "d01.growth:" + proposal.target_block + ":" + proposal.change_kind
    members, body, roots, qualification = [], [], [], "qualified"
    for metadata in rows:
        value = metadata.value
        if not metadata.valid or value["question_key"] != scope or value["current"] is not True: continue
        selected_roots = tuple(value["source_refs"])
        read.source_family(db, selected_roots, purpose="consolidation")
        atom = read.head(db, metadata.key, required=True)
        if (atom.revision != metadata.revision or canonical_digest(atom.value) != metadata.payload_digest
                or tuple(atom.value["source_refs"]) != selected_roots):
            raise ValueError("ordinary counter Body differs from its Source-qualified metadata selection")
        read.original(atom.key.token, digest=canonical_digest(atom.value))
        raw = atom.value
        if raw["stance"] == "oppose" and raw["evidence_status"] == "supported": qualification = "opposition"
        elif qualification != "opposition" and (raw["meaningful_unknowns"] or raw["evidence_status"] in {"insufficient", "conflicted"}):
            qualification = "unknown"
        version = GraphVersion(atom.key, atom.revision)
        members.append((version, canonical_digest(raw), raw["current"], raw["stance"], raw["evidence_status"], tuple(raw["meaningful_unknowns"])))
        body.append((atom.key.token, raw)); roots.extend(raw["source_refs"])
    binding = OrdinaryCounterScopeBindingV1("d07.current_interpretation.v1", scope, read.frame.snapshot.epochs[0], True,
        tuple(members), counter_original, qualification)
    return binding, tuple(body), tuple(dict.fromkeys(roots))


def _block_commitments_v1(plan, base):
    from .d01_ordinary_origin_v3 import OrdinaryBlockCommitmentV3
    from ..domains.d01.ordinary_cumulative_growth_v1 import ordinary_block_v1
    if tuple(v["block_id"] for v in plan["blocks"]) != tuple(v.block_id for v in base.blocks):
        raise ValueError("ordinary candidate changed its complete block structure")
    result = []
    for raw, old in zip(plan["blocks"], base.blocks, strict=True):
        if (raw["kind"], raw["plasticity"]) != (old.kind, old.plasticity):
            raise ValueError("ordinary candidate changed block classification")
        digest = canonical_digest(raw["claim"])
        if not ordinary_block_v1(old) and digest != old.claim_digest:
            raise ValueError("ordinary proposal changed a dedicated or nonplastic block")
        if digest != old.claim_digest and any(marker in raw["claim"] for marker in (
                "d01.semantic-identity-revision.v3", "d01.conditioned-capability-revision.v1",
                "d01.conditioned-strategy-revision.v1", "d01.method-policy.v1")):
            raise ValueError("ordinary proposal cannot install a dedicated claim protocol")
        result.append(OrdinaryBlockCommitmentV3(old.block_id, old.kind, old.plasticity, digest, old.claim_protocol))
    return tuple(result)


def _content_manifest_v1(history, content, candidate_plan, proposal_original, counter_body, trials, support_atoms, target_block):
    from ..runtime_contracts import canonical_serialize
    from ..domains.d01.ordinary_cumulative_growth_v1 import ordinary_block_v1
    entries = []
    def add(role, ref, original_digest, path, value):
        wire = canonical_serialize(value).encode("utf-8")
        entries.append(OrdinaryModelContentLocatorV1(role, ref, original_digest, path, canonical_digest(value), len(wire)))
    heads = (("anchor", history.anchor.head), ("current", history.current),
        *(("history", head) for row in history.transitions for head in row[:2]))
    seen = set()
    for role, head in heads:
        if (role, head.plan_ref) in seen: continue
        seen.add((role, head.plan_ref))
        plan = history.owner.content[(head.plan_ref.key.token, head.plan_ref.revision)]
        for index, block in enumerate(head.blocks):
            for field in ("block_id", "kind", "plasticity"):
                add(role + "_structure", head.plan_ref.key.token, head.plan_value_digest,
                    ("blocks", index, field), plan["blocks"][index][field])
            if ordinary_block_v1(block):
                add(role, head.plan_ref.key.token, head.plan_value_digest, ("blocks", index, "claim"), plan["blocks"][index]["claim"])
    for _, after, _, original_digest, _, _ in history.transitions:
        member = history.owner.origin_history[(after.plan_ref.key.token, after.plan_ref.revision)][0]
        add("history_proof", "d01-current:" + original_digest[:48], original_digest,
            ("identity", "operation_id"), member.event_id)
    add("candidate", proposal_original.original_ref, proposal_original.original_digest,
        ("replacement_claim",), next(v["claim"] for v in candidate_plan["blocks"] if v["block_id"] == target_block))
    for ref, value in counter_body: add("counter", ref, canonical_digest(value), (), value)
    for original, value in trials: add("trial", original.original_ref, original.original_digest, (), value)
    for atom in support_atoms: add("support", atom.key.token, canonical_digest(atom.value), ("text",), atom.value["text"])
    return tuple(entries)


def read_current_ordinary_continuity_basis_v1(readers, db, frame, growth_request, *, policy_ref, phase):
    """Freeze mechanical data from actual originals, before any new cognition."""
    from .d01_production_operations_v1 import CurrentDomainReadV1, InstalledD01ProductionReadersV1
    from .d01_general_growth_v1 import read_current_general_growth_facts_v1
    from ..domains.d01 import PersonaDomain
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..graph_types import GraphSnapshot
    if type(readers) is not InstalledD01ProductionReadersV1 or phase not in {"ordinary_screen", "deep_review"}:
        raise TypeError("ordinary continuity basis requires the actual D01 readers and closed phase")
    read = CurrentDomainReadV1(frame); read.check(db)
    owner = _owner_v1(db, frame.envelope.authority.namespace)
    policy, policy_original = read_current_ordinary_policy_metadata_v1(db, namespace=owner.namespace, policy_ref=policy_ref)
    current_policy = read_current_ordinary_policy_metadata_v1(db, namespace=owner.namespace)
    if current_policy[1] != policy_original or not _ordinary_now_v1(owner) < policy.valid_until_utc:
        raise MissingProductionOriginalV1("current_installed_ordinary_cumulative_policy")
    history = read_current_ordinary_cumulative_history_v1(db, namespace=owner.namespace)
    inputs, _ = read_current_general_growth_facts_v1(readers, db, frame, growth_request)
    snapshot = GraphSnapshot(tuple(v for v in frame.snapshot.atoms
        if not (v.key.type_name == "d01.growth_contribution.v1" and v.revision == 0)),
        frame.snapshot.epochs, frame.snapshot.ingress_receipts, frame.snapshot.scene_proofs)
    candidate = PersonaDomain().mechanical_growth_candidate_v1(snapshot, namespace=owner.namespace,
        current_guard=readers.owner_guard, proposal=inputs.proposal, source_ids=inputs.source_ids)
    from .current_full_persona_writer_v1 import (
        require_bound_current_full_persona_writer_v1, preserve_full_persona_writer_candidate_v1)
    outer_request=owner.reader.request
    writer,_=require_bound_current_full_persona_writer_v1(db,frame=frame,request=outer_request)
    candidate=preserve_full_persona_writer_candidate_v1(writer,candidate,frame=frame,request=outer_request)
    plan_write = next(w for w in candidate.typed_writes if w.key.type_name == "d01.persona_plan.v1")
    blocks = _block_commitments_v1(plan_write.value, history.current)
    changed = changed_ordinary_blocks_v1(history.current.blocks, blocks)
    from ..domains.d01.ordinary_cumulative_growth_v1 import ordinary_block_v1
    target = next((v for v in history.current.blocks if v.block_id == inputs.proposal.target_block), None)
    if target is None or not ordinary_block_v1(target) or len(changed) > 1 or changed and changed[0] != target.block_id:
        raise ValueError("ordinary continuity basis requires its exact ordinary target")
    proposal_raw, proposal_original = readers._read(db, read, growth_request.growth_proposal_ref, "growth_proposal")
    _, counter_original = readers._read(db, read, growth_request.counterevidence_query_ref, "growth_counterevidence")
    wrapper_raw, wrapper_original = readers._read(db, read, growth_request.general_growth_intent_ref, "general_growth_intent_v1")
    counter, counter_body, counter_roots = _current_counter_binding_v1(db, read, inputs.proposal, counter_original)
    trials = tuple((original, value) for ref in growth_request.trial_original_refs
        for value, original in (readers._read(db, read, ref, "general_growth_trial_v1"),))
    supports = tuple(proposal_raw["evidence_source_refs"])
    contexts = tuple(ref for ref in dict.fromkeys((*wrapper_raw["context_source_refs"], *history.support_source_refs, *counter_roots,
        *(ref for _, value in trials for ref in value["evidence_source_refs"]))) if ref not in supports)
    roots = tuple(dict.fromkeys((*supports, *contexts)))
    if len(roots) > frame.limits.max_source_roots:
        raise MissingProductionOriginalV1("source_root_budget_exceeded:" + str(len(roots)) + "/" + str(frame.limits.max_source_roots))
    if roots: read.source_family(db, roots, purpose="consolidation")
    content = read_current_ordinary_history_body_v1(read, history)
    base_content = content["current"]
    candidate_content = {**base_content, "version": plan_write.value["version"], "authored": plan_write.value["authored"],
        "blocks": [dict(v) for v in base_content["blocks"]]}
    for index, block in enumerate(blocks):
        if block.block_id in changed:
            candidate_content["blocks"][index].update(claim=plan_write.value["blocks"][index]["claim"], claim_digest=block.claim_digest)
    content = {**content, "candidate": candidate_content, "counter": counter_body,
        "trials": tuple((original.original_ref, value) for original, value in trials)}
    support_atoms = tuple(read.head(db, ref, required=True) for ref in supports)
    manifest = _content_manifest_v1(history, content, plan_write.value, proposal_original, counter_body, trials, support_atoms, target.block_id)
    from .d07_ordinary_continuity_cognition_v1 import read_actual_ordinary_proposal_cause_v1
    cause = read_actual_ordinary_proposal_cause_v1(readers, db, read, proposal_original=proposal_original,
        general_growth_intent_original=wrapper_original)
    cause.require_v1(readers, read)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_general_growth_v1 import GeneralGrowthIntentOriginalV1
    wrapper = decode_typed_production_value_v1(wrapper_raw, GeneralGrowthIntentOriginalV1)
    source_versions = tuple(v for v in frame.envelope.version_guard.read_versions if v.key.type_name in {
        "memory.source", "memory.access", "d06.source_correction_head.v1"})
    basis = OrdinaryContinuityBasisOriginalV1(owner.namespace, policy_original, history.anchor, history.coverage,
        history.current, proposal_original, blocks, canonical_digest(candidate.typed_writes),
        history.coverage.ordinary_change_count + bool(changed), source_versions, supports, contexts,
        tuple(dict.fromkeys((*wrapper.context_original_refs, *cause.prior_cognition_originals, wrapper_original))), counter,
        tuple(original for original, _ in trials), cause.prior_cognition_originals, cause.causal_original,
        cause.causal_operation_id, cause.causal_receipt_digest, cause.original_parent_budget_lease_ref,
        cause.original_parent_grant_digest, min(cause.original_deadline_utc, policy.valid_until_utc),
        manifest, canonical_digest(manifest))
    if phase != "ordinary_screen":
        raise ValueError("deep basis is read from its committed candidate and actual deep-required trigger")
    return _PreparedOrdinaryContinuityBasisV1(_BASIS_ISSUER, owner, frame, growth_request, candidate,
        basis, content, cause.prior_c3_call_ids)


def read_current_ordinary_d07_metadata_v1(db, *, namespace, issuer, kind, original_ref):
    """Whole-original signed metadata, without thawing any Prepared/Frozen Body."""
    owner = _owner_v1(db, namespace)
    if issuer is not owner.reader.graph._GraphCoordinator__d11_issuer or kind not in {"adopted", "prepared", "semantic_question"}:
        raise ValueError("ordinary D07 metadata has another signer or closed original family")
    from .d07_execution_v1 import TABLE, SIGN_KIND
    header = _fixed_v1(owner, TABLE, ("payload_digest", "signature"),
        "bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, original_ref))
    if header is None: return None
    profile = "ordinary_d07_" + {"adopted": "adopted", "prepared": "prepared", "semantic_question": "question"}[kind]
    column = read_current_ordinary_metadata_column_v1(owner, table=TABLE, column="payload_json",
        key_columns=("bot", "persona", "kind", "original_ref"),
        key=(*namespace.as_tuple, kind, original_ref), profile=profile)
    if column.semantic_digest != header[0]:
        raise ValueError("ordinary D07 metadata whole canonical EOF differs from its actual signed digest")
    from ..runtime_contracts import canonical_serialize
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, original_ref, header[0])), header[1])
    return column.metadata, ProductionOriginalRefV1("d07." + kind, original_ref, header[0])


def locate_current_ordinary_d07_prepared_v1(db, *, namespace, prepared_digest):
    owner = _owner_v1(db, namespace)
    found, cursor = [], ""
    for _ in range(2):
        row = _fixed_v1(owner, "graph_d07_execution_originals_v1", ("original_ref",),
            "bot=? AND persona=? AND kind='prepared' AND payload_digest=? AND original_ref>? ORDER BY original_ref",
            (*namespace.as_tuple, prepared_digest, cursor))
        if row is None: break
        found.append(row[0]); cursor = row[0]
    if len(found) != 1:
        raise MissingProductionOriginalV1("unique_actual_ordinary_continuity_prepared")
    return found[0]


def ordinary_cumulative_metadata_retains_path_v1(profile, path):
    """Closed origin projections. None means the existing profile owns it."""
    if profile in {"ordinary_cumulative_policy", "ordinary_continuity_assessment", "ordinary_deep_adoption", "ordinary_deep_anchor", "ordinary_basis_body"}:
        return True
    if profile in {"ordinary_d07_adopted", "ordinary_d07_prepared", "ordinary_d07_question"}:
        from .d07_ordinary_continuity_cognition_v1 import ordinary_continuity_metadata_retains_path_v1
        kind = {"ordinary_d07_adopted": "adopted", "ordinary_d07_prepared": "prepared", "ordinary_d07_question": "semantic_question"}[profile]
        return ordinary_continuity_metadata_retains_path_v1(kind, path)
    if profile == "ordinary_dedicated_member": return not path
    if profile == "ordinary_unchanged_producer":
        if not path: return True
        if path[0] == "writes": return len(path) < 3 or path[2] in {"key", "dependencies"}
        return path[0] in {"schema", "namespace", "identity", "coverage", "missing_inputs", "continuation_ref", "read_versions", "now_utc"}
    if profile not in {"ordinary_basis_locator", "ordinary_cumulative_producer"}:
        return None
    if not path: return True
    basis_path = path
    if profile == "ordinary_cumulative_producer":
        if path[0] == "provenance":
            if len(path) == 1: return True
            if path[1] not in {"ordinary_policy", "ordinary_basis", "ordinary_basis_original", "ordinary_assessment",
                    "ordinary_assessment_original", "ordinary_deep_preparation", "ordinary_trigger_assessment_original",
                    "ordinary_state", "growth_request", "basis_new"}:
                return False
            if path[1] == "ordinary_basis": basis_path = path[2:]
        if path[0] not in {"schema", "namespace", "identity", "authority", "owner_guard", "now_utc", "coverage",
                "missing_inputs", "continuation_ref", "request", "read_versions", "observed_originals", "provenance", "writes"}:
            return False
        if "values" in path or path[-1] in {"claim", "replacement_claim"}: return False
    if basis_path and basis_path[:2] == ("counter_scope", "members"):
        return False
    if profile == "ordinary_basis_locator":
        from dataclasses import fields
        return path[0] in {f.name for f in fields(OrdinaryContinuityBasisOriginalV1)}
    return True


def ordinary_cumulative_metadata_commits_path_v1(profile, path):
    if profile == "ordinary_dedicated_member": return not path
    if profile == "ordinary_unchanged_producer":
        return not path or len(path) == 3 and path[0] == "writes" and path[2] == "value"
    if profile not in {"ordinary_basis_locator", "ordinary_cumulative_producer"}:
        return None
    return (not path or profile == "ordinary_cumulative_producer" and (
        len(path) == 2 and path[0] == "provenance" and path[1] in {
            "ordinary_policy", "ordinary_basis", "ordinary_assessment", "ordinary_deep_preparation"}
        or len(path) == 3 and path[0] == "writes" and path[2] == "value"))


def _require_signed_ordinary_producer_v1(owner, original_ref, value, signed_header):
    """Authenticate immutable input bytes against their actual W01 producer."""
    from .d01_ordinary_origin_read_v3 import _column, _event
    from .domain_production_originals_v1 import _receipt
    from dataclasses import asdict
    kind, op, digest, _ = signed_header
    expected_kind = {POLICY_KIND: REGISTER, BASIS_KIND: ASSESS, ASSESSMENT_KIND: ASSESS, DEEP_ADOPTION_KIND: ADOPT}[kind]
    ns = owner.namespace; key = (*ns.as_tuple, op)
    header = _fixed_v1(owner, "graph_domain_production_originals_v1",
        ("domain", "operation_kind", "original_digest", "bundle_digest", "receipt_digest"),
        "bot=? AND persona=? AND operation_id=?", key)
    if header is None or header[:2] != ("d01", expected_kind):
        raise ValueError("ordinary signed original has another actual registered producer")
    pc = _column(owner, "graph_domain_production_originals_v1", "original_payload_json",
        ("bot", "persona", "operation_id"), key, "ordinary_cumulative_producer")
    payload = pc.metadata
    receipt = _receipt(_column(owner, "graph_domain_production_originals_v1", "receipt_json",
        ("bot", "persona", "operation_id"), key, "activation").metadata)
    row_reads = _column(owner, "graph_domain_production_originals_v1", "read_versions_json",
        ("bot", "persona", "operation_id"), key, "activation").metadata
    bundle = _fixed_v1(owner, "graph_bundle_operations", ("digest", "activity_id", "effect_id", "commit_seq"),
        "bot=? AND persona=? AND operation_id=?", key)
    from .d01_ordinary_origin_read_v3 import _versions
    if (pc.semantic_digest != header[2] or canonical_digest(receipt) != header[4]
            or payload["schema"] != "d01.current-" + expected_kind + ".v1"
            or payload["namespace"] != asdict(ns) or payload["identity"]["operation_id"] != op
            or payload["coverage"] != "complete" or payload["missing_inputs"] or payload["continuation_ref"] is not None
            or receipt.status != "committed" or receipt.operation_id != op or receipt.operation_digest != header[3]
            or bundle != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq)
            or _versions(payload["read_versions"]) != receipt.read_versions
            or tuple(GraphVersion(AtomKey.from_token(k), rev) for k, rev in row_reads) != receipt.read_versions):
        raise ValueError("ordinary signed input lost its actual complete producer and receipt")
    event = Event(Scope(*ns.as_tuple, receipt.activity_id), op, payload["now_utc"], "domain_bundle", {"bundle_digest": header[3]})
    actual_event = _event(owner, event)
    if (actual_event.recorded_digest != event.digest or actual_event.reads != receipt.read_versions
            or actual_event.revisions != receipt.write_versions):
        raise ValueError("ordinary signed input differs from its actual Graph event")
    provenance = payload["provenance"]
    if kind != DEEP_ADOPTION_KIND:
        name = {POLICY_KIND: "ordinary_policy", BASIS_KIND: "ordinary_basis", ASSESSMENT_KIND: "ordinary_assessment"}[kind]
        if pc.commitments.get(("provenance", name)) != digest:
            raise ValueError("ordinary signed input differs from the actual producer's exact typed subtree")
    else:
        if (value.activation_operation_id != op or value.activation_receipt != receipt
                or value.activation_event_digest != actual_event.recorded_digest
                or ordinary_deep_anchor_key_v1(ns, op) not in {v.key for v in receipt.write_versions}):
            raise ValueError("ordinary deep signed adoption lost its actual same-W01 marker/receipt")
        from ..domains.d01.production_operations_v1 import plain_v1
        preparation = plain_v1(value)
        for name in ("schema", "activation_receipt", "activation_event_digest"): preparation.pop(name)
        if preparation != provenance["ordinary_deep_preparation"]:
            raise ValueError("ordinary deep signed adoption differs from its exact actual pre-CAS preparation")
    roots_column = _column(owner, "graph_d01_production_inputs_v1", "source_refs_json",
        ("bot", "persona", "original_ref"), (*ns.as_tuple, original_ref), "activation")
    basis = provenance.get("ordinary_basis")
    roots = () if kind == POLICY_KIND else tuple(sorted(set((*basis["support_source_refs"], *basis["context_source_refs"]))))
    if tuple(roots_column.metadata) != roots:
        raise ValueError("ordinary signed input Source dependency header differs from its real producer")
    return payload, receipt, actual_event


_BASIS_LOCATORS = WeakKeyDictionary()


class _OrdinaryBasisLocatorV1:
    def __init__(self, issuer, owner, original, column, growth_request, operation_id):
        if issuer is not _BASIS_ISSUER: raise TypeError("actual ordinary basis locator issuer required")
        self.owner, self.basis_original, self.column = owner, original, column
        self.growth_request, self.producing_operation_id = growth_request, operation_id
        value = column.metadata
        self.namespace = owner.namespace
        self.support_source_refs = tuple(value["support_source_refs"])
        self.context_source_refs = tuple(value["context_source_refs"])
        self.source_versions = tuple(_decode_metadata_v1(v, GraphVersion) for v in value["source_versions"])
        self.basis_projection = value
        _BASIS_LOCATORS[self] = (owner, original, column, growth_request, operation_id, column.semantic_digest)
    def require_current_v1(self):
        require_current_ordinary_origin_owner_v1(self.owner)
        if (_BASIS_LOCATORS.get(self) != (self.owner, self.basis_original, self.column,
                self.growth_request, self.producing_operation_id, self.column.semantic_digest)
                or self.column.semantic_digest != self.basis_original.original_digest):
            raise ValueError("ordinary basis locator left its actual signed full-EOF metadata")
        return self
    def question_key_v1(self, phase, trigger_assessment_original):
        self.require_current_v1()
        from ..domains.d01.ordinary_cumulative_growth_v1 import _ordinary_continuity_question_key_fields_v1
        if phase == "deep_review":
            value, actual, _ = _signed_metadata_v1(self.owner, trigger_assessment_original.original_ref, ASSESSMENT_KIND)
            if (actual.kind, actual.original_ref, actual.original_digest) != (trigger_assessment_original.kind,
                    trigger_assessment_original.original_ref, trigger_assessment_original.original_digest):
                raise ValueError("ordinary deep metadata trigger differs from its actual signed original")
            screen = _ordinary_continuity_question_key_fields_v1(self.basis_original,
                self.column.semantic_digest, "ordinary_screen", None)
            if value.question_key != screen or value.decision != "deep_required":
                raise ValueError("ordinary deep question has no actual matching committed proposal")
        return _ordinary_continuity_question_key_fields_v1(self.basis_original,
            self.column.semantic_digest, phase, trigger_assessment_original)


def _decode_metadata_v1(value, cls):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(value, cls)


def read_current_ordinary_continuity_basis_metadata_v1(db, *, namespace, basis_original):
    """A Source locator, not a typed Basis or permission to decode its prose."""
    if type(basis_original) is not ProductionOriginalRefV1 or basis_original.kind != "d01." + BASIS_KIND:
        raise TypeError("exact ordinary basis original locator required")
    owner = _owner_v1(db, namespace)
    header = _fixed_v1(owner, "graph_d01_production_inputs_v1",
        ("kind", "producing_operation_id", "payload_digest", "signature"),
        "bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, basis_original.original_ref))
    if header is None or header[0] != BASIS_KIND or header[2] != basis_original.original_digest:
        raise MissingProductionOriginalV1("actual_committed_ordinary_continuity_basis")
    column = read_current_ordinary_metadata_column_v1(owner, table="graph_d01_production_inputs_v1",
        column="payload_json", key_columns=("bot", "persona", "original_ref"),
        key=(*namespace.as_tuple, basis_original.original_ref), profile="ordinary_basis_locator", signed_header=header)
    if not column.signature_verified or column.semantic_digest != header[2]:
        raise ValueError("ordinary basis locator lacks its real signature and complete original EOF")
    payload, _, _ = _require_signed_ordinary_producer_v1(owner, basis_original.original_ref, None, header)
    request = _decode_metadata_v1(payload["request"], AssessOrdinaryContinuityRequestV1)
    if request.interpretation_ref is not None or request.phase != "ordinary_screen":
        raise ValueError("ordinary mechanical basis was not issued by its actual initial freeze operation")
    from dataclasses import asdict
    if column.metadata["namespace"] != asdict(namespace):
        raise ValueError("ordinary basis actual signed namespace differs")
    roots = tuple(dict.fromkeys((*column.metadata["support_source_refs"], *column.metadata["context_source_refs"])))
    if len(roots) > 32: raise MissingProductionOriginalV1("source_root_budget_exceeded:" + str(len(roots)) + "/32")
    for ref in roots:
        key = AtomKey.from_token(ref)
        if key.type_name != "memory.source" or NamespaceId.from_key(key) != namespace:
            raise ValueError("ordinary basis Source locator crosses namespace or family")
    return _OrdinaryBasisLocatorV1(_BASIS_ISSUER, owner, basis_original, column, request.growth_request, header[1])


def read_plan_current_ordinary_continuity_basis_v1(db, *, namespace, basis_original):
    locator = read_current_ordinary_continuity_basis_metadata_v1(db, namespace=namespace, basis_original=basis_original)
    from .d01_general_growth_v1 import read_plan_adopt_current_general_growth_v1
    from .d01_production_operations_v1 import production_read_plan_v1
    history = read_current_ordinary_cumulative_history_v1(db, namespace=namespace)
    plan = read_plan_adopt_current_general_growth_v1(db, namespace=namespace, request=locator.growth_request,
        issuer=locator.owner.reader.graph._GraphCoordinator__d11_issuer)
    roots = tuple(dict.fromkeys((*plan.source_roots, *locator.support_source_refs,
        *locator.context_source_refs, *history.support_source_refs)))
    if len(roots) > 32: raise MissingProductionOriginalV1("source_root_budget_exceeded:" + str(len(roots)) + "/32")
    return production_read_plan_v1(plan.fixed_type_ids, tuple(dict.fromkeys((*plan.exact_keys,
        history.current.plan_ref.key, history.current.activation_ref.key))), roots,
        tuple(dict.fromkeys((*plan.required_original_refs, basis_original.original_ref,
            locator.basis_projection["policy_original"]["original_ref"]))))


def _require_current_committed_basis_v1(readers, db, read, *, basis_original, phase, trigger_assessment_original):
    locator = read_current_ordinary_continuity_basis_metadata_v1(db,
        namespace=read.frame.envelope.authority.namespace, basis_original=basis_original)
    roots = tuple(dict.fromkeys((*locator.support_source_refs, *locator.context_source_refs)))
    if roots: read.source_family(db, roots, purpose="consolidation")
    raw, actual = readers._read(db, read, basis_original.original_ref, BASIS_KIND)
    if (actual.kind, actual.original_ref, actual.original_digest) != (basis_original.kind, basis_original.original_ref, basis_original.original_digest):
        raise ValueError("ordinary full Basis differs from its actual signed locator")
    stored = _decode_metadata_v1(raw, OrdinaryContinuityBasisOriginalV1)
    current = read_current_ordinary_continuity_basis_v1(readers, db, read.frame, locator.growth_request,
        policy_ref=stored.policy_original.original_ref, phase="ordinary_screen")
    if ordinary_basis_semantics_v1(stored) != ordinary_basis_semantics_v1(current.basis):
        raise MissingProductionOriginalV1("stale_ordinary_continuity_basis")
    locator.question_key_v1(phase, trigger_assessment_original)
    result = _PreparedOrdinaryContinuityBasisV1(_BASIS_ISSUER, current.owner, read.frame,
        locator.growth_request, current.candidate, stored, current.content, current.prior_c3_call_ids,
        basis_original=actual, committed=True, phase=phase, trigger_assessment_original=trigger_assessment_original)
    result.require_current_v1(committed=True)
    return result


def require_current_ordinary_continuity_basis_for_cognition_v1(readers, db, read, *, basis_original, phase, trigger_assessment_original):
    result = _require_current_committed_basis_v1(readers, db, read, basis_original=basis_original,
        phase=phase, trigger_assessment_original=trigger_assessment_original)
    from .d07_ordinary_continuity_cognition_v1 import read_actual_ordinary_proposal_cause_v1
    _, general = readers._read(db, read, result.growth_request.general_growth_intent_ref, "general_growth_intent_v1")
    cause = read_actual_ordinary_proposal_cause_v1(readers, db, read,
        proposal_original=result.basis.candidate_proposal_original, general_growth_intent_original=general)
    cause.require_v1(readers, read)
    result.causal_parent_executions = cause.causal_parent_executions
    result.review_step = 1
    result.causal_depth = 1 + max(v[2] for v in result.causal_parent_executions)
    if phase == "deep_review":
        raw, _ = readers._read(db, read, trigger_assessment_original.original_ref, ASSESSMENT_KIND)
        assessment = _decode_metadata_v1(raw, OrdinaryContinuityAssessmentV1)
        if assessment.reason == "core_shift":
            from .d07_ordinary_continuity_cognition_v1 import read_actual_ordinary_assessment_cause_v1
            screen = read_actual_ordinary_assessment_cause_v1(readers, db, read, assessment_original=trigger_assessment_original)
            result.causal_parent_executions = tuple(dict.fromkeys((*result.causal_parent_executions, *screen.causal_parent_executions)))
            result.prior_c3_call_ids = tuple(dict.fromkeys((*result.prior_c3_call_ids, *screen.prior_c3_call_ids)))
            result.review_step = 2
            result.causal_depth = 1 + max(v[2] for v in result.causal_parent_executions)
    return result


_QUALIFICATION_ISSUER = object()
_QUALIFICATIONS = WeakKeyDictionary()
_STAGE_BINDINGS = {}


def _assessment_original_v1(value):
    return ProductionOriginalRefV1("d01." + ASSESSMENT_KIND,
        "ordinary-assessment:" + ordinary_cumulative_payload_digest_v1(value)[:48], ordinary_cumulative_payload_digest_v1(value))


def _assessment_v1(prepared, decision, reason, cognition_originals=(), *, valid_until_utc=None):
    b = prepared.basis
    return OrdinaryContinuityAssessmentV1(b.policy_original, b.anchor, b.history, b.base_head,
        b.candidate_proposal_original, b.candidate_blocks, b.candidate_ordinary_change_count,
        prepared.phase, prepared.question_key, tuple(cognition_originals), b.support_source_refs,
        b.context_source_refs, b.counter_scope.counter_query_original,
        tuple(row[0] for row in b.counter_scope.members), b.trial_originals, decision, reason,
        min(b.original_deadline_utc, valid_until_utc if valid_until_utc is not None else b.original_deadline_utc))


def _assess_cognition_v1(readers, db, read, prepared, interpretation_ref):
    from .d07_ordinary_continuity_cognition_v1 import require_actual_ordinary_continuity_cognition_v1
    prepared.require_current_v1(committed=True)
    fact = require_actual_ordinary_continuity_cognition_v1(readers, db, read, phase=prepared.phase,
        question_key=prepared.question_key, proposal_original=prepared.basis.candidate_proposal_original,
        excluded_call_ids=prepared.prior_c3_call_ids, interpretation_ref=interpretation_ref)
    fact.require_v1(readers, read)
    b = prepared.basis
    if not set(fact.source_refs).issubset(set((*b.support_source_refs, *b.context_source_refs))):
        raise ValueError("ordinary continuity cognition cited a Source outside its actual frozen basis")
    if fact.decision == "unknown" or not b.counter_scope.coverage_complete or b.counter_scope.qualification == "unknown":
        decision, reason = "unknown", "incomplete"
    elif fact.decision == "opposition" or b.counter_scope.qualification == "opposition":
        decision, reason = "rejected", "opposition"
    elif prepared.phase == "ordinary_screen" and fact.decision == "core_shift":
        decision, reason = "deep_required", "core_shift"
    elif fact.decision == "preserved":
        decision, reason = ("ordinary_allowed" if prepared.phase == "ordinary_screen" else "deep_accepted"), "preserved"
    else:
        raise ValueError("ordinary continuity C3 returned another closed phase decision")
    policy, _ = read_current_ordinary_policy_metadata_v1(db, namespace=b.namespace, policy_ref=b.policy_original.original_ref)
    if prepared.phase == "ordinary_screen" and b.candidate_ordinary_change_count >= policy.escalate_at_change_count:
        decision, reason = "deep_required", "count_threshold"
    return _assessment_v1(prepared, decision, reason, fact.originals, valid_until_utc=fact.valid_until_utc)


def _matching_assessments_v1(owner, prepared):
    """Complete signed metadata census; callers never choose a passing boolean."""
    rows, cursor = [], ""
    while True:
        row = _fixed_v1(owner, "graph_d01_production_inputs_v1", ("original_ref",),
            "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
            (*owner.namespace.as_tuple, ASSESSMENT_KIND, cursor))
        if row is None: break
        if len(rows) == 128: raise MissingProductionOriginalV1("complete_ordinary_assessment_inventory_bound")
        cursor = row[0]
        value, original, _ = _signed_metadata_v1(owner, cursor, ASSESSMENT_KIND)
        rows.append((value, original))
    b = prepared.basis
    return tuple((value, original) for value, original in rows
        if value.policy_original == b.policy_original and value.anchor == b.anchor
        and value.base_head == b.base_head and value.candidate_proposal_original == b.candidate_proposal_original
        and value.candidate_blocks == b.candidate_blocks
        and value.candidate_ordinary_change_count == b.candidate_ordinary_change_count
        and value.history.chain_digest == b.history.chain_digest)


class CurrentOrdinaryContinuityQualificationV1:
    """An actual same-Work qualification; constructing an assessment never issues it."""
    def __init__(self, issuer, prepared, assessment, assessment_original, request, mode):
        if issuer is not _QUALIFICATION_ISSUER:
            raise TypeError("actual ordinary continuity qualification issuer required")
        self.prepared, self.assessment, self.assessment_original = prepared, assessment, assessment_original
        self.request, self.mode = request, mode
        self.frame, self.owner = prepared.frame, prepared.owner
        _QUALIFICATIONS[self] = (prepared, assessment, assessment_original, request, mode,
            self.frame, self.owner.reader.operation, canonical_digest(prepared.candidate.typed_writes))
    def require_candidate_v1(self, frame, request, candidate):
        p = self.prepared; p.require_current_v1(committed=True)
        entry = (p, self.assessment, self.assessment_original, self.request, self.mode,
            self.frame, self.owner.reader.operation, canonical_digest(candidate.typed_writes))
        if (_QUALIFICATIONS.get(self) != entry or frame is not self.frame
                or candidate != p.candidate or not _same_declared_growth_request_v1(self.request, request)
                or not _ordinary_now_v1(self.owner) < min(self.assessment.valid_until_utc, p.valid_until_utc)):
            raise ValueError("ordinary growth left its actual candidate/Owner/Work/deadline qualification")
        expected = "ordinary_allowed" if self.mode == "ordinary" else "deep_accepted"
        if self.assessment.decision != expected:
            raise MissingProductionOriginalV1("ordinary_continuity_requires_" + expected)
        return self


def qualify_current_ordinary_continuity_v1(readers, db, read, request, candidate, *, mode):
    if mode not in {"ordinary", "deep"}:
        raise ValueError("ordinary continuity has only ordinary or deep adoption")
    from .d01_production_operations_v1 import InstalledD01ProductionReadersV1, CurrentDomainReadV1
    if type(readers) is not InstalledD01ProductionReadersV1 or type(read) is not CurrentDomainReadV1:
        raise TypeError("ordinary continuity requires actual installed D01 readers and frame")
    read.check(db)
    growth_request = request.growth_request if type(request) is AdoptOrdinaryDeepGrowthRequestV1 else request
    growth_request = _general_request_for_ordinary_v1(_owner_v1(db, read.frame.envelope.authority.namespace), growth_request)
    fresh = read_current_ordinary_continuity_basis_v1(readers, db, read.frame, growth_request,
        policy_ref=None, phase="ordinary_screen")
    if candidate != fresh.candidate:
        raise ValueError("ordinary continuity candidate differs from actual mechanical current inputs")
    header = _fixed_v1(fresh.owner, "graph_d01_production_inputs_v1", ("kind", "payload_digest"),
        "bot=? AND persona=? AND original_ref=?", (*fresh.owner.namespace.as_tuple, fresh.basis_original.original_ref))
    if header is None or header[0] != BASIS_KIND:
        raise MissingProductionOriginalV1("durable_ordinary_continuity_basis_and_assessment")
    actual_basis = ProductionOriginalRefV1("d01." + BASIS_KIND, fresh.basis_original.original_ref, header[1])
    if mode == "deep":
        assessment, original, _ = _signed_metadata_v1(fresh.owner, request.assessment_ref, ASSESSMENT_KIND)
        payload, _, _ = _require_signed_ordinary_producer_v1(fresh.owner, original.original_ref, assessment,
            _fixed_v1(fresh.owner, "graph_d01_production_inputs_v1",
                ("kind", "producing_operation_id", "payload_digest", "signature"),
                "bot=? AND persona=? AND original_ref=?", (*fresh.owner.namespace.as_tuple, original.original_ref)))
        basis_ref = _decode_metadata_v1(payload["provenance"]["ordinary_basis_original"], ProductionOriginalRefV1)
        trigger = _decode_metadata_v1(payload["provenance"]["ordinary_trigger_assessment_original"], ProductionOriginalRefV1)
        if basis_ref != actual_basis or assessment.phase != "deep_review":
            raise ValueError("deep adoption assessment has another actual committed basis/phase")
        prepared = _require_current_committed_basis_v1(readers, db, read, basis_original=actual_basis,
            phase="deep_review", trigger_assessment_original=trigger)
        if len(changed_ordinary_blocks_v1(prepared.basis.base_head.blocks, prepared.basis.candidate_blocks)) != 1:
            raise ValueError("only one actual ordinary claim change can establish a new deep anchor")
        # The General facts reader above independently retains its >=2-family/trial rules.
        matches = ((assessment, original),)
    else:
        prepared = _require_current_committed_basis_v1(readers, db, read, basis_original=actual_basis,
            phase="ordinary_screen", trigger_assessment_original=None)
        matches = tuple((a, o) for a, o in _matching_assessments_v1(fresh.owner, prepared)
            if a.phase == "ordinary_screen" and a.question_key == prepared.question_key)
    eligible = tuple((a, o) for a, o in matches
        if a.decision == ("ordinary_allowed" if mode == "ordinary" else "deep_accepted")
        and _ordinary_now_v1(fresh.owner) < a.valid_until_utc)
    if len(eligible) != 1:
        raise MissingProductionOriginalV1("unique_current_committed_ordinary_continuity_assessment")
    assessment, original = eligible[0]
    header = _fixed_v1(fresh.owner, "graph_d01_production_inputs_v1",
        ("kind", "producing_operation_id", "payload_digest", "signature"),
        "bot=? AND persona=? AND original_ref=?", (*fresh.owner.namespace.as_tuple, original.original_ref))
    payload, _, _ = _require_signed_ordinary_producer_v1(fresh.owner, original.original_ref, assessment, header)
    producing_request = _decode_metadata_v1(payload["request"], AssessOrdinaryContinuityRequestV1)
    if producing_request.interpretation_ref is None or producing_request.growth_request != growth_request:
        raise ValueError("an adoptable ordinary assessment requires its actual matching current C3 producer")
    fresh_assessment = _assess_cognition_v1(readers, db, read, prepared, producing_request.interpretation_ref)
    from dataclasses import replace
    if replace(fresh_assessment, history=assessment.history, valid_until_utc=assessment.valid_until_utc) != assessment:
        raise MissingProductionOriginalV1("stale_actual_ordinary_continuity_cognition")
    policy, _ = read_current_ordinary_policy_metadata_v1(db, namespace=fresh.owner.namespace)
    from ..domains.d01.ordinary_cumulative_growth_v1 import evaluate_ordinary_continuity_v1
    evaluate_ordinary_continuity_v1(policy, assessment, transitions=fresh.owner.history_result.transitions)
    proof = CurrentOrdinaryContinuityQualificationV1(_QUALIFICATION_ISSUER, prepared, assessment, original, request, mode)
    return proof.require_candidate_v1(read.frame, request, candidate)


def require_ordinary_continuity_candidate_v1(qualification, frame, request, candidate):
    if type(qualification) is not CurrentOrdinaryContinuityQualificationV1:
        raise MissingProductionOriginalV1("actual_current_ordinary_continuity_qualification")
    return qualification.require_candidate_v1(frame, request, candidate)


def _bind_stage_v1(stage, owner, frame, request, qualification=None):
    _STAGE_BINDINGS[id(stage)] = (stage, owner, frame, request, qualification, stage.original_digest)
    return stage


def require_actual_ordinary_cumulative_stage_v1(stage, db, *, frame=None):
    entry = _STAGE_BINDINGS.get(id(stage))
    if entry is None or entry[0] is not stage or entry[5] != stage.original_digest:
        raise ValueError("ordinary cumulative stage was not issued by its actual qualified Source Work")
    _, owner, actual_frame, request, qualification, _ = entry
    owner.require_current_v1()
    if db is not owner.db or frame is not None and frame is not actual_frame:
        raise ValueError("ordinary cumulative stage changed its actual database/frame")
    from .d01_production_operations_v1 import CurrentDomainReadV1
    CurrentDomainReadV1(actual_frame).check(db)
    if qualification is not None:
        qualification.require_candidate_v1(actual_frame, request, qualification.prepared.candidate)
    return verify_ordinary_cumulative_stage_v1(stage)


def _reuse_committed_basis_v1(readers, db, read, fresh):
    row = _fixed_v1(fresh.owner, "graph_d01_production_inputs_v1", ("kind", "payload_digest"),
        "bot=? AND persona=? AND original_ref=?", (*fresh.owner.namespace.as_tuple, fresh.basis_original.original_ref))
    if row is None: return fresh, True
    if row[0] != BASIS_KIND: raise ValueError("ordinary basis identity is already another signed input")
    actual = ProductionOriginalRefV1("d01." + BASIS_KIND, fresh.basis_original.original_ref, row[1])
    return _require_current_committed_basis_v1(readers, db, read, basis_original=actual,
        phase="ordinary_screen", trigger_assessment_original=None), False


def stage_ordinary_cumulative_growth_v1(db, *, frame, request, installed_readers):
    from .d01_production_operations_v1 import CurrentDomainReadV1, InstalledD01ProductionReadersV1, waiting_stage_v1
    from ..domains.d01.production_operations_v1 import stage_result_v1
    if type(installed_readers) is not InstalledD01ProductionReadersV1:
        raise TypeError("actual installed D01 cumulative readers required")
    kind = next((k for k, (cls, _) in OPERATIONS.items() if type(request) is cls), None)
    owner = _owner_v1(db, frame.envelope.authority.namespace)
    if kind is None or owner.reader.operation_kind != kind or owner.reader.request != request:
        raise ValueError("ordinary cumulative operation changed its actual typed Owner command")
    read = CurrentDomainReadV1(frame); read.check(db)
    try:
        if kind == REGISTER:
            policy = request.policy
            if not _ordinary_now_v1(owner) < policy.valid_until_utc:
                raise MissingProductionOriginalV1("ordinary_policy_original_deadline_elapsed")
            rows, cursor = [], ""
            while True:
                row = _fixed_v1(owner, "graph_d01_production_inputs_v1", ("original_ref",),
                    "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
                    (*owner.namespace.as_tuple, POLICY_KIND, cursor))
                if row is None: break
                if len(rows) == 128: raise MissingProductionOriginalV1("complete_ordinary_policy_inventory_bound")
                cursor = row[0]; rows.append(_signed_metadata_v1(owner, cursor, POLICY_KIND)[0])
            if rows and (any(v.policy_id != policy.policy_id for v in rows)
                    or policy.policy_version != max(v.policy_version for v in rows) + 1):
                raise ValueError("ordinary policy replacement must retain its identity and next explicit version")
            if not rows and policy.policy_version != 1:
                raise ValueError("first ordinary cumulative policy must be explicit version one")
            stage = stage_result_v1(frame, "d01", kind, request, provenance={"ordinary_policy": policy})
            return _bind_stage_v1(stage, owner, frame, request)
        if kind == ADOPT:
            return _stage_deep_growth_v1(db, frame, request, installed_readers, read, owner)
        if request.interpretation_ref is None:
            if request.phase != "ordinary_screen":
                raise ValueError("mechanical basis freeze precedes only its ordinary screen")
            prepared = read_current_ordinary_continuity_basis_v1(installed_readers, db, frame,
                request.growth_request, policy_ref=request.policy_ref, phase=request.phase)
            prepared, basis_new = _reuse_committed_basis_v1(installed_readers, db, read, prepared)
            policy, _ = read_current_ordinary_policy_metadata_v1(db, namespace=owner.namespace, policy_ref=request.policy_ref)
            assessment = (_assessment_v1(prepared, "deep_required", "count_threshold")
                if prepared.basis.candidate_ordinary_change_count >= policy.escalate_at_change_count else None)
            state = "awaiting_deep_review" if assessment else "awaiting_screen"
            trigger = None
        else:
            from .d07_ordinary_continuity_cognition_v1 import read_ordinary_continuity_interpretation_metadata_v1
            metadata = read_ordinary_continuity_interpretation_metadata_v1(db, namespace=owner.namespace,
                interpretation_ref=request.interpretation_ref, issuer=installed_readers.issuer)
            if metadata.phase != request.phase:
                raise ValueError("ordinary final assessment changed the actual cognition phase")
            prepared = require_current_ordinary_continuity_basis_for_cognition_v1(installed_readers, db, read,
                basis_original=metadata.basis_original, phase=metadata.phase,
                trigger_assessment_original=metadata.trigger_assessment_original)
            if prepared.basis.policy_original.original_ref != request.policy_ref or prepared.growth_request != request.growth_request:
                raise ValueError("ordinary final assessment changed its actual policy or declared candidate")
            assessment = _assess_cognition_v1(installed_readers, db, read, prepared, request.interpretation_ref)
            basis_new, trigger, state = False, metadata.trigger_assessment_original, assessment.decision
        provenance = {"ordinary_basis": prepared.basis, "ordinary_basis_original": prepared.basis_original,
            "growth_request": request.growth_request, "basis_new": basis_new, "ordinary_state": state}
        if assessment is not None:
            provenance.update(ordinary_assessment=assessment, ordinary_assessment_original=_assessment_original_v1(assessment))
        if trigger is not None: provenance["ordinary_trigger_assessment_original"] = trigger
        event = "ordinary_continuity_deep_required" if assessment and assessment.decision == "deep_required" else (
            "ordinary_continuity_basis_available_for_screen" if assessment is None else "ordinary_continuity_assessment_available")
        stage = stage_result_v1(frame, "d01", kind, request, provenance=provenance, receiver_events=(("d01", event),))
        return _bind_stage_v1(stage, owner, frame, request)
    except MissingProductionOriginalV1 as missing:
        return _bind_stage_v1(waiting_stage_v1(frame, "d01", kind, request, missing), owner, frame, request)



def _same_declared_growth_request_v1(original, current):
    from ..domains.d01.production_operations_v1 import AdoptCurrentGrowthRequestV1
    growth = original.growth_request if type(original) is AdoptOrdinaryDeepGrowthRequestV1 else original
    if current == original: return True
    if type(current) is AdoptCurrentGrowthRequestV1:
        return current == AdoptCurrentGrowthRequestV1(growth.growth_proposal_ref, growth.trigger_original_ref,
            growth.trial_original_refs, growth.counterevidence_query_ref)
    return False


def _candidate_successor_v1(prepared):
    from ..domains.d01 import PersonaActivation
    b, writes = prepared.basis, prepared.candidate.typed_writes
    plan = next(w for w in writes if w.key.type_name == "d01.persona_plan.v1")
    activation = next(w for w in writes if w.key.type_name == "d01.persona_activation.v1")
    value = _decode_metadata_v1(activation.value, PersonaActivation)
    return OrdinaryHeadCommitmentV3(b.namespace, plan.value["plan_id"], plan.value["version"],
        plan.value["authored"], GraphVersion(plan.key, b.base_head.plan_ref.revision + 1), canonical_digest(plan.value),
        GraphVersion(activation.key, b.base_head.activation_ref.revision + 1), canonical_digest(activation.value),
        value, b.candidate_blocks, canonical_digest(plan.value["values"]))


def _stage_deep_growth_v1(db, frame, request, readers, read, owner):
    from dataclasses import replace
    from .d01_general_growth_v1 import read_current_general_growth_facts_v1
    from ..domains.d01.production_operations_v1 import (AdoptCurrentGrowthRequestV1,
        compile_adopt_current_growth_v1, stage_result_v1, plain_v1)
    from ..domains.d01 import PersonaDomain
    from ..domains.d01.ordinary_cumulative_growth_v1 import OrdinaryDeepGrowthAnchorV1
    from ..graph_types import GraphSnapshot, GraphWrite
    inputs, general = read_current_general_growth_facts_v1(readers, db, frame, request.growth_request)
    snapshot = GraphSnapshot(tuple(v for v in frame.snapshot.atoms
        if not (v.key.type_name == "d01.growth_contribution.v1" and v.revision == 0)),
        frame.snapshot.epochs, frame.snapshot.ingress_receipts, frame.snapshot.scene_proofs)
    candidate = PersonaDomain().mechanical_growth_candidate_v1(snapshot, namespace=owner.namespace,
        current_guard=readers.owner_guard, proposal=inputs.proposal, source_ids=inputs.source_ids)
    from .current_full_persona_writer_v1 import (
        require_bound_current_full_persona_writer_v1, preserve_full_persona_writer_candidate_v1,
        require_full_persona_writer_stage_v1)
    writer,_=require_bound_current_full_persona_writer_v1(db,frame=frame,request=request)
    candidate=preserve_full_persona_writer_candidate_v1(writer,candidate,frame=frame,request=request)
    qualification = qualify_current_ordinary_continuity_v1(readers, db, read, request, candidate, mode="deep")
    inputs = replace(inputs, ordinary_continuity_qualification=qualification)
    r = request.growth_request
    ordinary_request = AdoptCurrentGrowthRequestV1(r.growth_proposal_ref, r.trigger_original_ref,
        r.trial_original_refs, r.counterevidence_query_ref)
    old_stage=compile_adopt_current_growth_v1(frame,ordinary_request,inputs,
        writer_qualification=writer,writer_request=request)
    old_stage=require_full_persona_writer_stage_v1(db,frame=frame,request=request,stage=old_stage)
    writes = tuple(w for proposal in old_stage.proposals for w in proposal.typed_writes)
    if writes != candidate.typed_writes:
        raise ValueError("deep adoption pure compiler changed its fully qualified actual candidate")
    prepared = qualification.prepared; b = prepared.basis
    successor = _candidate_successor_v1(prepared)
    marker_key = ordinary_deep_anchor_key_v1(owner.namespace, frame.envelope.identity.operation_id)
    if read.head(db, marker_key).revision != 0:
        raise ValueError("deep anchor operation already has a current marker")
    roots = tuple(dict.fromkeys((*b.support_source_refs, *b.context_source_refs)))
    marker = OrdinaryDeepGrowthAnchorV1(owner.namespace, frame.envelope.identity.operation_id,
        prepared.basis_original, qualification.assessment_original, b.policy_original, b.base_head.head_id,
        successor.head_id, roots)
    preparation = {"policy_original": b.policy_original, "prior_anchor": b.anchor, "history": b.history,
        "proposal_original": b.candidate_proposal_original, "assessment_original": qualification.assessment_original,
        "base_head": b.base_head, "successor_head": successor,
        "changed_block_ids": changed_ordinary_blocks_v1(b.base_head.blocks, b.candidate_blocks),
        "support_source_refs": b.support_source_refs, "trial_originals": b.trial_originals,
        "counter_query_original": b.counter_scope.counter_query_original,
        "activation_operation_id": frame.envelope.identity.operation_id}
    from ..domains.d01.ordinary_cumulative_growth_v1 import OrdinaryDeepGrowthPreparationV1
    preparation = OrdinaryDeepGrowthPreparationV1(**preparation)
    writes += (GraphWrite(marker_key, plain_v1(marker), tuple(AtomKey.from_token(ref) for ref in roots)),)
    stage = stage_result_v1(frame, "d01", ADOPT, request, writes=writes,
        provenance={"ordinary_basis": b, "ordinary_basis_original": prepared.basis_original,
            "ordinary_assessment": qualification.assessment, "ordinary_assessment_original": qualification.assessment_original,
            "ordinary_trigger_assessment_original": prepared.trigger_assessment_original,
            "ordinary_deep_preparation": preparation, "ordinary_deep_anchor": marker,
            "growth": candidate, "general_growth": general, "growth_request": request.growth_request},
        contribution_keys=tuple(k for proposal in old_stage.proposals for k in proposal.contribution_keys),
        receiver_events=(("d08", "persona_growth_requires_commitment_reevaluation"),
            ("d10", "persona_growth_requires_life_reevaluation")), costs=old_stage.paid_cost_originals,
        proposal_schema="d01.proposal.v1", proposal_hash=PersonaDomain().descriptor.request_schema_hash)
    return _bind_stage_v1(stage, owner, frame, request, qualification)


def provenance_types_ordinary_cumulative_v1(kind):
    from ..domains.d01 import GrowthAdoptionCandidate
    from ..domains.d01.ordinary_cumulative_growth_v1 import OrdinaryDeepGrowthAnchorV1, OrdinaryDeepGrowthPreparationV1
    if kind not in OPERATION_KINDS: raise ValueError("unregistered ordinary cumulative provenance")
    if kind == REGISTER: return {"ordinary_policy": OrdinaryCumulativeGrowthPolicyV1}
    fields = {"ordinary_basis": OrdinaryContinuityBasisOriginalV1,
        "ordinary_basis_original": ProductionOriginalRefV1, "growth_request": AdoptCurrentGeneralGrowthRequestV1}
    if kind == ASSESS:
        fields.update(basis_new=bool, ordinary_state=str,
            ordinary_assessment=OrdinaryContinuityAssessmentV1, ordinary_assessment_original=ProductionOriginalRefV1,
            ordinary_trigger_assessment_original=ProductionOriginalRefV1)
    else:
        fields.update(ordinary_assessment=OrdinaryContinuityAssessmentV1,
            ordinary_assessment_original=ProductionOriginalRefV1, ordinary_trigger_assessment_original=ProductionOriginalRefV1,
            ordinary_deep_preparation=OrdinaryDeepGrowthPreparationV1, ordinary_deep_anchor=OrdinaryDeepGrowthAnchorV1,
            growth=GrowthAdoptionCandidate, general_growth=None)
    return fields


def verify_ordinary_cumulative_stage_v1(stage):
    import json
    from .domain_production_contracts_v1 import StagedDomainOperationV1
    if type(stage) is not StagedDomainOperationV1 or stage.domain != "d01" or stage.operation_kind not in OPERATION_KINDS:
        raise TypeError("exact installed ordinary cumulative production stage required")
    if stage.coverage != "complete":
        if stage.proposals: raise ValueError("incomplete ordinary continuity cannot adopt a claim or anchor")
        return stage
    raw = json.loads(stage.original_payload_json)
    p = raw["provenance"]; fields = provenance_types_ordinary_cumulative_v1(stage.operation_kind)
    if set(p) - set(fields): raise ValueError("ordinary cumulative provenance includes unregistered fields")
    decoded = {name: value if fields[name] is None else _decode_metadata_v1(value, fields[name]) for name, value in p.items()}
    writes = tuple(w for proposal in stage.proposals for w in proposal.typed_writes)
    if stage.operation_kind == REGISTER:
        if set(p) != {"ordinary_policy"} or writes or stage.jobs:
            raise ValueError("ordinary policy installation cannot write a persona or start cognition")
    elif stage.operation_kind == ASSESS:
        if writes or stage.jobs or not {"ordinary_basis", "ordinary_basis_original", "growth_request", "basis_new", "ordinary_state"} <= set(p):
            raise ValueError("ordinary mechanical/semantic assessment cannot activate a persona")
        if ("ordinary_assessment" in p) != ("ordinary_assessment_original" in p):
            raise ValueError("ordinary assessment lost its own exact immutable original locator")
    else:
        candidate = decoded["growth"]; b = decoded["ordinary_basis"]
        markers = tuple(w for w in writes if w.key.type_name == ANCHOR_TYPE)
        if (len(markers) != 1 or tuple(w for w in writes if w.key.type_name != ANCHOR_TYPE) != candidate.typed_writes
                or decoded["ordinary_assessment"].decision != "deep_accepted"
                or canonical_digest(candidate.typed_writes) != b.candidate_write_digest
                or markers[0].key != ordinary_deep_anchor_key_v1(stage.namespace, stage.operation_id)
                or decoded["ordinary_deep_anchor"].successor_head != candidate.head_id):
            raise ValueError("ordinary deep stage changed its actual qualified candidate or same-CAS anchor")
    if "ordinary_basis" in decoded:
        b, original = decoded["ordinary_basis"], decoded["ordinary_basis_original"]
        if (original.kind != "d01." + BASIS_KIND or original.original_digest != ordinary_cumulative_payload_digest_v1(b)
                or original.original_ref != "ordinary-basis:" + canonical_digest(ordinary_basis_semantics_v1(b))[:48]
                or b.namespace != stage.namespace):
            raise ValueError("ordinary stage changed its exact immutable mechanical basis")
    if "ordinary_assessment" in decoded and _assessment_original_v1(decoded["ordinary_assessment"]) != decoded["ordinary_assessment_original"]:
        raise ValueError("ordinary stage changed its exact signed assessment locator")
    return stage


def record_ordinary_cumulative_after_cas_v1(readers, db, *, witness, frame, primary, request, receipt):
    from .domain_production_commit_v1 import require_ordinary_cumulative_after_cas_witness_v1
    p = require_ordinary_cumulative_after_cas_witness_v1(witness, db=db, frame=frame,
        producing_operation_id=primary.operation_id, request=request, receipt=receipt, operation_kind=primary.operation_kind)
    from ..runtime_contracts import canonical_serialize
    from ..domains.d01.production_operations_v1 import plain_v1
    from .d01_production_operations_v1 import TABLE, SIGN_KIND
    outputs = []
    if primary.operation_kind == REGISTER:
        value = p["ordinary_policy"]
        outputs.append((POLICY_KIND, "ordinary-policy:" + value.policy_id + ":" + str(value.policy_version), value, ()))
    else:
        b = p["ordinary_basis"]; roots = tuple(sorted(set((*b.support_source_refs, *b.context_source_refs))))
        if primary.operation_kind == ASSESS:
            if p["basis_new"]: outputs.append((BASIS_KIND, p["ordinary_basis_original"].original_ref, b, roots))
            if "ordinary_assessment" in p:
                outputs.append((ASSESSMENT_KIND, p["ordinary_assessment_original"].original_ref, p["ordinary_assessment"], roots))
        else:
            from .d01_general_growth_v1 import _general_operation_receipt_v1
            actual_receipt = _general_operation_receipt_v1(db, primary.namespace, primary.operation_id)
            if actual_receipt != receipt:
                raise ValueError("deep adoption cannot issue its anchor from an uncommitted or different receipt")
            event = Event(Scope(*primary.namespace.as_tuple, receipt.activity_id), primary.operation_id,
                frame.now_utc, "domain_bundle", {"bundle_digest": receipt.operation_digest})
            from dataclasses import fields
            preparation = p["ordinary_deep_preparation"]
            value = OrdinaryDeepGrowthAdoptionV1(**{f.name: getattr(preparation, f.name) for f in fields(preparation)},
                activation_receipt=receipt, activation_event_digest=event.digest)
            outputs.append((DEEP_ADOPTION_KIND, "ordinary-deep:" + primary.operation_id, value, roots))
    produced = []
    for kind, ref, value, roots in outputs:
        encoded = canonical_serialize(plain_v1(value)); digest = ordinary_cumulative_payload_digest_v1(value)
        expected = (kind, primary.operation_id, encoded, digest, readers.issuer._signer.sign(SIGN_KIND, encoded), canonical_serialize(roots))
        existing = db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json FROM " + TABLE
            + " WHERE bot=? AND persona=? AND original_ref=?", (*primary.namespace.as_tuple, ref)).fetchone()
        if existing is not None and tuple(existing) != expected:
            # Exact immutable originals keep their actual first producer on a fresh same-candidate request.
            if tuple(existing[i] for i in (0,2,3,4,5)) != tuple(expected[i] for i in (0,2,3,4,5)):
                raise ValueError("ordinary cumulative signed original conflicts with its actual first bytes")
        if existing is None:
            db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?,?)", (*primary.namespace.as_tuple, ref, *expected))
        produced.append(ProductionOriginalRefV1("d01." + kind, ref, digest, receipt.read_versions if existing is None else ()))
    return tuple(produced)


def committed_ordinary_cumulative_view_v1(stage, receipt):
    import json
    if stage.operation_kind not in OPERATION_KINDS or stage.coverage != "complete" or receipt.status != "committed" or receipt.operation_id != stage.operation_id:
        return None
    p = json.loads(stage.original_payload_json)["provenance"]
    def loc(name):
        value = p.get(name)
        return None if value is None else {key: value[key] for key in ("kind", "original_ref", "original_digest")}
    policy = p.get("ordinary_policy")
    return {"schema": "d01.ordinary-cumulative-growth-view.v1", "operation_id": stage.operation_id,
        "operation_kind": stage.operation_kind, "state": p.get("ordinary_state", "deep_adopted" if stage.operation_kind == ADOPT else "policy_installed"),
        "policy_ref": ("ordinary-policy:" + policy["policy_id"] + ":" + str(policy["policy_version"])) if policy else p["ordinary_basis"]["policy_original"]["original_ref"],
        "basis_original": loc("ordinary_basis_original"), "assessment_original": loc("ordinary_assessment_original"),
        "deep_adoption_original": (None if stage.operation_kind != ADOPT else {"kind": "d01." + DEEP_ADOPTION_KIND,
            "original_ref": "ordinary-deep:" + stage.operation_id}),
        "base_head": None if policy else p["ordinary_basis"]["base_head"]["plan_id"] + "@" + str(p["ordinary_basis"]["base_head"]["version"]),
        "candidate_ordinary_change_count": None if policy else p["ordinary_basis"]["candidate_ordinary_change_count"]}



def read_plan_ordinary_cumulative_growth_v1(db, *, namespace, request, issuer):
    from .d01_production_operations_v1 import production_read_plan_v1
    from .d01_general_growth_v1 import read_plan_adopt_current_general_growth_v1
    from ..graph_types import owner_grant_key
    owner = _owner_v1(db, namespace)
    if type(request) is RegisterOrdinaryCumulativeGrowthPolicyRequestV1:
        # Even an empty initial inventory is an actual complete bounded query.
        cursor, count = "", 0
        while True:
            row = _fixed_v1(owner, "graph_d01_production_inputs_v1", ("original_ref",),
                "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref", (*namespace.as_tuple, POLICY_KIND, cursor))
            if row is None: break
            count += 1
            if count > 128: raise MissingProductionOriginalV1("complete_ordinary_policy_inventory_bound")
            cursor = row[0]; _signed_metadata_v1(owner, cursor, POLICY_KIND)
        return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple),), (), ())
    if type(request) not in {AssessOrdinaryContinuityRequestV1, AdoptOrdinaryDeepGrowthRequestV1}:
        raise TypeError("exact ordinary cumulative Source plan request required")
    if type(request) is AssessOrdinaryContinuityRequestV1 and request.interpretation_ref is not None:
        from .d07_ordinary_continuity_cognition_v1 import read_ordinary_continuity_interpretation_metadata_v1
        metadata = read_ordinary_continuity_interpretation_metadata_v1(db, namespace=namespace,
            interpretation_ref=request.interpretation_ref, issuer=issuer)
        plan = read_plan_current_ordinary_continuity_basis_v1(db, namespace=namespace, basis_original=metadata.basis_original)
        originals = (*plan.required_original_refs, request.interpretation_ref)
    elif type(request) is AdoptOrdinaryDeepGrowthRequestV1:
        _, _, op = _signed_metadata_v1(owner, request.assessment_ref, ASSESSMENT_KIND)
        from .d01_ordinary_origin_read_v3 import _column
        payload = _column(owner, "graph_domain_production_originals_v1", "original_payload_json",
            ("bot", "persona", "operation_id"), (*namespace.as_tuple, op), "ordinary_cumulative_producer").metadata
        original = _decode_metadata_v1(payload["provenance"]["ordinary_basis_original"], ProductionOriginalRefV1)
        plan = read_plan_current_ordinary_continuity_basis_v1(db, namespace=namespace, basis_original=original)
        originals = (*plan.required_original_refs, request.assessment_ref)
    else:
        read_current_ordinary_policy_metadata_v1(db, namespace=namespace, policy_ref=request.policy_ref)
        history = read_current_ordinary_cumulative_history_v1(db, namespace=namespace)
        plan = read_plan_adopt_current_general_growth_v1(db, namespace=namespace, request=request.growth_request, issuer=issuer)
        roots = tuple(dict.fromkeys((*plan.source_roots, *history.support_source_refs)))
        if len(roots) > 32: raise MissingProductionOriginalV1("source_root_budget_exceeded:" + str(len(roots)) + "/32")
        plan = production_read_plan_v1(plan.fixed_type_ids, tuple(dict.fromkeys((*plan.exact_keys,
            history.current.plan_ref.key, history.current.activation_ref.key))), roots, plan.required_original_refs)
        originals = (*plan.required_original_refs, request.policy_ref)
    keys = plan.exact_keys
    if type(request) is AdoptOrdinaryDeepGrowthRequestV1:
        keys = tuple(dict.fromkeys((*keys, ordinary_deep_anchor_key_v1(namespace, owner.reader.operation.operation_id))))
    return production_read_plan_v1(plan.fixed_type_ids, keys, plan.source_roots, tuple(dict.fromkeys(originals)))


def read_bound_ordinary_signed_input_v1(db, read, ref, kind, issuer):
    """Exact existing Method original hook, after this immutable input's Source ALL."""
    if kind not in ORIGINAL_TYPES: return False, None
    owner = _owner_v1(db, read.frame.envelope.authority.namespace)
    if issuer is not owner.reader.graph._GraphCoordinator__d11_issuer:
        raise ValueError("ordinary signed input changed its actual installed issuer")
    row = _fixed_v1(owner, "graph_d01_production_inputs_v1",
        ("kind", "producing_operation_id", "payload_digest", "signature"),
        "bot=? AND persona=? AND original_ref=?", (*owner.namespace.as_tuple, ref))
    if row is None or row[0] != kind: raise MissingProductionOriginalV1("actual_signed_ordinary_input:" + ref)
    from .d01_ordinary_origin_read_v3 import _column
    roots = _column(owner, "graph_d01_production_inputs_v1", "source_refs_json",
        ("bot", "persona", "original_ref"), (*owner.namespace.as_tuple, ref), "activation").metadata
    if roots: read.source_family(db, tuple(roots), purpose="consolidation")
    profile = {POLICY_KIND: "ordinary_cumulative_policy", BASIS_KIND: "ordinary_basis_body",
        ASSESSMENT_KIND: "ordinary_continuity_assessment", DEEP_ADOPTION_KIND: "ordinary_deep_adoption"}[kind]
    if kind == BASIS_KIND:
        locator = read_current_ordinary_continuity_basis_metadata_v1(db, namespace=owner.namespace,
            basis_original=ProductionOriginalRefV1("d01." + kind, ref, row[2]))
        if set(roots) != set((*locator.support_source_refs, *locator.context_source_refs)):
            raise ValueError("ordinary Basis Body roots differ from its exact signed metadata locator")
    column = _column(owner, "graph_d01_production_inputs_v1", "payload_json",
        ("bot", "persona", "original_ref"), (*owner.namespace.as_tuple, ref), profile, signed_header=row)
    if not column.signature_verified or column.semantic_digest != row[2]:
        raise ValueError("ordinary signed Body differs from its complete actual original EOF")
    _decode_metadata_v1(column.metadata, ORIGINAL_TYPES[kind])
    _require_signed_ordinary_producer_v1(owner, ref, None if kind == BASIS_KIND else _decode_metadata_v1(column.metadata, ORIGINAL_TYPES[kind]), row)
    return True, (column.metadata, ProductionOriginalRefV1("d01." + kind, ref, row[2]))



ORDINARY_CONTINUITY_EVENTS_V1 = frozenset({"ordinary_continuity_basis_available_for_screen",
    "ordinary_continuity_deep_required", "ordinary_continuity_assessment_available"})
_FOLLOWUP_CAUSES = WeakKeyDictionary()


def ordinary_continuity_cause_locator_path_v1(owner, column, path):
    """The existing Background entry-column may retain these metadata fields only."""
    from .domain_background_read_v3 import BackgroundReadWorkV3, require_actual_background_attachment_owner_v3
    if type(owner) is not BackgroundReadWorkV3: return None
    require_actual_background_attachment_owner_v3(owner, db=owner.db)
    task = owner.entry_column
    if (task is None or task.column is not column or task.entry is None or task.entry[1] != "d01"
            or task.entry[2] not in ORDINARY_CONTINUITY_EVENTS_V1): return None
    if task.metadata[:2] != ("d01", ASSESS):
        raise ValueError("ordinary continuity outbox locator has another actual registered producer")
    if not path: return True
    if path[0] in {"schema", "namespace", "identity", "authority", "parent_budget", "coverage", "now_utc"}: return True
    if path[0] != "provenance": return False
    if len(path) >= 2 and path[1] == "ordinary_basis":
        return len(path) == 2 or path[2] in {"namespace", "original_parent_budget_lease_ref",
            "original_parent_grant_digest", "original_deadline_utc"}
    return len(path) == 1 or path[1] in {"ordinary_basis_original", "ordinary_assessment_original",
        "ordinary_assessment", "ordinary_state"}


def read_ordinary_continuity_followup_cause_v1(db, *, namespace, event_kind, causal_operation_id, original_ref, issuer):
    if event_kind not in ORDINARY_CONTINUITY_EVENTS_V1: return None
    from .domain_background_read_v3 import (_active_v3, require_actual_background_attachment_owner_v3,
        background_point_v3, background_json_loads_v3, background_json_matches_v3, background_typed_original_digest_v3)
    from .domain_production_originals_v1 import TABLE, _receipt
    owner = _active_v3(db); require_actual_background_attachment_owner_v3(owner, db=db)
    if (namespace != owner.namespace or issuer is not owner.graph._GraphCoordinator__d11_issuer
            or owner.entry is None or owner.entry[:3] != (causal_operation_id, "d01", event_kind)):
        raise ValueError("ordinary continuity cause requires its exact actual outbox Work")
    task = owner.entry_column
    if task is None or not task.complete or task.column.sha256 != task.metadata[2]:
        raise ValueError("ordinary continuity cause lacks actual canonical original EOF")
    metadata, payload = owner.entry_metadata
    if (metadata[:2] != ("d01", ASSESS) or payload["schema"] != "d01.current-" + ASSESS + ".v1"
            or payload["namespace"] != {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id}
            or payload["identity"]["operation_id"] != causal_operation_id or payload["coverage"] != "complete"
            or original_ref != "d01-current:" + metadata[2][:48] or owner.entry[4] != metadata[2]):
        raise ValueError("ordinary continuity cause changed its actual immutable producing W01")
    row = background_point_v3(db, table=TABLE,
        columns=("domain", "operation_kind", "request_digest", "original_digest", "read_versions_json", "bundle_digest", "receipt_json", "receipt_digest"),
        key_columns=("bot", "persona", "operation_id"), key=(*namespace.as_tuple, causal_operation_id), legacy_reader=lambda: None)
    if row is None or row[:2] != metadata[:2] or row[3] != metadata[2]:
        raise ValueError("ordinary continuity causal original metadata changed")
    reads_raw, receipt_raw = background_json_loads_v3(row[4]), background_json_loads_v3(row[6])
    reads = tuple(GraphVersion(AtomKey.from_token(token), revision) for token, revision in reads_raw)
    receipt = _receipt(receipt_raw)
    actual = background_point_v3(db, table="graph_bundle_operations", columns=("digest", "activity_id", "effect_id", "commit_seq"),
        key_columns=("bot", "persona", "operation_id"), key=(*namespace.as_tuple, causal_operation_id), legacy_reader=lambda: None)
    if (not background_json_matches_v3(row[4], reads_raw) or not background_json_matches_v3(row[6], receipt_raw)
            or background_typed_original_digest_v3(db, row[6], receipt) != row[7]
            or receipt.operation_id != causal_operation_id or receipt.status != "committed" or receipt.operation_digest != row[5]
            or actual != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq)
            or len(reads) > 1024 or any(NamespaceId.from_key(v.key) != namespace for v in reads) or receipt.read_versions != reads):
        raise ValueError("ordinary continuity cause lost its actual complete Graph receipt/readset")
    event_row = background_point_v3(db, table="graph_events", columns=("reads", "revisions", "epoch_revision"),
        key_columns=("bot", "persona", "session", "event_id"), key=(*namespace.as_tuple, receipt.activity_id, causal_operation_id), legacy_reader=lambda: None)
    from .domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
    if event_row is None or reconstruct_graph_bundle_commit_receipt_v1(namespace, causal_operation_id,
            (*actual, row[6]), event_row) != receipt:
        raise ValueError("ordinary continuity causal receipt differs from its actual event membership")
    p = payload["provenance"]
    basis_original = _decode_metadata_v1(p["ordinary_basis_original"], ProductionOriginalRefV1)
    if basis_original.kind != "d01." + BASIS_KIND:
        raise ValueError("ordinary continuity cause substituted another basis original family")
    assessment_original = None
    if "ordinary_assessment" in p:
        assessment = _decode_metadata_v1(p["ordinary_assessment"], OrdinaryContinuityAssessmentV1)
        assessment_original = _decode_metadata_v1(p["ordinary_assessment_original"], ProductionOriginalRefV1)
        if _assessment_original_v1(assessment) != assessment_original:
            raise ValueError("ordinary continuity cause changed its immutable assessment commitment")
    if event_kind == "ordinary_continuity_basis_available_for_screen":
        if assessment_original is not None or p["ordinary_state"] != "awaiting_screen":
            raise ValueError("ordinary screen cause is not an actual unassessed committed mechanical basis")
    elif event_kind == "ordinary_continuity_deep_required":
        if assessment_original is None or assessment.decision != "deep_required" or assessment.phase != "ordinary_screen":
            raise ValueError("ordinary deep attention lacks its actual prior committed deep-required assessment")
    elif assessment_original is None:
        raise ValueError("ordinary assessment event has no actual committed assessment")
    original = {"domain": row[0], "operation_kind": row[1], "request_digest": row[2], "original_digest": row[3],
        "read_versions": reads, "receipt": receipt, "payload": payload,
        "ordinary_basis_original": basis_original, "ordinary_assessment_original": assessment_original,
        "ordinary_budget_basis": {name: p["ordinary_basis"][name] for name in (
            "namespace", "original_parent_budget_lease_ref", "original_parent_grant_digest", "original_deadline_utc")}}
    _FOLLOWUP_CAUSES[owner] = (original, task, owner.operation, owner.graph_stamp)
    return original


def ordinary_continuity_followup_plan_v1(db, *, namespace, event):
    from .domain_background_read_v3 import _active_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..graph_types import owner_grant_key
    owner = _active_v3(db)
    original = read_ordinary_continuity_followup_cause_v1(db, namespace=namespace, event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id, original_ref=event.trigger_original.original_ref,
        issuer=owner.graph._GraphCoordinator__d11_issuer)
    if original is None or event.receiver_domain != "d01" or event.trigger_original.original_digest != original["original_digest"]:
        raise ValueError("ordinary continuity resolver has another actual causal event")
    # The resolver selects immutable locators only. The child performs its own complete Source Work.
    return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple),), (), ())


def resolve_ordinary_continuity_followup_v1(db, *, frame, event, original):
    from .domain_background_read_v3 import _active_v3, require_actual_background_attachment_owner_v3
    from .domain_production_followups_v1 import DomainFollowupResolutionV1, DomainFollowupCommandV1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from .d07_ordinary_continuity_cognition_v1 import RegisterOrdinaryContinuityAttentionRequestV1
    owner = _active_v3(db); require_actual_background_attachment_owner_v3(owner, db=db)
    entry = _FOLLOWUP_CAUSES.get(owner)
    if (entry != (original, owner.entry_column, owner.operation, owner.graph_stamp) or event.event_kind not in ORDINARY_CONTINUITY_EVENTS_V1
            or event.receiver_domain != "d01" or frame.envelope.authority.namespace != owner.namespace):
        raise ValueError("ordinary continuity resolution left its actual same-Work complete causal metadata")
    CurrentDomainReadV1(frame).check(db)
    if event.event_kind == "ordinary_continuity_assessment_available":
        return DomainFollowupResolutionV1("growth_review_observed", (), (), ())
    phase = "ordinary_screen" if event.event_kind == "ordinary_continuity_basis_available_for_screen" else "deep_review"
    trigger = None if phase == "ordinary_screen" else original["ordinary_assessment_original"]
    request = RegisterOrdinaryContinuityAttentionRequestV1(original["ordinary_basis_original"], phase, trigger)
    command = DomainFollowupCommandV1("d07", "register_ordinary_continuity_attention_v1", request,
        original["receipt"].activity_id, frame.envelope.authority.audience[0], frame.envelope.authority.audience)
    return DomainFollowupResolutionV1("ready", (command,), (), ())



def _dedicated_metadata_member_v1(owner, key, revision, event):
    """A member of this already authenticated dedicated event, without its Body."""
    from .d01_ordinary_origin_read_v3 import _column
    from .d01_ordinary_origin_v3 import OrdinaryHistoryMemberV3
    if NamespaceId.from_key(key) != owner.namespace or type(revision) is not int or revision < 1:
        raise ValueError("dedicated ordinary-carry member changed namespace or actual revision")
    header = _fixed_v1(owner, "graph_history",
        ("valid", "event_bot", "event_persona", "event_session", "event_id", "value_cell_id"),
        "token=? AND revision=?", (key.token, revision))
    if header is None or header[:5] != (1, *owner.namespace.as_tuple, event.scope.session, event.event_id):
        raise ValueError("dedicated ordinary-carry member has another complete actual event header")
    column = _column(owner, "graph_history", "value", ("token", "revision"), (key.token, revision),
        "ordinary_dedicated_member", cell_id=header[5])
    member = OrdinaryHistoryMemberV3(GraphVersion(key, revision), column.semantic_digest, True, event.scope, event.event_id)
    return member, column


def release_ordinary_continuity_followup_metadata_v1(owner):
    """Drop local cause metadata at final payload release; no receiver or Core ownership."""
    _FOLLOWUP_CAUSES.pop(owner, None)



def _ordinary_now_v1(owner):
    from .current_method_learning_read_v3 import actual_current_method_upper_utc_v1
    require_current_ordinary_origin_owner_v1(owner)
    return actual_current_method_upper_utc_v1(owner.reader)



def _general_request_for_ordinary_v1(owner, request):
    """Locate an existing true General producer; never synthesize an intent."""
    from ..domains.d01.production_operations_v1 import AdoptCurrentGrowthRequestV1
    if type(request) is AdoptCurrentGeneralGrowthRequestV1: return request
    if type(request) is not AdoptCurrentGrowthRequestV1:
        raise TypeError("ordinary growth has another exact registered request")
    from .d01_ordinary_origin_read_v3 import _column
    from .d01_general_growth_v1 import GeneralGrowthIntentOriginalV1
    cursor, count, matches = "", 0, []
    while True:
        row = _fixed_v1(owner, "graph_d01_production_inputs_v1",
            ("original_ref", "kind", "producing_operation_id", "payload_digest", "signature"),
            "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
            (*owner.namespace.as_tuple, "general_growth_intent_v1", cursor))
        if row is None: break
        count += 1
        if count > 128: raise MissingProductionOriginalV1("complete_ordinary_General_intent_inventory_bound")
        cursor = row[0]
        column = _column(owner, "graph_d01_production_inputs_v1", "payload_json",
            ("bot", "persona", "original_ref"), (*owner.namespace.as_tuple, row[0]), "general_intent", signed_header=row[1:])
        if not column.signature_verified or column.semantic_digest != row[3]:
            raise ValueError("ordinary legacy adapter lost its actual complete signed General intent")
        value = _decode_metadata_v1(column.metadata, GeneralGrowthIntentOriginalV1)
        if value.proposal_ref != request.growth_proposal_ref: continue
        producer = _fixed_v1(owner, "graph_domain_production_originals_v1", ("domain", "operation_kind"),
            "bot=? AND persona=? AND operation_id=?", (*owner.namespace.as_tuple, row[2]))
        bundle = _fixed_v1(owner, "graph_bundle_operations", ("commit_seq",),
            "bot=? AND persona=? AND operation_id=?", (*owner.namespace.as_tuple, row[2]))
        if producer != ("d01", "freeze_general_growth_intent_v1") or bundle is None or bundle[0] < 1:
            raise ValueError("ordinary legacy adapter cannot promote a manually recorded intent into a General producer")
        if value.required_trial_refs != request.trial_original_refs:
            raise ValueError("ordinary legacy request changed the actual General producer's declared trials")
        matches.append(row[0])
    if len(matches) != 1:
        raise MissingProductionOriginalV1("unique_existing_General_intent_for_ordinary_legacy_request")
    return AdoptCurrentGeneralGrowthRequestV1(matches[0], request.growth_proposal_ref,
        request.trigger_original_ref, request.trial_original_refs, request.counterevidence_query_ref)


def read_plan_legacy_ordinary_continuity_v1(db, *, namespace, request, issuer):
    """The old request is data; only its real General producer supplies extra roots."""
    from .d01_general_growth_v1 import read_plan_adopt_current_general_growth_v1
    from .d01_production_operations_v1 import production_read_plan_v1
    owner = _owner_v1(db, namespace)
    general = _general_request_for_ordinary_v1(owner, request)
    history = read_current_ordinary_cumulative_history_v1(db, namespace=namespace)
    _, policy = read_current_ordinary_policy_metadata_v1(db, namespace=namespace)
    plan = read_plan_adopt_current_general_growth_v1(db, namespace=namespace, request=general, issuer=issuer)
    roots = tuple(dict.fromkeys((*plan.source_roots, *history.support_source_refs)))
    if len(roots) > 32: raise MissingProductionOriginalV1("source_root_budget_exceeded:" + str(len(roots)) + "/32")
    return production_read_plan_v1(plan.fixed_type_ids, tuple(dict.fromkeys((*plan.exact_keys,
        history.current.plan_ref.key, history.current.activation_ref.key))), roots,
        tuple(dict.fromkeys((*plan.required_original_refs, policy.original_ref))))



_ORDINARY_FIXED_COLUMNS_V1 = {
    "graph_role_init_receipts_v1": frozenset({"operation_id"}),
    "graph_history": frozenset({"token", "revision", "valid", "event_bot", "event_persona", "event_session", "event_id", "value_cell_id"}),
    "graph_events": frozenset({"digest", "epoch_revision"}),
    "graph_bundle_operations": frozenset({"digest", "activity_id", "effect_id", "commit_seq"}),
    "graph_domain_production_originals_v1": frozenset({"domain", "operation_kind", "request_digest", "original_digest", "bundle_digest", "receipt_digest"}),
    "graph_d01_production_inputs_v1": frozenset({"original_ref", "kind", "producing_operation_id", "payload_digest", "signature"}),
    "graph_d07_execution_originals_v1": frozenset({"original_ref", "kind", "payload_digest", "signature"}),
}


def read_current_ordinary_fixed_metadata_v1(owner, table, columns, where, args):
    require_current_ordinary_origin_owner_v1(owner)
    if table not in _ORDINARY_FIXED_COLUMNS_V1 or not columns or set(columns) - _ORDINARY_FIXED_COLUMNS_V1[table]:
        raise ValueError("ordinary fixed metadata cannot select a Body column")
    identity = ("fixed", table, tuple(columns), where, tuple(args))
    if identity in owner.fixed_rows: return owner.fixed_rows[identity]
    owner.selected_fixed.add(identity)
    from .current_method_learning_read_v3 import _need_method_input
    _need_method_input(owner.reader, ("ordinary_cumulative_metadata", identity))


class _OrdinaryFixedMetadataTaskV1:
    def __init__(self, owner, identity):
        require_current_ordinary_origin_owner_v1(owner)
        if identity not in owner.selected_fixed:
            raise ValueError("ordinary fixed metadata task was not selected by its actual history recipe")
        self.owner, self.identity, self.complete = owner, identity, False
        owner.fixed_tasks[identity] = self
    def advance(self, meter):
        self.owner.require_current_v1()
        self.owner.reader.require_current(meter=meter)
        if self.owner.fixed_tasks.get(self.identity) is not self or self.identity not in self.owner.selected_fixed:
            raise ValueError("ordinary fixed metadata lost its actual same-Work selection")
        if not self.complete:
            _, table, columns, where, args = self.identity
            row = meter.read_fixed_row(self.owner.db, table, columns, where, args)
            from .source_correction_read_v3 import _heap
            self.owner.operation.retain(_heap((self.identity, row)) + 1024)
            self.owner.fixed_rows[self.identity] = row
            self.complete = True
        return self.complete
