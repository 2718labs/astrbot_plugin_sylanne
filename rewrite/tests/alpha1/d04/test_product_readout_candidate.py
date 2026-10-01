"""C06 behaviour changes with certified numeric input and stays HOLD."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d04 import (
    AffectAxis, AffectScheme, CommittedRef, D04ReadoutHold, FeelingState,
    NumericCheckpoint, RootAssetBindings, RootBlockIdentity,
    encode_numeric_checkpoint, project_conditional_affect_behaviour,
)
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.domains.d04.source_head import D04SourceHeadRead
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.native_runtime.d04_tanh_readout_asset import (
    D04LoadedTanhReadoutAsset, D04TanhReadoutRow, TRANSFORM,
)
from sylanne3.native_runtime.tanh_asset_readout import run_d04_conditional_tanh_readout_math
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d07 import AttentionPolicy, AttentionTicket, FocusState
from sylanne3.domains.d07.affective_readout_focus import project_focus_from_affective_readout
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import FenceScope, NamespaceId


def _source_read(source_ref, checkpoint, checkpoint_ref, checkpoint_revision):
    namespace = NamespaceId("bot:one", "alice")
    epoch = NamespaceEpoch("bot:one", "alice", 7)
    record = SourceRecord(
        "source:one", "evidence", "speaker", "reported", "reported", 1.0, 2.0,
        "family", ("entity:alice",), ("context",), (),
    )
    source_atom = GraphAtom(source_key(*namespace.as_tuple, "source:one"),
                            1, record.to_dict())
    access_atom = GraphAtom(access_key(*namespace.as_tuple, "source:one"), 1, {
        "source_id": "source:one", "audiences": ["entity:alice"],
        "purposes": ["context"], "status": "active", "recorded_at": 2.0,
    })
    head_atom = GraphAtom(source_correction_head_key(namespace, "source:one"),
                          0, {}, False)
    checkpoint_atom = GraphAtom(AtomKey.from_token(checkpoint_ref),
                                checkpoint_revision,
                                encode_numeric_checkpoint(checkpoint))
    feeling = FeelingState(
        checkpoint.block.block_id, checkpoint.block.object_ref,
        checkpoint.assets.scheme_version, checkpoint.assets.operator_version,
        tuple((axis, value) for axis, value in zip(checkpoint.axes,
                                                  checkpoint.latent_state)),
        (checkpoint.block.meaning_ref,), ("interpretation:one",), (),
        (source_ref,), checkpoint.assets.parameter_version,
        checkpoint.assets.coupling_version, checkpoint.cursor,
        checkpoint.graph_state.revision,
    )
    state_value = asdict(feeling)
    state_value["coordinates"] = [list(item) for item in feeling.coordinates]
    for name in ("meaning_refs", "interpretation_refs", "active_driver_refs",
                 "historical_source_refs"):
        state_value[name] = list(getattr(feeling, name))
    state_atom = GraphAtom(AtomKey.from_token(checkpoint.graph_state.ref),
                           checkpoint.graph_state.revision, state_value)
    assert source_atom.key.token == source_ref
    anchor = RestoreAnchor(
        authority_id="authority", namespace="authority-namespace",
        activation_generation=3, deletion_journal_id="deletion",
        deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution", execution_seq=0,
        execution_digest="genesis", revocation_epoch=0, proof="opaque-proof",
    )
    permit = FencePermitV2(
        authority_id=anchor.authority_id, namespace=anchor.namespace,
        subject="subject", holder="holder", generation=3, operation="read",
        operation_id="read-1", token="t" * 32, fence_epoch=7, revision=2,
        pinned_anchor=anchor,
    )
    fence = FenceScope(namespace, anchor.namespace, 3, "read", "read-1",
                       permit, anchor, epoch, 11)
    return D04SourceHeadRead(
        GraphSnapshot((source_atom, access_atom, head_atom,
                       checkpoint_atom, state_atom), (epoch,)), namespace,
        ("entity:alice",), "context", fence, True, True, True,
    )


def _case(*, care: float = 0.8, boundary: float = 0.6,
          block_id: str = "block:one"):
    owner = Owner("persona", "bot:one", "alice")
    assets = RootAssetBindings(
        SCHEME_VERSION, "operator:one", "parameter:one", "coupling:one",
        "readout:one", "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
    )
    scheme = AffectScheme(
        "d04.affect.scheme.v1", SCHEME_VERSION, "operator:one",
        "parameter:one", "coupling:one",
        tuple(AffectAxis(axis, "normalized", axis) for axis in REGISTERED_AXIS_IDS),
        (),
    )
    rows = tuple(D04TanhReadoutRow(
        f"output:{axis}", axis, "normalized", "readout:one", TRANSFORM,
        tuple(float(index == coordinate) for coordinate in range(24)),
    ) for index, axis in enumerate(REGISTERED_AXIS_IDS))
    asset = D04LoadedTanhReadoutAsset(
        "readout:one", "readout:one", SCHEME_VERSION,
        REGISTERED_AXIS_IDS, ("normalized",) * 24, rows, "e" * 64,
    )
    values = [0.0] * 24
    values[REGISTERED_AXIS_IDS.index("affiliative_approach:fast")] = care
    values[REGISTERED_AXIS_IDS.index("boundary_protection:fast")] = boundary
    state_ref = AtomKey(owner, "d04.feeling_state.v1", block_id).token
    checkpoint = NumericCheckpoint(
        f"checkpoint:{block_id.removeprefix('block:')}", ("bot:one", "alice"),
        RootBlockIdentity(block_id, "template:one", "feeling",
                          "person:one", "meaning:ambivalence", "source:one"),
        assets, assets.digest, REGISTERED_AXIS_IDS, tuple(values),
        tuple((value, value) for value in values), 0.0,
        "trusted_initial_box", "f" * 64, 10.0,
        CommittedRef(state_ref, 2), "1" * 64,
        "operation:adopt", "none", None,
    )
    source_ref = source_key("bot:one", "alice", "source:one").token
    checkpoint_ref = AtomKey(owner, "d04.numeric_checkpoint.v1", block_id).token
    math = run_d04_conditional_tanh_readout_math(asset, checkpoint.latent_state, 0.0)
    return (checkpoint, checkpoint_ref, source_ref, scheme, asset, math,
            _source_read(source_ref, checkpoint, checkpoint_ref, 3))


def _project(case):
    checkpoint, checkpoint_ref, source_ref, scheme, asset, math, source_read = case
    return project_conditional_affect_behaviour(
        checkpoint=checkpoint, checkpoint_ref=checkpoint_ref,
        checkpoint_revision=3, source_ref=source_ref, scheme=scheme,
        asset=asset, math_readout=math, source_read=source_read,
    )


def test_opposing_tendencies_survive_and_single_component_intervention_changes_behaviour():
    baseline = _project(_case())
    changed = _project(_case(boundary=0.9))
    assert baseline.status == "hold_for_d11_product_admission"
    assert len(baseline.tendencies) == 24
    by_axis = {item.axis_id: item for item in baseline.tendencies}
    assert by_axis["affiliative_approach:fast"].tendency == "care"
    assert by_axis["boundary_protection:fast"].tendency == "protect_boundary"
    assert by_axis["affiliative_approach:fast"].lower > 0
    assert by_axis["boundary_protection:fast"].lower > 0
    changed_axes = {old.axis_id for old, new in zip(baseline.tendencies, changed.tendencies)
                    if (old.lower, old.upper) != (new.lower, new.upper)}
    assert changed_axes == {"boundary_protection:fast"}
    assert changed.proof_digest != baseline.proof_digest


def test_omitted_inherited_error_and_math_tampering_are_rejected():
    checkpoint, ref, source, scheme, asset, math, source_read = _case()
    boxes = list(checkpoint.certified_box)
    boxes[0] = (0.0, 0.2)
    with_error = replace(checkpoint, certified_box=tuple(boxes), numeric_error_bound=0.2)
    with pytest.raises(D04ReadoutHold, match="inherited"):
        _project((with_error, ref, source, scheme, asset, math,
                  _source_read(source, with_error, ref, 3)))
    output = replace(math.outputs[0], upper=math.outputs[0].upper + 0.1)
    with pytest.raises(D04ReadoutHold, match="replay"):
        _project((checkpoint, ref, source, scheme, asset,
                  replace(math, outputs=(output,) + math.outputs[1:]), source_read))


def test_wrong_scheme_or_source_scope_is_rejected():
    checkpoint, ref, source, scheme, asset, math, source_read = _case()
    with pytest.raises(D04ReadoutHold, match="Scheme"):
        _project((checkpoint, ref, source, replace(scheme, parameter_version="new"),
                  asset, math, source_read))
    wrong_source = source_key("bot:one", "bob", "source:one").token
    with pytest.raises(D04ReadoutHold, match="namespace"):
        _project((checkpoint, ref, wrong_source, scheme, asset, math, source_read))


def test_revoked_access_and_missing_current_fence_hold_readout():
    checkpoint, ref, source, scheme, asset, math, source_read = _case()
    revoked = replace(source_read.snapshot.atoms[1], value={
        **source_read.snapshot.atoms[1].value, "status": "withdrawn",
    })
    with pytest.raises(D04ReadoutHold, match="source closure"):
        _project((checkpoint, ref, source, scheme, asset, math,
                  replace(source_read, snapshot=replace(
                      source_read.snapshot,
                      atoms=(source_read.snapshot.atoms[0], revoked),
                  ))))
    with pytest.raises(D04ReadoutHold, match="source closure"):
        _project((checkpoint, ref, source, scheme, asset, math,
                  replace(source_read, current_fence_confirmed=False)))


def test_stale_checkpoint_and_correction_head_hold_readout():
    checkpoint, ref, source, scheme, asset, math, source_read = _case()
    atoms = list(source_read.snapshot.atoms)
    atoms[3] = replace(atoms[3], revision=4)
    with pytest.raises(D04ReadoutHold, match="checkpoint"):
        _project((checkpoint, ref, source, scheme, asset, math,
                  replace(source_read, snapshot=replace(source_read.snapshot,
                                                         atoms=tuple(atoms)))))
    atoms = list(source_read.snapshot.atoms)
    atoms[2] = replace(atoms[2], revision=1, valid=True)
    with pytest.raises(D04ReadoutHold, match="corrected"):
        _project((checkpoint, ref, source, scheme, asset, math,
                  replace(source_read, snapshot=replace(source_read.snapshot,
                                                         atoms=tuple(atoms)))))


def test_unread_historical_source_cannot_hide_behind_qualified_selected_source():
    checkpoint, ref, source, scheme, asset, math, source_read = _case()
    atoms = list(source_read.snapshot.atoms)
    state = dict(atoms[4].value)
    state["historical_source_refs"] = [
        source, source_key("bot:one", "alice", "source:missing").token,
    ]
    atoms[4] = replace(atoms[4], value=state)
    with pytest.raises(D04ReadoutHold, match="source or correction head"):
        _project((checkpoint, ref, source, scheme, asset, math,
                  replace(source_read, snapshot=replace(source_read.snapshot,
                                                         atoms=tuple(atoms)))))


def test_feeling_graph_coordinates_must_match_certified_24d_checkpoint():
    checkpoint, ref, source, scheme, asset, math, source_read = _case()
    atoms = list(source_read.snapshot.atoms)
    feeling = dict(atoms[4].value)
    coordinates = [list(item) for item in feeling["coordinates"]]
    coordinates[REGISTERED_AXIS_IDS.index("affiliative_approach:fast")][1] = 0.1
    feeling["coordinates"] = coordinates
    atoms[4] = replace(atoms[4], value=feeling)
    with pytest.raises(D04ReadoutHold, match="24D coordinates differ"):
        _project((checkpoint, ref, source, scheme, asset, math,
                  replace(source_read, snapshot=replace(source_read.snapshot,
                                                         atoms=tuple(atoms)))))
    coordinates = [list(item) for item in atoms[4].value["coordinates"]]
    coordinates[0], coordinates[1] = coordinates[1], coordinates[0]
    atoms[4] = replace(atoms[4], value={**feeling, "coordinates": coordinates})
    with pytest.raises(D04ReadoutHold, match="24D coordinates differ"):
        _project((checkpoint, ref, source, scheme, asset, math,
                  replace(source_read, snapshot=replace(source_read.snapshot,
                                                         atoms=tuple(atoms)))))


def test_same_source_two_independent_24d_checkpoints_change_declared_d07_focus():
    low_case = _case(care=0.8, boundary=0.05, block_id="block:low")
    high_case = _case(care=0.8, boundary=0.9, block_id="block:high")
    low, high = _project(low_case), _project(high_case)
    assert low_case[0].latent_state != high_case[0].latent_state
    assert low_case[1] != high_case[1]
    assert len(low_case[0].latent_state) == len(high_case[0].latent_state) == 24
    assert low.source_ref == high.source_ref
    assert low_case[-1].snapshot.get(AtomKey.from_token(low.source_ref)).revision == 1
    assert high_case[-1].snapshot.get(AtomKey.from_token(high.source_ref)).revision == 1
    assert len(low.tendencies) == len(high.tendencies) == 24
    assert {item.axis_id for item in low.tendencies} == set(REGISTERED_AXIS_IDS)
    assert all(item.source_ref == low.source_ref for item in low.tendencies)
    assert all(item.source_ref == high.source_ref for item in high.tendencies)
    care_axis = "affiliative_approach:fast"
    boundary_axis = "boundary_protection:fast"
    assert next(item for item in low.tendencies if item.axis_id == care_axis).lower > 0
    assert next(item for item in high.tendencies if item.axis_id == boundary_axis).lower > 0

    def ticket(ticket_id, question, source, salience, seq):
        return AttentionTicket(ticket_id, question, None, source, "background",
                               0.0, 0.0, 0.0, 0.0, salience, 0.0, 0.0, 0.0, 0.0,
                               seq, 100.0, True, True, (), (source,))

    concerned = ticket("concerned", "person:one", low.source_ref, 0.0, 2)
    other = ticket("other", "project:other", "source:other", 0.3, 1)
    current = FocusState("alice", 1, None, (), "prior")
    policy = AttentionPolicy(0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0)
    baseline = project_focus_from_affective_readout(
        current, (other, concerned), policy, low,
        axis_id=boundary_axis, gain=1.0, now=10.0,
    )
    intervened = project_focus_from_affective_readout(
        current, (other, concerned), policy, high,
        axis_id=boundary_axis, gain=1.0, now=10.0,
    )
    assert baseline.focus.primary_ticket_ref == "other"
    assert intervened.focus.primary_ticket_ref == "concerned"
    assert baseline.source_ref == intervened.source_ref == low.source_ref
    assert baseline.adjusted_ticket.source_refs == intervened.adjusted_ticket.source_refs == (low.source_ref,)
    assert intervened.conservative_salience > baseline.conservative_salience
    assert "requires_w01" in intervened.status
    with pytest.raises(ValueError, match="incomplete"):
        project_focus_from_affective_readout(
            current, (other, concerned), policy, replace(high, tendencies=high.tendencies[:23]),
            axis_id=boundary_axis, gain=1.0, now=10.0,
        )
