"""Composition gate binds three independently tested D04 preflights."""

from dataclasses import asdict, replace
from pathlib import Path

import pytest

from sylanne3.domains.d04.numeric_drive import numeric_drive_id, sourced_numeric_drive_write
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.native_runtime.d04_checkpoint_initial_box import D04CheckpointInitialBoxPreflight
from sylanne3.native_runtime.d04_product_admission import (
    D04ProductNumericPreflight, D04ProductPreflightHold,
)
from sylanne3.native_runtime.d04_product_chain_preflight import (
    _replay_source_values_digest, preflight_d04_product_chain,
)

from rewrite.tests.alpha1.numerics.test_d04_semantic_drive_candidate import (
    _drive, _share,
)
from rewrite.tests.alpha1.runtime.test_authoritative_coupling_snapshot import _fixture, _insert, _read
from rewrite.tests.alpha1.numerics.test_current_numeric_sources_multisource import _read_v2
from sylanne3.domains.d04.root import decode_numeric_checkpoint, encode_numeric_checkpoint
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.native_runtime.d04_semantic_drive_candidate import compile_d04_semantic_drive_candidate
import json


def _appraisal_value(share):
    appraisal = asdict(share.appraisal)
    appraisal["meaning_facets"] = [asdict(facet) for facet in share.appraisal.meaning_facets]
    appraisal["competing_interpretation_refs"] = list(
        share.appraisal.competing_interpretation_refs)
    appraisal["source_refs"] = list(share.appraisal.source_refs)
    for facet in appraisal["meaning_facets"]:
        facet["unknown_fields"] = list(facet["unknown_fields"])
        facet["source_refs"] = list(facet["source_refs"])
    return appraisal


def _inputs(tmp_path, *, multi=False):
    store, namespace, scheme, assets, source_key_, checkpoint_key = _fixture(tmp_path)
    source_value = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (source_key_.token,),
    ).fetchone()[0])
    record = SourceRecord.from_dict(source_value)
    base = _share()
    share = replace(base, source=record, appraisal=replace(
        base.appraisal, source_family="authored", content_reality="authored_content",
    ))
    shares = [share]
    if multi:
        second_record = replace(record, source_id="source-2", provenance_root="family-2")
        second_key = source_key(*namespace.as_tuple, "source-2")
        _insert(store._db, namespace, second_key, second_record.to_dict())
        _insert(store._db, namespace, access_key(*namespace.as_tuple, "source-2"), {
            "source_id": "source-2", "audiences": ["owner"],
            "purposes": ["context"], "status": "active", "recorded_at": 0.0,
        })
        second = _share("source-2", root="family-2", contribution="event-2",
                        mechanism="gain_engagement")
        shares.append(replace(second, source=second_record, appraisal=replace(
            second.appraisal, source_family="authored",
            content_reality="authored_content",
        )))
    semantic = compile_d04_semantic_drive_candidate(
        checkpoint_ref=checkpoint_key.token, checkpoint_revision=1,
        role_start=1.0, role_end=2.0, shares=tuple(shares),
    )
    drives = tuple(replace(
        _drive(semantic, row), checkpoint_ref=checkpoint_key.token,
        drive_id=numeric_drive_id(checkpoint_key.token, row.source_ref, 1.0, 2.0),
    ) for row in semantic.source_vectors)
    writes = tuple(sourced_numeric_drive_write(drive) for drive in drives)
    for write in writes:
        _insert(store._db, namespace, write.key, write.value)
    graph = _read(store, namespace, scheme, assets, checkpoint_key)
    sources = _read_v2(store, graph, scheme, tuple(write.key.token for write in writes))
    checkpoint = decode_numeric_checkpoint(json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (checkpoint_key.token,),
    ).fetchone()[0]))
    atoms = [
        GraphAtom(checkpoint_key, 1, encode_numeric_checkpoint(checkpoint)),
    ]
    for item, write in zip(shares, writes):
        item_key = source_key(*namespace.as_tuple, item.source.source_id)
        item_access = access_key(*namespace.as_tuple, item.source.source_id)
        item_head = source_correction_head_key(namespace, item.source.source_id)
        atoms.extend((
            GraphAtom(AtomKey.from_token(item.appraisal_ref), 1, _appraisal_value(item)),
            GraphAtom(item_key, 1, item.source.to_dict()),
            GraphAtom(item_access, 1, {"source_id": item.source.source_id,
                                       "audiences": ["owner"], "purposes": ["context"],
                                       "status": "active", "recorded_at": 0.0}),
            GraphAtom(item_head, 0, {}, False), GraphAtom(write.key, 1, write.value),
        ))
    snapshot = GraphSnapshot(tuple(atoms), (NamespaceEpoch(*namespace.as_tuple, 1),))
    return store, graph, sources, checkpoint, snapshot, tuple(shares), drives


@pytest.mark.parametrize("multi", (False, True))
def test_product_chain_binds_real_graph_semantics_to_replayed_numeric_receipts(
    tmp_path, monkeypatch, multi,
):
    store, graph, sources, checkpoint, snapshot, shares, drives = _inputs(
        tmp_path, multi=multi,
    )
    try:
        from sylanne3.native_runtime import d04_product_chain_preflight as chain

        calls = []

        def initial(handle, root, graph_arg, sources_arg, checkpoint_arg):
            calls.append("native-initial-box")
            assert checkpoint_arg == checkpoint
            return D04CheckpointInitialBoxPreflight(
                "binding", graph.checkpoint_ref, graph.checkpoint_revision,
                graph.checkpoint_value_digest, "a" * 64, "b" * 64,
                "c" * 64, 0.1, checkpoint.numeric_error_bound, "d" * 64,
            )

        def numeric(handle, root, graph_arg, sources_arg, fixed, trajectory):
            calls.append("native-trajectory-readout")
            return D04ProductNumericPreflight(
                "binding", "snapshot", sources.read_values_digest,
                "e" * 64, "f" * 64, -0.2, 0.3, 0.2,
            )

        monkeypatch.setattr(chain, "preflight_d04_checkpoint_initial_box", initial)
        monkeypatch.setattr(chain, "preflight_d04_product_numeric_readout", numeric)
        kwargs = dict(handle=object(), package_root=Path.cwd(), graph=graph,
                      sources=sources, checkpoint=checkpoint,
                      semantic_snapshot=snapshot, shares=shares, drives=drives,
                      audience=("owner",), purpose="context",
                      fixed_snapshot=object(), trajectory=object())
        result = preflight_d04_product_chain(**kwargs)
        assert calls == ["native-initial-box", "native-trajectory-readout"]
        assert result.status == "candidate_hold_for_w01_current_graph_adoption"
        assert result.semantic.candidate.drive == sources.drive
        assert result.initial_box.verified_initial_error <= checkpoint.numeric_error_bound
        assert result.numeric.inherited_error == 0.2
        assert result.transcript_sha256
        calls.clear()
        with pytest.raises(D04ProductPreflightHold, match="inventory differ"):
            preflight_d04_product_chain(**{
                **kwargs, "sources": replace(sources, drive=(0.0,) * 24),
            })
        assert calls == []
        with pytest.raises(D04ProductPreflightHold, match="value transcript differs"):
            preflight_d04_product_chain(**{
                **kwargs, "sources": replace(sources, read_values_digest="0" * 64),
            })
        assert calls == []
    finally:
        store.close()


def test_two_source_numeric_values_replay_each_source_and_reject_substitution(tmp_path):
    store, graph, sources, checkpoint, snapshot, shares, drives = _inputs(
        tmp_path, multi=True,
    )
    try:
        assert len(drives) == len(sources.drive_versions) == 2
        assert _replay_source_values_digest(graph, sources, snapshot, drives) == sources.read_values_digest
        second_source = source_key(*graph.namespace.as_tuple, "source-2")
        tampered = replace(snapshot, atoms=tuple(
            replace(atom, value={**atom.value, "text": "substituted"})
            if atom.key == second_source else atom for atom in snapshot.atoms
        ))
        assert _replay_source_values_digest(graph, sources, tampered, drives) != sources.read_values_digest
    finally:
        store.close()
