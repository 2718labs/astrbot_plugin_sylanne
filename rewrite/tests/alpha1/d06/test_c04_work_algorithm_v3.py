"""V3 candidate ranking uses each target's own conditioned D04 original."""

from dataclasses import replace

from sylanne3.contracts import canonical_json
from sylanne3.domains.d06.c04_work_algorithm_v3 import activate_association_work_v3
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey
from sylanne3.memory_types import association_key, source_key
from sylanne3.runtime.c04_v3_contracts import AssociationPageV3, GraphHeadV3
from tests.alpha1.contracts.test_c04_v3_contracts import NS, target, work
from tests.alpha1.d06.test_c04_work_input_v2 import _access, _source


def _two_targets():
    frozen = work()
    cue = frozen.cue_source_ref
    second = source_key(*NS.as_tuple, "target-2").token
    edge_key = association_key(*NS.as_tuple, "cue", "edge-2")
    edge = GraphHeadV3(edge_key.token, 1, True, canonical_json({
        "association_id": "edge-2", "source_ref": cue,
        "target_ref": second, "kind": "similarity", "weight": 0.8,
        "context_tags": ["now"], "basis_source_refs": [cue],
        "content_reality": "subjective",
    }))
    extra = [GraphHeadV3(row.key.token, row.revision, row.valid, row.value_json)
             for row in (_source("target-2"), _access("target-2"))]
    extra.append(GraphHeadV3(
        source_correction_head_key(NS, "target-2").token, 0, False, None))
    cue_page = next(page for page in frozen.edge_pages if page.source_ref == cue)
    pages = tuple(sorted((replace(cue_page, edge_refs=tuple(sorted((
        *cue_page.edge_refs, edge.ref)))),
        *[page for page in frozen.edge_pages if page.source_ref != cue],
        AssociationPageV3(second, 1, (), None)), key=lambda page: page.source_ref))
    return replace(frozen,
                   reads=tuple(sorted((*frozen.reads, edge, *extra),
                                      key=lambda row: row.ref)),
                   edge_pages=pages,
                   targets=tuple(sorted((*frozen.targets, target(second)),
                                        key=lambda item: item.source_ref)))


def _weight(frozen, source_ref, interval):
    targets = []
    for item in frozen.targets:
        if item.source_ref == source_ref:
            item = replace(item, condition=replace(
                item.condition, conditioned_salience_interval=interval))
        targets.append(item)
    return replace(frozen, targets=tuple(targets))


def test_each_target_condition_changes_relative_ranking_and_digest():
    frozen = _two_targets()
    refs = tuple(item.source_ref for item in frozen.targets
                 if item.source_ref != frozen.cue_source_ref)
    lower = _weight(_weight(frozen, refs[0], (0.1, 0.1)), refs[1], (0.9, 0.9))
    higher = _weight(_weight(frozen, refs[0], (0.9, 0.9)), refs[1], (0.1, 0.1))
    first = activate_association_work_v3(lower)
    second = activate_association_work_v3(higher)
    assert first.candidates[0].source_ref == refs[1]
    assert second.candidates[0].source_ref == refs[0]
    assert first.input_digest != second.input_digest
    assert first.result_digest != second.result_digest
    assert all(item.evidence_eligibility == "subjective_association_only"
               for item in first.candidates)


def test_page_truncation_is_partial_and_preserves_budget():
    frozen = _two_targets()
    cue_page = next(page for page in frozen.edge_pages
                    if page.source_ref == frozen.cue_source_ref)
    pages = tuple(replace(page, next_after=page.edge_refs[-1])
                  if page == cue_page else page for page in frozen.edge_pages)
    partial = replace(frozen, edge_pages=pages, truncated=True)
    result = activate_association_work_v3(partial)
    assert result.truncated is True
    assert result.stop_reason == "traversal_budget_or_page_limit"
    assert result.visited_edges <= partial.budget.max_edges
    assert result.visited_nodes <= partial.budget.max_nodes
    assert result.iterations <= partial.budget.max_iterations
