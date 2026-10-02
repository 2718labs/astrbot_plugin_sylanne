"""Life V2 proposal's real dependency classification, no guard relaxation."""
from types import SimpleNamespace

import pytest

from sylanne3.graph_types import GraphVersion, GraphWrite
from sylanne3.memory_types import source_key,access_key
from sylanne3.runtime.d10_life_outcome_v2 import life_experience_dependencies_v1


def values():
    original=source_key('bot','persona','input');parent=source_key('bot','persona','parent')
    source=source_key('bot','persona','experience');access=access_key('bot','persona','experience')
    writes=(GraphWrite(source,{},(original,)),GraphWrite(access,{},(source,)))
    versions=(GraphVersion(original,2),GraphVersion(parent,3),GraphVersion(source,0),GraphVersion(access,0))
    return writes,versions


def test_actual_materialized_source_and_access_edges_are_classified_including_absence():
    writes,versions=values();actual=life_experience_dependencies_v1(SimpleNamespace(versions=versions),writes)
    assert set(actual.current_invalidation)=={versions[0],versions[2]}
    assert {v.key for v in actual.current_invalidation}=={key for write in writes for key in write.dependencies}
    assert actual.historical_provenance==versions[:2]
    assert writes[0].dependencies==(versions[0].key,) and writes[1].dependencies==(versions[2].key,)


@pytest.mark.parametrize('missing',[0,2])
def test_missing_actual_dependency_read_guard_remains_rejected(missing):
    writes,versions=values()
    with pytest.raises(ValueError,match='actual current read guard'):
        life_experience_dependencies_v1(SimpleNamespace(versions=tuple(v for i,v in enumerate(versions) if i!=missing)),writes)
