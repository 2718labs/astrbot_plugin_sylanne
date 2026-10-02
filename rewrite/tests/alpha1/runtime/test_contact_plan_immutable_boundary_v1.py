"""Actual global guard evidence for the unchanged legacy Contact plan.

This deliberately supplies no adopted/paid plan and issues no permission. It
proves the registered immutable TypeSpec rejects its producer's nonempty edge
shape before payload validation, with no Graph transaction effects.
"""
import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.runtime.contact_plan_adoption_v1 import contact_plan_type_specs_v1
from sylanne3.runtime_contracts import NamespaceId


def test_actual_registered_legacy_plan_rejects_invalidating_edges_before_any_write(tmp_path):
    ns=NamespaceId('bot','persona');registry=TypeRegistry()
    plan_spec,=contact_plan_type_specs_v1();registry.register(plan_spec)
    registry.register(TypeSpec('fixture.input',('persona',),'state',lambda value:value))
    store=GraphStore(tmp_path/'boundary.db',registry)
    try:
        dependency=AtomKey(Owner('persona',*ns.as_tuple),'fixture.input','input')
        key=AtomKey(Owner('activity',*ns.as_tuple,'activity'),'d08.contact_expression_plan.v1','plan')
        candidate=GraphCandidate(Event(Scope(*ns.as_tuple,'activity'),'plan-boundary',1.,'fixture',{}),
            (GraphVersion(key,0),GraphVersion(dependency,0)),(GraphWrite(key,{},(dependency,)),))
        assert plan_spec.immutable is True
        with pytest.raises(ValueError,match='immutable graph atoms cannot have invalidating dependencies'):
            store.graph_commit(candidate)
        assert store._db.execute('SELECT count(*) FROM graph_atoms').fetchone()==(0,)
        assert store._db.execute('SELECT count(*) FROM graph_events').fetchone()==(0,)
    finally:store.close()
