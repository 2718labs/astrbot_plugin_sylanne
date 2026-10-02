"""Real compiled D03 selection, with private lifecycle guards as test seams.

This does not issue a witness or permission. Installed final3 acceptance checks
the actual private lifecycle and authenticated Owner/scene binding separately.
"""
from types import SimpleNamespace

import pytest

from sylanne3.domains.d03.context import ContextProvider
from sylanne3.runtime import contact_final_stage_v3 as stage
from sylanne3.runtime import contact_final_projection_v3 as projection


@pytest.mark.parametrize('drift', [None, 'hash', 'schema', 'provider', 'stage'])
def test_registered_compiled_context_is_selected_without_rebuilding_from_bindings(monkeypatch, drift):
    provider = ContextProvider()
    provider.compile_scheme({'schema': 'd03.context.scheme.v1',
        'roles': ('scene_participant',), 'norms': ()}, None)
    registration = (provider, 'd03.proposal.v1', provider.descriptor.request_schema_hash)
    if drift == 'hash': registration = (provider, registration[1], '0' * 64)
    if drift == 'schema': registration = (provider, 'unknown', registration[2])
    if drift == 'provider': registration = (SimpleNamespace(), registration[1], registration[2])
    graph = SimpleNamespace(_GraphCoordinator__providers={'d03': registration})
    material = SimpleNamespace(runtime=SimpleNamespace(graph=graph))
    read = SimpleNamespace(_witness=SimpleNamespace(material=object() if drift == 'stage' else material))
    monkeypatch.setattr(stage, 'require_installed_contact_material_v3', lambda actual: actual)
    calls = []
    monkeypatch.setattr(projection, 'require_contact_projection_read_v3',
        lambda actual, db, phases: calls.append(phases))
    if drift is None:
        assert stage._installed_contact_context_v3(material, None, read) is provider
        assert provider._roles == frozenset({'scene_participant'})
    else:
        with pytest.raises(ValueError): stage._installed_contact_context_v3(material, None, read)
    assert calls == [('pre_e', 'provisional_e_plus_1', 'post_cas_e_plus_1')]
