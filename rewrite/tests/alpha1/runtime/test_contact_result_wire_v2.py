"""Closed response codec and transport failure seam; no installed permission claim."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.contact_model_result_contract_v2 import (
    ContactModelResultReadRequestV2, ContactModelResultReadV2,
    contact_result_to_wire_v2, contact_result_from_wire_v2,
)
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.runtime_contracts import NamespaceId


@pytest.fixture
def result():
    request = ContactModelResultReadRequestV2('authority', 'bot/persona',
        NamespaceId('bot', 'persona'), 'installation', 'contact:test',
        'contact_generation', 'job', 'acquire', 'prepare', 'call',
        'a'*64, 'b'*64, 'consumer', 'read-attempt')
    observation = ModelEgressObservationV1('authority', 'bot/persona', 'reader',
        'acquire', 'call', 'b'*64, 'completed', '{"synthetic":true}',
        (('tokens', 3),), (('units', 1),), 'synthetic-provider-call')
    receipt = ModelTerminalReceiptV2('c'*64, 'call', 'b'*64, 'd'*64,
        observation.digest, 'sha256:'+'e'*64, 'installation', 'f'*64)
    return ContactModelResultReadV2(request, observation, receipt, 123.0, '0'*64)


def test_complete_result_v2_json_roundtrip(result):
    import json
    wire = json.loads(json.dumps(contact_result_to_wire_v2(result), allow_nan=False))
    restored = contact_result_from_wire_v2(wire, ContactModelResultReadV2)
    assert restored == result
    assert restored.observation.usage == (('tokens', 3),)
    assert restored.terminal_receipt.observation_digest == restored.observation.digest


@pytest.mark.parametrize('change', ('observation_extra', 'missing', 'pair_shape',
    'amount_bool', 'amount_float', 'call', 'receipt_digest', 'unknown', 'result_extra'))
def test_delivered_response_v2_tamper_refusal(result, change):
    wire = deepcopy(contact_result_to_wire_v2(result))
    if change == 'observation_extra':
        wire['observation']['extra'] = True
    elif change == 'missing':
        del wire['observation']['provider_call_ref']
    elif change == 'pair_shape':
        wire['observation']['usage'] = [['tokens', 3, 4]]
    elif change == 'amount_bool':
        wire['observation']['usage'][0][1] = True
    elif change == 'amount_float':
        wire['observation']['usage'][0][1] = 3.0
    elif change == 'call':
        wire['observation']['call_id'] = 'another-call'
    elif change == 'receipt_digest':
        wire['terminal_receipt']['observation_digest'] = '1'*64
    elif change == 'unknown':
        wire['observation']['status'] = 'unknown'
        wire['observation']['result_json'] = None
    else:
        wire['extra'] = True
    with pytest.raises((ValueError, TypeError)):
        contact_result_from_wire_v2(wire, ContactModelResultReadV2)


def test_encoding_failure_releases_only_local_delivery_exclusion(result, monkeypatch):
    # Real handler dispatch/codec failure; service and transport authentication
    # are explicit seams. No finish/ACK or durable fence mutation is simulated.
    from sylanne3.authority_service import mtls_server as server_module
    from sylanne3.authority_service import contact_model_result_contract_v2 as codec
    server = object.__new__(server_module.AuthorityRpcServer)
    credential = server_module.MtlsPeerCredential('a'*64)
    delivery = SimpleNamespace(result=result)
    calls = []
    service = SimpleNamespace(_read_subject='mtls:sha256:'+'a'*64,
        prepare=lambda **kw: delivery,
        abandon_delivery=lambda **kw: calls.append(('abandon', kw['delivery'])),
        finish_delivery=lambda **kw: calls.append(('finish', kw['delivery'])))
    server._contact_model_reads_v2 = {'bot/persona': service}
    server._installations_v2 = {(credential.certificate_sha256, 'profile'):
        SimpleNamespace(installation_id='installation')}
    server._namespace_bindings_v2 = {
        (credential.certificate_sha256, 'profile', result.request.namespace): 'bot/persona'}
    monkeypatch.setattr(server, '_bound_v2_service', lambda *args: None)
    actual_wire = codec.contact_result_to_wire_v2
    def broken(value):
        if type(value) is ContactModelResultReadV2:
            raise ValueError('synthetic response encoding refusal')
        return actual_wire(value)
    monkeypatch.setattr(codec, 'contact_result_to_wire_v2', broken)
    with pytest.raises(Exception) as refused:
        server._v2_command('contact_model_result_read_v2', credential, 'profile', 'b'*64,
            {'namespace': 'bot/persona', 'read_request': contact_result_to_wire_v2(result.request)})
    assert calls == [('abandon', delivery)], repr(refused.value.__cause__)
