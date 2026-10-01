"""Closed paired RPC surface for independent authored-root execution originals."""
from .contract import AuthorityUnavailable,identifier
from .d04_root_execution_contract_v3 import (D04RootExecutionBindingV3,D04RootExecutionClaimV3,
    D04RootExecutionMeasurementV3,root_execution_to_wire_v3 as to_wire,root_execution_from_wire_v3 as from_wire)
from .d04_root_execution_bridge_v3 import (D04RootOriginalAppendV3,D04RootAdoptionBridgeV3,
    root_bridge_to_wire_v3,root_bridge_from_wire_v3)

METHODS=frozenset('d04_root_'+name+'_v3' for name in ('inspect','claim','terminal','original_append',
    'adoption_bridge','validate_gate','finish_adoption','gate_status','restore_manifest','restore_chunk',
    'cost_only','cost_inspect','accounting'))


def dispatch_d04_root_execution_v3(server,method,credential,profile_id,manifest_digest,command):
    if method not in METHODS:return None
    from .d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
    if type(command) is not dict:raise AuthorityUnavailable("root command shape differs")
    expected={"namespace","binding"}
    if method=='d04_root_claim_v3':expected.add('executor_incarnation')
    if method in {'d04_root_terminal_v3','d04_root_cost_only_v3'}:expected.update({'claim','measurement'})
    if method=='d04_root_original_append_v3':expected.add('claim')
    if method in {'d04_root_validate_gate_v3','d04_root_finish_adoption_v3','d04_root_gate_status_v3'}:expected.add('gate')
    if method=='d04_root_finish_adoption_v3':expected.add('outcome')
    if method=='d04_root_restore_chunk_v3':expected.update({'packet_digest','offset'})
    if method=='d04_root_accounting_v3':expected.update({'action','gate'})
    if set(command)!=expected:raise AuthorityUnavailable("root command fields differ")
    namespace=identifier(command['namespace'],'namespace')
    server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installation=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=server._d04_root_services_v3.get(namespace)
    binding=from_wire(command['binding'],D04RootExecutionBindingV3)
    if (type(service) is not AuthorityD04RootExecutionServiceV3 or service.installation_id!=installation.installation_id
            or binding.installation_id!=installation.installation_id or binding.authority_namespace!=namespace):raise AuthorityUnavailable("root paired concrete installation differs")
    if method=='d04_root_inspect_v3':
        claim,terminal=service.read_d04_root_originals_v3(binding)
        return {'claim':None if claim is None else to_wire(claim),'terminal':None if terminal is None else to_wire(terminal)}
    if method=='d04_root_claim_v3':return {'claim':to_wire(service.claim_d04_root_v3(binding,command['executor_incarnation']))}
    if method in {'d04_root_terminal_v3','d04_root_cost_only_v3'}:
        claim=from_wire(command['claim'],D04RootExecutionClaimV3);measurement=from_wire(command['measurement'],D04RootExecutionMeasurementV3)
        result=(service.record_d04_root_terminal_v3(binding,claim,measurement) if method=='d04_root_terminal_v3'
            else service.record_d04_root_measured_cost_closure_v3(binding,claim,measurement))
        return {'terminal' if method=='d04_root_terminal_v3' else 'cost_closure':to_wire(result)}
    if method=='d04_root_cost_inspect_v3':
        result=service.read_d04_root_measured_cost_closure_v3(binding)
        return {'cost_closure':None if result is None else to_wire(result)}
    if method=='d04_root_original_append_v3':return {'gate':root_bridge_to_wire_v3(service.begin_d04_root_original_append_v3(binding,from_wire(command['claim'],D04RootExecutionClaimV3)))}
    if method=='d04_root_adoption_bridge_v3':return {'gate':root_bridge_to_wire_v3(service.begin_d04_root_adoption_bridge_v3(binding))}
    if method in {'d04_root_restore_manifest_v3','d04_root_restore_chunk_v3'}:
        from .d04_root_restore_stream_v3 import read_root_restore_manifest_v3,read_root_restore_chunk_v3
        return read_root_restore_manifest_v3(service,binding) if method.endswith('manifest_v3') else read_root_restore_chunk_v3(service,binding,packet_digest=command['packet_digest'],offset=command['offset'])
    if method=='d04_root_accounting_v3':
        from .d04_root_accounting_v3 import operate_d04_root_accounting_v3,root_accounting_from_wire_v3,root_accounting_to_wire_v3
        gate=None if command['gate'] is None else root_accounting_from_wire_v3(command['gate'])
        result=operate_d04_root_accounting_v3(service,binding,command['action'],gate)
        return {'gate':root_accounting_to_wire_v3(result)} if command['action']=='begin' else {'ok':result}
    raw=command['gate'];kind={'d04.authored-root-original-append.v3':D04RootOriginalAppendV3,'d04.authored-root-adoption-bridge.v3':D04RootAdoptionBridgeV3}.get(raw.get('schema') if type(raw) is dict else None)
    gate=root_bridge_from_wire_v3(raw,kind)
    if method=='d04_root_gate_status_v3':return {'state':service.read_d04_root_gate_state_v3(binding,gate)}
    if method=='d04_root_validate_gate_v3':return {'gate':root_bridge_to_wire_v3(service.validate_d04_root_gate_v3(binding,gate))}
    service.finish_d04_root_adoption_bridge_v3(binding,gate,outcome=command['outcome'])
    return {'finished':True}
