"""New v6 non-authorizing full-wire counter preflight over the protected existing program."""
from dataclasses import dataclass
import json
from ..authority_service.d13_installed_counter_v1 import InstalledD13CounterCommandV1
from ..authority_service.d13_wire_evidence_v6 import (InstalledD13WirePolicyV6,d13_full_wire_count_request_v6,
    verify_signed_d13_wire_envelope_v6,record_signed_d13_wire_evidence_v6)
from ..runtime_contracts import canonical_digest,canonical_serialize
from .installed_d13_natural_frame_v6 import NaturalHistoryPairV6

@dataclass(frozen=True,slots=True)
class D13NaturalWirePreflightV6:
    pair: NaturalHistoryPairV6
    installed_policy_digest: str
    def __post_init__(self):
        if type(self.pair) is not NaturalHistoryPairV6 or self.pair.compressed is None:
            raise ValueError('v6 counter preflight requires both exact transient full wires')

@dataclass(frozen=True,slots=True)
class D13CountedNaturalPreflightV6:
    preflight: D13NaturalWirePreflightV6
    envelope_json: str
    status: str='non_authorizing_count_result'
    def __post_init__(self):
        if (type(self.preflight) is not D13NaturalWirePreflightV6 or self.status!='non_authorizing_count_result'
                or type(self.envelope_json) is not str or len(self.envelope_json.encode('utf-8'))+1>65536
                or canonical_serialize(json.loads(self.envelope_json))!=self.envelope_json):
            raise ValueError('v6 counter result requires the complete exact bounded signed envelope')
    @property
    def evidence_digest(self):
        return canonical_digest(json.loads(self.envelope_json))


def count_installed_d13_preflight_v6(db,*,graph_lock,bundle,preflight):
    from ..host.authority_profile import AdminInstallationBundle
    if (db.in_transaction or graph_lock._is_owned() or type(bundle) is not AdminInstallationBundle
            or type(preflight) is not D13NaturalWirePreflightV6
            or type(bundle.d13_wire_counter) is not InstalledD13CounterCommandV1
            or type(bundle.d13_wire_policy) is not InstalledD13WirePolicyV6
            or bundle.installation_policy.namespace!=preflight.pair.raw.input.plan.namespace
            or bundle.d13_wire_policy.policy_digest!=preflight.installed_policy_digest):
        raise ValueError('v6 counter needs actual installed policy/namespace and no transaction or Graph lock')
    request=d13_full_wire_count_request_v6(policy=bundle.d13_wire_policy,pair=preflight.pair)
    envelope=bundle.d13_wire_counter.count_outside_graph_transaction_v6(db=db,policy=bundle.d13_wire_policy,request=request)
    return D13CountedNaturalPreflightV6(preflight,canonical_serialize(envelope))


def record_counted_d13_preflight_v6(db,*,bundle,counted):
    from ..host.authority_profile import AdminInstallationBundle
    if (not db.in_transaction or type(bundle) is not AdminInstallationBundle
            or type(counted) is not D13CountedNaturalPreflightV6
            or type(bundle.d13_wire_policy) is not InstalledD13WirePolicyV6
            or counted.preflight.pair.raw.input.plan.namespace!=bundle.installation_policy.namespace
            or counted.preflight.installed_policy_digest!=bundle.d13_wire_policy.policy_digest):
        raise ValueError('v6 counter import needs its actual current fenced installed namespace/policy')
    envelope=json.loads(counted.envelope_json)
    payload=verify_signed_d13_wire_envelope_v6(bundle.d13_wire_policy,envelope)
    request=d13_full_wire_count_request_v6(policy=bundle.d13_wire_policy,pair=counted.preflight.pair)
    if any(payload[name]!=value for name,value in request['original'].items()):
        raise ValueError('v6 counter signature binds another original transient pair')
    return record_signed_d13_wire_evidence_v6(db,policy=bundle.d13_wire_policy,envelope=envelope)
