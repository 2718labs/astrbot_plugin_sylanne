"""Closed installed Contact accounting routes on the existing authenticated channel."""
from .contract import AuthorityUnavailable, identifier
from .contact_effect_accounting_contract_v1 import (
    SignedContactEffectBudgetOriginV1, ContactSenderMeasurementV1,
    ContactEffectAccountingRequestV1, ContactEffectAccountingGrantV1, to_wire, from_wire, encoded_v1,
)
from .v2_contract import from_wire as authority_from_wire

_METHODS = frozenset({"contact_effect_measurement_record_v1", "contact_effect_cost_fact_v1",
    "contact_effect_accounting_begin_v1", "contact_effect_accounting_validate_v1",
    "contact_effect_accounting_finish_v1", "contact_effect_accounting_recover_finish_v1"})


def dispatch_contact_effect_accounting_v1(server, method, credential, profile_id, manifest_digest, command):
    if method not in _METHODS: return None
    expected = {"namespace", "request"}
    if method.endswith("measurement_record_v1"):
        expected = {"namespace", "origin", "measurement", "observation", "claimed_receipt"}
    elif method.endswith("cost_fact_v1"):
        expected = {"namespace", "origin"}
    elif method in {"contact_effect_accounting_validate_v1", "contact_effect_accounting_finish_v1"}:
        expected.add("grant")
    if type(command) is not dict or set(command) != expected:
        raise AuthorityUnavailable("Contact accounting exact command fields differ")
    namespace = identifier(command["namespace"], "namespace")
    server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    service = server._contact_effect_accounting_v1.get((namespace, installed.installation_id))
    subject = "mtls:sha256:" + credential.certificate_sha256
    if (service is None or service.accounting is not server._v2_accounting.get(namespace)
            or server._accounting_observers_v2.get(namespace) != (credential.certificate_sha256, profile_id)
            or service.subject != subject or service.holder != installed.administrator_holder):
        raise AuthorityUnavailable("actual designated Contact accounting observer is unavailable")
    if method == "contact_effect_measurement_record_v1":
        result = service.record_measurement(credential=credential, subject=subject,
            origin=from_wire(command["origin"], SignedContactEffectBudgetOriginV1),
            measurement=from_wire(command["measurement"], ContactSenderMeasurementV1),
            observation=authority_from_wire(command["observation"]),
            claimed_receipt=authority_from_wire(command["claimed_receipt"]))
    elif method == "contact_effect_cost_fact_v1":
        result = service.read_fact(credential=credential, subject=subject,
            origin=from_wire(command["origin"], SignedContactEffectBudgetOriginV1))
    else:
        request = from_wire(command["request"], ContactEffectAccountingRequestV1)
        if method == "contact_effect_accounting_begin_v1":
            result = service.begin(credential=credential, subject=subject, request=request)
        elif method == "contact_effect_accounting_recover_finish_v1":
            service.recover_finish(credential=credential, subject=subject, request=request)
            result = True
        else:
            grant = from_wire(command["grant"], ContactEffectAccountingGrantV1)
            operation = service.validate if method == "contact_effect_accounting_validate_v1" else service.finish
            operation(credential=credential, subject=subject, request=request, grant=grant)
            result = True
    if result is not True: encoded_v1(result)
    return {"result": result if result is True else to_wire(result)}
