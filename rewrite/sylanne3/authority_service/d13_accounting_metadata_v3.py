"""Content-free D13 model accounting originals in the existing immutable HTTP store."""
from dataclasses import asdict, dataclass, fields
from hashlib import sha256
import json

from .contract import AuthorityUnavailable, identifier
from .v2_contract import FencePermitV2, from_wire as permit_from_wire
from .v2_model_egress_contract import (ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelAdmissionV2, ModelTerminalReceiptV2)
from .v2_model_egress_wire import from_wire as model_from_wire
from .d13_core_counter_contract_v1 import (D13CoreFrameIntentHeaderV7,
    D13CoreFullWireEnvelopeV1, d13_core_counter_from_wire_v1)
from ..model_broker.provider_billing_receipt_v1 import (ProviderBillingPolicyV1,
    ProviderBillingReceiptV1, provider_billing_policy_from_wire_v1,
    provider_billing_receipt_from_wire_v1, provider_billing_receipt_from_json_v1,
    provider_billing_receipt_signing_bytes_v1)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (read_core_payload_row_v3, insert_core_payload_row_v3,
    reserve_runtime_payload_v3, runtime_storage_operation_v3, runtime_storage_v3,
    runtime_storage_quantum_v3, begin_core_payload_read_v3, begin_core_payload_write_v3,
    runtime_source_identity_v4)
from .d13_provider_http_admission_v1 import TABLE

ADMISSION_PHASE = 'admission_accounting_lineage_v3'
TERMINAL_PHASE = 'terminal_accounting_metadata_v3'
SIGN_KIND = 'd11.model-terminal-accounting-metadata.v3'
_PHASES = (ADMISSION_PHASE, TERMINAL_PHASE)


def _shape(value, kind):
    if type(value) is not dict or set(value) != {field.name for field in fields(kind)}:
        raise AuthorityUnavailable('exact D13 accounting metadata fields required')
    return dict(value)


@dataclass(frozen=True, slots=True)
class D13AdmissionAccountingLineageV3:
    namespace: NamespaceId
    kind: str
    producer_operation_id: str
    request_phase: str
    prompt_template_digest: str
    intent: ModelEgressIntentV1
    admission: ModelAdmissionV2
    billing_policy: ProviderBillingPolicyV1 | None
    schema: str = 'sylanne3.d13.admission-accounting-lineage.v3'

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or type(self.intent) is not ModelEgressIntentV1
                or type(self.admission) is not ModelAdmissionV2
                or self.schema != 'sylanne3.d13.admission-accounting-lineage.v3'
                or (self.kind, self.request_phase) not in {
                    ('foreground_generation_v7', 'natural_generation'),
                    ('paid_precompression_v1', 'd13.precompress')}):
            raise ValueError('exact actual D13 accounting lineage required')
        identifier(self.producer_operation_id, 'producer_operation_id')
        if (self.intent.call_id, self.intent.request_digest, self.intent.namespace,
                self.intent.operation_id, self.intent.subject, self.intent.provider_config_digest) != (
                self.admission.call_id, self.admission.request_digest, self.admission.namespace,
                self.admission.operation_id, self.admission.subject, self.admission.provider_config_digest):
            raise ValueError('D13 accounting lineage admission differs')
        if self.billing_policy is not None:
            p = self.billing_policy
            if (type(p) is not ProviderBillingPolicyV1 or
                    (p.namespace, p.installation_id, p.manifest_digest, p.provider_id,
                     p.model_id, p.provider_config_digest) != (self.namespace,
                     self.admission.installation_id, self.admission.manifest_digest,
                     self.intent.provider_id, self.intent.model_id, self.intent.provider_config_digest)):
                raise ValueError('D13 billing snapshot crosses original installation or model')


@dataclass(frozen=True, slots=True)
class D13TerminalAccountingMetadataV3:
    lineage_digest: str
    terminal_state: str
    usage: tuple[tuple[str, int], ...]
    cost: tuple[tuple[str, int], ...]
    terminal_receipt: ModelTerminalReceiptV2
    provider_call_ref: str | None
    billing_receipt: ProviderBillingReceiptV1 | None
    schema: str = 'sylanne3.d13.terminal-accounting-metadata.v3'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.terminal-accounting-metadata.v3'
                or self.terminal_state != 'observed'
                or type(self.terminal_receipt) is not ModelTerminalReceiptV2):
            raise ValueError('actual completed D13 accounting metadata required')
        for pairs in (self.usage, self.cost):
            if (type(pairs) is not tuple or tuple(sorted(pairs)) != pairs
                    or len(dict(pairs)) != len(pairs)
                    or any(type(k) is not str or not k or type(v) is not int or v < 0 for k, v in pairs)):
                raise ValueError('original accounting dimensions must be distinct nonnegative integers')
        if self.provider_call_ref is not None:
            identifier(self.provider_call_ref, 'provider_call_ref')


@dataclass(frozen=True, slots=True)
class D13AccountingOriginalV3:
    phase: str
    payload: D13AdmissionAccountingLineageV3 | D13TerminalAccountingMetadataV3
    signature_kind: str
    signature: str
    schema: str = 'sylanne3.d13.accounting-metadata-original.v3'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.accounting-metadata-original.v3'
                or self.signature_kind != SIGN_KIND
                or (self.phase == ADMISSION_PHASE and type(self.payload) is not D13AdmissionAccountingLineageV3)
                or (self.phase == TERMINAL_PHASE and type(self.payload) is not D13TerminalAccountingMetadataV3)
                or self.phase not in _PHASES):
            raise ValueError('registered exact D13 accounting original required')


def accounting_original_from_wire_v3(raw):
    d = _shape(raw, D13AccountingOriginalV3)
    if d['phase'] == ADMISSION_PHASE:
        p = _shape(d['payload'], D13AdmissionAccountingLineageV3)
        p['namespace'] = NamespaceId(**_shape(p['namespace'], NamespaceId))
        p['intent'] = model_from_wire(p['intent'], ModelEgressIntentV1)
        p['admission'] = model_from_wire(p['admission'], ModelAdmissionV2)
        if p['billing_policy'] is not None:
            p['billing_policy'] = provider_billing_policy_from_wire_v1(p['billing_policy'])
        d['payload'] = D13AdmissionAccountingLineageV3(**p)
    elif d['phase'] == TERMINAL_PHASE:
        p = _shape(d['payload'], D13TerminalAccountingMetadataV3)
        for key in ('usage', 'cost'):
            p[key] = tuple(tuple(pair) for pair in p[key])
        p['terminal_receipt'] = model_from_wire(p['terminal_receipt'], ModelTerminalReceiptV2)
        if p['billing_receipt'] is not None:
            p['billing_receipt'] = provider_billing_receipt_from_wire_v1(p['billing_receipt'])
        d['payload'] = D13TerminalAccountingMetadataV3(**p)
    else:
        raise AuthorityUnavailable('unregistered D13 accounting phase')
    return D13AccountingOriginalV3(**d)


def verify_d13_accounting_original_v3(original, *, signer, phase):
    if type(original) is not D13AccountingOriginalV3 or original.phase != phase:
        raise AuthorityUnavailable('exact accounting original/phase required')
    signer.verify(SIGN_KIND, canonical_serialize(asdict(original.payload)), original.signature)
    return original.payload


def _read(db, *, intent, phase, signer):
    from .c09_d13_source_retirement_v3 import require_not_retired_d13_source_v3
    handle = runtime_storage_v3(db)
    control = None if handle is None else runtime_source_identity_v4(handle).control
    require_not_retired_d13_source_v3(db, control=control, namespace=intent.namespace,
        kind='http', item_id=intent.call_id)
    key = (intent.namespace, intent.call_id, phase)
    if runtime_storage_v3(db) is None:
        row = read_core_payload_row_v3(db, TABLE, key)
        if row is None:
            return None
        if sha256(row[0].encode('utf-8')).hexdigest() != row[1]:
            raise AuthorityUnavailable('D13 accounting original physical digest differs')
        raw = json.loads(row[0])
        if canonical_serialize(raw) != row[0]:
            raise AuthorityUnavailable('D13 accounting original canonical EOF differs')
    else:
        reader = begin_core_payload_read_v3(db, TABLE, key)
        try:
            while not reader.complete:
                with runtime_storage_quantum_v3(db) as meter:
                    reader.advance(meter=meter)
            eof = reader.require_v3(db, TABLE, key)
            if eof is None:
                return None
            raw = eof.decoded_v3(db, TABLE, key)
        finally:
            reader.release_payload_v3()
    with runtime_storage_quantum_v3(db):
        original = accounting_original_from_wire_v3(raw)
        p = verify_d13_accounting_original_v3(original, signer=signer, phase=phase)
    if phase == ADMISSION_PHASE and p.intent != intent:
        raise AuthorityUnavailable('D13 accounting lineage crossed actual model identity')
    return original


def _write(db, *, intent, admission, phase, payload, signer, lineage_digest):
    prior = _read(db, intent=intent, phase=phase, signer=signer)
    if prior is not None:
        if prior.payload != payload:
            raise AuthorityUnavailable('immutable D13 accounting replay conflicts')
        return prior
    with runtime_storage_quantum_v3(db):
        original = D13AccountingOriginalV3(phase, payload, SIGN_KIND,
            signer.sign(SIGN_KIND, canonical_serialize(asdict(payload))))
        reserve_runtime_payload_v3(db, original)
        encoded = canonical_serialize(asdict(original))
        if len(encoded.encode('utf-8')) > 65536:
            raise AuthorityUnavailable('D13 accounting metadata exceeds fixed original bound')
        digest = sha256(encoded.encode('utf-8')).hexdigest()
    read_proof = {'origin_kind': 'd13_accounting_metadata_v3', 'phase': phase,
        'call_id': intent.call_id, 'admission_id': admission.admission_id,
        'request_digest': intent.request_digest, 'original_digest': digest,
        'lineage_digest': lineage_digest}
    key = (intent.namespace, intent.call_id, phase)
    if runtime_storage_v3(db) is None:
        insert_core_payload_row_v3(db, TABLE, key, encoded, digest, read_proof=read_proof)
    else:
        writer = begin_core_payload_write_v3(db, TABLE, key, asdict(original))
        try:
            while writer.phase != 'ready':
                with runtime_storage_quantum_v3(db) as meter:
                    writer.advance(meter=meter)
            writer.attach_read_proof_v3(read_proof)
            while not writer.complete:
                with runtime_storage_quantum_v3(db) as meter:
                    writer.advance(meter=meter)
            actual = writer.require_v3(db, TABLE, key)
            if actual.digest != digest:
                raise AuthorityUnavailable('D13 accounting actual write/read-back EOF differs')
        finally:
            writer.release_payload_v3()
    return original


def record_d13_admission_accounting_lineage_v3(private_proof):
    from .v2_model_egress_service import require_actual_d13_admission_accounting_producer_v3
    service, db, intent, request, admission, permit, bundle, signer = require_actual_d13_admission_accounting_producer_v3(private_proof)
    from ..model_broker.natural_reply_history_v7 import TEMPLATE_DIGEST as foreground_template
    from ..model_broker.d13_precompression import TEMPLATE_DIGEST as paid_template
    if (request.identity.phase, request.prompt_template_digest) == ('natural_generation', foreground_template):
        kind = 'foreground_generation_v7'
        if service._d13_provider_http_counter_v1 is None:
            raise AuthorityUnavailable('actual V7 HTTP producer missing')
        expected = read_core_payload_row_v3(db, TABLE, (intent.namespace, intent.call_id, 'expected'))
        if expected is None:
            raise AuthorityUnavailable('V7 accounting admission lacks actual expected HTTP original')
    elif (request.identity.phase, request.prompt_template_digest) == ('d13.precompress', paid_template):
        kind = 'paid_precompression_v1'
    else:
        return None
    if (request.call_id, request.provider_id, request.model_id) != (intent.call_id, intent.provider_id, intent.model_id):
        raise AuthorityUnavailable('D13 accounting producer differs from actual admitted request')
    if (_read(db, intent=intent, phase=ADMISSION_PHASE, signer=signer) is None
            and _read(db, intent=intent, phase=TERMINAL_PHASE, signer=signer) is not None):
        raise AuthorityUnavailable('D13 first admission cannot backfill an orphan terminal projection')
    payload = D13AdmissionAccountingLineageV3(bundle.installation_policy.namespace, kind,
        request.identity.operation_id, request.identity.phase, request.prompt_template_digest,
        intent, admission, bundle.provider_billing_policy_v1)
    return _write(db, intent=intent, admission=admission, phase=ADMISSION_PHASE,
        payload=payload, signer=signer, lineage_digest=None)


def _billing(lineage, *, report, record):
    if report.billing_receipt_json is None or lineage.billing_policy is None:
        return None
    receipt = provider_billing_receipt_from_json_v1(report.billing_receipt_json)
    policy, intent, admission = lineage.billing_policy, lineage.intent, lineage.admission
    if (receipt.contract_digest, receipt.evidence_kind, receipt.installation_id,
            receipt.manifest_digest, receipt.provider_id, receipt.model_id,
            receipt.provider_config_digest, receipt.call_id, receipt.request_digest,
            receipt.provider_call_ref) != (policy.contract_digest, policy.evidence_kind,
            admission.installation_id, admission.manifest_digest, intent.provider_id,
            intent.model_id, intent.provider_config_digest, intent.call_id,
            intent.request_digest, report.provider_call_ref):
        raise AuthorityUnavailable('D13 signed final charge differs from original model/admission')
    if receipt.usage != dict(record.usage) or dict(record.cost).get('model_microusd') != receipt.final_charged_amount:
        raise AuthorityUnavailable('D13 final billing differs from actual terminal dimensions')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy.provider_ed25519_public_key_hex)).verify(
        bytes.fromhex(receipt.signature_hex), provider_billing_receipt_signing_bytes_v1(receipt))
    return receipt


def _terminal(private_proof, *, replay):
    from .v2_model_egress_service import (require_actual_d13_terminal_accounting_producer_v3,
        require_actual_d13_terminal_accounting_replay_v3)
    getter = require_actual_d13_terminal_accounting_replay_v3 if replay else require_actual_d13_terminal_accounting_producer_v3
    service, db, intent, admission, report, record, receipt, bundle, signer = getter(private_proof)
    lineage = _read(db, intent=intent, phase=ADMISSION_PHASE, signer=signer)
    if lineage is None:
        if _read(db, intent=intent, phase=TERMINAL_PHASE, signer=signer) is not None:
            raise AuthorityUnavailable('D13 terminal projection lost its original birth; no legacy downgrade')
        return None
    if lineage.payload.admission != admission:
        raise AuthorityUnavailable('D13 accounting terminal crossed original admission')
    payload = D13TerminalAccountingMetadataV3(canonical_digest(lineage), record.state,
        record.usage, record.cost, receipt, report.provider_call_ref,
        _billing(lineage.payload, report=report, record=record))
    if replay:
        original = _read(db, intent=intent, phase=TERMINAL_PHASE, signer=signer)
        if original is None or original.payload != payload:
            raise AuthorityUnavailable('recorded D13 accounting terminal missing or conflicting; no replay backfill')
        return original
    return _write(db, intent=intent, admission=admission, phase=TERMINAL_PHASE,
        payload=payload, signer=signer, lineage_digest=payload.lineage_digest)


def record_d13_terminal_accounting_metadata_v3(private_proof):
    return _terminal(private_proof, replay=False)


def verify_recorded_d13_terminal_accounting_metadata_v3(private_proof):
    return _terminal(private_proof, replay=True)


@dataclass(frozen=True, slots=True)
class D13CoreAccountingReadV3:
    namespace: NamespaceId
    record: ModelEgressRecoveryV1
    permit: FencePermitV2 | None
    admission: ModelAdmissionV2 | None
    terminal_receipt: ModelTerminalReceiptV2 | None
    lineage_original: D13AccountingOriginalV3 | None
    terminal_original: D13AccountingOriginalV3 | None
    frame: D13CoreFrameIntentHeaderV7 | None
    evidence: D13CoreFullWireEnvelopeV1 | None
    http_expected: dict | None
    http_observed: dict | None
    schema: str = 'sylanne3.d13.core-accounting-read.v3'

    def __post_init__(self):
        if (self.schema != 'sylanne3.d13.core-accounting-read.v3'
                or type(self.namespace) is not NamespaceId or type(self.record) is not ModelEgressRecoveryV1):
            raise ValueError('exact content-free D13 Core accounting read required')


def accounting_core_read_from_wire_v3(raw):
    d = _shape(raw, D13CoreAccountingReadV3)
    d['namespace'] = NamespaceId(**_shape(d['namespace'], NamespaceId))
    d['record'] = model_from_wire(d['record'], ModelEgressRecoveryV1)
    if d['permit'] is not None:
        d['permit'] = permit_from_wire(d['permit'])
        if type(d['permit']) is not FencePermitV2:
            raise AuthorityUnavailable('accounting original model permit wire differs')
    for key, kind in (('admission', ModelAdmissionV2), ('terminal_receipt', ModelTerminalReceiptV2)):
        if d[key] is not None:
            d[key] = model_from_wire(d[key], kind)
    for key in ('lineage_original', 'terminal_original'):
        if d[key] is not None:
            d[key] = accounting_original_from_wire_v3(d[key])
    for key, kind in (('frame', D13CoreFrameIntentHeaderV7), ('evidence', D13CoreFullWireEnvelopeV1)):
        if d[key] is not None:
            d[key] = d13_core_counter_from_wire_v1(d[key], kind)
    return D13CoreAccountingReadV3(**d)


def read_d13_model_accounting_metadata_v3(model_service, *, server, bundle, credential, subject, namespace, call_id):
    """Authenticated current metadata only; old absent projections remain unmigrated."""
    from .v2_model_egress_service import require_installed_d13_accounting_metadata_producer_v3
    from .d13_provider_http_admission_v1 import (require_recorded_provider_http_binding_v1,
        verify_historical_provider_http_phase_v1, _read_counter_phase)
    require_installed_d13_accounting_metadata_producer_v3(model_service, server=server, bundle=bundle)
    if type(namespace) is not NamespaceId or namespace != bundle.installation_policy.namespace:
        raise AuthorityUnavailable('D13 accounting namespace differs from actual installation')
    identifier(call_id, 'call_id')
    fences = model_service._fences
    fences.core._require(credential, 'read', fences.namespace)
    signer = model_service._graph_verifier._issuer._signer
    with runtime_storage_operation_v3(model_service._store._db, operation_id='d13-accounting-read:'+call_id):
        with fences._frozen() as (db, deletion_head, execution_head, _):
            fences._current_locked(db, deletion_head, execution_head, holder=subject)
            record = model_service._store._read(db, call_id)
            if record is None or record.intent.namespace != fences.namespace or record.intent.subject != subject:
                raise AuthorityUnavailable('D13 accounting call lacks its actual subject/namespace original')
            intent = record.intent
            has_admission = db.execute('SELECT 1 FROM authority_model_admissions_v2 WHERE call_id=?', (call_id,)).fetchone()
            admission, report_digest, receipt = ((None, None, None) if has_admission is None else
                model_service._store.read_admission_locked(db, intent))
            row = fences.fences._row(db, intent.operation_id)
            permit = None if row is None else fences.fences._permit(row)
            if receipt is not None and (row is None or row[6] != 'finished' or row[10] is not None
                    or row[8:10] != (call_id, receipt.finish_digest)
                    or receipt.observation_digest != record.observation_digest
                    or report_digest != receipt.report_digest):
                raise AuthorityUnavailable('D13 accounting terminal lost actual Core fence/receipt')
            lineage = _read(db, intent=intent, phase=ADMISSION_PHASE, signer=signer)
            terminal = _read(db, intent=intent, phase=TERMINAL_PHASE, signer=signer)
            if lineage is not None and ((receipt is not None and terminal is None)
                    or (record.state == 'observed' and (receipt is None or terminal is None))):
                raise AuthorityUnavailable('D13 recorded birth/actual Core terminal has no atomic accounting projection')
            if terminal is not None and (lineage is None or terminal.payload.lineage_digest != canonical_digest(lineage)
                    or terminal.payload.terminal_receipt != receipt
                    or terminal.payload.usage != record.usage or terminal.payload.cost != record.cost):
                raise AuthorityUnavailable('D13 accounting projection differs from actual terminal')
            frame = evidence = expected = observed = None
            if lineage is not None and lineage.payload.kind == 'foreground_generation_v7' and receipt is not None:
                counter = model_service._d13_provider_http_counter_v1
                if counter is None:
                    raise AuthorityUnavailable('D13 historical HTTP verifier missing')
                expected = require_recorded_provider_http_binding_v1(db, counter=counter, intent=intent, admission=admission)
                raw = read_core_payload_row_v3(db, TABLE, (intent.namespace, call_id, 'observed_before_send'))
                observed = json.loads(raw[0])
                verify_historical_provider_http_phase_v1(counter, observed, phase='observed_before_send', intent=intent, admission=admission)
                op = expected['counter_operation_id']
                frame = d13_core_counter_from_wire_v1(_read_counter_phase(db, counter, op, 'header'), D13CoreFrameIntentHeaderV7)
                evidence = d13_core_counter_from_wire_v1(_read_counter_phase(db, counter, op, 'evidence'), D13CoreFullWireEnvelopeV1)
            return D13CoreAccountingReadV3(namespace, record, permit, admission, receipt,
                lineage, terminal, frame, evidence, expected, observed)


D13_ACCOUNTING_PHASES_V3 = frozenset(_PHASES)


def verify_d13_accounting_source_originals_v3(lineage_original, terminal_original, *,
        signer, namespace, authority_namespace, authority_id, installation_id, manifest_digest,
        intent, admission, record, terminal_receipt, original_permit, fence_state,
        finish_request_id, finish_digest):
    """Verify captured metadata originals against their independently read Core facts."""
    lineage = verify_d13_accounting_original_v3(lineage_original, signer=signer, phase=ADMISSION_PHASE)
    if (type(namespace) is not NamespaceId or type(intent) is not ModelEgressIntentV1
            or type(admission) is not ModelAdmissionV2 or type(record) is not ModelEgressRecoveryV1
            or lineage.namespace != namespace or lineage.intent != intent
            or lineage.admission != admission or record.intent != intent
            or (intent.authority_id, intent.namespace, admission.installation_id, admission.manifest_digest) !=
                (authority_id, authority_namespace, installation_id, manifest_digest)):
        raise AuthorityUnavailable('captured D13 accounting lineage crosses actual installed model originals')
    from ..model_broker.natural_reply_history_v7 import TEMPLATE_DIGEST as foreground_template
    from ..model_broker.d13_precompression import TEMPLATE_DIGEST as paid_template
    expected_template = foreground_template if lineage.kind == 'foreground_generation_v7' else paid_template
    if lineage.prompt_template_digest != expected_template:
        raise AuthorityUnavailable('captured D13 accounting producer template differs')
    if (type(original_permit) is not FencePermitV2
            or (original_permit.authority_id, original_permit.namespace, original_permit.subject,
                original_permit.operation, original_permit.operation_id, original_permit.token,
                original_permit.fence_epoch, original_permit.revision, original_permit.generation,
                canonical_digest(asdict(original_permit.pinned_anchor))) !=
               (intent.authority_id, intent.namespace, intent.subject, 'model_egress',
                intent.operation_id, intent.fence_token, intent.fence_epoch, intent.fence_revision,
                intent.authority_activation_generation, intent.anchor_digest)):
        raise AuthorityUnavailable('captured D13 accounting original model fence differs')
    if terminal_original is None:
        if terminal_receipt is not None or record.state == 'observed':
            raise AuthorityUnavailable('captured D13 accounting birth has a terminal but no exact receipt/projection')
        return lineage, None
    terminal = verify_d13_accounting_original_v3(terminal_original, signer=signer, phase=TERMINAL_PHASE)
    if (type(terminal_receipt) is not ModelTerminalReceiptV2
            or terminal.lineage_digest != canonical_digest(lineage_original)
            or terminal.terminal_receipt != terminal_receipt or terminal.terminal_state != record.state
            or terminal.usage != record.usage or terminal.cost != record.cost
            or record.observation_digest != terminal_receipt.observation_digest
            or (terminal_receipt.call_id, terminal_receipt.request_digest, terminal_receipt.admission_id,
                terminal_receipt.installation_id, terminal_receipt.host_incarnation) !=
               (intent.call_id, intent.request_digest, admission.admission_id,
                admission.installation_id, admission.host_incarnation)
            or (fence_state, finish_request_id, finish_digest) !=
               ('finished', intent.call_id, terminal_receipt.finish_digest)):
        raise AuthorityUnavailable('captured D13 terminal projection lost its actual terminal/finish chain')
    billing = terminal.billing_receipt
    if billing is not None:
        policy = lineage.billing_policy
        if policy is None or (billing.contract_digest, billing.evidence_kind, billing.installation_id,
                billing.manifest_digest, billing.provider_id, billing.model_id,
                billing.provider_config_digest, billing.call_id, billing.request_digest,
                billing.provider_call_ref) != (policy.contract_digest, policy.evidence_kind,
                installation_id, manifest_digest, intent.provider_id, intent.model_id,
                intent.provider_config_digest, intent.call_id, intent.request_digest,
                terminal.provider_call_ref):
            raise AuthorityUnavailable('captured D13 final charge differs from its original pinned billing policy')
        if billing.usage != dict(record.usage) or dict(record.cost).get('model_microusd') != billing.final_charged_amount:
            raise AuthorityUnavailable('captured D13 signed charge differs from actual Core terminal dimensions')
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy.provider_ed25519_public_key_hex)).verify(
            bytes.fromhex(billing.signature_hex), provider_billing_receipt_signing_bytes_v1(billing))
    return lineage, terminal

