"""Fixed historical Habit selector binding inside a signed W01 DomainOriginal."""
from dataclasses import asdict
import json
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId, canonical_digest

HABIT_ACTIVITY_PROVENANCE_V1 = 'habit_activity_execution_v1'
HABIT_ACTIVITY_KINDS_V1 = {
    'record_habit_window_cue_v1': 'd11',
    'register_habit_occurrence_v1': 'd10',
    'qualify_habit_occurrence_v1': 'd10',
    'instantiate_current_habit_source_note_context_v1': 'd08',
    'prepare_current_habit_source_note_action_v1': 'd08',
    'prepare_source_note_body': 'd02',
    'register_current_habit_source_note_life_plan_v1': 'd10',
    'prepare_life': 'd10',
}
_FIELDS = frozenset(('schema', 'selector', 'selector_digest', 'standing_original_ref',
    'standing_original_digest', 'current_original_ref', 'current_original_digest',
    'permit_operation_id', 'scope_binding_digest'))
from .habit_census_provenance_v1 import METADATA_FIELDS_V1,decode_habit_census_fields_v1


def habit_activity_selector_from_wire_v1(raw):
    from ..authority_service.d10_habit_contract_v1 import (
        habit_window_cue_selector_from_wire_v1, habit_occurrence_birth_from_wire_v1)
    from ..authority_service.d10_habit_execution_contract_v1 import habit_occurrence_execution_from_wire_v1
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    schema = raw['schema']
    if schema == 'd11.habit-window-cue-selector.v1':
        return habit_window_cue_selector_from_wire_v1(raw)
    if schema == 'd10.habit-occurrence-birth-selector.v1':
        return habit_occurrence_birth_from_wire_v1(raw)
    if schema == 'd10.habit-occurrence-selector.v1':
        return habit_value_from_wire_v1(schema, raw)
    if schema == 'd10.habit-occurrence-execution-selector.v1':
        return habit_occurrence_execution_from_wire_v1(raw)
    raise ValueError('unregistered historical Habit selector schema')


def _root_selector_v1(selector):
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    return selector.qualification_selector if type(selector) is HabitOccurrenceExecutionSelectorV1 else selector


def habit_activity_scope_binding_v1(selector, *, permit, graph_revision, graph_epoch):
    root = _root_selector_v1(selector)
    return canonical_digest(('d10.habit-activity-scope-binding.v1', selector.namespace,
        permit.namespace, permit.operation_id, permit.token, permit.generation, permit.pinned_anchor,
        graph_revision, graph_epoch, root.parent_root_grant_ref, root.parent_root_grant_digest,
        root.standing_authorization_original_ref, root.standing_authorization_original_digest))


def current_habit_activity_provenance_v1(issued, graph, scope, *, frame):
    from .habit_activity_issuance_v1 import require_habit_activity_issuance_v1
    evidence = require_habit_activity_issuance_v1(issued, graph, scope)
    current = evidence.qualification_original or evidence.timecue_original or evidence.policy_original
    selector = evidence.request
    from .current_habit_source_read_v3 import current_habit_frame_census_v3
    census=current_habit_frame_census_v3(frame)
    if census is None:raise ValueError('Habit execution provenance lost its actual private Source census')
    return {**census,'schema': 'd10.habit-activity-execution-provenance.v1',
        'selector': asdict(selector), 'selector_digest': canonical_digest(selector),
        'standing_original_ref': evidence.policy_original.original_ref,
        'standing_original_digest': evidence.policy_original.digest,
        'current_original_ref': current.original_ref, 'current_original_digest': current.digest,
        'permit_operation_id': scope.operation_id,
        'scope_binding_digest': habit_activity_scope_binding_v1(selector, permit=scope.permit,
            graph_revision=scope.graph_revision, graph_epoch=scope.graph_epoch.revision)}


def validate_habit_activity_provenance_v1(domain, operation_kind, raw):
    from .habit_activity_issuance_v1 import habit_activity_operation_kind_v1
    if (type(raw) is not dict or set(raw) not in (_FIELDS,_FIELDS|METADATA_FIELDS_V1)
            or raw['schema'] != 'd10.habit-activity-execution-provenance.v1'
            or HABIT_ACTIVITY_KINDS_V1.get(operation_kind) != domain):
        raise ValueError('Habit historical provenance has another fixed phase/schema')
    selector = habit_activity_selector_from_wire_v1(raw['selector'])
    root = _root_selector_v1(selector)
    if (habit_activity_operation_kind_v1(selector) != operation_kind
            or canonical_digest(selector) != raw['selector_digest']
            or selector.operation_id != raw['permit_operation_id']
            or (root.standing_authorization_original_ref, root.standing_authorization_original_digest)
                != (raw['standing_original_ref'], raw['standing_original_digest'])):
        raise ValueError('Habit historical selector changed its full command or standing original')
    for name in ('selector_digest', 'standing_original_digest', 'current_original_digest', 'scope_binding_digest'):
        value = raw[name]
        if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('Habit historical binding requires exact canonical digests')
    if type(raw['current_original_ref']) is not str or not raw['current_original_ref']:
        raise ValueError('Habit historical binding lost its actual Core original locator')
    metadata=(decode_habit_census_fields_v1({name:raw[name]for name in METADATA_FIELDS_V1})
        if set(raw)==_FIELDS|METADATA_FIELDS_V1 else())
    if any(NamespaceId.from_key(version.key)!=selector.namespace for version in metadata):
        raise ValueError('Habit execution metadata crosses the actual selector namespace')
    refs = (root.policy_ref, root.parent_root_grant_ref, raw['standing_original_ref'], raw['current_original_ref'],
        *(version.key.token for version in metadata))
    return selector, refs


def require_habit_attempt_payload_v1(db, row, *, original, permit):
    """Called only after actual signed DomainOriginal and real COMMIT validation."""
    from .habit_activity_issuance_v1 import habit_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    payload = original['payload']
    raw = payload['provenance'][HABIT_ACTIVITY_PROVENANCE_V1]
    selector, refs = validate_habit_activity_provenance_v1(original['domain'], original['operation_kind'], raw)
    operation = installed_operation_v1(original['operation_kind'])
    request = decode_typed_production_value_v1(payload['request'], operation.request_type)
    if (selector.namespace != NamespaceId(row[0], row[1]) or row[2] != row[4] or row[4] != selector.operation_id
            or row[3] != canonical_digest(selector) or selector.request_digest != habit_typed_command_digest_v1(operation, request)
            or permit.operation_id != selector.operation_id or permit.operation != 'write'
            or raw['scope_binding_digest'] != habit_activity_scope_binding_v1(selector,
                permit=permit, graph_revision=row[6], graph_epoch=row[7])
            or payload['parent_budget'] != _root_selector_v1(selector).parent_root_grant_ref):
        raise ValueError('Habit actual attempt/permit/Root/typed command differs from its signed original')
    return selector


def read_habit_attempt_original_row_v1(db, row, *, meter):
    """Authenticate the actual signed Habit W01 and its unchanged mechanical attempt."""
    import re
    from dataclasses import asdict
    from ..runtime_contracts import NamespaceId, canonical_serialize
    from .c09_foreground_attempt_v1 import TABLE, COLUMNS, _RECEIPT_FIELDS, ForegroundAttemptOriginalV1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1, _receipt_wire
    from .restore_anchor import RestoreAnchor
    from ..authority_service.v2_contract import FencePermitV2, from_wire
    if not db.in_transaction or len(row) != len(COLUMNS):
        raise AuthorityUnavailable('actual one-row foreground source snapshot required')
    actual = db.execute('SELECT * FROM ' + TABLE + ' WHERE bot=? AND persona=? AND operation_id=?', row[:3]).fetchone()
    if actual is None or tuple(actual) != tuple(row):
        raise AuthorityUnavailable('foreground source row differs from the actual selected Graph')
    if tuple(item[1] for item in db.execute('PRAGMA table_info(' + TABLE + ')')) != COLUMNS:
        raise AuthorityUnavailable('actual foreground source schema differs')
    namespace = NamespaceId(row[0], row[1])
    operation, request_digest, attempt = row[2:5]
    if (type(request_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", request_digest) is None
            or attempt != operation
            or any(type(value) is not int or value < 0 for value in row[6:8])
            or row[8] is None or row[9] is None):
        raise AuthorityUnavailable("C09 foreground original is pending or has an invalid fixed identity; HOLD")
    permit = from_wire(json.loads(row[8]))
    anchor = RestoreAnchor(**json.loads(row[5]))
    recovery = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
        namespace.as_tuple).fetchone()
    if recovery is None:
        raise AuthorityUnavailable("C09 foreground namespace has no real recovery identity")
    requirements = json.loads(recovery[0])
    if (type(permit) is not FencePermitV2 or permit.operation != "write" or permit.operation_id != attempt
            or permit.pinned_anchor != anchor or permit.generation != anchor.activation_generation
            or (permit.authority_id, permit.namespace) != (requirements["authority_id"], requirements["authority_namespace"])
            or canonical_serialize(asdict(anchor)) != row[5]
            or canonical_serialize(json.loads(row[8])) != row[8]):
        raise AuthorityUnavailable("C09 foreground original permit/anchor/namespace differs")
    original = read_adopted_domain_operation_v1(db, namespace, operation)
    saved = json.loads(row[9])
    if original is None or type(saved) is not dict or set(saved) != _RECEIPT_FIELDS:
        raise AuthorityUnavailable("C09 foreground saved receipt or actual adopted original is absent")
    from .habit_maintenance_provenance_v1 import MAINTENANCE_PROVENANCE_V1,require_habit_maintenance_attempt_payload_v1
    maintenance=MAINTENANCE_PROVENANCE_V1 in original['payload']['provenance']
    if maintenance:require_habit_maintenance_attempt_payload_v1(row,original=original,permit=permit)
    else:require_habit_attempt_payload_v1(db,row,original=original,permit=permit)
    receipt, payload = original["receipt"], original["payload"]
    expected_domain=('d10' if maintenance and original['operation_kind']in {'record_habit_miss_v1','adopt_habit_outcome_v1'}
        else HABIT_ACTIVITY_KINDS_V1.get(original['operation_kind']))
    if (expected_domain != original["domain"]
            or saved["schema"] != "sylanne.domain-production-receipt.v1"
            or (saved["domain"], saved["operation_kind"], saved["operation_id"], saved["activity_id"])
                != (original["domain"], original["operation_kind"], operation, receipt.activity_id)
            or saved["original_ref"] != original["domain"] + "-current:" + original["original_digest"][:48]
            or saved["original_digest"] != original["original_digest"]
            or saved["receipt"] != _receipt_wire(receipt) or saved["receipt_digest"] != canonical_digest(receipt)
            or payload["authority"]["activation_generation"] != permit.generation
            or receipt.status != "committed" or canonical_serialize(saved) != row[9]):
        raise AuthorityUnavailable("C09 foreground receipt differs from its actual W01 adoption")
    finish = "sha256:" + canonical_digest({"schema": ("w01.habit-maintenance-write.v1"if maintenance else"w01.habit-domain-write.v1"),
        "operation_id": operation, "request_digest": request_digest, "permit_token": permit.token})
    fence = db.execute("SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,"
        "post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation)).fetchone()
    if fence != (receipt.operation_digest, row[8], row[6], row[7], row[6] + 1, row[7] + 1,
            "finish:" + attempt, finish):
        raise AuthorityUnavailable("C09 foreground real bundle fence or foreground finish schema differs")
    return ForegroundAttemptOriginalV1(namespace, operation, attempt, request_digest, permit, finish, tuple(row))

