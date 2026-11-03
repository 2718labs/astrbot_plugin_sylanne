"""Actual dedicated D01 transitions in an ordinary-origin metadata lineage.

This reader grants no claim or Source access. Actual Work-owned columns retain
closed controls and hash every omitted claim/write value to canonical EOF.
"""
from dataclasses import fields

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


DEDICATED_ORIGIN_KINDS_V3 = frozenset({
    'migrate_semantic_identity_v3', 'adopt_current_method_strategy_v1',
    'adopt_current_conditioned_self_v1', 'rollback_current_conditioned_strategy_v1',
    'adopt_ordinary_deep_growth_v1'})

_DOMAIN_FIELDS = frozenset({'schema', 'namespace', 'identity', 'authority',
    'owner_guard', 'now_utc', 'coverage', 'missing_inputs', 'continuation_ref',
    'request', 'read_versions', 'observed_originals', 'provenance', 'writes'})
_PROVENANCE_FIELDS = frozenset({'method_outcome_review_ref',
    'method_outcome_review_digest', 'semantic_identity_changed',
    'conditioned_candidate_ref', 'conditioned_candidate_digest',
    'conditioned_review_ref', 'rollback', 'conditioned_self_candidate'})
_REQUEST_FIELDS = frozenset({'expected_plan_head', 'expected_persona_head_id',
    'target_block_ids', 'plasticity_policy_ref', 'review_ref', 'candidate_ref',
    'expected_persona_head', 'general_request', 'rejected_strategy_ref'})


def _metadata_types_v3():
    from ..domains.d01.method_learning_v1 import MethodOutcomeReviewV1
    from ..domains.d01.conditioned_self_v1 import (
        ConditionedSelfReviewV1, ConditionedCapabilityRevisionV1,
        ConditionedStrategyRevisionV1)
    return (MethodOutcomeReviewV1, ConditionedSelfReviewV1,
        ConditionedCapabilityRevisionV1, ConditionedStrategyRevisionV1)


def ordinary_dedicated_metadata_retains_path_v3(path):
    if not path:
        return True
    if path[0] == 'writes':
        return len(path) < 3 or path[2] in {'key', 'dependencies'}
    if path[0] == 'request':
        return len(path) == 1 or path[1] in _REQUEST_FIELDS
    if path[0] == 'provenance':
        return len(path) == 1 or path[1] in _PROVENANCE_FIELDS
    # The graph values are four official metadata-only DTOs. Their exact full
    # field set is checked before typed decoding, rather than accepting a subset.
    metadata_fields = {f.name for cls in _metadata_types_v3() for f in fields(cls)}
    return path[0] in (_DOMAIN_FIELDS | metadata_fields)


def ordinary_dedicated_metadata_commits_path_v3(path):
    return not path or len(path) == 3 and path[0] == 'writes' and path[2] == 'value'


def _need(condition, reason):
    if not condition:
        raise AuthorityUnavailable(reason)


def _producer_column_v3(owner, operation_id):
    from .d01_ordinary_origin_read_v3 import _column, _fixed
    key = (*owner.namespace.as_tuple, operation_id)
    header = _fixed(owner, 'graph_domain_production_originals_v1',
        ('domain', 'operation_kind', 'original_digest', 'bundle_digest', 'receipt_digest'),
        'bot=? AND persona=? AND operation_id=?', key)
    _need(header is not None and header[0] == 'd01',
        'dedicated ordinary origin has no actual D01 producer')
    column = _column(owner, 'graph_domain_production_originals_v1',
        'original_payload_json', ('bot', 'persona', 'operation_id'), key,
        'ordinary_dedicated_producer_v3')
    _need(column.semantic_digest == header[2],
        'dedicated ordinary origin producer whole canonical EOF differs')
    return header, column


def _typed_history_v3(owner, ref, cls, reads, producer_kind):
    from .d01_ordinary_origin_read_v3 import _fixed, _column, _typed, _versions
    from .role_control_lineage_metadata_v4 import _qualified_operation_control_v4
    key = AtomKey.from_token(ref)
    from ..domains.d01.method_learning_v1 import VALUE_TYPES as method_types
    from ..domains.d01.conditioned_self_v1 import VALUE_TYPES as conditioned_types
    _need({**method_types, **conditioned_types}.get(key.type_name) is cls,
        'dedicated metadata locator has another registered graph family')
    versions = tuple(v for v in reads if v.key == key and v.revision > 0)
    _need(len(versions) == 1 and NamespaceId.from_key(key) == owner.namespace,
        'dedicated metadata has no exact original read-version membership')
    version = versions[0]
    row = _fixed(owner, 'graph_history',
        ('valid', 'event_bot', 'event_persona', 'event_session', 'event_id', 'value_cell_id'),
        'token=? AND revision=?', (ref, version.revision))
    _need(row is not None and row[:3] == (1, *owner.namespace.as_tuple),
        'dedicated metadata history is absent/invalid/foreign')
    column = _column(owner, 'graph_history', 'value', ('token', 'revision'),
        (ref, version.revision), 'ordinary_dedicated_producer_v3', cell_id=row[5])
    _need(column.fields[()] == {f.name for f in fields(cls)},
        'dedicated metadata is not its complete official closed DTO')
    value = _typed(column.metadata, cls)
    payload, receipt, digest, event = _qualified_operation_control_v4(owner, row[4], producer_kind)
    header, producer = _producer_column_v3(owner, row[4])
    _need(header[1] == producer_kind and header[2] == digest
        and row[3] == event.scope.session and version in receipt.write_versions
        and _versions(producer.metadata['read_versions']) == receipt.read_versions,
        'dedicated metadata is not a member of its actual complete W01 producer')
    writes = producer.metadata['writes']
    matched = tuple(i for i, write in enumerate(writes) if _typed(write['key'], AtomKey) == key)
    _need(len(writes) == len(receipt.write_versions) and len(matched) == 1
        and producer.commitments[('writes', matched[0], 'value')] == column.semantic_digest,
        'dedicated metadata typed write differs from its actual historical value')
    from ..domains.d01.production_operations_v1 import plain_v1
    _need(canonical_digest(plain_v1(value)) == column.semantic_digest,
        'dedicated metadata typed bytes differ from full canonical EOF')
    return value, column.semantic_digest


def _carry_dedicated_v3(owner, before, after, kind, column, reads):
    from .d01_ordinary_origin_read_v3 import _typed
    from ..domains.d01.production_operations_v1 import MigrateSemanticIdentityRequestV3, plain_v1
    from .d01_method_learning_v1 import AdoptCurrentMethodStrategyRequestV1
    from .conditioned_self_operations_v1 import (
        AdoptCurrentConditionedSelfRequestV1, RollbackCurrentConditionedStrategyRequestV1)
    from ..domains.d01.method_learning_v1 import MethodOutcomeReviewV1, POLICY_ID
    from ..domains.d01.conditioned_self_v1 import (
        ConditionedCapabilityRevisionV1, ConditionedStrategyRevisionV1, ConditionedSelfReviewV1)
    types = {
        'migrate_semantic_identity_v3': MigrateSemanticIdentityRequestV3,
        'adopt_current_method_strategy_v1': AdoptCurrentMethodStrategyRequestV1,
        'adopt_current_conditioned_self_v1': AdoptCurrentConditionedSelfRequestV1,
        'rollback_current_conditioned_strategy_v1': RollbackCurrentConditionedStrategyRequestV1}
    cls = types[kind]
    _need(column.fields[('request',)] == {f.name for f in fields(cls)},
        'dedicated head transition has another actual typed request')
    request = _typed(column.metadata['request'], cls)
    old = {v.block_id: v for v in before.blocks}
    new = {v.block_id: v for v in after.blocks}
    changed = tuple(k for k in old if old[k] != new[k])
    provenance = column.metadata['provenance']
    if kind == 'migrate_semantic_identity_v3':
        _need(request.expected_plan_head == before.plan_ref
            and request.expected_persona_head_id == before.head_id
            and set(changed) == set(request.target_block_ids)
            and all(old[k].kind == new[k].kind == 'semantic_identity'
                and new[k].claim_protocol == 'd01.semantic-identity-revision.v3' for k in changed),
            'semantic migration changed another block or predecessor')
    elif kind == 'adopt_current_method_strategy_v1':
        review, digest = _typed_history_v3(owner, request.review_ref,
            MethodOutcomeReviewV1, reads, 'review_current_method_growth_v1')
        target = review.target_block
        _need(changed == (target,) and review.namespace == owner.namespace
            and review.base_persona_head == before.head_id and review.qualification == 'qualified'
            and not review.missing_items and not review.counter_interpretation_refs
            and provenance['method_outcome_review_ref'] == request.review_ref
            and provenance['method_outcome_review_digest'] == digest
            and provenance['semantic_identity_changed'] is False
            and old[target].kind == new[target].kind == 'strategy'
            and old[target].plasticity == new[target].plasticity == 'growth'
            and (old[target].claim_digest == canonical_digest(canonical_serialize({
                'schema': 'd01.method-policy.v1', 'policy_id': POLICY_ID, 'strategy_state': 'ST0'}))
                or _require_method_predecessor_metadata_v3(owner,before,target))
            and new[target].claim_digest == canonical_digest(canonical_serialize({
                'schema': 'd01.method-policy.v1', 'policy_id': POLICY_ID, 'strategy_state': 'ST2'})),
            'method transition lost its actual qualified review/ST0 to ST2 target')
    else:
        raw_candidate = provenance['conditioned_self_candidate']
        schema = raw_candidate['schema']
        candidate_cls = {
            'd01.conditioned-capability-revision.v1': ConditionedCapabilityRevisionV1,
            'd01.conditioned-strategy-revision.v1': ConditionedStrategyRevisionV1}.get(schema)
        _need(candidate_cls is not None, 'unregistered conditioned candidate schema')
        candidate, digest = _typed_history_v3(owner, request.candidate_ref,
            candidate_cls, reads, 'review_current_conditioned_self_v1')
        review_ref = candidate.last_review_ref if candidate_cls is ConditionedCapabilityRevisionV1 else candidate.review_ref
        review, _ = _typed_history_v3(owner, review_ref, ConditionedSelfReviewV1,
            reads, 'review_current_conditioned_self_v1')
        target = review.target_block
        rollback = kind == 'rollback_current_conditioned_strategy_v1'
        identity = candidate.runtime_identity
        _need(changed == (target,) and request.expected_persona_head == before.plan_ref
            and review.expected_persona_head == before.plan_ref
            and review.candidate_ref == request.candidate_ref
            and review.runtime_identity == identity
            and identity.namespace == owner.namespace
            and provenance['conditioned_candidate_ref'] == request.candidate_ref
            and provenance['conditioned_candidate_digest'] == digest
            and provenance['conditioned_review_ref'] == review_ref
            and provenance['rollback'] is rollback and raw_candidate == plain_v1(candidate)
            and candidate.valid_from <= column.metadata['now_utc'] < candidate.valid_until
            and review.qualification == ('rollback_evidence_qualified' if rollback else 'qualified')
            and old[target].kind == new[target].kind == (
                'self_knowledge' if candidate_cls is ConditionedCapabilityRevisionV1 else 'strategy')
            and old[target].plasticity == new[target].plasticity == 'growth'
            and new[target].claim_digest == canonical_digest(canonical_serialize(plain_v1(candidate)))
            and new[target].claim_protocol == candidate.schema,
            'conditioned transition differs from its exact typed candidate/review/claim')
        guard = column.metadata['owner_guard']
        _need(identity.authority_id == guard['authority_id']
            and identity.installation_id == guard['installation_id'],
            'conditioned candidate belongs to another actual producer installation')
        if candidate.previous_ref is not None:
            previous, _ = _typed_history_v3(owner, candidate.previous_ref,
                candidate_cls, reads, 'review_current_conditioned_self_v1')
            _need(candidate.revision == previous.revision + 1
                and old[target].claim_digest == canonical_digest(canonical_serialize(plain_v1(previous))),
                'conditioned transition replaced another previous candidate')
        else:
            _need(candidate.revision == 1, 'initial conditioned revision is not one')
        if rollback:
            _need(candidate_cls is ConditionedStrategyRevisionV1
                and request.rejected_strategy_ref == candidate.previous_ref
                and candidate.qualification == 'rolled_back' and candidate.counterexamples,
                'conditioned rollback has no actual rejected predecessor/counterexamples')
    _need(changed, 'dedicated head transition changed no actual block')
    for key in changed:
        _need(new[key].kind == 'semantic_identity' or new[key].claim_protocol is not None,
            'dedicated producer cannot introduce an unauthenticated ordinary claim')
    return changed


def _signed_cumulative_v3(owner, ref, kind, expected=None):
    from .d01_ordinary_origin_read_v3 import _column, _fixed, _typed
    from .d01_ordinary_cumulative_growth_v1 import ORIGINAL_TYPES, _require_signed_ordinary_producer_v1
    from ..domains.d01.ordinary_cumulative_growth_v1 import POLICY_KIND, ASSESSMENT_KIND, DEEP_ADOPTION_KIND
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    header = _fixed(owner, 'graph_d01_production_inputs_v1',
        ('kind', 'producing_operation_id', 'payload_digest', 'signature'),
        'bot=? AND persona=? AND original_ref=?', (*owner.namespace.as_tuple, ref))
    _need(header is not None and header[0] == kind, 'actual signed ordinary cumulative original missing')
    profile = {POLICY_KIND: 'ordinary_cumulative_policy',
        ASSESSMENT_KIND: 'ordinary_continuity_assessment', DEEP_ADOPTION_KIND: 'ordinary_deep_adoption'}[kind]
    column = _column(owner, 'graph_d01_production_inputs_v1', 'payload_json',
        ('bot', 'persona', 'original_ref'), (*owner.namespace.as_tuple, ref), profile, signed_header=header)
    _need(column.signature_verified and column.semantic_digest == header[2],
        'ordinary deep original full canonical EOF/signature differs')
    value = _typed(column.metadata, ORIGINAL_TYPES[kind])
    original = ProductionOriginalRefV1('d01.' + kind, ref, header[2])
    if expected is not None:
        _need((original.kind, original.original_ref, original.original_digest) ==
            (expected.kind, expected.original_ref, expected.original_digest),
            'ordinary deep original locator/digest differs')
    payload, receipt, event = _require_signed_ordinary_producer_v1(owner, ref, value, header)
    return value, original, payload, receipt, event


def _deep_origin_v3(owner, lineage, before, after, operation, producer_digest, anchor, transitions):
    from .d01_ordinary_origin_read_v3 import _column, _signed, _references, _fixed
    from .d01_ordinary_cumulative_growth_v1 import ordinary_deep_anchor_key_v1
    from ..domains.d01.ordinary_cumulative_growth_v1 import (
        DEEP_ADOPTION_KIND, POLICY_KIND, ASSESSMENT_KIND, OrdinaryContinuityAnchorV1,
        ordinary_history_metrics_v1, evaluate_ordinary_continuity_v1)
    from .d01_ordinary_origin_v3 import OrdinaryBlockOriginV3, _source_selections_v3
    deep, original, payload, receipt, event = _signed_cumulative_v3(
        owner, 'ordinary-deep:' + operation, DEEP_ADOPTION_KIND)
    _need(deep.base_head == before and deep.successor_head == after
        and deep.activation_operation_id == operation and deep.prior_anchor == anchor,
        'deep origin lost its actual previous/successor head and preceding signed anchor')
    total, count, digest = ordinary_history_metrics_v1(anchor.head, before, tuple(transitions))
    _need((deep.history.anchor_head, deep.history.current_head, deep.history.transition_count,
        deep.history.ordinary_change_count, deep.history.chain_digest) ==
        (anchor.head.head_id, before.head_id, total, count, digest),
        'deep origin skipped an actual preceding transition')
    policy, _, _, _, _ = _signed_cumulative_v3(owner, deep.policy_original.original_ref,
        POLICY_KIND, deep.policy_original)
    assessment, _, _, _, _ = _signed_cumulative_v3(owner, deep.assessment_original.original_ref,
        ASSESSMENT_KIND, deep.assessment_original)
    _need(assessment.policy_original == deep.policy_original and assessment.anchor == anchor
        and assessment.base_head == before and assessment.candidate_blocks == after.blocks
        and assessment.phase == 'deep_review'
        and assessment.decision in {'deep_accepted', 'preserved'}
        and assessment.candidate_proposal_original == deep.proposal_original
        and assessment.trial_originals == deep.trial_originals
        and assessment.counter_query_original == deep.counter_query_original,
        'deep origin lost its actual accepted assessment/policy/candidate')
    evaluate_ordinary_continuity_v1(policy, assessment, transitions=tuple(transitions))
    observed = _references(payload['observed_originals'])
    proposal_column, proposal_ref, _, roots = _signed(owner, deep.proposal_original.original_ref,
        'proposal', {'growth_proposal'}, observed)
    proposal = proposal_column.metadata
    target = deep.changed_block_ids[0]
    block = next(v for v in after.blocks if v.block_id == target)
    _need(proposal_ref.original_digest == deep.proposal_original.original_digest
        and proposal['base_head'] == before.head_id and proposal['target_block'] == target
        and proposal_column.commitments[('replacement_claim',)] == block.claim_digest
        and tuple(proposal['required_trial_refs']) == tuple(v.original_ref for v in deep.trial_originals)
        and set(proposal['evidence_source_refs']) == set(roots)
        and tuple(deep.support_source_refs) == assessment.support_source_refs,
        'deep origin proposal actual signed replacement/trials/Source roots differ')
    from .d01_ordinary_origin_v3 import OrdinaryOriginalReferenceV3
    related = [OrdinaryOriginalReferenceV3(v.kind,v.original_ref,v.original_digest)
        for v in (original,deep.policy_original,deep.assessment_original)] + [proposal_ref]
    for trial in deep.trial_originals:
        column, ref, _, _ = _signed(owner, trial.original_ref, 'trial', {'general_growth_trial_v1'}, observed)
        value = column.metadata
        _need(ref.original_digest == trial.original_digest and value['completed'] is True
            and value['growth_proposal_ref'] == proposal_ref.original_ref
            and value['settled_outcome_refs'], 'deep origin has another/unsettled actual trial')
        related.append(ref)
    counter_column, counter, _, _ = _signed(owner, deep.counter_query_original.original_ref,
        'counter', {'growth_counterevidence'}, observed)
    cv = counter_column.metadata
    _need(counter.original_digest == deep.counter_query_original.original_digest
        and cv['growth_proposal_ref'] == proposal_ref.original_ref and cv['coverage_complete'] is True,
        'deep origin counter query differs or is incomplete')
    related.append(counter)
    marker_key = ordinary_deep_anchor_key_v1(owner.namespace, operation)
    version = tuple(v for v in receipt.write_versions if v.key == marker_key)
    _need(len(version) == 1 and version[0].revision == 1, 'deep origin lacks unique marker WRITE1')
    row = _fixed(owner, 'graph_history',
        ('valid', 'event_bot', 'event_persona', 'event_session', 'event_id', 'value_cell_id'),
        'token=? AND revision=?', (marker_key.token, 1))
    _need(row is not None and row[:5] == (1, *owner.namespace.as_tuple, receipt.activity_id, operation),
        'deep marker has another actual producer history')
    marker = _column(owner, 'graph_history', 'value', ('token', 'revision'),
        (marker_key.token, 1), 'ordinary_deep_anchor', cell_id=row[5]).metadata
    from ..domains.d01.ordinary_cumulative_growth_v1 import OrdinaryDeepGrowthAnchorV1
    from .d01_ordinary_origin_read_v3 import _typed
    marker_value = _typed(marker, OrdinaryDeepGrowthAnchorV1)
    _need(marker_value.operation_id == operation
        and marker_value.namespace == owner.namespace
        and marker_value.policy_original == deep.policy_original
        and marker_value.assessment_original == deep.assessment_original
        and marker_value.base_head == before.head_id and marker_value.successor_head == after.head_id,
        'deep marker differs from actual signed deep admission')
    source_column = _column(owner, 'graph_d01_production_inputs_v1', 'source_refs_json',
        ('bot', 'persona', 'original_ref'), (*owner.namespace.as_tuple, original.original_ref), 'activation')
    source_roots = tuple(source_column.metadata)
    _need(set(source_roots) == set((*assessment.support_source_refs, *assessment.context_source_refs))
        and set(marker_value.source_refs) == set(source_roots),
        'deep origin complete signed Source closure differs')
    support = _source_selections_v3(owner.namespace, source_roots,
        {v.key: v.revision for v in receipt.read_versions})
    owner.origin_support_readsets[proposal_ref.original_ref] = {
        v.key: v.revision for v in receipt.read_versions}
    revision = tuple(v for v in receipt.write_versions if v.key.type_name == 'd01.persona_revision.v1')
    _need(len(revision) == 1, 'deep origin actual revision member is not unique')
    lineage.origins[target] = OrdinaryBlockOriginV3(
        after.namespace, after.head_id, after.plan_ref, after.activation_ref,
        block, 'ordinary_deep_growth_v1', lineage.initial_head, lineage.initial_receipt_digest,
        after.head_id, revision[0], operation, producer_digest,
        proposal_ref.original_ref, proposal_ref.original_digest,
        tuple(v.original_ref for v in deep.trial_originals), counter.original_ref,
        support, tuple(related))
    return OrdinaryContinuityAnchorV1('deep', original, after, canonical_digest(receipt))


def advance_dedicated_ordinary_origins_v3(owner, lineage, before, after, members, anchor, transitions):
    """Consume only registered, actual committed dedicated producers."""
    from .d01_ordinary_origin_read_v3 import _actual
    from .d01_ordinary_origin_v3 import _same_owner
    from .role_control_lineage_metadata_v4 import _transition_v4
    _actual(owner)
    operation = members[0].event_id
    checked, transition = _transition_v4(owner, before, after.plan_ref, operation)
    kind, _, digest, receipt_digest, event_digest, reads, writes = transition
    _need(checked == after and lineage.head == before and kind in DEDICATED_ORIGIN_KINDS_V3
        and after.values_digest == before.values_digest and after.authored is False
        and tuple(v.block_id for v in before.blocks) == tuple(v.block_id for v in after.blocks),
        'dedicated ordinary transition changed its actual head/census/values')
    _same_owner(before, after)
    if kind == 'adopt_ordinary_deep_growth_v1':
        anchor = _deep_origin_v3(owner, lineage, before, after, operation, digest, anchor, transitions)
        transitions = []
    else:
        header, column = _producer_column_v3(owner, operation)
        _need(header[1] == kind and header[2] == digest, 'dedicated producer changed its authenticated identity')
        changed = _carry_dedicated_v3(owner, before, after, kind, column, reads)
        for target in changed:
            lineage.origins.pop(target, None)
        transitions = [*transitions, (before, after, kind, digest, receipt_digest, event_digest)]
    lineage.head = after
    return anchor, transitions

def new_method_policy_metadata_scan_v3():
    # Only three short string fields can survive. Non-JSON ordinary claims
    # immediately cease this optional metadata scan; their Body is not retained.
    return {'state': 'open', 'raw': [], 'escaped': False, 'key': None, 'values': {}}


def feed_method_policy_metadata_v3(scan, char):
    state = scan['state']
    if state == 'invalid':
        return
    if state in {'key_string', 'value_string'}:
        raw = scan['raw']
        raw.append(char)
        if len(raw) > 1024:
            scan.clear(); scan['state'] = 'invalid'
            return
        if scan['escaped']:
            scan['escaped'] = False
            return
        if char == '\\':
            scan['escaped'] = True
            return
        if char != '"':
            return
        import json
        try:
            value = json.loads(''.join(raw))
        except ValueError:
            scan.clear(); scan['state'] = 'invalid'
            return
        scan['raw'] = []
        if state == 'key_string':
            if value not in {'schema', 'policy_id', 'strategy_state'} or value in scan['values']:
                scan.clear(); scan['state'] = 'invalid'
                return
            scan['key'], scan['state'] = value, 'colon'
        else:
            scan['values'][scan['key']] = value
            scan['key'], scan['state'] = None, 'comma_or_end'
        return
    if char in ' \t\r\n':
        return
    if state == 'open' and char == '{':
        scan['state'] = 'key_or_end'
    elif state in {'key_or_end', 'key_required'} and char == '"':
        scan['state'], scan['raw'] = 'key_string', ['"']
    elif state == 'key_or_end' and char == '}':
        scan['state'] = 'end'
    elif state == 'colon' and char == ':':
        scan['state'] = 'value'
    elif state == 'value' and char == '"':
        scan['state'], scan['raw'] = 'value_string', ['"']
    elif state == 'comma_or_end' and char == ',':
        scan['state'] = 'key_required'
    elif state == 'comma_or_end' and char == '}':
        scan['state'] = 'end'
    else:
        scan.clear(); scan['state'] = 'invalid'


def finish_method_policy_metadata_v3(scan):
    from ..domains.d01 import METHOD_POLICY_SCHEMA_V1, METHOD_POLICY_ID_V1
    if scan is None or scan['state'] != 'end':
        return None
    values = scan['values']
    if (set(values) != {'schema', 'policy_id', 'strategy_state'}
            or values['schema'] != METHOD_POLICY_SCHEMA_V1
            or values['policy_id'] != METHOD_POLICY_ID_V1
            or values['strategy_state'] not in {'ST0', 'ST2'}):
        return None
    return values['strategy_state']


def _require_method_predecessor_metadata_v3(owner, before, target):
    from .d01_ordinary_origin_read_v3 import _actual, _history, OrdinaryOriginColumnV3
    _actual(owner)
    member, column = _history(owner, before.plan_ref.key, before.plan_ref.revision, 'plan')
    _need(type(column) is OrdinaryOriginColumnV3,
        'method predecessor requires its actual registered ordinary READ column')
    column.require_v3()  # Actual private _COLUMNS identity, Work and selection.
    positions = tuple(i for i, block in enumerate(before.blocks) if block.block_id == target)
    _need(len(positions) == 1, 'method predecessor block index is not unique')
    i = positions[0]
    path = ('blocks', i, 'claim')
    block = before.blocks[i]
    _need(column.owner is owner and column.complete and column.profile == 'plan'
        and column.table == 'graph_history' and column.column == 'value'
        and column.key_columns == ('token', 'revision')
        and column.key == (before.plan_ref.key.token, before.plan_ref.revision)
        and member.ref == before.plan_ref and member.value_digest == before.plan_value_digest
        and column.semantic_digest == before.plan_value_digest
        and column.metadata['blocks'][i]['block_id'] == target
        and column.commitments[path] == block.claim_digest
        and column.parser.method_policy_claims.get(path) == 'ST0',
        'method predecessor is not the exact full-EOF closed ST0 claim of its original CAS head')
    return True

