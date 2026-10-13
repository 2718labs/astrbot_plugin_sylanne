"""Current review accepts same-version originals and rejects mixed seal pairs."""
from dataclasses import fields, replace
import json
import pytest
from test_natural_review import _frozen_and_seals, _pass_text
from rewrite.tests.alpha1.d09.test_natural_reply import _case
from sylanne3.model_broker.natural_review import freeze_natural_reply_review_v1, parse_natural_reply_review_output_v1
from sylanne3.runtime_contracts import NaturalReplyReviewOriginalSealV2, canonical_digest
from sylanne3.runtime.natural_original_v3 import NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3
from sylanne3.runtime.natural_original_v4 import NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4
from sylanne3.runtime.natural_original_v6 import NaturalReplyGenerationOriginalSealV6, NaturalReplyReviewOriginalSealV6
from sylanne3.runtime.natural_original_v7 import NaturalReplyGenerationOriginalSealV7, NaturalReplyReviewOriginalSealV7


def case(version):
    old_generation, old_frozen, old_review = _frozen_and_seals()
    generation_type, review_type = {
        3: (NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3),
        4: (NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4),
        6: (NaturalReplyGenerationOriginalSealV6, NaturalReplyReviewOriginalSealV6),
        7: (NaturalReplyGenerationOriginalSealV7, NaturalReplyReviewOriginalSealV7),
    }[version]
    values = {f.name: getattr(old_generation, f.name) for f in fields(old_generation) if f.name not in {"schema", "template_version"}}
    values.update(original_operation_id=f"generation-original-v{version}", call_id=f"generation-call-v{version}",
                  frozen_input_digest=canonical_digest({"independent_fixture_generation": version}))
    generation = generation_type(**values)
    plan, _, output = _case()
    if version in (6, 7):
        from sylanne3.domains.d09.natural_reply import NATURAL_REPLY_OUTPUT_SCHEMA_V3
        output.update(schema=NATURAL_REPLY_OUTPUT_SCHEMA_V3,
                      semantic_segments=[{'start': 0, 'end': len(output['body'])}])
    frozen = freeze_natural_reply_review_v1(generation, output, plan.units, (), old_frozen.review_policy_version, old_frozen.installation)
    values = {f.name: getattr(old_review, f.name) for f in fields(old_review) if f.name not in {"schema", "template_version"}}
    values.update(generation_original_operation_id=generation.original_operation_id, generation_call_id=generation.call_id,
        generation_frozen_input_digest=generation.frozen_input_digest, generation_output_digest=frozen.generation_output_digest,
        review_frozen_input_digest=frozen.digest, model_request_digest=frozen.wire_digest)
    return generation, frozen, review_type(**values), values


@pytest.mark.parametrize("version", [3, 4, 6, 7])
def test_review_retains_same_version_generation_and_original_identity(version):
    generation, frozen, review, _ = case(version)
    result = parse_natural_reply_review_output_v1(review_text(version), frozen, generation, review)
    assert result.status == "untrusted_review_candidate"
    assert review.generation_frozen_input_digest == generation.frozen_input_digest
    assert generation.schema.endswith(f".v{version}") and review.schema.endswith(f".v{version}")


@pytest.mark.parametrize("version", [3, 4, 6, 7])
def test_review_cannot_mix_new_generation_with_legacy_review_seal(version):
    generation, frozen, _, values = case(version)
    with pytest.raises(TypeError, match="typed frozen review"):
        parse_natural_reply_review_output_v1(review_text(version), frozen, generation, NaturalReplyReviewOriginalSealV2(**values))


def review_text(version):
    if version not in (6, 7):
        return _pass_text()
    from sylanne3.model_broker.natural_review import OUTPUT_SCHEMA_V2
    return json.dumps({'schema': OUTPUT_SCHEMA_V2, 'verdict': 'pass', 'issues': [], 'prefix_safe': True})


@pytest.mark.parametrize('version', [6, 7])
def test_semantic_review_rejects_cross_version_pair_and_changed_output_identity(version):
    generation, frozen, review, values = case(version)
    other_type = NaturalReplyReviewOriginalSealV7 if version == 6 else NaturalReplyReviewOriginalSealV6
    with pytest.raises(TypeError, match='typed frozen review'):
        parse_natural_reply_review_output_v1(review_text(version), frozen, generation, other_type(**values))
    changed = replace(review, generation_output_digest='f' * 64)
    with pytest.raises(ValueError, match='not bound'):
        parse_natural_reply_review_output_v1(review_text(version), frozen, generation, changed)


def test_v7_review_freeze_rejects_unknown_generation_type_and_changed_basis():
    generation, frozen, _, _ = case(7)
    plan, _, output = _case()
    from sylanne3.domains.d09.natural_reply import NATURAL_REPLY_OUTPUT_SCHEMA_V3
    output.update(schema=NATURAL_REPLY_OUTPUT_SCHEMA_V3,
                  semantic_segments=[{'start': 0, 'end': len(output['body'])}])
    class UnknownGeneration(NaturalReplyGenerationOriginalSealV7):
        pass
    values = {field.name: getattr(generation, field.name) for field in fields(generation)}
    with pytest.raises(TypeError, match='typed generation'):
        freeze_natural_reply_review_v1(UnknownGeneration(**values), output, plan.units, (),
                                     frozen.review_policy_version, frozen.installation)
    with pytest.raises(ValueError, match='qualified basis differs'):
        freeze_natural_reply_review_v1(replace(generation, qualified_units_digest='f' * 64),
                                     output, plan.units, (), frozen.review_policy_version, frozen.installation)


@pytest.mark.parametrize('version', [6, 7])
def test_review_issuer_saves_same_version_original_and_reservation(monkeypatch, version):
    """Issuer/SQLite protocol seam; no installed budget or paid execution claim."""
    import sqlite3
    from types import SimpleNamespace
    from sylanne3.runtime.budget import BudgetLease, create_budget_lease, get_budget_lease, install_schema
    from sylanne3.runtime.jobs import get_job, install_schema as install_jobs_schema
    from sylanne3.runtime.issuers import BudgetLeaseGrant
    from sylanne3.runtime import natural_reply_budget_v3, natural_reply_job_v2
    from sylanne3.runtime.natural_review_issue_v2 import issue_original_natural_review_in_transaction_v2
    from sylanne3.runtime.natural_reply_job_v2 import SavedNaturalPreparationV2
    from sylanne3.runtime_contracts import QueryEpoch
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION_V2
    generation_seal, frozen, _, _ = case(version)
    plan, reads, _ = _case()
    generation = SavedNaturalPreparationV2('generation', generation_seal.c02_operation_id,
        generation_seal, SimpleNamespace(input=SimpleNamespace(plan=plan)), reads,
        (QueryEpoch(plan.namespace, 'all', 1),), 1, 0, 0, 'terminal',
        'b'*64, 1, 'c'*64, frozen.generation_output_digest)
    ceiling = {'tokens': 100}
    workflow = SimpleNamespace(quote_ceiling=ceiling, work_kind='natural_review', purpose='proposal',
        template_version=REVIEW_TEMPLATE_VERSION_V2, audiences=(plan.audience_id,),
        provider_id=frozen.installation.provider_id, model_id=frozen.installation.model_id,
        provider_config_digest=frozen.installation.provider_config_digest,
        provider_config_ref='review-config', max_output_tokens=frozen.installation.max_output_tokens,
        timeout_seconds=10.0)
    installed = SimpleNamespace(installation_policy=SimpleNamespace(namespace=plan.namespace,
        installation_id=frozen.installation.installation_id),
        model_workflows=SimpleNamespace(natural_review=workflow))
    grant = BudgetLeaseGrant('review-grant', 1, *plan.namespace.as_tuple,
        generation_seal.parent_budget_lease_id, 'USD', ceiling, ('natural_review',), 150.0, 'review-policy')
    db = sqlite3.connect(':memory:')
    try:
        install_schema(db); install_jobs_schema(db)
        db.execute('BEGIN')
        create_budget_lease(db, BudgetLease(grant.lease_id, None, *plan.namespace.as_tuple,
            'USD', {'tokens': 200}, {}, {}, {}, 1, 'active'), 'create:review-budget', 'd'*64)
        monkeypatch.setattr(natural_reply_budget_v3, 'resolve_natural_reply_budget_for_original_admission_v3',
            lambda *_args, **_kwargs: (get_budget_lease(db, grant.lease_id), grant))
        read_preparation = natural_reply_job_v2.read_original_preparation
        monkeypatch.setattr(natural_reply_job_v2, 'read_original_preparation',
            lambda read_db, namespace, parent, stage: generation if
            (read_db is db and namespace == plan.namespace and parent == generation.parent_original_id
             and stage == 'generation') else read_preparation(read_db, namespace, parent, stage))
        quotes = []
        def issue(original):
            return issue_original_natural_review_in_transaction_v2(db,
                generation=original, adopted_plan=SimpleNamespace(review_ceiling=tuple(ceiling.items())),
                frozen=frozen, read_versions=reads, query_epochs=generation.query_epochs, graph_epoch=1,
                access_epoch=0, deletion_epoch=0, installed_bundle=installed,
                d02_issuer=SimpleNamespace(issue_quote=lambda read_db, value: quotes.append(value)),
                d11_issuer=object(), now_utc=110.0)
        from sylanne3.runtime.natural_review_issue_v2 import NaturalReviewIssueHold
        class UnknownGeneration(type(generation_seal)):
            pass
        values = {field.name: getattr(generation_seal, field.name) for field in fields(generation_seal)}
        with pytest.raises(NaturalReviewIssueHold, match='unknown natural generation original version'):
            issue(replace(generation, seal=UnknownGeneration(**values)))
        with pytest.raises(NaturalReviewIssueHold, match='scope or parent budget changed'):
            issue(replace(generation, state='cancelled'))
        assert quotes == [] and get_budget_lease(db, grant.lease_id).reserved == {}
        assert db.execute('SELECT 1 FROM runtime_jobs').fetchone() is None
        job, quote, _, seal = issue(generation)
        assert quotes == [quote] and get_job(db, job.job_id) == job
        assert seal.schema == f'sylanne.d09.natural_review_seal.v{version}'
        assert seal.generation_frozen_input_digest == generation_seal.frozen_input_digest
        assert seal.reservation_operation_id == quote.operation_id
        assert get_budget_lease(db, grant.lease_id).reserved == ceiling
        raw = db.execute('SELECT seal_json FROM graph_natural_review_preparations_v2').fetchone()
        saved_seal = natural_reply_job_v2._seal('review', json.loads(raw[0]))
        assert type(saved_seal) is type(seal) and saved_seal == seal
        parsed = parse_natural_reply_review_output_v1(review_text(version), frozen, generation_seal, saved_seal)
        assert parsed.status == 'untrusted_review_candidate'
        db.rollback()
        assert db.execute('SELECT 1 FROM runtime_jobs').fetchone() is None
    finally:
        db.close()
