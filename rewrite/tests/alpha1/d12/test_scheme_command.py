"""D12 creator scheme commands remain candidates until W01 supplies authority."""

from dataclasses import replace

import pytest

from sylanne3.domains.d12 import (
    ActiveSchemeHeadV1, CharacterDraft, D12CurrentCreatorDraftV1,
    D12DomainCompileReceiptV1, active_scheme_head_key, character_draft_key,
    graph_type_specs, plan_creator_draft_update_v1,
    D12DomainCompileRejectionV1, D12SchemeDiagnosticV1,
    D12IsolatedPreviewV1, D12SchemeAdoptionReceiptV1,
    D12SchemeCommandIssuer, D12SchemeHold, compiled_scheme_digest_v1,
)
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId


class _TrustedPortStandIn:
    def __init__(self):
        namespace = NamespaceId("bot", "persona")
        draft_ref = character_draft_key(namespace).token
        head_ref = active_scheme_head_key(namespace).token
        draft = CharacterDraft(
            "persona", 2, {"d01.value": "care", "d04.recovery_rate": 0.2},
            {"d01.value": "administrative_edit",
             "d04.recovery_rate": "administrative_edit"},
        )
        self.frame = D12CurrentCreatorDraftV1(
            namespace, draft_ref, 2, draft, head_ref, 3, 12, 4, 5, True,
        )
        self.commits = 0
        self.compilation_originals = {}
        self.preview_originals = {}

    def with_current_creator_draft_v1(self, authority, lease, *, draft_ref,
                                      required_capability, project):
        assert lease is self
        assert draft_ref == self.frame.draft_ref
        assert required_capability == "workbench.create"
        return project(self.frame)

    def compile_domain_scheme_v1(self, *, domain, fields, field_input_digest):
        return D12DomainCompileReceiptV1(
            domain, tuple(item[0] for item in fields), field_input_digest,
            f"candidate:{domain}", "a" * 64,
        )

    def preview_isolated_scheme_v1(self, authority, lease, *, compiled):
        assert lease is self
        return D12IsolatedPreviewV1(
            compiled.compiled_digest, NamespaceId("sandbox", "persona"),
            compiled.draft_digest, compiled.graph_revision,
            compiled.graph_revision, (), (), (), "cost:preview",
        )

    def record_compilation_original_v1(self, authority, lease, *, compiled):
        self.compilation_originals[compiled.compiled_digest] = compiled

    def read_compilation_original_v1(self, authority, lease, *, compiled_digest):
        return self.compilation_originals.get(compiled_digest)

    def record_preview_original_v1(self, authority, lease, *, compiled, result,
                                   certificate):
        self.preview_originals[certificate.issuer_seal] = certificate

    def read_preview_original_v1(self, authority, lease, *, preview_seal):
        return self.preview_originals.get(preview_seal)

    def commit_current_scheme_v1(self, authority, lease, *, intent):
        assert lease is self
        self.commits += 1
        return D12SchemeAdoptionReceiptV1(
            intent.operation_id, intent.namespace, intent.compiled_digest,
            intent.expected_active_head_ref, intent.expected_active_head_revision,
            intent.expected_active_head_ref, intent.expected_active_head_revision + 1,
            13,
        )


def _authority():
    return AuthorityContext(
        "creator", "d12", "creator-capability", NamespaceId("bot", "persona"),
        ("persona",), "consolidation", ("owner",), "policy", 1,
    )


def test_missing_w01_port_holds_and_valid_chain_keeps_preview_separate():
    with pytest.raises(D12SchemeHold, match="W01 creator"):
        D12SchemeCommandIssuer(object())
    port = _TrustedPortStandIn()
    issuer = D12SchemeCommandIssuer(port)
    authority = _authority()
    compiled = issuer.compile_current(authority, port, draft_ref=port.frame.draft_ref)
    assert [item.domain for item in compiled.domain_receipts] == ["d01", "d04"]
    assert compiled_scheme_digest_v1(compiled) == compiled.compiled_digest
    assert compiled.status == "compiled_candidate_requires_current_adoption"
    preview = issuer.preview_isolated(authority, port, compiled=compiled)
    assert preview.status == "preview_candidate_no_adoption_authority"
    assert port.commits == 0
    intent = issuer.prepare_adoption(
        authority, port, operation_id="adopt:one", compiled=compiled,
        preview=preview,
    )
    assert intent.status == "hold_for_w01_atomic_adoption"
    assert intent.expected_graph_revision == port.frame.graph_revision
    receipt = issuer.adopt_current(authority, port, intent=intent)
    assert receipt.status == "coordinator_committed_scheme"
    assert port.commits == 1
    rollback = issuer.prepare_rollback(
        authority, historical_plan_ref="plan:old",
        active_head_ref=receipt.active_head_ref,
        active_head_revision=receipt.active_head_revision,
    )
    assert rollback.status == "hold_for_new_administrative_draft_and_recompile"


def test_trusted_port_receives_issuer_originals_only_after_valid_results():
    port = _TrustedPortStandIn()
    originals = []
    port.record_compilation_original_v1 = (
        lambda authority, lease, *, compiled:
            (originals.append(("compilation", compiled)),
             port.compilation_originals.__setitem__(compiled.compiled_digest, compiled)))
    port.record_preview_original_v1 = (
        lambda authority, lease, *, compiled, result, certificate:
            (originals.append(("preview", compiled, result, certificate)),
             port.preview_originals.__setitem__(certificate.issuer_seal, certificate)))
    issuer = D12SchemeCommandIssuer(port)
    compiled = issuer.compile_current(_authority(), port,
                                      draft_ref=port.frame.draft_ref)
    certificate = issuer.preview_isolated(_authority(), port, compiled=compiled)
    assert originals[0] == ("compilation", compiled)
    assert originals[1][0] == "preview"
    assert originals[1][1] == compiled
    assert originals[1][2].status == "isolated_preview_only"
    assert originals[1][3] == certificate


def test_issuer_holds_when_record_or_durable_readback_is_missing():
    port = _TrustedPortStandIn()
    port.record_compilation_original_v1 = None
    with pytest.raises(D12SchemeHold, match="recorder"):
        D12SchemeCommandIssuer(port).compile_current(
            _authority(), port, draft_ref=port.frame.draft_ref)

    port = _TrustedPortStandIn()
    port.read_compilation_original_v1 = None
    with pytest.raises(D12SchemeHold, match="durable compilation"):
        D12SchemeCommandIssuer(port).compile_current(
            _authority(), port, draft_ref=port.frame.draft_ref)

    port = _TrustedPortStandIn()
    issuer = D12SchemeCommandIssuer(port)
    compiled = issuer.compile_current(_authority(), port,
                                      draft_ref=port.frame.draft_ref)
    port.record_preview_original_v1 = None
    with pytest.raises(D12SchemeHold, match="preview original recorder"):
        issuer.preview_isolated(_authority(), port, compiled=compiled)
    port.record_preview_original_v1 = (
        lambda authority, lease, *, compiled, result, certificate: None)
    with pytest.raises(D12SchemeHold, match="durable preview"):
        issuer.preview_isolated(_authority(), port, compiled=compiled)


def test_same_issuer_hmac_does_not_bypass_a_missing_original():
    port = _TrustedPortStandIn()
    issuer = D12SchemeCommandIssuer(port)
    compiled = issuer.compile_current(_authority(), port,
                                      draft_ref=port.frame.draft_ref)
    port.compilation_originals.clear()
    with pytest.raises(D12SchemeHold, match="compiled scheme"):
        issuer.preview_isolated(_authority(), port, compiled=compiled)
    port.compilation_originals[compiled.compiled_digest] = compiled
    preview = issuer.preview_isolated(_authority(), port, compiled=compiled)
    port.preview_originals.clear()
    with pytest.raises(D12SchemeHold, match="compilation"):
        issuer.prepare_adoption(_authority(), port, operation_id="adopt:missing",
                                compiled=compiled, preview=preview)


def test_new_issuer_rejects_prior_compilation_without_trusted_original_read():
    port = _TrustedPortStandIn()
    first = D12SchemeCommandIssuer(port)
    compiled = first.compile_current(_authority(), port,
                                     draft_ref=port.frame.draft_ref)
    port.read_compilation_original_v1 = None
    with pytest.raises(D12SchemeHold, match="compiled scheme"):
        D12SchemeCommandIssuer(port).preview_isolated(
            _authority(), port, compiled=compiled)


def test_new_issuer_recovers_only_exact_trusted_compilation_and_preview_originals():
    port = _TrustedPortStandIn()
    compilations = {}
    previews = {}
    port.record_compilation_original_v1 = (
        lambda authority, lease, *, compiled:
            compilations.setdefault(compiled.compiled_digest, compiled))
    port.read_compilation_original_v1 = (
        lambda authority, lease, *, compiled_digest:
            compilations.get(compiled_digest))
    port.record_preview_original_v1 = (
        lambda authority, lease, *, compiled, result, certificate:
            previews.setdefault(certificate.issuer_seal, certificate))
    port.read_preview_original_v1 = (
        lambda authority, lease, *, preview_seal:
            previews.get(preview_seal))
    compiled = D12SchemeCommandIssuer(port).compile_current(
        _authority(), port, draft_ref=port.frame.draft_ref)
    preview = D12SchemeCommandIssuer(port).preview_isolated(
        _authority(), port, compiled=compiled)
    intent = D12SchemeCommandIssuer(port).prepare_adoption(
        _authority(), port, operation_id="adopt:restart",
        compiled=compiled, preview=preview)
    assert intent.preview_seal == preview.issuer_seal
    with pytest.raises(D12SchemeHold, match="compiled scheme"):
        D12SchemeCommandIssuer(port).preview_isolated(
            _authority(), port, compiled=replace(compiled, issuer_seal="forged"))
    with pytest.raises(D12SchemeHold, match="compilation"):
        D12SchemeCommandIssuer(port).prepare_adoption(
            _authority(), port, operation_id="adopt:tampered",
            compiled=compiled, preview=replace(preview, actual_cost_receipt_ref="forged"))


def test_creator_scope_old_draft_and_experiment_effects_fail_closed():
    port = _TrustedPortStandIn()
    issuer = D12SchemeCommandIssuer(port)
    authority = _authority()
    port.frame = replace(port.frame, creator_authorized=False)
    with pytest.raises(D12SchemeHold, match="creator Authority"):
        issuer.compile_current(authority, port, draft_ref=port.frame.draft_ref)
    port.frame = replace(port.frame, creator_authorized=True)
    compiled = issuer.compile_current(authority, port, draft_ref=port.frame.draft_ref)
    with pytest.raises(D12SchemeHold, match="compiled scheme"):
        issuer.preview_isolated(replace(authority, issuer_domain="d12",
                                        namespace=NamespaceId("bot", "other")),
                                port, compiled=compiled)
    port.frame = replace(port.frame, draft_revision=3,
                         draft=replace(port.frame.draft, revision=3))
    preview = issuer.preview_isolated(authority, port, compiled=compiled)
    with pytest.raises(D12SchemeHold, match="stale"):
        issuer.prepare_adoption(authority, port, operation_id="adopt:old",
                                compiled=compiled, preview=preview)
    port.frame = replace(port.frame, draft_revision=2,
                         draft=replace(port.frame.draft, revision=2))
    original = port.preview_isolated_scheme_v1
    port.preview_isolated_scheme_v1 = lambda *args, **kwargs: replace(
        original(*args, **kwargs), external_effect_refs=("effect:forbidden",),
    )
    with pytest.raises(D12SchemeHold, match="isolation"):
        issuer.preview_isolated(authority, port, compiled=compiled)
    assert port.commits == 0


def test_caller_forged_compilation_cannot_reach_commit():
    port = _TrustedPortStandIn()
    issuer = D12SchemeCommandIssuer(port)
    authority = _authority()
    compiled = issuer.compile_current(authority, port, draft_ref=port.frame.draft_ref)
    preview = issuer.preview_isolated(authority, port, compiled=compiled)
    with pytest.raises(D12SchemeHold, match="compilation"):
        issuer.prepare_adoption(
            authority, port, operation_id="adopt:forged",
            compiled=replace(compiled, draft_revision=99), preview=preview,
        )
    assert port.commits == 0


def test_unknown_field_is_preserved_as_a_located_compile_error():
    port = _TrustedPortStandIn()
    port.frame = replace(port.frame, draft=CharacterDraft(
        "persona", 2, {"d99.secret": "candidate"},
        {"d99.secret": "administrative_edit"},
    ))
    with pytest.raises(D12SchemeHold) as error:
        D12SchemeCommandIssuer(port).compile_current(
            _authority(), port, draft_ref=port.frame.draft_ref)
    assert error.value.code == "invalid_field_path"
    assert error.value.diagnostics[0].field_path == "d99.secret"
    assert port.frame.draft.fields["d99.secret"] == "candidate"
    assert port.commits == 0


@pytest.mark.parametrize("code,field", [
    ("conflicting_rule", "d01.value"),
    ("out_of_range", "d04.recovery_rate"),
])
def test_domain_compiler_rejection_retains_field_diagnostic(code, field):
    port = _TrustedPortStandIn()
    def reject(*, domain, fields, field_input_digest):
        if domain == field.partition(".")[0]:
            return D12DomainCompileRejectionV1(
                domain, tuple(item[0] for item in fields), field_input_digest,
                (D12SchemeDiagnosticV1(field, code, "Domain schema rejected this value"),),
            )
        return _TrustedPortStandIn.compile_domain_scheme_v1(
            port, domain=domain, fields=fields, field_input_digest=field_input_digest)
    port.compile_domain_scheme_v1 = reject
    with pytest.raises(D12SchemeHold) as error:
        D12SchemeCommandIssuer(port).compile_current(
            _authority(), port, draft_ref=port.frame.draft_ref)
    assert error.value.code == "domain_compile_rejected"
    assert error.value.diagnostics[0].field_path == field
    assert error.value.diagnostics[0].code == code
    assert port.commits == 0


def test_changed_graph_read_set_stales_adoption_even_when_draft_is_unchanged():
    port = _TrustedPortStandIn()
    issuer = D12SchemeCommandIssuer(port)
    compiled = issuer.compile_current(_authority(), port, draft_ref=port.frame.draft_ref)
    preview = issuer.preview_isolated(_authority(), port, compiled=compiled)
    port.frame = replace(port.frame, graph_revision=port.frame.graph_revision + 1)
    with pytest.raises(D12SchemeHold, match="stale"):
        issuer.prepare_adoption(_authority(), port, operation_id="adopt:stale",
                                compiled=compiled, preview=preview)
    assert port.commits == 0


def test_empty_initial_draft_and_active_head_are_versioned_graph_values():
    namespace = NamespaceId("bot", "persona")
    draft = CharacterDraft("persona", 1, {}, {})
    specs = {spec.name: spec for spec in graph_type_specs()}
    specs["d12.character_draft.v1"].validator({
        "schema": "d12.character_draft.v1", "scope": draft.scope,
        "revision": draft.revision, "fields": draft.fields,
        "field_sources": draft.field_sources,
    })
    head = ActiveSchemeHeadV1(
        "persona", 1, "a" * 64, character_draft_key(namespace).token,
        1, "b" * 64, None, "initial:one", "initial",
    )
    specs["d12.active_scheme_head.v1"].validator({
        "schema": "d12.active_scheme_head.v1",
        **{name: getattr(head, name) for name in head.__dataclass_fields__},
    })
    with pytest.raises(ValueError, match="prior digest"):
        replace(head, generation=2)
    with pytest.raises(ValueError, match="adoption kind"):
        replace(head, adoption_kind="rollback_history")


def test_draft_update_is_read_only_cas_candidate_and_keeps_unknown_fields():
    port = _TrustedPortStandIn()
    base = port.frame.draft
    proposed = CharacterDraft(
        "persona", 3, {**base.fields, "d99.unknown": {"raw": "kept"}},
        {**base.field_sources, "d99.unknown": "administrative_edit"},
    )
    decision = plan_creator_draft_update_v1(
        port.frame, _authority(), operation_id="edit:one",
        base_draft=base, proposed_draft=proposed,
    )
    assert decision.status == "candidate_requires_w01_cas"
    assert decision.expected_revision == 2
    assert decision.creator_changed_fields == ("d99.unknown",)
    assert decision.proposed_draft.fields["d99.unknown"] == {"raw": "kept"}
    assert port.commits == 0

    # The same operation cannot infer durable success from a matching value.
    advanced = replace(port.frame, draft_revision=3, draft=proposed,
                       graph_revision=13)
    repeated = plan_creator_draft_update_v1(
        advanced, _authority(), operation_id="edit:one",
        base_draft=base, proposed_draft=proposed,
    )
    assert repeated.status == "stale_requires_merge"
    assert repeated.proposed_draft is None
    assert repeated.conflicting_fields == ("d99.unknown",)


def test_concurrent_edits_return_three_way_conflicts_without_overwrite():
    port = _TrustedPortStandIn()
    base = port.frame.draft
    mine = CharacterDraft("persona", 3,
                          {**base.fields, "d01.value": "kindness"},
                          base.field_sources)
    theirs = CharacterDraft("persona", 3,
                            {**base.fields, "d01.value": "honesty"},
                            base.field_sources)
    frame = replace(port.frame, draft_revision=3, draft=theirs,
                    graph_revision=13)
    decision = plan_creator_draft_update_v1(
        frame, _authority(), operation_id="edit:two",
        base_draft=base, proposed_draft=mine,
    )
    assert decision.status == "stale_requires_merge"
    assert decision.creator_changed_fields == ("d01.value",)
    assert decision.concurrent_changed_fields == ("d01.value",)
    assert decision.conflicting_fields == ("d01.value",)
    assert decision.proposed_draft is None
    assert frame.draft.fields["d01.value"] == "honesty"


def test_disjoint_concurrent_edit_still_requires_explicit_merge():
    port = _TrustedPortStandIn()
    base = port.frame.draft
    mine = CharacterDraft("persona", 3,
                          {**base.fields, "d01.value": "kindness"},
                          base.field_sources)
    theirs = CharacterDraft("persona", 3,
                            {**base.fields, "d04.recovery_rate": 0.4},
                            base.field_sources)
    frame = replace(port.frame, draft_revision=3, draft=theirs,
                    graph_revision=13)
    decision = plan_creator_draft_update_v1(
        frame, _authority(), operation_id="edit:three",
        base_draft=base, proposed_draft=mine,
    )
    assert decision.status == "stale_requires_merge"
    assert decision.conflicting_fields == ()
    assert decision.creator_changed_fields == ("d01.value",)
    assert decision.concurrent_changed_fields == ("d04.recovery_rate",)
    assert decision.proposed_draft is None


def test_creator_read_rejects_a_port_returning_a_different_draft_ref():
    port = _TrustedPortStandIn()
    port.with_current_creator_draft_v1 = (
        lambda authority, lease, *, draft_ref, required_capability, project:
            project(port.frame))
    issuer = D12SchemeCommandIssuer(port)
    wrong = character_draft_key(NamespaceId("bot", "other")).token
    with pytest.raises(D12SchemeHold, match="ref differs"):
        issuer.read_current(_authority(), port, draft_ref=wrong)
    with pytest.raises(D12SchemeHold, match="ref differs"):
        issuer.compile_current(_authority(), port, draft_ref=wrong)
