"""D06 expression evidence cannot promote a report into an external fact."""

from dataclasses import replace

import pytest

from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d06.qualified_expression import (
    QualifiedExpressionRequest, SourceTextSpan, prepare_qualified_expression_unit,
    recompute_qualified_expression_unit,
)
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")
REPORTED = "Alice said the payment was not sent on Friday."
OBSERVED = "The payment was not sent on Friday."


def fixture():
    atoms = []
    for source_id, text, source_kind, assertion_status, parents in (
        ("report", REPORTED, "reported", "reported", ("parent",)),
        ("observed", OBSERVED, "observed", "confirmed", ()),
        ("parent", "Alice privately described the invoice.", "reported", "reported", ()),
    ):
        record = SourceRecord(
            source_id, text, "alice", source_kind, assertion_status, 3.0, 4.0,
            "family-1", ("owner",), ("expression",), parents,
        )
        atoms.extend((
            GraphAtom(source_key(*NAMESPACE.as_tuple, source_id), 1,
                      record.to_dict()),
            GraphAtom(access_key(*NAMESPACE.as_tuple, source_id), 1,
                      {"source_id": source_id, "audiences": ["owner"],
                       "purposes": ["expression"], "status": "active",
                       "recorded_at": 4.0}),
            GraphAtom(source_correction_head_key(NAMESPACE, source_id), 0, {}, False),
        ))
    return GraphSnapshot(tuple(atoms), (NamespaceEpoch(*NAMESPACE.as_tuple, 5),))


def request(source_id, claim_kind, text, *, quote=None, negation=None):
    return QualifiedExpressionRequest(
        source_key(*NAMESPACE.as_tuple, source_id).token,
        claim_kind, SourceTextSpan(0, len(text)),
        SourceTextSpan(*quote) if quote else None,
        text[quote[0]:quote[1]] if quote else None,
        SourceTextSpan(*negation) if negation else None,
    )


def prepare(snapshot, expression_request, audiences=("owner",)):
    return prepare_qualified_expression_unit(
        snapshot, namespace=NAMESPACE, request=expression_request,
        audiences=audiences, access_epoch=2, deletion_epoch=0,
        valid_until=20.0,
    )


def changed(snapshot, key, *, revision=None, valid=None, **value):
    return replace(snapshot, atoms=tuple(
        replace(atom, revision=atom.revision if revision is None else revision,
                valid=atom.valid if valid is None else valid,
                value={**atom.value, **value})
        if atom.key == key else atom for atom in snapshot.atoms
    ))


def test_report_stays_attributed_and_cannot_become_confirmed_external_fact():
    snapshot = fixture()
    report = prepare(snapshot, request("report", "attributed_report", REPORTED))
    assert report.attribution_required
    assert report.claim_kind == "attributed_report"
    assert report.speaker_id == "alice"
    assert report.occurred_at == 3.0 and report.learned_at == 4.0
    assert report.status == "candidate_hold_semantic_review_and_authority"
    assert len(report.lineage_source_refs) == 2
    report.assert_current(snapshot, access_epoch=2, deletion_epoch=0, now=10.0)
    with pytest.raises(ValueError, match="reported or unconfirmed"):
        prepare(snapshot, request("report", "confirmed_external_fact", REPORTED))
    report_key = source_key(*NAMESPACE.as_tuple, "report")
    merely_marked_confirmed = changed(snapshot, report_key,
                                       assertion_status="confirmed")
    with pytest.raises(ValueError, match="reported or unconfirmed"):
        prepare(merely_marked_confirmed,
                request("report", "confirmed_external_fact", REPORTED))
    observed_key = source_key(*NAMESPACE.as_tuple, "observed")
    unconfirmed_observation = changed(snapshot, observed_key,
                                      assertion_status="reported")
    with pytest.raises(ValueError, match="reported or unconfirmed"):
        prepare(unconfirmed_observation,
                request("observed", "confirmed_external_fact", OBSERVED))


def test_confirmed_observation_retains_exact_quote_and_negation_cue():
    snapshot = fixture()
    quote = (4, len(OBSERVED) - 1)
    negation = (16, 19)
    candidate = prepare(snapshot, request(
        "observed", "confirmed_external_fact", OBSERVED,
        quote=quote, negation=negation,
    ))
    assert candidate.direct_quote_text == OBSERVED[quote[0]:quote[1]]
    assert candidate.polarity_status == "source_cue_unreviewed"
    assert not candidate.attribution_required
    assert candidate.source_excerpt == OBSERVED
    wrong_quote = replace(request("observed", "confirmed_external_fact", OBSERVED,
                                  quote=quote), direct_quote_text="payment was sent")
    with pytest.raises(ValueError, match="exactly"):
        prepare(snapshot, wrong_quote)
    with pytest.raises(ValueError, match="negation span exceeds evidence"):
        prepare(snapshot, replace(request("observed", "confirmed_external_fact",
                                          OBSERVED), evidence_span=SourceTextSpan(0, 10),
                                  negation_cue_span=SourceTextSpan(*negation)))


def test_ancestor_restriction_and_current_barriers_invalidate_candidate():
    snapshot = fixture()
    expression_request = request("report", "attributed_report", REPORTED)
    candidate = prepare(snapshot, expression_request)
    parent_access = access_key(*NAMESPACE.as_tuple, "parent")
    withdrawn = changed(snapshot, parent_access, revision=2, status="withdrawn")
    with pytest.raises(PermissionError, match="unavailable"):
        prepare(withdrawn, expression_request)
    with pytest.raises(ValueError, match="closure changed"):
        candidate.assert_current(withdrawn, access_epoch=2, deletion_epoch=0, now=10.0)
    corrected = changed(snapshot, source_correction_head_key(NAMESPACE, "parent"),
                        revision=1, valid=True, correction_id="new")
    with pytest.raises(ValueError, match="corrected"):
        prepare(corrected, expression_request)
    with pytest.raises(ValueError, match="stale or expired"):
        candidate.assert_current(snapshot, access_epoch=3, deletion_epoch=0, now=10.0)
    with pytest.raises(ValueError, match="stale or expired"):
        candidate.assert_current(snapshot, access_epoch=2, deletion_epoch=0, now=21.0)
    with pytest.raises(PermissionError, match="unavailable"):
        prepare(snapshot, expression_request, ("owner", "group"))


def test_current_recompute_rejects_tampered_candidate_and_permission_change():
    snapshot = fixture()
    candidate = prepare(snapshot, request("report", "attributed_report", REPORTED))

    def recompute(value, current=snapshot, *, access_epoch=2, audiences=("owner",)):
        return recompute_qualified_expression_unit(
            current, namespace=NAMESPACE, candidate=value, audiences=audiences,
            access_epoch=access_epoch, deletion_epoch=0, now=10.0,
        )

    assert recompute(candidate) == candidate
    assert candidate.qualification_digest == candidate.unit_id.removeprefix(
        "d06-qualified:")
    with pytest.raises(ValueError, match="qualification changed"):
        recompute(replace(candidate, speaker_id="bob"))
    with pytest.raises(ValueError, match="qualification changed"):
        recompute(replace(candidate, unit_id="d06-qualified:forged"))
    with pytest.raises(PermissionError, match="audience changed"):
        recompute(candidate, audiences=("group",))
    report_access = access_key(*NAMESPACE.as_tuple, "report")
    withdrawn = changed(snapshot, report_access, revision=2, status="withdrawn")
    with pytest.raises(PermissionError, match="unavailable"):
        recompute(candidate, withdrawn)
    with pytest.raises(ValueError, match="qualification changed"):
        recompute(candidate, access_epoch=3)


def test_unrelated_graph_epoch_does_not_change_qualification_identity():
    snapshot = fixture()
    candidate = prepare(snapshot, request("report", "attributed_report", REPORTED))
    advanced = replace(snapshot, epochs=(NamespaceEpoch(*NAMESPACE.as_tuple, 9),))

    refreshed = recompute_qualified_expression_unit(
        advanced, namespace=NAMESPACE, candidate=candidate,
        audiences=("owner",), access_epoch=2, deletion_epoch=0, now=10.0,
    )
    assert refreshed.unit_id == candidate.unit_id
    assert refreshed.qualification_digest == candidate.qualification_digest
    assert refreshed.graph_epoch == advanced.epochs[0]
    assert refreshed.read_versions == candidate.read_versions
    with pytest.raises(ValueError, match="stale or expired"):
        candidate.assert_current(advanced, access_epoch=2, deletion_epoch=0,
                                 now=10.0)
    refreshed.assert_current(advanced, access_epoch=2, deletion_epoch=0, now=10.0)

    corrected = changed(
        advanced, source_correction_head_key(NAMESPACE, "parent"),
        revision=1, valid=True, correction_id="new",
    )
    with pytest.raises(ValueError, match="corrected"):
        recompute_qualified_expression_unit(
            corrected, namespace=NAMESPACE, candidate=candidate,
            audiences=("owner",), access_epoch=2, deletion_epoch=0, now=10.0,
        )
    withdrawn = changed(
        advanced, access_key(*NAMESPACE.as_tuple, "parent"),
        revision=2, status="withdrawn",
    )
    with pytest.raises(PermissionError, match="unavailable"):
        recompute_qualified_expression_unit(
            withdrawn, namespace=NAMESPACE, candidate=candidate,
            audiences=("owner",), access_epoch=2, deletion_epoch=0, now=10.0,
        )
