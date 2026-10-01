"""C04 D11 context cannot be issued from caller bytes or facet IDs alone."""

import pytest

from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.c04_encoding_context_original_v3 import (
    D11EncodingContextHold, MeaningFacetIssuerBindingV3,
    issue_d11_encoding_context_original_v3,
)
from sylanne3.runtime.c04_v3_contracts import ExactRefV3


def test_meaning_facet_is_an_id_with_appraisal_issuer_not_a_graph_version() -> None:
    appraisal = ExactRefV3(AtomKey(
        Owner("persona", "bot", "persona"), "d04.appraisal_bundle.v1", "appraisal"
    ).token, 1)
    binding = MeaningFacetIssuerBindingV3("facet:care", appraisal, "a" * 64, "b" * 64)
    assert binding.facet_id == "facet:care"
    with pytest.raises(ValueError, match="appraisal"):
        MeaningFacetIssuerBindingV3("facet:care", ExactRefV3(AtomKey(
            Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "feeling"
        ).token, 1), "a" * 64, "b" * 64)
    with pytest.raises(D11EncodingContextHold, match="trusted W01"):
        issue_d11_encoding_context_original_v3(
            trusted_w01_read={"perspective_ref": "caller", "as_known_at": 1.0},
            facet_issuer_evidence=binding,
        )
