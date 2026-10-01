"""A lost Authority observation response never causes another OneBot send."""

import pytest

from test_natural_p2_true_owner_handoff import _run_true_owner_natural_case


@pytest.mark.asyncio
async def test_true_owner_natural_p2_lost_observation_ack_recovers_once(
    tmp_path, monkeypatch,
):
    await _run_true_owner_natural_case(
        tmp_path, monkeypatch, "observation_ack_lost")
