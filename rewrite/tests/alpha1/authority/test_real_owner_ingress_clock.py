"""The installed Owner and graph share one mTLS Authority clock source."""

import asyncio
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_post_c02_reply_assembly_v2 import (  # noqa: E402
    test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case,
)

from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2


@pytest.mark.asyncio
async def test_real_owner_graph_and_mtls_clock_share_installed_source(tmp_path):
    async def after_c02(case):
        assert case["owner_issue_committed"] is not None
        assert case["graph"]._GraphCoordinator__content_fence_v2 is case["port"]
        policy = case["ingress_clock"]
        reading = await asyncio.to_thread(case["port"].read_ingress_clock, policy)
        assert type(reading) is VerifiedIngressClockV2
        assert reading.sample.installation_id == case["policy"].installation_id
        assert reading.sample.source_id == policy.source_id
        assert reading.sample.authority_id == case["client_grant"].authority_id

        with pytest.raises(RuntimeError, match="unqualified"):
            await asyncio.to_thread(
                case["port"].read_ingress_clock,
                AdminIngressClockPolicy("clock:other-installation", 0.5, 2.0),
            )
        with pytest.raises(RuntimeError, match="unqualified"):
            await asyncio.to_thread(
                case["port"].read_ingress_clock,
                AdminIngressClockPolicy(policy.source_id, 0.01, 2.0),
            )

    await real_owner_case(tmp_path, "owned", after_c02=after_c02)
