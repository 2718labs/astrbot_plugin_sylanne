"""The installed Owner and clock chain exposes a current D06 C04 input."""

import asyncio
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_post_c02_reply_assembly_v2 import (  # noqa: E402
    test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case,
)

from sylanne3.graph_types import AtomKey
from sylanne3.memory_types import access_key
from sylanne3.runtime_contracts import AuthorityContext


@pytest.mark.asyncio
async def test_real_owner_c02_source_is_current_d06_evidence_for_c04(tmp_path):
    async def after_c02(case):
        graph = case["graph"]
        namespace = case["namespace"]
        source = AtomKey.from_token(case["source_ref"])
        access_ref = access_key(*namespace.as_tuple, source.owner.subject)
        with case["store"]._lock:
            source_row = case["store"]._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?", (source.token,)
            ).fetchone()
            access_row = case["store"]._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?",
                (access_ref.token,),
            ).fetchone()
        assert source_row is not None and access_row is not None
        lease, capability = graph.grant(
            case["bootstrap"], actor=case["client_grant"].subject,
            issuer_domain="d06", namespace=namespace, domains=("d06",),
            activation_generation=1,
        )
        try:
            import json
            access = json.loads(access_row[0])
            authority = AuthorityContext(
                case["client_grant"].subject, "d06", capability, namespace,
                ("event", "activity"), "context", (access["audiences"][0],),
                case["policy"].root_grant.policy_ref, 1,
            )
            page = await asyncio.to_thread(
                graph.read_current_memory_evidence_v1, authority, lease)
            assert any(item.source_ref == source.token for item in page.candidates)
        finally:
            graph.release_authority_lease(case["bootstrap"], lease)

    await real_owner_case(tmp_path, "owned", after_c02=after_c02)
