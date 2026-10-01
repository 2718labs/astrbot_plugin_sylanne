"""Reply admission cannot inherit D06's generic acquire proof."""

from pathlib import Path

import pytest


@pytest.fixture
def token_ingress_system(tmp_path, monkeypatch):
    # Runtime fixtures use sibling imports; resolve them only inside this test.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "runtime"))
    from test_current_model_egress_graph_verifier import token_ingress_system as setup

    yield from setup.__wrapped__(tmp_path, monkeypatch)


def test_reply_work_kind_requires_its_own_durable_preparation(token_ingress_system):
    from test_current_model_egress_graph_verifier import _case
    from sylanne3.runtime.reply_model_job import install_schema

    db, verifier, intent = _case(token_ingress_system)
    assert verifier.graph_facts_current(intent)
    install_schema(db)
    assert db.execute(
        "SELECT 1 FROM graph_post_c02_reply_model_preparations_v1 "
        "WHERE job_id=?", (intent.job_id,)).fetchone() is None

    # A job label alone cannot reclassify a D06 acquire as a reply acquire.
    db.execute(
        "UPDATE runtime_jobs SET work_kind='reply' WHERE job_id=?",
        (intent.job_id,))
    assert verifier.graph_facts_current(intent) is False
    assert verifier.complete_graph_current(intent) is False
