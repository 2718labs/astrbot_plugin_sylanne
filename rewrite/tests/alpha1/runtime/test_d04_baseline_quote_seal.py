"""The D04 stage price cannot authorize an unrelated graph bundle."""

import sqlite3
from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import AuthorityDenied, GraphCoordinator
from sylanne3.runtime.issuers import D04_BASELINE_WORK_KIND
from sylanne3.runtime_contracts import NamespaceId


class _D02:
    def authorize_resources(self, bundle, db):
        return True

    def qualified_quote(self, envelope, db):
        return SimpleNamespace(work_kind=D04_BASELINE_WORK_KIND,
                               quote_id="signed-d04-quote")


class _D11:
    def admit_runtime(self, bundle, db):
        raise AssertionError("D11 admission must wait for the sealed issuance")


def _bundle(*, operation_id="baseline-op", source_ref="source", event_ref="event",
            write_type="d04.encoding_baseline.v1", extra_proposal=False):
    proposal = SimpleNamespace(
        domain="d04", typed_writes=(SimpleNamespace(
            key=SimpleNamespace(type_name=write_type)),))
    return SimpleNamespace(
        envelope=SimpleNamespace(
            authority=SimpleNamespace(namespace=NamespaceId("bot", "persona")),
            identity=SimpleNamespace(operation_id=operation_id),
            input_refs=(source_ref, event_ref)),
        proposals=(proposal, proposal) if extra_proposal else (proposal,),
        persistent_job_refs=(), outbox_refs=(), d02_settlement_refs=(),
        d11_cost_settlement_refs=(), digest="original-bundle-digest")


def _coordinator():
    coordinator = object.__new__(GraphCoordinator)
    coordinator._GraphCoordinator__d02_issuer = _D02()
    coordinator._GraphCoordinator__d11_issuer = _D11()
    return coordinator


def test_d04_price_holds_without_atomic_graph_issuance():
    with sqlite3.connect(":memory:") as db:
        with pytest.raises(AuthorityDenied, match="sealed graph issuance"):
            _coordinator()._admit_runtime_bundle(db, _bundle())


@pytest.mark.parametrize("change", ["operation", "source", "event", "digest",
                                     "write", "mixed"])
def test_d04_price_cannot_be_rebound_to_another_bundle(change):
    with sqlite3.connect(":memory:") as db:
        db.execute("""CREATE TABLE graph_d04_baseline_issuance_v1(
            bot TEXT, persona TEXT, operation_id TEXT, source_ref TEXT,
            event_ref TEXT, quote_id TEXT, bundle_digest TEXT)""")
        db.execute("INSERT INTO graph_d04_baseline_issuance_v1 VALUES(?,?,?,?,?,?,?)",
                   ("bot", "persona", "baseline-op", "source", "event",
                    "signed-d04-quote", "original-bundle-digest"))
        changed = {
            "operation": {"operation_id": "other-op"},
            "source": {"source_ref": "other-source"},
            "event": {"event_ref": "other-event"},
            "digest": {},
            "write": {"write_type": "d04.possible_feeling.v1"},
            "mixed": {"extra_proposal": True},
        }[change]
        bundle = _bundle(**changed)
        if change == "digest":
            bundle.digest = "changed-bundle-digest"
        with pytest.raises(AuthorityDenied, match="mixed bundle"):
            _coordinator()._admit_runtime_bundle(db, bundle)
