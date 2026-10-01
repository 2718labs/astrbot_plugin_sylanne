"""C04 preflight binds real issuer rows to one activity and operation."""

from dataclasses import replace

import pytest

from sylanne3.domains.d06.current_association_candidates import CurrentAssociationBudgetV1
from sylanne3.domains.d06.current_c04_association_preflight import (
    CurrentC04AssemblyOriginalsV1, preflight_current_c04_association_v1,
)
from sylanne3.graph_types import GraphSnapshot
from sylanne3.runtime.d06_atomic_association_v2 import read_atomic_association_v2

from test_d06_atomic_association_v2 import _setup


def test_c04_support_originals_share_the_real_quote_operation_and_job(tmp_path):
    harness, _, _, original, focus_snapshot, _ = _setup(tmp_path)
    candidate, envelope, ticket, candidates, scheme, coupling, mood_key, support, bundle = original
    body_snapshot = harness.store.graph_snapshot(tuple(
        version.key for version in envelope.version_guard.read_versions
        if version.key.type_name in {"d02.body_state.v1", "d02.reservation.v1"}))
    try:
        with harness.store._lock:
            db = harness.store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                atomic = read_atomic_association_v2(
                    db, candidate, ticket=ticket, focus_snapshot=focus_snapshot,
                    namespace=harness.namespace, now=5.0, audience="owner",
                    purpose="context", budget=CurrentAssociationBudgetV1(max_edges=1),
                    context_tags=("evening",),
                )
                reads = tuple({version.key: version for version in (
                    *envelope.version_guard.read_versions,
                    *atomic.current_snapshot.versions,
                )}.values())
                envelope = replace(envelope, version_guard=replace(
                    envelope.version_guard, read_versions=reads))
                current = GraphSnapshot(
                    (*atomic.current_snapshot.atoms, *body_snapshot.atoms),
                    atomic.current_snapshot.epochs)
                originals = CurrentC04AssemblyOriginalsV1(
                    mood_key, scheme, coupling, harness.providers["d04"],
                    "feeling-atomic",
                    tuple(replace(support[domain], envelope=envelope)
                          for domain in ("d07", "d02", "d11")),
                    bundle.choice_refs[0], bundle.d02_settlement_refs[0],
                    bundle.d11_cost_settlement_refs[0],
                    bundle.persistent_job_refs[0], bundle.outbox_refs[0],
                )

                def check(candidate_originals):
                    return preflight_current_c04_association_v1(
                        candidate, ticket=ticket, candidates=candidates,
                        associations=atomic.associations,
                        current_snapshot=current,
                        namespace=harness.namespace, envelope=envelope,
                        originals=candidate_originals, now=5.0,
                        audience="owner", purpose="context",
                    )

                accepted = check(originals)
                assert accepted.bundle_candidate.d11_cost_settlement_refs == (
                    originals.d11_cost_settlement_ref,)
                by_domain = {proposal.domain: proposal
                             for proposal in originals.supporting_proposals}

                def changed(domain, ref, value):
                    proposal = by_domain[domain]
                    writes = tuple(replace(write, value=value)
                                   if write.key.token == ref else write
                                   for write in proposal.typed_writes)
                    replacement = replace(proposal, typed_writes=writes)
                    return replace(originals, supporting_proposals=tuple(
                        replacement if item.domain == domain else item
                        for item in originals.supporting_proposals))

                d02 = next(write.value for write in by_domain["d02"].typed_writes
                           if write.key.token == originals.d02_settlement_ref)
                choice = next(write.value for write in by_domain["d07"].typed_writes
                              if write.key.token == originals.choice_ref)
                with pytest.raises(ValueError, match="D07 choice"):
                    check(changed("d07", originals.choice_ref,
                                  {**choice, "selected_candidate_ids": ["other"]}))
                interpretation = next(write for write in by_domain["d07"].typed_writes
                                      if write.key.type_name == "d07.current_interpretation.v1")
                with pytest.raises(ValueError, match="D07 choice"):
                    check(changed("d07", interpretation.key.token,
                                  {**interpretation.value, "source_refs": []}))
                bad_quote = changed("d02", originals.d02_settlement_ref, {
                    **d02, "reservation": {**d02["reservation"],
                                           "quote_id": "another-quote"},
                })
                with pytest.raises(ValueError, match="D02 settlement"):
                    check(bad_quote)
                with pytest.raises(ValueError, match="D02 settlement"):
                    check(changed("d02", originals.d02_settlement_ref,
                                  {**d02, "unpaid_cost": "not a number"}))
                body_state = next(write for write in by_domain["d02"].typed_writes
                                  if write.key.type_name == "d02.body_state.v1")
                with pytest.raises(ValueError, match="D02 settlement"):
                    check(changed("d02", body_state.key.token,
                                  {**body_state.value, "energy": 0.4}))
                body_reservation = next(
                    write for write in by_domain["d02"].typed_writes
                    if write.key.type_name == "d02.reservation.v1")
                with pytest.raises(ValueError, match="D02 settlement"):
                    check(changed("d02", body_reservation.key.token,
                                  {**body_reservation.value, "status": "reserved"}))
                missing_state_guard = replace(envelope, version_guard=replace(
                    envelope.version_guard,
                    read_versions=tuple(version for version in reads
                                        if version.key != body_state.key)))
                missing_state_originals = replace(
                    originals, supporting_proposals=tuple(
                        replace(proposal, envelope=missing_state_guard)
                        for proposal in originals.supporting_proposals))
                with pytest.raises(ValueError, match="D02 settlement"):
                    preflight_current_c04_association_v1(
                        candidate, ticket=ticket, candidates=candidates,
                        associations=atomic.associations,
                        current_snapshot=current, namespace=harness.namespace,
                        envelope=missing_state_guard,
                        originals=missing_state_originals,
                        now=5.0, audience="owner", purpose="context")

                cost = next(write.value for write in by_domain["d11"].typed_writes
                            if write.key.token == originals.d11_cost_settlement_ref)
                with pytest.raises(ValueError, match="D11 cost"):
                    check(changed("d11", originals.d11_cost_settlement_ref,
                                  {**cost, "bundle_operation_id": "other-operation"}))
                outbox = next(write.value for write in by_domain["d11"].typed_writes
                              if write.key.token == originals.outbox_ref)
                with pytest.raises(ValueError, match="D11 cost"):
                    check(changed("d11", originals.outbox_ref,
                                  {**outbox, "job_id": "unrelated-job"}))
                with pytest.raises(ValueError, match="this recollection"):
                    check(changed("d11", originals.outbox_ref,
                                  {**outbox, "payload_ref": "other-recollection"}))
                job = next(write.value for write in by_domain["d11"].typed_writes
                           if write.key.token == originals.persistent_job_ref)
                with pytest.raises(ValueError, match="this recollection"):
                    check(changed("d11", originals.persistent_job_ref,
                                  {**job, "parent_budget_lease_ref": "another-lease"}))
            finally:
                db.execute("ROLLBACK")
    finally:
        harness.close()
