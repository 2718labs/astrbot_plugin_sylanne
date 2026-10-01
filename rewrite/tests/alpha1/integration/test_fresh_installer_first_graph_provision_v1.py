"""Real fresh installer original -> once-only first Graph CAS, without seed SQL."""
from dataclasses import replace
import os
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.installer_genesis_v1 import (
    TABLE, CONSUMPTIONS, read_installer_genesis_original_v1_locked, install_first_graph_provision_composition_v1,
)
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.graph_types import TypeRegistry, TypeSpec
from sylanne3.runtime_contracts import NamespaceId
from rewrite.tests.alpha1.runtime.test_graph_v2_provisioning import policy_for
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import ROLE, AUTH_NS, SUBJECT, WORKER
from rewrite.tests.alpha1.integration.c09_four_store_process_acceptance_support_v1 import _fresh_installed_factory


def test_real_fresh_installer_first_provision_once_and_recover_same_request(tmp_path):
    state, protected = tmp_path / "state", tmp_path / "protected"
    state.mkdir(); protected.mkdir()
    (protected / "instance.lock").write_bytes(b"\0")
    (protected / "control.key").write_bytes(os.urandom(32))
    graph, bootstrap, service, _compose, _expected, _principal, authority_id, resources = _fresh_installed_factory(state)
    core = service.core
    try:
        with core._tx() as db:
            original = read_installer_genesis_original_v1_locked(db, AUTH_NS)
            assert original is not None and original.anchor.execution_seq == original.anchor.deletion_seq == 0
            assert db.execute(f"SELECT COUNT(*) FROM {CONSUMPTIONS}").fetchone() == (0,)
        from types import SimpleNamespace
        config = graph._GraphCoordinator__content_fence_v2.c09_config
        peer, installation = next(iter(config.installations_v2.items()))
        changed_config = SimpleNamespace(**{**vars(config), "installations_v2": {peer: replace(installation, manifest_digest="e" * 64)}})
        changed_registry = TypeRegistry()
        for spec in resources[0]._registry.specs: changed_registry.register(spec)
        changed_registry.register(TypeSpec("d06.installer_catalogue_variant.v1", ("persona",), "state", lambda value: None, writer_domain="d06"))
        for selected_config, selected_registry in ((changed_config, resources[0]._registry), (config, changed_registry)):
            changed_service = AuthorityV2FenceService(core=core, fences=service.fences, deletion=service.deletion,
                execution=service.execution, namespace=AUTH_NS)
            install_first_graph_provision_composition_v1(changed_service, selected_config, selected_registry)
            with pytest.raises(AuthorityUnavailable, match="package/catalogue/configuration"):
                changed_service.activate_namespace(credential=WORKER, subject=SUBJECT, holder="administrator",
                    namespace_id=ROLE, request_id="same-peer-changed-installation")
        for changed in ({"subject": "unpaired-subject"}, {"namespace_id": NamespaceId("bot", "other")}, {"holder": "other-holder"}):
            arguments = dict(credential=WORKER, subject=SUBJECT, holder="administrator", namespace_id=ROLE, request_id="wrong-before-first")
            with pytest.raises(AuthorityUnavailable): service.activate_namespace(**{**arguments, **changed})
        policy = replace(policy_for(resources[0]), expected_authority_id=authority_id, authority_namespace=AUTH_NS)
        receipt = graph.provision_namespace_v2(bootstrap, policy, operation_id="actual-fresh-first-graph")
        assert graph.provision_namespace_v2(bootstrap, policy, operation_id="actual-fresh-first-graph") == receipt
        with core._tx() as db:
            saved = db.execute(f"SELECT request_id,request_json FROM {CONSUMPTIONS} WHERE namespace=?", (AUTH_NS,)).fetchone()
            assert saved is not None
            assert read_installer_genesis_original_v1_locked(db, AUTH_NS) == original
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                db.execute(f"UPDATE {TABLE} SET original_json='{{}}' WHERE namespace=?", (AUTH_NS,))
        recovered = service.activate_namespace(credential=WORKER, subject=SUBJECT, holder="administrator", namespace_id=ROLE, request_id=saved[0])
        assert recovered.anchor == original.anchor and recovered.generation == 1
        with pytest.raises(AuthorityUnavailable, match="consumed"):
            service.activate_namespace(credential=WORKER, subject=SUBJECT, holder="administrator", namespace_id=ROLE, request_id="different-first-graph")
    finally:
        for handle in resources: handle.close()
        graph._GraphCoordinator__content_fence_v2.c09_lease.close()
