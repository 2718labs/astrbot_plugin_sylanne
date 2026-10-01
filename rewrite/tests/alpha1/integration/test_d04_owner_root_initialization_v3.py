"""Permanent installed acceptance for root producers on an existing D09 draft.

This uses real Owner pairing/session, D01 initialization and Authority mTLS.
No budget, author grant or D04 root is seeded; no model provider is invoked.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
from uuid import uuid4

import pytest

from test_d04_owner_semantic_initialization_v3 import (
    current_owner, install_d04_test_composition, installed_d04_root, real_owner_case,
)
from sylanne3.contracts import EventConflict
from sylanne3.domains.d04.authored_lineage_v3 import AuthoredRootBlockInputV3, RootAuthoredFacetV3
from sylanne3.domains.d09.expression_policy import D09ExpressionPolicyV1
from sylanne3.domains.d12.types import active_scheme_head_key, character_draft_key
from sylanne3.host.installed_d04_root_resources import load_installed_d04_root_preset_v3
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.d11_d04_root_freeze_v3 import ROOT_WORK_KIND_V3


@pytest.mark.asyncio
async def test_owner_root_preserves_d09_and_splits_budget_once(tmp_path, installed_d04_root):
    async def after_role(case):
        def accept():
            install_d04_test_composition(case)
            graph, store, ns = case["graph"], case["store"], case["namespace"]
            preset = load_installed_d04_root_preset_v3(case["package_root"], case["manifest_digest"])
            blocks = tuple(AuthoredRootBlockInputV3(
                RootAuthoredFacetV3("preserved-block:" + str(i), item.template_id, item.kind,
                                   "preserved-facet:" + str(i)), preset.axes, (0.5,) * 24,
                ((0.5, 0.5),) * 24, "owner-box:" + str(i))
                for i, item in enumerate(preset.block_templates))
            field = {"candidate_id": "preserved-d09-root", "cursor": 0.0,
                "preset_digest": preset.digest, "asset_digest": preset.assets.digest,
                "blocks": json.loads(json.dumps([asdict(block) for block in blocks]))}
            def graph_value(key):
                with store._lock:
                    row = store._db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
                return row[0], json.loads(row[1]), row[2]
            expression = D09ExpressionPolicyV1("owner:existing-expression", "owner:existing-v1", 768)
            with current_owner(case) as (authority, lease):
                graph.initialize_current_d09_scheme_draft_v1(authority, lease,
                    operation_id=str(uuid4()), policy=expression)
                prior_draft = graph_value(character_draft_key(ns))
                prior_head = graph_value(active_scheme_head_key(ns))
                operation = str(uuid4())
                initialized = graph.initialize_current_d04_root_draft_v3(authority, lease,
                    operation_id=operation, root_field=field)
                assert graph.initialize_current_d04_root_draft_v3(authority, lease,
                    operation_id=operation, root_field=field) == initialized
                current = graph_value(character_draft_key(ns))
                assert current[0] == prior_draft[0] + 1
                assert current[1]["fields"]["d09.expression_policy"] == prior_draft[1]["fields"]["d09.expression_policy"]
                assert current[1]["field_sources"]["d09.expression_policy"] == prior_draft[1]["field_sources"]["d09.expression_policy"]
                assert current[1]["fields"]["d04.authored_root"] == field
                assert graph_value(active_scheme_head_key(ns)) == prior_head
                with pytest.raises(EventConflict, match="changed its original input"):
                    graph.initialize_current_d04_root_draft_v3(authority, lease,
                        operation_id=operation, root_field={**field, "candidate_id": "changed"})
                assert graph_value(character_draft_key(ns)) == current
                budget_operation = str(uuid4())
                parent_id = case["policy"].root_grant.lease_id
                with store._lock:
                    parent_before = get_budget_lease(store._db, parent_id)
                allocation = graph.allocate_current_d04_root_budget_v3(authority, lease,
                    operation_id=budget_operation, parent_budget_lease_ref=parent_id,
                    ceiling={"thread_cpu_ms": 60000})
                assert graph.allocate_current_d04_root_budget_v3(authority, lease,
                    operation_id=budget_operation, parent_budget_lease_ref=parent_id,
                    ceiling={"thread_cpu_ms": 60000}) == allocation
                with store._lock:
                    parent_after = get_budget_lease(store._db, parent_id)
                    child = get_budget_lease(store._db, allocation["lease_id"])
                    signed = case["d11_issuer"].current_budget_grant(store._db, child.lease_id)
                assert parent_after.version == parent_before.version + 1
                assert parent_after.reserved == {**parent_before.reserved,
                    "thread_cpu_ms": parent_before.reserved.get("thread_cpu_ms", 0) + 60000}
                assert parent_after.used == parent_before.used
                assert parent_after.unconfirmed == parent_before.unconfirmed
                assert child.parent_id == parent_id
                assert child.limits == {"thread_cpu_ms": 60000}
                assert signed.allowed_work_kinds == (ROOT_WORK_KIND_V3,)
                assert signed.max_ceiling == child.limits
                assert graph.read_current_d04_root_budget_lease_v3(ns) == child.lease_id
                with pytest.raises(EventConflict, match="changed its original input"):
                    graph.allocate_current_d04_root_budget_v3(authority, lease,
                        operation_id=budget_operation, parent_budget_lease_ref=parent_id,
                        ceiling={"thread_cpu_ms": 101})
                with store._lock:
                    assert get_budget_lease(store._db, parent_id) == parent_after
                compiled = graph.compile_current_scheme_for_operation_v1(authority, lease,
                    operation_id=str(uuid4()), draft_ref=character_draft_key(ns).token, budget_ref=parent_id)
                assert {item.domain for item in compiled.compiled.domain_receipts} == {"d04", "d09"}
                root_operation = str(uuid4())
                graph.commit_current_d04_authored_root_v3(authority, lease, operation_id=root_operation,
                    compiled_digest=compiled.compiled.compiled_digest,
                    parent_budget_lease_ref=child.lease_id, preset=preset)
                root = graph.read_current_d04_authored_root_v3(authority, lease, operation_id=root_operation)
                assert root.operation_id == root_operation
                adopted_head = graph_value(active_scheme_head_key(ns))
                assert adopted_head[0] == prior_head[0] + 1
                assert adopted_head[1]["draft_revision"] == current[0]
                assert adopted_head[1]["compiled_digest"] == compiled.compiled.compiled_digest
                assert graph_value(character_draft_key(ns)) == current
        await asyncio.to_thread(accept)
    await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
        after_role_initialization=after_role, enable_d09_workbench=True, enable_d04_root_cpu=True)


@pytest.mark.asyncio
async def test_owner_authored_topology_has_independent_original_and_exact_closure(tmp_path, installed_d04_root):
    """Adopt configuration via the real Owner, then replay on a separate RO DB."""
    import sqlite3
    from dataclasses import replace
    from test_d04_owner_semantic_initialization_v3 import initialize_owner_root_v3, current_mapping_read
    from sylanne3.domains.d04.authored_topology_v3 import TYPE_NAME
    from sylanne3.domains.d04.numeric_coupling import validate_numeric_coupling
    from sylanne3.runtime.d04_owner_initialization_v3 import (
        InstalledD04AuthoredTopologyVerifierV3, TOPOLOGY_TABLE, verifier_for_coordinator_v3,
    )
    async def after_role(case):
        def accept():
            initialize_owner_root_v3(case)
            graph, store, ns = case["graph"], case["store"], case["namespace"]
            with store._lock:
                source_count = store._db.execute("SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
                    "AND type_name='memory.source'", ns.as_tuple).fetchone()[0]
            with current_owner(case) as (authority, lease):
                operation = str(uuid4())
                adopted = graph.adopt_current_d04_root_coupling_v3(authority, lease,
                    operation_id=operation, root_operation_id=case["root_operation_id"], effective_until=86400.0)
                assert adopted["edge_count"] == 48
                assert adopted["coefficient"] == 0.125
                assert graph.adopt_current_d04_root_coupling_v3(authority, lease,
                    operation_id=operation, root_operation_id=case["root_operation_id"], effective_until=86400.0) == adopted
                with pytest.raises(EventConflict, match="changed its original input"):
                    graph.adopt_current_d04_root_coupling_v3(authority, lease,
                        operation_id=operation, root_operation_id=case["root_operation_id"], effective_until=86401.0)
            with store._lock:
                rows = store._db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
                    "AND type_name='d04.numeric_coupling.v1' ORDER BY token", ns.as_tuple).fetchall()
                assert len(rows) == 48 and all(revision == 1 and valid == 1 for _, revision, _, valid in rows)
                edges = [validate_numeric_coupling(json.loads(row[2])) for row in rows]
                assert {edge.source_ref for edge in edges} == {adopted["marker_ref"]}
                assert len({(edge.left_ref, edge.right_ref) for edge in edges}) == 2
                assert len({edge.left_ref for edge in edges} | {edge.right_ref for edge in edges}) == 3
                assert all(edge.left_axis == edge.right_axis and edge.coefficient == 0.125 for edge in edges)
                assert store._db.execute("SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
                    "AND type_name='memory.source'", ns.as_tuple).fetchone()[0] == source_count
            verifier = verifier_for_coordinator_v3(graph)
            with current_mapping_read(case):
                separate = sqlite3.connect("file:" + str(tmp_path / "business.db") + "?mode=ro", uri=True, isolation_level=None)
                try:
                    separate.execute("BEGIN")
                    independent = InstalledD04AuthoredTopologyVerifierV3(package_root=case["package_root"],
                        trusted_manifest_sha256=case["manifest_digest"], d11_issuer=case["d11_issuer"],
                        namespace=ns, installation_id=case["policy"].installation_id)
                    closure = independent.verify_in_transaction(separate, ns, edges[0])
                    assert len(closure) == 57  # 49 configuration + 6 members + 2 adopted scheme/role rows
                    assert len({item[0] for item in closure}) == len(closure)
                    assert all(item[3] for item in closure)
                    assert any(item[0] == adopted["marker_ref"] for item in closure)
                    assert independent.verify_in_transaction(separate, ns, edges[-1]) == closure
                    separate.rollback()
                finally:
                    separate.close()
            # Fault injection is confined to rolled-back transactions after
            # genuine Owner/root/topology adoption; no authority is seeded.
            from sylanne3.contracts import canonical_json
            with current_mapping_read(case) as db:
                draft_ref = character_draft_key(ns).token
                draft_revision, encoded = db.execute("SELECT revision,value FROM graph_atoms WHERE token=?",
                    (draft_ref,)).fetchone()
                draft = json.loads(encoded)
                draft["revision"] = draft_revision + 1
                draft["fields"]["d04.authored_root"]["candidate_id"] = "unadopted-editor-change"
                db.execute("UPDATE graph_atoms SET revision=?,value=? WHERE token=?",
                    (draft_revision + 1, canonical_json(draft), draft_ref))
                assert verifier.verify_in_transaction(db, ns, edges[0]) == closure
                assert draft_ref not in {row[0] for row in closure}
            for field, replacement in (("reads", "[]"), ("epoch_reads", "[]"),
                                       ("invalidated", canonical_json([[adopted["marker_ref"], 2]]))):
                with current_mapping_read(case) as db:
                    db.execute(f"UPDATE graph_events SET {field}=? WHERE bot=? AND persona=? "
                        "AND session='d04.authored_root_coupling.v3' AND event_id=?",
                        (replacement, *ns.as_tuple, operation))
                    with pytest.raises(ValueError, match="CAS read set or epoch"):
                        verifier.verify_in_transaction(db, ns, edges[0])
            for field in ("permit_json", "anchor_json"):
                with current_mapping_read(case) as db:
                    encoded = db.execute(f"SELECT {field} FROM graph_owner_domain_attempts_v3 "
                        "WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, operation)).fetchone()[0]
                    value = json.loads(encoded)
                    if field == "anchor_json":
                        value["proof"] = "altered-historical-anchor"
                    else:
                        value["operation_id"] = "altered-owner-attempt"
                    db.execute(f"UPDATE graph_owner_domain_attempts_v3 SET {field}=? "
                        "WHERE bot=? AND persona=? AND operation_id=?",
                        (canonical_json(value), *ns.as_tuple, operation))
                    with pytest.raises(ValueError, match="retained permit or anchor"):
                        verifier.verify_in_transaction(db, ns, edges[0])
            with current_mapping_read(case) as db:
                db.execute("UPDATE graph_owner_issue_operations_v1 SET proof_json='{}' "
                    "WHERE bot=? AND persona=?", ns.as_tuple)
                with pytest.raises(ValueError, match="historical Owner grant/proof"):
                    verifier.verify_in_transaction(db, ns, edges[0])
            with current_mapping_read(case) as db:
                foreign = InstalledD04AuthoredTopologyVerifierV3(package_root=case["package_root"],
                    trusted_manifest_sha256=case["manifest_digest"], d11_issuer=case["d11_issuer"],
                    namespace=ns, installation_id="unqualified-target-installation")
                with pytest.raises(ValueError, match="current independent target admission"):
                    foreign.verify_in_transaction(db, ns, edges[0])
            with current_mapping_read(case) as db:
                with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                    db.execute(f"UPDATE {TOPOLOGY_TABLE} SET original_digest='forged'")
            with current_mapping_read(case) as db:
                altered = json.loads(rows[0][2]); altered["coefficient"] = 0.0625
                db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (canonical_json(altered), rows[0][0]))
                with pytest.raises(ValueError, match="current marker or edge"):
                    verifier.verify_in_transaction(db, ns, edges[0])
            with current_mapping_read(case) as db:
                db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (adopted["marker_ref"],))
                with pytest.raises(ValueError, match="current marker or edge"):
                    verifier.verify_in_transaction(db, ns, edges[0])
            with current_mapping_read(case) as db:
                with pytest.raises(ValueError, match="source or endpoint lineage"):
                    verifier.verify_in_transaction(db, ns, replace(edges[0], source_ref=character_draft_key(ns).token))
                assert verifier.verify_in_transaction(db, ns, edges[0]) == closure
            from test_d04_owner_semantic_initialization_v3 import adopt_mapping_and_clock
            mapping, clock = adopt_mapping_and_clock(case)
            case.update(migration_mapping=mapping, migration_clock=clock)
            _assert_real_transferred_topology(case, tmp_path, adopted, edges[0], closure)
        await asyncio.to_thread(accept)
    await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
        after_role_initialization=after_role, enable_d09_workbench=True, enable_d04_root_cpu=True)


def _assert_real_transferred_topology(case, tmp_path, adopted, edge, source_closure):
    """Move the actually authored Graph and use a newly signed target identity.

    The same real migration factory used by D12 performs freeze, snapshot,
    source revocation, import/reconciliation and activation. No target Graph,
    Owner grant, migration receipt or admission is manufactured by the test.
    """
    from dataclasses import replace
    from datetime import datetime, timedelta, timezone
    import sqlite3
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sylanne3.authority_service.mtls_server import AdministratorInstallationV2, MtlsPeerCredential
    from sylanne3.authority_service.installed_migration_pairing import (
        AdministratorMigrationPairingV1, InstalledMigrationPairingRegistry)
    from sylanne3.authority_service.installed_migration_graph_proofs import InstalledSourceGraphProofV1
    from sylanne3.authority_service.v2_migration_service import AuthorityV2MigrationService
    from sylanne3.authority_service.v2_migration_store import AuthorityV2MigrationStore
    from sylanne3.authority_service.v2_migration_contract import MigrationPlanV2
    from sylanne3.authority_service.d12_target_registry_v1 import D12TargetLeaseOriginalV1, InstalledD12TargetRegistryV1
    from sylanne3.authority_service.d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
    from sylanne3.authority_service.v2_owner_proof import OwnerCredentialRegistrationV1
    from sylanne3.authority_service.v2_owner_contract import OwnerActorBindingV1
    from sylanne3.host.d12_local_transfer_factory_v1 import (
        install_d12_isolated_target_schema_v1, install_local_d12_transfer_port_v1)
    from sylanne3.runtime.d12_installed_transfer_registry_v1 import InstalledD12TransferManifestV1
    from sylanne3.runtime.graph_migration_snapshot_v1 import _install_import_receipt_schema, _schema_digest, _catalogue_digest
    from sylanne3.runtime.d04_owner_initialization_v3 import InstalledD04AuthoredTopologyVerifierV3, TOPOLOGY_TABLE
    from sylanne3.runtime.lifecycle_operations_v1 import digest
    from sylanne3.runtime_contracts import FenceScope
    from sylanne3.graph_store import ProductionGraphStore
    from sylanne3.graph_types import NamespaceEpoch, owner_grant_key

    graph, source = case["graph"], case["store"]
    core, ns, authority_ns = case["core"], case["namespace"], case["authority_namespace"]
    peer, admin, fences = case["peer"], case["admin_peer"], case["protected"]
    source_install, source_holder = case["policy"].installation_id, case["policy"].administrator_holder
    source_subject = "mtls:sha256:" + peer.certificate_sha256
    target_peer = MtlsPeerCredential("e" * 64)
    target_subject, target_install, target_holder = "mtls:sha256:" + "e" * 64, "topology-target", "host:topology-target"
    target_path = tmp_path / "topology-target.db"
    now = lambda: datetime.now(timezone.utc)
    previous_authorizer = core._authorize_callback
    def authorize(credential, action, namespace, holder):
        return (namespace == authority_ns and (
            credential == admin and action in {"migration_pair_install", "migration_pair_register", "d12_target_install",
                "d12_target_register", "d12_target_owner_install"}
            or credential == peer and action in {"migration_begin", "migration_revoke", "migration_recover"}
            or credential == target_peer and action in {"migration_prepare_target", "migration_activate", "migration_recover",
                "read", "write", "current", "owner_pair", "owner_session", "owner_guard_read"}
        )) or previous_authorizer(credential, action, namespace, holder)
    core._authorize_callback = authorize
    transfer = target = None
    try:
        with source._lock:
            _install_import_receipt_schema(source._db)
            original_before = source._db.execute(f"SELECT original_json,original_digest FROM {TOPOLOGY_TABLE} "
                "WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, adopted["operation_id"])).fetchone()
            grant_before = source._db.execute("SELECT value FROM graph_atoms WHERE token=?",
                (owner_grant_key(*ns.as_tuple).token,)).fetchone()
            semantic_tables = ("graph_d04_semantic_installations_v3", "runtime_d11_owner_role_clock_originals_v1")
            semantic_before = {table: source._db.execute(f"SELECT original_json,original_digest,signature FROM {table} "
                "WHERE bot=? AND persona=? ORDER BY revision", ns.as_tuple).fetchall() for table in semantic_tables}
            assert all(semantic_before.values())
            source_schema, source_catalogue = _schema_digest(source._db), _catalogue_digest(source._db)
        install_d12_isolated_target_schema_v1(graph_db=target_path, registry=source._registry,
            schema_fence_port=case["port"], holder=target_holder)
        with sqlite3.connect(target_path.as_uri() + "?mode=ro", uri=True) as installed_target:
            assert (_schema_digest(installed_target), _catalogue_digest(installed_target)) == (
                source_schema, source_catalogue), "fresh installed target must include the actual authored source schema"
        installations = {
            (peer.certificate_sha256, "source-topology"): AdministratorInstallationV2(
                source_install, source_holder, "topology-policy", "v2", case["manifest_digest"]),
            (target_peer.certificate_sha256, "target-topology"): AdministratorInstallationV2(
                target_install, target_holder, "topology-policy", "v2", case["manifest_digest"])}
        bindings = {(cert, profile, ns): authority_ns for cert, profile in installations}
        pairing = AdministratorMigrationPairingV1(authority_ns, ns, peer.certificate_sha256, "source-topology",
            source_holder, source_install, target_peer.certificate_sha256, "target-topology", target_holder, target_install)
        pairs = InstalledMigrationPairingRegistry(core, {authority_ns: pairing}, installations, bindings)
        pairs.install_schema(admin); pairs.register(admin, authority_ns)
        target_lease = D12TargetLeaseOriginalV1("topology-target-lease", "topology-local-target", authority_ns, ns,
            target_install, target_holder, "topology-target-incarnation", str(target_path), source_schema, source_catalogue,
            (now() + timedelta(hours=1)).isoformat(), "topology-relocation-policy", digest("topology-relocation-policy"))
        targets = InstalledD12TargetRegistryV1(pairing_registry=pairs, target_leases=(target_lease,), utc_clock=now)
        targets.install_schema(admin); targets.register(admin, target_lease.lease_ref)
        migration = AuthorityV2MigrationService(fences=fences,
            store=AuthorityV2MigrationStore(core._db, lock=core._lock, create=True), pairing_verifier=pairs.verify_pairing,
            source_snapshot_verifier=InstalledSourceGraphProofV1(graph_db=tmp_path / "business.db",
                namespace=authority_ns, namespace_id=ns, installation_id=source_install),
            target_recovery_verifier=None, owner_tickets=case["server"]._v2_owner_tickets)
        manifest = InstalledD12TransferManifestV1("topology-transfer-manifest", ns, authority_ns,
            source_install, source_holder, target_lease.target_ref, ("namespace:" + "/".join(ns.as_tuple),),
            source_schema, source_catalogue, "topology-relocation-policy", digest("topology-relocation-policy"))
        transfer = install_local_d12_transfer_port_v1(source_store=source, source_graph_db=tmp_path / "business.db",
            source_recovery_capability=graph._GraphCoordinator__graph_capability, migration=migration,
            manifests=(manifest,), target_registry=targets, source_credential=peer, source_subject=source_subject,
            target_credential=target_peer, target_subject=target_subject)
        plan = MigrationPlanV2("topology-transfer-" + str(uuid4()), authority_ns, ns, source_holder, source_install,
            target_holder, target_install, fences.current_anchor(credential=peer, subject=source_subject))
        begun, _ = migration.begin_transfer(credential=peer, subject=source_subject, plan=plan, request_id="topology-begin")
        snapshot = transfer.read_current_source_snapshot_v2(plan=plan, permit=begun.permit)
        migration.revoke_source(credential=peer, subject=source_subject, permit=begun.permit,
            snapshot=snapshot, request_id="topology-revoke")
        prepared, _ = migration.prepare_target(credential=target_peer, subject=target_subject,
            transfer_id=plan.transfer_id, request_id="topology-prepare-target")
        recovery = transfer.recover_current_target_graph_v2(plan=plan, permit=prepared.permit,
            source_snapshot=snapshot, target_lease_ref=target_lease.lease_ref)
        migration.activate_target(credential=target_peer, subject=target_subject, permit=prepared.permit,
            recovery=recovery, request_id="topology-activate")
        transfer.target_factory.close()
        target = ProductionGraphStore(target_path, source._registry)

        pairing_source = case["pairing_source"]
        pairing_source.revoke_credential(administrator_credential=admin, authority_namespace=authority_ns,
            principal=case["principal"])
        key = Ed25519PrivateKey.generate()
        registration = OwnerCredentialRegistrationV1(case["grant"].authority_id, authority_ns, target_install,
            case["principal"], "topology-target-owner-key", 1,
            key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), "topology-target-enroll")
        pairing_source.pair_credential(administrator_credential=admin, registration=registration,
            client_certificate_sha256=target_peer.certificate_sha256,
            valid_until_utc=(now() + timedelta(hours=1)).replace(microsecond=0))
        actor = "topology-target-owner"
        pairing_source.pair_actor(administrator_credential=admin, binding=OwnerActorBindingV1(
            case["grant"].authority_id, target_install, ns, actor, case["principal"], 1))
        case["owner_proofs"].register_credential(transport_credential=target_peer, registration=registration)
        request = replace(case["owner_session_request"], installation_id=target_install, credential_id=registration.credential_id)
        sessions = case["owner_sessions"]
        challenge = sessions.begin_login(transport_credential=target_peer, request=request)
        token = sessions.accept_login(transport_credential=target_peer, challenge=challenge,
            signature=key.sign(challenge.signed_bytes()))
        owner = InstalledD12TargetOwnerAdmissionServiceV1(migration=migration,
            owner_tickets=case["server"]._v2_owner_tickets, target_graph_db=target_path, namespace_id=ns,
            target_installation_id=target_install, target_holder=target_holder,
            policy_ref="topology-target-owner-policy", policy_digest=digest("topology-target-owner-policy"))
        owner.install_schema(admin)
        anchor = fences.current_anchor(credential=target_peer, subject=target_subject)
        permit = fences.begin_fence(credential=target_peer, subject=target_subject, holder=target_holder,
            operation="read", operation_id="topology-target-proof", expected_anchor=anchor)
        try:
            authority, _ = owner.get_current_owner_authority_for_fence_v1(credential=target_peer,
                subject=target_subject, permit=permit, actor=actor, session_token=token, session_request=request)
            metadata_row = target._db.execute("SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
                "WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
            epoch = target._db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()[0]
            scope = FenceScope(ns, authority_ns, permit.generation, "read", permit.operation_id, permit, anchor,
                NamespaceEpoch(*ns.as_tuple, epoch), metadata_row[2])
            verifier = InstalledD04AuthoredTopologyVerifierV3(package_root=case["package_root"],
                trusted_manifest_sha256=case["manifest_digest"], d11_issuer=case["d11_issuer"],
                namespace=ns, installation_id=target_install)
            observed = verifier.observe_current_service_location_for_fence_v3(owner, scope,
                credential=target_peer, subject=target_subject)
            assert observed == authority
            target._db.execute("BEGIN")
            try:
                assert verifier.verify_in_transaction(target._db, ns, edge) == source_closure
                assert target._db.execute(f"SELECT original_json,original_digest FROM {TOPOLOGY_TABLE} "
                    "WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, adopted["operation_id"])).fetchone() == original_before
                assert target._db.execute("SELECT value FROM graph_atoms WHERE token=?",
                    (owner_grant_key(*ns.as_tuple).token,)).fetchone() == grant_before
            finally:
                target._db.rollback()
            assert verifier.observe_current_service_location_for_fence_v3(owner, scope,
                credential=target_peer, subject=target_subject) == observed
        finally:
            fences.finish_fence(credential=target_peer, subject=target_subject, permit=permit,
                request_id="topology-target-proof-finish", request_digest=digest("topology-target-proof-finish"))
        # Reuse this actual target service/Graph migration, rather than creating
        # a second target or treating an admission DTO as current authority.
        from sylanne3.graph_coordinator import GraphCoordinator
        from sylanne3.host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
        from sylanne3.runtime.d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
        class ActualTargetPort:
            # This is local transport configuration from the administrator's
            # target registration; every guard/permit comes from the real Core.
            installation_grant = replace(case["grant"], subject=target_subject,
                administrator_holder=target_holder, installation_id=target_install)
            def current_anchor(self, *, namespace, authority_namespace):
                assert (namespace, authority_namespace) == (ns, authority_ns)
                assert not target._db.in_transaction and not target._lock._is_owned()
                return fences.current_anchor(credential=target_peer, subject=target_subject)
            def begin_fence(self, *, namespace, authority_namespace, holder, generation, operation, operation_id,
                    expected_anchor, **kwargs):
                assert (namespace, authority_namespace, holder, generation) == (
                    ns, authority_ns, target_holder, expected_anchor.activation_generation)
                assert not target._db.in_transaction and not target._lock._is_owned()
                return fences.begin_fence(credential=target_peer, subject=target_subject, holder=holder,
                    operation=operation, operation_id=operation_id, expected_anchor=expected_anchor, **kwargs)
            def finish_fence(self, selected, *, request_id, request_digest):
                assert not target._db.in_transaction and not target._lock._is_owned()
                return fences.finish_fence(credential=target_peer, subject=target_subject, permit=selected.permit,
                    request_id=request_id, request_digest=request_digest)
            def validate_fence(self, selected):
                assert not target._db.in_transaction and not target._lock._is_owned()
                return fences.validate_fence(credential=target_peer, subject=target_subject, permit=selected.permit)
            def get_current_background_owner_authority_for_fence_v1(self, *, namespace, authority_namespace, permit):
                assert (namespace, authority_namespace) == (ns, authority_ns)
                assert not target._db.in_transaction and not target._lock._is_owned()
                return owner.get_current_background_owner_authority_for_fence_v1(
                    credential=target_peer, subject=target_subject, permit=permit)
        target_port = ActualTargetPort()
        def current_target_principal(actor_id, namespace):
            paired = pairing_source.current_actor_binding(authority_namespace=authority_ns,
                installation_id=target_install, actor_id=actor_id)
            return paired.principal if paired is not None and namespace == ns else None
        target_graph = GraphCoordinator(target, object(), holder=target_holder,
            content_fence_v2=target_port, d11_issuer=case["d11_issuer"], d02_issuer=case["d02_issuer"],
            owner_principal_resolver=current_target_principal)
        target_reader = InstalledD04SemanticMappingReaderV3(target_graph, case["package_root"], case["manifest_digest"])
        target_graph._GraphCoordinator__d04_semantic_mapping_reader = target_reader
        def read_mapping_at(selected_scope):
            with target_reader.current_fence(selected_scope):
                with target._lock:
                    target._db.execute("BEGIN")
                    try:
                        assert target_reader(target._db, ns) == case["migration_mapping"]
                        assert read_current_role_clock_installation_v1(target_reader, target._db, ns) == case["migration_clock"]
                        for table in semantic_tables:
                            assert target._db.execute(f"SELECT original_json,original_digest,signature FROM {table} "
                                "WHERE bot=? AND persona=? ORDER BY revision", ns.as_tuple).fetchall() == semantic_before[table]
                    finally:
                        target._db.rollback()
        anchor = fences.current_anchor(credential=target_peer, subject=target_subject)
        permit = fences.begin_fence(credential=target_peer, subject=target_subject, holder=target_holder,
            operation="read", operation_id="semantic-target-proof", expected_anchor=anchor)
        semantic_scope = replace(scope, operation_id=permit.operation_id, permit=permit, pinned_anchor=anchor)
        try:
            read_mapping_at(semantic_scope)
        finally:
            fences.finish_fence(credential=target_peer, subject=target_subject, permit=permit,
                request_id="semantic-target-proof-finish", request_digest=digest("semantic-target-proof-finish"))
        # Owner-session/key changes serialize after all existing work fences.
        sessions.logout(transport_credential=target_peer, token=token, request=request)
        anchor = fences.current_anchor(credential=target_peer, subject=target_subject)
        permit = fences.begin_fence(credential=target_peer, subject=target_subject, holder=target_holder,
            operation="read", operation_id="topology-target-after-logout", expected_anchor=anchor)
        scope = replace(scope, operation_id=permit.operation_id, permit=permit, pinned_anchor=anchor)
        try:
            assert verifier.observe_current_service_location_for_fence_v3(owner, scope,
                credential=target_peer, subject=target_subject) == observed
            read_mapping_at(scope)
        finally:
            fences.finish_fence(credential=target_peer, subject=target_subject, permit=permit,
                request_id="topology-target-logout-finish", request_digest=digest("topology-target-logout-finish"))
        pairing_source.revoke_credential(administrator_credential=admin, authority_namespace=authority_ns,
            principal=case["principal"])
        anchor = fences.current_anchor(credential=target_peer, subject=target_subject)
        permit = fences.begin_fence(credential=target_peer, subject=target_subject, holder=target_holder,
            operation="read", operation_id="topology-target-after-key-revoke", expected_anchor=anchor)
        scope = replace(scope, operation_id=permit.operation_id, permit=permit, pinned_anchor=anchor)
        try:
            with pytest.raises(Exception):
                verifier.observe_current_service_location_for_fence_v3(owner, scope,
                    credential=target_peer, subject=target_subject)
            with pytest.raises(Exception):
                read_mapping_at(scope)
            target._db.execute("BEGIN")
            try:
                with pytest.raises(ValueError, match="current independent target admission"):
                    verifier.verify_in_transaction(target._db, ns, edge)
            finally:
                target._db.rollback()
        finally:
            fences.finish_fence(credential=target_peer, subject=target_subject, permit=permit,
                request_id="topology-target-revoke-finish", request_digest=digest("topology-target-revoke-finish"))
    finally:
        if target is not None:
            target.close()
        if transfer is not None:
            transfer.target_factory.close()
        core._authorize_callback = previous_authorizer
