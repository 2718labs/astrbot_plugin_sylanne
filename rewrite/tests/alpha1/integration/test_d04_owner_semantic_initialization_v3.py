"""Installed D04 first use: real signed Owner -> root -> mapping -> D11 clock.

Run with SYLANNE_D04_INSTALLED_ROOT naming an extracted, freshly built pinned
candidate, and PYTHONPATH beginning with that package's rewrite directory.
The same permanent fixture is reusable by later full/LOO/atomic-advance tests.
No root, Owner guard, accepted mapping or clock original is seeded by this test.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_post_c02_reply_assembly_v2 import (  # noqa: E402
    test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case,
)
from sylanne3.domains.d04.authored_lineage_v3 import (
    AuthoredRootBlockInputV3, RootAuthoredFacetV3,
)
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.host.installed_d04_output_policy import load_installed_d04_output_policy_v1
from sylanne3.host.installed_d04_root_resources import load_installed_d04_root_preset_v3
from sylanne3.host.installed_d04_semantic_mapping_v3 import (
    InstalledD04SemanticMappingReaderV3, PROFILE_PATH,
    load_installed_d04_semantic_profile_v3,
)
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.runtime.d04_semantic_installation_original_v3 import (
    TABLE, install_d04_semantic_installation_schema_v3,
)
from sylanne3.runtime.d11_role_clock_installation_v1 import (
    TABLE as CLOCK_TABLE, read_current_role_clock_installation_v1,
)
from sylanne3.runtime_contracts import FenceScope, canonical_digest


@pytest.fixture
def installed_d04_root():
    configured = os.environ.get("SYLANNE_D04_INSTALLED_ROOT")
    if not configured:
        pytest.skip("requires a freshly built installed D04 backend package")
    root = Path(configured).resolve(strict=True)
    import sylanne3.host.installed_d04_semantic_mapping_v3 as installed
    assert Path(installed.__file__).resolve() == root / "rewrite/sylanne3/host/installed_d04_semantic_mapping_v3.py"
    pin = hashlib.sha256((root / "release-manifest.json").read_bytes()).hexdigest()
    load_installed_d04_semantic_profile_v3(root, pin)
    return root


def install_d04_test_composition(case):
    """Compose actual installed resources; no test issuer replaces production."""
    graph, store, bootstrap = case["graph"], case["store"], case["bootstrap"]
    if case.get("mapping_reader") is not None:
        assert graph._GraphCoordinator__d04_semantic_mapping_reader is case["mapping_reader"]
        return case["mapping_reader"]
    daemon=case.get("c09_daemon")
    bundle=(case["installed_bundle"] if daemon is not None else
        replace(case["installed_bundle"], ingress_clock=case["ingress_clock"]))
    if daemon is not None:
        assert daemon.config.natural_model_authorities_v2[case["authority_namespace"]].installation_bundle is bundle
    # Use the same signer as the donor's real D11/D02 issuers. Keys are ephemeral
    # local test-installation data and never written to a packaged artifact.
    assembly = V2InstallationAssembly(case["policy"], case["grant"],
        bundle.d11_signing_key if daemon is not None else b"reply-issuer-key-"*2,
        bundle.d02_signing_key if daemon is not None else b"reply-issuer-key-"*2,
        lambda: case["port"], case["package_root"], Path(store.path).parent if hasattr(store, "path") else case["package_root"],
        ingress_clock=case["ingress_clock"], admin_bundle=bundle)
    graph._GraphCoordinator__d04_installed_joint_assembly = assembly
    graph._GraphCoordinator__d04_installed_joint_output_policy = load_installed_d04_output_policy_v1(
        case["package_root"], case["manifest_digest"], require_formal=False, require_backend_runtime=True)
    for domain in ("d02", "d04", "d11", "d12"):
        registration = case["domain_registry"].registrations[domain]
        graph.register_provider(bootstrap, domain, registration.provider,
            registration.proposal_schema, registration.proposal_schema_hash)
    with store._lock:
        install_d04_semantic_installation_schema_v3(store._db)
    reader = InstalledD04SemanticMappingReaderV3(graph, case["package_root"], case["manifest_digest"])
    graph._GraphCoordinator__d04_semantic_mapping_reader = reader
    case["mapping_reader"] = reader
    if case.get("enable_d04_root_cpu"):
        from d04_numeric_authority_acceptance_support_v3 import install_actual_root_authority_case_v3
        install_actual_root_authority_case_v3(case, owner_loop=case["owner_loop"])
    return reader


@contextmanager
def current_owner(case):
    graph = case["graph"]
    authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply",
        namespace=case["namespace"], domains=("d02", "d04", "d11", "d12"),
        purpose="workbench_user_action", audience="owner", activation_generation=1,
        owner_session_token=case["owner_session_token"], owner_session_request=case["owner_session_request"])
    try:
        yield authority, lease
    finally:
        graph.release_current_owner_lease(case["bootstrap"], lease)


@contextmanager
def current_mapping_read(case):
    """Actual installed Authority fence and the production reader transaction."""
    graph, store, port, ns = case["graph"], case["store"], case["port"], case["namespace"]
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(ns)
    anchor = port.current_anchor(namespace=ns, authority_namespace=case["authority_namespace"])
    operation = "d04-owner-acceptance-read:" + str(uuid4())
    permit = port.begin_fence(namespace=ns, authority_namespace=case["authority_namespace"],
        holder=case["policy"].administrator_holder, generation=1, operation="read", operation_id=operation,
        expected_anchor=anchor)
    scope = FenceScope(ns, case["authority_namespace"], 1, "read", operation, permit, anchor, epoch, metadata.graph_revision)
    try:
        with case["mapping_reader"].current_fence(scope):
            with store._lock:
                store._db.execute("BEGIN")
                try:
                    yield store._db
                finally:
                    store._db.rollback()
    finally:
        port.finish_fence(scope, request_id="finish:" + operation,
            request_digest="sha256:" + canonical_digest((operation, permit.token)))


def initialize_owner_root_v3(case, *, root_operation_id=None, before_root_compile=None):
    """Use only real Owner draft, signed D11 budget, compile and root adoption."""
    graph, ns = case["graph"], case["namespace"]
    reader = install_d04_test_composition(case)
    preset = load_installed_d04_root_preset_v3(case["package_root"], case["manifest_digest"])
    blocks = tuple(AuthoredRootBlockInputV3(
        RootAuthoredFacetV3("owner-block:" + str(index), template.template_id, template.kind,
                           "owner-facet:" + str(index)), preset.axes, (0.5,) * 24,
        ((0.5, 0.5),) * 24, "owner-initial-box:" + str(index))
        for index, template in enumerate(preset.block_templates))
    field = {"candidate_id": "owner-authored-initial", "cursor": 0.0,
             "preset_digest": preset.digest, "asset_digest": preset.assets.digest,
             "blocks": json.loads(json.dumps([asdict(block) for block in blocks]))}
    with current_owner(case) as (authority, lease):
        graph.initialize_current_d04_root_draft_v3(authority, lease,
            operation_id=str(uuid4()), root_field=field)
        if before_root_compile is not None:
            before_root_compile()
        budget = graph.allocate_current_d04_root_budget_v3(authority, lease,
            operation_id=str(uuid4()), parent_budget_lease_ref=case["policy"].root_grant.lease_id,
            ceiling={"thread_cpu_ms": 60000})
        compiled = graph.compile_current_scheme_for_operation_v1(authority, lease,
            operation_id=str(uuid4()), draft_ref=character_draft_key(ns).token,
            budget_ref=case["policy"].root_grant.lease_id)
        root_operation = str(uuid4()) if root_operation_id is None else root_operation_id
        graph.commit_current_d04_authored_root_v3(authority, lease, operation_id=root_operation,
            compiled_digest=compiled.compiled.compiled_digest, parent_budget_lease_ref=budget["lease_id"], preset=preset)
        original = graph.read_current_d04_authored_root_v3(authority, lease, operation_id=root_operation)
        assert original.operation_id == root_operation
    case["root_operation_id"] = root_operation
    case["root_original"] = original
    return reader


def adopt_mapping_and_clock(case, *, role_clock_rate="1"):
    reader, graph, namespace = case["mapping_reader"], case["graph"], case["namespace"]
    profile = reader.profile()
    with current_mapping_read(case) as db:
        with pytest.raises(ValueError, match="explicit current Owner acceptance"):
            reader(db, namespace)
    with current_owner(case) as (authority, lease):
        operation = str(uuid4())
        accepted = reader.adopt_current(authority, lease, operation_id=operation,
            profile_digest=profile.profile_digest, expected_revision=0)
        assert accepted["acceptance_revision"] == 1
        assert reader.adopt_current(authority, lease, operation_id=operation,
            profile_digest=profile.profile_digest, expected_revision=0) == accepted
        with pytest.raises(ValueError, match="different immutable request"):
            reader.adopt_current(authority, lease, operation_id=operation,
                profile_digest=profile.profile_digest, expected_revision=1)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        request = {"operation_id": str(uuid4()), "expected_version": 0,
            "character_origin": "0", "rate": role_clock_rate, "wall_origin_utc": now.isoformat().replace("+00:00", "Z"),
            "valid_from_utc": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "valid_until_utc": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z")}
        clock = reader.register_current_role_clock(authority, lease, **request)
        assert reader.register_current_role_clock(authority, lease, **request) == clock
        assert clock["mapping_version"] == 1
        with pytest.raises(ValueError, match="different immutable request"):
            reader.register_current_role_clock(authority, lease, **{**request, "rate": "2" if role_clock_rate != "2" else "3"})
    with current_mapping_read(case) as db:
        mapping = reader(db, namespace)
        assert mapping.acceptance_digest == accepted["acceptance_digest"]
        assert sorted(share for _, share in mapping.block_shares) == [0.25, 0.25, 0.5]
        assert len(mapping.block_shares) == 3
        assert reader.current_role_condition(db, namespace).role_ref == mapping.asset.role_ref
        from sylanne3.domains.d01 import _activation_key
        activation = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?",
            (_activation_key(namespace).token,)).fetchone()[0])
        assert mapping.asset.role_ref == activation["head_id"]
        installed_clock = read_current_role_clock_installation_v1(reader, db, namespace)
        assert reader.current_role_clock_identity(db, namespace) == (installed_clock.mapping_id, 1)
    case.update(mapping_acceptance=accepted, clock_acceptance=clock)
    return mapping, installed_clock


def reread_after_database_reopen(case, expected_mapping, expected_clock):
    """A fresh coordinator reconstructs acceptance solely from durable originals."""
    from sylanne3.graph_store import ProductionGraphStore
    from sylanne3.graph_coordinator import GraphCoordinator
    old = case["graph"]
    with case["store"]._lock:
        path = case["store"]._db.execute("PRAGMA database_list").fetchone()[2]
    reopened = ProductionGraphStore(path, case["domain_registry"].type_registry)
    try:
        fresh = GraphCoordinator(reopened, case["bootstrap"],
            holder=case["policy"].administrator_holder, content_fence_v2=case["port"],
            d02_issuer=case["d02_issuer"], d11_issuer=case["d11_issuer"],
            owner_principal_resolver=old._GraphCoordinator__owner_principal_resolver,
            scene_clock_policy=case["ingress_clock"],
            d04_installed_joint_assembly=old._GraphCoordinator__d04_installed_joint_assembly,
            d04_installed_joint_output_policy=old._GraphCoordinator__d04_installed_joint_output_policy)
        reader = InstalledD04SemanticMappingReaderV3(fresh, case["package_root"], case["manifest_digest"])
        fresh._GraphCoordinator__d04_semantic_mapping_reader = reader
        current = {**case, "graph": fresh, "store": reopened, "mapping_reader": reader}
        with current_mapping_read(current) as db:
            assert reader(db, current["namespace"]) == expected_mapping
            assert read_current_role_clock_installation_v1(reader, db, current["namespace"]) == expected_clock
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_true_owner_root_mapping_clock_and_rejection_boundaries(tmp_path, installed_d04_root):
    async def after_role(case):
        def accept():
            initialize_owner_root_v3(case)
            mapping, clock = adopt_mapping_and_clock(case)
            reread_after_database_reopen(case, mapping, clock)
            # Original immutable storage is enforced by SQLite itself.
            with current_mapping_read(case) as db:
                for table in (TABLE, CLOCK_TABLE):
                    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                        db.execute(f"UPDATE {table} SET signature='forged'")
            # Changed actual member inventory fails closed in the same reader.
            with current_mapping_read(case) as db:
                ref = mapping.block_shares[0][0]
                db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (ref,))
                with pytest.raises(ValueError, match="invalid or unsupported"):
                    case["mapping_reader"](db, case["namespace"])
            # A registered row with modified policy is not a signed clock.
            with current_mapping_read(case) as db:
                db.execute("UPDATE runtime_character_clocks SET policy_ref='changed' WHERE mapping_id=?", (clock.mapping_id,))
                with pytest.raises(ValueError, match="registered role clock changed"):
                    case["mapping_reader"].current_role_clock_identity(db, case["namespace"])
            # Changed installed asset bytes invalidate the external package pin.
            path = case["package_root"] / PROFILE_PATH
            content = path.read_bytes()
            try:
                path.write_bytes(content + b"\n")
                with pytest.raises(ValueError, match="verified installed runtime"):
                    case["mapping_reader"].profile()
            finally:
                path.write_bytes(content)
            # Revoking the actual paired Owner key invalidates the signed
            # session. No synthetic guard or fabricated revoke DTO is used.
            case["pairing_source"].revoke_credential(
                administrator_credential=case["admin_peer"],
                authority_namespace=case["authority_namespace"], principal=case["principal"])
            with pytest.raises(Exception, match="Owner|owner|principal|session|pair"):
                with current_owner(case):
                    pytest.fail("revoked Owner obtained a current process lease")
            with pytest.raises(Exception, match="Owner|owner|principal|session|pair"):
                with current_mapping_read(case) as db:
                    case["mapping_reader"](db, case["namespace"])
        await asyncio.to_thread(accept)
    await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
        after_role_initialization=after_role, enable_d09_workbench=True, enable_d04_root_cpu=True)
