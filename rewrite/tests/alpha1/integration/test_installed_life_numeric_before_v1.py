"""Permanent real-installation prospective Life before-state acceptance.

The donor installs an actual Owner-authored native root, executes SourceNote
once and adopts its actual Episode. No prepared/capture DTO or SQL original is
injected. The final numerical chain may reuse this runner instead of repeating
this antecedent as a separate leaf acceptance.
"""
import asyncio
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest

from test_d11_installed_life_source_note_v1 import installed_d04_root, run_installed_owner_life_case


async def run_installed_life_before_case(tmp_path, installed_d04_root, *,
        natural_workflow_builder=None, after_before_async=None,
        enable_d04_semantic_drive=False, enable_d04_joint_numeric=False,
        initial_phase_fixture_installation=None,complete_c09_current_v3=False,
        c09_protected_root=None,c09_phase_setup_file=None):
    if initial_phase_fixture_installation is None:
        from beta1_fixture_phase_controller_v1 import current_beta1_fixture_case_v3
        current=current_beta1_fixture_case_v3(installed_d04_root)
        if current is not None:
            if after_before_async is not None:await after_before_async(current)
            return
        root_operation_id=str(uuid4())
    else:
        selected=initial_phase_fixture_installation.initial_bundle.life_d04_before_capture_policy
        if selected is None:
            raise ValueError("Numeric first phase requires its Root-prepared explicit prospective selector")
        root_operation_id=selected.root_operation_id

    async def after_episode(case):
        def inspect():
            from sylanne3.runtime.d11_life_preparation_v1 import read_prepared_life_by_ref_v1
            from sylanne3.runtime.d04_life_before_original_v1 import read_life_d04_before_original_v1
            from sylanne3.runtime.d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
            from sylanne3.graph_types import AtomKey
            from sylanne3.runtime_contracts import canonical_digest
            from sylanne3.domains.d01.production_operations_v1 import plain_v1
            import json
            ns, store = case['namespace'], case['store']
            path = Path(store._db.execute('PRAGMA database_list').fetchone()[2])
            with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as cold:
                cold.execute('PRAGMA query_only=ON'); cold.execute('BEGIN')
                key = AtomKey.from_token(case['episode_ref'])
                raw = cold.execute('SELECT value FROM graph_atoms WHERE token=? AND valid=1',
                    (AtomKey(key.owner, PROVENANCE, 'record').token,)).fetchone()
                proof = decode_internal_life_value_v2(PROVENANCE, json.loads(raw[0]))
                rows = cold.execute('SELECT original_ref FROM graph_d11_life_originals_v1 '
                    "WHERE bot=? AND persona=? AND kind='prepared'", ns.as_tuple).fetchall()
                assert len(rows) == 1
                prepared = read_prepared_life_by_ref_v1(cold, namespace=ns,
                    prepared_original_ref=rows[0][0], issuer=case['d11_issuer'])
                before = read_life_d04_before_original_v1(cold, prepared=prepared, issuer=case['d11_issuer'])
                assert before.root_operation_id == root_operation_id == case['root_operation_id']
                assert before.root_digest == case['root_original'].original_digest
                assert before.selection_scope == 'explicit_installed_root_complete_inventory'
                assert before.assertion_scope == 'authenticated_state_before_execution_not_identified_causation'
                assert before.execution_id == prepared.binding.execution_id == proof.event.activity.execution_id
                assert before.prepared_digest == prepared.digest
                assert before.captured_at_utc <= proof.event.activity.started_at <= proof.event.activity.completed_at
                assert before.activation_generation == proof.event.activation_generation
                assert before.graph_incarnation == proof.event.graph_incarnation
                # Complete selected-root inventory, not one convenient Feeling.
                root_refs = tuple(sorted(ref for ref, _, _ in json.loads(case['root_original'].output_json)['rows']
                    if AtomKey.from_token(ref).type_name == 'd04.numeric_checkpoint.v2'))
                assert tuple(m.checkpoint.ref for m in before.members) == root_refs
                assert before.members and all(m.root_digest == before.root_digest for m in before.members)
                assert cold.execute('SELECT count(*) FROM graph_d11_life_originals_v1 '
                    "WHERE bot=? AND persona=? AND kind='d04_before_v1'", ns.as_tuple).fetchone() == (1,)
                again = read_life_d04_before_original_v1(cold, prepared=prepared, issuer=case['d11_issuer'])
                assert again == before and canonical_digest(plain_v1(again)) == before.digest
                assert cold.total_changes == 0
            return {**case, 'numeric_before': before, 'numeric_life_prepared': prepared,
                'numeric_occurrence': proof}
        complete = await asyncio.to_thread(inspect)
        if after_before_async is not None:
            await after_before_async(complete)

    await run_installed_owner_life_case(tmp_path, installed_d04_root,
        natural_workflow_builder=natural_workflow_builder if initial_phase_fixture_installation is None else None,
        initial_phase_fixture_installation=initial_phase_fixture_installation,
        complete_c09_current_v3=complete_c09_current_v3,c09_protected_root=c09_protected_root,
        c09_phase_setup_file=c09_phase_setup_file,enable_c09_maintenance=complete_c09_current_v3,
        life_before_root_operation_id=root_operation_id, after_episode_async=after_episode,
        enable_d04_semantic_drive=enable_d04_semantic_drive,
        enable_d04_joint_numeric=enable_d04_joint_numeric)


@pytest.mark.asyncio
async def test_installed_life_before_actual_prepare_claim_and_cold_original(tmp_path, installed_d04_root):
    await run_installed_life_before_case(tmp_path, installed_d04_root)
