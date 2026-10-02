"""Actual Owner/GCP FIRST acquisition with installed TLS worker execution identity.

This node covers delegation acquisition and its durable cold reader, not
Authority model admission/call/settlement/content adoption. No model is sent.
"""
import pytest
from test_installed_internal_life_content_v1 import installed_d04_root,run_installed_life_content_preparation_case

@pytest.mark.asyncio
async def test_installed_life_content_worker_v2_acquires_authenticated_subject_once(tmp_path,installed_d04_root):
    await run_installed_life_content_preparation_case(tmp_path,installed_d04_root,acquire=True,worker_v2=True)
