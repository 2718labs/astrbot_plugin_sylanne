# D12 repeated C09 checkpoint — 2026-09-30 11:06 UTC

No mutating acceptance process remains active. The actual second erasure is
safely retained in its durable pending phase. No barrier, accepted phase, second
storage rebase or second RELEASED has been claimed.

## Completed adjacent acceptance

- C11 real-process forward: PASS 1/71.01 s,
  `../../verification/c11-process-forward-1035.log`
- C11 failed-candidate current-data rollback: PASS 1/188.54 s,
  `../../verification/c11-process-rollback-1037.log`
- C11 latest-package pre-switch abort and activation/executor exact replay:
  PASS 1/59.81 s, `../../verification/c11-process-abort-1041.log`
- Explicit C11 boundary: root-owned path checks and systemd are mapped to private
  test paths and actual subprocess groups. All Owner/Core/journal/Graph/mTLS,
  backup, candidate, pointer, native/catalogue and activation proofs are real.
  No privileged deployment or external provider/platform action occurred.
- First real C09 RELEASED source Owner admission, survivor read and ordinary
  access-revoke write passed on the retained fixture; the C09 worker also ran
  its fresh full four-process case successfully. The immutable grant is retained.

## Current repeated-erasure evidence

Permanent test:
`rewrite/tests/alpha1/integration/test_d12_repeated_c09_owner_v1.py`

Process helper:
`rewrite/tests/alpha1/integration/d12_repeated_c09_acceptance_support_v1.py`

Retained actual root:
`/workspace/scratch/1c46e691a951/sylanne/build/d12-repeated-c09-1051/test_two_actual_c09_releases_p0`

The initial run completed the first PREPARED/SWITCHED/RELEASED, then a real fresh
signed Owner/storage admission, survivor read and new actual Graph erasure plan.
The old plan-verifier grant-incarnation equality rejected the next entrance.
Log: `../../verification/d12-repeated-c09-1051.log`.

After the lead's reviewed short read-observation hook, the same retained actual
second operation successfully committed its real Authority pending deletion.
It then stopped at `GraphCoordinator.commit_current_c09_source_barrier_v1`,
currently around line 19611, with `C09 graph Owner differs from Authority`.
Log: `../../verification/d12-repeated-c09-prepare-1103.log`.

The packet retains `next_operation_id`, selected from its actual immutable Graph
plan, and `next_erased_refs`. The process helper now detects an existing actual
pending request, rereads that exact typed plan and invokes the product replay
path. It does not request a new ordinary content lease or a new deletion while
pending. A fresh full test still checks that its first signed survivor read
occurred in the expected process; a retained pending retry truthfully reports
`first_fresh_owner_read=false` for that retry.

## Source changes held by D12

`authority_service/d12_owner_storage_admission_v1.py` now independently reads
all three actual pending/accepted/closed ancestor receipts through the installed
scoped reader. It verifies the immutable accepted original and PREPARED digest,
exact pending.after → accepted.before → prepared.old anchor, actual rebase,
closed original, Graph ACK and scoped-applied Core event. The next generation
starts at the previous applied epoch through its actual pending.before anchor;
there is no `>=` allowance. All Core/journal/RELEASED observations occur outside
the service's Graph SQL snapshot. The snapshot rereads the same ACK/certificates.

The first-generation retained Owner read passed these stronger joins. Its final
ordinary write correctly rejected re-withdrawing a source that the prior
successful acceptance had already withdrawn; that was not a new ancestry fault.

The existing C09 fixture has only one additive optional `additional_sources=()`
argument, with default behavior unchanged. The repeated case adds a second,
unrelated source, preserving an ordinary survivor for the final read/write.

All above Python sources compile and pass Ruff F821/F822/F823.

## Shared lead changes and remaining blocker

The lead owns `current_erasure_service.py`,
`current_erasure_plan_graph_verifier.py`, shared GraphCoordinator and server
installation forwarding. The concrete hook is:
`erasure.install_current_owner_storage_reader_v1(owner_service)`.

The remaining Graph barrier must validate the current location through the
actual authorized plan/storage evidence while retaining the immutable original
Owner grant. It must not waive incarnation equality based on a caller DTO.
The current pending request must be resumed, not replaced.

## Resume commands

From the repository, after the shared barrier repair compiles:

```sh
PYTHONPATH=.:rewrite ../../venv/bin/python \
  rewrite/tests/alpha1/integration/d12_repeated_c09_acceptance_support_v1.py \
  prepare_second \
  /workspace/scratch/1c46e691a951/sylanne/build/d12-repeated-c09-1051/test_two_actual_c09_releases_p0
```

On successful actual PREPARED generation 2, run that same helper/root sequentially
with `switch`, `release`, then `verify`. Inspect every outcome before advancing.
After the retained chain closes, run the permanent pytest once with a new empty
basetemp to establish all seven actual cold processes and both fresh Owner
admissions in one complete case.

No test session remains active: 9478/35302 ended at the documented failures;
89684/9862 ended PASS. C11 fixtures performed their actual process cleanup.

## 11:28 UTC resumed checkpoint

The independently reviewed shared barrier repair passed on the exact retained
second pending original. The actual second Graph barrier and Authority accepted
receipt are now durable. No prior original was reconstructed or replaced.

The fixture correctly uses `recover_prepared_pending` and the actual persisted
updated permit when resuming a pending request. It does not fabricate an Owner
bearer or attempt a new content login while the namespace is pending. Fresh
Owner login is performed only for the new request entrance. The helper also
recognizes an already accepted original for a subsequent same-operation retry.

Current blocker: `AuthorityErasureClosureInventory._registry_locked` rejects
`execution journal installation changed` because the immutable initial surface
registry points to generation 0 while the actual current signed C09 successor is
generation 1. Log: `../../verification/d12-repeated-c09-prepare-1127.log`.
The packet's active operation is now the second accepted operation. The next
work is a concrete, internally issued current-location qualification from exact
signed C09 ancestry, preserving the original registry bytes/digest. The shared
reader will also support consumer-specific model/self-identity location checks;
it must confer no new Owner or business admission and must never accept caller
DTOs or a broad path/journal-ID inequality waiver. A second storage rebase has
not yet started. The same `prepare_second` command remains the recovery entry.

### 2026-09-30 12:30 UTC continuation

The source Owner lineage and immutable grant remain unchanged. The common
`InstalledCurrentSourceLocationQualifierV1` now authenticates separate Core and
Graph observations through actual selected storage ancestry. An actual released
generation-one case accepted its live read-fence observation and rejected copied,
wrong-purpose and finished-fence observations (`current-source-location-1205.log`).

The retained second operation reached its durable INTENT, then the full mapped
four-role inventory and selected-Graph snapshot passed and a real generation-two
Graph candidate was recorded (`d12-repeated-c09-prepare-1218.log`). The next normal
fixture reopen changed source SQLite bytes, so reuse of that immutable candidate
correctly HOLDs (`d12-repeated-c09-prepare-1219.log`). Do not rewrite its fingerprint
or start a replacement deletion in that preserved fixture. It remains evidence
of the distinct cold-INTENT startup/recovery gap.

The mapped inventory keeps the original installer manifest/resources/generation
metadata and V2 scan preimage. Its V3 envelope authenticates exact per-role
ancestor-to-selected mappings, registered companions, retired path absence,
all original directory children and duplicate selected-path coverage. Existing
V2 inventory tests pass (4/0.22s, `c09-inventory-v2-regression-1229.log`). Final
close/scan continuation is implemented in `c09_final_inventory_v3.py`; integration
awaits the separately requested closing-boundary review. A fresh seven-process
permanent case is required after that integration. No second RELEASED or final
second-generation Owner acceptance is claimed at this checkpoint.
