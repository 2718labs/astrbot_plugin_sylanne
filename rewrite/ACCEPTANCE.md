# Foundation milestone acceptance — 2026-09-22

**Status: engineering foundation accepted locally; full Embodiment 3.0 product remains in progress.**

This document records the earlier foundation snapshot. Subsequent user instructions retired the old root runtime and required a full heavyweight product architecture. See `HOST_ACCEPTANCE.md` for the later cutover checks and `../docs/architecture/embodiment-3-system.md` for the overall design; statements below about retaining the old entry describe the historical foundation milestone only.

Workspace `G:\Sylanne`, branch `codex/embodiment-3-rewrite`, baseline `72de068bf6f97a70086abdddc8cc487933350c5c`. The new files are working-tree changes, not a published release. The original 2.5.1 entry point is not replaced in this milestone. The executable new chain lives in `rewrite/sylanne3` and does not import the original core.

## Executed verification

Interpreter: `C:\Users\pidan\AppData\Roaming\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe` (CPython 3.13.14). Native toolchain: Rust/Cargo 1.97.0, Windows x86_64 MSVC. Ruff 0.16.8.

Executed from the repository root:

```powershell
& 'C:\Users\pidan\AppData\Roaming\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe' rewrite/tools/verify.py
uvx ruff check rewrite/sylanne3 rewrite/tests rewrite/tools
git -c core.safecrlf=false diff --check
```

| Check | Observed result |
| --- | --- |
| Static AST boundary | PASS; no old-core imports found in new runtime/tools |
| `cargo fmt --check` | exit 0 |
| `cargo check` | exit 0 |
| `cargo test` | 2 passed, 0 failed |
| `cargo build --release` | exit 0; actual DLL linked |
| Python new-chain suite | 43 passed, 0 failed; 2.802 seconds reported by unittest |
| Python compilation | PASS |
| Ruff | All checks passed |
| Git whitespace check | exit 0 |

The MSVC linker emits an informational library/object creation message surfaced by Rust as a linker warning; it did not prevent compilation. No old 2.5.1 full-suite result is claimed because its production code was not changed or exercised by this isolated milestone.

Detailed machine-readable receipt: [verification JSON](artifacts/verification-20260921T180949.720251Z.json), with [complete output log](artifacts/verification-20260921T180949.720251Z.log). UTC receipt time corresponds to 2026-09-22 local Asia/Shanghai. It records the Git base, branch, each command/exit code, and SHA256 for the exact new code/tests before and after checks. `source_drift=false`. Artifacts are local ignored files; rerun verify to regenerate them on another machine.

Release DLL SHA256: `6531a11f0322686864316232c2223c5415ca12ed89aba97dbd6e1c949cb36414`. Build output is intentionally not committed.

## What the executable slice proves

- Positive recovery and allowed coupling produce the declared discrete operator; full residual plus documented roundoff allowance controls accepted numerical output.
- Refinement resumes the same problem without repeating physical input or advancing event time.
- Full read-set validation, absence versions, transaction rollback, scoped event idempotence/conflicts and restart behavior work in the tested SQLite scenarios.
- CPU steps run in an owned bounded worker pool; pending/running work both count toward capacity; fair service, cancellation and actual worker exit are tested.
- Typed interpretation/correction events replay valid episode evidence, retain invalidated evidence records and preserve already-delivered local history.
- Pending actions depend on the committed state/evidence revisions; obsolete actions are superseded before claim. Delivery outcomes are separate from numerical/model suggestions.
- Relevant state changes alter the deterministic expression contract in a counterfactual test. This is not evidence of general natural-language consistency or emotional realism.

## Review findings fixed before acceptance

1. Extreme coupling could erase the recovery diagonal in floating-point assembly and falsely certify a wrong solution with zero error. A regression first reproduced the failure; structure-preserving residuals, roundoff allowance and representability rejection fixed it. Independent actual-DLL probes confirmed the original case and impossible nonzero tolerance are rejected, while exact zero remains accepted.
2. Cancelling during the SQLite delivery claim could leave an unexplained `sending` without calling the transport. Lifecycle tasks are now owned and joined; successful claim followed by pre-send cancellation records `failed/cancelled_before_send`. Independent one- and two-cancellation probes produced zero sends, settled state and no automatic resend.
3. Active reuse of the same mutable solver job could run its steps concurrently. Identity admission rejects duplicate active jobs until actual exit; the regression was observed failing before the fix.
4. JSON tuple serialization, stale pending actions, and scope-independent action identifiers were corrected and covered by integration tests.

## Manual local demonstration

After building with verify, from the repository root:

```powershell
$env:PYTHONPATH = (Resolve-Path .\rewrite).Path
& 'C:\Users\pidan\AppData\Roaming\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe' -m sylanne3.demo
```

Observed: first episode -> committed `engage`, reaction approximately `(2.7, 0.3)`; identical replay -> duplicate with no new record; correction -> committed `neutral`, reaction `(0, 0)`. Final output: `local_records=2`, `real_messages_sent=0`. The demo uses temporary local storage and a RecordingTransport, not AstrBot, QQ or another messaging service.

## Not yet accepted

- Full plugin replacement, real AstrBot lifecycle, Provider/tool/TTS cooperation or platform delivery.
- Model-generated semantic proposals, calibrated emotion/personality/relationship behavior, longitudinal benefit or speed/cost superiority over 2.5.1.
- Sparse active-region solving, general atom dependency invalidation, online learning, migration and new workbench.
- Process-kill recovery with an automatic dispatcher, real transport idempotency and cross-platform native distribution.
- Continuous-time integration accuracy: present bounds certify only the selected backward-Euler discrete problem within the documented floating-point domain.

The two-component episode example is a test fixture, not the final character-state dimensionality. Pending/sending records after a process crash require inspection; unknown non-idempotent external effects are never automatically replayed.

## Next implementation phase

Create the new AstrBot adapter and bounded semantic-proposal interface against these contracts, then verify actual host lifecycle and cancellation before broader domains/UI. Routine implementation goes to Sol, mechanical tooling to Luna; architecture, mathematical decisions and critical review remain with Astra. No further approval is needed for the already-authorized phased rewrite; public release remains a separate delivery action.
