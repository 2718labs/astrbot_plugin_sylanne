# Persistent memory and recall integration acceptance

Date: 2026-09-22. Workspace: `G:\Sylanne`. Branch: `codex/embodiment-3-rewrite`.
HEAD remains `72de068bf6f97a70086abdddc8cc487933350c5c`; implementation is uncommitted.

## Executed evidence

- Core/native receipt: `artifacts/verification-20260922T124852.309287Z.json` and matching `.log`.
- AstrBot SDK receipt: `artifacts/host-verification-20260922T124852.707557Z.json` and matching `.log`.
- 173 core Python tests passed, including 4 graph-query tests, 46 memory types/repository/retrieval/recall tests, and 21 recall-policy tests.
- 2 Rust tests passed. Cargo formatting, checking, tests and release build passed.
- 9 controlled SDK tests passed against isolated AstrBot 4.28.1.
- Python compilation, retired-import boundary checks, Ruff 0.16.0 and Git diff whitespace checks passed.
- Both receipts report `source_drift=false`. Main-agent comparison of all recorded hashes against current files found zero mismatches (46 core and 29 host manifest entries).

Executed from the repository root:

```powershell
& 'C:\Users\pidan\AppData\Roaming\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe' rewrite/tools/verify.py
& 'D:\bun\tmp\codex\sylanne3-host\Scripts\python.exe' rewrite/tools/verify_host.py
```

Worker checks preceded this combined run. Independent review covered types and repository; main integration review covered retrieval and the recall bridge. No unresolved P1/P2 finding remains in that scope. A deterministic two-connection WAL regression exercises another connection committing an identical event between receipt lookup and domain reads: the first call returns the original duplicate receipt, with one persisted source revision. This does not constitute long-running concurrent load testing.

## Implemented behavior

- `memory_types.py`: frozen source/interpretation records, strict JSON fields and finite times, explicit origins/status/audiences/purposes, and registered memory graph types.
- `memory_repository.py`: atomic immutable source plus mutable access creation; revised interpretations with preserved history; operation-bound event identity; complete read/epoch CAS; restart persistence; current and historical-knowledge filtering. Confirmed interpretation admission requires an observed, confirmed source; this validates caller attribution rather than independently establishing real-world truth.
- Permissions are checked through the full source ancestry. Interpretation dependencies include ancestor source/access keys, so ancestor restriction invalidates dependent interpretations and graph projections. Source withdrawal is logical access control, not physical deletion. Evidence proofs contain keys and versions with empty payloads. An already invalid interpretation can be denied using just its invalid atom and epoch.
- `memory_retrieval.py`: direct point reads for explicit IDs; bounded structured pages and case-insensitive substring predicates for other queries; speaker/subject, audience, purpose and time filtering; authorized supporting sources; provenance roots; version proofs; candidate/node/page usage; resumable cursors and explicit complete/incomplete coverage. Pages and proofs must share an epoch, with another epoch check before returning.
- `memory_recall.py`: connects actual repository results to RecallPolicy. Working-set IDs are revalidated through exact queries. Light/deep stages consume actual candidate/node counts, stop further batches once the declared predicate has a hit, and resume incomplete searches when needed. No auxiliary model calls are made in this slice. Initial epoch-read time counts toward the deadline; no new batch starts after expiry, and late evidence is not accepted.
- Interpretation hits activate their supporting source IDs; they do not create new external evidence. Observed/reported attribution is kept separate from internal/simulated attribution. Provenance families are supplied source metadata, not a certification of independent evidence.
- Mandatory correction, commitment, deadline and classification checks remain unresolved in this bridge. Lexical matches cannot satisfy them. `READY` means coverage of explicitly supplied retrieval predicates, not semantic truth or authority to execute an action. Every returned plan retains `action_authorized=False`; no message is sent and no recall experience is committed.

## Remaining work and manual gates

This is the persistent-memory/retrieval slice of phase 5b, not complete memory-product or Sylanne 3.0 acceptance.

1. The root AstrBot application still uses the labelled semantic fixture. Wire the graph/memory/recall APIs into the new domain runtime before attempting live memory acceptance. Current SDK tests establish regression compatibility only; they do not exercise this new memory chain through a real model/platform.
2. After that integration, use isolated bot/persona accounts to check private-to-group isolation, source withdrawal between retrieval and expression, correction after restart, duplicate platform delivery, and unload during a query. Revalidate the returned epoch immediately before a new decision; stored batches are historical snapshots.
3. Current methods are synchronous for bounded off-thread callers. Async admission/cancellation, durable working sets/recall cooldowns and persistent recall experiences remain open. The timeout is cooperative between database batches, not interruption of an in-flight SQLite call.
4. Full-text/vector indexes, event segmentation, competing-evidence resolution, semantic extraction, consolidation, physical deletion, full historical interpretation reconstruction and schema migration remain open. Substring matching over bounded structured pages is not a scalable semantic search claim. An incomplete miss never proves that a fact does not exist.
5. Character domains, the workbench, native distribution and real-platform release acceptance remain open. Measure realistic corpus scale, foreground/background cost and longitudinal quality before making speed/quality comparisons. No existing user memory database was migrated or erased in this work.

The complete requirement scope remains in `REQUIREMENTS.md`; executable API details are in `MEMORY_CONTRACT.md`.
