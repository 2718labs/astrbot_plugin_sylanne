# Embodiment 3.0 rewrite

## Authority and baseline
- User approved the attached whole-plugin redesign and explicitly requested phased implementation on 2026-09-22.
- Baseline: `72de068bf6f97a70086abdddc8cc487933350c5c` (`Embodiment-2.5.1`).
- Workspace: `G:\Sylanne`; branch: `codex/embodiment-3-rewrite`.
- New implementation lives in `rewrite/`; no import of `sylanne_alpha`, `v2core`, `_engine`, or old `v3core` is permitted there.
- Subsequent user instruction retires old interfaces and core; the new root plugin is the sole entry. Legacy reference is Git history, not a runtime fallback.
- User permits a compressed release ZIP of approximately 10 MB. Treat this as acceptable distribution capacity, not a minimum size or permission for unbounded runtime costs; measure actual package contents and sizes at packaging acceptance.
- User requested further design depth beyond the twelve-system outline. Candidate mechanism design is in docs/architecture/embodiment-3-mechanisms.md; this design turn does not implement those future capabilities or claim their acceptance.
- Further design continuation adds docs/architecture/embodiment-3-ecosystem.md. User explicitly requires a redesigned memory module, research-grounded mechanisms, speed/quality tradeoffs and when recall should occur: see embodiment-3-memory.md and embodiment-3-memory-theory.md in the same directory. These are design proposals; theory transfer and performance require implementation and controlled evaluation.

## Phases
1. [complete] Freeze executable foundation contracts and mathematical assumptions.
2. [complete] Implement Rust constrained solver + Python binding, versioned atomic store, bounded resumable scheduler.
3. [complete] Integrate one-scope correction -> solve -> commit -> action -> delivery-result slice using the new components.
4. [complete] Independently review and verify numerical, transactional, scheduling, and causal behavior; record evidence in rewrite/ACCEPTANCE.md.
5a. [complete locally] Sole AstrBot root entry, strict model proposals, durable ingress deduplication, bounded provider admission, SDK integration checks, retirement of legacy interfaces/core/UI/packaging. Full live-host acceptance remains future work.
5b. [in progress; persistent memory/recall slice verified] Typed multi-owner graph, cross-owner transactions, dependency invalidation, namespace epochs, resumable pure operators and bounded async runtime implemented. Persistent source/access/interpretation records, bounded authorized retrieval and a synchronous RecallPolicy bridge are now implemented. See rewrite/MEMORY_ACCEPTANCE.md for 173 core + 2 Rust + 9 controlled SDK tests. Coupled numerical graph planning, domain capabilities, full memory semantics and host integration remain open.
5c. [future] Heavyweight persona/values/needs, rich appraisal and emotion regulation, object-specific relationship model and action contracts.
5d. [future] Layered memory, world/context, cognition, goals/commitments/planning and expressive conversation.
5e. [future] Life activities, habits, schedules and proactive behavior on the shared causal runtime.
6. [future] Full character workbench, native binary distribution, migration, longitudinal behavior/cost evaluation, real-platform and release acceptance.

## Current milestone
Phase 5a connects the foundation to the public AstrBot API and retires the old runtime, following explicit user steering. The restricted appraisal mapping and deterministic replies remain integration fixtures. The approved product scale is a heavyweight character system as detailed in docs/architecture/embodiment-3-system.md. SDK checks with controlled provider/platform inputs do not establish live delivery, language quality, or a complete 3.0 product.

The active full-implementation goal continues through phase 5b and the redesigned memory requirements. The requirement/evidence ledger is rewrite/REQUIREMENTS.md. Source/access/interpretation persistence, bounded temporal/audience retrieval and actual-result recall control are locally verified. Next: asynchronous memory admission/lifecycle, domain-owned mandatory checks, event organization and versioned working-set/recall persistence, followed by semantic/domain and product host integration. Remaining character systems and complete release acceptance retain their full scope.

## Acceptance
- Rust compilation and tests; no third-party native dependency required for the first kernel.
- Full-system residual certificate, independent direct-solve oracle, no-input decay, precision-budget invariance.
- Full read-set validation, all-or-nothing writes, exact event replay idempotence, conflicting event rejection, restart persistence.
- Bounded worker admission, fairness, cooperative cancellation, no event-loop CPU execution; stale results cannot commit.
- Corrections invalidate referenced interpretations without rewriting delivered history or unrelated personality.
- State-derived action contract and durable delivery intent/result separation, including unknown outcome.
- No legacy imports; meaningful integration tests plus source compilation; verified limitations reported explicitly.

## Errors
- Initial Git clone using OpenSSL failed with SSL_ERROR_SYSCALL; retry with per-command Schannel succeeded. No TLS validation disabled.
- Python launcher listed a missing D:\WLDA runtime; use verified uv CPython at C:\Users\pidan\AppData\Roaming\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe.
