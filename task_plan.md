# Embodiment 3.0 rewrite

> 2026-09-30：用户将原会话 `01a0c908-2e83-7453-9d34-25628e22b8e7` 的任务交由本会话接手，并再次明确要求完成插件全部后端。当前执行记录见 `docs/plans/alpha1-20260923/backend-execution-20260930.md`；目标仍是 alpha1 全部非前端部分，接手、局部编译或四条链路补漏均不代表完成。

> 当前阶段（2026-09-23）：用户已要求落地完整重型 `embodiment-3.0.0-alpha1`。当前实施闸门和工作包见 `docs/plans/alpha1-20260923/architecture-gate.md`、`docs/plans/alpha1-20260923/task_plan.md`；十二域设计入口见 `docs/architecture/sylanne-3-design-index.md`。此前纯本地设计阶段与 D06/D07 计划保留作历史；下文早期实施进度不代表 alpha1 已通过。正式版号、PR、推送和发布待实际门槛与授权，不能把开发适配器改名交付。

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


## 2026-10-20 当前任务：全部 283 项生产源码链

用户明确要求继续逐项查全部283需求，修完代码缺口；服务器实测由用户负责。旧交付 production-closure-r1 与 codex/beta1 982e4c9 是本轮固定基线，不能当本次全部需求通过。

1. 已完成审查覆盖（不等于实现闭合）：原283行分母全部逐行实际链审查；台账 docs/plans/complete-agent-20261006/beta1-283-source-chain-audit.json。
2. 进行中：逐项修复并复核真实授权、producer、consumer、失效/删除、cold/replay。审查归类134项含代码缺口，保留总任务HOLD；新增修改随独立应用收据记录，不因局部修复自动改整行通过。
3. 随修改执行必要的有限验证：保留首次失败，已绿部分不无故重复。全部283行已有具体源码结论；最终统一快照尚未冻结，旧证据不能转移。
4. 待执行：独立新快照和不含测试的运行ZIP<=16,000,000字节，沿用未变native真实hash；服务器/HOLD资格单列。

主对话唯一G写者；全分母审查已完成，Sol按限定实际修改复核ABI；仅必要共享架构契约复用一名Astra high，其余不自动恢复。无真实模型/sender，不SQL修账，不改TTL/预算。

当前共享 Natural 修复：最终原件 canonical 准备已接真实 inventory Work，有限 codec/清理验证已保存；独立首次 Source READ Work、最终同步原上限及其他283领域缺口继续实施。审查覆盖283/283不是代码闭合283/283。


2026-10-20 r18（实际源码继续，非冻结/交付）：Owner承诺首建→明确Scope→具名确定性Prepare→PromiseUse→真实outbound采纳→communicated/ACK的已有协议接线落入产品；共享commit fresh返回临时11字段正文摘要，实际持久receipt剔除正文，只保存真实stage与同CommitReceipt导出的4字段Scope元数据。已提交Scope恢复先只查固定nullness元数据，再沿原操作/请求与当前Owner fence恢复，不新建授权、预算或发送。Host实际outbound结果现在消费Owned lease并最终释放。单次同源Vue typecheck/build130模块，双运行资源1,841,965 bytes，SHA adf37c2eccd4552f30e91f88d95052d458b16799c2cd5dd5a8cb5757671d4bb1；浏览器/服务器未验。
D13已采用后的独立fact READ与distinct metadata-only duplicate replay为真实Work kind；ordinary FULL/initial/P2 roster官方RPC在SQL外、每实际事务完整currentness核验，跨后续调用只用私issued prepared+原retained operation，最终真实closed callback释放元数据。C09 actor已接退休receiver清理：continuous drain后、Graph checkpoint/关闭及capture前，PREPARED切换前、SWITCHED显式旧→新恢复分开；首HOLD保留失败，不循环同失败，不用进程退出代替durable owner terminal。READ/remote范围已落，WRITE/model formal terminal、fresh完整consumer安装和controlledSDK-ready仍在编码。
283全分母记录继续保持原134/98/50/1，不按编译/import/build提升。只读重核发现11,054条旧源码证据中3,950条哈希已变化，123/134 confirmed-gap行含变化文件，属于需重新核当前源码，不能视作PASS或已闭合。D05真实prior/boundary SourceWork和其输入producer继续补。POSIX TLS加载已移除纯schema-test开关；测试源不进运行ZIP成员，尚未构新ZIP。保留全部旧失败数据库、日志、快照；无DB/full节点/付费/sender/WSL/native/服务器运行，无新冻结/推送/发布。


### r19 continuation — IN PROGRESS / HOLD

Continue D13 generation/Counter first-writer obligations, real Core birth/retirement, Source metadata remaining actual consumers/producers and authorized legacy capture; then remaining 283 code gaps. Keep first-failure evidence; do not rebuild/retest unchanged green nodes or treat frontend build as closure. Final artifact remains runtime-only <=16,000,000 bytes, not yet produced.


### 2026-10-21 r29 — actual D13 / Source / R09 continuation, IN PROGRESS / HOLD

Actual V4 parent cleanup drain, installed metadata-only Life census controller and explicit Body-profile mTLS census/segment interfaces are applied and compiled. R09 native Method routing, original absolute deadline and same-W01 preparation facts are wired; scheduler lifetime and real terminal adoption remain in progress. D04 per-producer FullPersonaWriter/role lineage, R03 actual Case C3 Source groups, and labor chronological B/C/adoption producers are being integrated by disjoint writers. First source-review profile/ABI errors were preserved and corrected before DB execution. No full-node rerun, database, provider, sender, new snapshot, package, push or server acceptance. Full 283 row statuses remain unpromoted. Exact hashes and open points are in audit ongoing_source_work_20261021_r29.


### 2026-10-21 r30 — actual source interfaces / FIRST IMPORT FAILURE PRESERVED / HOLD

Applied actual R09 retained same-ticket child handoff, original/parent deadline cap, explicit labor B Source/metadata/dual-purpose/quote/CAS/census consumption, independent policy/plan producers, and R03 Case attention/signature/Review V2 compatibility seams. Source candidates compiled before guarded writes. The one new shared-module import/API check FAILED before any Work/DB: ProductionOriginalRefV1 is missing from the R09 command annotation module. First log is D:/bun/tmp/sylanne-r30-census-r09-source-interface-20261021.log; sole writer is repairing the formal import, without repeating installed nodes. New labor C Source classification, chronological rebuild, Host WRITE adoption/settlement/cold, retained accounting basis/C09 and D04 FullWriter remain actively in progress. No new frozen snapshot/package/push or server/native/model/sender execution. All 283 row statuses remain unpromoted; exact changing-source hashes and limits are audit r30.


### 2026-10-21 r32 — actual consumers / cold ACK / shared lifetime, IN PROGRESS / HOLD

Public D13 adoption/execution now enters actual metadata Work, same-ticket handoff and original Core/Source gates; Owner async continuation consumes actual Progress before ordered checkpoints. Initial Body install signs its true GraphReceipt checkpoint in the installation transaction; no old missing checkpoint is invented. Shared handoff outer lifetime now survives inherited final mappers and is released on abort; one necessary existing scheduler regression run passed 11 cases in 1.81s, including updated lifetime ordering and first-error cleanup. This is not D13 business/Numeric/native/installation/server acceptance. Selector/Owner WebUI rebuild factory, exact new C09 retirement consumers, R03 experience causality and remaining whole283 production gaps stay open. No new package/freeze/push; whole283 row statuses unchanged. Exact hashes and first-checker limits are audit r32.
