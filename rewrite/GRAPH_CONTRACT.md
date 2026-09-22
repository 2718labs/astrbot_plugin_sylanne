# Typed graph milestone contract

Status: implementation contract for phase 5b; not a whole-product completion claim.

## Shared API

`graph_types.py` reuses strict JSON validation and Event/Scope/errors from contracts.py. Frozen values:

- `Owner(kind, bot, persona, subject=None)`: kind is persona/relation/scene/event/activity. All identifiers nonempty strings; persona requires subject=None, other kinds require nonempty subject. Distinct owner kinds cannot alias.
- `AtomKey(owner, type_name, name)`: stable `token` property is canonical JSON of `[kind,bot,persona,subject,type_name,name]`; `from_token(token)` reconstructs and validates.
- `TypeSpec(name, owner_kinds, storage_role, validator, immutable=False, schema_version=1)`: roles source/state/projection/cache. validator takes a detached JSON object, returns None or raises. Registry unknown types fail closed. `TypeRegistry.register(spec)`, `.validate(key,value)`, `.spec(name)`. A store freezes its registry/catalogue at construction; it cannot silently adopt later registry edits or reopen existing types with another schema version.
- `GraphVersion(key, revision)` nonnegative exact integer.
- `GraphAtom(key, revision, value, valid=True)`; missing atoms have revision 0, value {}, valid=False.
- `NamespaceEpoch(bot,persona,revision)`; incremented by every state-changing transaction for that namespace, including new records. Used for query-domain/negative-cache invalidation.
- `GraphSnapshot(atoms, epochs)` provides `.get(key)` and `.versions`.
- `GraphWrite(key,value,dependencies=())`; dependency keys must be in complete read set. They refer to post-transaction revisions when also written, otherwise observed revisions; revision zero can describe observed absence. Live-invalid dependencies are forbidden unless recomputed in this transaction. Source/history references belong in payloads, not invalidating dependency edges.
- `GraphCandidate(event, reads, writes, epochs=())`. All keys/epochs must belong to event.scope.bot/persona. Cross-owner atomicity is supported within that namespace; cross-bot/persona operations require a future explicit protocol, never an implicit broad grant.
- `GraphReceipt(status,revisions,invalidated,epoch)` status committed/duplicate; all tuples hold GraphVersion except epoch which is NamespaceEpoch.

`GraphStore(path,registry)` in graph_store.py extends the existing Store, using its same connection/lock, not a second database service. Existing fixture API remains for host tests until product runtime cutover. New API:

- `graph_snapshot(keys) -> GraphSnapshot` coherent multi-owner read and namespace epochs; reject duplicates/unknown types.
- `graph_commit(candidate) -> GraphReceipt` event deduplication by scope and event ID, conflicting digest rejected, every write in full CAS read set, optional namespace epochs CAS, validation before writes, all-or-nothing commit.
- `graph_epoch(bot,persona) -> NamespaceEpoch`.

Validation, read values and writes must detach mutable JSON containers. A single transaction writes state, dependency edges, revision history and event receipt. Historical revisions include validity, not only user writes. Immutable source atoms reject overwrites; immutable records cannot have invalidating dependencies. Ordinary correction invalidates derived interpretations, not actual source/experience records. Explicit erasure is a future separate protocol.

## Invalidation and recomputation

On writing changed keys, traverse the old reverse dependency graph transitively, including through freshly recomputed keys. Unwritten descendants become invalid and their revisions advance; already-invalid descendants need not advance again but traversal continues. Freshly written descendants remain valid only if their declared dependencies are valid after the transaction. Reject instantaneous dependency cycles, including cycles formed with stored edges. Read snapshots expose invalidity; it is never hidden by serving an older valid value.

Unrelated owners/atoms remain unchanged. Recomputing a dirty DAG from a frozen snapshot must match an independent full recomputation under the same inputs. No numerical local-truncation guarantee is claimed by the dependency store.

## Operator API

`operators.py`: `OperatorSpec(name, inputs, outputs, compute, delayed_inputs=())`. Keys are AtomKeys; compute receives a detached mapping AtomKey -> JSON dict and returns an exact output mapping. Pure DAG operators only in the first executable compiler. Delayed inputs are a subset of inputs and always read the frozen snapshot; instantaneous edges use staged producer outputs. Multiple writers, undeclared access/output, malformed keys and unsupported instantaneous cycles fail closed.

`compile_operators(specs) -> OperatorPlan`, `.order` is tuple of operator names, `.required_keys` is deterministic tuple of all input/output keys. `plan.evaluate(snapshot, changed=None) -> tuple[GraphWrite,...]`: changed=None runs all; otherwise seed operators reading changed keys or with missing/invalid outputs and transitively activate instantaneous descendants. Deterministic independent order. No inputs may silently become {}; invalid existing inputs require a prior staged replacement, otherwise fail. Missing input policy is explicit: no generic acceptance of absent numerical/domain input. Return a topologically ordered write set, with current instantaneous inputs as invalidating dependencies. Delayed/history inputs are frozen causal references, not current-version dependency edges; temporal operators must preserve their actual input revisions in domain payloads/history. First compiler does not support coupled numerical SCCs; unsupported cycles are rejected, never iterated until they appear stable.

`plan.job(snapshot, changed=None)` freezes the snapshot and returns a resumable `OperatorJob`. `step(budget, cancelled)` evaluates at most `budget` operators, checking cooperative cancellation between operators; output maps are validated in full before a step updates staged state. A single Python operator must itself bound its work; the scheduler cannot forcibly terminate arbitrary code. `evaluate` uses the same job implementation.

`GraphRuntime(store,scheduler,capacity=8).apply(event,plan,changed=None)` owns bounded admission, off-thread snapshot/commit, scheduled computation and complete CAS. Cancellation is joined through the active operator/database call. Cancellation during commit may leave a committed event and callers must inspect/retry the same event identity; this runtime performs no external delivery. `close` drains its operations but leaves shared store/scheduler ownership to the caller.

Graph event rows store full input revisions and epoch reads; every history revision links to its generating event. This preserves which historical revisions a delayed computation read. Persisted operator name/version/plan identity is not yet recorded, so independent replay of an entire versioned operator package remains future work.

## Required evidence

Multi-owner CAS/rollback, absent reads, restart/event conflict/deduplication, transitive invalidation across fresh intermediates, immutable source protection, schema reopen checks, epoch phantom detection, namespace isolation, cycle rejection, detached containers, DAG sparse/full equivalence and delayed feedback frozen reads. Tests must exercise real SQLite; compile first, targeted tests, then one integrated acceptance run.
