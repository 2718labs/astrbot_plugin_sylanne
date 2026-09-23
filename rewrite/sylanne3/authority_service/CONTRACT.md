# Authority service kernel contract

`AuthorityServiceCore` is a server-side storage kernel. It contains no HTTP
listener, TLS, pairing, credential store, OS installer, or plugin-side trust
shortcut. A product client must connect to a separately installed or remote
service through an authenticated transport. Until that exists, production
bootstrap must fail closed.

The deployment injects five server-owned verifiers: `authorizer`,
`deletion_verifier`, `execution_verifier`, `effect_verifier`, and
`dispatch_verifier`. The two journal verifiers must prove the complete,
**currently latest** independent chain head. They are called with
`previous == current` on every content admission, current-anchor read, and
transfer check. They must return false if a journal has advanced beyond the
service's stored head. A callback that merely accepts a valid old prefix is
unsafe. The effect verifier confirms the exact immutable recovery footprint;
the dispatch verifier confirms D08/D10's complete opaque conflict-key set.
Test doubles are not production verifiers.

The wire adapter should authenticate each call and bind its credential to the
allowed action, namespace, and holder. The service then offers:

- `current`, `current_anchor`, `verify_current`, and `check` for current identity;
- `begin_content_operation` and `end_content_operation` for durable in-flight
  permits around *all* content reads, subscriptions, downloads, model egress,
  adoption, writes, and dispatch. A permit survives process death and has no
  timeout resurrection. A lost permit blocks transfer until independently
  recovered. `check` alone does not serialize a content operation;
- `begin_transfer`, `revoke_source`, `activate_target`, and
  `recover_transfer`. Source revocation requires zero permits. Target activation
  requires the revoked state and exact current deletion/execution heads;
- `observe_deletion_head` and `observe_execution_head` to CAS verified journal
  heads. Pending/accepted deletion blocks content. An unresolved effect and its
  opaque conflict keys remain after business-database rollback;
- `admit_dispatch` to check the exact effect and conflict set while a live
  dispatch permit is held. It is eligibility only, never a platform send token.

The service stores no role content, model payload, message body, or replayable
command. It stores opaque namespace/effect/conflict identities, journal heads,
generations, revocation epochs, transfer state, and permit state.

`LocalJournalBridge` is the service-owned append path for one namespace. It
holds the Authority SQLite write transaction while checking permits, appending
to the independent deletion/execution journal, and advancing the authority
head. Its verifiers read the real latest head and recompute the entire chain.
If journal fsync succeeds but the authority transaction fails, new admissions
fail closed; `reconcile_one` imports exactly one verified missing append. An
out-of-band writer, unbounded gap, or unavailable journal keeps the namespace
closed. The server must own and restrict all three files; the plugin must not
receive a writable journal path. Existing GraphCoordinator deletion closure
checks remain required even after a deletion journal phase reaches `closed`.
The kernel cannot prove freshness if the service storage and all independent
authorities are rolled back together.
