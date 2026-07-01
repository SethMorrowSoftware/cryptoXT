# Riptide implementation plan

The build plan for Riptide, the secure-communications layer specified in this folder. Read this
after the spec foundation ([00-overview.md](00-overview.md), [01-threat-model.md](01-threat-model.md),
[03-conventions.md](03-conventions.md)). The spec is the WHAT; this document is the HOW and, more
importantly, the ORDER. The operational as-built record and the hard-won-lesson list live in
[CLAUDE.md](CLAUDE.md), in the same spirit as the `CLAUDE.md` files in our sibling extensions Box2Dxt,
ShowControl, TorrentXT, and SodiumXT.

House style: no em-dashes (hyphens, commas, colons, parentheses instead). ASCII only.

---

## 0. Purpose and context

Riptide implements the protocols in docs 02-10 of this folder. It is a communications layer, not a
cryptography library and not a BitTorrent client. It **composes two existing OpenXTalk extensions**:

- **SodiumXT** (`sx*`): the cryptography. Riptide adds no cryptography of its own.
- **TorrentXT** (`bt*` / `tx*`): the DHT, BEP44 records, the BEP10 peer wire, and swarms.

Everything Riptide does is: agree keys, shape bytes into the envelopes and records defined in
[03-conventions.md](03-conventions.md), and move them over TorrentXT. The value is the composition and
the discipline, not new primitives.

## 1. Architecture decision: build on the two bindings

Riptide is primarily a **LiveCode Builder library** (public `rt*` handlers) plus **livecodescript**
protocol logic, depending on the SodiumXT and TorrentXT extensions. Rationale:

- The crypto is done and audited (SodiumXT wraps libsodium; Riptide composes it).
- The transport is done (TorrentXT wraps a real BitTorrent engine).
- The only native (C shim) work Riptide needs is a small set of **capability gaps in the sibling
  extensions** ([11-capabilities-required.md](11-capabilities-required.md)); those land in the
  SodiumXT / TorrentXT repos, not here, so Riptide stays a script-and-protocol layer.

Rejected alternative: reimplementing crypto or BitTorrent inside Riptide. That would throw away the
audited primitives and the proven bindings, and it violates the first rule of the CLAUDE.md (add no
crypto; compose SodiumXT).

## 2. Prerequisites: the upstream capability work (the real blockers)

From [11-capabilities-required.md](11-capabilities-required.md). These must be scheduled in the
sibling repos; Riptide cannot ship a channel whose capability is missing.

**TorrentXT (the critical path):**
- **BEP10 custom extension messages** (register the `rp1` extension, send/receive raw payloads,
  read/write the extended-handshake fields). This is the single most enabling addition and the one
  most likely to be entirely absent from a download-oriented engine. It blocks every live channel
  and Phase 0. Schedule it first.
- Raw DHT `announce_peer` / `get_peers` on an arbitrary 20-byte id (rendezvous, presence).
- BEP44 `put` / `get`, mutable (with an externally supplied ed25519 signature hook so SodiumXT signs
  the BEP44 buffer of 03 section 3.7) and immutable.
- Add/seed a torrent by infohash or magnet with the SodiumXT encrypted-file helpers wired in.
- Peer/connection events and access to `peer_id`; a phantom-swarm participation mode.

**SodiumXT (smaller, not a Phase 0 blocker):**
- **Seeded X25519 / kx keypairs** (`crypto_box_seed_keypair`, `crypto_kx_seed_keypair`) and/or the
  ed25519-to-X25519 conversion, for the one-seed identity of [02-identity.md](02-identity.md). This is
  an ABI addition (bump `SXT_ABI_VERSION` and `kSXTABIVersion` together, per the SodiumXT rules). The
  doc-02 fallback (store separate keypairs) unblocks Phase 0 without it.
- Optional, only if a channel needs it: a k-of-n secret-sharing helper (dead-man messages).

A capability that is missing is a blocker to be scheduled upstream, never a reason to hand-roll the
capability inside Riptide.

## 3. Module layout for the new repo

```
riptide/                         (this folder becomes the repo root)
  CLAUDE.md                      operational guidance + the hard-won-lesson list
  IMPLEMENTATION-PLAN.md         this file
  README.md, 00-..-13-*.md, glossary.md    the spec (source of truth)
  src/
    riptide.lcb                  the LCB library: public rt* handlers over sx*/bt*
    riptide-identity.livecodescript     master seed, derivation, prekeys, key-transparency, store
    riptide-session.livecodescript      handshake, secretstream session, cover-seed (doc 05)
    riptide-mailbox.livecodescript      async ratcheted store-and-forward (doc 06)
    riptide-feed.livecodescript         signed encrypted feed + wall (doc 07)
    riptide-groups.livecodescript       rooms (doc 08)
    riptide-objects.livecodescript      capability links, drops, large transfer (doc 09)
    riptide-store.livecodescript        persistent, encrypted-at-rest state (section 4)
  examples/
    riptide-demo.livecodescript         a two-pane demo (like sodium-demo)
    riptide-tests.livecodescript        the on-engine self-test / interop harness
  tests/
    vectors/                     conformance-vector generator + a KAT test (doc 12)
  tools/
    check-livecodescript.py      ported from SodiumXT (the static gate)
    package-extension.py         ported from SodiumXT (bundle + MANIFEST.sha256)
```

Public handler prefix `rt*` (mirroring `sx*` / `bt*`); C ABI, if Riptide ever needs its own shim,
`rtx_*` (it should not; the shims live in the siblings).

## 4. State and persistence (a new concern Riptide owns)

Unlike SodiumXT (stateless) and unlike a fire-and-forget call, Riptide holds **long-lived secret
state**: the master seed, per-contact records and verified key-transparency positions, unconsumed
one-time prekeys, and per-session ratchet chain keys and counters. Design the store first:

- One `riptide-store` module; a clear schema (identity, contacts, sessions, feeds, groups).
- **Encrypt at rest:** wrap the store under a passphrase-derived key
  (`sxPwHash` + `sxSecretBox`), salt stored beside it (doc 02 section 2.1).
- Be honest about the boundary Riptide inherits from SodiumXT: a secret living in a LiveCode `Data`
  cannot be `mlock`ed or reliably wiped. Minimize how long keys sit in script variables; keep the
  most sensitive operations (whole-file encryption) on the C side via `sxEncryptFile`.
- Ratchet and counter state must be persisted atomically with delivery, or a crash reuses a message
  key. Define the persistence order carefully (persist the advanced chain key before treating a
  message as sent/received).

## 5. Phased delivery plan

Each phase ends green: the static checker passes, the conformance vectors pass, and an on-engine
two-instance interop round-trip works. If a phase touches a sibling shim, its `SXT_ABI_VERSION` /
`checkABI` (or the TorrentXT equivalent) is bumped in the same change, upstream.

- **Phase 0: the vertical slice (the single most important phase).** Identity (one-seed, or the
  doc-02 fallback) + rendezvous (derive a 20-byte id, `DHT.announce` / `DHT.getPeers`) + ONE
  secretstream session over the BEP10 `rp1` extension. This is the phantom swarm ([05-session.md](05-session.md),
  channel C2): two instances derive the same rendezvous id, find each other, run the handshake, and
  exchange one authenticated encrypted message. Do this before anything else, because it integrates
  the three riskiest, least-proven pieces at once (BEP10 extension messages, arbitrary-id DHT
  announce, and a secretstream session over the wire). Gate: a real interop round-trip between two
  instances on-engine, byte-verified. Do not proceed until it works.

- **Phase 1: identity and key management.** Complete [02-identity.md](02-identity.md): prekey bundles
  as BEP44 records, the key-transparency log, safety numbers, and the encrypted store (section 4).
  Gate: the conformance vectors ([12-conformance-vectors.md](12-conformance-vectors.md)) pass in a
  runnable test; a prekey bundle round-trips through the DHT and verifies.

- **Phase 2: the mailbox.** [06-mailbox.md](06-mailbox.md): async store-and-forward, the
  double-ratchet-lite, inbox-id scanning, acks. Gate: an offline message is delivered end to end; the
  negative tests pass (a flipped byte fails to open, a replayed record is dropped, a wrong key fails).

- **Phase 3: the feed.** [07-feed.md](07-feed.md): the signed BEP44 seq-chain index over encrypted
  torrents (`sxEncryptFile`), subscriber follow / signature-and-chain verification / decrypt, and the
  public wall variant. Gate: a subscriber reconstructs and decrypts a multi-entry feed; a forged
  entry and a broken chain link are both surfaced, not silently accepted.

- **Phase 4: cover-seed (the flagship, and the research question).** The deniable session mode
  ([05-session.md](05-session.md), channel C3): both peers seed a real, lawful torrent; recognition
  tokens in the extended handshake; tunnel the session inside `rp1`. Gate: a working tunnel inside a
  real swarm, AND a written analysis of how far the deniability actually goes against a
  tracker-running / traffic-analyzing adversary (open question A2 in
  [13-open-questions.md](13-open-questions.md)). Ship it labeled experimental until that analysis
  exists.

- **Phase 5: groups and objects.** [08-groups.md](08-groups.md) small static rooms with sender keys
  and linear rekey, and [09-objects.md](09-objects.md) capability links, content-addressed drops, and
  large transfers. Gate: a 3-member room round-trips and a removed member cannot read new messages; a
  capability link opens on a second instance.

- **Phase 6: anti-abuse and privacy, as they mature.** [10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md):
  proof-of-work and capability tokens for open inboxes, recipient-side moderation, then k-anonymous
  inboxes and cover traffic. Multi-hop relay and covert channels stay R&D
  ([13-open-questions.md](13-open-questions.md)); do not present them as finished guarantees.

## 6. Test strategy

A communications protocol built from audited primitives fails in the **composition**, not the
primitives, so the tests target the composition and the negative paths.

- **Conformance vectors (mandatory).** Port the SodiumXT discipline: the deterministic derivations
  (identity, rendezvous id, inbox id, safety number, the BEP44 signature) have fixed known answers in
  [12-conformance-vectors.md](12-conformance-vectors.md), asserted by a runnable test that fails if a
  libsodium bump changes any of them. This pins the wire format across implementations.
- **Static gate.** `tools/check-livecodescript.py` on every `.lcb` / `.livecodescript` change (smart
  quotes, handler/unsafe balance, the prefixed-token-shadow trap, constants-before-use). There is no
  headless OXT compile; static is all you get, so say "verified statically; needs an on-engine pass."
- **On-engine interop (the only real protocol test).** Two instances, per channel, exercising the
  full round-trip. Negative tests are the security-relevant ones: tamper a byte -> open fails
  (`SXT_ERR_AUTH`); replay a record -> dropped; wrong key -> fails; stale epoch -> rejected; a forged
  BEP44 signature -> rejected; a fork in the key-transparency log -> surfaced.
- **Property tests.** Ratchet stays in sync under reordering and gaps; a truncated stream fails
  (the secretstream FINAL tag); epoch-adjacency handling under clock drift.
- **Sanitizers** apply only if Riptide adds its own C shim (it should not; the capability shims live
  in the siblings and get gcc ASan/UBSan there).

## 7. Build, packaging, and tooling

- **Port `check-livecodescript.py` and `package-extension.py`** from SodiumXT verbatim (as SodiumXT
  ported them from TorrentXT). The static checker is non-negotiable.
- **Riptide ships as an LCB library plus livecodescript that depends on the SodiumXT and TorrentXT
  extensions.** Either declare them as install-time dependencies, or bundle their native libraries
  under the same `src/code/<arch>-<platform>/` convention with a `MANIFEST.sha256` and the CI
  `verify-binaries` gate (the SodiumXT model). Prefer dependency declaration; bundle only if the
  target workflow needs a single self-contained package.
- **CI:** the static gate and the conformance-vector KATs run here; the native matrix is owned by the
  sibling repos. If Riptide ever adds a shim, stand up the matrix and the sanitizers exactly as
  SodiumXT does.

## 8. Risk register

| # | Risk | Mitigation |
|---|---|---|
| 1 | **TorrentXT lacks BEP10 custom extension messages** (the critical blocker). | Schedule it first upstream; Phase 0 depends on it; do not start channels until it exists. |
| 2 | **Composition bugs** (the dangerous failure mode of a crypto protocol built from good parts). | Follow [03-conventions.md](03-conventions.md) exactly; conformance vectors + adversarial/negative tests; seek independent review before any "secure" claim. |
| 3 | **Overclaiming metadata privacy or deniability.** | Ship the honest posture of [01-threat-model.md](01-threat-model.md); label cover-seed experimental until analyzed (open question A2). |
| 4 | **Ratchet / counter desync or key reuse across a crash.** | Persist advanced ratchet state atomically before delivery (section 4); property-test reordering and gaps. |
| 5 | **Secret state in script memory.** | Encrypt the store at rest; minimize key lifetime; keep bulk crypto on the C side; document the boundary honestly (inherited from SodiumXT). |
| 6 | **Key loss is unrecoverable.** | Backup and social-recovery UX as a first-class feature, not an afterthought (N5). |
| 7 | **Group forward secrecy is an open (MLS-class) problem.** | Ship small static rooms with linear rekey; do not overclaim; track the tree-based path in doc 13. |
| 8 | **No headless OXT.** | Static gate + on-engine passes; never claim runtime behavior you did not observe. |
| 9 | **Sibling ABI skew** (a Riptide build against a mismatched SodiumXT/TorrentXT native lib). | Depend on the siblings' `checkABI()` guards; pin the extension versions Riptide is built against. |

## 9. Security and honesty posture (carried into every phase)

- **Add no cryptography.** Compose SodiumXT. If a channel seems to need a new primitive, that is a
  SodiumXT feature request, not Riptide code.
- **The constitution is law.** [03-conventions.md](03-conventions.md) fixes the encodings, the KDF
  labels, the envelope shapes, the epoch clock, and the error model. A channel does not diverge; it
  extends the registries there.
- **Authenticate everything, fail closed, compare secrets in constant time** (`sxMemEqual`). Inherited
  from SodiumXT; non-negotiable at the protocol level too.
- **Ship the honesty.** State the non-goals (N1-N7) to users. A tool that overstates its guarantees
  is worse than one that is candid about them.

## 10. First move in the new repo

1. Move this folder in. Read [CLAUDE.md](CLAUDE.md), then [00-overview.md](00-overview.md),
   [01-threat-model.md](01-threat-model.md), and [03-conventions.md](03-conventions.md).
2. Port `tools/check-livecodescript.py` and `tools/package-extension.py` from SodiumXT.
3. Confirm or schedule the TorrentXT **BEP10 extension-message** capability
   ([11-capabilities-required.md](11-capabilities-required.md)); Phase 0 blocks on it.
4. Build **Phase 0 only**: identity + rendezvous + one secretstream session over `rp1`, proven with a
   two-instance on-engine interop round-trip. Everything else is downstream of that working.
