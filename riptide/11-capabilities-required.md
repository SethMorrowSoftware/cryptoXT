# 11. Capabilities required

This is the buildability checklist. It states exactly what SodiumXT and TorrentXT must expose for
Riptide to be implemented, marks what already exists, and names each gap. It does not restate the
protocol: the crypto conventions live in [03-conventions.md](03-conventions.md), the identity
derivations in [02-identity.md](02-identity.md), the layer cake and channel list in
[00-overview.md](00-overview.md). Where a capability is used, this doc cross-references by filename
rather than duplicating the design.

Two honesty notes up front:

- SodiumXT is close. Riptide leans on its existing `sx*` surface almost entirely; the only crypto
  gap is a small ABI addition (a handful of new bound calls), plus one clearly-optional helper.
- TorrentXT is the long pole. Several needs are new subsystems, not new bindings. Each TorrentXT
  item below is marked "small" (a few new bound calls over an existing engine feature) or "large"
  (a subsystem that must be built or surfaced). The single most enabling addition is BEP10 custom
  extension messages (section 11.2.3).

BitTorrent capabilities are grounded in the real BEPs: BEP5 (mainline DHT), BEP44 (storing
arbitrary data in the DHT, mutable and immutable), BEP10 (extension protocol), BEP9 (metadata
exchange), BEP3/BEP52 (the core protocol, v1 SHA-1 and v2 SHA-256 infohashes), BEP11 (peer
exchange), BEP15 (UDP trackers). Riptide targets mainline-DHT semantics.

## 11.1 SodiumXT

### 11.1.1 What Riptide already has

The full surface is in [../docs/api-reference.md](../docs/api-reference.md). Riptide uses these
existing `sx*` handlers directly; none needs a change. Grouped by the role they play in the spec:

| Role in Riptide | Existing handler(s) | Used by (docs) |
|---|---|---|
| Master seed and all randomness | `sxRandomBytes`, `sxRandomUniform` | seed 02; nonces/salts/ids everywhere |
| Identity signing keypair from seed | `sxSignKeypairFromSeed` (BEP44-compatible ed25519) | 02 (id 0), the keystone |
| Signatures (detached, for BEP44 and tokens) | `sxSignDetached`, `sxSignVerifyDetached` | 02 prekey/log signing, 03 sec 3.7, 05 recognition tokens, 07 feed/wall |
| Signatures (attached) | `sxSign`, `sxSignOpen` | 07 signed index entries where attached form is convenient |
| Box keypair (X25519) | `sxBoxKeypair` | 02 (`IK_x`, current fallback), prekeys |
| Authenticated PK encryption | `sxBox`, `sxBoxOpen` | 03 boxed envelope, 05/06 handshake |
| Anonymous-sender sealed box | `sxSeal`, `sxSealOpen` | 03 sealed envelope, 06 first mailbox message, 09 objects, 10 onion |
| Key agreement (crypto_kx) | `sxKeyExchangeKeypair`, `sxKeyExchangeClient`, `sxKeyExchangeServer` | 02 (`KX`, current fallback), 05 handshake |
| Symmetric AEAD (with AD binding) | `sxAeadEncrypt`, `sxAeadDecrypt` | 03 AEAD envelope + AD binding (3.5.1), 08 sender keys |
| Symmetric (no AD) | `sxSecretBox`, `sxSecretBoxOpen` | 02 at-rest seed wrap, 08 room key |
| Streaming AEAD | `sxSecretStreamInitPush`, `sxSecretStreamPush`, `sxSecretStreamInitPull`, `sxSecretStreamPull`, `sxIsFinalTag`, `sxFreeStream` | 03 stream frame (3.8), 05 live session |
| Whole-file encryption (C-side) | `sxEncryptFile`, `sxDecryptFile` | 07 feed payloads, 09 objects/bulk |
| KDF (BLAKE2b crypto_kdf) | `sxKdfDerive` | 02 identity derivation, 03 KDF label registry (3.4), 04 rendezvous, 05/06/07/08 |
| Hash / id derivation | `sxHash`, `sxHashKeyed`, `sxHashFile`, `sxHashFileKeyed` | 03 public-key-addressed ids (3.4), 04 rendezvous ids, 06 inbox ids, 09 content addressing |
| Encodings | `sxBin2Hex`, `sxHex2Bin`, `sxBin2Base64`, `sxBase642Bin` | 02 human-facing identity, 09 capability links |
| Constant-time compare | `sxMemEqual` | 02 safety number, 03 sec 3.3, every secret comparison |
| Passphrase to key (Argon2id) | `sxPwHash`, `sxPwHashStr`, `sxPwHashStrVerify`, `sxPwMem*` presets | 02 at-rest seed wrapping |
| Length hiding | `sxPad`, `sxUnpad` | 03 padding (3.5.2), everywhere before encryption |
| Multipart hash | `sxHashInit`, `sxHashInitKeyed`, `sxHashUpdate`, `sxHashFinal`, `sxFreeHash` | 02/07 hash-chained logs and feeds over assembled records |

The conclusion: for the cryptography, Riptide is essentially already buildable. The one exception
is the identity derivation of [02-identity.md](02-identity.md), which wants encryption keys derived
deterministically from the same master seed as the signing key.

### 11.1.2 GAP: seeded X25519 / kx keypairs (one-seed identity)

> **STATUS: SHIPPED in SodiumXT ABI 5.** Delivered as `sxBoxKeypairFromSeed(pSeed, out rPk, out rSk)`
> and `sxKeyExchangeKeypairFromSeed(pSeed, out rPk, out rSk)` (C ABI `sxt_box_keypair_from_seed` /
> `sxt_kx_keypair_from_seed`, named to mirror the existing `sxt_sign_keypair_from_seed`), with the
> `sxt_box_seedbytes()` / `sxt_kx_seedbytes()` length getters. `SXT_ABI_VERSION` and `kSXTABIVersion`
> were bumped 4 -> 5 together. The one-seed identity of [02-identity.md](02-identity.md) is therefore
> fully derivable now, and all three identity ids are pinned in
> [12-conformance-vectors.md](12-conformance-vectors.md). The proposal below is kept as the design
> record (the shipped C-symbol names differ slightly from the names proposed here).

This was the only crypto gap that blocked a canonical design, and it was small.

**Why.** [02-identity.md](02-identity.md) sec 2.2 derives all subkeys from one 32-byte master seed
`S`: id 0 becomes the ed25519 identity keypair via `sxSignKeypairFromSeed` (already deterministic),
and ids 1 and 2 should become the X25519 box keypair `IK_x` and the crypto_kx keypair `KX`. Today
`sxBoxKeypair` and `sxKeyExchangeKeypair` generate from fresh randomness only, so there is no way to
turn a derived 32-byte seed into a specific box/kx keypair. Until this lands, doc 02 uses a
documented fallback (generate `IK_x` and `KX` once and store them beside `S`), which works but
breaks the "one backup blob is the whole identity" property and leaves conformance vectors
([12-conformance-vectors.md](12-conformance-vectors.md)) unable to pin ids 1 and 2.

**What libsodium already provides** (so the shim work is thin marshaling, not new crypto):

- `crypto_box_seed_keypair(pk, sk, seed)`, seed length `crypto_box_SEEDBYTES` (32).
- `crypto_kx_seed_keypair(pk, sk, seed)`, seed length `crypto_kx_SEEDBYTES` (32).
- `crypto_sign_ed25519_pk_to_curve25519(x_pk, ed_pk)` and
  `crypto_sign_ed25519_sk_to_curve25519(x_sk, ed_sk)`, the ed25519->X25519 conversion.

**Two designs, both acceptable; the spec allows either as long as the vectors are pinned:**

1. Preferred: seeded keypairs. Feed each derived 32-byte seed (`sxKdfDerive(S, "1"/"2", "rp-ident",
   32)`) straight into `crypto_box_seed_keypair` / `crypto_kx_seed_keypair`. This keeps the box and
   kx keys as independent curve points and matches the id/label table in doc 02 exactly.
2. Alternative: convert the one ed25519 identity key to its X25519 equivalent with the
   `pk_to_curve25519` / `sk_to_curve25519` pair. This makes `IK_x` a deterministic function of
   `IK`, so there is truly one curve point behind two representations. It is a smaller surface (one
   conversion instead of two seeded generators) but couples signing and encryption keys, which some
   reviewers dislike; note the tradeoff and let doc 02 choose.

Riptide's recommendation: ship the seeded generators (design 1) as the primary, and optionally the
conversion pair as a convenience. The seeded form composes cleanly with the existing `sxKdfDerive`
label registry and keeps the three identity keys independent.

**Proposed names (follow the repo prefix conventions: `sxt_snake_case` C ABI, `sxPascalCase` LCB):**

| libsodium | C ABI symbol (`sxt_`) | LCB handler (`sx`) | Shape |
|---|---|---|---|
| `crypto_box_seed_keypair` | `sxt_box_seed_keypair` | `sxBoxKeypairFromSeed(pSeed, out rPk, out rSk)` | mirror `sxt_sign_keypair_from_seed` / `sxSignKeypairFromSeed` |
| `crypto_kx_seed_keypair` | `sxt_kx_seed_keypair` | `sxKeyExchangeKeypairFromSeed(pSeed, out rPk, out rSk)` | same |
| `crypto_sign_ed25519_pk_to_curve25519` | `sxt_sign_ed25519_pk_to_curve25519` | `sxSignPkToBoxPk(pEdPk)` returns `Data` | optional |
| `crypto_sign_ed25519_sk_to_curve25519` | `sxt_sign_ed25519_sk_to_curve25519` | `sxSignSkToBoxSk(pEdSk)` returns `Data` | optional |

Also expose the length constants from the shim, per the repo rule against hardcoding sizes:
`sxt_box_seedbytes()` and `sxt_kx_seedbytes()` (both 32 today, but libsodium is allowed to change
them). `sxSignKeypairFromSeed` already models the exact pattern (validate the seed length, fill
`-needed` on a short out buffer, `sodium_memzero` scratch), so each new call is a near-copy.

**ABI impact (mandatory, per the repo rules).** Adding these entry points is an ABI change. Bump
`SXT_ABI_VERSION` (currently 4, in `src/sodium_shim.h`) and `kSXTABIVersion` (currently 4, in
`src/sodium.lcb`) together, in the same change, so `checkABI()` throws a clear version-skew error
instead of the engine corrupting memory on first use. Add the new handlers to `sxSelfTest`, add a
known-answer vector to `tests/sodium_smoke_test.c` (derive a keypair from a fixed seed and assert
the fixed public key), and only then is the change "done" per CLAUDE.md.

Size: **small.** Four new marshaling functions plus two constant getters, each a near-copy of an
existing entry point, plus the mandatory ABI bump and one known-answer test.

### 11.1.3 GAP (optional): k-of-n secret sharing, and scalarmult

These are only needed by specific channels and are marked optional; neither blocks any milestone.

- **k-of-n secret sharing** (Shamir-style threshold split of a 32-byte key). Needed only by the
  dead-man's-switch idea (brainstorm C9: split the payload key across holders, publish shares if
  heartbeats stop). libsodium does not ship a Shamir implementation, so this is not a thin bind: it
  is either a small self-contained GF(256) Shamir routine added to the shim, or a pure-LCB
  implementation over `sxRandomBytes`. Keep it out of the core; add it only if and when a
  threshold-reveal channel is specified (that channel does not yet have a doc in 04-10). Mark
  **optional, small-to-medium** and defer.

- **scalarmult** (`crypto_scalarmult`, raw X25519 Diffie-Hellman). Riptide's handshakes are
  expressed with `sxKeyExchange*` (crypto_kx) and `sxBox`/`sxSeal`, which cover every session in
  docs 05/06. A raw scalarmult would only be needed if a future channel wants a custom
  Diffie-Hellman (for example a bespoke X3DH variant or a non-interactive triple-DH not expressible
  via crypto_kx). It is a genuinely thin bind (`crypto_scalarmult_base`, `crypto_scalarmult`) if a
  channel ever needs it. Mark **optional, small** and do not add speculatively; raw DH is exactly
  the kind of low-level primitive the "easy way is the safe way" principle
  ([00-overview.md](00-overview.md)) says to avoid exposing without a loud reason.

## 11.2 TorrentXT

These are the operations Riptide needs from the transport fabric. Each is mapped to the docs and
channels that require it and marked must-have (blocks a specified channel) vs nice-to-have (an
optimization or a harder channel). "small" / "large" estimates the binding effort over TorrentXT's
existing engine.

### 11.2.1 Raw DHT announce_peer / get_peers on an arbitrary 20-byte id (BEP5)

- **Need.** Announce presence at, and discover peers at, a caller-supplied 160-bit id that need not
  correspond to any real torrent. This is the rendezvous and presence primitive.
- **Operations.** `DHT.announce(id20)` (BEP5 `announce_peer`, with the implied `get_peers` token
  dance the engine already does for real infohashes) and `DHT.getPeers(id20) -> list of ip:port`.
  The id is any 20 bytes from `sxHash(..., 20)`; the DHT does not verify an announced id maps to
  content, which is exactly what makes a derived id a private meeting point (brainstorm sec 1).
- **Maps to.** [03-conventions.md](03-conventions.md) sec 3.11 names these `DHT.announce(id)` /
  `DHT.getPeers(id)`. Rendezvous and presence (docs 04, 07 for feed swarm discovery, 08 for group
  rooms). brainstorm C2, C5, C7.
- **Must-have.** Blocks rendezvous, so blocks the first milestone.
- **Size: small-to-medium.** The engine already does `get_peers`/`announce_peer` for real
  infohashes; the work is surfacing them on an arbitrary id, decoupled from adding a torrent, and
  returning the peer list to script. Depends on how tightly the current engine ties announces to a
  loaded torrent (see 11.2.6).

### 11.2.2 BEP44 put / get, mutable and immutable, with an external signature hook

- **Need.** Store and retrieve small signed values in the DHT. This is the entire asynchronous
  carrier layer.
- **Operations.**
  - Immutable: `DHT.putImmutable(value) -> id20` (id is the BEP44-specified hash of the bencoded
    value) and `DHT.getImmutable(id20) -> value`. For self-contained sealed envelopes whose address
    the recipient learns elsewhere.
  - Mutable: `DHT.putMutable(pubkey, salt, seq, value, sig)` and
    `DHT.getMutable(pubkey, salt) -> (seq, value, sig)`. Keyed by an ed25519 public key plus an
    optional salt, carrying a monotonic `seq`.
  - **The signature hook is the load-bearing detail.** BEP44 signs the byte string formed by
    concatenating `4:salt` + bencoded salt, `3:seqi<seq>e`, then `1:v` + bencoded value (exactly as
    pinned in [03-conventions.md](03-conventions.md) sec 3.7). Riptide must produce that signature
    with SodiumXT, not with an ed25519 key held inside TorrentXT, because the signing key is the
    Riptide identity key derived from the master seed and it must never leave the crypto layer. So
    the binding must either (a) expose the exact bytes to be signed to script, take back a detached
    signature from `sxSignDetached(bep44SignBuf, IK_sec)`, and put it on the wire verbatim, or (b)
    accept a caller-supplied signature and public key and pass them straight through. Option (a) is
    cleaner and is the one the spec assumes: TorrentXT must NOT sign with its own key.
    Symmetrically, `getMutable` must return the raw `sig` so Riptide can `sxSignVerifyDetached` it,
    rather than verifying internally with an opaque key.
- **Maps to.** [02-identity.md](02-identity.md) (prekey bundle under salt `rp-prekeys`, key
  transparency log under salt `rp-idlog`), [03-conventions.md](03-conventions.md) sec 3.7 (the whole
  carrier), the mailbox (doc 06), feed/wall (doc 07 salts `rp-feed` / `rp-wall`), objects (doc 09
  immutable cells). brainstorm C1, C4, C6, C8, C9.
- **Must-have** for every asynchronous channel. Not required for the first (session-only)
  milestone, but required immediately after.
- **Size: medium.** BEP44 is a well-specified engine feature; the specific work is the external
  signature hook (do not sign internally) and returning `seq`/`sig`/`value` faithfully. If the
  current engine has no BEP44 at all, this is **large** (a new store-and-forward DHT subsystem).

### 11.2.3 BEP10 custom extension messages (the single most enabling addition)

- **Need.** Register a named peer-wire extension, send and receive arbitrary payloads on a peer
  connection, and read/write the extended-handshake fields. This is the live-carrier layer and the
  cover-seed recognition mechanism.
- **Operations.**
  - Register the extension by the name `rp1` in the BEP10 extended handshake (the `m` dictionary),
    so a peer that also advertises `rp1` is recognized as Riptide-capable.
  - Send an `rp1` message with a raw payload and receive `rp1` messages from a peer, delivering the
    raw bytes to script. The payload framing (a 1-byte subtype then bytes) is Riptide's, defined in
    [03-conventions.md](03-conventions.md) sec 3.8; TorrentXT only needs to move opaque bytes under
    the registered extension id.
  - Read and write custom fields in the extended handshake dictionary. Riptide places a per-epoch,
    ed25519-signed recognition token in a benign-looking handshake field (not a `RIPT`-style magic,
    to avoid a fingerprint: see doc 05 and [03-conventions.md](03-conventions.md) sec 3.8) so a
    contact can spot a Riptide peer on a connection that is otherwise serving a real torrent.
- **Maps to.** [03-conventions.md](03-conventions.md) sec 3.8 (the `rp1` carrier), the pairwise
  session and cover-seed mode (doc 05), group rooms over the peer wire (doc 08). brainstorm C2, C3,
  C5.
- **Must-have, and flagged as the single most enabling addition** (brainstorm sec 7 item 3 says the
  same): it unlocks every live channel and the strongest deniability mode, and it is the piece
  most likely to be entirely absent from a download-oriented BitTorrent engine.
- **Size: large** if BEP10 extension messages are not already surfaced (a peer-wire extension
  subsystem: registration, message multiplexing on the extension id, handshake-field access,
  inbound delivery to script). **Medium** if the engine already speaks BEP10 (as it must for BEP9
  metadata exchange) and only the custom-extension registration and raw payload path need exposing.

### 11.2.4 Add / seed a torrent by infohash or magnet, with the file helpers wired in

- **Need.** Create, add, and seed a torrent, and download by infohash or magnet link, so encrypted
  payloads move as ordinary swarm content. Access piece/metadata state as needed.
- **Operations.** Add by magnet or infohash; create a torrent from a file and start seeding; report
  completion and swarm/piece status. The payload path is: `sxEncryptFile(plainPath, encPath, K)`
  produces the file that becomes the torrent, and the downloader runs `sxDecryptFile(encPath,
  plainPath, K)` after the swarm delivers it, so plaintext never crosses the FFI as a `Data` (the
  SodiumXT file helpers already exist, section 11.1.1). Metadata access (BEP9) is needed where a
  channel reads or writes the info dictionary; piece-level access is nice-to-have for covert
  carriers (brainstorm C11).
- **Maps to.** Feed payloads (doc 07), objects / capability links / bulk transfer (doc 09).
  brainstorm C4, C6. Real infohashes are SHA-1 (BEP3 v1) or SHA-256 (BEP52 v2) of the info dict;
  Riptide addresses content by the swarm's real infohash and carries the decryption key out of band
  in the capability link (doc 09), never on the wire.
- **Must-have** for the bulk/object channels; **nice-to-have** for the messaging core (mailbox and
  session do not need real torrents).
- **Size: small-to-medium.** Adding and seeding torrents is the engine's core competency; the work
  is wiring the encrypted-file helpers into the add/seed flow and surfacing completion/status.
  Metadata and piece access are additional surface if a channel needs them.

### 11.2.5 Peer / connection events and access to peer_id

- **Need.** Know when a peer connects or disconnects, on which connection, and read the peer's
  `peer_id`, so Riptide can drive the recognition handshake and bind a session to a connection.
- **Operations.** A peer-connected / peer-disconnected event (with a stable per-connection handle),
  the peer's advertised extensions (did it send `rp1`?), and read access to the 20-byte `peer_id`
  from the BitTorrent handshake. The peer_id is a low-bandwidth field a covert channel can key on
  (brainstorm C11), and the connection event is what triggers reading the extended-handshake
  recognition token (11.2.3).
- **Maps to.** The session handshake and cover-seed recognition (doc 05), anti-abuse and covert
  micro-channels (doc 10). brainstorm C3, C10, C11.
- **Must-have** for the live session (you cannot start a handshake without a connection event);
  peer_id-as-carrier is **nice-to-have**.
- **Size: medium**, and largely shares implementation with 11.2.3 (both are peer-wire surface). If
  connection events already exist for normal downloads, exposing them plus peer_id is small; the new
  part is correlating an event with the `rp1` extended handshake.

### 11.2.6 Phantom-swarm mode (participate in a swarm id without real content metadata)

- **Need.** Join and announce at a swarm id, and accept incoming peer connections there, without
  possessing or fetching the torrent's info dictionary. The swarm membership itself is the channel;
  the "torrent" is a MacGuffin (brainstorm C2).
- **Operations.** Announce at an id (11.2.1), accept a peer-wire connection, and complete the
  BitTorrent + BEP10 handshake without ever obtaining real metadata (so no BEP9 metadata fetch is
  forced, and no "torrent" object with pieces is required). In practice this is 11.2.1 plus 11.2.3
  minus the requirement that a real torrent back the connection.
- **Maps to.** The phantom-swarm session (doc 05, brainstorm C2) and private presence escalating to
  a session (doc 07 presence, brainstorm C7). Called out in the prompt as doc 04 / doc 07 / C11.
- **Must-have** for the realtime-core milestone (the phantom swarm is C2, the second milestone
  channel in [00-overview.md](00-overview.md)); the mailbox core does not need it.
- **Size: medium-to-large.** Depends entirely on whether the engine can hold a peer connection open
  on a swarm id with no backing metadata. A download-oriented engine typically assumes a torrent
  object owns every connection; decoupling "I have peers on this id and a live peer-wire connection"
  from "I have this torrent's metadata and pieces" may require engine changes. If 11.2.1 and 11.2.3
  are built to operate on a bare id, phantom-swarm mode largely falls out of them.

## 11.3 Capability-to-channel matrix

Rows are the capabilities above; columns are the spec docs / channels that consume them. A cell is
`M` (must-have for that channel), `o` (optional / nice-to-have), or blank (not used). Channels use
the brainstorm ids where a doc is not yet written (docs 04-10 are in progress; the foundation docs
00-03 already reference these capabilities).

Legend for columns: Ident = [02-identity.md](02-identity.md); Rndz = rendezvous/presence (doc 04,
brainstorm C2/C7); Sess = pairwise session (doc 05, C2); Cover = cover-seed session (doc 05, C3);
Mbox = mailbox (doc 06, C1); Feed = feed/wall (doc 07, C4/C8); Grp = groups (doc 08, C5); Obj =
objects/links (doc 09, C6); Priv = anti-abuse/privacy (doc 10, C10/C11).

| Capability | Ident | Rndz | Sess | Cover | Mbox | Feed | Grp | Obj | Priv |
|---|---|---|---|---|---|---|---|---|---|
| SodiumXT existing `sx*` surface (11.1.1) | M | M | M | M | M | M | M | M | M |
| SodiumXT seeded box/kx keypairs (11.1.2, GAP) | M | o | o | o | o | o | o | o | o |
| SodiumXT k-of-n sharing (11.1.3, optional) | | | | | | | | o | |
| SodiumXT scalarmult (11.1.3, optional) | | | o | | o | | | | |
| DHT announce/get_peers, 20-byte id (11.2.1) | | M | M | o | | o | M | o | M |
| BEP44 put/get + ext sig hook (11.2.2) | M | | | | M | M | o | M | o |
| BEP10 custom ext messages (11.2.3) | | | M | M | | | M | | o |
| Add/seed torrent + file helpers (11.2.4) | | | | o | o | M | o | M | |
| Peer/connection events + peer_id (11.2.5) | | | M | M | | | M | | o |
| Phantom-swarm mode (11.2.6) | | M | M | | | o | M | | o |

Reading the matrix: the SodiumXT existing surface underpins everything; the seeded-keypair gap is a
"M" only for identity itself (every other channel can run on the doc-02 fallback keys, just without
the one-backup-blob property). On the TorrentXT side, BEP44 (11.2.2) carries all the asynchronous
channels, while BEP10 + connection events + phantom-swarm (11.2.3, 11.2.5, 11.2.6) together carry
all the live channels. No single channel needs everything, which is what makes an incremental build
possible.

## 11.4 Minimal-viable subset (first milestone)

[00-overview.md](00-overview.md) and brainstorm sec 10 both name the first buildable vertical slice:
**identity + rendezvous + one `sxSecretStream` tunnel over a BEP10 extension message** (the phantom
swarm, brainstorm C2). That single slice validates the whole two-network keystone end to end. To
ship it, and only it, you need:

**SodiumXT (all already present):**
- `sxRandomBytes` (the master seed), `sxSignKeypairFromSeed` (the ed25519 identity), `sxKdfDerive`
  and `sxHash` (the rendezvous id from [04] / brainstorm sec 3.2), `sxKeyExchange*` or `sxAeadEncrypt`
  (the challenge/response that proves shared-secret knowledge without revealing it), the
  `sxSecretStream*` family (the live tunnel), `sxMemEqual` (constant-time checks), `sxPad`/`sxUnpad`
  (length hiding).
- The seeded-keypair gap (11.1.2) is NOT required for this milestone: the phantom swarm authenticates
  with the shared secret and the ed25519 identity, and any X25519/kx keypair it needs can come from
  the doc-02 fallback (generate once and store). So the first milestone has **no SodiumXT blocker**.

**TorrentXT (the actual gating work):**
- 11.2.1 DHT announce_peer / get_peers on a 20-byte id (rendezvous). Must-have.
- 11.2.3 BEP10 custom extension messages, at least: register `rp1`, send/receive one raw payload
  (enough to carry the secretstream header and chunks). Must-have.
- 11.2.5 peer/connection events (to know a peer arrived and start the handshake). Must-have.
- 11.2.6 phantom-swarm mode (hold the connection on a bare swarm id with no metadata). Must-have for
  C2 specifically; if too large for a first cut, the milestone can be demonstrated over a real
  seeded torrent instead (which slides the demo toward cover-seed / C3 and adds 11.2.4), but the
  pure phantom swarm is the intended slice.

Not needed for the first milestone: BEP44 (11.2.2, that is the mailbox/feed milestone), add/seed
torrent (11.2.4, unless substituting a real swarm as above), and every optional SodiumXT helper
(11.1.3).

## 11.5 Blocker summary

- **The one hard blocker for the first milestone is BEP10 custom extension messages (11.2.3).** It
  is both must-have and the capability most likely to be entirely missing from a download-oriented
  BitTorrent engine, and it is on the critical path for every live channel, not just the first. If
  TorrentXT already speaks BEP10 for BEP9 metadata exchange, exposing a custom `rp1` extension and a
  raw payload path is medium work; if it does not, this is a new peer-wire subsystem and is the
  single largest item in this document. Everything else for the first milestone is either already
  present (all the SodiumXT calls) or a smaller surfacing of an existing engine feature (raw DHT
  announces, connection events, bare-id swarm participation).
- **The seeded-keypair gap (11.1.2) blocks the canonical one-seed identity but not the first
  milestone**, because the fallback in [02-identity.md](02-identity.md) sec 2.2 covers it. It is a
  small, high-value ABI addition (bump `SXT_ABI_VERSION` + `kSXTABIVersion` together) that should
  land before conformance vectors ([12-conformance-vectors.md](12-conformance-vectors.md)) try to
  pin identity ids 1 and 2.
