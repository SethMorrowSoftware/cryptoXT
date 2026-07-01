# 03. Wire and crypto conventions (the constitution)

This document pins the shared decisions every Riptide channel must obey: versioning, serialization,
the KDF label registry, the cryptographic envelope formats, how records live in BEP44 and BEP10, and
the error model. Channel documents (04-10) build on this and must not invent alternative encodings,
KDF labels, or nonce handling. If a channel needs a new KDF label or message type, it is added to the
registries here.

## 3.1 Versioning

- **Protocol version:** `1`. Every structured message carries `v: 1`. A receiver rejects unknown
  major versions rather than guessing.
- **Spec version:** this directory is spec draft `0.1`. The wire protocol version and the spec
  version are independent; the wire `v` changes only on a breaking wire change.

## 3.2 Serialization

Riptide has exactly two serializations:

- **Structured records** (everything with fields: identity cards, prekey bundles, log entries, feed
  entries, manifests, control messages) are **bencoded dictionaries with keys sorted lexicographically
  by raw byte value**. This matches BitTorrent and, crucially, BEP44 signing, which operates on the
  bencoded bytes. Write `bencode(x)` for this canonical form. Integers are bencode integers; binary
  blobs (keys, ciphertext, signatures) are bencode byte strings (length-prefixed raw bytes, so they
  hold arbitrary bytes safely).
- **Peer-wire frames** (the live session data path) are a 1-byte subtype followed by a payload, sent
  inside a BEP10 extension message (3.7). The payload is either a secretstream chunk (raw bytes) or a
  bencoded control dict.

Every structured record includes two mandatory fields:

| Key | Meaning |
|---|---|
| `v` | protocol version (int, = 1) |
| `t` | message type (int, from the registry in 3.6) |

Field-name keys are kept short (one or two ASCII letters) to fit the ~1000-byte BEP44 budget.

## 3.3 Cryptographic primitives

Riptide adds no cryptography; it composes SodiumXT calls. Fixed choices:

| Purpose | Primitive | SodiumXT call | Sizes |
|---|---|---|---|
| Identity signing | ed25519 | `sxSign*` | pub 32, sec 64, seed 32, sig 64 |
| Sealed (anon-sender) encryption | crypto_box_seal (X25519 + XSalsa20-Poly1305) | `sxSeal` / `sxSealOpen` | overhead 48 |
| Authenticated PK encryption | crypto_box (X25519) | `sxBox` / `sxBoxOpen` | nonce 24 (prepended), tag 16 |
| Key agreement | crypto_kx | `sxKeyExchange*` | pub 32, sec 32, session 32 |
| Symmetric AEAD | XChaCha20-Poly1305 IETF | `sxAeadEncrypt` / `sxAeadDecrypt` | key 32, nonce 24 (prepended), tag 16 |
| Symmetric (no AD) | XSalsa20-Poly1305 secretbox | `sxSecretBox` / `sxSecretBoxOpen` | key 32, nonce 24 (prepended), mac 16 |
| Streaming AEAD | secretstream XChaCha20-Poly1305 | `sxSecretStream*` | key 32, header 24, per-chunk overhead 17 |
| KDF | crypto_kdf (BLAKE2b) | `sxKdfDerive` | master 32, context 8, id uint64, out 16..64 |
| Hash / id derivation | BLAKE2b | `sxHash` / `sxHashKeyed` | out 16..64 |
| Passphrase to key | Argon2id | `sxPwHash` | salt 16, key 32 |
| Randomness | CSPRNG | `sxRandomBytes` / `sxRandomUniform` | as needed |

**Nonce discipline.** Riptide never chooses a nonce. `sxSeal`, `sxBox`, `sxAeadEncrypt`, and
`sxSecretBox` each draw a fresh random nonce and prepend it to their output; secretstream derives
per-chunk nonces from a random header. This is a hard rule inherited from SodiumXT: there is no
bring-your-own-nonce path anywhere in Riptide.

**Secret comparison.** Any equality check on a secret, MAC, tag, or safety number uses `sxMemEqual`
(constant time). Never `is` or `=`.

## 3.4 The KDF label registry

`sxKdfDerive` needs an 8-byte context and a uint64 id, and its master key must be a 32-byte secret.
Contexts are exactly 8 ASCII bytes. This registry is authoritative; a channel that needs a new label
adds it here.

| Context (8 bytes) | Master key | id | Output | Used by |
|---|---|---|---|---|
| `rp-ident` | master seed `S` | purpose (0 sign, 1 box, 2 kx) | 32 | identity derivation (doc 02) |
| `rp-rndzv` | pairwise/shared secret (32) | epoch | 20 | rendezvous DHT id (doc 04) |
| `rp-prsnc` | pairwise secret (32) | epoch | 20 | presence DHT id (doc 04) |
| `rp-sess0` | handshake shared secret (32) | 0 | 32 | session root key (doc 05) |
| `rp-txrx0` | session root key (32) | 0 tx, 1 rx | 32 | directional session keys (doc 05) |
| `rp-ratch` | mailbox chain key (32) | message counter | 32+32 | next chain key + message key (doc 06) |
| `rp-sendr` | group room key (32) | member index | 32 | per-member sender key (doc 08) |
| `rp-feedk` | feed master key (32) | epoch | 32 | feed read-key rotation (doc 07) |
| `rp-cvsig` | cover-seed epoch secret (32) | epoch | 32 | reserved (optional): cover-seed recognition signing (doc 05) |

Derivations from a **public key** (not a 32-byte secret), such as a mailbox inbox id, use `sxHash`
instead of `sxKdfDerive`, because crypto_kdf requires a secret master key. Those are defined at their
point of use with an explicit domain-separation tag, for example
`inboxId = sxHash(recipientIK_x & be64(counter) & "rp-mbxid", 20)`.

**Domain-separation tag registry.** Unlike KDF contexts (which are exactly 8 bytes), an `sxHash` /
`sxHashKeyed` domain tag is an ASCII label of any length. To keep them collision-free across the
spec, every tag is listed here; a channel that needs a new one adds it.

| Tag | Used by |
|---|---|
| `rp-mbxid` | mailbox inbox id (doc 06) |
| `rp-fc-meet/v1` | first-contact meeting id (doc 04) |
| `rp-rndzv-pw/v1` | passphrase-derived rendezvous secret (doc 04) |
| `rp-cover` | cover-swarm blend id (doc 04) |
| `rp-cvrsd` | cover-seed recognition token (doc 05) |
| `rp-room0` | local room label (doc 08) |

Anti-abuse proof-of-work and capability-token tags are defined in
[10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md).

## 3.5 Envelopes

A Riptide **envelope** is the byte format of one protected message. Structured envelopes are bencode
dicts (3.2); their ciphertext lives in a byte-string field named `c`. The four envelope shapes:

- **Sealed envelope** (anonymous sender, e.g. a first mailbox message): `c = sxSeal(pad(m), recipientPub)`.
- **Boxed envelope** (authenticated sender): `c = sxBox(pad(m), recipientPub, senderSec)`. The
  sender's public key is conveyed out of band or in a signed field, never trusted from the envelope
  alone.
- **AEAD envelope** (symmetric, with binding): `c = sxAeadEncrypt(pad(m), ad, key)` where the
  associated data `ad` is defined in 3.5.1.
- **Stream frame** (live session): a secretstream chunk from `sxSecretStreamPush`, framed per 3.7.

The recipient reverses with the matching open/decrypt call, which fails closed on any tamper (3.9).

### 3.5.1 Associated-data binding

Every AEAD envelope binds its position and kind so a captured ciphertext cannot be replayed or
reordered into another slot. The associated data is the canonical bencode of a small sorted dict:

```
ad = bencode({ e: epoch, q: seq, t: type })
```

`e` is the epoch (3.8), `q` is the per-channel monotonic sequence number, `t` is the message type
(3.6). A decrypt that supplies a different `e`, `q`, or `t` than was sealed fails authentication.

### 3.5.2 Padding

Plaintext is padded to a size bucket before encryption so ciphertext length stops leaking message
length. Use `sxPad(m, B)` with a per-channel block size `B`; the default ladder is `B = 256` for
DHT-record channels (keeping records inside the ~1000-byte budget) and `B = 1024` for peer-wire
sessions. Recipients `sxUnpad` after a successful open. A message whose padded size would exceed a
single BEP44 record MUST use an object/torrent carrier (doc 09), not a record.

## 3.6 Message type registry

The `t` field (and the peer-wire subtype byte) come from this registry. Ranges are reserved per
channel so channel documents can claim values without collision.

| Range | Channel | Examples |
|---|---|---|
| 0x01-0x0F | identity / control | 0x01 identity-card, 0x02 prekey-bundle, 0x03 idlog-entry, 0x04 rendezvous-hello |
| 0x10-0x1F | mailbox (doc 06) | 0x10 message, 0x11 ack, 0x12 prekey-consume |
| 0x20-0x2F | session (doc 05) | 0x20 handshake-init, 0x21 handshake-resp, 0x22 data, 0x23 rekey |
| 0x30-0x3F | feed / wall (doc 07) | 0x30 feed-entry, 0x31 wall-entry, 0x32 feed-key-update |
| 0x40-0x4F | groups (doc 08) | 0x40 group-message, 0x41 member-add, 0x42 member-remove |
| 0x50-0x5F | objects (doc 09) | 0x50 manifest, 0x51 chunk-key |
| 0x60-0x6F | privacy extensions (doc 10) | 0x60 relay-onion, 0x61 cover |

## 3.7 Carrier: BEP44 DHT records

Asynchronous channels store an envelope in a BEP44 record.

- **Immutable** records (`sxHash`-addressed) hold self-contained sealed envelopes whose address the
  recipient learns elsewhere (objects, capability links).
- **Mutable** records are keyed by an ed25519 public key plus a **salt** and carry a monotonic `seq`.
  The value `v` is the canonical bencode of the envelope, at most 1000 bytes.

Salts namespace a key's records. Reserved salts:

| Salt | Contents |
|---|---|
| `rp-prekeys` | the owner's current prekey bundle (doc 02) |
| `rp-idlog` | the owner's key-transparency log entries (doc 02) |
| `rp-feed` | a feed's signed index entries (doc 07) |
| `rp-wall` | a public wall's entries (doc 07) |

**Signing.** A mutable put is signed exactly as BEP44 specifies: the signature covers the byte string
formed by concatenating, in order, `4:salt` + the bencoded salt, then `3:seqi<seq>e`, then `1:v` +
the bencoded value. Riptide produces this signature with `sxSignDetached(bep44SignBuf, IK_sec)`;
because SodiumXT's ed25519 is the same primitive BEP44 uses, the result validates in any conformant
DHT. Mutable records at guessable keys (an inbox derived from a public key) additionally require the
anti-abuse gate of doc 10 before a node accepts the put in Riptide's own relay nodes; the public DHT
does not enforce this, so treat inbox writability as open and defend at the application layer. Inbox
writes carry the anti-abuse fields `w` (proof-of-work nonce) and/or `k` (capability token) defined in
[10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md); a recipient checks these cheaply before
spending effort to trial-decrypt.

## 3.8 Carrier: BEP10 peer-wire extension

Live channels run over the peer wire. Riptide registers a single BEP10 extension by the name `rp1`
in the extended handshake. Once both peers advertise `rp1`, either may send an `rp1` message whose
payload is:

```
[ subtype : 1 byte ] [ payload : bytes ]
```

`subtype` is a value from the type registry (3.6, the session and control ranges). The payload is a
secretstream chunk (for `0x22` data) or a bencoded control dict (for handshake and rekey). The
handshake that turns a fresh `rp1` connection into a keyed session is in [05-session.md](05-session.md).

For the cover-seed mode, Riptide is carried on a peer connection that also serves a real torrent; the
recognition token that says "this peer speaks Riptide" is placed in the extended handshake as
described in [05-session.md](05-session.md), and no `RIPT`-like magic is used, to avoid a fingerprint.

## 3.9 The epoch clock

Rotating identifiers use a shared epoch derived from wall-clock time:

```
epoch = floor(unixTimeSeconds / EPOCH_SECONDS)
```

`EPOCH_SECONDS` defaults to `3600` (one hour) for rendezvous and presence; feeds and mailboxes may
choose coarser epochs. Because clocks drift, a party checking a rendezvous or inbox id SHOULD also
check the adjacent epochs (`epoch-1`, `epoch+1`). All parties to a channel MUST agree on
`EPOCH_SECONDS` for that channel; it is part of the channel's out-of-band setup.

## 3.10 Error model

- **Fail closed.** Any open/decrypt/verify that does not authenticate returns an error and no
  plaintext, never partial or unverified bytes. This is inherited directly from SodiumXT (open calls
  throw `SXT_ERR_AUTH`).
- **Surface, do not swallow.** A signature failure, a broken key-transparency link, or an epoch/seq
  mismatch is surfaced to the application (and usually the user), not silently dropped, because these
  are the signatures of an attack.
- **Replay is dropped.** A record or frame whose `(channel, seq)` has already been accepted is
  discarded. Mailboxes and feeds track the highest accepted `seq`; sessions rely on secretstream's
  built-in ordering.
- **Availability failures are retried, not trusted around.** A missing DHT record or a dead swarm is
  a delivery failure to retry or report, never a reason to fall back to an unauthenticated path.

## 3.11 Notation used in the channel documents

- `A`, `B` are parties; `IK_A` is A's identity signing pubkey, `IK_x_A` A's identity X25519 pubkey.
- `x || y` is concatenation; `be64(n)` is `n` as 8 big-endian bytes; `0^n` is `n` zero bytes.
- `bencode(...)` is canonical bencode (3.2); `pad`, `sxSeal`, `sxKdfDerive`, etc. are the SodiumXT
  calls of 3.3.
- `DHT.put(salt, seq, v, sig)` / `DHT.get(pub, salt)`, `DHT.putImmutable(v)` / `DHT.getImmutable(addr)`,
  and `DHT.announce(id)` / `DHT.getPeers(id)` are the TorrentXT DHT operations; `PW.connect`,
  `PW.send`, `PW.recv`, `PW.onConnect`, and `PW.handshakeDict` are the BEP10 peer-wire operations. All
  are formalized in [11-capabilities-required.md](11-capabilities-required.md).
