# 07. Broadcast feed and public wall

Two one-to-many channels built on the same spine, a BEP44 mutable seq-chain under the publisher's
identity key ([02-identity.md](02-identity.md)):

- **C4 Signed encrypted feed** (`salt = rp-feed`): an authenticated, encrypted, tamper-evident
  "podcast / private Telegram channel." The index is public and signed; the payloads are encrypted
  torrents readable only by the current reader set.
- **C8 Public wall** (`salt = rp-wall`): the same signed seq-chain with the encryption removed. A
  signed, un-deplatformable public feed (a self-owned microblog). Tier-0 by design: no
  confidentiality, only authenticity and ordering.

Both inherit the constitution ([03-conventions.md](03-conventions.md)) without exception:
canonical bencode (3.2), the KDF label registry (3.4), the envelope and associated-data rules
(3.5), nonce and comparison discipline (3.3), the message-type registry (3.6), the BEP44 carrier
and signing buffer (3.7), the epoch clock (3.9), and the error model (3.10). Notation is 3.11.

Nothing here invents a new encoding, KDF label, salt, or message type. All four were reserved in
the constitution already: labels `rp-feedk` (3.4), salts `rp-feed` and `rp-wall` (3.7), types
`0x30` / `0x31` / `0x32` (3.6). See the registry note below.

## Registry additions

None. This document only *uses* registry entries that [03-conventions.md](03-conventions.md)
already reserved for it:

| Kind | Value | Registry | Use here |
|---|---|---|---|
| KDF label | `rp-feedk` | 3.4 | per-epoch feed read key (master = feed master key `FMK`, id = epoch, out 32) |
| BEP44 salt | `rp-feed` | 3.7 | the encrypted feed's signed index |
| BEP44 salt | `rp-wall` | 3.7 | the public wall's signed index |
| Message type | `0x30` | 3.6 | feed-entry (encrypted feed index entry) |
| Message type | `0x31` | 3.6 | wall-entry (public wall index entry) |
| Message type | `0x32` | 3.6 | feed-key-update (per-reader wrapped read key) |

If a future revision needs a new label, salt, or type, it is added to the constitution first, not
here.

## 7.1 What a feed is

A feed is an append-only, hash-chained, ed25519-signed list of entries, published as a BEP44
**mutable seq-chain** keyed by the publisher's identity signing pubkey `IK_pub` under a salt. This
is the exact structure the key-transparency log uses ([02-identity.md](02-identity.md) 2.6): one
signed dict per `seq`, each carrying `prev = sxHash(previous entry, 32)`, so the whole history is a
single chain that forks loudly if tampered.

Entries are tiny (they fit the ~1000-byte BEP44 budget, 3.7). The bulk (the actual post body,
audio, image, document) never goes in the record. In the encrypted feed it lives in an **encrypted
torrent**; the record carries only a pointer to that torrent plus the wrapped content key. In the
public wall the body is small enough to inline, or the same torrent pointer is used unencrypted.

```
publisher IK  --(sign each entry)-->  BEP44 seq-chain under IK_pub, salt rp-feed / rp-wall
                                            |
   seq 0 --prev=0^32--> seq 1 --prev=H(0)--> seq 2 --prev=H(1)--> ...   (the signed index)
                                            |
                                   entry.ptr names an encrypted torrent (infohash H, wrapped K)
                                            |
                                     the swarm distributes the ciphertext body
```

There is exactly **one FFI-costly crypto operation per logical publish**: one file encryption for
the body, one detached signature for the index entry. The per-entry index record is a few hundred
bytes, well inside budget, so no chunking of the index is needed.

## 7.2 The signed index entry (encrypted feed, type 0x30)

Each feed entry is a canonical bencode dict (3.2, keys sorted by raw byte value). Keys are one or
two ASCII letters to fit the budget.

```
FeedEntry[n] = {
  v:    1,                       -- protocol version (3.1)
  t:    0x30,                    -- feed-entry (3.6)
  q:    n,                       -- seq: matches the BEP44 seq for this put
  p:    prev,                    -- sxHash(bencode(FeedEntry[n-1]), 32); 0^32 for n = 0
  e:    epoch,                   -- read-key epoch this payload was encrypted under (7.5)
  ts:   <unix epoch seconds>,    -- publish time (advisory, not trusted for ordering)
  pt:   ptr                      -- the payload pointer (7.4)
}
```

Field notes:

- `q` (seq) is the ordering authority, not `ts`. It equals the BEP44 `seq` used in the put, so the
  DHT's own monotonic-seq rule (3.10) and the entry's `q` agree. A receiver that sees `q` not equal
  to the BEP44 seq it fetched rejects the entry.
- `p` (prev) chains integrity: `p = sxHash(bencode(FeedEntry[n-1]), 32)`, and `0^32` (32 zero
  bytes) for `n = 0`. The hash is over the **canonical bencode of the whole prior entry dict**,
  before signing, exactly as 2.6 hashes a log entry. This is what makes a fork detectable.
- `e` is the read-key epoch (7.5); the payload body was encrypted with the feed read key for that
  epoch, so a subscriber knows which read key to use without trial decryption.
- `pt` (ptr) is the payload pointer of 7.4.

The entry dict is **not** itself encrypted. Its confidentiality comes entirely from the payload
being an encrypted torrent whose key is wrapped for readers (7.4, 7.5). The index leaks only that a
publisher posted at time `ts`, of ciphertext size implied by the torrent, under epoch `e`. That is
the price of a public, signed, ordered index; it is stated plainly in 7.9 (N2).

### 7.2.1 Signing the entry (the BEP44 signature IS the entry signature)

The feed does not carry a separate application-level signature field. The BEP44 mutable-put
signature over the record value **is** the entry's authenticity proof, because the value is the
canonical bencode of `FeedEntry[n]` and BEP44 signs the value. This is the keystone from the README
and brainstorm: `sxSignDetached` and the BEP44 signature are the same ed25519 primitive over the
same key.

The signing buffer is constructed exactly as [03-conventions.md](03-conventions.md) 3.7 (which is
BEP44's rule) prescribes: concatenate, in order,

```
bep44SignBuf =  "4:salt"  || bencode-of-salt          -- 4:salt then e.g. 7:rp-feed
             || "3:seq"   || "i" || decimal(seq) || "e"
             || "1:v"     || bencode-of-value
```

Concretely, with `salt = rp-feed` (7 bytes), `seq = n`, and `value = bencode(FeedEntry[n])`:

```
bep44SignBuf = "4:salt7:rp-feed" || "3:seqi" || decimal(n) || "e" || "1:v" || bencode(FeedEntry[n])
sig = sxSignDetached(bep44SignBuf, IK_sec)
DHT.put(salt=rp-feed, seq=n, v=bencode(FeedEntry[n]), sig=sig)
```

`decimal(n)` is `n` rendered as ASCII decimal with no leading zeros (bencode integer form, so `0`
is `i0e`, `10` is `i10e`). `bencode-of-salt` is the bencode byte string of the salt, so `rp-feed`
is `7:rp-feed` and `rp-wall` is `7:rp-wall`. `bencode-of-value` is the bencode byte string wrapping
the value bytes: `<len>:<value-bytes>`. This is byte-for-byte what a conformant BEP44 node
recomputes and verifies against `IK_pub`; because SodiumXT's ed25519 is the same primitive, the
signature validates in the mainline DHT with no special casing.

The publisher never chooses a nonce anywhere in this path: the signature is deterministic ed25519,
and all payload encryption draws its randomness inside SodiumXT (3.3).

## 7.3 The payload: body to encrypted torrent

The body (a post, an episode, an attachment) becomes an encrypted torrent. The encryption is done
entirely C-side so the plaintext and ciphertext never both sit in a LiveCode `Data`, per the
performance playbook (CLAUDE.md) and [09-objects.md](09-objects.md).

```
1. K   = sxRandomBytes(32)                      -- fresh per-payload content key, CSPRNG (3.3)
2. sxEncryptFile bodyPath, cipherPath, K        -- secretstream XChaCha20-Poly1305, C-side
3. seed cipherPath as a torrent  ->  infohash H (v1 SHA-1 or v2 SHA-256 of the info dict)
4. DHT.announce(H)                              -- publisher seeds the swarm
5. bodyHash = sxHashFile(bodyPath, 32)          -- BLAKE2b of the PLAINTEXT, for end-to-end verify
```

Notes:

- `K` is a fresh 32-byte key per payload from `sxRandomBytes`, never derived from and never equal
  to the feed read key. The read key's only job is to *wrap* `K` for readers (7.4); the body itself
  is under `K`. This two-level scheme (per-object content key, wrapped under a rotating read key) is
  what lets the publisher rotate reader access (7.5) without re-encrypting every torrent.
- `sxEncryptFile` uses secretstream, so the ciphertext carries per-chunk authentication, ordering,
  and a FINAL tag that makes **truncation detectable** (the constitution's file rule, 3.5 / 3.10).
  A cut-off or spliced torrent fails to decrypt; it never yields partial plaintext.
- `bodyHash` is BLAKE2b over the **plaintext**, computed with `sxHashFile` (streamed C-side). It is
  carried in the pointer (7.4) so a subscriber, after `sxDecryptFile`, can confirm the recovered
  plaintext is exactly what the publisher signed. This is defense in depth: secretstream already
  authenticates the ciphertext under `K`, but `bodyHash` binds the plaintext into the ed25519-signed
  index, so a swarm that serves a *different but validly-K-encrypted* file (only possible if `K`
  leaked to it) is still caught.
- `H` is a normal BitTorrent infohash. The DHT does not verify that an announced id maps to real
  content (brainstorm 1), but here it does: the torrent is real ciphertext. Both v1 (BEP3 / SHA-1)
  and v2 (BEP52 / SHA-256) infohashes are supported; the pointer says which (7.4). Metadata is
  fetched with BEP9 as usual.

## 7.4 The payload pointer (`pt`)

The `pt` field of a feed entry is a sorted bencode dict naming the torrent and carrying the wrapped
content key. It is embedded whole inside `FeedEntry[n]`, so it is covered by the same BEP44
signature (7.2.1).

```
ptr = {
  hv:  1 | 2,                    -- infohash version: 1 = v1 SHA-1 (BEP3), 2 = v2 SHA-256 (BEP52)
  h:   H,                        -- the infohash bytes (20 for v1, 32 for v2)
  bh:  bodyHash,                 -- sxHash of the PLAINTEXT body, 32 bytes (7.3)
  sz:  <ciphertext byte length>, -- advisory, for the subscriber's fetch budget
  wk:  wrappedKey                -- the content key K wrapped for the reader set (7.5)
}
```

`wk` (the wrapped content key) depends on the read-key distribution mode (7.5):

- **Group-key mode (default, 7.5.1):** `wk = sxAeadEncrypt(K, ad, RK_e)` where `RK_e` is the feed
  read key for epoch `e` and `ad = bencode({ e: epoch, q: seq, t: 0x30 })` (3.5.1). Because the AD
  binds `e`, `q`, and the type, a wrapped key lifted from one entry cannot be replayed into another
  slot. Every current reader holds `RK_e`, so `wk` is O(1) in the audience size. This is the field
  carried in the signed index.
- **Per-reader mode (7.5.2):** `wk` is empty in the index; `K` is instead delivered per reader via
  a separate `feed-key-update` record (type `0x32`), one sealed box per reader. Use this only for
  very small or high-assurance reader sets (7.5.2).

The public wall has no `wk` and no `bh`-secrecy concern; its pointer is defined in 7.7.

## 7.5 Read-key management and rotation

Confidentiality of an encrypted feed is confidentiality *to the current reader set*. Riptide gives
the publisher a rotating **feed read key** so that (a) a reader added at epoch `e` cannot read
payloads from before the epoch it was given a key for (bounded backward access), (b) a reader
removed at epoch `e+1` cannot read anything encrypted from `e+1` on (reader revocation), and (c)
compromise of one epoch's read key does not expose other epochs (per-epoch forward secrecy, the G3
form feeds get, which is by rotation, not per-message, per 01 G3).

The read key rotates on the **feed epoch clock** (3.9). Feeds MAY (and usually SHOULD) choose a
coarser `EPOCH_SECONDS` than the 3600 s rendezvous default, for example one day or one week, since a
feed's rotation cadence is a publish-policy choice, not a rendezvous-unlinkability one. The chosen
value is part of the feed's out-of-band setup (3.9) and is fixed for the feed.

Everything derives from one long-term secret the publisher holds, the **feed master key** `FMK`
(32 bytes, `sxRandomBytes(32)`, backed up with the identity seed but distinct from it). The
per-epoch read key is the constitution's `rp-feedk` derivation (3.4):

```
RK_e = sxKdfDerive(FMK, decimal(epoch), "rp-feedk", 32)     -- feed read key for this epoch
```

`decimal(epoch)` is the epoch integer as a decimal String (`sxKdfDerive`'s `pSubkeyId` is a decimal
String, api-reference). Because `RK_e` is derived from `FMK` and the epoch, a reader who is given
`RK_e` for a range of epochs can read exactly those epochs and no others: giving out one epoch's
key does not reveal the master key or any other epoch (crypto_kdf's guarantee). Revoking a reader is
"stop giving them the next epoch's `RK`."

The remaining question is only *how a reader gets `RK_e`*. Two distribution options.

### 7.5.1 Group-key distribution (default, scales to larger audiences)

Treat the reader set as a group and hand out `RK_e` with the group's sender/room-key machinery in
[08-groups.md](08-groups.md). The publisher, as room owner, distributes the current-epoch read key
to members through the group's keyed channel; `RK_e` here plays the role of a room key that
[08-groups.md](08-groups.md) already knows how to rotate and re-key on membership change. The wrapped
content key in each index entry is then `wk = sxAeadEncrypt(K, ad, RK_e)` (7.4), a single O(1) field
that every current holder of `RK_e` can open.

This is the recommended mode because the per-entry cost is constant in audience size: the index
carries one `wk`, and only the read-key handoff (once per epoch, out of the index) is O(readers) in
the worst case. It inherits [08-groups.md](08-groups.md)'s membership and rekey story rather than
reinventing one.

**The honest hard part.** Efficient membership revocation for a *large* audience without an O(n)
rekey on every removal is the MLS-class problem the brainstorm (8) and [01-threat-model.md](01-threat-model.md)
name. The group-key scheme here bounds a revoked reader to epochs up to and including the last one
whose `RK` they received; it does **not** give instant, sub-linear revocation for thousands of
readers. Tree-based group rekey (the true MLS answer) is deferred to
[13-open-questions.md](13-open-questions.md) as an open research track. Do not claim this feed gives
cheap large-audience revocation; it gives *epoch-granular* revocation, and that granularity is the
knob.

### 7.5.2 Per-reader key-wrap (simple, O(readers), small sets)

For a small or high-assurance reader set, skip the shared read key and wrap the per-payload content
key `K` directly to each reader's identity X25519 key with a sealed box. There is no `RK`; the
index entry's `wk` is empty, and `K` is delivered out of the index in a `feed-key-update` record.

The `feed-key-update` entry (type `0x32`) is itself a BEP44 mutable record under `IK_pub` with a
per-reader salt, or an immutable cell whose id the reader learns from the index; its value is:

```
KeyUpdate = {
  v:  1,
  t:  0x32,                      -- feed-key-update (3.6)
  q:  n,                         -- the feed seq this key unlocks
  r:  IK_x_reader,               -- which reader this wrap is for (their identity X25519 pubkey)
  wk: sxSeal(K, IK_x_reader)     -- K sealed to the reader; anonymous-sender sealed box (3.5)
}
```

`sxSeal` gives sealed-sender delivery: only the holder of the matching X25519 secret key opens it
(`sxSealOpen`), and the wrap does not name the publisher. The cost is one sealed box **per reader
per payload** (or per epoch if the readers instead wrap `RK_e`), which is O(readers). That is fine
for a handful of readers and does not scale; hence it is the non-default option. Revocation is
trivial and instant here: stop producing a `feed-key-update` for the removed reader on the next
payload.

Either mode, the content key `K` is fresh per payload (7.3); only the *wrapping* differs.

## 7.6 The subscriber flow (encrypted feed)

A subscriber holds the publisher's `IK_pub` (verified per [02-identity.md](02-identity.md) 2.5, so
a rung-3 DHT liar cannot substitute a key) and read access (either membership in the group that
holds `RK`, 7.5.1, or a per-reader key stream, 7.5.2). It maintains the highest `(seq, hash)` it has
verified, exactly like the key-transparency follower of 2.6.

```
1.  known = highest verified (seq, hash) for this feed, or (-1, 0^32) if new.
2.  For n = known.seq + 1, known.seq + 2, ... :
3.     rec = DHT.get(IK_pub, salt=rp-feed)          -- fetch the seq-n mutable record
        (fetch by seq; the DHT returns value v, seq, and sig)
4.     Verify BEP44 sig: reconstruct bep44SignBuf (7.2.1) from salt rp-feed, seq n, value v.
        if not sxSignVerifyDetached(sig, bep44SignBuf, IK_pub):  FAIL LOUD (3.10), stop.
5.     entry = bencode-decode(v). Check entry.v == 1, entry.t == 0x30, entry.q == n.
        if not: FAIL LOUD, stop.
6.     Verify the chain: if entry.p != known.hash:  FAIL LOUD as a FORK (3.10, 2.6), stop.
        (0^32 required at n = 0.) A second valid entry at an already-accepted seq is also a fork.
7.     thisHash = sxHash(v, 32).                     -- v IS bencode(FeedEntry[n]) (7.2.1)
8.     Unwrap K:
          group-key mode:   ad = bencode({e: entry.e, q: n, t: 0x30});
                            RK = sxKdfDerive(FMK-or-received-RK-for entry.e, ...);  -- 7.5.1
                            K  = sxAeadDecrypt(entry.pt.wk, ad, RK)   -- throws on wrong RK / tamper
          per-reader mode:  fetch this reader's feed-key-update for seq n (7.5.2);
                            K  = sxSealOpen(update.wk, IK_x_reader_pub, IK_x_reader_sec)
        if decrypt/open throws:  FAIL LOUD (wrong key or tampered, 3.10), stop or skip per policy.
9.     Download the torrent by entry.pt.h (entry.pt.hv selects v1/v2):
          DHT.getPeers(entry.pt.h); fetch metadata (BEP9); download; -> cipherPath.
10.    sxDecryptFile cipherPath, bodyPath, K
        (throws on wrong K or truncation/corruption -> FAIL LOUD, the torrent was tampered.)
11.    Verify plaintext: if not sxMemEqual(sxHashFile(bodyPath, 32), entry.pt.bh):
          FAIL LOUD (3.10) -- the plaintext is not what the publisher signed. Discard.
12.    Accept entry n. Set known = (n, thisHash). Deliver bodyPath to the app.
13.  When DHT.get for n+1 returns nothing, the subscriber is caught up; retry later (3.10 N7).
```

Every failure is surfaced, never swallowed (3.10). Specifically:

- A **bad signature** (step 4) means the record was not produced by `IK` (forgery, or the DHT lied);
  stop and warn.
- A **broken prev-link or a duplicate seq** (step 6) is a **fork**: two histories under one key. Per
  [02-identity.md](02-identity.md) 2.6 and the error model (3.10) this is evidence of tampering or a
  compromised signing key and is surfaced to the user, not silently accepted. The subscriber pins the
  last-good `(seq, hash)` and refuses to advance past a fork.
- A **wrap open failure** (step 8) means the reader lacks the read key for that epoch (revoked, or
  not yet added) or the wrap was tampered; distinguish "not for me" from "tampered" where possible.
- A **decrypt or plaintext-hash failure** (steps 10-11) means the torrent body does not match the
  signed pointer; discard the payload but keep the (verified-signature) index position.

Because `q`/seq is monotonic and the subscriber tracks the highest accepted seq, a **replayed**
older record is dropped (3.10). Compare `bh` with `sxMemEqual`, never `is` (3.3).

## 7.7 The public wall (C8, type 0x31, salt rp-wall)

The wall is the encrypted feed with the confidentiality removed, by design (tier-0). It is the
"trust the key, not the host" model: a signed, ordered, un-deplatformable feed anyone can read and
verify, but no one can forge or silently reorder. Same seq-chain integrity, no read keys, no wrapped
content keys.

```
WallEntry[n] = {
  v:   1,
  t:   0x31,                     -- wall-entry (3.6)
  q:   n,                        -- seq (matches the BEP44 seq)
  p:   prev,                     -- sxHash(bencode(WallEntry[n-1]), 32); 0^32 for n = 0
  ts:  <unix epoch seconds>,
  b:   body                      -- inline post bytes, if small; OR omit b and use pt
  pt:  { hv, h, bh, sz }         -- OPTIONAL public torrent pointer for large bodies (no wk, no encryption)
}
```

- A wall entry inlines a short body in `b` (bounded by the ~1000-byte record budget after the other
  fields, so a few hundred bytes of text). A larger body uses `pt`, a **cleartext** torrent
  pointer: `hv`/`h`/`bh`/`sz` as in 7.4 but with **no `wk`** (nothing is wrapped) and the torrent is
  plain (the body is `sxHashFile`-hashed for `bh`, but *not* `sxEncryptFile`-encrypted). Exactly one
  of `b` or `pt` is present.
- There is **no `e`** (no read-key epoch; nothing is encrypted).
- Signing and publishing are identical to 7.2.1 with `salt = rp-wall`:

```
bep44SignBuf = "4:salt7:rp-wall" || "3:seqi" || decimal(n) || "e" || "1:v" || bencode(WallEntry[n])
sig = sxSignDetached(bep44SignBuf, IK_sec)
DHT.put(salt=rp-wall, seq=n, v=bencode(WallEntry[n]), sig=sig)
```

### 7.7.1 Reading the wall

The reader flow is 7.6 with steps 8-11 removed (no unwrap, no decrypt) and step 11 replaced by an
optional plaintext-hash check when a `pt` is present:

```
1.  For n = known.seq + 1, ... :
2.     rec = DHT.get(IK_pub, salt=rp-wall)
3.     Verify BEP44 sig against IK_pub (7.2.1, salt rp-wall). Bad sig -> FAIL LOUD, stop.
4.     entry = decode(v); check v==1, t==0x31, q==n. Bad -> FAIL LOUD, stop.
5.     Chain: entry.p == known.hash (0^32 at n=0)? No -> FAIL LOUD as a FORK, stop.
6.     If entry has b: body = entry.b.
       If entry has pt: download torrent by pt.h (pt.hv); then
          if not sxMemEqual(sxHashFile(bodyPath, 32), pt.bh): FAIL LOUD (tampered body), discard.
7.     Accept. known = (n, sxHash(v, 32)). Deliver body.
```

The wall gives **no confidentiality** (N2, tier-0) but the full G2 integrity, G4 ordering, and G5
censorship-resistance of the encrypted feed. Anyone can read it; no one can forge an entry under
`IK` or splice the history without producing a detectable fork.

## 7.8 Publishing lifecycle notes

- **Republication.** BEP44 items expire and the DHT churns (3.10 N7, brainstorm 8). The publisher
  MUST periodically re-put the tail of the chain (at least the highest seq, ideally a sliding
  window) so followers can always fetch the latest. A subscriber that cannot fetch seq `n` retries
  (3.10), it does not fall back to an unauthenticated source.
- **Payload availability.** The publisher must keep seeding the torrents it wants readable, or hand
  seeding to willing readers (who thereby seed ciphertext, learning nothing extra). A dead swarm is
  an availability failure (N7), not a confidentiality one.
- **Seq is the authority.** `ts` is advisory. Two entries with the same `q`/seq are a fork (7.6), so
  a publisher must never reuse a seq; the BEP44 monotonic-seq rule enforces this at the DHT.
- **Rotation of the whole feed id.** Unlike rendezvous ids (principle 4), a feed's whole point is a
  stable name (`IK_pub` + salt) that followers subscribe to, so the *feed key does not rotate*; only
  the *read key* rotates (7.5). This is a deliberate exception to "rotate everything": a publisher
  who wants unlinkability across time publishes under a fresh identity, not a rotated salt.

## 7.9 Security properties

Mapping to the goals and non-goals of [01-threat-model.md](01-threat-model.md), per adversary rung.

**Encrypted feed (C4).**

- **G1 Confidentiality (rungs 1-4):** payload bodies are XChaCha20-Poly1305 secretstream ciphertext
  under a fresh per-payload key `K`, and `K` is delivered only to the current reader set (7.5).
  Everything an on-path tap, a DHT crawler, or a swarm insider sees is ciphertext plus the signed
  index metadata. The read key rotates per epoch (`rp-feedk`, 7.5), so this is confidentiality *to
  the reader set as of each epoch*.
- **G2 Integrity and authenticity (rungs 1-4):** every index entry is ed25519-signed by `IK` as its
  BEP44 signature (7.2.1); every payload is authenticated by secretstream under `K` and again by the
  signed `bodyHash` (7.3, step 11). Forgery, tampering, and a wrong key are detected and rejected,
  never silently accepted (3.10).
- **G3 Forward secrecy (rungs 1-4, by rotation):** feeds get the rotation form of G3 (01 G3), not
  per-message ratcheting. Compromise of one epoch's `RK_e` exposes only that epoch's payloads;
  `crypto_kdf` separation means it does not reveal `FMK` or any other epoch's `RK`. A reader added
  at epoch `e` gets bounded backward access, a reader revoked after epoch `e` loses `e+1` onward.
- **G4 Replay and reorder resistance (rungs 1-4):** ordering is the `q`/seq plus the `prev`-hash
  chain (7.2, 7.6), monotonic at the BEP44 layer (3.10). A replayed older record is dropped; a
  reordered or spliced history forks and is surfaced. The wrapped-key AD binds `e`, `q`, and type
  (7.4), so a `wk` cannot be moved between slots.
- **G5 Censorship resistance (rung 2; rung 3 with effort):** there is no host to seize; the index is
  in the DHT and the payload is in a swarm. A rung-3 Sybil that eclipses the feed's BEP44 key can
  censor the index for targeted followers; the mitigation is republication and redundant fetch
  (7.8), and G5 is weaker at rung 3 exactly as [01-threat-model.md](01-threat-model.md) states.
- **Fork detection (rung 3):** the hash-chained, signed index makes a silent history rewrite loud
  (7.6, mirroring the key-transparency guarantee of 2.6). A compromised `IK` can still sign a fork,
  but it cannot do so *silently*: followers pinning `(seq, hash)` see two histories at one seq.

**Public wall (C8).**

- Achieves **G2** (authenticity), **G4** (ordering / fork detection), and **G5** (censorship
  resistance) identically to the feed. It deliberately does **not** provide **G1** (tier-0, no
  confidentiality) and there is no read-key or forward-secrecy notion (7.7). Its value is exactly an
  un-deplatformable *public* signed feed: trust the key, not the host.

**Non-goals that apply (both).**

- **N2 Incomplete metadata privacy (honest, load-bearing here):** the subscriber set is **observable
  at the swarm level**. Anyone can watch who joins the swarm for a payload torrent (`H`) and infer
  the reader set, and a rung-3 DHT crawler can see the feed's BEP44 key being read. The signed index
  itself is public and reveals post times (`ts`), ciphertext sizes (`sz`), and epoch (`e`). Riptide
  raises no wall against this at the feed layer; padding (`sxPad` at the object layer,
  [09-objects.md](09-objects.md)) and k-anonymous swarming reduce but do not eliminate it. This is
  the brainstorm's stated limit (C4: "the *set* of subscribers is observable at the swarm level")
  and it stands.
- **N1 No IP anonymity by default:** announcing or fetching a payload torrent, or reading the index,
  exposes IP to peers and DHT nodes. Run over Tor/I2P or the multi-hop extension
  ([10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)).
- **N4 No content moderation:** the feed authenticates *who* published so a reader can choose whom
  to follow and block; it does not filter content. Recipient-side allow/block is the model
  ([10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)).
- **N5 / N6 / N7:** loss of `IK` or `FMK` is unrecoverable (N5); a compromised endpoint exposes
  `FMK`, `K`, and plaintext (N6); DHT churn and swarm death are availability failures to retry, not
  reasons to trust an unauthenticated path (N7, 7.8).

**Adversary rungs summary.** Confidentiality (G1) and authenticity (G2) hold against rungs 1-4. The
large-audience *revocation* problem (efficient, sub-linear membership removal) is unsolved here and
deferred to [13-open-questions.md](13-open-questions.md); the buildable baseline is epoch-granular
revocation (7.5). Against rung 5 (global passive correlation) the feed makes no claim (N3).
