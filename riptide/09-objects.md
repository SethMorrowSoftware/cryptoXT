# 09. Objects and links

An **object** is an encrypted file that lives in a BitTorrent swarm instead of a ~1000-byte DHT
record. Where a mailbox message or a feed entry is small enough to fit inside one BEP44 value, an
object is the carrier for everything larger: a photo, a document, a video, or the oversized body of
any other channel's message. The object channel gives three user-facing shapes:

- a **capability link**, a self-contained URL whose fragment carries the key, that anyone in
  possession can open;
- a **content-addressed drop**, a sealed manifest published as a BEP44 immutable record and pointed
  at from a mailbox or feed;
- a **bulk body** for another channel, when a padded payload would exceed one BEP44 record
  ([03-conventions.md](03-conventions.md) 3.5.2) and so MUST move as a torrent.

This document is channel C6 in [../brainstorm.md](../brainstorm.md). It builds on the constitution
([03-conventions.md](03-conventions.md)) and invents no new encodings, KDF labels, or nonce
handling. Its message types (`0x50` manifest, `0x51` chunk-key) come from the registry in 3.6.

## Registry additions

The object channel needs no new KDF label and no new salt. It uses two already-reserved message
types from [03-conventions.md](03-conventions.md) 3.6, restated here for reference:

| `t` | Name | Shape |
|---|---|---|
| `0x50` | `manifest` | the object manifest dict of 9.3 (sealed to a recipient, or bare) |
| `0x51` | `chunk-key` | a per-recipient key-wrap for a shared object (9.4), so one ciphertext serves many named recipients |

One DHT operation used here is not spelled out in 3.11's mutable-only list, because BEP44 immutable
puts are addressed by the hash of their own value, not by a key and salt. This document uses:

- `DHT.putImmutable(v) -> addr` : store the bencoded value `v` as a BEP44 immutable item; the DHT
  address `addr` is `SHA1(v)` (BEP44 computes it; it is 20 bytes, mainline-DHT sized). Riptide keeps
  its own content integrity separate from this SHA1 (see 9.5 and the security note), so a weak
  transport hash cannot be used to smuggle a bad object past verification.
- `DHT.getImmutable(addr) -> v` : fetch the value stored at `addr`; the fetcher recomputes `SHA1(v)`
  and rejects a mismatch, exactly as BEP44 requires.

These wrap the same TorrentXT BEP44 surface as the mutable `DHT.put` / `DHT.get` of 3.11; they are
named separately only because the address is derived, not chosen.

## 9.1 What an object is, and why it is not a record

A BEP44 value is capped near 1000 bytes and expires with DHT churn ([03-conventions.md](03-conventions.md)
3.7). That is fine for a signaling pointer, a prekey bundle, or a short message, but it cannot hold a
file. So Riptide splits a large payload in two:

- the **bytes** become an **encrypted torrent**: `sxEncryptFile` seals the plaintext under a fresh
  32-byte key `K`, and the resulting ciphertext file is a normal torrent with a normal infohash `H`.
  The swarm distributes it, seeders replicate it, and it is exactly the "bulk payload carrier" of
  [../brainstorm.md](../brainstorm.md) 1. The plaintext never enters a LiveCode `Data`, so an
  arbitrarily large file encrypts in constant script memory (the whole point of the C-side file
  helpers).
- the **metadata** needed to find, decrypt, and verify those bytes becomes a small **manifest**
  (9.3), which is a structured record ([03-conventions.md](03-conventions.md) 3.2) that DOES fit in a
  BEP44 value, or that travels in a link, or that is embedded inline in another channel's message.

The manifest is the durable, shareable, small thing. The torrent is the large, self-hosting,
swarm-replicated thing. Separating them is what lets one ~200-byte manifest stand in for a gigabyte
of ciphertext.

## 9.2 Encrypting an object (the seal)

Sealing is one file-encrypt call plus two hashes. All calls are SodiumXT
([../docs/api-reference.md](../docs/api-reference.md)); none chooses a nonce (secretstream, under
`sxEncryptFile`, derives per-chunk nonces from a random header, per
[03-conventions.md](03-conventions.md) 3.3).

```
Flow 9.2  Seal a plaintext file at path SRC into a shareable object

1. put sxRandomBytes(32) into K                      -- fresh per-object content key (CSPRNG only)
2. get sz = size in bytes of the file at SRC         -- plaintext length, for the manifest
3. put sxHashFile(SRC, 32) into PH                    -- 32-byte BLAKE2b of the PLAINTEXT (integrity)
4. sxEncryptFile SRC, ENC, K                          -- write ciphertext file ENC (secretstream)
5. build a v1 or v2 torrent over ENC -> infohash H    -- H is 20 bytes (v1) or 32 bytes (v2)
6. DHT.announce(H)  and start seeding ENC             -- publish the bytes to the swarm
7. build the manifest M over { H, sz, PH, K, ... }    -- see 9.3; K is wrapped, never stored bare
```

Notes on each step:

- **Step 1.** `K = sxRandomBytes(32)` is the content key. It is used once, for this object. Reusing a
  content key across two different plaintexts would reuse a keystream context and is forbidden by the
  nonce discipline; a fresh `K` per object makes that impossible.
- **Step 3.** `PH = sxHashFile(SRC, 32)` is a BLAKE2b hash of the **plaintext**, computed C-side so a
  huge file does not enter memory. It is the object's integrity anchor: a decryptor recomputes it
  after decrypting and refuses the object on a mismatch (9.6). This is independent of the infohash
  `H` (which authenticates the ciphertext to BitTorrent) and of the secretstream tags (which
  authenticate each chunk and detect truncation); `PH` is the end-to-end check that the recovered
  plaintext is exactly what the sender sealed.
- **Step 4.** `sxEncryptFile SRC, ENC, K` is the bulk carrier. The AEAD is secretstream
  XChaCha20-Poly1305 ([03-conventions.md](03-conventions.md) 3.3): every chunk carries a Poly1305 tag
  and the last chunk carries the FINAL tag, so a truncated download fails to decrypt (a cut-off
  object is detected, not silently accepted).
- **Step 5.** The torrent is built over the **ciphertext** file `ENC`, so `H` is the infohash of
  ciphertext, and a swarm member sees only ciphertext. Riptide supports both BEP52 v2 (32-byte
  SHA-256 infohash, preferred for new objects) and BEP3/BEP5 v1 (20-byte SHA-1 infohash, for
  compatibility with v1-only swarms). The manifest records which by the length of `H` and the `alg`
  field (9.3).

## 9.3 The object manifest (type 0x50)

The manifest is a bencoded dict ([03-conventions.md](03-conventions.md) 3.2, keys sorted by raw byte
value). It is the small record that names one object. Fields:

| Key | Type | Meaning |
|---|---|---|
| `v` | int | protocol version, `1` (mandatory, 3.2) |
| `t` | int | message type, `0x50` = 80 (mandatory, 3.2) |
| `h` | bytes | the infohash `H`: 20 bytes for a v1 torrent, 32 bytes for a v2 torrent |
| `alg` | int | ciphertext format / hash-suite tag: `1` = secretstream-XChaCha20Poly1305 over a v2 (SHA-256) torrent; `2` = the same over a v1 (SHA-1) torrent |
| `klen` | int | content-key length in bytes, `32` (from `sxRandomBytes(32)`; recorded, not hardcoded by the reader) |
| `sz` | int (or ZString) | plaintext size in bytes; a size that can exceed 2^31 crosses as a decimal string, matching the no-64-bit-foreign-int rule ([../CLAUDE.md](../CLAUDE.md) FFI conventions) |
| `ph` | bytes | the 32-byte plaintext BLAKE2b hash `PH` from step 9.2.3 |
| `kw` | dict or absent | the key-wrap (9.4); a `kw` dict wraps `K` for a named recipient, absence means `K` travels out of band in a link fragment |

Canonical bencode of a **bare** manifest (link-bearer case, `kw` absent), for a v2 torrent, with `H`
and `PH` shown as `<32 bytes>`:

```
d
  3:alg i1e
  1:h  32:<H, 32 bytes>
  4:klen i32e
  2:ph 32:<PH, 32 bytes>
  2:sz i1048576e
  1:t  i80e
  1:v  i1e
e
```

(Keys sort as `alg` < `h` < `klen` < `ph` < `sz` < `t` < `v` by raw byte value; the bencode is
written with no whitespace, shown indented here only for reading.)

Canonical bencode of a **sealed** manifest (private send, `kw` present), same object, sealed to a
recipient whose X25519 identity key is `IK_x_B`:

```
d
  3:alg i1e
  1:h  32:<H, 32 bytes>
  4:klen i32e
  2:kw d 1:k 80:<80 bytes: sxSeal(K, IK_x_B)> 1:m i1e e
  2:ph 32:<PH, 32 bytes>
  2:sz i1048576e
  1:t  i80e
  1:v  i1e
e
```

Key order in the sealed manifest is `alg` < `h` < `klen` < `kw` < `ph` < `sz` < `t` < `v` by raw
byte value: `klen` sorts before `kw` because their shared prefix is `k`, then `l` (0x6C) < `w`
(0x77). The `kw` dict itself has keys `k` (the wrapped-key bytes) and `m` (the wrap-method int, 9.4),
already sorted. A reader MUST sort keys itself and not trust the writer's ordering; a manifest whose
keys are not in canonical order is malformed and rejected ([03-conventions.md](03-conventions.md)
3.2).

## 9.4 The key-wrap (`kw`): who can decrypt `K`

`K` is the only secret that unlocks the object. How `K` reaches the opener is the whole access-control
story, and there are exactly two supported modes, selected by the presence and `m` value of `kw`:

- **(a) Sealed to a recipient (`kw.m = 1`), for a private send.** `K` is wrapped with a sealed box to
  one recipient's X25519 identity key:

  ```
  kw = { m: 1, k: sxSeal(K, IK_x_B) }        -- 32-byte K wrapped: 32 + 48 overhead = 80-byte k
  ```

  (`sxSeal` adds 48 bytes of overhead, [03-conventions.md](03-conventions.md) 3.3, so `k` is
  `klen + 48 = 80` bytes for a 32-byte `K`.) Only the holder of `IK_x_B`'s secret key can run
  `sxSealOpen(kw.k, IK_x_B_pub, IK_x_B_sec)` to recover `K`. The sender is anonymous (sealed box
  hides the sender, goal G7), so a sealed manifest is a private, sender-anonymous object delivery.
  Fan-out to several named recipients uses one `chunk-key` record (`0x51`) per recipient, so the
  bytes are shared (one torrent, one `H`, one `K`) but each recipient gets its own individual
  `sxSeal(K, IK_x_i)` wrap and no recipient learns another's identity.

- **(b) Bare, a capability (`kw` absent).** `K` is NOT in the manifest at all. It travels in a link
  fragment (9.5). Anyone who has the link has `K`; anyone who has only the manifest (from the DHT or
  the swarm) has ciphertext they cannot open. This is the "password in the URL, but authenticated
  encryption" model of [../brainstorm.md](../brainstorm.md) C6: possession of the link is the
  capability.

A manifest MUST use exactly one mode. A manifest with `kw` present is opened by unwrapping; a
manifest with `kw` absent requires `K` from the link. There is deliberately no third mode where `K`
sits in the manifest in the clear: that would put the key next to the ciphertext address on a public
network, which is never safe.

## 9.5 Capability links

A **capability link** is a URL-like string that carries everything needed to fetch and open a bare
object (9.4b). Its form:

```
bt-secure://<infohash-hex>#<key-b64>

where  <infohash-hex> = textDecode(sxBin2Hex(H), "ascii")     -- 40 hex chars (v1) or 64 (v2)
       <key-b64>      = textDecode(sxBin2Base64(K), "ascii")  -- URL-safe base64, no padding, of the 32-byte K
```

Example (v2 infohash, illustrative bytes):

```
bt-secure://b1946ac92492d2347c6235b4d2611184a3e2f5c7d8e9...<64 hex>#Zm9vYmFyYmF6cXV4Y29ycmVjdGhvcnNlYmF0dGVyeQ
```

The key rule, from [../brainstorm.md](../brainstorm.md) C6: **`K` lives only after the `#`.** A URL
fragment is not sent to a server on an HTTP fetch and, more to the point here, `K` is never written to
the DHT, never put in a torrent, and never placed in a manifest for this mode. The network sees `H`
(the ciphertext infohash) and the ciphertext; it never sees `K`. Whoever holds the whole link holds
the capability to decrypt.

```
Flow 9.5  Build and open a capability link

Build (sender), continues from Flow 9.2 with kw absent:
  L1. put textDecode(sxBin2Hex(H), "ascii") into hexPart
  L2. put textDecode(sxBin2Base64(K), "ascii") into keyPart
  L3. put "bt-secure://" & hexPart & "#" & keyPart into link
  L4. share link out of band (QR, chat, paper); optionally publish the bare manifest (9.6)

Open (recipient), given link:
  O1. split link on "#": hexPart before, keyPart after
  O2. put sxHex2Bin(textEncode(hexPart, "ascii")) into H
  O3. put sxBase642Bin(textEncode(keyPart, "ascii")) into K
  O4. DHT.getPeers(H); download the ciphertext file ENC from the swarm
  O5. run the decrypt/verify flow (9.6) with H, K, and (if present) the bare manifest's sz and ph
```

**Bencoded manifest alternative.** A link is convenient for a human but a manifest is convenient for a
program. The same bare object can be conveyed as a bencoded manifest (9.3, `kw` absent) plus `K` sent
by any confidential side channel, instead of packed into a `bt-secure://` string. The two are
interchangeable: the link is `H` + `K` inline; the bare manifest is `H` + `sz` + `ph` on the wire with
`K` delivered separately. Use the link when a human copies it; use the manifest when another channel
embeds the object (9.8) and can carry `K` in its own encrypted body.

**Who can open.** Anyone with the link (mode b) or anyone holding the recipient secret key (mode a).
There is no per-open authorization and no revocation of an already-shared link: possession is access.

**Revocation.** Because the key is baked into the capability, you cannot un-share `K`. Revocation is
by **re-encryption under a fresh `K'`**: re-run Flow 9.2 on the plaintext with a new random key,
producing a new ciphertext, a new infohash `H'`, and a new link; stop seeding the old ciphertext so
the old swarm dies from churn. Anyone holding the old link can still open any old copy they already
downloaded (you cannot recall bytes that left your control), but they cannot open the new object and,
once the old swarm is gone, cannot fetch the old ciphertext either. Rotating `K` per share, or per
recipient (via mode a), limits the blast radius of a leaked link.

## 9.6 Decrypt and verify (fail closed)

Opening an object fetches ciphertext by infohash, decrypts it, and then verifies both the declared
size and the plaintext hash before handing any bytes to the caller. Every check fails closed
([03-conventions.md](03-conventions.md) 3.10): on any mismatch the flow returns an error and no
plaintext, never partial or unverified bytes.

```
Flow 9.6  Fetch, decrypt, verify an object

Inputs: the manifest M (or a link, which yields H and K per Flow 9.5), and the recipient keypair if
        M carries a sealed kw.

1. read H, sz, PH from M (or from the link + bare manifest)
2. recover K:
     - mode a (M.kw present, M.kw.m = 1):
         put sxSealOpen(M.kw.k, IK_x_B_pub, IK_x_B_sec) into K     -- throws on wrong recipient / tamper
     - mode b (bare):  K came from the link fragment (Flow 9.5 O3)
3. DHT.getImmutable(addr) if the manifest itself was a content-addressed drop (9.7), else skip
4. DHT.getPeers(H); download the ciphertext file ENC from the swarm     -- BitTorrent verifies H piece-by-piece
5. sxDecryptFile ENC, OUT, K
     -- secretstream: any wrong key, flipped bit, dropped/reordered/truncated chunk THROWS here.
     -- a truncated download fails because the FINAL tag is missing. No plaintext escapes on failure.
6. verify size:      if (size in bytes of OUT) <> sz  then FAIL "size mismatch", delete OUT
7. verify plaintext: put sxHashFile(OUT, 32) into PH2
                     if not sxMemEqual(PH2, PH) then FAIL "content mismatch", delete OUT
8. accept OUT as the recovered plaintext
```

Why three independent checks:

- **BitTorrent piece hashing (step 4)** guarantees the bytes you downloaded match the infohash `H`,
  so a swarm peer cannot feed you ciphertext that is not the ciphertext the sender published. For v2
  torrents this is SHA-256 per BEP52; for v1 it is SHA-1 per BEP3.
- **secretstream tags (step 5)** guarantee the ciphertext decrypts under `K` with per-chunk
  authenticity and correct ordering, and that it was not truncated (FINAL tag). A wrong `K` throws
  here, not later.
- **`sz` and `ph` (steps 6-7)** are the end-to-end binding to what the sender intended: they catch a
  mismatch between the manifest and the actual object (for example, a manifest that points at a
  different, validly-encrypted torrent, or a size lie), which the transport-layer hashes alone cannot
  see. `PH` is compared with `sxMemEqual` ([03-conventions.md](03-conventions.md) 3.3), not `is`.

Only after step 8 does any plaintext reach the application. This is the object channel's expression of
"fail closed": a wrong key, a tampered ciphertext, a truncated download, a size lie, or a
content-hash mismatch each stop the flow with an error and leave no readable output.

## 9.7 The content-addressed drop

A capability link is push (you hand someone the link). A **content-addressed drop** is pull: publish
the manifest itself into the DHT at an address anyone who learns that address can fetch, and share the
address (small, stable, 20 bytes) instead of the whole manifest.

The manifest is published as a **BEP44 immutable record** ([03-conventions.md](03-conventions.md) 3.7:
immutable records hold self-contained sealed envelopes addressed by hash). The address is the hash of
the manifest's own bencoded bytes, so the drop is content-addressed: the address commits to the exact
manifest, and a fetcher recomputes it and rejects any substitution.

```
Flow 9.7  Publish and resolve a content-addressed drop

Publish (sender), continues from Flow 9.2, using a SEALED manifest (mode a) for a private drop:
  D1. build the sealed manifest M (9.3, kw.m = 1, sealed to IK_x_B)
  D2. put bencode(M) into Mb
  D3. put addr = DHT.putImmutable(Mb)            -- addr = SHA1(Mb), 20 bytes, the drop address
  D4. share addr with B by:
        - a mutable pointer: put addr into a mailbox message (doc 06) or a feed entry (doc 07); or
        - out of band (QR, link of the form bt-secure://drop/<addr-hex>, spoken aloud)

Resolve (recipient B), given addr:
  R1. put DHT.getImmutable(addr) into Mb          -- fetcher checks SHA1(Mb) == addr, rejects mismatch
  R2. parse Mb -> M ; check M.v = 1 and M.t = 0x50
  R3. run Flow 9.6 on M (B unwraps kw with its recipient secret key, downloads by M.h, verifies)
```

The pointer that carries `addr` is where rotation and unlinkability live: putting `addr` in a mailbox
message means only the mailbox's recipient learns the drop exists; putting it in a feed entry means
the feed's readers learn it. The drop record itself is immutable and self-verifying, so it can be
replicated and cached freely; the confidentiality comes from the sealed `kw` (only `IK_x_B` opens
`K`) and, if you want to hide even the drop's existence, from keeping `addr` inside an encrypted
mailbox or feed body rather than announcing it.

**Sealed vs. bare in a drop.** A drop normally uses a **sealed** manifest (mode a): the manifest is
public (anyone with `addr` fetches it) so `K` must be wrapped, or the object would be world-readable.
A **bare** manifest in a drop is only appropriate when the object is meant to be openable by anyone
who finds the address (a public content-addressed object); then `K` must still reach openers by a link
fragment or side channel, since a bare manifest never contains `K`. If you want "anyone with the
address can read it" you are describing a public object and should ship the link, not just the drop.

## 9.8 Objects as the body of an over-size mailbox or feed message

This is the reason the object channel is L1 infrastructure and not just a user feature. Whenever a
mailbox message ([06-mailbox.md](06-mailbox.md)) or a feed entry ([07-feed.md](07-feed.md)) has a
payload that, once padded ([03-conventions.md](03-conventions.md) 3.5.2), would exceed a single BEP44
record, that channel MUST put an **object manifest** in its record and the **bytes** in a torrent,
rather than trying to split a payload across many DHT records.

The pattern, used identically by docs 06 and 07:

```
Flow 9.8  Carry an over-size channel payload as an object

Sender (in the mailbox / feed sending path):
  1. seal the large body as an object: run Flow 9.2 -> H, K, sz, PH
  2. build a manifest M (9.3). For a private mailbox message, wrap K for the recipient (mode a);
     for a feed, wrap K under the feed's current read key (the feed's own key schedule, doc 07) or
     carry K inside the feed entry's already-encrypted body.
  3. embed M (or the drop address addr from Flow 9.7) INSIDE the channel's normal envelope, in place
     of the raw body. The envelope is still a single BEP44 record; it now contains a pointer, not the
     payload.
  4. send/publish that record exactly as the channel normally does (its epoch/seq/AD binding,
     3.5.1, is unchanged).

Recipient:
  5. open the channel envelope as usual -> recover M (or addr)
  6. run Flow 9.6 (resolving a drop via Flow 9.7 first if it was an address) to fetch, decrypt, and
     verify the object; the recovered plaintext is the message body.
```

The channel's own security properties still apply to the small record (its signature, its epoch/seq
AD, its ratchet or feed-key rotation); the object adds bulk transport and its own content hash on top.
A mailbox thus gains attachments and a feed gains large posts without either channel learning anything
about torrents beyond "here is a manifest to embed." The manifest's `kw` mode is chosen to match the
carrying channel: sealed-to-recipient for a 1:1 mailbox message, feed-read-key-wrapped (or
body-carried) for a 1:many feed.

## 9.9 Security properties

Against the adversary ladder and goals of [01-threat-model.md](01-threat-model.md):

- **G1 Confidentiality (rungs 1-4).** The object plaintext is XChaCha20-Poly1305 (secretstream)
  ciphertext in the swarm; without `K` a swarm member, a DHT crawler, or an on-path observer sees only
  ciphertext and its infohash. `K` is 256 bits of CSPRNG output and reaches openers only via a sealed
  `kw` (mode a) or a link fragment that never touches the network (mode b).
- **G2 Integrity and authenticity (rungs 1-4).** Three layers, all fail-closed (9.6): BitTorrent
  piece hashing binds the download to `H`; secretstream Poly1305 tags bind every chunk to `K` and the
  FINAL tag makes truncation detectable; the plaintext hash `ph` (compared with `sxMemEqual`) binds
  the recovered bytes end-to-end to what the sender sealed. A wrong key, a flipped bit, a dropped or
  reordered chunk, a truncated file, or a lying manifest is detected and rejected, never silently
  accepted.
- **G3 Forward secrecy: NOT provided per-object, by design.** A static object is a fixed ciphertext
  under a fixed `K`; anyone who later learns `K` (a leaked link, a compromised recipient key that
  unwraps `kw`) can decrypt it, exactly as [01-threat-model.md](01-threat-model.md) G3 states ("Feeds
  and static objects provide this only via key rotation, not per-message"). The only forward-secrecy
  analogue here is **rotation**: re-encrypt under a fresh `K'` (9.5 revocation) and retire the old
  swarm. Callers who need per-message forward secrecy should carry the object inside a forward-secret
  channel (mailbox or session), which wraps `K` under a ratcheted key (9.8).
- **G7 Sender anonymity (sealed manifests and drops).** A sealed `kw` uses `sxSeal`, a sealed box that
  hides the sender ([03-conventions.md](03-conventions.md) 3.3), so a mode-a manifest or a
  content-addressed drop reveals the object and its wrapped key to the intended recipient without
  revealing who sent it, unless the sender chooses to sign an enclosing record. A bare capability link
  carries no sender identity at all.

Non-goals and honest limits ([01-threat-model.md](01-threat-model.md)):

- **N2 Incomplete metadata privacy, and swarm membership is observable.** An object is a torrent, and
  a torrent has a swarm. Anyone can `get_peers(H)` and enumerate the IP addresses currently seeding or
  leeching an object; for a **popular** object this peer set is large and easy to observe (rung 3-4).
  The ciphertext and the plaintext stay secret (G1), but the fact that an id is being shared, and by
  which IPs, is public DHT/swarm metadata that Riptide does not hide here. A drop's address `addr` is
  likewise a public DHT key once known; keep it inside an encrypted mailbox/feed body if its existence
  must stay private (9.7). Rotation of `K` (and thus of `H`) per epoch or per share bounds cross-time
  linkage but does not make swarm membership unobservable.
- **N1 No IP anonymity by default.** Seeding or downloading an object exposes your IP to the swarm
  (rung 4) and your announce to the DHT (rung 3), like any BitTorrent transfer. Run over Tor/I2P or the
  multi-hop extension ([10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)) if this matters.
- **N6 Endpoint security assumed, and N5 key loss.** `K` and the plaintext live in script-managed
  memory once opened and cannot be locked or wiped by SodiumXT; a compromised endpoint exposes them. A
  lost recipient secret key cannot unwrap a sealed `kw`, and there is no recovery path (this is the
  point of a capability system, not a bug).

Summary against the rungs: confidentiality and integrity of an object's content hold from rung 1
through rung 4; a rung-3 DHT crawler and a rung-4 swarm insider learn that an object exists and who is
transferring it (N2, N1) but not what it contains. A global passive adversary (rung 5) is out of scope
([01-threat-model.md](01-threat-model.md) N3), as everywhere in Riptide.
