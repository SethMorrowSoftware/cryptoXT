# 06. Asynchronous mailbox (channel C1)

Store-and-forward 1:1 messaging with no server: the DHT is both the key directory
([02-identity.md](02-identity.md)) and the message queue. A sender who knows only your public
identity can drop a first, forward-secret message while you are offline; you scan a small window of
derived inbox ids, open it, and both sides run a light double ratchet so every later message has its
own key. This document defines only the mailbox; it reuses the foundation ([03-conventions.md](03-conventions.md))
verbatim and does not redefine any primitive, encoding, or the handshake.

This is the async, 1:1 counterpart to the live session of [05-session.md](05-session.md). The
handshake that turns a prekey bundle into a shared secret is defined once, in
[05-session.md](05-session.md); this document references it and never restates it.

## Registry additions

Nothing new is added to the constitution ([03-conventions.md](03-conventions.md)). The mailbox uses
only registered entries, listed here for auditability:

- **KDF label** `rp-ratch` (registry 3.4): master key = the mailbox chain key `K_n`, id = the message
  counter `n`, output 64 bytes, split `nextChainKey (32) || messageKey (32)`. Authoritative here.
- **Message types** (registry 3.6, mailbox range 0x10-0x1F): `0x10` message, `0x11` ack,
  `0x12` prekey-consume header. No values outside 0x10-0x1F are claimed.
- **Non-secret derivation tag** `rp-mbxid` (registry 3.4, the "derive from a public key with `sxHash`"
  rule): `inboxId(counter) = sxHash(recipientIK_x & be64(counter) & "rp-mbxid", 20)`. Defined at its
  point of use, as 3.4 requires, because the master here is a public key, not a 32-byte secret.

No new BEP44 salt is reserved: message and ack records live at unguessable **inbox ids**, not under a
named salt on the identity key. The only identity-keyed salt the mailbox reads is `rp-prekeys`
(the recipient's prekey bundle, doc 02). Notation is that of 3.11.

## 6.1 Inbox ids: derivation, scanning, rotation

A recipient does not have one inbox; they have a **counter-indexed sequence** of them. Each is a
20-byte DHT id derived from the recipient's identity X25519 public key `IK_x` (the box key from the
IdentityCard, doc 02) and a 64-bit counter, domain-separated with `rp-mbxid`:

```
inboxId(c) = sxHash(recipientIK_x || be64(c) || "rp-mbxid", 20)      -- c is a uint64, 20-byte DHT key
```

`recipientIK_x` is public, so this is a `sxHash` derivation, not `sxKdfDerive` (3.4). Because it takes
a public key, **anyone who knows the recipient's identity can compute the same ids**; that is the cost
of letting a stranger send a first message. Recipient privacy and spam are handled by k-anonymous
inboxes and the anti-abuse gate in [10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md), not
here.

**Counter semantics.** `c` is a per-recipient inbox slot, not a per-message ratchet index. One slot
holds one delivery (one BEP44 record). A sender who wants to place a message picks the lowest slot it
believes to be free (6.5); a recipient reads slots in order and advances a low-water mark.

**Scanning window.** The recipient keeps a persisted `base` (the lowest slot not yet reclaimed, doc
02's per-channel state) and scans a sliding window of `W` slots ahead of it:

```
for c in base .. base+W-1:
    r = DHT.get_immutable(inboxId(c))       or   DHT.get(inboxId(c) as publess mutable, no salt)
    if r present: enqueue(c, r)
advance base past the longest run of consecutively delivered-and-acked slots
```

- `W` defaults to `32`. It bounds both the number of `DHT.get` round-trips per poll and how far a
  sender may run ahead of the recipient before deliveries stop being found. A sender MUST NOT write to
  a slot more than `W-1` beyond the recipient's last observed low-water mark (6.5 explains how the
  sender estimates it); a message past the window is undeliverable until the recipient catches up.
- Scanning is **trial**: the recipient does not know which slots a sender used, only the contiguous
  range. A `DHT.get` miss is normal (an empty slot), not an error (error model 3.10: a missing record
  is a delivery gap, not an attack).
- Polling cadence is a client policy (for example every few minutes when foregrounded), traded against
  DHT load. Status-text updates stay at <= ~4 Hz (the single-threaded playbook in CLAUDE.md).

**Rotation.** The mailbox does not put an epoch inside `inboxId` (unlike rendezvous, doc 04): the
counter already advances the id every message, so two deliveries are already at unlinkable ids.
Linkage across the whole sequence is bounded by two moves:

1. **Reclaiming.** Once slot `c` is delivered and acked (6.6), the recipient advances `base` past it.
   Old ids fall out of the scan window and, on DHT churn, out of the DHT (forward-secrecy-by-forgetting,
   brainstorm 5); no tombstone is written.
2. **Rekey epoch (optional).** For a long-lived relationship, both sides MAY fold the epoch clock
   (3.9, coarse: mailboxes may pick a day-length `EPOCH_SECONDS`) into a rekey of the ratchet root, so
   the whole id sequence restarts under a fresh chain key on an epoch boundary. This is the DH-step
   option of 6.4 and reuses the session rekey (`0x23`) of [05-session.md](05-session.md); it is not
   required for correctness, only for stronger unlinkability and forward secrecy.

A rung-3 crawler ([01-threat-model.md](01-threat-model.md)) who knows the recipient's `IK_x` can
enumerate the window and see *that* slots are active; it cannot read them (G1) and, without the
sender's identity, cannot attribute them (G7). This is the N2 residual (metadata is reduced, not
eliminated), stated plainly.

## 6.2 The first message (Sealed): consuming a prekey

The first message from a new sender A to recipient B has no shared secret yet, so it is a **Sealed
envelope** (3.5, anonymous sender, G7) that carries two parts: a **prekey-consume header** (type
`0x12`) naming which of B's keys A used, and the **first ciphertext** (type `0x10`). Both are sealed to
B, so a DHT observer learns neither.

### 6.2.1 What A fetches and runs

1. A fetches B's prekey bundle: `DHT.get(IK_B, "rp-prekeys")`, the BEP44 mutable record of doc 02.4.
2. A verifies it: check `spk_sig` with `sxSignVerifyDetached(spk_sig, SPK_pub, IK_ed_B)`, check `exp`
   against the clock, and check `ik_ed`/`ik_x` against B's last-verified identity (doc 02.5, safety
   number or key-transparency log). A bundle that fails any check is refused (fail closed, 3.10); A does
   not send.
3. A **consumes one one-time prekey**: pick an unused `OPK_j = opks[j]` from the bundle. If `opks` is
   empty or A has already consumed all it holds, A falls back to **SPK only** (6.2.3).
4. A runs the **handshake of [05-session.md](05-session.md)** with inputs (B's `SPK`, the chosen
   `OPK_j`, B's identity keys, and a **fresh sender ephemeral** keypair `EK_A` from `sxBoxKeypair`) to
   agree the initial shared secret. That handshake, its exact DH combination, and the derivation of the
   mailbox chain key `K_0` from it via `rp-sess0` (registry 3.4) are defined there and MUST NOT be
   restated here. This document uses only its output: `K_0`, the chain key that seeds the ratchet (6.3).

### 6.2.2 The prekey-consume header and the first record

A builds the header naming exactly which keys it consumed, so B can pick the matching secret keys to
complete the same handshake:

```
Header = {
  v:  1,
  t:  0x12,                 -- prekey-consume
  ek: EK_A_pub,             -- 32 bytes, A's fresh handshake ephemeral public key
  sk: SPK_pub,              -- the signed prekey A used (echoed so B binds the right SPK)
  ok: OPK_j_pub  (omit if SPK-only fallback, 6.2.3)
}
```

The first ciphertext is the first ratchet message (counter `n = 0`), padded and encrypted under the
message key derived from `K_0` (6.3). The whole first delivery is one **Sealed envelope** whose plaintext
is the bencode of a dict carrying both parts:

```
FirstRecord = {
  v: 1,
  t: 0x10,                  -- message (the envelope's outer type; the header rides inside)
  h: bencode(Header),       -- the 0x12 prekey-consume header, bencoded
  c: sxAeadEncrypt(sxPad(m, 256), ad, messageKey_0)     -- the n=0 AEAD ciphertext (6.3)
}
where ad = bencode({ e: epoch, q: 0, t: 0x10 })         -- 3.5.1 binding, seq q = 0

Envelope = sxSeal( bencode(FirstRecord), IK_x_B )       -- 3.5 Sealed: anonymous sender, sealed to B's box key
```

Two layers, on purpose. The **inner AEAD** (`c`) is the ratchet message key, giving forward secrecy and
the `{e,q,t}` replay binding of 3.5.1. The **outer Seal** hides the sender (G7) and delivers the
handshake header confidentially, since only B's secret box key opens it. `sxSeal` draws and prepends its
own ephemeral and nonce (3.3 nonce discipline); A never chooses one.

A writes this at the lowest free inbox slot (6.5):

```
DHT.put_immutable( inboxId(c_first), Envelope )         -- one-shot first message, immutable (6.5)
```

### 6.2.3 No-OPK fallback (SPK only)

If the bundle's `opks` is empty (B has not replenished, doc 02.7), A omits `ok` from the Header and runs
the handshake with **SPK only**. The handshake of [05-session.md](05-session.md) defines the reduced DH
combination; the only mailbox-visible differences are: `ok` is absent, and B, on open, sees no `ok` and
completes the SPK-only handshake. The property lost is the one-time-key guarantee: an attacker who later
compromises B's medium-term `SPK` secret (before it rotates) can compute `K_0` for SPK-only first
messages, whereas an OPK is deleted on first use and cannot be recomputed. Per-message forward secrecy
from the ratchet (6.3) still holds for every message after the first. Clients SHOULD keep `opks`
replenished (doc 02.7) so the fallback is rare.

### 6.2.4 B opens the first message

```
1. B scans (6.1), gets Envelope at inboxId(c_first).
2. FirstRecord = sxUnpad-free... no:  plain = sxSealOpen(Envelope, IK_x_B_pub, IK_x_B_sec)   -- fails closed on tamper
3. FirstRecord = bencode-decode(plain);  Header = bencode-decode(FirstRecord.h)
4. B looks up the secret keys named by Header.sk / Header.ok (its stored SPK_sec and OPK_j_sec).
   If Header.ok is present but B has already consumed OPK_j (replay of a first message), B treats the
   OPK as spent: it still holds the secret until it is sure no honest delivery needs it, but a second
   distinct handshake on the same OPK is refused (one OPK, one sender; 3.10 replay).
5. B runs the same handshake (05-session.md) with (SPK_sec, OPK_j_sec or none, Header.ek) -> K_0.
6. B derives messageKey_0 (6.3) and mp = sxAeadDecrypt(FirstRecord.c, ad, messageKey_0),
   with ad = bencode({e: epoch, q: 0, t: 0x10}).  Fails closed (3.10) on wrong key or tamper.
7. m = sxUnpad(mp, 256).  B initializes its receive ratchet state at n = 1 (6.3), records the sender
   (recovered from the handshake, 05-session.md), and sends an ack (6.6).
```

B **deletes `OPK_j_sec` after step 5** so it can never be reused (doc 02.7; one-time means one time).

## 6.3 The double-ratchet-lite

After the handshake, both sides hold the initial chain key `K_0`. Every message advances the chain and
yields a fresh message key, so compromising one message key does not expose the others (G3, per-message
forward secrecy).

**The ratchet step.** For message counter `n` (`n = 0` is the first ciphertext inside the FirstRecord;
`n >= 1` are subsequent AEAD envelopes):

```
kdfOut          = sxKdfDerive(K_n, "<n>", "rp-ratch", 64)    -- 64 bytes; id is n as decimal String
nextChainKey    = first 32 bytes of kdfOut         -- becomes K_{n+1}
messageKey_n    = last  32 bytes of kdfOut          -- used once, for message n, then discarded
```

`rp-ratch` is the registered label (3.4); `<n>` is `n` rendered as a decimal string because `sxKdfDerive`
takes its id as a decimal `String` (api-reference; there is no 64-bit foreign int, CLAUDE.md). Output is
exactly 64 bytes (crypto_kdf allows 16..64, 3.3), split high-32 chain / low-32 message. After deriving,
the sender **discards `K_n`** and keeps only `K_{n+1}`; the receiver does the same once it has accepted
message `n`. Neither side ever stores a message key after using it.

**Encrypting message n (n >= 1).** A subsequent message is a plain **AEAD envelope** (3.5), not Sealed,
because both sides now share the chain:

```
ad  = bencode({ e: epoch, q: n, t: 0x10 })                  -- 3.5.1 binding: epoch, seq = n, type message
Rec = {
  v: 1,
  t: 0x10,
  q: n,                                                      -- the counter, advertised in cleartext (see below)
  c: sxAeadEncrypt(sxPad(m, 256), ad, messageKey_n)
}
DHT.put ...  at inboxId(c_slot)  (6.5)
```

**Advertising n and staying in sync.** The message key for `n` cannot be derived without `n`, so the
receiver must learn `n`. Two facts carry it, redundantly:

- **In cleartext, `Rec.q = n`.** This is not secret (the epoch/seq are already public metadata, 3.5.1)
  and it lets the receiver select the right ratchet target directly. It is **not trusted**: the value is
  also bound into `ad`, so a tampered `q` makes `sxAeadDecrypt` fail closed (the ad no longer matches).
  `q` is a hint that the AEAD verifies.
- **Implicitly, by the chain.** Because every step is deterministic from `K_0`, the receiver can also
  advance its own chain and match; `Rec.q` just spares it from guessing across a gap.

The receiver keeps `(K_recv, n_recv)` = (its current chain key, the next counter it expects). On a record
with advertised counter `q`:

```
if q == n_recv:        derive messageKey_{n_recv}, decrypt, on success ratchet K_recv forward, n_recv += 1
if q  > n_recv:        a gap (out-of-order / skipped): see below
if q  < n_recv:        already accepted -> replay, drop (3.10, replay dropped by seq)
```

**Out-of-order and gap handling.** DHT records are not guaranteed to appear in order, and a slot may be
missing when scanned. When the receiver sees `q > n_recv` (or scans slots out of order), it must derive
the message keys for the skipped counters `n_recv .. q-1` **without decrypting them yet** (their records
have not arrived), then decrypt `q`. It does this with a **skipped-message-key cache**:

```
while n_recv < q:
    (K_recv, mk) = ratchet(K_recv, n_recv)     -- rp-ratch step
    cache[n_recv] = mk                          -- store the message key for the not-yet-seen message
    n_recv += 1
(K_recv, mk_q) = ratchet(K_recv, q); decrypt q with mk_q; n_recv = q+1
```

When a delayed record for a cached counter `k` later arrives, the receiver decrypts it with `cache[k]`,
verifies (fails closed on tamper), then **erases `cache[k]`**. The cache is bounded: a client caps it at
`MAX_SKIP` (default `256`, comfortably above the scan window `W`) skipped keys and refuses to ratchet
further ahead than that, so a sender cannot force unbounded key derivation by advertising a huge `q`
(a denial-of-service guard; a `q` beyond `n_recv + MAX_SKIP` is dropped and surfaced, 3.10). Cached keys
are secret material and are zeroed when erased or when the channel is closed (CLAUDE.md secret hygiene;
honest limit: a `Data` in script cannot be reliably wiped, N6).

**Symmetry.** Each direction is an independent chain. A and B each keep a **send chain** and a **receive
chain**; A's send chain is B's receive chain and vice versa. The counters are per-direction. The first
message seeds both sides' chains from the single handshake `K_0` (05-session.md defines how the two
directional roots split, mirroring the session's `rp-txrx0` in registry 3.4); a client MUST NOT let the
two directions collide on one chain (that would reuse a message key, catastrophic, rule 3 of CLAUDE.md).

**Option: a DH step per round for stronger forward secrecy.** The scheme above is a **symmetric-key**
ratchet: it gives forward secrecy (old keys are discarded) but not **post-compromise recovery** (an
attacker who learns the current `K_recv` can compute all future keys until a fresh secret is injected).
To add post-compromise security, both sides periodically inject a new Diffie-Hellman output into the
chain, exactly as the session rekey (`0x23`) of [05-session.md](05-session.md) does: each party attaches
a fresh ephemeral X25519 public key to a message, and the new chain root becomes
`sxKdfDerive` of the current root mixed with the fresh `sxBox`/kx shared secret (the exact mixing is the
rekey of doc 05, not restated here). This is optional for the mailbox (it costs an extra 32-byte field
per rekey and a key agreement) and is the same mechanism as the rekey-epoch rotation of 6.1; a client
that wants Signal-grade forward secrecy turns it on, a client that wants minimal records leaves it off
and relies on the symmetric ratchet plus periodic full re-handshake.

## 6.4 Storing envelopes as BEP44 records

Each mailbox delivery is one DHT record at an inbox id (6.1). Two record shapes, chosen by role:

- **Immutable (BEP44 immutable, sxHash-addressed, 3.7).** Used for the **first message** and for any
  strictly **one-shot** delivery: the value is self-contained (a Sealed envelope), it is never updated,
  and its address is the inbox id. Immutable records are simplest and carry no signature or seq. The
  first message (6.2) is immutable: A has no shared key with B yet, so it cannot sign as B and would not
  want to sign as itself (G7, sender anonymity).

  ```
  DHT.put_immutable( inboxId(c), Envelope )          -- Envelope = the Sealed bytes; id must equal the value's hash per BEP44 immutable rule
  ```

  Note: BEP44 immutable items are addressed by `sxHash`-of-value in BEP44's own scheme, whereas the
  inbox id is derived from the recipient key. Riptide reconciles this by storing the envelope as an
  **immutable value whose retrieval key is the inbox id via Riptide's relay convention** (doc 11's
  `DHT.put_immutable(id, v)`), or, on the vanilla mainline DHT where an immutable item's key is fixed by
  BEP44 to be the hash of its value, by using the **mutable** form below at the inbox id. A client that
  must interoperate with the unmodified mainline DHT therefore SHOULD prefer the mutable form for all
  mailbox slots and reserve true immutables for object drops (doc 09), whose address genuinely is the
  content hash. The mutable form is the portable default.

- **Mutable (BEP44 mutable, salt-less, monotonic seq, 3.7).** The portable default for every slot,
  including the first. The record is keyed by a throwaway ed25519 key the **sender** owns for that slot
  (not B's identity key, since A cannot sign as B), placed so that the DHT location resolves to the
  inbox id; `seq` is monotonic so an update (for example a re-put after churn, brainstorm 8) is accepted
  and a stale copy rejected (G4, BEP44 monotonic seq). The signed buffer is exactly BEP44's
  (`4:salt` omitted when salt is empty, `3:seqi<seq>e`, `1:v` + value), signed with
  `sxSignDetached(bep44SignBuf, slotKey_sec)` (3.7).

  ```
  DHT.put( slotPub, salt="" , seq, v = Envelope, sig )       -- 3.7 mutable put; slotPub is the sender's per-slot key
  ```

  Because the DHT does not enforce who may write a given id (3.7), inbox writability is treated as open
  and defended at the application layer (anti-abuse, doc 10). Monotonic `seq` gives replace-on-republish
  without a second slot; the ratchet counter `n` (6.3) is independent of the BEP44 `seq` (the record's
  `seq` counts re-puts of one delivery; `n` counts messages).

Both shapes stay inside the ~1000-byte BEP44 budget because plaintext is padded to `B = 256` (3.5.2) and
the envelope overhead (Seal 48, or AEAD nonce 24 + tag 16, plus bencode framing) is small. A message
whose padded envelope would exceed one record MUST NOT be split across slots; it overflows to an object
(6.7).

## 6.5 Slot selection and delivery retry

**Choosing a slot (sender).** A tracks, per recipient, the next slot it will use (`c_next`, persisted).
To place a message it:

```
1. c = c_next
2. probe: r = DHT.get(inboxId(c))       -- is the slot already taken (by our own earlier put, or a race)?
3. if r present and not ours: c += 1, goto 2   (skip a collided slot; rare, bounded by W)
4. put the Envelope at inboxId(c); c_next = c + 1
```

The probe is best-effort; two senders to the same recipient share the id space, so slot collisions are
possible (two strangers messaging B). A collision is resolved by advancing to the next free slot, and the
receiver's contiguous scan (6.1) tolerates the resulting sparseness. The sender MUST keep `c` within
`W-1` of its estimate of B's low-water mark; B advertises its low-water mark implicitly (the highest slot
it has acked, 6.6) so an ongoing correspondent stays in range, and a brand-new sender starts at a slot
derived from the epoch to avoid always colliding at `c = 0` (client policy; a fresh sender MAY start at
`c = 0` and accept early-slot contention, which the anti-abuse gate of doc 10 also rate-limits).

**Delivery retry vs. the availability non-goal (N7).** The mailbox favors confidentiality and integrity
over guaranteed delivery ([01-threat-model.md](01-threat-model.md), N7). Delivery is therefore
**best-effort with bounded retry, never a fallback to an unauthenticated path** (3.10):

- **Republish against churn.** DHT records expire; the sender re-puts the same Envelope (mutable form,
  incremented `seq`) periodically until it observes an ack (6.6) or gives up after a client-set deadline.
  Re-put uses the same inbox id and the same ciphertext (the message key is fixed by `n`), so re-puts are
  idempotent at the recipient (the receiver's replay guard, 3.10, drops the duplicate after the first
  accept).
- **No delivery guarantee.** If the recipient never comes online, or a rung-3 Sybil eclipses the inbox id
  ([01-threat-model.md](01-threat-model.md), G5 limit), the message is simply not delivered; the sender
  surfaces a delivery failure to retry or report (3.10), and does not weaken the crypto to force it
  through. Redundancy (writing to more than one nearby slot) and rotation raise the cost of eclipse but
  do not defeat a determined rung-3 adversary (N7 residual).
- **Acks close the loop.** Absence of an ack after the deadline is reported to the user as "not
  confirmed delivered," never silently treated as success.

## 6.6 Acknowledgements (type 0x11)

An ack lets the sender stop republishing and lets the recipient advance its low-water mark. An ack is a
tiny message on the **reverse chain** (B -> A), so it is itself a normal ratchet message with type `0x11`:

```
ad  = bencode({ e: epoch, q: n_ack, t: 0x11 })              -- 3.5.1 binding on the reverse direction's counter
Ack = {
  v: 1,
  t: 0x11,
  a: n,                                                      -- the counter (A's send-chain n) being acknowledged
  c: sxAeadEncrypt(sxPad(0-length or a status byte, 256), ad, reverseMessageKey_{n_ack})
}
put Ack at inboxId(c) on A's inbox (B writes to A exactly as A wrote to B)
```

The ack is authenticated (AEAD, G2) and forward-secret (its own message key), so an observer cannot forge
an ack to make A stop retrying, and cannot read which message was acked (`a` is inside the ciphertext,
carried as content, not in the public `ad`). A, on opening the ack, matches `a` to its outstanding
message and stops republishing that slot; it also learns B's progress (B only acks what it decrypted,
which advances B's low-water mark and lets A safely advance `c` for the next message within `W`). Acks
are optional-to-send but cheap; a client MAY batch one ack that carries the highest contiguous `n` it has
accepted (cumulative ack), which the reverse chain's ordering supports.

If A is offline when B acks, B stores the ack at A's inbox like any message; A picks it up on its next
scan. Acks are subject to the same N7 best-effort delivery as messages (an un-delivered ack just means A
keeps republishing until its deadline).

## 6.7 Size limit and overflow to an object

A single BEP44 record is ~1000 bytes (3.7), and after padding to `B = 256` and envelope overhead the
in-band plaintext budget is a few hundred bytes: fine for text, not for a photo. A message whose padded
ciphertext would not fit one record MUST overflow to an **object** ([09-objects.md](09-objects.md))
rather than being fragmented across inbox slots (fragmentation would multiply DHT puts, leak the size in
the slot count, and lose the single-record replay binding):

```
1. A encrypts the large payload as an object per 09-objects.md
   (sxEncryptFile / secretstream to a torrent or immutable cell; the object carries its own key K).
2. A sends a normal mailbox message (0x10) whose plaintext is a small object reference:
   a bencode dict { ref: <object id / infohash>, k: <wrapped K>, n: <size>, ... } as defined in 09.
3. B opens the mailbox message, then fetches and decrypts the object out of band (09), off the DHT
   record path.
```

The mailbox thus stays a **signaling and pointer** layer (brainstorm 8): small, forward-secret control
messages in the DHT; bulk bytes in the swarm. The object's own key `K` is wrapped for B by the ratchet
message that references it, so possession of the reference implies the right to open the object. Exact
object formats, chunk keys (type `0x50`/`0x51`, registry 3.6), and the wrapping live in
[09-objects.md](09-objects.md) and are not restated here.

## 6.8 Sender anonymity vs. authenticated sender

The mailbox offers both, selected by which envelope the sender uses:

- **Anonymous sender (Sealed, G7).** The default for a **first** message (6.2) and for any message where
  the sender wants deniable, unattributed delivery: the outer envelope is `sxSeal` (3.5), which reveals
  nothing about the sender, even to the recipient, beyond what the handshake or the message body chooses
  to disclose. The recipient learns the sender's identity only from the handshake keys (which A chose to
  present) or from signed content A put inside the plaintext. This is G7 in [01-threat-model.md](01-threat-model.md).
- **Authenticated sender (Boxed).** Once A and B share a chain, subsequent messages are AEAD envelopes
  keyed by the ratchet, which already authenticate A **to B** (only the two chain holders can produce a
  valid tag, G2) without revealing A to the network. If A additionally wants **cryptographic
  non-repudiation** (B can prove to a third party that A said it), A includes an `sxSignDetached`
  signature over the plaintext inside the padded message, or uses the **Boxed envelope** (`sxBox`, 3.5)
  for the first message instead of Sealed, trading G7 for a sender-authenticated first contact. That is a
  deliberate downgrade of anonymity and is never the default.

Recipient privacy (hiding *which* recipient a slot addresses) and spam resistance on these
publicly-derivable inbox ids are **not** solved here. They are the job of **k-anonymous inboxes** (a set
of recipients share a bucket prefix and all trial-decrypt; sealed-box auth means only the intended one
opens) and the **anti-spam gate** (proof-of-work or capability tokens bound to inbox+epoch, checked before
spending effort trial-decrypting), both defined in
[10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md). This document assumes those layers sit
underneath it.

## 6.9 End-to-end flows (exact calls and record bencode)

Notation is 3.11. `IK_x_B` is B's identity box public key; `IK_x_B_sec` its secret. All bencode is
canonical (3.2, keys sorted by raw byte). Epoch `e` is the coarse mailbox epoch (3.9).

### Flow 1: first message (A -> B, OPK available)

```
A side:
 1.  bundle = DHT.get(IK_ed_B, "rp-prekeys")                              -- BEP44 mutable, doc 02.4
 2.  assert sxSignVerifyDetached(bundle.spk_sig, bundle.spk, IK_ed_B)     -- fail closed on false (3.10)
 3.  assert bundle.exp >= now  and  bundle matches B's verified identity  -- doc 02.5
 4.  OPK_j = bundle.opks[j]        (pick an unused index j)               -- consume one-time prekey
 5.  sxBoxKeypair EK_A_pub, EK_A_sec                                       -- fresh handshake ephemeral
 6.  K_0 = handshake(SPK=bundle.spk, OPK=OPK_j, IK_x_B, EK_A_sec)          -- defined in 05-session.md
 7.  (K_1, mk_0) = split( sxKdfDerive(K_0, "0", "rp-ratch", 64) )          -- 6.3 ratchet, n=0
 8.  ad = bencode({ e: e, q: 0, t: 16 })                                   -- 3.5.1 (0x10 = 16 dec)
 9.  Header = { ek: EK_A_pub, ok: OPK_j, sk: bundle.spk, t: 18, v: 1 }     -- 0x12 = 18 dec
10.  FirstRecord = { c: sxAeadEncrypt(sxPad(m,256), ad, mk_0),
                     h: bencode(Header), t: 16, v: 1 }
11.  Env = sxSeal( bencode(FirstRecord), IK_x_B )                          -- 3.5 Sealed (G7)
12.  c = next free slot (6.5); DHT.put at inboxId(c) with Env             -- mutable form (6.4), seq=1

B side:
13.  scan window (6.1); at inboxId(c): Env = DHT.get(...).v
14.  FirstRecord = bdecode( sxSealOpen(Env, IK_x_B_pub, IK_x_B_sec) )      -- fails closed (3.10)
15.  Header = bdecode(FirstRecord.h);  look up SPK_sec, OPK_j_sec by Header.sk/Header.ok
16.  refuse if OPK_j already consumed (replay of a first msg, 3.10)
17.  K_0 = handshake(SPK_sec, OPK_j_sec, Header.ek, IK_x_B_sec)            -- same shared secret (05)
18.  delete OPK_j_sec                                                       -- one-time (doc 02.7)
19.  (K_1, mk_0) = split( sxKdfDerive(K_0, "0", "rp-ratch", 64) )
20.  ad = bencode({ e: e, q: 0, t: 16 })
21.  m = sxUnpad( sxAeadDecrypt(FirstRecord.c, ad, mk_0), 256 )            -- fails closed (3.10)
22.  set receive chain (K_recv = K_1, n_recv = 1); send ack (Flow 3)
```

### Flow 2: subsequent message (A -> B, n >= 1)

```
A side (send chain at (K_send, n)):
 1.  (K_next, mk_n) = split( sxKdfDerive(K_send, "<n>", "rp-ratch", 64) )
 2.  ad  = bencode({ e: e, q: n, t: 16 })
 3.  Rec = { c: sxAeadEncrypt(sxPad(m,256), ad, mk_n), q: n, t: 16, v: 1 }
 4.  c = next free slot (6.5); DHT.put at inboxId(c) with Rec (mutable)
 5.  K_send = K_next; n += 1;  republish until acked or deadline (6.5, N7)

B side (receive chain at (K_recv, n_recv)):
 6.  scan; at some inboxId(c): Rec = DHT.get(...).v ; q = Rec.q
 7.  if q < n_recv: drop (replay, 3.10).  if q > n_recv + MAX_SKIP: drop+surface.
 8.  while n_recv < q: (K_recv, mk) = ratchet(K_recv, n_recv); cache[n_recv]=mk; n_recv+=1
 9.  (K_recv, mk_q) = ratchet(K_recv, q)                                   -- or mk_q = cache[q] if delayed
10.  ad = bencode({ e: e, q: q, t: 16 })
11.  m = sxUnpad( sxAeadDecrypt(Rec.c, ad, mk_q), 256 )                    -- fails closed (3.10)
12.  n_recv = max(n_recv, q+1); erase cache[q]; send ack (Flow 3)
```

### Flow 3: ack (B -> A, on B's reverse send chain at counter na)

```
B side:
 1.  (K_rev_next, mk_na) = split( sxKdfDerive(K_rev, "<na>", "rp-ratch", 64) )
 2.  ad  = bencode({ e: e, q: na, t: 17 })                                 -- 0x11 = 17 dec
 3.  Ack = { a: n_acked, c: sxAeadEncrypt(sxPad(<status>,256), ad, mk_na), t: 17, v: 1 }
 4.  put Ack at a free slot on A's inbox (inboxId over IK_x_A); K_rev=K_rev_next; na+=1
A side:
 5.  scan A's own inbox; open Ack (reverse receive chain), read Ack.a
 6.  stop republishing message n = Ack.a; advance send-side low-water mark
```

## 6.10 Security properties

Mapping to the goals and non-goals of [01-threat-model.md](01-threat-model.md), with adversary rungs.

- **G1 Confidentiality (rungs 1-4).** Every mailbox record is authenticated encryption: the first message
  is a Sealed box to B's box key (`sxSeal`); every later message is AEAD under a single-use ratchet
  message key. A passive observer (rung 1), a censor (rung 2), a DHT Sybil (rung 3), and a swarm insider
  (rung 4) all see only ciphertext and unguessable-from-the-outside 20-byte ids. There is no
  unauthenticated mode (principle 1).
- **G2 Integrity and authenticity (rungs 1-4).** The inner AEAD tag (Poly1305) and the Seal MAC reject
  any tamper, failing closed (3.10). Once a chain is shared, a valid tag proves the message came from the
  chain holder (sender-to-recipient authentication) without a network-visible signature. Optional
  `sxSignDetached` inside the plaintext adds third-party non-repudiation (6.8).
- **G3 Forward secrecy (rungs 1-4).** The `rp-ratch` symmetric ratchet discards each message key and each
  spent chain key, so compromising B's state at message `n` does not decrypt messages `< n`. The first
  message adds a one-time prekey (deleted on use) so a later `SPK` compromise does not retroactively open
  it (the SPK-only fallback, 6.2.3, weakens this for the first message only). The optional per-round DH
  step (6.4) adds post-compromise recovery (Signal-grade), which the pure symmetric ratchet does not
  provide; that limit is stated, not hidden.
- **G4 Replay and reorder resistance (rungs 1-4).** `ad = bencode({e,q,t})` binds every AEAD envelope to
  its epoch, counter, and type (3.5.1): a captured record replayed into another slot, epoch, or counter
  fails to open. Within a channel, the receiver drops any `q` at or below its low-water mark (3.10,
  replay dropped by seq), and BEP44 monotonic `seq` (6.4) rejects a stale re-put. A first-message replay
  is refused by the one-time-prekey consumption check (6.2.4).
- **G7 Sender anonymity (rungs 1-4).** The Sealed first message reveals nothing about the sender to the
  DHT or, cryptographically, to the recipient beyond what the sender chose to present in the handshake
  or body. A sender who wants attribution opts into a signature or a Boxed envelope (6.8); anonymity is
  the default, not an afterthought.
- **N1 No IP anonymity by default.** The DHT `put`/`get` reveal the sender's and recipient's IP to DHT
  nodes and any rung-3/rung-4 observer of those nodes. The mailbox does nothing to hide this; run over
  Tor/I2P or the multi-hop extension ([10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)).
- **N2 Incomplete metadata privacy.** A rung-3 crawler that knows B's `IK_x` can enumerate `inboxId(c)`
  over the scan window and see *that* slots are active and when, and can see *that* B is being messaged
  (though not by whom, G7, nor what, G1). Counter rotation, reclaiming, k-anonymous inboxes, and cover
  traffic (doc 10) reduce this; they do not eliminate it. Slot activity and timing remain observable to
  a determined rung-3 adversary.
- **N7 Availability is best-effort.** Delivery depends on DHT persistence and the recipient coming
  online. Republication (6.5) fights churn; it does not defeat a rung-3 eclipse of an inbox id (G5
  limit) or a recipient who never returns. A missing record is a retryable delivery failure, never a
  reason to weaken the crypto (3.10). Acks make non-delivery visible ("not confirmed") rather than
  silently assumed.

Recipient privacy and open-inbox spam are out of scope here and handled underneath, in
[10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md).
