# 08. Group rooms

Channel **C5** from [../brainstorm.md](../brainstorm.md): a shared encrypted room for N members, with
no central room server. Many-to-many, on the same identity and conventions as every other channel.

A group room is the hardest channel to get right, because two things that are cheap for a pairwise
channel become expensive at N members: **membership churn** (adding and removing members means
rekeying) and **forward secrecy** (a leaked long-term key should not decrypt future traffic). This
document specifies a concrete, buildable baseline for **small static rooms** and is honest that the
efficient large-group case is an MLS-class open problem, deferred to [13-open-questions.md](13-open-questions.md).

Everything here obeys the constitution ([03-conventions.md](03-conventions.md)): canonical bencode
(3.2), the KDF label registry (3.4), the envelope and associated-data rules (3.5), nonce discipline
(3.3), the message-type registry (3.6), the epoch clock (3.9), and the error model (3.10). Rendezvous
uses [04-rendezvous.md](04-rendezvous.md); the mailbox that carries room-key distribution and control
messages is [06-mailbox.md](06-mailbox.md); the live transport is BEP10 `rp1` (3.8) with BEP11 PEX
gossip.

## Registry additions

No new KDF label and no new message type are introduced here. This channel uses only what the
constitution already reserves:

- **KDF label** `rp-sendr` (3.4): master key = room key `R`, id = member index, output 32 bytes.
  Already registered. Used for per-member sender keys (8.3).
- **Message types** in the groups range 0x40-0x4F (3.6): `0x40` group-message, `0x41` member-add,
  `0x42` member-remove. Already reserved. `0x43-0x4F` remain free for future group control messages
  (a tree-based rekey path, 8.7, would claim some).

One convention is fixed here for the whole channel and stated once so it is not reinvented per flow:

- **Room rendezvous label.** The rotating room DHT id is derived per [04-rendezvous.md](04-rendezvous.md)
  from the room key `R` and the epoch, using the `rp-rndzv` label of 3.4 with `R` as the shared
  secret. See 8.2 for the exact call.
- **Padding block size.** Group messages carried over the peer wire pad to `B = 1024` (3.5.2, the
  peer-wire bucket); control messages carried in a mailbox record pad to `B = 256` (the DHT-record
  bucket). Both are the constitution defaults, restated so the flows below can cite them.

## 8.1 What a room is

A room is defined by exactly one secret and an ordered member list:

- **Room key `R`:** a 32-byte secret, `sxRandomBytes(32)`, generated once by the room creator. `R` is
  the root of everything: the rendezvous id, every sender key, and the epoch rotation all derive from
  it. `R` is a shared group secret, not a per-member key; its confidentiality is the room's
  confidentiality.
- **Member roster:** an ordered list of member identity keys `[IK_0, IK_1, ... IK_{n-1}]`. A member's
  position in this list is their **member index** `i` (a `uint64`, starting at 0), and that index is
  the id fed to `sxKdfDerive` to make their sender key (8.3). The roster is versioned by an **epoch
  counter** `g` (the group generation, distinct from the wall-clock rendezvous epoch of 3.9); every
  add or remove bumps `g` and produces a fresh `R` (8.5, 8.6).

The tuple a client persists per room is `{ roomId, g, R, roster, myIndex, highestSeq[] }`, where
`highestSeq[]` is the per-sender replay high-water mark of 8.4. `roomId` is a stable local label
(for example `sxBin2Base64(sxHash(R_0 & "rp-room0", 16))` computed from the founding room key) so the
room keeps one name across rekeys even as `R` and `g` change.

The baseline targets **small, static rooms** (single digits to low tens of members). It is honest
about not scaling to large dynamic groups; see 8.7 and [13-open-questions.md](13-open-questions.md).

## 8.2 Establishing a room

There are two ways `R` reaches the members, and a room may use either.

**(a) Out of band.** The creator shares `R` (and the roster, `g = 0`, and `EPOCH_SECONDS`) with each
member over an already-trusted channel: in person as a QR code, or over an authenticated side band.
This is the simplest path and matches how a small trusted group actually forms.

**(b) Pairwise via the mailbox.** The creator sends each member a `member-add` control message
(type `0x41`, 8.5) through that member's mailbox ([06-mailbox.md](06-mailbox.md)). Because the mailbox
message is a sealed or boxed envelope to that member's identity key, `R` is delivered confidentially
and (in the boxed form) authenticated as coming from the creator. This is the path used for every
subsequent add as well, so establishment and growth share one mechanism.

Either way, first-contact key authenticity for each member is verified per [02-identity.md](02-identity.md)
(safety numbers or the key-transparency log) before that member is trusted with `R`. Handing `R` to a
key you have not verified hands the room to whoever holds that key.

### Room rendezvous id

All members meet at a rotating DHT id derived from `R` and the wall-clock epoch (3.9), exactly as
[04-rendezvous.md](04-rendezvous.md) defines for a shared secret, using the `rp-rndzv` label (3.4):

```
epoch  = floor(unixTimeSeconds / EPOCH_SECONDS)          -- 3.9, default 3600
roomId = sxKdfDerive(R, str(epoch), "rp-rndzv", 20)      -- 20-byte DHT id, per 04
```

`sxKdfDerive`'s id argument (`pSubkeyId`) crosses as a decimal string (3.3 / API), hence `str(epoch)`.
The 20-byte output matches the mainline DHT keyspace (BEP5). Because the epoch rotates hourly, the
meeting point moves hourly and a passive DHT crawler cannot link two epochs of the same room
(principle 4). Members check the adjacent epochs (`epoch-1`, `epoch+1`) for clock drift, per 3.9.

The rendezvous id depends on `R`, so a rekey (8.5, 8.6) that changes `R` also **moves the room** to a
new set of ids. A removed member, who no longer holds the new `R`, cannot even compute where the room
went, let alone read it. That is the mechanism behind the post-removal secrecy claim of 8.6.

Flow 1 (join a room, per epoch):

```
1. Compute roomId = sxKdfDerive(R, str(epoch), "rp-rndzv", 20).
2. DHT.announce(roomId)                          -- publish "I am here" (BEP5 announce_peer)
3. DHT.getPeers(roomId)  -> peer list            -- learn other members' IP:port (BEP5 get_peers)
4. For each peer, open a BEP10 connection and advertise the rp1 extension (3.8).
5. Once rp1 is negotiated, exchange BEP11 PEX (8.4) so the mesh fills in members not seen via the DHT.
```

## 8.3 Per-member sender keys

Each member has a **sender key** derived deterministically from the room key and their member index:

```
SK_i = sxKdfDerive(R, str(i), "rp-sendr", 32)            -- 32-byte per-member key, label rp-sendr (3.4)
```

Every member can compute **every** member's sender key, because every member holds `R` and knows the
roster (hence each index `i`). That is the point: `SK_i` is not a secret between member `i` and the
group, it is a **domain-separated symmetric key that only member `i` sends under**. When member `i`
encrypts a message with `SK_i` and binds `i` into the associated data (8.4), every recipient can
decrypt it (they can derive `SK_i`) and every recipient knows it could only have been produced by
someone holding `R` who claims index `i`. Within an honest room where each member guards `R`, that is
per-sender authentication: a valid AEAD tag under `SK_i` with `i` bound in says "member `i` sent
this."

**What this authentication is and is not.** Sender-key authentication is **intra-group**: it
distinguishes member `i` from member `j` to the other members, because in normal operation each member
only ever sends under their own index. It is **not** a proof to an outsider, and it is **repudiable
inside the group**: any member holds `R`, can derive `SK_j`, and could forge a message that appears to
come from member `j`. This is a deliberate deniability property (no member can prove to a third party
that another member said a specific thing), and it is the same trade-off group messengers make with
symmetric sender keys. If the room needs stronger guarantees, see the ed25519 option below.

**Optional cross-member non-repudiation (ed25519).** A sender may additionally sign the plaintext (or,
better, the ciphertext and its AD) with their identity key:

```
s = sxSignDetached(c & ad, IK_sec_i)                     -- detached ed25519 signature
```

carried in an `s` field of the message dict (8.4). A recipient verifies with
`sxSignVerifyDetached(s, c & ad, IK_pub_i)`. This upgrades intra-group authentication to
**cryptographic non-repudiation**: now member `j` cannot forge member `i`'s messages (they lack
`IK_sec_i`), and a recipient can prove to a third party that `i` signed. **The cost is the loss of
deniability**: a signed message is a portable, transferable proof that `i` said it, which is exactly
what a deniable messenger tries to avoid. The room chooses at establishment (a room policy flag,
distributed with `R`): default is **unsigned** (deniable, sender-key auth only); a room that values
accountability over deniability turns signing on. Do not mix modes within a room, or a recipient
cannot know whether an unsigned message from `i` is genuine or a peer's forgery.

Sender keys are **not forward-secret within a generation**: `SK_i` is fixed for the life of `R`, so
every message member `i` sends in generation `g` uses the same key (with per-message nonces, never
reused; see 8.4). Forward secrecy for groups comes only from **rekeying** (8.5, 8.6), which is
coarse-grained (per membership change), not per message. This limitation is stated plainly in 8.8 and
is the crux of the open problem in 8.7.

## 8.4 The group message (type 0x40)

A group message is an **AEAD envelope** (3.5) sealed under the sender's sender key, with the sender's
member index and a per-sender sequence number bound into the associated data so a captured ciphertext
cannot be replayed or attributed to another member.

### Associated data

Per 3.5.1 the AD is the canonical bencode of a small sorted dict `{e, q, t}`, and this channel binds
the **member index** in as well. The extended AD for a group message is:

```
ad = bencode({ e: epoch, i: senderIndex, q: seq, t: 0x40 })
```

Keys sorted lexicographically by raw byte value (3.2): `e < i < q < t`. `e` is the wall-clock epoch
(3.9), `i` is the sender's member index (8.1), `q` is that sender's per-sender monotonic sequence
number, `t` is the type (`0x40`). Binding `i` into the AD is what ties the ciphertext to the sender
key that must have produced it: a decrypt under `SK_i` that supplies a different `i`, `q`, `e`, or `t`
fails authentication (3.10, fail closed). It also stops a **key-confusion** attack where a message
sealed under `SK_i` is replayed and claimed to be from `j`.

### Ciphertext and message dict

```
c = sxAeadEncrypt(sxPad(m, 1024), ad, SK_i)              -- XChaCha20-Poly1305 IETF, nonce prepended (3.3)
```

`sxPad(m, 1024)` pads the plaintext to the peer-wire bucket (3.5.2) so ciphertext length stops leaking
message length. `sxAeadEncrypt` draws and prepends a fresh random 24-byte nonce (3.3); Riptide never
chooses a nonce, and the room MUST NOT reuse a nonce with `SK_i` (the prepend-random discipline makes
reuse a 2^-96-ish accident, acceptable for the message volumes a small room produces; a room that
would send billions of messages under one generation should rekey before that bound, 8.7).

The wire message is the canonical bencode of:

```
GroupMessage = {
  v: 1,                 -- protocol version (3.1)
  t: 0x40,              -- group-message (3.6)
  g: <group generation> -- which R/roster this was sealed under (8.1); lets a lagging member ask for the rekey
  i: <senderIndex>,     -- member index of the sender (also bound in ad)
  q: <seq>,             -- sender's monotonic per-sender sequence
  e: <epoch>,           -- wall-clock epoch (bound in ad)
  c: <ciphertext>,      -- sxAeadEncrypt output (nonce || ct || tag)
  s: <signature>        -- OPTIONAL ed25519 sxSignDetached over (c & ad), present iff the room signs (8.3)
}
```

`g`, `i`, `q`, and `e` appear both in the dict (so a receiver can pick the right key and check
ordering before attempting a decrypt) and, for `i`/`q`/`e`, inside `ad` (so they are cryptographically
bound). A receiver MUST use the values it recomputes / expects to build `ad`, not blindly trust the
dict's copies, then let the AEAD tag reject any mismatch (fail closed, 3.10). Padded to 1024 the whole
frame is small; a message whose padded plaintext would exceed a peer-wire frame's practical size uses
an object carrier (doc 09), not a group frame.

### Transport: flood over rp1, gossip over PEX

Group messages are **flooded** across the member mesh. There is no server and no single ordering
authority, so delivery is epidemic:

- **rp1 (BEP10).** A member sends the frame to each connected member as an `rp1` extension message
  (3.8) with subtype byte `0x40` followed by the bencoded `GroupMessage`. Recipients that have not
  seen it re-flood it to their own connected members. This is the gossip bus of the C5 sketch,
  realized on the peer wire.
- **PEX (BEP11).** Members exchange peer lists via BEP11 peer exchange so the mesh heals: a member who
  learned only a few peers from the DHT (Flow 1) discovers the rest through PEX, and a partitioned
  member reconnects. PEX carries **peer addresses only**, never message content; it grows the flood's
  reach, it does not carry the flood.

Flow 2 (send a group message):

```
1. seq = ++myHighestSentSeq                              -- monotonic per-sender counter, persisted
2. epoch = floor(unixTimeSeconds / EPOCH_SECONDS)
3. ad = bencode({ e: epoch, i: myIndex, q: seq, t: 0x40 })
4. c  = sxAeadEncrypt(sxPad(m, 1024), ad, SK_myIndex)    -- SK_myIndex = sxKdfDerive(R, str(myIndex), "rp-sendr", 32)
5. [if room signs] s = sxSignDetached(c & ad, IK_sec)
6. frame = bencode({ v:1, t:0x40, g:g, i:myIndex, q:seq, e:epoch, c:c [, s:s] })
7. For each connected member M: send rp1 message [0x40][frame] to M          (3.8)
8. Members receiving it that have not seen (i, q) re-flood to their peers.   (epidemic gossip)
```

Flow 3 (receive a group message):

```
1. Parse the bencoded frame; require v == 1 and t == 0x40.
2. If frame.g != my current g:                          -- sender is on a different generation
      - if frame.g < g: message from before a rekey I have completed; drop (removed-member era or stale).
      - if frame.g > g: I am lagging a rekey; queue and fetch the pending member-add/-remove (8.5/8.6), then retry.
3. i = frame.i. Reject if i is not a current roster member.
4. De-dup: if (i, frame.q) is at-or-below highestSeq[i], drop (already accepted; replay or gossip echo). (3.10)
5. ad = bencode({ e: frame.e, i: i, q: frame.q, t: 0x40 }).
6. SK_i = sxKdfDerive(R, str(i), "rp-sendr", 32).
7. m_padded = sxAeadDecrypt(frame.c, ad, SK_i)          -- throws on wrong key / tamper / wrong ad (fail closed, 3.10)
8. [if room signs] require sxSignVerifyDetached(frame.s, frame.c & ad, IK_pub_i) == true, else reject.
9. m = sxUnpad(m_padded, 1024).
10. highestSeq[i] = frame.q                              -- advance this sender's replay high-water mark
11. Re-flood [0x40][frame] to my connected members that may not have seen it (epidemic).
12. Deliver m to the application, tagged as "from member i".
```

### De-duplication and ordering across members

Flooding means a member sees the same frame arrive from several peers, and frames from different
senders arrive interleaved. Two mechanisms keep this sane:

- **De-dup by `(i, q)`.** Each frame is uniquely identified by its sender index and that sender's
  sequence number. A member keeps `highestSeq[i]` per sender (the per-sender replay high-water mark,
  3.10) and, for tolerance of out-of-order gossip arrival, a small window / set of recently seen
  `(i, q)` below the high-water mark. A frame at or below the high-water mark that has already been
  accepted is dropped (it is a gossip echo or a replay); this both suppresses the flood's duplicates
  and enforces the replay resistance of G4.
- **Ordering: total order is not promised.** Each **sender's own stream** is totally ordered by its
  monotonic `q` (a member delivers `i`'s messages in `q` order, and can detect a gap as a missing
  message to be back-filled by PEX-reachable peers). **Across senders** there is no global clock and
  no server, so Riptide provides only a **causal-ish, best-effort** order: the wall-clock `e` and
  local receive order give a reasonable display order, but two members can observe two different
  senders' messages in different relative orders. A room that needs a strict total order must layer a
  logical clock (a per-message vector or Lamport timestamp in the dict) on top; that is out of scope
  for the baseline and noted in [13-open-questions.md](13-open-questions.md). For a small chat room,
  per-sender order plus wall-clock is what users expect and what other serverless group chats provide.

## 8.5 Adding a member (type 0x41) and the rekey

Adding a member is not just appending to the roster: it forces a **rekey**, because a new member must
not be able to read messages sent before they joined (backward secrecy for the newcomer's history is a
policy choice; forward secrecy for the group against a later-removed member is not). The baseline
rekeys on **every** membership change so the two cases share one path.

The mechanics:

```
1. Founder/admin picks the new roster [IK_0 ... IK_{n}] (the newcomer gets index n) and bumps g -> g+1.
2. Derive a fresh room key:  R' = sxKdfDerive(R, str(g+1), "rp-rekey?", 32)   -- see note on the label below
   OR (preferred for a true rekey) R' = sxRandomBytes(32).                     -- a fresh independent secret
3. Distribute R', the new roster, g+1, and EPOCH_SECONDS to EVERY current-and-new member,
   each via that member's mailbox (06-mailbox.md) as a member-add control message.
```

**On deriving `R'`.** Deriving `R' = KDF(R, ...)` is convenient but is **not forward-secret**: anyone
who ever held `R` can compute `R'`. For the baseline that is acceptable on an **add** (the members who
held `R` are all still in the room), but it is **wrong on a remove** (8.6), where the removed member
held `R` and could derive `R'`. Therefore the baseline uses a **fresh random `R'` = `sxRandomBytes(32)`
on every rekey** and distributes it under each remaining member's key. This is the linear-cost rekey
(one sealed control message per remaining member) and it is what makes removal actually remove
(8.6). No `rp-rekey?` KDF label is registered, precisely because the safe path is a fresh random key,
not a derived one.

The control message (delivered to each member's mailbox, [06-mailbox.md](06-mailbox.md)):

```
MemberAdd = {
  v: 1,
  t: 0x41,               -- member-add (3.6)
  g: <new generation>,   -- g+1
  R: <new room key R'>,  -- 32 bytes, the fresh room key for generation g+1
  r: [ IK_0, IK_1, ... IK_n ],   -- the new ordered roster (each entry a 32-byte identity pubkey)
  a: <index just added>, -- which index is new (n), so members can show "X joined"
  ts: <unix epoch>
}
```

This dict is the **plaintext**; it is delivered confidentially by wrapping it in a mailbox envelope to
each recipient. Because it carries the room key, it MUST be sent as an **authenticated, confidential**
envelope, not a sealed (anonymous-sender) one, so recipients know the rekey came from the room admin
and not an attacker:

```
c_M = sxBox(sxPad(bencode(MemberAdd), 256), IK_x_M, IK_x_sec_admin)     -- boxed envelope (3.5), to member M
```

carried in a mailbox record (or an `rp1` control message to already-connected members). The `sxBox`
authenticates the admin as sender (3.5, boxed envelope) and encrypts to member M's X25519 identity
key. Padding to 256 (3.5.2) fits the DHT-record bucket.

Flow 4 (add member M):

```
1. Verify M's IK_pub per 02-identity.md (safety number or key-transparency log).
2. newRoster = oldRoster ++ [IK_M]; newIndex = len(oldRoster); g' = g + 1.
3. R' = sxRandomBytes(32).                              -- fresh room key, not derived from R
4. For each member P in newRoster (including M):
      msg  = bencode({ v:1, t:0x41, g:g', R:R', r:newRoster, a:newIndex, ts:now })
      c_P  = sxBox(sxPad(msg, 256), IK_x_P, IK_x_sec_admin)
      DHT.put(P's mailbox salt/id per 06-mailbox.md, seq++, bencode({v:1,t:0x41,c:c_P}), sig)   -- or rp1 to online P
5. Each P: sxBoxOpen -> sxUnpad -> adopt (g', R', newRoster); recompute roomId (8.2) and re-announce.
6. The room has MOVED to the ids derived from R' (8.2); old-generation traffic stops being readable
   by anyone at the new ids, and the newcomer M can now derive SK_i for all members and join Flow 1.
```

The newcomer can read messages from generation `g'` onward and cannot read generation `g` and earlier
(they never held the earlier `R`). If a room wants to hand a newcomer some history, an existing member
re-sends selected past messages inside generation `g'`, deliberately; nothing leaks it automatically.

## 8.6 Removing a member (type 0x42) and post-removal secrecy

Removing a member is the case that makes the fresh-random rekey mandatory. After removal, the removed
member MUST NOT be able to read future messages. Since every derived quantity (rendezvous id, sender
keys) flows from `R`, the removal is achieved by rekeying to a fresh `R'` and distributing it to
**everyone except the removed member**.

```
MemberRemove = {
  v: 1,
  t: 0x42,               -- member-remove (3.6)
  g: <new generation>,   -- g+1
  R: <new room key R'>,  -- fresh sxRandomBytes(32); the removed member never receives this
  r: [ ... new ordered roster ... ],   -- roster WITHOUT the removed member (indices renumbered)
  x: <old index removed>,-- which member left, so clients can show "X removed"
  ts: <unix epoch>
}
```

Flow 5 (remove member X at old index k):

```
1. newRoster = oldRoster with IK_k deleted; remaining members RE-INDEXED 0..n-2 (indices are positional).
2. g' = g + 1;  R' = sxRandomBytes(32).                 -- MUST be fresh & independent of R (see below)
3. For each member P in newRoster (NOT X):
      msg = bencode({ v:1, t:0x42, g:g', R:R', r:newRoster, x:k, ts:now })
      c_P = sxBox(sxPad(msg, 256), IK_x_P, IK_x_sec_admin)
      DHT.put(P's mailbox per 06-mailbox.md, seq++, bencode({v:1,t:0x42,c:c_P}), sig)   -- or rp1 to online P
4. Each remaining P: sxBoxOpen -> sxUnpad -> adopt (g', R', newRoster); recompute roomId (8.2); re-announce
   at the NEW ids and stop announcing at the old ones.
5. From generation g' on:
      - roomId' = sxKdfDerive(R', str(epoch), "rp-rndzv", 20)  is unknown to X (X lacks R').
      - Every SK_i for g' derives from R', so X cannot decrypt any g' message even if it captures one.
```

**Why re-indexing.** Sender keys are `sxKdfDerive(R', str(i), "rp-sendr", 32)`; with a fresh `R'`,
every member's sender key changes anyway (the KDF master changed), so re-indexing the roster to a
compact `0..n-2` is safe and keeps indices dense. The only rule is that all members agree on the same
new roster order, which they do because they all receive the same `MemberRemove.r`.

**What removal guarantees (and what it does not).**

- **Guaranteed (post-compromise / forward secrecy against the removed member).** Because `R'` is a
  fresh random secret delivered only to remaining members, the removed member cannot compute the new
  rendezvous id, cannot derive any new sender key, and therefore cannot read or even locate future
  traffic. This is genuine forward secrecy **at the granularity of the removal event**: everything
  after the rekey is opaque to X.
- **NOT guaranteed (retroactive secrecy of pre-removal traffic).** X held `R` and legitimately read
  every message up to the rekey. Nothing un-reads them. If X recorded generation-`g` ciphertext and
  kept its copy of `R`, X can still decrypt that recorded generation-`g` traffic. The room cannot
  claw back what a member already had. This is the standard limit: removal protects the future, not
  the past.
- **Collusion / delivery caveats.** Removal is only as strong as the delivery of `R'`. If the removed
  member controls or observes a remaining member's device, or a remaining member forwards `R'` to
  them, the removal is defeated by that endpoint (N6). And an offline member does not learn the rekey
  until they fetch their mailbox; until then they are simply partitioned (they see generation `g`
  ciphertext they can still read, and cannot yet read `g'`), which is a liveness gap, not a
  confidentiality break.

The linear rekey is **O(members)**: one boxed control message per remaining member per membership
change. For a small static room that is fine (ten members, ten sealed ~256-byte records). It does not
scale: a thousand-member room pays a thousand messages per single removal, which is the pain point
that motivates a tree-based ratchet (8.7).

## 8.7 The scaling limit and the path to a ratchet

The baseline above is deliberately the **simplest thing that is correct**: a shared room key, per-
member sender keys by KDF, and a linear rekey on every membership change. Its costs are exactly the
two hard problems the brainstorm (section 8) and [13-open-questions.md](13-open-questions.md) flag:

1. **Rekey cost is O(N).** Every add or remove sends one control message per member. Acceptable for
   small static rooms; quadratic pain over a room's lifetime for large or churny groups.
2. **Forward secrecy is coarse.** Within a generation, `SK_i` is static, so a compromise of `R`
   exposes every message of that generation (both directions, all senders). Forward secrecy only
   advances at a rekey, i.e. at a membership change, not per message. A long-lived room that rarely
   changes membership has weak forward secrecy for long stretches.

**This is an MLS-class open problem.** Efficient group key management with per-message forward secrecy
and post-compromise security, at logarithmic rekey cost, is exactly what the IETF Messaging Layer
Security (MLS, RFC 9420) TreeKEM construction solves, and it is genuinely hard to do well over a
serverless, partition-prone transport with no ordering authority. Riptide does not solve it in the
baseline and does not pretend to; see [13-open-questions.md](13-open-questions.md).

**Sketch of the tree-based path (not specified here, a research track).** The direction, for a future
revision that would claim `0x43+` in the groups range (3.6):

- Arrange members as leaves of a binary tree. Each node holds a key; a member knows the keys on the
  path from its leaf to the root (its **co-path**). The root key seeds the room key.
- **Add / remove touch only a path**, not every member: updating a leaf re-keys the log2(N) nodes on
  its path to the root, and the affected members are exactly those whose co-path includes a changed
  node. Rekey cost drops from O(N) to **O(log N)** messages.
- **Per-message forward secrecy** comes from ratcheting the sender's key with `sxKdfDerive` after each
  message (as the mailbox already does per-message, [06-mailbox.md](06-mailbox.md)), so a leaked key
  does not expose earlier messages within a generation.
- The unsolved parts for a serverless deployment are **ordering the tree operations** (MLS assumes a
  delivery service that sequences commits; Riptide has none and would need a consensus or a
  last-writer-wins-with-conflict-detection scheme over BEP44/gossip) and **agreeing on the epoch of a
  concurrent add and remove**. These are the open questions, deferred to
  [13-open-questions.md](13-open-questions.md), not hand-waved as done.

Until that lands, the honest posture is: **use group rooms for small, relatively static, trusted
sets**, accept coarse (per-membership-change) forward secrecy, and use pairwise mailboxes
([06-mailbox.md](06-mailbox.md)) or sessions ([05-session.md](05-session.md)) when strong per-message
forward secrecy matters.

## 8.8 Security properties

Mapped to the goals and non-goals of [01-threat-model.md](01-threat-model.md), and to the adversary
rungs 1-4. Rung 5 (global passive correlation) is out of scope (N3) as everywhere in Riptide.

- **G1 Confidentiality (rungs 1-4).** Every group message is an AEAD envelope under a per-member
  sender key derived from the room key `R`; the room key never crosses the wire in clear (it is shared
  out of band or as a boxed mailbox envelope). Content is readable only by holders of `R`. Endpoint
  compromise (N6) and a member leaking `R` are the residual risks.
- **G2 Integrity and authenticity (rungs 1-4).** The Poly1305 tag on each frame rejects tampering and
  wrong keys (fail closed, 3.10). Binding the sender index `i` into the AD (8.4) gives **per-sender
  authentication inside the room**: a valid frame under `SK_i` with `i` bound in could only be
  produced by a holder of `R` claiming index `i`. Optional ed25519 signing (8.3) upgrades this to
  cross-member and third-party **non-repudiation**, at the cost of deniability.
- **G3 Forward secrecy, LIMITED for groups (rungs 1-4).** This is the honest weak spot and the reason
  this section exists. Forward secrecy is **coarse**: it advances only at a rekey (every membership
  change, 8.5/8.6), not per message. A compromise of `R` exposes the entire current generation. A
  **removed** member is cryptographically shut out of all **future** generations (fresh random `R'`,
  8.6): that is real forward secrecy against the removed member, at membership-change granularity. But
  a **removed member keeps whatever it already read**, and a long-lived generation has no intra-
  generation forward secrecy at all. Full per-message group forward secrecy and efficient large-group
  rekey are the MLS-class open problem of 8.7 and [13-open-questions.md](13-open-questions.md). A room
  that needs strong per-message forward secrecy should use pairwise mailboxes/sessions, not a room.
- **G4 Replay and reorder resistance (rungs 1-4).** The epoch `e`, sender index `i`, sender sequence
  `q`, and type `t` are bound into the AD (8.4); a replayed or reslotted frame fails to authenticate.
  De-dup by `(i, q)` with per-sender high-water marks (8.4) drops gossip echoes and replays. Ordering
  is per-sender total, cross-sender best-effort (8.4); a strict global order is not promised and is
  noted as future work.
- **N2 Incomplete metadata privacy (residual, rung 3).** The room rendezvous id rotates hourly with
  the epoch (8.2), so a passive DHT crawler cannot link two epochs of the room, and a rekey moves the
  room entirely. But members **announce** at the room id (Flow 1), so a rung-3 Sybil that guesses or
  sits on a room id can enumerate the announcing IP set and learn the group's size and liveness, and a
  swarm-insider (rung 4) sees the member mesh directly via PEX. Rotation and derived-unguessable ids
  raise the cost; they do not hide membership from a determined participant. This is the standard N2
  boundary, sharper for groups because a room concentrates several members at one id.

Adversary rungs, concretely:

- **Rung 1 (passive network observer).** Sees encrypted rp1 traffic and DHT announces; reads nothing
  (G1), cannot forge (G2), cannot replay (G4). Sees that *a* group is active at a rotating id.
- **Rung 2 (platform/censor).** No server to seize; the room is a rotating DHT id plus a peer mesh.
  Blocking one epoch's id is defeated by the next epoch's rotation and by PEX healing the mesh.
- **Rung 3 (active DHT/Sybil).** Can target a specific room id to eclipse or log announcers (N2);
  rotation and adjacent-epoch checks (3.9) plus republication raise the cost, but a Sybil on a live
  room id learns the announcing IP set. Cannot read content without `R`.
- **Rung 4 (swarm insider).** A member (or a peer that joined the mesh) sees peer IPs via PEX and the
  full gossip. A **legitimate member** is inside the trust boundary by definition and can, being a
  holder of `R`, forge unsigned messages as any index (the deniability trade-off, 8.3) and read
  everything in its generations. This is why removal (8.6) and, for accountability, ed25519 signing
  (8.3) exist, and why rooms are for **trusted** sets. Endpoint security of every member is assumed
  (N6); one compromised member compromises the room's confidentiality for its generations.

Cross-references, not duplicated here: crypto primitives and nonce discipline
([03-conventions.md](03-conventions.md) 3.3), the KDF label registry and message-type registry (3.4,
3.6), envelope and AD rules (3.5), the epoch clock (3.9), the error model (3.10); rendezvous id
derivation ([04-rendezvous.md](04-rendezvous.md)); room-key and control-message delivery over the
mailbox ([06-mailbox.md](06-mailbox.md)); the peer-wire carrier and PEX (3.8, and the transport
capabilities of [11-capabilities-required.md](11-capabilities-required.md)); and the group
forward-secrecy / large-group rekey open problem ([13-open-questions.md](13-open-questions.md)).
