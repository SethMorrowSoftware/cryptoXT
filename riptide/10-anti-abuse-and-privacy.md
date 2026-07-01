# 10. Anti-abuse and privacy

This document defines the mechanisms that keep an open, serverless system usable in the face of
abuse, and the (mostly experimental) mechanisms that push Riptide's metadata and IP-anonymity
boundary. It has two halves that pull in opposite directions and must be read together: Part A makes
open inboxes survivable; Part B tries to hide more of the metadata that Part A's open inboxes still
leak.

The foundation binds everything here. Bencode is canonical per [03-conventions.md](03-conventions.md)
section 3.2; hashes and KDFs follow 3.3 and 3.4; envelope shapes follow 3.5; the epoch clock is 3.9;
the error model is 3.10; notation (`x || y`, `be64(n)`, `0^n`, `bencode(...)`) is 3.11. The carriers
are the BEP44 record (3.7) and the BEP10 peer wire (3.8). SodiumXT calls are the `sx*` surface of
[../docs/api-reference.md](../docs/api-reference.md). Nothing here invents an encoding, a KDF label,
or a nonce path; where a new one is needed it is registered below.

## Registry additions

This document claims the privacy-extensions message-type range `0x60-0x6F` already reserved in
[03-conventions.md](03-conventions.md) section 3.6, and fixes concrete values in it. No new KDF
context label is required (Part A's proof-of-work and tokens hash public inputs, so they use `sxHash`
/ `sxHashKeyed` with an explicit domain tag, per 3.4's rule that derivations from a public value use
`sxHash`, not `sxKdfDerive`). No new BEP44 salt is required.

| `t` value | Name | Envelope | Defined in |
|---|---|---|---|
| 0x60 | relay-onion | sealed (nested), fixed-size | Part B, multi-hop |
| 0x61 | cover | AEAD or sealed decoy, indistinguishable from a real record | Part B, cover traffic |

Two anti-abuse fields ride alongside a mailbox message (doc 06) envelope rather than as their own
message type, because they gate a write of some other type:

| Field | Meaning | Defined in |
|---|---|---|
| `w` | proof-of-work nonce (byte string) | Part A, proof-of-work |
| `k` | capability token `(token, expiry)` (bencoded pair) | Part A, capability tokens |

A recipient's acceptance policy decides which of `w` or `k` (or both, or neither) a given inbox
requires; see Part A.

---

# Part A. Anti-abuse

A Riptide inbox derived from a public key (`inboxId = sxHash(recipientIK_x || be64(counter) ||
"rp-mbxid", 20)`, per [03-conventions.md](03-conventions.md) section 3.4) is writable by anyone who
knows the recipient's public key, because the public DHT does not and cannot enforce an
application-layer gate (3.7). That is deliberate: consent, not central reach (principle 7 in
[00-overview.md](00-overview.md)). The cost is that an open inbox is a spam and malware-drop magnet
unless the recipient can reject junk *before* spending a sealed-box trial-decrypt on it. Part A gives
two gates for that: an open, sender-costly one (proof-of-work) and a consented, sender-cheap one
(capability tokens). They compose; a recipient can require either, both, or neither per inbox.

## A.1 The threat and the design target

Trial-decrypting a sealed-box envelope (`sxSealOpen`) is a full X25519 operation plus an AEAD open.
It is cheap in absolute terms but not free, and an inbox address is guessable to anyone who has the
recipient's identity card ([02-identity.md](02-identity.md)). A flooder who writes ten thousand junk
records to an inbox counter range forces ten thousand `sxSealOpen` attempts, all of which fail, plus
the DHT `get` traffic to fetch them. The design target is: a check the recipient can run in
microseconds, on the *outside* of the envelope, that a spammer cannot pass cheaply and that a
legitimate sender can pass. Both gates in Part A are checked before any `sxSealOpen`.

## A.2 Proof-of-work (open inboxes)

The proof-of-work (PoW) binds a sender's spent effort to *this recipient's inbox* and *this epoch*,
so work cannot be precomputed far in advance or replayed against a different target.

Let `D` be the recipient's difficulty in leading zero bits (tunable; see A.2.3). Let `inboxId` be the
20-byte inbox address the sender is writing to. Let `epoch` be the current mailbox epoch (3.9; a
mailbox MAY use a coarser `EPOCH_SECONDS` than the 3600-second rendezvous default, and the value is
part of the inbox's published policy). The sender searches for a `nonce` (an arbitrary byte string,
conventionally 8 to 16 bytes from `sxRandomBytes`) such that:

```
h = sxHash(inboxId || be64(epoch) || nonce, 32)
h has at least D leading zero bits
```

The sender attaches `nonce` as the `w` field of the record it writes.

### A.2.1 The recipient's exact check

Before any trial-decrypt, the recipient recomputes the same hash and counts leading zero bits. In
xTalk terms, with `pRecord` the fetched bencoded record and `tInboxId` the 20-byte address the
recipient is scanning:

```
-- reject a record whose PoW is missing, stale, or too weak, before sxSealOpen.
local tEpoch, tNonce, tH, tZeros
put <current mailbox epoch> into tEpoch          -- see A.2.2 for the accepted window
put <the record's w field> into tNonce
put sxHash(tInboxId & be64(tEpoch) & tNonce, 32) into tH
put leadingZeroBits(tH) into tZeros              -- helper below
if tZeros < D then
   -- reject: insufficient work. Do NOT sxSealOpen. Drop the record.
end if
-- else: PoW passes; proceed to sxSealOpen(pRecord's c field, IK_x_pub, IK_x_sec)
```

Counting leading zero bits of a `Data` is done on the raw bytes, most-significant bit first:

```
function leadingZeroBits pHash
   local tCount, tI, tByte, tBit
   put 0 into tCount
   repeat with tI = 1 to the length of pHash
      put byteToNum(byte tI of pHash) into tByte   -- 0..255
      if tByte = 0 then
         add 8 to tCount
         next repeat
      end if
      -- highest set bit in this byte ends the run
      repeat with tBit = 7 down to 0
         if (tByte bitAnd (2 ^ tBit)) <> 0 then
            add (7 - tBit) to tCount
            return tCount
         end if
      end repeat
   end repeat
   return tCount   -- all-zero hash (astronomically unlikely)
end leadingZeroBits
```

The asymmetry is the whole point: the sender does on the order of `2^D` hashes to find a passing
`nonce`; the recipient does exactly one `sxHash` and one bit-count to verify it. `sxHash` (BLAKE2b) is
the same primitive on both sides, so there is no separate PoW hash to agree on.

### A.2.2 Stale-epoch rejection

A PoW is valid only for the epoch it was minted against. The recipient MUST reject a `w` whose bound
epoch is stale. Because clocks drift and a record may be fetched an epoch after it was written, the
recipient accepts a small window: recompute the check for `epoch`, and, only if that fails, retry for
`epoch-1` (and optionally `epoch+1` for a fast sender clock), exactly as 3.9 prescribes for
rendezvous ids. A `w` that passes for none of the accepted epochs is rejected without a trial-decrypt.
Outside the window the work is worthless, which caps how far in advance a flooder can precompute: a
one-hour mailbox epoch means precomputed junk is dead within roughly two hours. This is the
anti-replay analogue of 3.5.1's associated-data binding, applied to the outer gate rather than the
inner ciphertext.

The epoch is not a substitute for the message-level replay defense. A record that passes PoW and
decrypts is still subject to the `(channel, seq)` replay drop of 3.10; PoW gates *writes*, the `seq`
tracking gates *acceptance*.

### A.2.3 Choosing and publishing D

`D` is a latency knob, published by the recipient as part of the inbox policy in their identity card
or prekey bundle ([02-identity.md](02-identity.md)) so senders know the cost before they mint. Rough
costs, at a commodity rate of a few million `sxHash` calls per second per core:

| D | Expected sender hashes | Order-of-magnitude sender time | Posture |
|---|---|---|---|
| 16 | ~65 thousand | milliseconds | trivial deterrent, stops accidental floods |
| 20 | ~1 million | fraction of a second | light gate, barely felt by a human sender |
| 24 | ~16 million | seconds | meaningful cost per message |
| 28 | ~268 million | tens of seconds | heavy; only for a very hostile inbox |

PoW is a cost, not an elimination (threat-model N4, and the attack table row "Spam an open inbox" in
[01-threat-model.md](01-threat-model.md)): a determined, resourced flooder still gets through, just
more slowly, and a raised `D` also taxes legitimate senders and drains battery on mobile. Riptide
treats PoW as the gate of last resort for a genuinely open inbox and prefers capability tokens
(A.3) for anyone the recipient has already accepted.

## A.3 Capability tokens (consented senders)

Once a recipient has accepted a sender, making that sender re-mint PoW on every message is pure waste.
A capability token replaces the open, costly PoW with a consented, cheap MAC that only the recipient
can issue and only the recipient can verify.

### A.3.1 Issuance

The recipient holds a secret `recipientCapKey` (32 bytes from `sxRandomBytes`, never published,
stored beside the master seed). To grant a sender identified by their identity signing key
`senderIK` a capability that expires at unix time `expiry`, the recipient computes:

```
token = sxHashKeyed(senderIK || be64(expiry), recipientCapKey)   -- a BLAKE2b MAC, 32 bytes
```

and delivers `(token, expiry)` to the sender over an already-authenticated channel (the pairwise
session of doc 05, or the first accepted mailbox exchange). `sxHashKeyed` is keyed BLAKE2b, i.e. a
MAC over the sender's identity and the expiry, keyed by a secret only the recipient knows. The token
binds *which sender* and *until when*; it is unforgeable without `recipientCapKey`.

### A.3.2 Spending and verification

The sender attaches `k = (token, expiry)` as a bencoded pair to the record it writes. Before any
trial-decrypt, the recipient recomputes and compares in constant time:

```
-- reject a record whose capability token is missing, expired, or forged, before sxSealOpen.
local tSenderIK, tExpiry, tToken, tExpected
put <the record's claimed sender IK, from the k field or the boxed envelope's signed sender field> into tSenderIK
put <the record's k.expiry> into tExpiry
put <the record's k.token> into tToken
if tExpiry < the current unix time then
   -- reject: expired.
end if
put sxHashKeyed(tSenderIK & be64(tExpiry), recipientCapKey) into tExpected
if not sxMemEqual(tToken, tExpected) then
   -- reject: forged or wrong sender/expiry. Do NOT sxSealOpen.
end if
-- else: token valid; proceed to trial-decrypt.
```

The comparison MUST be `sxMemEqual`, never `is` or `=`: a token is a MAC, and comparing a MAC with a
byte-by-byte early-exit equality is a timing leak that lets a forger recover the token one byte at a
time (rule 4 of the FFI/crypto discipline; 3.3's secret-comparison rule). Verification is one
`sxHashKeyed` and one constant-time compare, on the order of a microsecond, with no per-message work
asked of the sender.

The `senderIK` used in the MAC MUST be authenticated, not merely claimed in the `k` field, or a
spammer would attach a valid token minted for some *other* sender and paste their own key. Bind it by
carrying the token only on a boxed (authenticated-sender) envelope (3.5) whose signed sender field is
the same `senderIK` the token commits to, or by delivering tokens only to senders whose first message
already proved possession of `senderIK`.

### A.3.3 Revocation

There is no revocation list and no server to check one. Revocation is by rotation: the recipient
generates a fresh `recipientCapKey` with `sxRandomBytes(32)`, which instantly invalidates every token
ever issued under the old key, then re-issues tokens to the senders it still wants. This is coarse
(it revokes everyone at once) but it needs no infrastructure and no online check. For finer control, a
recipient MAY keep a small set of cap keys (for example one per trust tier or one per cohort) and
rotate only the compromised one; the token then also carries a one-byte key id so the recipient knows
which cap key to recompute under. Expiry (A.3.1) is the routine, self-cleaning form of revocation:
short expiries mean stale grants lapse on their own without any rotation.

## A.4 PoW versus tokens (when to use which)

| | Proof-of-work (A.2) | Capability token (A.3) |
|---|---|---|
| Who can write | anyone (open inbox) | only senders the recipient granted |
| Sender cost | high (~`2^D` hashes per message) | negligible (attach a stored token) |
| Recipient cost | one `sxHash` + bit-count | one `sxHashKeyed` + `sxMemEqual` |
| Prior relationship | none required | required (the grant) |
| Binding | to `inboxId` and `epoch` | to `senderIK` and `expiry` |
| Revocation | n/a (per-message, stale after ~2 epochs) | rotate `recipientCapKey`, or let expiry lapse |
| Failure mode | flooder pays, still gets through slowly | grant leaks, but is scoped and revocable |

The intended shape: an inbox is open to strangers behind PoW, and the moment the recipient accepts a
sender, it issues that sender a token so subsequent messages skip the PoW entirely. First contact
pays the open cost once; the relationship is cheap thereafter. A recipient that wants a fully closed
inbox requires a token and never advertises a `D`; a recipient that wants a fully open one advertises
a `D` and issues no tokens.

## A.5 Recipient-side moderation

Riptide has no central moderation and cannot have any (non-goal N4 in
[01-threat-model.md](01-threat-model.md)): there is no server in the message path to filter, label, or
delete content, by the same design choice that makes the system unseizable and uncensorable. Filtering
lives entirely at the recipient, keyed by identity. This is a feature, not a gap: the protocol
authenticates *who* said something (G2) precisely so the recipient can decide whom to trust, rather
than delegating that judgment to an operator who could be compelled or could overreach.

The recipient-side primitives:

- **Block list**, keyed by identity signing key `IK`. A record whose authenticated `senderIK` is on
  the block list is dropped after the cheap gate check and before any trial-decrypt where the sender
  is known; where the envelope is sealed-sender (anonymous), the block is applied after `sxSealOpen`
  reveals a signed sender field, and the plaintext is discarded unread. Block is by key, so it
  survives a spammer changing display names but not a spammer minting a fresh identity (which then
  faces PoW again).
- **Allow list (consent-default)**, keyed by `IK`. By default only *accepted* senders reach the main
  inbox; the allow list is the set of `IK`s whose messages surface normally. This is principle 7
  (consent, not reach) made concrete: unknown senders land in a gated request area governed by PoW,
  not in the main view, so a flood of strangers cannot bury real conversation. Accepting a sender
  moves their `IK` to the allow list and (A.3) issues them a token.
- **Report / verify**, local primitives. *Verify*: recompute the sender's safety number
  (`SN = sxHash(min(aIK,bIK) || max(aIK,bIK), 32)`, [02-identity.md](02-identity.md) section 2.5) and
  compare with `sxMemEqual` to confirm the key is the one the user vetted out of band, and follow the
  sender's key-transparency log ([02-identity.md](02-identity.md) section 2.6) so a later key
  substitution is surfaced, not silently accepted. *Report* is necessarily local: there is no
  authority to report to, so a report attaches the offending signed record (which is
  self-authenticating evidence of what that key published) to the user's own block action and MAY be
  shared out of band with a community that maintains its own shared block list keyed by `IK`. Riptide
  provides the authenticated evidence; it does not provide, and by N4 cannot provide, an adjudicator.

### A.5.1 Responsible-use notes

A serverless, deniable, censorship-resistant tool has abuse exposure that Riptide surfaces honestly
rather than hiding (principle 5, and section 9 of [../brainstorm.md](../brainstorm.md)):

- **Cover-seed must use lawful content.** The deniability of the cover-seed mode
  ([05-session.md](05-session.md), C3) comes from genuinely participating in a real swarm. That
  swarm's content is actually transferred and is visible to the tracker, the DHT, and every swarm
  peer, so it MUST be content that is lawful to share in the operator's jurisdiction. Deniability
  built on an unlawful transfer is not deniability; it is a second offense used as camouflage for the
  first.
- **Relay operators have abuse exposure.** A node that runs the multi-hop relay of Part B forwards
  bytes it cannot read (that is the point of the onion). It therefore cannot filter what it relays and
  may forward abusive traffic, and its address is the one that appears to write the next hop's inbox.
  Running a relay is a deliberate choice to carry others' unreadable traffic, with the legal and abuse
  exposure that implies; it is not a default, and Part B flags it as experimental.
- **Open inboxes attract malware drops, not just spam.** The gates of Part A raise the cost of a flood
  but do not inspect content (they cannot; it is sealed). Endpoint hygiene (N6) is the user's, and a
  client SHOULD treat any attachment or object link from a non-allow-listed sender as untrusted.

---

# Part B. Privacy extensions

Everything in Part B is a metadata- or IP-privacy mechanism layered on top of the authenticated
encryption the rest of the spec already provides. Confidentiality and integrity (G1, G2) do not depend
on any of it. What is at stake here is the harder, only-partly-solved goals: *who* is talking to
*whom*, from *what address* (non-goals N1, N2, N3 in [01-threat-model.md](01-threat-model.md)). Each
mechanism below is marked with how finished it is. Two of them (k-anonymity, cover traffic) are
buildable but under-quantified; two (multi-hop, covert channels) are open research included because
they are the honest answer to "but my IP and my social graph still leak," not because they are done.

## B.1 k-anonymous inboxes (buildable, under-quantified)

The direct inbox of doc 06 is addressed by the full derived id, so a rung-3 crawler
([01-threat-model.md](01-threat-model.md)) who watches a specific `inboxId` learns exactly which
recipient is being written to. k-anonymity blurs the recipient inside a set.

Instead of addressing the full 20-byte inbox id, a sender addresses a **bucket prefix**: the first `p`
bytes of the inbox id (the remaining `20 - p` bytes are unaddressed). A set of recipients whose full
inbox ids share that `p`-byte prefix form a **bucket**. Each recipient in the bucket fetches *all*
records under the bucket prefix and trial-decrypts every one; because the envelope is a sealed box
(3.5), only the record actually meant for a given recipient opens under that recipient's key
(`sxSealOpen` fails closed on all the others, per 3.10). An observer who watches the bucket learns
only that *someone in a set of size k* received a message, not which one.

Concretely, a sender computes the full `inboxId` as usual, then writes to (and the recipient scans)
the DHT under the truncated key formed by the first `p` bytes. The bucket size `k` is the expected
number of distinct recipients sharing a `p`-byte prefix; recipients coordinate `p` out of band (it is
part of the inbox policy) so they land in the same bucket on purpose.

### B.1.1 The anonymity-set versus bandwidth trade-off

k-anonymity is a direct trade of bandwidth for ambiguity, and the trade is quantifiable:

- The anonymity set has size `k`: an observer's best guess at the true recipient is 1-in-`k`, so the
  linking uncertainty is `log2(k)` bits.
- Every recipient in the bucket must fetch and trial-decrypt *every* record in the bucket. If each of
  the `k` recipients receives on average `m` messages per epoch, each recipient does `k * m` fetches
  and `k * m` `sxSealOpen` attempts per epoch, of which only its own `m` succeed. Bandwidth and CPU
  scale as `k * m` per recipient, i.e. linearly in the anonymity set.

So doubling the anonymity set (one more bit of uncertainty) doubles every member's fetch and
trial-decrypt load. A bucket of `k = 16` gives 4 bits of recipient ambiguity at 16x the bandwidth of a
direct inbox; `k = 256` gives 8 bits at 256x. This is the reason k-anonymity is a knob, not a default:
small `k` (say 8 to 32) is a cheap, real improvement; large `k` is expensive fast. The right `p`
(hence `k`) depends on how contested the recipient's privacy is and how much idle bandwidth the
bucket's members will spend. Choosing `k` well against a real crawler is one of the open metadata
questions in [13-open-questions.md](13-open-questions.md).

## B.2 Cover traffic (buildable, open how-much)

A crawler distinguishes a busy relationship from a quiet one by watching *when* real records and
announces appear. Cover traffic blurs that by manufacturing a baseline of indistinguishable
non-events.

- **Decoy records.** On an epoch schedule, a participant writes `t = 0x61` cover records to inboxes
  and buckets it does not actually use, or extra decoy records to ones it does. A cover record is a
  sealed or AEAD envelope over random padding that no one is meant to open (or that opens to a
  discard-me marker), so it is byte-indistinguishable from a real record to anyone without the key. A
  crawler counting records per epoch can no longer tell a real message from a decoy.
- **Decoy announces.** On the same schedule, a participant issues DHT announces
  (`DHT.announce(id)`, doc 11) for rendezvous ids it is not really meeting on, so the pattern of
  *which ids a node announces* stops mapping cleanly to that node's real relationships (this directly
  supports the presence and rendezvous privacy of doc 04 and doc 07).

Cover traffic is cheap to add and directly attacks traffic analysis (it is one of the cross-cutting
mechanisms in section 5 of [../brainstorm.md](../brainstorm.md)). What is genuinely unsettled is *how
much* is needed: too little and the real signal still stands out of the noise; too much and it is a
bandwidth tax on every participant and, on mobile, a battery tax. The optimal cover schedule against a
specific crawler model is an open question (reference [13-open-questions.md](13-open-questions.md),
"how much metadata privacy can rotating derived ids + k-anonymity + cover traffic actually buy,
quantitatively"). Riptide specifies the mechanism and the `0x61` type; it does not yet specify a
rate, because a rate that is not justified by a threat model is security theater.

## B.3 Multi-hop relay (EXPERIMENTAL, open research)

This is channel C10 from [../brainstorm.md](../brainstorm.md). It is the honest answer to non-goal N1
(no IP anonymity by default): route a write to a recipient's inbox through willing relay peers so the
address that finally writes the inbox is a relay's, not the sender's. It is **experimental** and does
**not** deliver the guarantees of a real mixnet or Tor; the reasons are in B.3.3.

### B.3.1 The onion

A message to a final destination `dstPub`, routed through relays with public keys `r1Pub` then
`r2Pub`, is wrapped in nested sealed boxes, outermost layer for the first hop:

```
onion = sxSeal( hop1instr || sxSeal( hop2instr || sxSeal( finalMsg, dstPub ), r2Pub ), r1Pub )
```

Each `hopNinstr` is the small bencoded instruction telling relay N where to forward the inner blob:
the next hop's inbox id (or the next relay's identity), and nothing else. The message travels as a
`t = 0x60` relay-onion envelope.

### B.3.2 Peeling

Each relay opens exactly one layer and learns exactly one successor:

```
peeled = sxSealOpen( onion, rNPub, rNSec )    -- relay N's own keypair
-- peeled = hopNinstr || innerBlob
-- relay reads hopNinstr (the next hop), then writes innerBlob forward to that next inbox.
```

`sxSeal` / `sxSealOpen` is anonymous-sender (3.3), so a relay learns nothing about who is upstream of
the peer that handed it the blob, and nothing about the contents of the inner layers (they are sealed
to keys it does not hold). The final relay's inner blob is `sxSeal(finalMsg, dstPub)`, an ordinary
sealed mailbox envelope the destination opens exactly as in doc 06.

**Fixed-size padding is mandatory.** Every layer, at every hop, MUST be padded to the *same* fixed
size, so that an observer (or a relay) cannot tell a near-the-source layer (many layers still nested
inside) from a near-the-destination layer (few) by its length. Without this, layer count leaks the hop
position and the whole point is lost. Pad each `sxSeal` input to a single protocol-wide bucket with
`sxPad` (3.5.2) before sealing, sized so the largest supported message plus the maximum hop count
fits; a relay that peels a layer re-pads the inner blob back up to the same bucket before forwarding.
All `0x60` records are therefore the same length on the wire regardless of their position in the
route.

### B.3.3 What is unsolved

Multi-hop is included for honesty, not because it works yet. The hard parts, all flagged in
[../brainstorm.md](../brainstorm.md) (C10) and [13-open-questions.md](13-open-questions.md):

- **Relay incentives.** Nothing makes a peer volunteer to forward strangers' unreadable traffic, and
  running a relay carries the abuse exposure of A.5.1. Without an incentive model there are no relays.
- **Sybil relays.** An adversary who supplies most of the relay pool can put itself on both ends of a
  route and defeat the unlinkability entirely; path selection over an open, unauthenticated relay set
  is exactly the Sybil problem the DHT already has (rung 3), now on the relay layer too.
- **Timing correlation.** Fixed-size padding hides layer *length* but not *timing*. A rung-5 observer
  (or a Sybil straddling the path) who watches a blob enter the first relay and a same-size blob leave
  the last relay a predictable interval later can correlate them; defeating this needs batching,
  mixing, and cover, which this sketch does not specify.

Therefore: this approximates but does **not** equal a real mixnet or Tor. It does not defeat the
global passive adversary (non-goal N3) and it does not by itself deliver N1's IP anonymity as a
guarantee. Where real IP anonymity is required, run Riptide over Tor or I2P (the recommendation in
[01-threat-model.md](01-threat-model.md) N1) rather than relying on this layer. Building a
swarm-native mixnet, or concluding that it reduces to "just use Tor underneath," is an explicit open
question in [13-open-questions.md](13-open-questions.md).

## B.4 Covert / steganographic micro-channels (EXPERIMENTAL, open research)

This is channel C11 from [../brainstorm.md](../brainstorm.md). It targets the case where even *using
the DHT to talk* must be invisible: not just the content, but the fact that any structured message was
sent, must hide inside ordinary BitTorrent noise. Capacity is bytes, not kilobytes; deniability is
high; the channels are fragile. Each carrier ferries small **AEAD micro-frames**
(`sxAeadEncrypt(pad(m), ad, key)` over a shared secret, 3.5), so even the few bytes that do cross are
authenticated and confidential, and a wrong-key observer sees only noise.

The carriers, in decreasing order of naturalness:

- **Announce-pattern coding.** The *choice* of which rendezvous ids a node announces (doc 04) is
  itself a symbol alphabet. A shared secret derives a per-epoch set of candidate ids
  (`sxHash`-derived, as in doc 04); announcing id A versus id B versus id C encodes a symbol, and a
  sequence of announces spells a micro-frame. To a crawler it is indistinguishable from ordinary DHT
  announce churn.
- **Timing coding.** The *inter-arrival timing* of announces or `get_peers` requests carries a low-bit
  code (for example, a gap above or below a threshold is a 1 or a 0). Extremely low capacity, and
  fragile against jitter and dropped packets, but it rides on activity that has to happen anyway.
- **peer_id / port entropy carriers.** The BitTorrent `peer_id` (20 bytes, partly client-defined) and
  the source port have entropy a client normally fills with random or client-version bytes; a few of
  those bytes can instead carry an AEAD micro-frame, so the covert payload hides in fields an observer
  expects to be high-entropy anyway.

Properties and use: traffic is indistinguishable from ordinary DHT and peer churn (tier-3
deniability); capacity is on the order of bytes per epoch; the channels are fragile against active
manipulation (a Sybil that rewrites `peer_id`s or perturbs timing degrades them) and against loss. The
intended use is not to carry a conversation but to **bootstrap** one: use a micro-channel to establish
or confirm a shared secret with tiny, deniable traffic, then *graduate* to a real channel (the
phantom-swarm session of doc 05, or a mailbox of doc 06) that has the bandwidth for actual messages.
Quantifying their real-world capacity and their resistance to an active adversary is open research
([13-open-questions.md](13-open-questions.md)).

---

# Security properties

This section maps each mechanism to the goals (G1-G7) and non-goals (N1-N7) of
[01-threat-model.md](01-threat-model.md), across adversary rungs 1-5, and is scrupulous about solved
versus open. The headline: Part A hardens *availability and consent* for open inboxes without touching
the crypto guarantees; Part B pushes on the two hardest non-goals, **N1 (IP anonymity)** and **N2
(metadata privacy)**, and partially, honestly, fails to close them.

## Summary matrix

| Mechanism | Status | Primary rungs | Helps | Does not solve |
|---|---|---|---|---|
| A.2 Proof-of-work | buildable | 2-3 (floods, Sybil) | availability of open inboxes; caps precompute via epoch bind | N4 (no central moderation); a resourced flooder still gets through slowly |
| A.3 Capability tokens | buildable | any writer | cheap consented access; scoped, revocable grants | leaked token until rotation/expiry; needs a prior relationship |
| A.5 Moderation | buildable | any | recipient consent-default (principle 7); trust-on-key (G2) | N4 (cannot filter content centrally; no adjudicator) |
| B.1 k-anonymity | buildable, under-quantified | 3 (crawler) | N2: `log2(k)` bits of recipient ambiguity | full recipient privacy; costs `k*m` bandwidth; `k` unproven |
| B.2 Cover traffic | buildable, rate open | 1, 3 | N2: blurs which/when ids are active | N2 fully; correct rate is unknown |
| B.3 Multi-hop | EXPERIMENTAL | 3-4 target | N1: hides sender IP from the final inbox writer | N1 as a guarantee; N3; incentives, Sybil, timing all unsolved |
| B.4 Covert channels | EXPERIMENTAL | 3, 5 target | N2 existence-hiding; deniable bootstrap | tiny capacity; fragile; unquantified vs active adversary |

## By adversary rung

- **Rung 1 (passive network observer).** The crypto goals G1-G4 already hold from the foundation, so
  Part A adds nothing a rung-1 observer would notice, and Part B's cover traffic (B.2) and covert
  channels (B.4) further deny a passive tap the ability to see *when* real activity happens. A rung-1
  observer is fully addressed by the existing spec plus B.2; nothing in this document is *needed*
  against rung 1, and everything in it is at least harmless against it.
- **Rung 2 (censor).** Part A is the relevant half: PoW and tokens keep an open, unseizable inbox
  usable, which is what makes censorship-resistant messaging (G5) survivable rather than
  spam-drowned. A censor cannot compel a moderator because there is none (N4); that is the point, and
  A.5 puts the moderation where a censor cannot reach it (the recipient). Part B is orthogonal to a
  rung-2 censor.
- **Rung 3 (Sybil / DHT crawler).** This is where Part B earns its keep and where it is most honest
  about limits. B.1 (k-anonymity) buys `log2(k)` bits of recipient ambiguity against a crawler but
  costs linear bandwidth and does not eliminate linking (N2 stays "reduced, not eliminated"). B.2
  raises the crawler's noise floor. A.2's PoW also taxes a Sybil trying to flood many inboxes. None
  of these *closes* N2; a determined rung-3 crawler still learns a great deal, exactly as N2 states.
- **Rung 4 (swarm insider).** A swarm insider sees IPs directly. B.3 (multi-hop) is aimed here and at
  rung 3: it removes the sender's IP from the final inbox write. But B.3.3 is explicit that Sybil
  relays and timing correlation are unsolved, so multi-hop *approaches* N1 without *delivering* it; a
  swarm insider who is also a relay-pool Sybil can still de-anonymize. The honest mitigation for N1
  remains an underlay (Tor/I2P), not this layer.
- **Rung 5 (global passive adversary with correlation).** Riptide does not claim to defeat rung 5
  (N3). B.3's fixed-size padding denies a *length* correlation but not a *timing* one, and B.4's
  covert channels are a deniability play, not a defense against an omniscient correlator. Only
  cover-seed ([05-session.md](05-session.md)) and multi-hop even *approach* rung 5, and both fall
  short of a guarantee. This is stated plainly rather than papered over.

## Solved versus open (the honest ledger)

- **Solved (buildable now, guarantees hold):** PoW and capability tokens as gates (A.2, A.3);
  recipient-side block/allow/verify keyed by identity (A.5); the `0x60`/`0x61` type reservations and
  the fixed-size-padding rule for onions (B.3.1). These do not weaken any G1-G4 guarantee and do not
  overclaim.
- **Buildable but under-quantified (mechanism specified, parameters open):** k-anonymity's `k`/`p`
  choice (B.1) and cover traffic's rate (B.2). The mechanisms are concrete; the numbers that would
  make them a *quantified* defense against a real crawler are open questions in
  [13-open-questions.md](13-open-questions.md).
- **Open research (included for honesty, not finished):** multi-hop relay (B.3) does not equal a
  mixnet or Tor and does not close N1 or N3; its incentives, Sybil resistance, and timing defense are
  unsolved. Covert micro-channels (B.4) are a fragile, tiny-capacity bootstrap, not a channel.
  Neither is a v1 guarantee, and neither should be presented to a user as one.

The two non-goals this document pushes hardest on, N1 and N2, are *reduced* but not *eliminated*. That
is not a temporary state pending better engineering in every case: N2 against a public DHT and N1
without an anonymizing underlay may be irreducible for a system that, by design, rides the open
BitTorrent network rather than hiding from it. Riptide's contribution here is to raise the cost and to
say exactly how far it gets, per principle 5 of [00-overview.md](00-overview.md).
