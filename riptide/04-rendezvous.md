# 04. Rendezvous and presence

This document defines where two parties meet on the DHT and how one learns another is online, without
a server and without a fixed, linkable address. It covers the channels the brainstorm calls C2
(discovery) and C7 (private presence), plus the first-contact-by-public-key bootstrap and the
cover-blending trick that lets a meeting id ride an existing swarm.

Everything here obeys the constitution in [03-conventions.md](03-conventions.md): canonical bencode
(3.2), the KDF label registry (3.4), the envelope and AD rules (3.5), the crypto primitives and nonce
discipline (3.3), the epoch clock (3.9), the error model (3.10), and the notation (3.11). Carriers are
the BEP44 records (3.7), the BEP10 `rp1` extension (3.8), and the TorrentXT DHT operations
`DHT.announce` / `DHT.getPeers` / `DHT.put` / `DHT.get` (doc 11). The identity keys `IK`, `IK_x`, `KX`
are from [02-identity.md](02-identity.md). The handshake that a rendezvous hands off to is in
[05-session.md](05-session.md).

Rendezvous is a signaling layer only. It answers "at what 20-byte DHT id do we look for each other,
and how do we learn an IP:port there." It does not carry message content; the moment two parties have
each other's IP:port they open an `rp1` connection and run the [05-session.md](05-session.md)
handshake.

## Registry additions

This document introduces no new KDF label and no new message type: the two labels it uses, `rp-rndzv`
and `rp-prsnc`, are already reserved in the registry of [03-conventions.md](03-conventions.md) section
3.4. It defines one control record that rides the `rp1` peer wire, and it reuses the identity/control
type range `0x01-0x0F` for it:

| Type (`t`) | Name | Meaning | Where |
|---|---|---|---|
| `0x04` | rendezvous-hello | first `rp1` control frame after a derived meeting: proves epoch and rendezvous knowledge, requests handshake | this doc, 4.3 |

`0x04` is added to the identity/control range (3.6) here. If a later edition of
[03-conventions.md](03-conventions.md) is regenerated, fold this row into its 3.6 table. No new KDF
label is required: presence and rendezvous ids are DHT keys, not typed records, and both use labels
already in the 3.4 registry (`rp-rndzv`, `rp-prsnc`). This doc also coins three point-of-use `sxHash`
domain tags, which are NOT KDF-registry labels (3.4 explicitly routes derivations from a public key or
from non-secret material through `sxHash` with an explicit domain tag, defined where they are used):
`rp-fc-meet/v1` (first-contact meeting id, 4.5), `rp-cover` (cover-blend XOR mask, 4.7), and
`rp-rndzv-pw/v1` (the fixed public salt for the passphrase path, 4.1). They are byte-string tags of any
convenient length, not the 8-byte contexts crypto_kdf requires, so they do not touch the KDF registry.

## 4.1 The shared-secret input

Every derived rendezvous or presence id is keyed by a **32-byte pairwise secret** the two parties
already hold. This document does not create that secret; it consumes one. There are three sanctioned
sources, in decreasing order of preference:

1. **A session root from a completed handshake.** After the first successful session
   ([05-session.md](05-session.md)), the two parties share the 32-byte session root
   `RK = sxKdfDerive(handshakeSharedSecret, "0", <"rp-sess0">, 32)` (label `rp-sess0`, 3.4). For all
   subsequent meetings the pairwise secret `PS` used below **is** `RK`. This is the normal steady
   state: once you have talked once, every future meeting id is keyed off the relationship, not off a
   guessable public key.

2. **A key-exchange secret from the identity kx keys.** Two contacts who have exchanged and verified
   identity cards ([02-identity.md](02-identity.md) 2.3, 2.5) can agree a pairwise secret directly from
   their long-term kx keypairs, with no live handshake, so a meeting id can be computed offline before
   either is online:

   ```
   -- A (the lexicographically smaller IK_pub is the "client", for a symmetric result):
   sxKeyExchangeClient KX_pub_A, KX_sec_A, KX_pub_B, tRx, tTx
   PS = sxHash(tRx & tTx, 32)                 -- 32-byte pairwise secret, order-independent
   -- B computes sxKeyExchangeServer with the mirrored roles and gets the same tRx/tTx pair,
   -- so B's sxHash(tRx & tTx, 32) equals A's PS.
   ```

   Deriving `PS` by hashing both directional keys together (rather than using one directly) keeps `PS`
   independent of which side is nominally client, and confines it to the rendezvous purpose so it is
   not the same bytes as any session key. Roles are fixed by comparing the identity keys: the party
   with the smaller `IK_pub` (raw byte compare) is the client. This mirrors the ordering trick used for
   safety numbers in [02-identity.md](02-identity.md) 2.5.

3. **A pre-shared passphrase (out-of-band setup).** When two parties can share a secret phrase out of
   band (spoken, on paper, over an already-trusted channel) but have not yet exchanged public keys,
   they derive `PS` from the passphrase with Argon2id. The passphrase crosses as UTF-8, the salt is a
   fixed, agreed, non-secret domain string (both sides MUST use the identical salt or they derive
   different secrets), and the cost is a preset both sides agree on:

   ```
   tSalt = sxHash(textEncode("rp-rndzv-pw/v1", "utf-8"), 16)          -- 16-byte fixed public salt
   PS    = sxPwHash(textEncode(pPassphrase, "utf-8"), tSalt, 32, "3", sxPwMemModerate())
   ```

   The fixed salt is deliberate: a random per-party salt would have to be exchanged, which defeats the
   point of a purely out-of-band passphrase. Because the salt is public, the passphrase itself carries
   all the entropy, so it MUST be strong (a short or guessable phrase lets a rung-3 crawler that
   guesses it compute the same rendezvous id). This path is a bootstrap: the first thing the parties do
   after meeting is exchange identity cards and run the [05-session.md](05-session.md) handshake, after
   which source 1 supersedes the passphrase-derived `PS` and the phrase can be forgotten.

In the flows below, `PS` denotes whichever of these the channel is using. `EPOCH_SECONDS` for
rendezvous and presence is `3600` (3.9) unless the channel's out-of-band setup pins another value; all
parties MUST agree on it.

## 4.2 Rendezvous id derivation

The rendezvous id is a 20-byte DHT key derived from `PS` and the current epoch with the `rp-rndzv`
label. Twenty bytes matches the mainline DHT keyspace (160 bits, BEP5).

```
epoch = floor(unixTimeSeconds / 3600)                                 -- (3.9)
rid   = sxKdfDerive(PS, <decimal string of epoch>, <"rp-rndzv">, 20)  -- 20-byte DHT id
```

Notes on the exact call, matching `sxKdfDerive(pMasterKey, pSubkeyId, pContext, pSubkeyLen)`:

- `pMasterKey` is `PS`, a 32-byte secret (crypto_kdf requires a 32-byte secret master key, which is why
  `PS` is always hashed/derived to 32 bytes above and why a public key alone cannot key this call).
- `pSubkeyId` is the epoch as a **decimal string** (there is no 64-bit foreign int; ids cross as
  decimal per 03 and the SodiumXT ABI). Both parties compute the same epoch from wall-clock time.
- `pContext` is the 8 ASCII bytes `rp-rndzv`.
- `pSubkeyLen` is `20`.

`rid` is unguessable to anyone without `PS`: it is a keyed derivation, not a hash of a public value, so
a DHT crawler that sees an announce at `rid` learns only "some pair is meeting here this hour," never
who or under what relationship (N2), and cannot precompute future or past `rid`s.

## 4.3 The announce / getPeers discovery dance

Both parties compute the same `rid`, announce themselves in that swarm, and query it, so each learns
the other's IP:port. This is the C2 core.

```
1. A: rid = sxKdfDerive(PS, epoch, <"rp-rndzv">, 20)          -- both use the same PS and epoch
2. A: DHT.announce(rid)                                       -- A joins the rid swarm (BEP5 announce_peer)
3. A: put peersA into DHT.getPeers(rid)                       -- A asks who else is here (BEP5 get_peers)
   (B runs steps 1-3 symmetrically)
4. A: for each candidate IP:port in peersA, open an rp1 connection (3.8) and send a
      rendezvous-hello control frame (below). B does the same toward A's address.
5. On a rendezvous-hello that authenticates, both drop into the 05-session.md handshake on that
   same rp1 connection. rendezvous is done; session takes over.
```

Steps 2 and 3 both run because either party may arrive first: announcing makes you findable, querying
finds a peer who already announced. A party polls `DHT.getPeers(rid)` on a modest interval (for
example every 30 to 60 seconds) while it wants to be reachable, and keeps its announce fresh (DHT
entries expire, so re-announce on the same cadence). Keep the poll rate low: a tight loop is both a UI
cost (the single OXT thread, see [03-conventions.md](03-conventions.md) does not say this but the
SodiumXT performance playbook does) and a louder DHT footprint.

### 4.3.1 The rendezvous-hello control frame

`DHT.getPeers(rid)` returns raw IP:port candidates. Anyone can announce at any 20-byte id, so a
returned peer is not proof of anything: it might be an unrelated client that happens to share the
swarm, or a Sybil probing the id. Before running the handshake, the initiator sends a control frame
that proves it derived `rid` from the shared secret for this epoch, so the responder can reject noise
cheaply and the two can confirm they are the intended pair.

The frame is an `rp1` message (3.8): a 1-byte subtype `0x04` followed by the canonical bencode of:

```
rendezvous-hello (t = 0x04):
{
  v: 1,                                   -- protocol version (3.1)
  t: 4,                                   -- type = 0x04
  e: <epoch>,                             -- the epoch the sender used to derive rid
  n: <16 random bytes from sxRandomBytes> -- a fresh challenge nonce, echoed in the response
  p: <proof>                              -- see below
}
```

The `proof` is an AEAD tag over the epoch and nonce, keyed by a rendezvous-confirmation key derived
from `PS` so that only a holder of `PS` can produce it, and it binds the epoch and nonce as associated
data so it cannot be replayed into another epoch (3.5.1):

```
kConfirm = sxKdfDerive(PS, epoch, <"rp-rndzv">, 32)                  -- 32-byte confirm key, same label, 32 not 20
ad       = bencode({ e: epoch, q: 0, t: 4 })                         -- AD binding (3.5.1); q = 0, single frame
proof    = sxAeadEncrypt(<empty Data>, ad, kConfirm)                 -- nonce+tag over empty plaintext bound to ad
```

Deriving `kConfirm` at length 32 from the same `PS`, epoch, and `rp-rndzv` label (versus `rid` at
length 20) gives an independent confirmation key without a new registry label: crypto_kdf produces
independent output for a different requested length, and the 20-byte `rid` and 32-byte `kConfirm` never
collide. The responder verifies by recomputing `kConfirm` and `ad` for the claimed epoch (checking it
against the adjacent epochs it accepts, 4.4) and calling `sxAeadDecrypt(p, ad, kConfirm)`; success
authenticates the peer as a `PS` holder. A failure is surfaced, not retried blindly (3.10), and the
connection is dropped. On success the responder replies with its own `rendezvous-hello` echoing `n` in
its `ad` (setting `q: 1`) so the initiator gets mutual confirmation, and both proceed to the
[05-session.md](05-session.md) handshake, which supersedes this lightweight confirmation with the full
authenticated key agreement. The hello is a cheap gate to avoid spending handshake effort on Sybil
noise, not the security boundary; the handshake is.

## 4.4 Epoch adjacency (clock drift) and rotation

Clocks drift, and a meeting attempt can straddle an epoch boundary. Per 3.9, a party checking a
rendezvous id SHOULD also check the adjacent epochs. Concretely, a listener announces and polls at
three ids at once, and an initiator tries all three when reaching out:

```
for eOff in [-1, 0, +1]:
    ridN = sxKdfDerive(PS, <epoch + eOff>, <"rp-rndzv">, 20)
    DHT.announce(ridN)                 -- (listener) be findable across the boundary
    put peers[eOff] into DHT.getPeers(ridN)
```

Three epochs at one-hour `EPOCH_SECONDS` tolerate up to one hour of clock skew between the parties in
either direction, which is generous for any host with rough time sync. A responder accepts a
`rendezvous-hello` whose `e` is `epoch-1`, `epoch`, or `epoch+1` relative to its own clock and no
other; a hello for a distant epoch is rejected (a captured hello cannot be replayed a day later,
because `ad` binds `e` and the confirm key rotates every epoch).

**Rotation** is automatic and is the whole point of the epoch: `rid` moves every `EPOCH_SECONDS`, so a
passive DHT crawler that catalogs an active `rid` cannot follow the relationship into the next epoch
(principle 4, and the N2 mitigation "rotate ids/keys per epoch" in [01-threat-model.md](01-threat-model.md)).
Two epochs of the same relationship are unlinkable without `PS`. Parties who are online only
intermittently do not need to be online in the same epoch on the first try: they retry across epochs,
and because the id is derivable for any epoch from `PS`, a party can also compute a **future** meeting
id and agree out of band "meet at the top of the hour at 14:00 UTC," which is just a specific epoch.

## 4.5 First contact by public key (no shared secret yet)

When A wants to reach B for the very first time and no `PS` exists, there is nothing to key `rp-rndzv`
with. A derives a **meeting id from B's published identity key** instead. Because the input is a public
key (not a 32-byte secret), the derivation uses `sxHash` with an explicit domain tag, exactly as 3.4
directs for public-key-derived ids:

```
mid = sxHash(IK_x_B & textEncode("rp-fc-meet/v1", "utf-8"), 20)     -- first-contact meeting id
```

`IK_x_B` is B's identity X25519 public key from B's identity card ([02-identity.md](02-identity.md)
2.3). Anyone who knows B's public identity can compute `mid`, which is the intended property: `mid` is
not secret, it is a well-known "knock here to reach B" location, analogous to B's public prekey record
but as a live meeting point rather than a stored bundle. The domain tag `rp-fc-meet/v1` separates this
id from any other `sxHash`-derived id over the same key (for example the mailbox inbox id of doc 06,
which uses a different tag), so the two never collide.

Flow to bootstrap from `mid` into a real relationship:

```
1. B (accepting first contact): DHT.announce(mid) and poll DHT.getPeers(mid) for the epochs it is
   willing to be cold-contacted in. Because mid does not rotate (it has no secret and no epoch), B
   treats it as a knock channel it opens deliberately, not a standing beacon (see the caution below).
2. A: mid = sxHash(IK_x_B & "rp-fc-meet/v1", 20); DHT.announce(mid); put peers into DHT.getPeers(mid).
3. A finds B's IP:port, opens an rp1 connection, and sends a first-contact hello that is a sealed box
   to B, so A stays anonymous to onlookers and only B can open it:
        intro = bencode({ v: 1, t: 4, ik_ed: IK_pub_A, ik_x: IK_x_pub_A, kx: KX_pub_A })
        c     = sxSeal(pad(intro, 256), IK_x_B)                    -- sealed to B; sender-anonymous (G7)
   A sends c as an rp1 control frame (subtype 0x04, the sealed intro carried in a byte-string field).
4. B: sxSealOpen(c, IK_x_pub_B, IK_x_sec_B) -> A's identity card. B now runs first-contact
   verification (02-identity.md 2.5: safety number and/or key-transparency log) BEFORE trusting the
   keys, then proceeds to the 05-session.md handshake using A's kx key.
5. Once the handshake completes, both hold a session root RK; from the next meeting on they use
   PS = RK with rp-rndzv (4.1 source 1) and abandon mid. First contact happens on mid exactly once
   per relationship.
```

`mid` is a static, publicly computable id: it does not rotate and it is enumerable by anyone who has
B's identity key. That is the cost of being reachable by strangers, and it is the same cost B's public
prekey record already pays. B controls exposure by only announcing at `mid` when it is willing to
accept cold contacts (an "open to first contact" toggle), and by gating the sealed intros it opens with
the anti-abuse mechanisms of [10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md) (proof-of-work
or capability tokens on the knock), because an open `mid` is a spam and enumeration target. A B who
does not want to be cold-contactable simply never announces `mid` and is reachable only by parties who
already share a `PS`.

## 4.6 Private presence beacons (C7)

Presence is "I am online and reachable," visible only to a specific contact. It is a rendezvous id
under a different label so it is unlinkable to the meeting id even by a party who somehow learned one:

```
epoch = floor(unixTimeSeconds / 3600)
pid   = sxKdfDerive(PS, <decimal string of epoch>, <"rp-prsnc">, 20)   -- 20-byte presence id
```

`pid` uses the `rp-prsnc` label (3.4) and the same `PS` as the pair's rendezvous, but crypto_kdf's
domain separation by context means `pid` and `rid` for the same epoch are independent 20-byte values:
learning one tells an adversary nothing about the other. Only a holder of `PS` (that is, only the
contact) can derive `pid`; to everyone else it is an unremarkable 20-byte DHT key with no announced
content.

Presence flow:

```
1. Online: while you are online and want THIS contact to see you, DHT.announce(pid) (and pid for the
   adjacent epochs, 4.4). Refresh on the DHT expiry cadence. Announce ONLY while online: the presence
   of an announce at pid is the whole signal, so stop announcing (let it expire) the moment you go
   offline.
2. Watching: the contact polls DHT.getPeers(pid) for the adjacent epochs. A non-empty result means
   "my contact is online right now, at this IP:port."
3. Escalate: because pid already yielded the contact's IP:port, the watcher opens an rp1 connection to
   it and sends a rendezvous-hello (4.3.1) keyed by the same PS, then hands off to the 05-session.md
   handshake exactly as a normal rendezvous does. Presence doubles as the rendezvous for the session
   it triggers, so no second lookup is needed.
```

Presence is a capability: it leaks nothing to anyone who cannot derive `pid`, and it rotates every
epoch like `rid`. The residual leak is intrinsic and stated as a non-goal: announcing at `pid` is an
IP disclosure to the DHT (N1), and the pattern of when `pid` is announced reveals the contact's online
schedule to a rung-3 adversary who has somehow obtained `PS` (which requires already being the
contact). Against everyone else, the online/offline signal is private. Pair presence with the privacy
underlay (Tor/I2P or the multi-hop extension, N1, [10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md))
when the IP disclosure of announcing matters.

## 4.7 Blending into cover (riding a popular swarm)

Announcing at a derived, otherwise-empty id makes that id's swarm suspicious to a careful observer: a
20-byte id with a handful of peers and no real content is a subtle tell (the brainstorm's note on C2).
The fix is to make the rendezvous id **coincide with a popular, real infohash**, so the two contacts
are needles in a large, legitimate swarm haystack. The meeting id is the real infohash perturbed by a
secret offset only the pair can compute:

```
coverId = popularInfohash XOR sxHash(PS & <"rp-cover">, 20)         -- 20-byte id, blended into cover
```

where `popularInfohash` is the 20-byte (BEP5 keyspace) infohash of a large, lawful, actively-seeded
torrent both parties agree on out of band, and the XOR mask is a secret 20-byte value derived from `PS`
with an `sxHash` domain tag (public-key/non-secret-material rule of 3.4; here `PS` is secret but the
XOR-into-a-public-value construction is a hash-derived mask, so `sxHash` with the `rp-cover` tag is the
right tool, and the output length is 20 to match the id width).

Two properties make this cover, not just obfuscation:

- **The pair does not announce at `popularInfohash` itself**, so they do not appear in the real swarm's
  peer list; they announce at `coverId`, which is a different id XOR-close to it. To a crawler, `coverId`
  is one more busy-looking id in the neighborhood of a popular torrent, indistinguishable from the
  churn of a large swarm, rather than a lonely contentless id.
- **`coverId` still rotates** if the parties fold the epoch into the mask
  (`sxHash(PS & be64(epoch) & <"rp-cover">, 20)`), so even the blended id is not a fixed fingerprint
  across epochs. The choice of whether to rotate the cover id trades a little more cover stability for
  a little less cross-epoch linkage; a channel picks one and pins it in its out-of-band setup.

This is only the id-selection half of deniability. The strong form, where the two parties additionally
**genuinely seed the popular torrent** and tunnel the conversation inside the real BEP10 peer
connection so that to the tracker and a passive tap they are simply two clients sharing that torrent,
is the **cover-seed mode** specified in [05-session.md](05-session.md) (channel C3). Rendezvous-by-`coverId`
gets you a meeting point that hides in a crowd; cover-seed mode gets you a session that hides in a
lawful transfer. Use `coverId` for discovery, then hand off to the cover-seed session in
[05-session.md](05-session.md) for the tier-3 deniability.

## 4.8 Sybil, eclipse, and enumeration considerations

The rendezvous layer runs on the public mainline DHT, so it inherits the DHT's exposure to a rung-3
active participant ([01-threat-model.md](01-threat-model.md) adversary 3). The concrete risks and the
mitigations, all of which are the ones the threat model already names:

- **Eclipse of a specific id.** An adversary who places Sybil nodes with node-ids close to a target
  `rid` (Kademlia XOR-distance, BEP5) can intercept `announce`/`getPeers` for that id, censoring the
  meeting or logging who queries it. Mitigations (from the 01 attack table, rows "Eclipse a DHT key"
  and "Enumerate active channels"): rotation already moves `rid` every epoch, so an eclipse must be
  re-established each hour against an unpredictable id; **redundant ids** spread a single meeting across
  several derived ids so no one Sybil cluster sees them all; and never trusting a single lookup means a
  meeting that fails at `rid` is retried, not abandoned. Redundant ids are a straightforward extension
  of 4.2: derive a small fixed number `R` of sibling ids for the same epoch,
  `rid_j = sxKdfDerive(PS, <epoch>, <"rp-rndzv">, 20)` folded with a replica index (for example key the
  derivation with `epoch * 8 + j` for `j` in `0..R-1`, still a single decimal-string id argument), and
  announce/query all `R`. An eclipse of one `rid_j` does not block the others, and the replica set is
  itself unguessable without `PS`. `R` = 3 is a reasonable default; more `R` costs more DHT traffic
  (the availability-vs-footprint trade of N7).

- **Enumeration of active rendezvous ids.** A crawler that scrapes the whole DHT can list which 20-byte
  ids are hot and when. It cannot invert a `rid` to a relationship (the derivation is keyed by `PS`,
  4.2, N2), so it learns "these ids are active," not "these people are talking." Rotation bounds
  cross-epoch linkage to a single epoch; cover-blending (4.7) buries the id in a popular swarm so it is
  not even distinguishable as a private meeting; and cover traffic (join swarms and announce decoy ids,
  the Section 5 mechanism of the brainstorm, elaborated in
  [10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)) raises the noise floor. The residual is
  statistical (N2): a determined crawler learns aggregate activity patterns even though it cannot read
  any single relationship.

- **Sybil noise at a meeting id.** Any node can announce at any id, so `getPeers(rid)` may return
  unrelated or hostile peers. The `rendezvous-hello` proof (4.3.1) gates this cheaply: a peer that
  cannot produce a valid AEAD proof under `kConfirm` is dropped before any handshake work, so Sybil
  peers at the id cost only a single failed decrypt each.

- **The public-key first-contact id `mid` is enumerable by design** (4.5): anyone with B's identity key
  can compute and watch it. This is not a break, it is the price of being publicly reachable, the same
  price B's published prekey record pays. Rotation does not apply (there is no secret to key an epoch),
  so B's defense is announcing at `mid` only when open to cold contact and gating the sealed knocks with
  anti-abuse ([10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)). Parties who share a `PS`
  never use `mid` and are not enumerable this way.

## 4.9 Security properties

Mapping to the goals (G1-G7) and non-goals (N1-N7) of [01-threat-model.md](01-threat-model.md) and the
adversary rungs 1-5. Rendezvous is signaling, so it inherits its confidentiality and authenticity from
the session it hands off to (05); the properties specific to this layer are the unlinkability of the
meeting itself and the honest metadata/IP leakage.

- **G1 Confidentiality (rungs 1-4):** rendezvous carries no message content, so there is no plaintext
  to protect here; content confidentiality begins at the [05-session.md](05-session.md) handshake. The
  one payload this layer does send, the first-contact intro (4.5), is a sealed box (G1, and G7 below).

- **G2 Integrity / authenticity (rungs 1-4):** the `rendezvous-hello` proof (4.3.1) authenticates the
  peer as a holder of `PS` via an AEAD tag under `kConfirm`, and the first-contact intro is opened only
  by B; neither replaces the full mutual authentication of the 05 handshake, which is where forgery and
  wrong-key are definitively rejected (3.10, fail closed).

- **G3 Forward secrecy:** not a property of the rendezvous layer; it is provided by the ratcheted /
  ephemeral keys of the session and mailbox ([05-session.md](05-session.md),
  [06-mailbox.md](06-mailbox.md)). Rotation of `rid`/`pid` per epoch limits how much a compromised `PS`
  reveals about *which* meetings occurred, but does not by itself give message forward secrecy.

- **G4 Replay / reorder resistance (rungs 1-4):** the `rendezvous-hello` binds `e`, `q`, and `t` as
  associated data (4.3.1, 3.5.1) and `kConfirm` rotates every epoch, so a captured hello cannot be
  replayed into another epoch or slot. Epoch adjacency (4.4) accepts only `epoch-1..epoch+1`.

- **G5 Censorship resistance (rung 2; rung 3 with effort):** there is no server or fixed id to seize.
  Against a rung-3 Sybil that eclipses one `rid`, per-epoch rotation plus redundant ids plus
  re-announce (4.8, and the G5 note in 01) raise the cost, but a determined targeted eclipse of a known
  relationship's id space remains possible for the epoch it holds; G5 is weaker at rung 3, exactly as
  01 states.

- **G6 Deniability (cover-seed, rungs 1, 2, 4):** the `coverId` blending (4.7) is the discovery half of
  deniability, making the meeting id indistinguishable from ordinary swarm churn. The full existence
  hiding (a conversation inside a lawful transfer) is the cover-seed mode of
  [05-session.md](05-session.md); this doc only points the meeting at the right swarm.

- **G7 Sender anonymity (first contact):** the first-contact intro is `sxSeal`ed to B (4.5), so an
  onlooker at `mid` cannot tell who is knocking, and B learns A's identity only after opening the
  sealed box; A can withhold a signature until after out-of-band verification.

Non-goals that bite hardest at this layer, stated plainly:

- **N1 IP exposure (rungs 3-4):** this is the sharpest limit of rendezvous. To meet, both parties
  `DHT.announce` at `rid`/`pid`/`mid`/`coverId`, and `getPeers` returns IP:port, so the DHT and the
  peer see your address; a rung-3/4 adversary can map an identity or a derived id to an IP by watching
  the announce. Rotation hides *which relationship* an id belongs to, not *that an IP announced there*.
  The only real mitigations are the underlay (Tor/I2P) or the multi-hop extension (N1,
  [10-anti-abuse-and-privacy.md](10-anti-abuse-and-privacy.md)), neither of which this layer provides by
  itself. Presence (4.6) is the starkest case: announcing at `pid` is precisely an IP-tagged "online
  now" signal.

- **N2 Incomplete metadata privacy (rung 3):** the DHT is public and crawlable. Derived unguessable ids
  (4.2), per-epoch rotation (4.4), redundant ids and cover-blending (4.7, 4.8), and cover traffic raise
  the cost of enumeration and linkage, but a rung-3 crawler still learns aggregate activity: which ids
  are hot and when, and, for a static `mid` (4.5), that someone is knocking at a known identity.
  Riptide reduces this metadata leakage; it does not eliminate it.

- **N3 Global passive adversary (rung 5):** a rung-5 observer that correlates announces, timings, and
  IPs across the whole network can confirm a meeting regardless of id rotation. This layer does not
  defend against rung 5; only cover-seed and multi-hop even approach it, and only partially.

- **N7 Availability (best-effort):** DHT churn, expiry, and eclipse can delay or block a meeting. The
  answer is retry across epochs and redundant ids (4.4, 4.8), never a fall back to an unauthenticated
  path (3.10). A missed epoch is a delivery delay, not a security failure.

In one line: rendezvous gives you an unlinkable, unguessable, self-rotating meeting point that a rung-3
crawler cannot invert to a relationship and a rung-1/2 observer cannot distinguish from ordinary DHT
activity, at the unavoidable cost of exposing, to the DHT and the peer, the IP address that announces
there (N1). Everything stronger than that, content secrecy, forward secrecy, and existence hiding, is
provided by the session and cover-seed modes in [05-session.md](05-session.md), which this layer hands
off to.
